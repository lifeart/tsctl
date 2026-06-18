package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config is the fully-resolved runtime configuration. Source is flags + env
// only (DESIGN §5: no YAML, no committed secrets).
type Config struct {
	Hostname     string        // tsnet hostname presented to the control server
	StateDir     string        // tsnet state dir (the crown jewel -- 0700, DESIGN §7)
	Listen       string        // tailnet-side listen addr (tsnet.Listen)
	HealthAddr   string        // 127.0.0.1-only /healthz host socket
	Routers      []string      // managed router 100.x IPv4s
	SSHUser      string        // OpenWRT login ("root" in v1)
	AuthKey      string        // one-time tagged enrollment key (env or LoadCredential)
	Debug        bool          // forward verbose tsnet backend logs
	SSHTimeout   time.Duration // per dial/exec deadline
	Owner        string        // tailnet login allowed to control (RequireAuth, DESIGN §7); optional if UIPassword set
	AllowedHosts []string      // Host-header allowlist for CSRF/rebinding defense (DESIGN §7)
	PollInterval time.Duration // refresh cadence while ≥1 client is connected (DESIGN §6)

	// HTTPListen, when non-empty (e.g. ":8080" or "0.0.0.0:8080"), runs a SECOND
	// http.Server on this HOST socket serving the SAME UI+API as the tailnet
	// listener, so the UI can be reached from a published Docker/NAS port. It is
	// distinct from the loopback-only /healthz socket. Requires UIPassword.
	HTTPListen string
	// UIPassword is the shared password for the host-socket/session auth path
	// (api.RequireAuth). Empty disables password login (tailnet-owner path only).
	UIPassword string

	// ExitNodeLANAccess controls the only non-exit-node pref tsctl ever writes.
	// nil = PRESERVE the router's existing --exit-node-allow-lan-access (default);
	// non-nil = tsctl sets it to this value when setting an exit node. Other
	// `tailscale up` settings are always preserved (we use incremental `set`).
	ExitNodeLANAccess *bool
}

// env returns the env var or a default.
func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// envDur returns a duration from the env var, or def if unset. A set-but-invalid
// value is a hard error (never silently swallowed) so container/env config is
// accurate.
func envDur(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", key, v, err)
	}
	return d, nil
}

// loadConfig resolves config from env defaults overridden by flags. args is the
// flag slice (e.g. os.Args[1:] for `serve`).
func loadConfig(args []string) (*Config, error) {
	fs := flag.NewFlagSet("tsctl", flag.ContinueOnError)
	c := &Config{}

	// Duration defaults are env-overridable too (fail fast on a bad value).
	sshTimeoutDef, err := envDur("TSCTL_SSH_TIMEOUT", 15*time.Second)
	if err != nil {
		return nil, err
	}
	pollIntervalDef, err := envDur("TSCTL_POLL_INTERVAL", 30*time.Second)
	if err != nil {
		return nil, err
	}

	// StateDir default: systemd's STATE_DIRECTORY when present, else local dir.
	defStateDir := env("TSCTL_STATE_DIR", env("STATE_DIRECTORY", "./tsnet-state"))

	fs.StringVar(&c.Hostname, "hostname", env("TSCTL_HOSTNAME", "tsctl"), "tsnet hostname")
	fs.StringVar(&c.StateDir, "state-dir", defStateDir, "tsnet state directory (treat as a private key)")
	fs.StringVar(&c.Listen, "listen", env("TSCTL_LISTEN", ":80"), "tailnet-side listen address (tsnet)")
	fs.StringVar(&c.HealthAddr, "healthz", env("TSCTL_HEALTH_ADDR", "127.0.0.1:8088"), "loopback-only /healthz address")
	fs.StringVar(&c.SSHUser, "ssh-user", env("TSCTL_SSH_USER", "root"), "OpenWRT SSH login")
	fs.BoolVar(&c.Debug, "debug", env("TSCTL_DEBUG", "") != "", "forward verbose tsnet backend logs")
	routers := fs.String("routers", env("TSCTL_ROUTERS", ""), "comma-separated router 100.x IPv4s")
	fs.DurationVar(&c.SSHTimeout, "ssh-timeout", sshTimeoutDef, "per dial/exec SSH deadline")
	fs.StringVar(&c.Owner, "owner", env("TSCTL_OWNER", ""), "tailnet login (email) allowed to control (optional if -ui-password is set)")
	fs.StringVar(&c.HTTPListen, "http-listen", env("TSCTL_HTTP_LISTEN", ""), "host-socket listen address for the UI/API, e.g. :8080 (off by default; requires -ui-password)")
	fs.StringVar(&c.UIPassword, "ui-password", env("TSCTL_UI_PASSWORD", ""), "shared password for the host-socket/session auth path")
	allowed := fs.String("allowed-hosts", env("TSCTL_ALLOWED_HOSTS", ""), "extra comma-separated Host values to allow (DNS-rebinding defense)")
	fs.DurationVar(&c.PollInterval, "poll-interval", pollIntervalDef, "refresh cadence while a client is connected")
	lanAccess := fs.String("exit-node-lan-access", env("TSCTL_EXIT_NODE_LAN_ACCESS", "preserve"),
		"manage --exit-node-allow-lan-access on the router: preserve|true|false (preserve keeps the router's existing setting)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	switch strings.ToLower(strings.TrimSpace(*lanAccess)) {
	case "", "preserve", "keep":
		c.ExitNodeLANAccess = nil
	case "true", "yes", "on", "1":
		v := true
		c.ExitNodeLANAccess = &v
	case "false", "no", "off", "0":
		v := false
		c.ExitNodeLANAccess = &v
	default:
		return nil, fmt.Errorf("invalid -exit-node-lan-access %q: want preserve|true|false", *lanAccess)
	}
	for _, r := range strings.Split(*routers, ",") {
		if r = strings.TrimSpace(r); r != "" {
			c.Routers = append(c.Routers, r)
		}
	}

	// Host allowlist: always trust our own tsnet hostname and the listen host;
	// the composition root adds the discovered MagicDNS FQDN + 100.x after Up.
	c.AllowedHosts = []string{c.Hostname}
	if host, _, err := net.SplitHostPort(c.Listen); err == nil && host != "" {
		c.AllowedHosts = append(c.AllowedHosts, host)
	}
	for _, h := range strings.Split(*allowed, ",") {
		if h = strings.TrimSpace(h); h != "" {
			c.AllowedHosts = append(c.AllowedHosts, h)
		}
	}
	// Auto-allow the host-listen host so reaching the UI at that bind address
	// works out of the box. A wildcard bind (":8080" → empty host) adds nothing;
	// the user must still add the NAS hostname/IP they browse to via
	// TSCTL_ALLOWED_HOSTS (documented in the README / .env.example).
	if c.HTTPListen != "" {
		if host, _, err := net.SplitHostPort(c.HTTPListen); err == nil && host != "" {
			c.AllowedHosts = append(c.AllowedHosts, host)
		}
	}

	key, err := loadAuthKey()
	if err != nil {
		return nil, err
	}
	c.AuthKey = key

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// loadAuthKey returns the one-time tagged enrollment key from TS_AUTHKEY or, in
// production, from systemd LoadCredential ($CREDENTIALS_DIRECTORY/ts_authkey, on
// tmpfs). Empty is OK: once enrolled, the node key lives in the state dir and
// the auth key is no longer needed (DESIGN §7). A configured-but-unreadable
// credential is a hard error -- never silently ignored.
func loadAuthKey() (string, error) {
	if v := os.Getenv("TS_AUTHKEY"); v != "" {
		return strings.TrimSpace(v), nil
	}
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		b, err := os.ReadFile(filepath.Join(dir, "ts_authkey"))
		if err != nil {
			return "", fmt.Errorf("reading LoadCredential ts_authkey: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", nil
}

// validate fails fast on bad config (DESIGN: fail-fast, non-zero exit).
func (c *Config) validate() error {
	if c.Hostname == "" {
		return fmt.Errorf("hostname must not be empty")
	}
	if c.StateDir == "" {
		return fmt.Errorf("state-dir must not be empty")
	}
	if c.Listen == "" {
		return fmt.Errorf("listen must not be empty")
	}
	if c.SSHUser == "" {
		return fmt.Errorf("ssh-user must not be empty")
	}
	if err := requireLoopback(c.HealthAddr); err != nil {
		return fmt.Errorf("healthz address %q: %w", c.HealthAddr, err)
	}
	if c.HTTPListen != "" {
		if _, _, err := net.SplitHostPort(c.HTTPListen); err != nil {
			return fmt.Errorf("http-listen %q: %w (want host:port, e.g. :8080)", c.HTTPListen, err)
		}
	}
	for _, r := range c.Routers {
		if _, err := netip.ParseAddr(r); err != nil {
			return fmt.Errorf("router %q is not a valid IP (use the 100.x IPv4): %w", r, err)
		}
	}
	return nil
}

// requireLoopback rejects any /healthz bind that is not loopback (DESIGN §7:
// the host socket must never leak to the LAN).
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("expected host:port: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("host must be a loopback IP literal (e.g. 127.0.0.1): %w", err)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("must bind a loopback address, got %s", ip)
	}
	return nil
}
