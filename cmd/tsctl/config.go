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
	Owner        string        // tailnet login allowed to control (RequireOwner, DESIGN §7)
	AllowedHosts []string      // Host-header allowlist for CSRF/rebinding defense (DESIGN §7)
	PollInterval time.Duration // refresh cadence while ≥1 client is connected (DESIGN §6)

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

// loadConfig resolves config from env defaults overridden by flags. args is the
// flag slice (e.g. os.Args[1:] for `serve`).
func loadConfig(args []string) (*Config, error) {
	fs := flag.NewFlagSet("tsctl", flag.ContinueOnError)
	c := &Config{}

	// StateDir default: systemd's STATE_DIRECTORY when present, else local dir.
	defStateDir := env("TSCTL_STATE_DIR", env("STATE_DIRECTORY", "./tsnet-state"))

	fs.StringVar(&c.Hostname, "hostname", env("TSCTL_HOSTNAME", "tsctl"), "tsnet hostname")
	fs.StringVar(&c.StateDir, "state-dir", defStateDir, "tsnet state directory (treat as a private key)")
	fs.StringVar(&c.Listen, "listen", env("TSCTL_LISTEN", ":80"), "tailnet-side listen address (tsnet)")
	fs.StringVar(&c.HealthAddr, "healthz", env("TSCTL_HEALTH_ADDR", "127.0.0.1:8088"), "loopback-only /healthz address")
	fs.StringVar(&c.SSHUser, "ssh-user", env("TSCTL_SSH_USER", "root"), "OpenWRT SSH login")
	fs.BoolVar(&c.Debug, "debug", env("TSCTL_DEBUG", "") != "", "forward verbose tsnet backend logs")
	routers := fs.String("routers", env("TSCTL_ROUTERS", ""), "comma-separated router 100.x IPv4s")
	fs.DurationVar(&c.SSHTimeout, "ssh-timeout", 15*time.Second, "per dial/exec SSH deadline")
	fs.StringVar(&c.Owner, "owner", env("TSCTL_OWNER", ""), "tailnet login (email) allowed to control")
	allowed := fs.String("allowed-hosts", env("TSCTL_ALLOWED_HOSTS", ""), "extra comma-separated Host values to allow (DNS-rebinding defense)")
	fs.DurationVar(&c.PollInterval, "poll-interval", 30*time.Second, "refresh cadence while a client is connected")
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
