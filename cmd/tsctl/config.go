package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lifeart/tsctl/internal/router"
)

// defaultEgressURL is the stable 204 generator the egress probe fetches by
// default (docs/design/keep-egress.md). Used both as the -egress-url flag default
// and by `tsctl demo`, so the demo exercises the egress ✓/✗ indicator.
const defaultEgressURL = "http://captive.tailscale.com/generate_204"

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

	// EgressCheck enables the read-only egress probe the poller runs on a router
	// after a CONFIRMED exit-node change (docs/design/keep-egress.md). Default TRUE.
	// EgressURL is the http(s) endpoint the router fetches; validated fail-closed at
	// load (must be http(s):// with no shell metacharacters).
	EgressCheck bool
	EgressURL   string

	// RequireKeep gates the explicit-Keep step (docs/design/keep-egress.md stage 2).
	// Default FALSE = backward-compatible auto-keep. When true, a confirmed exit-node
	// change is held in "awaiting-keep" within the revert window until the operator
	// issues an explicit Keep (the strongest dead-man's-switch).
	RequireKeep bool

	// --- router command transport (DEFAULT: tailscale-ssh) ---------------------
	// RouterTransport selects how tsctl reaches a router to run commands:
	//   - "tailscale-ssh" (default): SSH over the tailnet, `none` auth (ACL-gated).
	//   - "ip-password": SSH to the router's LAN endpoint with a password, host-key
	//     verified. Opt-in; trades ACL-governed identity for a flat secret.
	RouterTransport string
	// RouterHostKeyMode is the ip-password host-key verification mode:
	// "tofu" (default) | "strict" | "pin" | "insecure". Unused by tailscale-ssh
	// (which uses InsecureIgnoreHostKey -- safe, WireGuard authenticates the peer).
	RouterHostKeyMode string
	// SSHPassword is the shared router SSH password for the ip-password transport.
	// It is a SECRET: loaded via loadSSHPassword (TSCTL_SSH_PASSWORD env or the
	// systemd LoadCredential ssh_password), NEVER a flag and never logged.
	SSHPassword string
	// RouterAddrs maps a router's canonical 100.x identity to the LAN endpoint to
	// dial ("host" or "host:port") for the ip-password transport. The 100.x stays
	// the identity everywhere; this is consumed only at the SSH dial boundary.
	RouterAddrs map[string]string
	// KnownHostsPath is the OpenSSH known_hosts file used by the ip-password
	// tofu/strict/pin host-key modes. Defaults to $STATE_DIR/known_hosts.
	KnownHostsPath string
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

// envBool returns a bool from the env var (strconv.ParseBool: 1/t/true/0/f/false,
// case-insensitive), or def if unset. A set-but-invalid value is a hard error so
// container/env config is accurate (never silently swallowed).
func envBool(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return false, fmt.Errorf("invalid %s %q: want a boolean (true/false): %w", key, v, err)
	}
	return b, nil
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
	// Egress check defaults to TRUE; a set-but-invalid env value is a hard error
	// (never silently ignored), like the duration envs above.
	egressCheckDef, err := envBool("TSCTL_EGRESS_CHECK", true)
	if err != nil {
		return nil, err
	}
	// Explicit-Keep gate defaults to FALSE (backward-compatible auto-keep); a
	// set-but-invalid env value is a hard error, like the bools above.
	requireKeepDef, err := envBool("TSCTL_REQUIRE_KEEP", false)
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
	fs.BoolVar(&c.EgressCheck, "egress-check", egressCheckDef,
		"after a confirmed exit-node change, run a read-only egress probe ON the router (default true)")
	fs.StringVar(&c.EgressURL, "egress-url", env("TSCTL_EGRESS_URL", defaultEgressURL),
		"URL the egress probe fetches from the router (http(s) only, no shell metacharacters)")
	fs.BoolVar(&c.RequireKeep, "require-keep", requireKeepDef,
		"require an explicit operator Keep within the revert window after a confirmed exit-node change (default false = auto-keep)")
	fs.StringVar(&c.RouterTransport, "router-transport", env("TSCTL_ROUTER_TRANSPORT", "tailscale-ssh"),
		"router command transport: tailscale-ssh (default) | tailnet-password (password over the tailnet; no Tailscale SSH, no LAN map) | ip-password (password to a LAN endpoint, host-key-verified)")
	fs.StringVar(&c.RouterHostKeyMode, "router-hostkey-mode", env("TSCTL_ROUTER_HOSTKEY_MODE", "tofu"),
		"ip-password host-key verification: tofu (default) | strict | pin | insecure")
	routerAddrs := fs.String("router-addrs", env("TSCTL_ROUTER_ADDRS", ""),
		"ip-password LAN endpoints: comma-separated 100.x=host[:port] pairs (the 100.x stays the router identity)")

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

	// ip-password transport: parse the 100.x->LAN-endpoint map, default the
	// known_hosts path under the (private) state dir, and load the SSH password
	// secret (env or systemd LoadCredential; never a flag, never logged). These
	// are parsed for any transport (cheap) but only required by validate() when
	// the ip-password transport is selected.
	c.RouterAddrs = map[string]string{}
	for _, pair := range strings.Split(*routerAddrs, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		id, ep, ok := strings.Cut(pair, "=")
		id = strings.TrimSpace(id)
		ep = strings.TrimSpace(ep)
		if !ok || id == "" || ep == "" {
			return nil, fmt.Errorf("invalid -router-addrs entry %q: want 100.x=host[:port]", pair)
		}
		if _, err := netip.ParseAddr(id); err != nil {
			return nil, fmt.Errorf("invalid -router-addrs key %q: must be the router's 100.x IPv4: %w", id, err)
		}
		c.RouterAddrs[id] = ep
	}
	if c.StateDir != "" {
		c.KnownHostsPath = filepath.Join(c.StateDir, "known_hosts")
	}
	pw, err := loadSSHPassword()
	if err != nil {
		return nil, err
	}
	c.SSHPassword = pw

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

// loadSSHPassword returns the shared router SSH password for the ip-password
// transport, mirroring loadAuthKey's secret pattern: TSCTL_SSH_PASSWORD env, or
// the systemd LoadCredential ($CREDENTIALS_DIRECTORY/ssh_password, on tmpfs). It
// is NEVER a flag and never logged. Empty is OK here (the default tailscale-ssh
// transport needs no password); validate() fails closed if ip-password is
// selected without one. Because LoadCredential=ssh_password is OPTIONAL in the
// systemd unit, a MISSING credential file is treated as "unset" (empty), not an
// error -- only a genuinely unreadable file is a hard error.
func loadSSHPassword() (string, error) {
	if v, ok := os.LookupEnv("TSCTL_SSH_PASSWORD"); ok {
		return strings.TrimSpace(v), nil
	}
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		b, err := os.ReadFile(filepath.Join(dir, "ssh_password"))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return "", nil // credential not provided -> unset (fine unless ip-password)
			}
			return "", fmt.Errorf("reading LoadCredential ssh_password: %w", err)
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

	// Egress probe URL: fail-closed on a bad value (same http(s)+no-metacharacters
	// rule the router layer enforces before it ever reaches a shell), regardless of
	// whether the check is enabled, so a typo is caught at startup.
	if err := router.ValidateEgressURL(c.EgressURL); err != nil {
		return fmt.Errorf("invalid -egress-url / TSCTL_EGRESS_URL: %w", err)
	}

	// Router transport + host-key mode (fail-closed; default tailscale-ssh).
	// Reject unknown values for both. The host-key mode is validated regardless
	// of transport so a typo never silently degrades verification.
	switch c.RouterTransport {
	case "tailscale-ssh", "ip-password", "tailnet-password":
	default:
		return fmt.Errorf("invalid -router-transport %q: want tailscale-ssh, tailnet-password, or ip-password", c.RouterTransport)
	}
	switch c.RouterHostKeyMode {
	case "tofu", "strict", "pin", "insecure":
	default:
		return fmt.Errorf("invalid -router-hostkey-mode %q: want tofu, strict, pin, or insecure", c.RouterHostKeyMode)
	}
	if c.RouterTransport == "ip-password" {
		// Require the password secret (fail loud -- the whole point of the mode).
		if c.SSHPassword == "" {
			return errors.New("router transport ip-password requires an SSH password: set TSCTL_SSH_PASSWORD or provide the systemd LoadCredential ssh_password (it is never a flag and never logged)")
		}
		// insecure is allowed ONLY because it was explicitly selected (the default
		// is tofu); main logs a loud warning. tofu/strict/pin need a known_hosts
		// path (defaulted to $STATE_DIR/known_hosts above).
		if c.RouterHostKeyMode != "insecure" && c.KnownHostsPath == "" {
			return fmt.Errorf("router transport ip-password with host-key mode %q requires a known_hosts path (default $STATE_DIR/known_hosts; set a non-empty -state-dir)", c.RouterHostKeyMode)
		}
		// NOTE: that each managed router has a -router-addrs mapping is enforced at
		// use-time (router.endpointFor fails loud per router), not here, because
		// routers may be auto-discovered from the netmap and are unknown at config
		// time. Document the mapping requirement (README) for ip-password users.
	}
	if c.RouterTransport == "tailnet-password" {
		// Password SSH over the tailnet (tsnet) to the router's own sshd -- no LAN
		// map, no Tailscale SSH. Require the password; host-key mode is irrelevant
		// (WireGuard authenticates the peer, like tailscale-ssh).
		if c.SSHPassword == "" {
			return errors.New("router transport tailnet-password requires an SSH password: set TSCTL_SSH_PASSWORD or provide the systemd LoadCredential ssh_password (it is never a flag and never logged)")
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
