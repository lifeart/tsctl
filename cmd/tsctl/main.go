// Command tsctl is the Tailscale exit-node manager. It joins the tailnet as its
// own tsnet node (tag:tsctl, persistent), serves a small web UI over the tailnet
// only, and lets the user set which exit node each OpenWRT router uses.
//
// This file is the composition root (DESIGN §5): config, tsnet Up->Listen,
// loopback /healthz, wiring, ordered graceful shutdown. Plus a `spike`
// subcommand that proves the SSH-over-tailnet path against a real router.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"

	"github.com/lifeart/tsctl/internal/api"
	"github.com/lifeart/tsctl/internal/demo"
	"github.com/lifeart/tsctl/internal/groups"
	"github.com/lifeart/tsctl/internal/netmap"
	"github.com/lifeart/tsctl/internal/poller"
	"github.com/lifeart/tsctl/internal/router"
	"github.com/lifeart/tsctl/internal/sse"
	"github.com/lifeart/tsctl/internal/store"
	"github.com/lifeart/tsctl/web"
)

// Frozen seam assertions (DESIGN §4): one *netmap.Mapper satisfies both the
// poller's Netmapper and the api's WhoIser; *router.Client satisfies
// RouterClient. If a Phase B agent drifts a signature, this stops compiling.
var (
	_ poller.Netmapper    = (*netmap.Mapper)(nil)
	_ poller.RouterClient = (*router.Client)(nil)
	_ poller.Broadcaster  = (*sse.Hub)(nil)
	_ poller.GroupReader  = (*groups.Store)(nil)
	_ api.WhoIser         = (*netmap.Mapper)(nil)
	_ api.Controller      = (*poller.Poller)(nil)
	_ api.GroupStore      = (*groups.Store)(nil)

	// The demo World plays the Mapper (Netmapper+WhoIser) and RouterClient roles
	// against the SAME frozen seams, so `tsctl demo` exercises the real stack;
	// demo.Groups plays the GroupReader + GroupStore roles.
	_ poller.Netmapper    = (*demo.World)(nil)
	_ poller.RouterClient = (*demo.World)(nil)
	_ api.WhoIser         = (*demo.World)(nil)
	_ poller.GroupReader  = (*demo.Groups)(nil)
	_ api.GroupStore      = (*demo.Groups)(nil)
)

// demoListen is the plain loopback address `tsctl demo` serves on (no tsnet).
const demoListen = "127.0.0.1:8089"

// version is the build version, stamped via -ldflags "-X main.version=...".
// Defaults to "dev" for `go run`/`go build` without the linker flag.
var version = "dev"

func main() {
	lg := log.New(os.Stderr, "tsctl: ", log.LstdFlags|log.Lmsgprefix)

	args := os.Args[1:]

	// Top-level help / version, accepted both as a bare word and as a flag so
	// `tsctl version`, `tsctl -version`, `tsctl help`, and `tsctl -h` all work.
	if len(args) > 0 {
		switch args[0] {
		case "help", "-h", "-help", "--help":
			printUsage(os.Stdout)
			return
		case "version", "-v", "-version", "--version":
			fmt.Printf("tsctl %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
			return
		}
	}

	// Subcommand dispatch. A leading BARE token (not a -flag) selects the command;
	// flags-first or no args defaults to `serve`. An unrecognized leading token is
	// a HARD error -- never silently ignored. (Before this, `tsctl serve -flags`
	// dropped every flag because flag.Parse stops at the first non-flag arg, then
	// failed with a confusing "owner must be set".)
	cmd, rest := "serve", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, rest = args[0], args[1:]
	}

	switch cmd {
	case "serve":
		if err := runServe(rest, lg); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return // `serve -h` already printed flag usage; clean exit
			}
			lg.Fatalf("%v", err)
		}
	case "spike":
		if len(rest) < 1 {
			lg.Fatal("usage: tsctl spike <router-100.x-ipv4>")
		}
		if err := runSpike(rest[0], lg); err != nil {
			lg.Fatalf("spike: %v", err)
		}
	case "demo":
		if err := runDemo(lg); err != nil {
			lg.Fatalf("demo: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "tsctl: unknown command %q\n\n", cmd)
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

// printUsage writes a concise command summary. Per-flag help for the server is
// available via `tsctl serve -h` (the flag set prints its own defaults).
func printUsage(w io.Writer) {
	fmt.Fprintf(w, `tsctl %s -- Tailscale exit-node manager

Usage:
  tsctl [serve] [flags]      Run the server (default); see "tsctl serve -h" for flags
  tsctl spike <router-ip>    Prove the SSH-over-tailnet path to a router
  tsctl demo                 Offline UI preview on %s (no tsnet, no tailnet)
  tsctl version              Print version and exit
  tsctl help                 Print this help

Config is flags + env (TSCTL_*, TS_AUTHKEY). See the README.
`, version, demoListen)
}

// newTSNet builds the persistent, tagged, non-ephemeral tsnet node (DESIGN §2/§7).
func newTSNet(cfg *Config, lg *log.Logger) *tsnet.Server {
	return &tsnet.Server{
		Dir:           cfg.StateDir,
		Hostname:      cfg.Hostname,
		AdvertiseTags: []string{"tag:tsctl"},
		Ephemeral:     false,
		AuthKey:       cfg.AuthKey, // ignored once enrolled (key lives in StateDir)
		UserLogf:      lg.Printf,   // user-facing: AuthURL, status
		Logf:          filteredLogf(cfg.Debug, lg),
	}
}

// filteredLogf controls tsnet backend log verbosity (DESIGN: Logf filtered).
// This is verbosity control, not error swallowing: user-facing events come via
// UserLogf, and real errors surface through /healthz, Snapshot.NetmapErr, and
// RouterView.LastError.
func filteredLogf(debug bool, lg *log.Logger) func(string, ...any) {
	if debug {
		return lg.Printf
	}
	return func(string, ...any) {}
}

func runServe(args []string, lg *log.Logger) error {
	cfg, err := loadConfig(args)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	// serve needs AT LEAST ONE auth method (RequireAuth fails closed otherwise):
	// the tailnet path (an owner login) and/or the host/password path. Owner is
	// now optional. Surface this as a fail-fast config error, not a silent lockout.
	if cfg.Owner == "" && cfg.UIPassword == "" {
		return errors.New("no authentication configured: set an owner (TSCTL_OWNER / --owner) for the tailnet path and/or a UI password (TSCTL_UI_PASSWORD / --ui-password) for the host-port path")
	}
	// Never expose an unauthenticated control UI on a host socket.
	if cfg.HTTPListen != "" && cfg.UIPassword == "" {
		return errors.New("a password is required to expose the UI on a host port; set TSCTL_UI_PASSWORD")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := newTSNet(cfg, lg)

	// tsnet MUST be Up before Listen (DESIGN §9). Fatal on failure -> non-zero
	// exit -> systemd Restart=on-failure.
	upCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	_, err = srv.Up(upCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("tsnet up: %w", err)
	}
	lg.Printf("tsnet up as %q; serving SPA + API on tailnet %s", cfg.Hostname, cfg.Listen)

	lc, err := srv.LocalClient()
	if err != nil {
		return fmt.Errorf("tsnet local client: %w", err)
	}

	// --- wiring ---
	st := store.New()
	mapper := netmap.New(lc) // implements poller.Netmapper AND api.WhoIser
	rc, err := router.New(routerOptions(cfg, srv.Dial))
	if err != nil {
		return fmt.Errorf("router client: %w", err)
	}
	warnIfInsecureHostKey(cfg, lg)
	// Persisted zone/group store ($STATE_DIR/groups.json). Fail-fast on a corrupt
	// file (never silently start empty and risk clobbering the user's data).
	grpStore, err := groups.New(filepath.Join(cfg.StateDir, "groups.json"))
	if err != nil {
		return fmt.Errorf("groups store: %w", err)
	}
	// hub.Transitions() drives the poller's idle suspension; api.EncodeSnapshot
	// makes SSE frames identical to the REST Snapshot DTO (PHASE_B §3).
	hub := sse.New(st, api.EncodeSnapshot)
	pol := poller.New(st, mapper, rc, grpStore, cfg.Routers, hub, hub.Transitions(), cfg.PollInterval, lg.Printf)
	pol.ConfigureEgress(cfg.EgressCheck, cfg.EgressURL) // post-confirm egress probe (keep-egress stage 1)
	apiH := api.New(st, mapper, pol, api.Config{
		Owner:        cfg.Owner,
		UIPassword:   cfg.UIPassword,
		AllowedHosts: allowedHosts(ctx, cfg, lc, lg),
		Groups:       grpStore,
	})

	// Long-lived workers run off appCtx so shutdown can stop them in order.
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel() // also covers early-return error paths; cancel is idempotent
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := hub.Run(appCtx); err != nil && !errors.Is(err, context.Canceled) {
			lg.Printf("sse hub stopped: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := pol.Run(appCtx); err != nil && !errors.Is(err, context.Canceled) {
			lg.Printf("poller stopped: %v", err)
		}
	}()

	// HTTP surface: SPA + REST + SSE, shared by BOTH listeners (tailnet + the
	// optional host socket). RequireAuth admits either the tailnet owner or a
	// password session, so the SAME handler serves both paths.
	mux := buildMux(apiH, hub)

	ln, err := srv.Listen("tcp", cfg.Listen) // tailnet-only by construction; never Funnel (DESIGN §7)
	if err != nil {
		return fmt.Errorf("tsnet listen: %w", err)
	}
	httpSrv := &http.Server{
		Handler:           mux,
		WriteTimeout:      0, // SSE: a write deadline silently kills long-lived streams (DESIGN §2)
		ReadHeaderTimeout: 10 * time.Second,
		// Derive every request context from appCtx so cancelling it on shutdown
		// releases the long-lived SSE handlers (an SSE stream never ends on its
		// own; Shutdown would otherwise block until the WriteTimeout-free conns).
		BaseContext: func(net.Listener) context.Context { return appCtx },
	}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Printf("tailnet http server: %v", err)
		}
	}()

	// --- optional host-socket listener (DESIGN §7: NOT the loopback /healthz) ---
	// When cfg.HTTPListen is set, serve the SAME handler on a real host socket so
	// the UI is reachable from a published Docker/NAS port. Auth here is the
	// password/session path (RequireAuth). Validation above guarantees a password
	// is set, so this is never an unauthenticated control UI.
	var hostSrv *http.Server
	if cfg.HTTPListen != "" {
		hostLn, err := net.Listen("tcp", cfg.HTTPListen)
		if err != nil {
			return fmt.Errorf("http-listen %q: %w", cfg.HTTPListen, err)
		}
		hostSrv = &http.Server{
			Handler:           mux,
			WriteTimeout:      0, // SSE (same rationale as the tailnet server)
			ReadHeaderTimeout: 10 * time.Second,
			BaseContext:       func(net.Listener) context.Context { return appCtx },
		}
		go func() {
			if err := hostSrv.Serve(hostLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				lg.Printf("host http server: %v", err)
			}
		}()
		lg.Printf("ALSO serving SPA + API on host socket http://%s/ (password auth required); the tailnet path still works", cfg.HTTPListen)
	}

	// --- separate /healthz server, 127.0.0.1 only (DESIGN §4/§7) ---
	var healthy atomic.Bool
	healthy.Store(true) // tsnet is up by here
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if ne := st.Load().NetmapErr; ne != "" {
			fmt.Fprintf(w, "ok (netmap error: %s)\n", ne) // surface staleness; tsnet itself is up
			return
		}
		fmt.Fprintln(w, "ok")
	})
	hln, err := net.Listen("tcp", cfg.HealthAddr)
	if err != nil {
		return fmt.Errorf("healthz listen: %w", err)
	}
	healthSrv := &http.Server{Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := healthSrv.Serve(hln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Printf("healthz server: %v", err)
		}
	}()
	lg.Printf("healthz on http://%s/healthz (loopback only)", cfg.HealthAddr)

	// Tell systemd we're up, and keep the Type=notify watchdog fed (no-op when
	// not running under systemd). See deploy/tsctl.service.
	if err := sdNotify("READY=1"); err != nil {
		lg.Printf("sd_notify READY: %v", err)
	}
	startWatchdog(appCtx, lg)

	<-ctx.Done()
	lg.Printf("shutdown signal received; draining")
	if err := sdNotify("STOPPING=1"); err != nil {
		lg.Printf("sd_notify STOPPING: %v", err)
	}

	// Ordered shutdown (DESIGN §9, adapted for SSE): stop workers first by
	// cancelling appCtx -- this releases the long-lived SSE handlers (their
	// request contexts derive from appCtx via BaseContext, and the hub closes),
	// so the subsequent HTTP drain can actually complete. Then tsnet.Close.
	healthy.Store(false)
	appCancel()
	wg.Wait() // hub + poller stopped; SSE handlers have returned
	shCtx, shCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shCancel()
	if err := httpSrv.Shutdown(shCtx); err != nil {
		lg.Printf("tailnet http shutdown: %v", err)
	}
	if hostSrv != nil {
		if err := hostSrv.Shutdown(shCtx); err != nil {
			lg.Printf("host http shutdown: %v", err)
		}
	}
	if err := healthSrv.Shutdown(shCtx); err != nil {
		lg.Printf("healthz shutdown: %v", err)
	}
	if err := srv.Close(); err != nil {
		return fmt.Errorf("tsnet close: %w", err)
	}
	lg.Printf("clean shutdown")
	return nil
}

// buildMux assembles the full HTTP surface served IDENTICALLY on every listener
// (the tailnet listener, the optional host socket, and the demo loopback): the
// SPA static files, the REST API, and the auth-gated SSE stream. Both auth paths
// (tailnet WhoIs==owner, or a password session) flow through api.RequireAuth, so
// one handler serves them all. Go 1.22 mux: the more specific "/api/events" wins
// over "/api/".
func buildMux(apiH *api.API, hub *sse.Hub) http.Handler {
	mux := http.NewServeMux()
	// SSE: auth-gated AND host-pinned (DESIGN §7). RequireAuth admits the tailnet
	// owner OR a valid session; RequireHost rejects DNS rebinding.
	mux.Handle("/api/events", apiH.RequireAuth(apiH.RequireHost(hub)))
	mux.Handle("/api/", apiH.Routes())
	mux.Handle("/", http.FileServerFS(web.FS))
	return securityHeaders(mux)
}

// securityHeaders adds defense-in-depth response headers to every response —
// cheap hardening that matters most on the optional plain-HTTP host port. The CSP
// keeps the SPA fully working (same-origin scripts/styles, inline styles set via
// the DOM, data: SVGs) while blocking external/injected scripts, framing, and
// base-uri hijacking. The SPA is written CSP-clean (no inline <script>); scripts
// stay 'self'-only, which is the load-bearing XSS protection.
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// allowedHosts builds the Host-header allowlist for DNS-rebinding defense: the
// statically configured hosts (hostname, listen host, TSCTL_ALLOWED_HOSTS) plus
// the tsnet node's discovered MagicDNS FQDN and 100.x addresses (best-effort --
// a status read failure is logged, never fatal, never swallowed).
func allowedHosts(ctx context.Context, cfg *Config, lc *local.Client, lg *log.Logger) []string {
	hosts := append([]string(nil), cfg.AllowedHosts...)
	st, err := lc.Status(ctx)
	if err != nil {
		lg.Printf("warning: could not read self status for Host allowlist: %v", err)
		return hosts
	}
	if st == nil || st.Self == nil {
		return hosts
	}
	if dn := strings.TrimSuffix(st.Self.DNSName, "."); dn != "" {
		hosts = append(hosts, dn)
		if i := strings.IndexByte(dn, '.'); i > 0 {
			hosts = append(hosts, dn[:i]) // bare label
		}
	}
	for _, ip := range st.Self.TailscaleIPs {
		hosts = append(hosts, ip.String())
	}
	return hosts
}

// routerOptions builds router.Options from cfg. tailscaleDial is
// tsnet.Server.Dial for the tailscale-ssh transport (pass nil for ip-password,
// which dials the router's LAN endpoint with its own net.Dialer). Keyboard-
// interactive is enabled so older dropbear builds that advertise it instead of
// the password method still authenticate; it is ignored by the tailscale-ssh
// (`none` auth) transport.
func routerOptions(cfg *Config, tailscaleDial router.DialFunc) router.Options {
	return router.Options{
		Transport:           cfg.RouterTransport,
		TailscaleDial:       tailscaleDial,
		RouterAddrs:         cfg.RouterAddrs,
		User:                cfg.SSHUser,
		Password:            cfg.SSHPassword,
		KeyboardInteractive: true,
		HostKeyMode:         cfg.RouterHostKeyMode,
		KnownHostsPath:      cfg.KnownHostsPath,
		Timeout:             cfg.SSHTimeout,
		LANAccess:           cfg.ExitNodeLANAccess,
	}
}

// warnIfInsecureHostKey logs a loud warning when the ip-password transport runs
// with host-key verification disabled -- an active MITM on the LAN could then
// capture the SSH password. insecure is never the default (tofu is), so this
// only ever fires on an explicit opt-in.
func warnIfInsecureHostKey(cfg *Config, lg *log.Logger) {
	if cfg.RouterTransport == "ip-password" && cfg.RouterHostKeyMode == "insecure" {
		lg.Printf("WARNING: router transport ip-password with host-key mode 'insecure' -- router host keys are NOT verified; an active MITM on the LAN can capture the SSH password. Use tofu (default), strict, or pin instead.")
	}
}

// runSpike is a REAL, runnable diagnostic (DESIGN §9): it proves the CONFIGURED
// router transport end to end against ONE router, then prints a summary. Use it
// to prove the path before trusting the full binary.
//   - tailscale-ssh (default): bring tsnet up and dial the router's :22 over the
//     tailnet with `none` auth.
//   - ip-password: dial the router's MAPPED LAN endpoint with a plain net.Dialer,
//     the configured password, and host-key verification -- no tsnet needed, so
//     the password path is proven in isolation.
//
// Either way it runs `tailscale status --json`, parses it (the same router.Client
// the server uses), and prints online state + the current/available exit nodes.
func runSpike(addr string, lg *log.Logger) error {
	cfg, err := loadConfig(nil) // env + defaults; spike takes the addr positionally
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var tailscaleDial router.DialFunc
	switch cfg.RouterTransport {
	case "ip-password":
		// No tsnet needed -- the ip-password transport dials the LAN endpoint
		// directly. router.endpointFor fails loud below if addr is unmapped.
		warnIfInsecureHostKey(cfg, lg)
		lg.Printf("spike: ip-password transport -- dialing %s's mapped LAN endpoint %q (host-key mode %q)", addr, cfg.RouterAddrs[addr], cfg.RouterHostKeyMode)
	default: // tailscale-ssh
		srv := newTSNet(cfg, lg)
		defer srv.Close()
		upCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		_, err = srv.Up(upCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("tsnet up: %w", err)
		}
		lg.Printf("spike: tailscale-ssh transport -- tsnet up; dialing %s:22 over the tailnet", addr)
		tailscaleDial = srv.Dial
	}

	rc, err := router.New(routerOptions(cfg, tailscaleDial))
	if err != nil {
		return fmt.Errorf("router client: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, cfg.SSHTimeout+10*time.Second)
	defer cancel()
	rt, err := rc.Status(runCtx, addr) // dial + auth + host-key + run + parse
	if err != nil {
		return err // surfaces dial/handshake/host-key/auth failures and command stderr
	}

	current := "(none)"
	if rt.Current != nil {
		current = rt.Current.IP
		if rt.Current.Name != "" {
			current = fmt.Sprintf("%s (%s)", rt.Current.IP, rt.Current.Name)
		}
	}
	fmt.Printf("=== tailscale status --json @ %s via %s transport ===\n", addr, cfg.RouterTransport)
	fmt.Printf("online:            %t\n", rt.Online)
	fmt.Printf("current exit node: %s\n", current)
	fmt.Printf("exit-node options: %d\n", len(rt.Options))
	for _, o := range rt.Options {
		fmt.Printf("  - %s %s\n", o.IP, o.Name)
	}
	return nil
}

// runDemo serves the web UI offline against scripted fixtures (internal/demo).
// It NEVER starts tsnet and never touches the real serve/auth path: it wires the
// REAL store/sse/poller/api stack -- the exact same mux runServe builds -- but
// against a demo.World that plays the Mapper (Inventory+WhoIs) and RouterClient
// roles, on a PLAIN loopback listener. "What you see is what prod renders."
func runDemo(lg *log.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	world := demo.New()
	dgroups := demo.NewGroups() // in-memory sample zones (no file)

	// --- wiring (mirrors runServe, with the demo World as both edges) ---
	st := store.New()
	hub := sse.New(st, api.EncodeSnapshot)
	// Short poll interval so live SSE updates (ticking stats, the flipping node)
	// are visibly streamed to the browser.
	pol := poller.New(st, world, world, dgroups, world.RouterIPs(), hub, hub.Transitions(), demo.TickInterval, lg.Printf)
	pol.ConfigureEgress(true, defaultEgressURL) // exercise the egress ✓/✗ indicator in the demo
	demoCfg := api.Config{Owner: demo.Owner, AllowedHosts: world.AllowedHosts(), Groups: dgroups}
	// Optional password-preview: with TSCTL_UI_PASSWORD set, disable the auto-owner
	// path so the login overlay (the host-port/session UI) is exercised offline.
	if pw := os.Getenv("TSCTL_UI_PASSWORD"); pw != "" {
		demoCfg.Owner = ""
		demoCfg.UIPassword = pw
		lg.Printf("demo: password mode -- sign in with TSCTL_UI_PASSWORD")
	}
	apiH := api.New(st, world, pol, demoCfg)

	// Long-lived workers run off appCtx so shutdown stops them in order; SSE
	// request contexts derive from appCtx (BaseContext) so cancelling it releases
	// the long-lived handlers and the HTTP drain can complete.
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		if err := hub.Run(appCtx); err != nil && !errors.Is(err, context.Canceled) {
			lg.Printf("sse hub stopped: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := pol.Run(appCtx); err != nil && !errors.Is(err, context.Canceled) {
			lg.Printf("poller stopped: %v", err)
		}
	}()
	go func() { defer wg.Done(); world.Run(appCtx) }() // time-variation goroutine

	// EXACTLY the mux runServe builds: SSE (auth+host gated), REST API, SPA.
	mux := buildMux(apiH, hub)

	ln, err := net.Listen("tcp", demoListen) // PLAIN loopback -- no tsnet
	if err != nil {
		return fmt.Errorf("demo listen: %w", err)
	}
	httpSrv := &http.Server{
		Handler:           mux,
		WriteTimeout:      0, // SSE: a write deadline silently kills long-lived streams
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return appCtx },
	}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Printf("demo http server: %v", err)
		}
	}()

	lg.Printf("demo UI (offline, no tsnet) on http://%s/ -- Ctrl-C to stop", demoListen)
	fmt.Printf("\n  tsctl demo: open http://%s/ in your browser\n\n", demoListen)

	<-ctx.Done()
	lg.Printf("shutdown signal received; draining")
	appCancel()
	wg.Wait()
	shCtx, shCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shCancel()
	if err := httpSrv.Shutdown(shCtx); err != nil {
		lg.Printf("demo http shutdown: %v", err)
	}
	lg.Printf("clean shutdown")
	return nil
}
