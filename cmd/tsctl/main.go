// Command tsctl is the Tailscale exit-node manager. It joins the tailnet as its
// own tsnet node (tag:tsctl, persistent), serves a small web UI over the tailnet
// only, and lets the user set which exit node each OpenWRT router uses.
//
// This file is the composition root (DESIGN §5): config, tsnet Up->Listen,
// loopback /healthz, wiring, ordered graceful shutdown. Plus a `spike`
// subcommand that proves the SSH-over-tailnet path against a real router.
package main

import (
	"bytes"
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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"tailscale.com/client/local"
	"tailscale.com/tsnet"

	"github.com/lifeart/tsctl/internal/api"
	"github.com/lifeart/tsctl/internal/demo"
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
	_ api.WhoIser         = (*netmap.Mapper)(nil)
	_ api.Controller      = (*poller.Poller)(nil)

	// The demo World plays the Mapper (Netmapper+WhoIser) and RouterClient roles
	// against the SAME frozen seams, so `tsctl demo` exercises the real stack.
	_ poller.Netmapper    = (*demo.World)(nil)
	_ poller.RouterClient = (*demo.World)(nil)
	_ api.WhoIser         = (*demo.World)(nil)
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
	rc := router.New(srv.Dial, cfg.SSHUser, cfg.SSHTimeout, cfg.ExitNodeLANAccess)
	// hub.Transitions() drives the poller's idle suspension; api.EncodeSnapshot
	// makes SSE frames identical to the REST Snapshot DTO (PHASE_B §3).
	hub := sse.New(st, api.EncodeSnapshot)
	pol := poller.New(st, mapper, rc, cfg.Routers, hub, hub.Transitions(), cfg.PollInterval, lg.Printf)
	apiH := api.New(st, mapper, pol, api.Config{
		Owner:        cfg.Owner,
		UIPassword:   cfg.UIPassword,
		AllowedHosts: allowedHosts(ctx, cfg, lc, lg),
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
func buildMux(apiH *api.API, hub *sse.Hub) *http.ServeMux {
	mux := http.NewServeMux()
	// SSE: auth-gated AND host-pinned (DESIGN §7). RequireAuth admits the tailnet
	// owner OR a valid session; RequireHost rejects DNS rebinding.
	mux.Handle("/api/events", apiH.RequireAuth(apiH.RequireHost(hub)))
	mux.Handle("/api/", apiH.Routes())
	mux.Handle("/", http.FileServerFS(web.FS))
	return mux
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

// runSpike is a REAL, runnable diagnostic (DESIGN §9): bring tsnet up, dial the
// router's :22 over the tailnet, SSH with `none` auth, run `tailscale status
// --json`, and print stdout/stderr/exit code. Use it to prove the SSH path in a
// real tailnet before trusting the full binary.
func runSpike(addr string, lg *log.Logger) error {
	cfg, err := loadConfig(nil) // env + defaults; spike takes the addr positionally
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := newTSNet(cfg, lg)
	defer srv.Close()

	upCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	_, err = srv.Up(upCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("tsnet up: %w", err)
	}
	lg.Printf("tsnet up; dialing %s:22 over the tailnet", addr)

	target := net.JoinHostPort(addr, "22")
	dialCtx, dcancel := context.WithTimeout(ctx, cfg.SSHTimeout)
	defer dcancel()
	conn, err := srv.Dial(dialCtx, "tcp", target)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}

	sshConf := &ssh.ClientConfig{
		User: cfg.SSHUser,
		Auth: nil, // `none` auth: the ACL grants tagged src (tag:tsctl) action:accept (DESIGN §2/§7)
		// HostKeyCallback: ssh.InsecureIgnoreHostKey is DELIBERATE (DESIGN §7).
		// tsnet.Dial only reaches the WireGuard-authenticated peer; there is no
		// known_hosts and WireGuard already authenticates the peer. This is NOT a
		// silent host-key skip -- it is the documented, intended choice.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         cfg.SSHTimeout,
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, target, sshConf)
	if err != nil {
		conn.Close()
		return fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()

	// Sessions predate context; cancel by closing the session on ctx.Done (DESIGN §6).
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			sess.Close()
		case <-done:
		}
	}()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	const cmd = "tailscale status --json"
	exitCode := 0
	if runErr := sess.Run(cmd); runErr != nil {
		var ee *ssh.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitStatus() // non-zero exit is still a useful result
		} else {
			return fmt.Errorf("run %q: %w", cmd, runErr)
		}
	}

	fmt.Printf("=== %s @ %s (exit %d) ===\n", cmd, addr, exitCode)
	fmt.Printf("--- stdout (%d bytes) ---\n%s\n", stdout.Len(), stdout.String())
	if stderr.Len() > 0 {
		fmt.Printf("--- stderr ---\n%s\n", stderr.String())
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

	// --- wiring (mirrors runServe, with the demo World as both edges) ---
	st := store.New()
	hub := sse.New(st, api.EncodeSnapshot)
	// Short poll interval so live SSE updates (ticking stats, the flipping node)
	// are visibly streamed to the browser.
	pol := poller.New(st, world, world, world.RouterIPs(), hub, hub.Transitions(), demo.TickInterval, lg.Printf)
	demoCfg := api.Config{Owner: demo.Owner, AllowedHosts: world.AllowedHosts()}
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
