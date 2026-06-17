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
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"tailscale.com/tsnet"

	"github.com/lifeart/tsctl/internal/api"
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
)

func main() {
	lg := log.New(os.Stderr, "tsctl: ", log.LstdFlags|log.Lmsgprefix)

	args := os.Args[1:]
	if len(args) > 0 && args[0] == "spike" {
		if len(args) < 2 {
			lg.Fatal("usage: tsctl spike <router-100.x-ipv4>")
		}
		if err := runSpike(args[1], lg); err != nil {
			lg.Fatalf("spike: %v", err)
		}
		return
	}
	if err := runServe(args, lg); err != nil {
		lg.Fatalf("%v", err)
	}
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
	rc := router.New(srv.Dial, cfg.SSHUser, cfg.SSHTimeout)
	hub := sse.New()
	pol := poller.New(st, mapper, rc, cfg.Routers, hub, lg.Printf)
	apiH := api.New(st, mapper, pol)

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

	// tailnet HTTP surface: SPA + REST + SSE. Go 1.22 mux: the more specific
	// "/api/events" wins over "/api/".
	mux := http.NewServeMux()
	mux.Handle("/api/events", hub)
	mux.Handle("/api/", apiH.Routes())
	mux.Handle("/", http.FileServerFS(web.FS))

	ln, err := srv.Listen("tcp", cfg.Listen) // tailnet-only by construction; never Funnel (DESIGN §7)
	if err != nil {
		return fmt.Errorf("tsnet listen: %w", err)
	}
	httpSrv := &http.Server{
		Handler:           mux,
		WriteTimeout:      0, // SSE: a write deadline silently kills long-lived streams (DESIGN §2)
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Printf("tailnet http server: %v", err)
		}
	}()

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

	// Ordered shutdown (DESIGN §9): drain HTTP -> stop workers -> tsnet.Close.
	shCtx, shCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shCancel()
	healthy.Store(false)
	if err := httpSrv.Shutdown(shCtx); err != nil {
		lg.Printf("tailnet http shutdown: %v", err)
	}
	if err := healthSrv.Shutdown(shCtx); err != nil {
		lg.Printf("healthz shutdown: %v", err)
	}
	appCancel()
	wg.Wait()
	if err := srv.Close(); err != nil {
		return fmt.Errorf("tsnet close: %w", err)
	}
	lg.Printf("clean shutdown")
	return nil
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
