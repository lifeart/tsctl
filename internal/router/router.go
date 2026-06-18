// Package router talks to OpenWRT routers over SSH.
//
// Connect-per-action (DESIGN §2/§6): for each Status/SetExitNode we dial fresh,
// run one command with x/crypto/ssh, capture stdout+stderr+exit code, and close.
// No long-lived *ssh.Client.
//
// Two transports plug into the SAME runSSH seam (see Options/New):
//   - tailscale-ssh (DEFAULT): dial over the tailnet (tsnet.Server.Dial), `none`
//     auth -- the ACL grants tagged src action:accept -- and an InsecureIgnore
//     host key (safe: WireGuard authenticates the peer; DESIGN §7).
//   - ip-password (opt-in): dial the router's LAN endpoint with a plain
//     net.Dialer, authenticate with a password (+ keyboard-interactive dropbear
//     fallback), and VERIFY the host key via known_hosts (see hostkey.go).
//
// The 100.x IPv4 stays the canonical router identity everywhere (poller, exitArg,
// store keys, Status/SetExitNode addr arg). Only the ip-password transport maps
// that identity to a LAN dial target, and ONLY at the runSSH boundary.
//
// ParseStatus is a PURE function (DESIGN §4): golden-fixture tested,
// version-tolerant. *Client implements poller.RouterClient.
package router

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"tailscale.com/ipn/ipnstate"

	"github.com/lifeart/tsctl/internal/store"
)

// DialFunc dials a tailnet address; satisfied by tsnet.Server.Dial.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// commandRunner is the command-execution seam (test seam). The real
// implementation runs the command over Tailscale SSH (sshRunnerFunc -> runSSH);
// tests inject a fake so Status/SetExitNode are exercisable without a live SSH
// server. Returning a non-zero exit with err==nil means "the command ran and
// failed" -- a RESULT, distinct from a transport error.
type commandRunner interface {
	run(ctx context.Context, addr, cmd string) (stdout, stderr []byte, exit int, err error)
}

// sshRunnerFunc adapts a func (e.g. (*Client).runSSH) to commandRunner.
type sshRunnerFunc func(ctx context.Context, addr, cmd string) (stdout, stderr []byte, exit int, err error)

func (f sshRunnerFunc) run(ctx context.Context, addr, cmd string) ([]byte, []byte, int, error) {
	return f(ctx, addr, cmd)
}

// CommandError reports a router command that RAN but exited non-zero (a result,
// not a transport failure). It carries the command's stderr as a first-class
// field so callers can surface it -- the api layer reads Stderr() into the
// {stderr} response field (PHASE_B §3) rather than relying on it being baked
// into the message string. errors.As(err, &*CommandError) (or the structural
// interface{ Stderr() string }) reaches it, including through the %w-wrapped
// confirm-read failure in SetExitNode.
type CommandError struct {
	Addr       string // router 100.x IPv4
	Cmd        string // human label of the command that failed
	StderrText string // raw command stderr (untrimmed)
	Exit       int    // the non-zero exit code
}

// Error renders the same message shape the call sites used before CommandError
// existed: "router <addr>: <cmd> exited <n>: <trimmed stderr>".
func (e *CommandError) Error() string {
	return fmt.Sprintf("router %s: %s exited %d: %s", e.Addr, e.Cmd, e.Exit, e.Stderr())
}

// Stderr returns the trimmed command stderr; the api surfaces it in {stderr}.
func (e *CommandError) Stderr() string { return strings.TrimSpace(e.StderrText) }

// Client runs commands on routers over SSH (transport set by New, see Options).
type Client struct {
	dial    DialFunc
	user    string        // OpenWRT login, "root" in v1 (DESIGN §7)
	timeout time.Duration // per dial/exec deadline

	// Transport knobs, set by New per the selected transport and consumed ONLY
	// at the runSSH boundary (the 100.x identity is unchanged everywhere else):
	//   - endpointFor maps the canonical 100.x addr to the "host:port" to dial.
	//     tailscale-ssh => addr+":22"; ip-password => the configured LAN endpoint
	//     (errors loudly if a router has no mapping -- never falls back silently).
	//   - authMethods is nil for tailscale-ssh (`none` auth) or [Password, ...]
	//     for ip-password.
	//   - hostKey is InsecureIgnoreHostKey for tailscale-ssh (safe: WireGuard
	//     authenticates the peer) or a verifying known_hosts callback otherwise.
	endpointFor func(addr string) (string, error)
	authMethods []ssh.AuthMethod
	hostKey     ssh.HostKeyCallback

	runner    commandRunner // defaults to the real ssh runner built from dial
	newMarker func() string // keep-marker path generator; settable for tests

	// lanAccess controls the ONLY non-exit-node preference tsctl ever touches.
	// nil (default) = PRESERVE: emit a bare `tailscale set --exit-node=...` so the
	// router keeps whatever --exit-node-allow-lan-access it already has (and every
	// other pref -- `set` is incremental, unlike `up`). Non-nil = tsctl manages it,
	// appending --exit-node-allow-lan-access=<v> when SETTING an exit node.
	lanAccess *bool

	// Per-addr serialization (DESIGN §6: one command in flight per router). A
	// keyed mutex -- NOT singleflight, which dedups concurrent identical work;
	// here we need mutual exclusion so two SetExitNode calls to one router can't
	// race independent dead-man's-switch markers and a Status read can't observe
	// a half-applied `set`.
	muLocks sync.Mutex
	locks   map[string]*sync.Mutex
}

// Options configures a router Client and its command transport. Transport
// selects how runSSH reaches a router; everything else (the dead-man's-switch,
// per-addr lock, ParseStatus, the frozen poller.RouterClient seam) is identical
// across transports.
type Options struct {
	// Transport is "tailscale-ssh" (default; "" is treated as the default) or
	// "ip-password". Any other value is an error.
	Transport string

	// TailscaleDial dials over the tailnet (tsnet.Server.Dial). REQUIRED for the
	// tailscale-ssh transport; ignored for ip-password.
	TailscaleDial DialFunc

	// RouterAddrs maps a router's canonical 100.x identity to the LAN endpoint to
	// dial ("host" or "host:port"; ":22" is appended when no port is given). Used
	// ONLY by ip-password. A missing mapping is a loud, use-time error.
	RouterAddrs map[string]string

	// User is the SSH login ("root" in v1). Password is the SSH password for the
	// ip-password transport (loaded as a secret; never logged). KeyboardInteractive
	// also offers the keyboard-interactive method (answering every prompt with the
	// password) as a fallback for older dropbear builds.
	User                string
	Password            string
	KeyboardInteractive bool

	// HostKeyMode selects host-key verification for ip-password: "tofu" (default),
	// "strict", "pin", or "insecure" (see hostkey.go). KnownHostsPath is the
	// known_hosts file used by tofu/strict/pin.
	HostKeyMode    string
	KnownHostsPath string

	// Timeout is the per dial/exec deadline. LANAccess is nil to PRESERVE the
	// router's existing --exit-node-allow-lan-access (the safe default), or non-nil
	// for tsctl to manage that one flag when setting an exit node.
	Timeout   time.Duration
	LANAccess *bool
}

// New constructs a router Client for the transport in opts. It returns an error
// (never a half-built client) if the transport is unknown or its required inputs
// are missing -- e.g. tailscale-ssh without a dial func, ip-password without a
// password, or a known_hosts/host-key mode that cannot be built. Fail-closed.
func New(opts Options) (*Client, error) {
	c := &Client{
		user:      opts.User,
		timeout:   opts.Timeout,
		lanAccess: opts.LANAccess,
		newMarker: defaultMarker,
		locks:     make(map[string]*sync.Mutex),
	}

	switch opts.Transport {
	case "", "tailscale-ssh":
		if opts.TailscaleDial == nil {
			return nil, errors.New("router: tailscale-ssh transport requires a dial func (tsnet.Server.Dial)")
		}
		c.dial = opts.TailscaleDial
		// Identity == endpoint: dial the router's 100.x over the tailnet on :22.
		c.endpointFor = func(addr string) (string, error) { return net.JoinHostPort(addr, "22"), nil }
		c.authMethods = nil // `none` auth: ACL grants tagged src action:accept (DESIGN §2/§7)
		// HostKeyCallback: ssh.InsecureIgnoreHostKey is DELIBERATE here (DESIGN §7) --
		// tsnet.Dial only reaches the WireGuard-authenticated peer, there is no
		// known_hosts, and this is NOT a silent skip.
		c.hostKey = ssh.InsecureIgnoreHostKey()

	case "ip-password":
		if opts.Password == "" {
			return nil, errors.New("router: ip-password transport requires a password")
		}
		c.dial = (&net.Dialer{}).DialContext
		// Resolve the 100.x identity to a LAN endpoint; FAIL LOUD if unmapped --
		// never silently fall back to the tailnet path (a missing mapping would
		// otherwise dial the userspace 100.x, which a host net.Dialer can't reach).
		addrs := opts.RouterAddrs
		c.endpointFor = func(addr string) (string, error) {
			ep := strings.TrimSpace(addrs[addr])
			if ep == "" {
				return "", fmt.Errorf("router %s: no LAN endpoint mapping for the ip-password transport "+
					"(add it to -router-addrs / TSCTL_ROUTER_ADDRS as %s=host[:port])", addr, addr)
			}
			return ensurePort(ep), nil
		}
		auth := []ssh.AuthMethod{ssh.Password(opts.Password)}
		if opts.KeyboardInteractive {
			pw := opts.Password
			// Older dropbear may advertise keyboard-interactive instead of password:
			// answer every challenge with the same password.
			auth = append(auth, ssh.KeyboardInteractive(
				func(name, instruction string, questions []string, echos []bool) ([]string, error) {
					answers := make([]string, len(questions))
					for i := range answers {
						answers[i] = pw
					}
					return answers, nil
				}))
		}
		c.authMethods = auth
		hk, err := hostKeyCallback(opts.HostKeyMode, opts.KnownHostsPath)
		if err != nil {
			return nil, err
		}
		c.hostKey = hk

	default:
		return nil, fmt.Errorf("router: unknown transport %q (want tailscale-ssh or ip-password)", opts.Transport)
	}

	c.runner = sshRunnerFunc(c.runSSH)
	return c, nil
}

// ensurePort appends the default SSH port to a LAN endpoint that has none. It
// handles bare hostnames/IPv4 ("host" -> "host:22"), bracketless IPv6
// ("fe80::1" -> "[fe80::1]:22"), and leaves an explicit port untouched.
func ensurePort(endpoint string) string {
	if _, _, err := net.SplitHostPort(endpoint); err == nil {
		return endpoint // already host:port
	}
	return net.JoinHostPort(endpoint, "22")
}

// lockAddr acquires the per-router lock for addr, creating it on first use, and
// returns the unlock func. The whole Status call and the whole SetExitNode
// arm→apply→confirm→keep sequence hold this lock so commands to the SAME router
// are strictly serialized (DESIGN §6). Different routers proceed in parallel.
// The map is created lazily so a Client built directly (tests) needs no New().
func (c *Client) lockAddr(addr string) func() {
	c.muLocks.Lock()
	if c.locks == nil {
		c.locks = make(map[string]*sync.Mutex)
	}
	m := c.locks[addr]
	if m == nil {
		m = &sync.Mutex{}
		c.locks[addr] = m
	}
	c.muLocks.Unlock()
	m.Lock()
	return m.Unlock
}

// Status reads `tailscale status --json` from the router and parses it.
// addr is the router's 100.x IPv4 (no port). It holds the per-router lock for
// the whole call so it cannot interleave with an in-flight SetExitNode (§6).
func (c *Client) Status(ctx context.Context, addr string) (store.RouterRuntime, error) {
	unlock := c.lockAddr(addr)
	defer unlock()
	return c.status(ctx, addr)
}

// status is the unlocked core of Status. SetExitNode calls it for the confirm
// read while ALREADY holding the per-router lock, so it must not relock (a
// sync.Mutex is not reentrant -- relocking would deadlock).
func (c *Client) status(ctx context.Context, addr string) (store.RouterRuntime, error) {
	stdout, stderr, exit, err := c.runner.run(ctx, addr, statusCmd)
	if err != nil {
		return store.RouterRuntime{}, fmt.Errorf("router %s: status: %w", addr, err)
	}
	if exit != 0 {
		return store.RouterRuntime{}, &CommandError{Addr: addr, Cmd: fmt.Sprintf("%q", statusCmd), StderrText: string(stderr), Exit: exit}
	}
	return ParseStatus(stdout)
}

// SetExitNode applies the dead-man's-switch sequence (DESIGN §8, PHASE_B §6):
// ARM a self-reverting timer on the router, APPLY the change, CONFIRM the actual
// selection by re-reading status, and KEEP (cancel the revert) only on success.
// On any failure the keep-marker is left untouched so the armed revert fires and
// the router self-heals; the runtime we could read is returned with a non-nil
// error (never swallowed). target/prev nil or empty IP means "clear".
func (c *Client) SetExitNode(ctx context.Context, addr string, target *store.ExitNodeRef, prev *store.ExitNodeRef) (store.RouterRuntime, error) {
	targetArg, err := exitArg(target)
	if err != nil {
		return store.RouterRuntime{}, fmt.Errorf("router %s: target: %w", addr, err)
	}
	prevArg, err := exitArg(prev)
	if err != nil {
		return store.RouterRuntime{}, fmt.Errorf("router %s: prev: %w", addr, err)
	}
	setting := targetArg != ""
	marker := c.newMarker()

	// Serialize the whole arm→apply→confirm→keep sequence against any other
	// command to this router (DESIGN §6). Acquired after the pure arg validation
	// (which never touches the router). The confirm read below uses c.status, the
	// UNLOCKED core, so it does not relock and deadlock.
	unlock := c.lockAddr(addr)
	defer unlock()

	// 1. ARM (DESIGN §8 step 2): schedule a revert to prev unless the keep-marker
	// appears within the window. Backend can't revert if the link dies, so this
	// runs locally on the router.
	if _, stderr, exit, err := c.runner.run(ctx, addr, armCmd(marker, prevArg)); err != nil {
		return store.RouterRuntime{}, fmt.Errorf("router %s: arm revert: %w", addr, err)
	} else if exit != 0 {
		return store.RouterRuntime{}, &CommandError{Addr: addr, Cmd: "arm revert", StderrText: string(stderr), Exit: exit}
	}

	// 2. APPLY (step 3). The marker is NOT written yet, so if anything below
	// fails the armed revert fires and the router self-heals to prev.
	if _, stderr, exit, err := c.runner.run(ctx, addr, applyCmd(targetArg, setting, c.lanAccess)); err != nil {
		return store.RouterRuntime{}, fmt.Errorf("router %s: apply exit-node: %w", addr, err)
	} else if exit != 0 {
		return store.RouterRuntime{}, &CommandError{Addr: addr, Cmd: "apply exit-node", StderrText: string(stderr), Exit: exit}
	}

	// 3. CONFIRM (step 4): re-read the actual selection over the tailnet (an
	// exit-node change does not sever the control path). Uses the unlocked core
	// since we already hold the per-router lock.
	//
	// KNOWN LIMITATION (v1, Sec-M4 — deferred, see README "Known limitations"):
	// "confirmed" here means the device REPORTS the target exit node selected and
	// is reachable over the tailnet (a selection + tailnet-reachability match). It
	// does NOT verify actual internet EGRESS through the exit node. And there is
	// no explicit user "Keep" (DESIGN §8 step 5): we auto-KEEP on confirmation, so
	// the armed revert only fires if the device cannot be confirmed AT ALL (apply
	// failed, confirm read failed, or the selection didn't take). An explicit-user
	// "Keep" within the window plus an egress reachability probe are planned, not
	// implemented in v1.
	rt, statusErr := c.status(ctx, addr)
	if statusErr != nil {
		return rt, fmt.Errorf("router %s: confirm read failed (revert will fire): %w", addr, statusErr)
	}
	if !confirmed(rt, targetArg, setting) {
		return rt, fmt.Errorf("router %s: exit-node not confirmed (revert will fire): want %s, got %s",
			addr, describeArg(targetArg), describeCurrent(rt))
	}

	// 4. KEEP (step 5): only on confirmed success drop the marker so the sleeping
	// revert sees it and exits without reverting.
	if _, stderr, exit, err := c.runner.run(ctx, addr, keepCmd(marker)); err != nil {
		return rt, fmt.Errorf("router %s: keep marker (revert may fire): %w", addr, err)
	} else if exit != 0 {
		return rt, &CommandError{Addr: addr, Cmd: "keep marker (revert may fire)", StderrText: string(stderr), Exit: exit}
	}
	return rt, nil
}

// Probe runs a READ-ONLY diagnostic on the router over the SAME transport/runner
// as Status (per-addr lock + per-command timeout). It changes no state. addr is
// the router's 100.x IPv4 (no port). On success it returns the command's trimmed
// stdout; a non-zero exit returns a *CommandError carrying stderr (the same error
// type Status surfaces); a transport/auth/host-key failure is returned verbatim.
func (c *Client) Probe(ctx context.Context, addr string) (string, error) {
	unlock := c.lockAddr(addr)
	defer unlock()

	stdout, stderr, exit, err := c.runner.run(ctx, addr, probeCmd)
	if err != nil {
		return "", fmt.Errorf("router %s: probe: %w", addr, err)
	}
	if exit != 0 {
		return "", &CommandError{Addr: addr, Cmd: "probe", StderrText: string(stderr), Exit: exit}
	}
	return strings.TrimSpace(string(stdout)), nil
}

// ParseStatus turns the bytes of `tailscale status --json` into a RouterRuntime.
// Pure and version-tolerant.
func ParseStatus(raw []byte) (store.RouterRuntime, error) {
	// anchor: this is the exact wire shape ParseStatus consumes (DESIGN §4).
	var st ipnstate.Status
	if err := json.Unmarshal(raw, &st); err != nil {
		return store.RouterRuntime{}, fmt.Errorf("router: parse tailscale status --json: %w", err)
	}

	var rt store.RouterRuntime
	if st.Self != nil {
		rt.Online = st.Self.Online
	}

	// Collect selectable options and locate the in-use exit node (the peer whose
	// ExitNode bit is set).
	var current *ipnstate.PeerStatus
	for _, p := range st.Peer {
		if p == nil {
			continue
		}
		if p.ExitNodeOption {
			rt.Options = append(rt.Options, peerToRef(p))
		}
		if p.ExitNode {
			current = p
		}
	}
	// Map iteration is random; sort options for a stable, testable order.
	sort.Slice(rt.Options, func(i, j int) bool { return rt.Options[i].StableID < rt.Options[j].StableID })

	switch {
	case current != nil:
		ref := peerToRef(current)
		rt.Current = &ref
		rt.Stats = store.RouterStats{
			RxBytes:       current.RxBytes,
			TxBytes:       current.TxBytes,
			LastHandshake: current.LastHandshake,
		}
	case st.ExitNodeStatus != nil:
		// Fallback: some daemon versions report the selection only via the
		// top-level ExitNodeStatus without flipping a peer's ExitNode bit.
		ref := store.ExitNodeRef{
			StableID: string(st.ExitNodeStatus.ID),
			IP:       firstIPv4Prefix(st.ExitNodeStatus.TailscaleIPs),
		}
		for _, p := range st.Peer {
			if p == nil || p.ID != st.ExitNodeStatus.ID {
				continue
			}
			ref.Name = trimDNSName(p.DNSName)
			if ref.IP == "" {
				ref.IP = firstIPv4Addr(p.TailscaleIPs)
			}
			rt.Stats = store.RouterStats{
				RxBytes:       p.RxBytes,
				TxBytes:       p.TxBytes,
				LastHandshake: p.LastHandshake,
			}
			break
		}
		rt.Current = &ref
	}
	return rt, nil
}

// runSSH resolves addr (the canonical 100.x identity) to the transport's dial
// endpoint, dials it, runs one command over an SSH session, and returns stdout,
// stderr and the exit code. Non-zero exit is a RESULT (returned with err==nil
// and exitCode set); only transport/dial/handshake failures are errors. Context
// cancellation closes the session (sessions predate context).
//
// The Auth and HostKeyCallback come from the transport selected in New: `none`
// auth + InsecureIgnoreHostKey for tailscale-ssh (safe -- WireGuard authenticates
// the peer), or password auth + a verifying known_hosts callback for ip-password.
// This is the ONLY place identity->endpoint translation and the auth/host-key
// swap happen; everything else treats addr as the canonical 100.x.
func (c *Client) runSSH(ctx context.Context, addr, cmd string) (stdout, stderr []byte, exitCode int, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	endpoint, err := c.endpointFor(addr)
	if err != nil {
		return nil, nil, 0, err
	}
	conn, err := c.dial(ctx, "tcp", endpoint)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("dial %s: %w", endpoint, err)
	}

	// Bound the SSH handshake (M1): ClientConfig.Timeout does NOT cover
	// ssh.NewClientConn, and the ctx watcher below is only armed AFTER the
	// handshake. Without a deadline a stalled router hangs this goroutine
	// forever which -- combined with the per-router lock (H3) and the poller --
	// freezes all polling. Set the deadline before the handshake; clear it once
	// the handshake succeeds so it doesn't also bound the session.
	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		_ = conn.Close()
		return nil, nil, 0, fmt.Errorf("set handshake deadline %s: %w", endpoint, err)
	}

	config := &ssh.ClientConfig{
		User:            c.user,
		Auth:            c.authMethods, // nil (`none`) for tailscale-ssh; password (+ki) for ip-password
		HostKeyCallback: c.hostKey,     // Insecure for tailscale-ssh (WireGuard auths); verifying for ip-password
		Timeout:         c.timeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, endpoint, config)
	if err != nil {
		_ = conn.Close()
		return nil, nil, 0, fmt.Errorf("ssh handshake %s: %w", endpoint, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs) // takes ownership of conn
	defer client.Close()

	// Handshake done: clear the deadline so it does not bound the session run.
	// ctx (and the watcher below) governs the per-command timeout from here.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, nil, 0, fmt.Errorf("clear handshake deadline %s: %w", endpoint, err)
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ssh session %s: %w", endpoint, err)
	}

	// Cap captured output (M2): the buffers are otherwise unbounded, so a
	// compromised/flooding router could OOM the control node. Overflow past the
	// cap is treated as an error below.
	outBuf := &cappedBuffer{max: maxOutputBytes}
	errBuf := &cappedBuffer{max: maxOutputBytes}
	session.Stdout = outBuf
	session.Stderr = errBuf

	// Context cancellation: ssh sessions predate context, so cancel by closing
	// the session on ctx.Done() (DESIGN §6).
	var closeOnce sync.Once
	closeSession := func() { closeOnce.Do(func() { _ = session.Close() }) }
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeSession()
		case <-done:
		}
	}()

	runErr := session.Run(cmd)
	close(done)
	closeSession()

	stdout = outBuf.Bytes()
	stderr = errBuf.Bytes()

	// Overflow protection (M2): if either stream blew the cap, fail the command
	// rather than trusting truncated output (a router flooding us is a fault).
	if outBuf.overflowed() || errBuf.overflowed() {
		return stdout, stderr, 0, fmt.Errorf("ssh run %q on %s: captured output exceeded %d-byte cap", cmd, endpoint, maxOutputBytes)
	}

	if runErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			// Non-zero exit is a RESULT, not a transport error (DESIGN §6).
			return stdout, stderr, exitErr.ExitStatus(), nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return stdout, stderr, 0, fmt.Errorf("ssh run on %s canceled: %w", endpoint, ctxErr)
		}
		return stdout, stderr, 0, fmt.Errorf("ssh run %q on %s: %w", cmd, endpoint, runErr)
	}
	return stdout, stderr, 0, nil
}

// maxOutputBytes caps stdout/stderr captured from a single command (M2). A few
// MiB is far more than any `tailscale status --json` or `set` output; anything
// past it is treated as a fault, not stored, so a router cannot OOM us.
const maxOutputBytes = 4 << 20 // 4 MiB per stream

// cappedBuffer is an io.Writer that stores at most max bytes and then flags an
// overflow, discarding the rest (it still reports the full length consumed so
// the ssh stream's copy loop neither errors nor blocks). The caller checks
// overflowed() and fails the command. Not safe for concurrent use; runSSH reads
// it only after session.Run returns, when no writer goroutine remains.
type cappedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.overflow {
		return len(p), nil // already over the cap: swallow the bytes, not the signal
	}
	if room := b.max - b.buf.Len(); len(p) > room {
		if room > 0 {
			b.buf.Write(p[:room])
		}
		b.overflow = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *cappedBuffer) Bytes() []byte    { return b.buf.Bytes() }
func (b *cappedBuffer) overflowed() bool { return b.overflow }

// --- command strings (DESIGN §8 / PHASE_B §6) ---------------------------------

const (
	statusCmd           = "tailscale status --json"
	revertWindowSeconds = 60 // dead-man's-switch window

	// probeCmd is the read-only diagnostic run by Probe: kernel/uname, uptime, load
	// average, and total/available memory. Portable across busybox/OpenWRT; reads
	// only, changes no state. It is BEST-EFFORT by design: the reads are independent
	// and `2>&1` folds any per-stage error into the output, then a trailing `true`
	// forces exit 0 -- so the probe's pass/fail reflects whether the SSH session RAN
	// (the thing being tested), NOT whether the last stage (awk/meminfo) happened to
	// succeed. A real SSH/auth/host-key failure still surfaces as a transport error
	// (not an exit code), so it is still correctly reported as a failure.
	probeCmd = "{ uname -snr; cat /proc/uptime; cat /proc/loadavg; awk '/^MemTotal:|^MemAvailable:/{print $1, $2, $3}' /proc/meminfo; } 2>&1; true"
)

// armCmd schedules a self-reverting timer that fires unless marker exists.
func armCmd(marker, prevArg string) string {
	return fmt.Sprintf("nohup sh -c 'sleep %d; [ -f %s ] && exit 0; tailscale set --exit-node=%s' >/dev/null 2>&1 &",
		revertWindowSeconds, marker, prevArg)
}

// applyCmd builds the incremental `tailscale set` that changes ONLY the exit node
// (every other pref -- advertise-routes, accept-routes, --ssh, accept-dns,
// hostname, advertise-tags -- is preserved because this is `set`, not `up`). The
// optional --exit-node-allow-lan-access is appended ONLY when SETTING an exit node
// AND the operator opted tsctl into managing it (lanAccess != nil); otherwise the
// router's existing value is preserved. (old signature below was setting-only.)
// only when SETTING, not when clearing (DESIGN §8 step 3).
func applyCmd(targetArg string, setting bool, lanAccess *bool) string {
	cmd := "tailscale set --exit-node=" + targetArg
	if setting && lanAccess != nil {
		cmd += fmt.Sprintf(" --exit-node-allow-lan-access=%t", *lanAccess)
	}
	return cmd
}

// keepCmd drops the keep-marker so the armed revert exits without reverting.
func keepCmd(marker string) string { return fmt.Sprintf(": > %s", marker) }

// --- helpers ------------------------------------------------------------------

// confirmed reports whether the re-read runtime matches the intended change.
// Comparison is by 100.x IPv4 (what we set with), per DESIGN §2.
func confirmed(rt store.RouterRuntime, targetArg string, setting bool) bool {
	if setting {
		return rt.Current != nil && rt.Current.IP == targetArg
	}
	return rt.Current == nil
}

// exitArg validates and returns the `--exit-node=` argument for a ref: "" to
// clear, otherwise the CANONICAL 100.x IPv4. It rejects anything that is not a
// plain IPv4 literal so nothing untrusted can be injected into the `sh -c`
// command line. Defense-in-depth on the injection chokepoint (low fix): the
// command only ever sees a re-serialized, validated IPv4 -- a zone id or an
// IPv6 form is refused outright.
func exitArg(ref *store.ExitNodeRef) (string, error) {
	if ref == nil || ref.IP == "" {
		return "", nil
	}
	addr, err := netip.ParseAddr(ref.IP)
	if err != nil {
		return "", fmt.Errorf("invalid exit-node IP %q: %w", ref.IP, err)
	}
	if addr.Zone() != "" {
		return "", fmt.Errorf("invalid exit-node IP %q: zone identifiers are not allowed", ref.IP)
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return "", fmt.Errorf("invalid exit-node IP %q: must be an IPv4 address (the router's 100.x)", ref.IP)
	}
	return addr.String(), nil // canonical, re-serialized form
}

// defaultMarker returns a unique per-op keep-marker path. The id is non-security
// critical (uniqueness only): unixnano guarantees per-op uniqueness, plus random
// hex for safety. Path chars are numeric/hex, so it is shell-safe by construction.
func defaultMarker() string {
	return fmt.Sprintf("/tmp/tsctl-keep-%d-%x", time.Now().UnixNano(), mrand.Uint32())
}

func peerToRef(p *ipnstate.PeerStatus) store.ExitNodeRef {
	return store.ExitNodeRef{
		StableID: string(p.ID),
		Name:     trimDNSName(p.DNSName),
		IP:       firstIPv4Addr(p.TailscaleIPs),
	}
}

// trimDNSName drops the trailing dot from a MagicDNS FQDN for display.
func trimDNSName(s string) string { return strings.TrimSuffix(s, ".") }

// firstIPv4Addr returns the first IPv4 (the 100.x) from a peer's TailscaleIPs.
func firstIPv4Addr(addrs []netip.Addr) string {
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap().String()
		}
	}
	return ""
}

// firstIPv4Prefix returns the first IPv4 from ExitNodeStatus.TailscaleIPs.
func firstIPv4Prefix(prefixes []netip.Prefix) string {
	for _, p := range prefixes {
		if a := p.Addr().Unmap(); a.Is4() {
			return a.String()
		}
	}
	return ""
}

func describeArg(arg string) string {
	if arg == "" {
		return "(none)"
	}
	return arg
}

func describeCurrent(rt store.RouterRuntime) string {
	if rt.Current == nil {
		return "(none)"
	}
	return rt.Current.IP
}
