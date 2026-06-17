// Package router talks to OpenWRT routers over Tailscale SSH.
//
// Connect-per-action (DESIGN §2/§6): for each Status/SetExitNode we dial fresh
// via the injected Dialer (tsnet.Server.Dial), run one command with x/crypto/ssh
// (`none` auth -- the ACL grants tagged src action:accept), capture
// stdout+stderr+exit code, and close. No long-lived *ssh.Client.
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

// Client runs commands on routers over Tailscale SSH.
type Client struct {
	dial    DialFunc
	user    string        // OpenWRT login, "root" in v1 (DESIGN §7)
	timeout time.Duration // per dial/exec deadline

	runner    commandRunner // defaults to the real ssh runner built from dial
	newMarker func() string // keep-marker path generator; settable for tests
}

// New constructs a router Client. dial is tsnet.Server.Dial; user is "root".
func New(dial DialFunc, user string, timeout time.Duration) *Client {
	c := &Client{dial: dial, user: user, timeout: timeout, newMarker: defaultMarker}
	c.runner = sshRunnerFunc(c.runSSH)
	return c
}

// Status reads `tailscale status --json` from the router and parses it.
// addr is the router's 100.x IPv4 (no port).
func (c *Client) Status(ctx context.Context, addr string) (store.RouterRuntime, error) {
	stdout, stderr, exit, err := c.runner.run(ctx, addr, statusCmd)
	if err != nil {
		return store.RouterRuntime{}, fmt.Errorf("router %s: status: %w", addr, err)
	}
	if exit != 0 {
		return store.RouterRuntime{}, fmt.Errorf("router %s: %q exited %d: %s", addr, statusCmd, exit, strings.TrimSpace(string(stderr)))
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

	// 1. ARM (DESIGN §8 step 2): schedule a revert to prev unless the keep-marker
	// appears within the window. Backend can't revert if the link dies, so this
	// runs locally on the router.
	if _, stderr, exit, err := c.runner.run(ctx, addr, armCmd(marker, prevArg)); err != nil {
		return store.RouterRuntime{}, fmt.Errorf("router %s: arm revert: %w", addr, err)
	} else if exit != 0 {
		return store.RouterRuntime{}, fmt.Errorf("router %s: arm revert exited %d: %s", addr, exit, strings.TrimSpace(string(stderr)))
	}

	// 2. APPLY (step 3). The marker is NOT written yet, so if anything below
	// fails the armed revert fires and the router self-heals to prev.
	if _, stderr, exit, err := c.runner.run(ctx, addr, applyCmd(targetArg, setting)); err != nil {
		return store.RouterRuntime{}, fmt.Errorf("router %s: apply exit-node: %w", addr, err)
	} else if exit != 0 {
		return store.RouterRuntime{}, fmt.Errorf("router %s: apply exit-node exited %d: %s", addr, exit, strings.TrimSpace(string(stderr)))
	}

	// 3. CONFIRM (step 4): re-read the actual selection over the tailnet (an
	// exit-node change does not sever the control path).
	rt, statusErr := c.Status(ctx, addr)
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
		return rt, fmt.Errorf("router %s: keep marker exited %d (revert may fire): %s", addr, exit, strings.TrimSpace(string(stderr)))
	}
	return rt, nil
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

// runSSH dials addr:22, runs one command over a `none`-auth SSH session, and
// returns stdout, stderr and the exit code. Non-zero exit is a RESULT (returned
// with err==nil and exitCode set); only transport/dial/handshake failures are
// errors. Context cancellation closes the session (sessions predate context).
//
// HostKeyCallback: ssh.InsecureIgnoreHostKey is DELIBERATE here (DESIGN §7) --
// tsnet.Dial only reaches the WireGuard-authenticated peer, there is no
// known_hosts, and this is NOT a silent skip.
func (c *Client) runSSH(ctx context.Context, addr, cmd string) (stdout, stderr []byte, exitCode int, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	hostport := net.JoinHostPort(addr, "22")
	conn, err := c.dial(ctx, "tcp", hostport)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("dial %s: %w", hostport, err)
	}

	config := &ssh.ClientConfig{
		User: c.user,
		Auth: nil, // `none` auth: ACL grants tagged src action:accept (DESIGN §2/§7)
		// HostKeyCallback: ssh.InsecureIgnoreHostKey is DELIBERATE here (DESIGN §7) --
		// tsnet.Dial only reaches the WireGuard-authenticated peer, there is no
		// known_hosts, and this is NOT a silent skip.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.timeout,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, hostport, config)
	if err != nil {
		_ = conn.Close()
		return nil, nil, 0, fmt.Errorf("ssh handshake %s: %w", hostport, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs) // takes ownership of conn
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ssh session %s: %w", hostport, err)
	}

	var outBuf, errBuf bytes.Buffer
	session.Stdout = &outBuf
	session.Stderr = &errBuf

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

	if runErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			// Non-zero exit is a RESULT, not a transport error (DESIGN §6).
			return stdout, stderr, exitErr.ExitStatus(), nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return stdout, stderr, 0, fmt.Errorf("ssh run on %s canceled: %w", hostport, ctxErr)
		}
		return stdout, stderr, 0, fmt.Errorf("ssh run %q on %s: %w", cmd, hostport, runErr)
	}
	return stdout, stderr, 0, nil
}

// --- command strings (DESIGN §8 / PHASE_B §6) ---------------------------------

const (
	statusCmd           = "tailscale status --json"
	revertWindowSeconds = 60 // dead-man's-switch window
)

// armCmd schedules a self-reverting timer that fires unless marker exists.
func armCmd(marker, prevArg string) string {
	return fmt.Sprintf("nohup sh -c 'sleep %d; [ -f %s ] && exit 0; tailscale set --exit-node=%s' >/dev/null 2>&1 &",
		revertWindowSeconds, marker, prevArg)
}

// applyCmd sets (or clears) the exit node. --exit-node-allow-lan-access is added
// only when SETTING, not when clearing (DESIGN §8 step 3).
func applyCmd(targetArg string, setting bool) string {
	if setting {
		return fmt.Sprintf("tailscale set --exit-node=%s --exit-node-allow-lan-access=true", targetArg)
	}
	return fmt.Sprintf("tailscale set --exit-node=%s", targetArg)
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
// clear, otherwise the 100.x IPv4. It rejects anything that is not a valid IP so
// nothing untrusted can be injected into the `sh -c` command line.
func exitArg(ref *store.ExitNodeRef) (string, error) {
	if ref == nil || ref.IP == "" {
		return "", nil
	}
	if _, err := netip.ParseAddr(ref.IP); err != nil {
		return "", fmt.Errorf("invalid exit-node IP %q: %w", ref.IP, err)
	}
	return ref.IP, nil
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
