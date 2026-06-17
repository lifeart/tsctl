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
	"context"
	"errors"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"tailscale.com/ipn/ipnstate"

	"github.com/lifeart/tsctl/internal/poller"
	"github.com/lifeart/tsctl/internal/store"
)

// DialFunc dials a tailnet address; satisfied by tsnet.Server.Dial.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Client runs commands on routers over Tailscale SSH.
type Client struct {
	dial    DialFunc
	user    string        // OpenWRT login, "root" in v1 (DESIGN §7)
	timeout time.Duration // per dial/exec deadline
}

// New constructs a router Client. dial is tsnet.Server.Dial; user is "root".
func New(dial DialFunc, user string, timeout time.Duration) *Client {
	return &Client{dial: dial, user: user, timeout: timeout}
}

// Status reads `tailscale status --json` from the router and parses it.
// addr is the router's 100.x IPv4 (no port). Phase B fills in the body.
func (c *Client) Status(ctx context.Context, addr string) (poller.RouterRuntime, error) {
	return poller.RouterRuntime{}, errors.New("not implemented: router.Status")
}

// SetExitNode applies the dead-man's-switch sequence (DESIGN §8): arm a local
// revert on the router, apply `tailscale set --exit-node=<target.IP>` (empty
// clears), then re-read and reconcile. Phase B fills in the body.
func (c *Client) SetExitNode(ctx context.Context, addr string, target *store.ExitNodeRef, prev *store.ExitNodeRef) (poller.RouterRuntime, error) {
	return poller.RouterRuntime{}, errors.New("not implemented: router.SetExitNode")
}

// ParseStatus turns the bytes of `tailscale status --json` into a RouterRuntime.
// Pure and version-tolerant. Phase B unmarshals into ipnstate.Status and maps
// Self / Peer / ExitNodeStatus into the result.
func ParseStatus(raw []byte) (poller.RouterRuntime, error) {
	// anchor: this is the exact wire shape ParseStatus consumes (DESIGN §4).
	var _ ipnstate.Status
	return poller.RouterRuntime{}, errors.New("not implemented: router.ParseStatus")
}

// runSSH dials addr:22, runs one command over a `none`-auth SSH session, and
// returns stdout, stderr and the exit code. Phase B implements it.
//
// HostKeyCallback: ssh.InsecureIgnoreHostKey is DELIBERATE here (DESIGN §7) --
// tsnet.Dial only reaches the WireGuard-authenticated peer, there is no
// known_hosts, and this is NOT a silent skip.
func (c *Client) runSSH(ctx context.Context, addr, cmd string) (stdout, stderr []byte, exitCode int, err error) {
	var _ = &ssh.ClientConfig{
		User:            c.user,
		Auth:            nil, // `none` auth: ACL grants tagged src action:accept
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.timeout,
	}
	return nil, nil, 0, errors.New("not implemented: router.runSSH")
}
