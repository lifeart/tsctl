// Package poller runs the idle-aware refresh loop that builds Snapshots.
//
// It declares the consumer-side interfaces it depends on (Netmapper,
// RouterClient) and the RouterRuntime type, per DESIGN §4: interfaces live at
// the CONSUMER to avoid import cycles. The concrete *netmap.Mapper and
// *router.Client are injected by the composition root (cmd/tsctl), so this
// package never imports netmap or router.
//
// FROZEN CONTRACT: the interface and type names below are the seam.
package poller

import (
	"context"
	"errors"

	"golang.org/x/sync/singleflight"

	"github.com/lifeart/tsctl/internal/store"
)

// RouterRuntime is the parsed result of `tailscale status --json` on a router:
// its current exit node, the selectable options, and its own stats. Produced by
// router.ParseStatus (a pure function) and by RouterClient.
type RouterRuntime struct {
	Current *store.ExitNodeRef  // currently selected exit node (nil = none)
	Options []store.ExitNodeRef // selectable exit nodes (ExitNodeOption == true)
	Stats   store.RouterStats   // the router node's own counters
	Online  bool                // router self-reports online
}

// Netmapper supplies inventory from the tsnet node's local netmap.
// Implemented by *netmap.Mapper.
type Netmapper interface {
	Inventory(ctx context.Context) ([]store.NodeView, error)
}

// RouterClient talks to a single OpenWRT router over Tailscale SSH.
// Implemented by *router.Client. addr is the router's 100.x IPv4 (no port).
type RouterClient interface {
	Status(ctx context.Context, addr string) (RouterRuntime, error)
	SetExitNode(ctx context.Context, addr string, target *store.ExitNodeRef, prev *store.ExitNodeRef) (RouterRuntime, error)
}

// Logf is the minimal logging sink the poller surfaces stub/refresh errors to.
// (Errors are never swallowed -- DESIGN §6/§8.)
type Logf func(format string, args ...any)

// Poller owns the refresh loop and writes Snapshots into the Store.
type Poller struct {
	store   *store.Store
	nm      Netmapper
	rc      RouterClient
	routers []string // router 100.x IPv4s
	logf    Logf
	group   singleflight.Group // collapse concurrent first-viewer refreshes (DESIGN §6)
}

// New constructs a Poller. logf must be non-nil; pass log.Printf or similar.
func New(st *store.Store, nm Netmapper, rc RouterClient, routers []string, logf Logf) *Poller {
	return &Poller{store: st, nm: nm, rc: rc, routers: routers, logf: logf}
}

// Refresh builds one fresh Snapshot (inventory + per-router status) and stores
// it, gated through singleflight so concurrent first-loads collapse to one
// fetch. Phase B implements the body.
func (p *Poller) Refresh(ctx context.Context) error {
	_, err, _ := p.group.Do("refresh", func() (any, error) {
		return nil, errors.New("not implemented: poller.Refresh")
	})
	return err
}

// Run is the idle-aware loop. Phase B implements 0->1 / 1->0 client-count
// transitions and ~45s linger. The scaffold attempts one refresh (surfacing the
// not-implemented error -- never swallowed) and then blocks until ctx is
// cancelled by the composition root's ordered shutdown.
func (p *Poller) Run(ctx context.Context) error {
	if err := p.Refresh(ctx); err != nil {
		p.logf("poller: initial refresh: %v", err)
	}
	<-ctx.Done()
	return ctx.Err()
}
