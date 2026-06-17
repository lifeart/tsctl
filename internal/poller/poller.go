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

// RouterRuntime moved to package store (a leaf) so the router package depends
// only on store, never on poller -- the two Phase B packages stay build-
// decoupled. See store.RouterRuntime.

// Netmapper supplies inventory from the tsnet node's local netmap.
// Implemented by *netmap.Mapper.
type Netmapper interface {
	Inventory(ctx context.Context) ([]store.NodeView, error)
}

// RouterClient talks to a single OpenWRT router over Tailscale SSH.
// Implemented by *router.Client. addr is the router's 100.x IPv4 (no port).
type RouterClient interface {
	Status(ctx context.Context, addr string) (store.RouterRuntime, error)
	SetExitNode(ctx context.Context, addr string, target *store.ExitNodeRef, prev *store.ExitNodeRef) (store.RouterRuntime, error)
}

// Broadcaster receives each freshly built Snapshot for fan-out to SSE clients.
// Implemented by *sse.Hub. The poller calls Broadcast after every Store so the
// browser sees changes in real time; declared here (consumer side) so the
// poller never imports sse.
type Broadcaster interface {
	Broadcast(snap *store.Snapshot)
}

// Logf is the minimal logging sink the poller surfaces stub/refresh errors to.
// (Errors are never swallowed -- DESIGN §6/§8.)
type Logf func(format string, args ...any)

// Poller owns the refresh loop and writes Snapshots into the Store.
type Poller struct {
	store   *store.Store
	nm      Netmapper
	rc      RouterClient
	bc      Broadcaster
	routers []string // router 100.x IPv4s
	logf    Logf
	group   singleflight.Group // collapse concurrent first-viewer refreshes (DESIGN §6)
}

// New constructs a Poller. logf must be non-nil; pass log.Printf or similar.
// bc receives every freshly built Snapshot -- Phase B calls bc.Broadcast after
// each Store so SSE clients update in real time.
func New(st *store.Store, nm Netmapper, rc RouterClient, routers []string, bc Broadcaster, logf Logf) *Poller {
	return &Poller{store: st, nm: nm, rc: rc, bc: bc, routers: routers, logf: logf}
}

// SetExitNode is the api.Controller seam (DESIGN §8). It resolves routerID -> the
// router's addr and targetStableID -> *store.ExitNodeRef from the current
// snapshot, runs the dead-man's-switch SetExitNode on the RouterClient,
// reconciles the device's ACTUAL selection into a fresh Snapshot, Broadcasts it,
// and returns the updated RouterView. targetStableID == "" clears the exit node.
// Phase B implements the body.
func (p *Poller) SetExitNode(ctx context.Context, routerID, targetStableID string) (store.RouterView, error) {
	return store.RouterView{}, errors.New("not implemented: poller.SetExitNode")
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
