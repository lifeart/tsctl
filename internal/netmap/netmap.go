// Package netmap implements inventory and identity lookups over the tsnet
// node's LocalClient.Status() / WhoIs(). One Mapper, backed by a single
// *local.Client, satisfies BOTH consumer interfaces:
//
//	poller.Netmapper -> Inventory(ctx)
//	api.WhoIser       -> WhoIs(ctx, remoteAddr)
//
// (Both are LocalClient calls, so they share the one client.) The composition
// root injects the same *Mapper into the poller and the api middleware. Phase B
// fills in the bodies.
package netmap

import (
	"context"
	"errors"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"

	"github.com/lifeart/tsctl/internal/store"
)

// Mapper reads the tsnet node's netmap.
type Mapper struct {
	lc *local.Client
}

// New returns a Mapper backed by the tsnet server's LocalClient.
func New(lc *local.Client) *Mapper { return &Mapper{lc: lc} }

// Inventory returns every visible tailnet node as a NodeView, classifying each
// by NodeType. Phase B: call m.lc.Status(ctx), iterate Status.Peer, map fields.
// Surfaces a NetmapErr to the snapshot on error -- never swallowed (DESIGN §8).
func (m *Mapper) Inventory(ctx context.Context) ([]store.NodeView, error) {
	// Contract anchors -- the upstream shapes Phase B will consume:
	var _ *ipnstate.Status // <- m.lc.Status(ctx)
	var _ func(*ipnstate.PeerStatus) store.NodeType = classify
	return nil, errors.New("not implemented: netmap.Inventory")
}

// WhoIs identifies the caller behind remoteAddr (an IP or IP:port) via
// LocalClient.WhoIs. Fail-closed (DESIGN §7): on ANY error, callers must deny;
// tagged/shared/unknown peers are not the owner. Phase B fills in the body.
func (m *Mapper) WhoIs(ctx context.Context, remoteAddr string) (login string, tagged bool, err error) {
	return "", false, errors.New("not implemented: netmap.WhoIs")
}

// classify maps a peer to a NodeType. Phase B implements it; declared here so
// classification is owned by the netmap package and frozen as part of the seam.
func classify(p *ipnstate.PeerStatus) store.NodeType {
	// anchor: PeerStatus.ID is a tailcfg.StableNodeID (DESIGN §4 field reference).
	var _ tailcfg.StableNodeID = p.ID
	return store.NodeGeneric
}
