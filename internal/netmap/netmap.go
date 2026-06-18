// Package netmap implements inventory and identity lookups over the tsnet
// node's LocalClient.Status() / WhoIs(). One Mapper, backed by a single
// *local.Client, satisfies BOTH consumer interfaces:
//
//	poller.Netmapper -> Inventory(ctx)
//	api.WhoIser       -> WhoIs(ctx, remoteAddr)
//
// (Both are LocalClient calls, so they share the one client.) The composition
// root injects the same *Mapper into the poller and the api middleware.
//
// The field mapping is factored into PURE helpers (buildInventory, mapPeer,
// classify) so it is unit-testable by constructing ipnstate.Status values
// directly -- no fake of the concrete *local.Client is needed.
package netmap

import (
	"context"
	"errors"
	"sort"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"

	"github.com/lifeart/tsctl/internal/store"
)

// routerTag is the ACL tag that marks a node as a controllable router.
const routerTag = "tag:router"

// Mapper reads the tsnet node's netmap.
type Mapper struct {
	lc *local.Client
}

// New returns a Mapper backed by the tsnet server's LocalClient.
func New(lc *local.Client) *Mapper { return &Mapper{lc: lc} }

// Inventory returns every visible tailnet node (Self + all peers) as a
// NodeView, classifying each by NodeType. On lc.Status error it returns the
// error so the poller can surface it as Snapshot.NetmapErr -- never swallowed
// (DESIGN §8).
func (m *Mapper) Inventory(ctx context.Context) ([]store.NodeView, error) {
	st, err := m.lc.Status(ctx)
	if err != nil {
		return nil, err
	}
	return buildInventory(st), nil
}

// buildInventory is the pure mapping from a netmap status to NodeViews. It
// includes Self (DESIGN §4 / PHASE_B §4) and every peer, sorted by StableID for
// deterministic output (so the SSE-driven UI list does not reshuffle between
// frames -- the underlying Status.Peer is a map with random iteration order).
func buildInventory(st *ipnstate.Status) []store.NodeView {
	if st == nil {
		return nil
	}
	nodes := make([]store.NodeView, 0, len(st.Peer)+1)
	if st.Self != nil {
		self := mapPeer(st.Self)
		self.IsSelf = true // mark the tsctl node so the poller never lists itself as a router
		nodes = append(nodes, self)
	}
	for _, p := range st.Peer {
		if p == nil {
			continue
		}
		nodes = append(nodes, mapPeer(p))
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].StableID < nodes[j].StableID })
	return nodes
}

// mapPeer projects one PeerStatus into the read-only store.NodeView.
func mapPeer(p *ipnstate.PeerStatus) store.NodeView {
	return store.NodeView{
		StableID: string(p.ID),
		// Trim the trailing MagicDNS dot for display parity with the router
		// package's trimmed ExitNodeRef.Name (low fix).
		Name:           strings.TrimSuffix(p.DNSName, "."),
		Hostname:       p.HostName,
		TailscaleIPs:   peerIPs(p),
		OS:             p.OS,
		Online:         p.Online,
		LastSeen:       p.LastSeen,
		ExitNodeOption: p.ExitNodeOption,
		Tags:           peerTags(p),
		Type:           classify(p),
	}
}

// classify maps a peer to a NodeType. Precedence (first match wins, PHASE_B §4 /
// DESIGN §4): a tag:router node is a NodeRouter; else an exit-node-capable node
// is a NodeExitNode; else NodeGeneric. (ExitNodeOption is still exposed on the
// NodeView regardless of type so the picker can offer any approved exit node.)
func classify(p *ipnstate.PeerStatus) store.NodeType {
	if hasTag(p, routerTag) {
		return store.NodeRouter
	}
	if p.ExitNodeOption {
		return store.NodeExitNode
	}
	return store.NodeGeneric
}

// peerIPs converts TailscaleIPs ([]netip.Addr) to strings; [0] is the 100.x
// IPv4. Returns nil when the peer has no addresses.
func peerIPs(p *ipnstate.PeerStatus) []string {
	if len(p.TailscaleIPs) == 0 {
		return nil
	}
	ips := make([]string, len(p.TailscaleIPs))
	for i, a := range p.TailscaleIPs {
		ips[i] = a.String()
	}
	return ips
}

// peerTags returns an independent copy of the peer's ACL tags (the upstream
// Tags is a *views.Slice[string], nil when the node has no tags).
func peerTags(p *ipnstate.PeerStatus) []string {
	if p.Tags == nil || p.Tags.Len() == 0 {
		return nil
	}
	return append([]string(nil), p.Tags.AsSlice()...)
}

// hasTag reports whether the peer carries the given ACL tag.
func hasTag(p *ipnstate.PeerStatus, tag string) bool {
	if p == nil || p.Tags == nil {
		return false
	}
	return p.Tags.ContainsFunc(func(t string) bool { return t == tag })
}

// WhoIs identifies the caller behind remoteAddr (an IP or IP:port) via
// LocalClient.WhoIs. FAIL-CLOSED (DESIGN §7): on ANY error it returns the error
// (callers must deny). login comes from UserProfile.LoginName; tagged is true
// when the node is tagged (it has no real user identity), so callers can deny
// tagged/shared peers. Errors are never swallowed.
func (m *Mapper) WhoIs(ctx context.Context, remoteAddr string) (login string, tagged bool, err error) {
	resp, err := m.lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		return "", false, err
	}
	if resp == nil {
		// Defensive: a nil response with a nil error should not happen, but
		// fail closed rather than treat an unknown caller as authorized.
		return "", false, errors.New("netmap: WhoIs returned a nil response")
	}
	if resp.Node != nil {
		tagged = resp.Node.IsTagged()
	}
	if resp.UserProfile != nil {
		login = resp.UserProfile.LoginName
	}
	return login, tagged, nil
}
