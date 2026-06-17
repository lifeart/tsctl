package netmap

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/views"

	"github.com/lifeart/tsctl/internal/store"
)

// tagsPtr builds the *views.Slice[string] shape that ipnstate.PeerStatus.Tags
// expects (nil when there are no tags).
func tagsPtr(tags ...string) *views.Slice[string] {
	if len(tags) == 0 {
		return nil
	}
	s := views.SliceOf(tags)
	return &s
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		peer *ipnstate.PeerStatus
		want store.NodeType
	}{
		{
			name: "tag:router wins",
			peer: &ipnstate.PeerStatus{Tags: tagsPtr(routerTag)},
			want: store.NodeRouter,
		},
		{
			name: "tag:router wins even when also exit-node capable",
			peer: &ipnstate.PeerStatus{Tags: tagsPtr(routerTag), ExitNodeOption: true},
			want: store.NodeRouter,
		},
		{
			name: "tag:router among other tags",
			peer: &ipnstate.PeerStatus{Tags: tagsPtr("tag:server", routerTag, "tag:prod")},
			want: store.NodeRouter,
		},
		{
			name: "exit node option without router tag",
			peer: &ipnstate.PeerStatus{ExitNodeOption: true},
			want: store.NodeExitNode,
		},
		{
			name: "exit node option with unrelated tag",
			peer: &ipnstate.PeerStatus{Tags: tagsPtr("tag:server"), ExitNodeOption: true},
			want: store.NodeExitNode,
		},
		{
			name: "generic: no tags, not an exit node",
			peer: &ipnstate.PeerStatus{},
			want: store.NodeGeneric,
		},
		{
			name: "generic: unrelated tag only",
			peer: &ipnstate.PeerStatus{Tags: tagsPtr("tag:server")},
			want: store.NodeGeneric,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify(tt.peer); got != tt.want {
				t.Fatalf("classify() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildInventoryNil(t *testing.T) {
	if got := buildInventory(nil); got != nil {
		t.Fatalf("buildInventory(nil) = %v, want nil", got)
	}
}

func TestBuildInventoryMapping(t *testing.T) {
	lastSeen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	self := &ipnstate.PeerStatus{
		ID:           "self-0001",
		DNSName:      "tsctl.example.ts.net.",
		HostName:     "tsctl",
		OS:           "linux",
		Online:       true,
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a::1")},
		Tags:         tagsPtr("tag:tsctl"),
	}

	exit := &ipnstate.PeerStatus{
		ID:             "exit-0002",
		DNSName:        "exit.example.ts.net.",
		HostName:       "exit",
		OS:             "linux",
		Online:         true,
		ExitNodeOption: true,
		TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.2")},
	}

	router := &ipnstate.PeerStatus{
		ID:           "router-0003",
		DNSName:      "router.example.ts.net.",
		HostName:     "router",
		OS:           "linux",
		Online:       false,
		LastSeen:     lastSeen,
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
		Tags:         tagsPtr(routerTag),
	}

	generic := &ipnstate.PeerStatus{
		ID:           "generic-0004",
		DNSName:      "laptop.example.ts.net.",
		HostName:     "laptop",
		OS:           "macOS",
		Online:       true,
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.4")},
	}

	st := &ipnstate.Status{
		Self: self,
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): exit,
			key.NewNode().Public(): router,
			key.NewNode().Public(): generic,
		},
	}

	nodes := buildInventory(st)
	if len(nodes) != 4 {
		t.Fatalf("buildInventory returned %d nodes, want 4 (Self + 3 peers)", len(nodes))
	}

	// Deterministic sort by StableID: exit, generic, router, self.
	wantOrder := []string{"exit-0002", "generic-0004", "router-0003", "self-0001"}
	for i, want := range wantOrder {
		if nodes[i].StableID != want {
			t.Fatalf("nodes[%d].StableID = %q, want %q (expected sorted-by-StableID order)", i, nodes[i].StableID, want)
		}
	}

	byID := make(map[string]store.NodeView, len(nodes))
	for _, n := range nodes {
		byID[n.StableID] = n
	}

	// Self mapped, with tag:tsctl -> generic (not a router, not an exit node).
	gotSelf := byID["self-0001"]
	if gotSelf.Name != "tsctl.example.ts.net." || gotSelf.Hostname != "tsctl" || gotSelf.OS != "linux" {
		t.Errorf("self field mapping wrong: %+v", gotSelf)
	}
	if !gotSelf.Online {
		t.Errorf("self Online = false, want true")
	}
	if gotSelf.Type != store.NodeGeneric {
		t.Errorf("self Type = %q, want %q", gotSelf.Type, store.NodeGeneric)
	}
	if len(gotSelf.TailscaleIPs) != 2 || gotSelf.TailscaleIPs[0] != "100.64.0.1" {
		t.Errorf("self TailscaleIPs = %v, want [100.64.0.1 fd7a::1]", gotSelf.TailscaleIPs)
	}
	if len(gotSelf.Tags) != 1 || gotSelf.Tags[0] != "tag:tsctl" {
		t.Errorf("self Tags = %v, want [tag:tsctl]", gotSelf.Tags)
	}

	// Exit node: ExitNodeOption set, classified NodeExitNode.
	gotExit := byID["exit-0002"]
	if !gotExit.ExitNodeOption {
		t.Errorf("exit ExitNodeOption = false, want true")
	}
	if gotExit.Type != store.NodeExitNode {
		t.Errorf("exit Type = %q, want %q", gotExit.Type, store.NodeExitNode)
	}
	if len(gotExit.Tags) != 0 {
		t.Errorf("exit Tags = %v, want empty", gotExit.Tags)
	}

	// Router: tag:router -> NodeRouter; offline with LastSeen preserved.
	gotRouter := byID["router-0003"]
	if gotRouter.Type != store.NodeRouter {
		t.Errorf("router Type = %q, want %q", gotRouter.Type, store.NodeRouter)
	}
	if gotRouter.Online {
		t.Errorf("router Online = true, want false")
	}
	if !gotRouter.LastSeen.Equal(lastSeen) {
		t.Errorf("router LastSeen = %v, want %v", gotRouter.LastSeen, lastSeen)
	}

	// Generic peer.
	gotGeneric := byID["generic-0004"]
	if gotGeneric.Type != store.NodeGeneric {
		t.Errorf("generic Type = %q, want %q", gotGeneric.Type, store.NodeGeneric)
	}
	if gotGeneric.OS != "macOS" {
		t.Errorf("generic OS = %q, want macOS", gotGeneric.OS)
	}
}

func TestBuildInventorySkipsNilPeerAndNoSelf(t *testing.T) {
	st := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): nil,
			key.NewNode().Public(): {ID: "only-0001"},
		},
	}
	nodes := buildInventory(st)
	if len(nodes) != 1 {
		t.Fatalf("buildInventory returned %d nodes, want 1 (nil peer skipped, no Self)", len(nodes))
	}
	if nodes[0].StableID != "only-0001" {
		t.Fatalf("nodes[0].StableID = %q, want only-0001", nodes[0].StableID)
	}
}
