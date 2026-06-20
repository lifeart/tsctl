package authz

import (
	"context"
	"testing"
	"time"

	"github.com/lifeart/tsctl/internal/store"
)

func sampleSnapshot() *store.Snapshot {
	return &store.Snapshot{
		Nodes: []store.NodeView{
			{StableID: "r1", Name: "router1", Online: true},
			{StableID: "e1", Name: "exit1", Online: false}, // offline allowed exit: must be kept
			{StableID: "other", Name: "secret-node", Online: true},
		},
		Routers: []store.RouterView{
			{Node: store.NodeView{StableID: "r1", Name: "router1"}, State: store.RouterOK},
			{Node: store.NodeView{StableID: "r2", Name: "router2"}, State: store.RouterOK},
		},
		Groups: []store.GroupView{
			{
				ID:               "z1",
				Name:             "Work",
				Consumers:        []store.GroupMember{{StableID: "r1", Present: true}},
				AllowedExitNodes: []store.GroupMember{{StableID: "e1", Present: false}},
			},
			{
				ID:        "z2",
				Name:      "Other",
				Consumers: []store.GroupMember{{StableID: "r2", Present: true}},
			},
		},
		NetmapAt:  time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC),
		NetmapErr: "some-warning",
		BuiltAt:   time.Date(2026, 6, 19, 10, 0, 5, 0, time.UTC),
	}
}

func TestFilterSnapshotToZone_Correctness(t *testing.T) {
	snap := sampleSnapshot()
	out := FilterSnapshotToZone(snap, "z1")

	if len(out.Groups) != 1 || out.Groups[0].ID != "z1" {
		t.Fatalf("filtered groups = %+v, want exactly z1", out.Groups)
	}
	// Nodes: r1 (consumer) + e1 (offline allowed exit, KEPT); NOT "other".
	gotNodes := map[string]bool{}
	for _, n := range out.Nodes {
		gotNodes[n.StableID] = true
	}
	if !gotNodes["r1"] || !gotNodes["e1"] {
		t.Errorf("filtered nodes missing r1/e1: %v", gotNodes)
	}
	if gotNodes["other"] {
		t.Error("filtered nodes must not include out-of-zone 'other'")
	}
	// Routers: only r1 (r2 is a consumer of z2, not z1).
	if len(out.Routers) != 1 || out.Routers[0].Node.StableID != "r1" {
		t.Errorf("filtered routers = %+v, want only r1", out.Routers)
	}
	// Freshness carried through.
	if !out.BuiltAt.Equal(snap.BuiltAt) || !out.NetmapAt.Equal(snap.NetmapAt) || out.NetmapErr != snap.NetmapErr {
		t.Error("filtered snapshot must carry NetmapAt/NetmapErr/BuiltAt")
	}
}

func TestFilterSnapshotToZone_UnknownZoneIsEmpty(t *testing.T) {
	snap := sampleSnapshot()
	out := FilterSnapshotToZone(snap, "nope")
	if out == nil {
		t.Fatal("filter must return a non-nil snapshot")
	}
	if len(out.Groups) != 0 || len(out.Nodes) != 0 || len(out.Routers) != 0 {
		t.Errorf("unknown zone must yield an empty snapshot, got %+v", out)
	}
	// Non-nil empty slices (consumers never have to nil-check).
	if out.Nodes == nil || out.Routers == nil || out.Groups == nil {
		t.Error("empty slices must be non-nil")
	}
}

func TestFilterSnapshotToZone_NoMutation(t *testing.T) {
	snap := sampleSnapshot()
	_ = FilterSnapshotToZone(snap, "z1")
	if len(snap.Nodes) != 3 || len(snap.Routers) != 2 || len(snap.Groups) != 2 {
		t.Errorf("filter must NOT mutate the shared snapshot: nodes=%d routers=%d groups=%d",
			len(snap.Nodes), len(snap.Routers), len(snap.Groups))
	}
}

func TestSubjectContextRoundTrip(t *testing.T) {
	ctx := context.Background()
	if _, ok := SubjectFromContext(ctx); ok {
		t.Error("empty context should have no subject")
	}
	want := Subject{GuestID: "g1", ZoneID: "z1"}
	got, ok := SubjectFromContext(WithSubject(ctx, want))
	if !ok || got != want {
		t.Errorf("round-trip = %+v ok=%v want %+v", got, ok, want)
	}
}
