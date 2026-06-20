// Package authz carries the small cross-cutting authorization types shared by
// the api and sse packages without creating an import cycle (both already import
// store, and authz imports only store + context).
//
// A Subject is the authenticated identity resolved on EVERY request by the api:
// either the full-access admin (tailnet owner or the shared UI password) or a
// guest bound to exactly one zone. The api injects it into the request context
// (WithSubject) after authenticating; downstream handlers and the sse hub read it
// (SubjectFromContext) to scope what a guest may see.
//
// FilterSnapshotToZone is a PURE, defense-in-depth snapshot scoper. It is NOT the
// access control: every guest WRITE is independently authorized in the api
// against the live group store, so a bug in this filter can leak a read at worst,
// never grant a write.
package authz

import (
	"context"

	"github.com/lifeart/tsctl/internal/store"
)

// Subject is the authenticated identity for a request. Admin is the full-access
// role; a guest has Admin=false, a GuestID, and is bound to a single zone
// (ZoneID, resolved live from the guest store on every request). The zero
// Subject is an unauthenticated / denied caller.
type Subject struct {
	Admin   bool
	GuestID string
	ZoneID  string
}

// subjectKey is the unexported context key for a Subject (avoids collisions).
type subjectKey struct{}

// WithSubject returns a child context carrying sub. The api calls this in
// RequireAuth so handlers (and the sse hub) can recover the Subject.
func WithSubject(ctx context.Context, sub Subject) context.Context {
	return context.WithValue(ctx, subjectKey{}, sub)
}

// SubjectFromContext recovers the Subject injected by WithSubject. ok is false
// when no Subject is present (treat as unauthenticated / fail-closed).
func SubjectFromContext(ctx context.Context) (Subject, bool) {
	sub, ok := ctx.Value(subjectKey{}).(Subject)
	return sub, ok
}

// Revalidate re-checks, on demand, whether the caller behind a LONG-LIVED
// connection is still authorized. Per-request REST auth already revokes a
// disabled/deleted guest instantly, but a streaming GET (the SSE event stream)
// authenticates only once at connect; the sse hub calls this periodically to drop
// a guest's open stream promptly after revocation. It returns false once access
// should end. The api builds it as a closure over resolveSubject for the request.
type Revalidate func() bool

// revalidateKey is the unexported context key for a Revalidate func.
type revalidateKey struct{}

// WithRevalidate returns a child context carrying fn (set by the api in
// RequireAuth alongside the Subject).
func WithRevalidate(ctx context.Context, fn Revalidate) context.Context {
	return context.WithValue(ctx, revalidateKey{}, fn)
}

// RevalidateFromContext recovers the Revalidate func, if any.
func RevalidateFromContext(ctx context.Context) (Revalidate, bool) {
	fn, ok := ctx.Value(revalidateKey{}).(Revalidate)
	return fn, ok
}

// FilterSnapshotToZone returns a NEW snapshot scoped to zoneID, without ever
// mutating snap (pure): the shared snapshot stays the single owned value the
// poller built. The result carries exactly the one matching GroupView; the Nodes
// in that zone's Consumers UNION its AllowedExitNodes (offline allowed exits are
// KEPT so a guest's exit-node picker matches the admin's); and the Routers whose
// node is one of the zone's Consumers. NetmapAt/NetmapErr/BuiltAt are carried
// through so the guest sees the same freshness/error state. An unknown (or empty)
// zoneID yields an empty-but-non-nil snapshot (fail-closed: a guest whose zone
// vanished sees nothing).
func FilterSnapshotToZone(snap *store.Snapshot, zoneID string) *store.Snapshot {
	out := &store.Snapshot{
		Nodes:     []store.NodeView{},
		Routers:   []store.RouterView{},
		Groups:    []store.GroupView{},
		NetmapAt:  snap.NetmapAt,
		NetmapErr: snap.NetmapErr,
		BuiltAt:   snap.BuiltAt,
	}

	var gv *store.GroupView
	for i := range snap.Groups {
		if snap.Groups[i].ID == zoneID {
			g := snap.Groups[i] // value copy; member slices are read-only below
			gv = &g
			break
		}
	}
	if gv == nil {
		return out // unknown/empty zone -> nothing
	}
	out.Groups = []store.GroupView{*gv}

	// consumers = the routers the guest may control; allowed = consumers UNION the
	// zone's allowed exit nodes (the nodes the guest is permitted to see).
	consumers := make(map[string]struct{}, len(gv.Consumers))
	allowed := make(map[string]struct{}, len(gv.Consumers)+len(gv.AllowedExitNodes))
	for _, m := range gv.Consumers {
		consumers[m.StableID] = struct{}{}
		allowed[m.StableID] = struct{}{}
	}
	for _, m := range gv.AllowedExitNodes {
		allowed[m.StableID] = struct{}{}
	}

	for _, n := range snap.Nodes {
		if _, ok := allowed[n.StableID]; ok {
			out.Nodes = append(out.Nodes, n) // keep offline allowed exits too
		}
	}
	for _, rv := range snap.Routers {
		if _, ok := consumers[rv.Node.StableID]; ok {
			out.Routers = append(out.Routers, rv)
		}
	}
	return out
}
