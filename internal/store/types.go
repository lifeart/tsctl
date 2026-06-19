// Package store holds the immutable snapshot types that every other package
// reads, plus a lock-free Store backed by atomic.Pointer[Snapshot].
//
// FROZEN CONTRACT (DESIGN §4). Exact field/method names below are the seam
// that all Phase B agents build against; do not rename them.
package store

import (
	"sync/atomic"
	"time"
)

// NodeType classifies an inventory node. See DESIGN §4.
type NodeType string

const (
	NodeExitNode NodeType = "exit-node"
	NodeRouter   NodeType = "router"
	NodeGeneric  NodeType = "generic"
)

// NodeView is the read-only projection of one tailnet node from the local
// netmap (LocalClient.Status()).
type NodeView struct {
	StableID       string    // tailcfg.StableNodeID, as a string
	Name           string    // MagicDNS name (DNSName)
	Hostname       string    // HostInfo hostname
	TailscaleIPs   []string  // [0] is the 100.x IPv4
	OS             string    //
	Online         bool      // connected to the control plane
	LastSeen       time.Time // only meaningful when offline
	ExitNodeOption bool      // advertised AND approved -> selectable as exit node
	Tags           []string  // ACL tags
	Type           NodeType  //
	IsSelf         bool      // this is the tsctl node itself (Status.Self) -- internal, never a router/consumer
}

// ExitNodeRef identifies an exit node. IP is the 100.x IPv4 (DESIGN: select by
// IPv4, never MagicDNS, on a router about to route through it).
type ExitNodeRef struct {
	StableID string
	Name     string
	IP       string // 100.x IPv4
}

// RouterState is the lifecycle of a router's exit-node selection. See DESIGN §8.
type RouterState string

const (
	RouterOK          RouterState = "ok"
	RouterPending     RouterState = "pending"
	RouterUnconfirmed RouterState = "unconfirmed"
	RouterUnreachable RouterState = "unreachable"
	// RouterAwaitingKeep is a CONFIRMED exit-node selection within the dead-man's-
	// switch revert window whose keep-marker has NOT yet been written (the
	// explicit-Keep gate, docs/design/keep-egress.md stage 2, behind -require-keep).
	// It is NOT success: the armed revert WILL fire unless the operator calls Keep
	// before RevertAt. The UI shows a live countdown + a Keep button; success is
	// only RouterOK after Keep (or after auto-keep in the default mode).
	RouterAwaitingKeep RouterState = "awaiting-keep"
	// RouterUnprobed is a router that is LISTED but has never been contacted:
	// the non-exit-node auto-discovery fallback surfaces every device as a
	// consumer WITHOUT auto-SSHing it (a tailnet can have many nodes), so its
	// SSH state is unknown until a manual probe or an exit-node change. Neutral,
	// not an error -- the UI shows "Not probed" + the Test SSH action.
	RouterUnprobed RouterState = "unprobed"
)

// RouterStats are the counters of the router's CURRENT exit-node peer, read from
// the router's own `tailscale status --json` (PHASE_B §6): rx/tx and the last
// handshake to that exit node. A router using no exit node (Direct) has no such
// peer, so its stats are zero.
type RouterStats struct {
	RxBytes       int64
	TxBytes       int64
	LastHandshake time.Time
}

// RouterRuntime is the parsed result of `tailscale status --json` on a router:
// its current exit node, the selectable options, and its own stats. Produced by
// router.ParseStatus (a pure function) and returned by a RouterClient.
//
// It lives in store (a leaf package) so the router package depends only on store
// and never on poller -- keeping the two Phase B packages build-decoupled.
type RouterRuntime struct {
	Current *ExitNodeRef  // currently selected exit node (nil = none)
	Options []ExitNodeRef // selectable exit nodes (ExitNodeOption == true)
	Stats   RouterStats   // counters for the current exit-node peer (zero if Direct)
	Online  bool          // router self-reports online
}

// RouterView is the full state of one managed OpenWRT router.
//
// The device's ACTUAL selection (CurrentExitNode) is the source of truth; the
// UI never shows success for an unconfirmed change (Desired). LastError is
// never "" while broken -- surface it here, never swallow (DESIGN §8).
type RouterView struct {
	Node            NodeView
	CurrentExitNode *ExitNodeRef // actual, from the router's own status (source of truth)
	Desired         *ExitNodeRef // pending intent; never shown as success until confirmed
	State           RouterState
	Stats           RouterStats
	Reachable       bool
	LastError       string // "" = healthy; NEVER swallow -- surface here
	LastConfirmedAt time.Time

	// RevertAt is the instant the armed dead-man's-switch revert fires for a
	// confirmed-but-not-yet-kept selection (docs/design/keep-egress.md stage 2). It
	// is ONLY meaningful while State == RouterAwaitingKeep -- the UI counts down to
	// it and shows the Keep button. Zero in every other state.
	RevertAt time.Time

	// Egress probe result (docs/design/keep-egress.md, stage 1). After a CONFIRMED
	// exit-node SET the poller can run a read-only outbound request FROM the router
	// (which now routes through its new exit node) to test actual internet egress.
	// It is advisory: an egress failure never reverts or fails the set.
	EgressOK        *bool     // nil = not checked / not applicable (Direct); else last egress result
	EgressDetail    string    // probe output or error (when checked)
	EgressCheckedAt time.Time // when egress was last checked
}

// ProbeResult is the outcome of a read-only SSH diagnostic against a router
// (the "test SSH + get router stats" probe). An SSH/transport failure is a
// RESULT (OK=false + Error), not a Go error -- only a router-not-found surfaces
// as an HTTP error. CheckedAt is always set. This type carries JSON tags (unlike
// the other store types) because it IS the frozen wire shape the api writes back
// directly for POST /api/routers/{id}/probe.
type ProbeResult struct {
	OK         bool      `json:"ok"`
	DurationMs int64     `json:"durationMs,omitempty"` // omitted when no dial occurred (offline) -> UI shows no "· N ms"
	Output     string    `json:"output,omitempty"`
	Error      string    `json:"error,omitempty"`
	CheckedAt  time.Time `json:"checkedAt"`
}

// Group is the RAW, persisted/CRUD shape of a zone (DESIGN docs/design/zones.md):
// a named set of consumer routers plus the exit nodes they are allowed to use.
// Members are node StableIDs (soft membership -- a member may be absent from the
// current netmap; the resolved GroupView flags that, it is never rejected). ID is
// server-assigned (random hex) and is the key; Name need not be globally unique.
//
// This is a leaf data type (no JSON tags -- the api package owns the wire DTOs and
// the groups package owns the on-disk format), matching the rest of store.
type Group struct {
	ID               string   // stable id, server-assigned (random hex)
	Name             string   // user label (non-empty; not required to be unique)
	Consumers        []string // node StableIDs of the controllable routers in the zone
	AllowedExitNodes []string // node StableIDs of the exit nodes the consumers may use
}

// GroupMember is one resolved member of a group, ready for rendering. The poller
// resolves each StableID against the current snapshot nodes: a member present in
// the netmap carries its display Name/IP/Online; an absent one has Present=false
// (and empty Name/IP) so the UI can flag it "missing" without hiding it.
type GroupMember struct {
	StableID string
	Name     string // node display name when Present; "" when absent
	IP       string // 100.x IPv4 when Present; "" when absent
	Online   bool   // node online state when Present; false when absent
	Present  bool   // true iff the StableID currently exists in the netmap
}

// GroupView is the RESOLVED shape of a Group carried in the Snapshot: the group's
// ID/Name plus its members resolved to GroupMembers for rendering the graph.
type GroupView struct {
	ID               string
	Name             string
	Consumers        []GroupMember
	AllowedExitNodes []GroupMember
}

// Snapshot is an immutable, fully-built view of the world. The poller builds a
// fresh one and atomically swaps it in; readers Load() lock-free and must treat
// it (and everything it points to) as read-only.
type Snapshot struct {
	Nodes   []NodeView
	Routers []RouterView
	// Groups are the resolved zone views (ADDITIVE field). Always non-nil (an
	// empty, made slice when there are no groups) so consumers never nil-check.
	Groups    []GroupView
	NetmapAt  time.Time
	NetmapErr string // "" = healthy
	BuiltAt   time.Time
}

// Store is a lock-free holder of the current Snapshot.
//
// Concurrency contract (DESIGN §6): the poller builds a fresh immutable
// Snapshot and Store()s it; all readers Load() without locking. Never mutate a
// Snapshot after storing it.
type Store struct {
	ptr atomic.Pointer[Snapshot]
}

// New returns a Store pre-populated with an empty (non-nil) Snapshot so callers
// of Load never have to nil-check.
func New() *Store {
	s := &Store{}
	s.ptr.Store(&Snapshot{BuiltAt: time.Now()})
	return s
}

// Load returns the current Snapshot. Lock-free; never nil for a Store from New.
func (s *Store) Load() *Snapshot { return s.ptr.Load() }

// Store atomically swaps in a freshly built Snapshot.
func (s *Store) Store(snap *Snapshot) { s.ptr.Store(snap) }
