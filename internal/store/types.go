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
)

// RouterStats are the router node's own counters, from its tailscale status.
type RouterStats struct {
	RxBytes       int64
	TxBytes       int64
	LastHandshake time.Time
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
}

// Snapshot is an immutable, fully-built view of the world. The poller builds a
// fresh one and atomically swaps it in; readers Load() lock-free and must treat
// it (and everything it points to) as read-only.
type Snapshot struct {
	Nodes     []NodeView
	Routers   []RouterView
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
