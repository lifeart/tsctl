// Package demo provides an offline, scripted backend for the `tsctl demo`
// subcommand: a faithful preview of the web UI with NO tsnet, NO SSH, and NO
// real tailnet. cmd/tsctl wires the REAL store/sse/poller/api stack against the
// World here, so "what you see is what prod renders".
//
// World plays two of the composition-root's injected roles at once:
//   - the Mapper: it implements poller.Netmapper (Inventory) AND api.WhoIser
//     (WhoIs returns a fixed demo owner so RequireOwner passes -- there is no
//     real tailnet identity to check against);
//   - the RouterClient: it implements poller.RouterClient (Status / SetExitNode)
//     with SCRIPTED, TIME-VARYING behavior so every UI state is reachable.
//
// It is the single source of truth for the demo and is safe for concurrent use.
// Never-optimistic semantics are preserved: SetExitNode only reports a confirmed
// change after it has actually mutated the (in-memory) device state, exactly like
// the real router client's arm->apply->confirm->keep sequence.
package demo

import (
	"context"
	"fmt"
	mrand "math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/lifeart/tsctl/internal/groups"
	"github.com/lifeart/tsctl/internal/router"
	"github.com/lifeart/tsctl/internal/store"
)

// Owner is the fixed login WhoIs reports; cmd/tsctl passes it as api.Config.Owner
// so RequireOwner admits the local browser (no real tailnet identity exists).
const Owner = "demo-owner@example.com"

// ApplyLatency is how long a scripted SetExitNode "takes" before it resolves, so
// the UI visibly shows the pending / "Applying…" state (well under the 3s poll).
const ApplyLatency = 1500 * time.Millisecond

// TickInterval drives the time-variation goroutine (stats tick, a node flips).
const TickInterval = 3 * time.Second

// Fixture addresses (100.x IPv4s). Routers are the controllable set; exit nodes
// are approved options; flaky/broken drive the two non-happy SetExitNode paths.
const (
	r1IP = "100.64.0.10" // home-router        — online, Direct (no exit node)
	r2IP = "100.64.0.11" // office-router      — online, USING tokyo, stats tick up
	r3IP = "100.64.0.12" // cabin-router       — OFFLINE (control disabled)
	r4IP = "100.64.0.13" // warehouse (long)   — online, current exit node is OFFLINE → warn

	tokyoIP     = "100.64.0.20" // online exit node (normal → confirmed)
	frankfurtIP = "100.64.0.21" // online exit node (normal → confirmed)
	londonIP    = "100.64.0.22" // OFFLINE exit node → "(offline)" in the picker
	comboIP     = "100.64.0.23" // exit node that is ALSO tag:router
	flakyIP     = "100.64.0.24" // scripted → applied-but-unconfirmed (amber)
	brokenIP    = "100.64.0.25" // scripted → *router.CommandError (permission denied)

	aliceIP = "100.64.0.30" // generic, online
	bobIP   = "100.64.0.31" // generic — FLIPS online/offline each tick
	kioskIP = "100.64.0.32" // generic, online, very long hostname (truncation)
)

// flipID is the StableID of the node the time-variation goroutine toggles
// online/offline so SSE frames visibly change. It is a generic node, never an
// exit-node target, so toggling it can't interfere with the scripted control
// paths (the poller pre-flight rejects an offline target).
const flipID = "n-bob-iphone"

// demoNode is the mutable fixture for one inventory node.
type demoNode struct {
	stableID string
	name     string // MagicDNS-style name
	hostname string
	ips      []string
	os       string
	online   bool
	lastSeen time.Time
	exitOpt  bool // advertised AND approved → selectable as an exit node
	tags     []string
	typ      store.NodeType
}

// routerRuntime is the mutable per-router device state Status/SetExitNode read
// and write (the "router's own tailscale status").
type routerRuntime struct {
	currentExitIP string // "" = Direct
	rx, tx        int64
	lastHandshake time.Time
}

// World is the scripted demo backend. It owns the fixture nodes and per-router
// runtime, and serves both the Mapper and RouterClient roles.
type World struct {
	mu      sync.Mutex
	nodes   []*demoNode
	routers map[string]*routerRuntime // keyed by router 100.x IPv4

	// per-router serialization, mirroring the real router.Client: one command in
	// flight per router. Lock order is always lockAddr → mu (never the reverse),
	// so there is no cycle.
	muLocks sync.Mutex
	locks   map[string]*sync.Mutex
}

// New builds the demo World with every UI state represented at t=0.
func New() *World {
	now := time.Now()
	w := &World{
		routers: make(map[string]*routerRuntime),
		locks:   make(map[string]*sync.Mutex),
		nodes: []*demoNode{
			// --- controllable routers (tag:router) ---
			{stableID: "n-home-router", name: "home-router.tail-demo.ts.net", hostname: "home-router",
				ips: []string{r1IP}, os: "linux", online: true, tags: []string{"tag:router"}, typ: store.NodeRouter},
			{stableID: "n-office-router", name: "office-router.tail-demo.ts.net", hostname: "office-router",
				ips: []string{r2IP}, os: "linux", online: true, tags: []string{"tag:router"}, typ: store.NodeRouter},
			{stableID: "n-cabin-router", name: "cabin-router.tail-demo.ts.net", hostname: "cabin-router",
				ips: []string{r3IP}, os: "linux", online: false, lastSeen: now.Add(-37 * time.Minute),
				tags: []string{"tag:router"}, typ: store.NodeRouter},
			{stableID: "n-warehouse-router",
				name:     "warehouse-router-with-an-intentionally-very-long-hostname-for-truncation.tail-demo.ts.net",
				hostname: "warehouse-router-with-an-intentionally-very-long-hostname-for-truncation",
				ips:      []string{r4IP}, os: "linux", online: true, tags: []string{"tag:router"}, typ: store.NodeRouter},

			// --- approved exit nodes (exitNodeOption=true) ---
			{stableID: "n-exit-tokyo", name: "exit-tokyo.tail-demo.ts.net", hostname: "exit-tokyo",
				ips: []string{tokyoIP}, os: "linux", online: true, exitOpt: true, typ: store.NodeExitNode},
			{stableID: "n-exit-frankfurt", name: "exit-frankfurt.tail-demo.ts.net", hostname: "exit-frankfurt",
				ips: []string{frankfurtIP}, os: "linux", online: true, exitOpt: true, typ: store.NodeExitNode},
			{stableID: "n-exit-london", name: "exit-london.tail-demo.ts.net", hostname: "exit-london",
				ips: []string{londonIP}, os: "linux", online: false, lastSeen: now.Add(-12 * time.Minute),
				exitOpt: true, typ: store.NodeExitNode},
			// an exit node that is ALSO tag:router: tag:router wins classification,
			// but exitNodeOption stays true so it still appears in the picker.
			{stableID: "n-exit-combo", name: "edge-combo.tail-demo.ts.net", hostname: "edge-combo",
				ips: []string{comboIP}, os: "linux", online: true, exitOpt: true,
				tags: []string{"tag:router"}, typ: store.NodeRouter},
			{stableID: "n-exit-flaky", name: "exit-flaky.tail-demo.ts.net", hostname: "exit-flaky",
				ips: []string{flakyIP}, os: "linux", online: true, exitOpt: true, typ: store.NodeExitNode},
			{stableID: "n-exit-broken", name: "exit-broken.tail-demo.ts.net", hostname: "exit-broken",
				ips: []string{brokenIP}, os: "linux", online: true, exitOpt: true, typ: store.NodeExitNode},

			// --- generic nodes ---
			{stableID: "n-alice-mbp", name: "alices-macbook-pro.tail-demo.ts.net", hostname: "alices-macbook-pro",
				ips: []string{aliceIP}, os: "macOS", online: true, typ: store.NodeGeneric},
			{stableID: flipID, name: "bobs-iphone.tail-demo.ts.net", hostname: "bobs-iphone",
				ips: []string{bobIP}, os: "iOS", online: false, lastSeen: now.Add(-3 * time.Minute), typ: store.NodeGeneric},
			{stableID: "n-kiosk",
				name:     "front-lobby-conference-room-A-information-kiosk-display.tail-demo.ts.net",
				hostname: "front-lobby-conference-room-A-information-kiosk-display",
				ips:      []string{kioskIP}, os: "linux", online: true, typ: store.NodeGeneric},
		},
	}

	// Per-router device state at t=0 — one per UI scenario.
	w.routers[r1IP] = &routerRuntime{}                                                                                                // Direct
	w.routers[r2IP] = &routerRuntime{currentExitIP: tokyoIP, rx: 18_400_000, tx: 4_200_000, lastHandshake: now.Add(-9 * time.Second)} // via tokyo, ticks
	w.routers[r3IP] = &routerRuntime{}                                                                                                // offline → Status errors anyway
	w.routers[r4IP] = &routerRuntime{currentExitIP: londonIP, rx: 940_000, tx: 210_000, lastHandshake: now.Add(-11 * time.Minute)}    // via OFFLINE london → warn
	return w
}

// RouterIPs is the configured, controllable router set (cmd/tsctl passes it to
// poller.New). Order is stable so the cards render predictably.
func (w *World) RouterIPs() []string { return []string{r1IP, r2IP, r3IP, r4IP} }

// AllowedHosts is the Host-header allowlist for the plain loopback listener.
func (w *World) AllowedHosts() []string {
	return []string{"127.0.0.1:8089", "localhost:8089", "127.0.0.1", "localhost"}
}

// --- Mapper role -------------------------------------------------------------

// Inventory implements poller.Netmapper: the current netmap as []store.NodeView.
func (w *World) Inventory(ctx context.Context) ([]store.NodeView, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]store.NodeView, 0, len(w.nodes))
	for _, n := range w.nodes {
		out = append(out, store.NodeView{
			StableID:       n.stableID,
			Name:           n.name,
			Hostname:       n.hostname,
			TailscaleIPs:   append([]string(nil), n.ips...),
			OS:             n.os,
			Online:         n.online,
			LastSeen:       n.lastSeen,
			ExitNodeOption: n.exitOpt,
			Tags:           append([]string(nil), n.tags...),
			Type:           n.typ,
		})
	}
	return out, nil
}

// WhoIs implements api.WhoIser: a fixed, untagged owner so RequireOwner passes.
// There is no real tailnet peer to identify in demo mode.
func (w *World) WhoIs(ctx context.Context, remoteAddr string) (login string, tagged bool, err error) {
	return Owner, false, nil
}

// --- RouterClient role -------------------------------------------------------

// Status implements poller.RouterClient: read the router's own device state. An
// offline router can't be reached (its SSH dial would fail), so it errors —
// driving the UI's "offline … control disabled" / unreachable path.
func (w *World) Status(ctx context.Context, addr string) (store.RouterRuntime, error) {
	unlock := w.lockAddr(addr)
	defer unlock()

	w.mu.Lock()
	defer w.mu.Unlock()
	rn := w.findByIPLocked(addr)
	if rn == nil {
		return store.RouterRuntime{}, fmt.Errorf("demo: no router configured at %s", addr)
	}
	if !rn.online {
		return store.RouterRuntime{}, fmt.Errorf("dial %s:22: connect: host is down (demo: router offline)", addr)
	}
	return w.runtimeLocked(addr), nil
}

// SetExitNode implements poller.RouterClient with the three scripted outcomes
// (DESIGN §8 failure-mode table). It honours (target, prev): on success current
// becomes target; on any failure current is left at prev (i.e. the armed revert
// would restore it), and the error is surfaced, never swallowed.
func (w *World) SetExitNode(ctx context.Context, addr string, target, prev *store.ExitNodeRef) (store.RouterRuntime, error) {
	unlock := w.lockAddr(addr)
	defer unlock()

	// Simulate the apply+confirm latency so the UI shows pending / countdown.
	select {
	case <-time.After(ApplyLatency):
	case <-ctx.Done():
		return store.RouterRuntime{}, ctx.Err()
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	rn := w.findByIPLocked(addr)
	rs := w.routers[addr]
	if rn == nil || rs == nil {
		return store.RouterRuntime{}, fmt.Errorf("demo: no router configured at %s", addr)
	}
	if !rn.online {
		return store.RouterRuntime{}, fmt.Errorf("dial %s:22: connect: host is down (demo: router offline)", addr)
	}

	switch {
	case target == nil || target.IP == "": // clear → confirmed Direct
		rs.currentExitIP = ""
		rs.rx, rs.tx, rs.lastHandshake = 0, 0, time.Time{}
		return w.runtimeLocked(addr), nil

	case target.IP == flakyIP:
		// Applied but NOT confirmed: leave current at prev, report online but
		// return a non-nil (non-CommandError) error → poller marks unconfirmed.
		return w.runtimeLocked(addr), fmt.Errorf(
			"router %s: exit-node not confirmed (revert will fire): want %s, got %s",
			addr, target.IP, currentArg(rs))

	case target.IP == brokenIP:
		// The apply command itself failed: a *router.CommandError carrying stderr.
		// The change did NOT take -- the device is still reachable and on its
		// PREVIOUS selection (currentExitIP is left untouched above), so the
		// runtime we return (and any re-read via Status) reflects that unchanged
		// state, not a contradictory one. The poller surfaces the error and shows
		// the actual, unchanged selection (no misleading "unconfirmed/auto-revert").
		return w.runtimeLocked(addr), &router.CommandError{
			Addr: addr, Cmd: "apply exit-node", StderrText: "permission denied", Exit: 1,
		}

	default: // normal target → confirmed
		rs.currentExitIP = target.IP
		rs.rx, rs.tx = 96_000, 24_000 // a fresh tunnel starts with a little traffic
		rs.lastHandshake = time.Now()
		return w.runtimeLocked(addr), nil
	}
}

// --- time variation ----------------------------------------------------------

// Run mutates the world on a ticker so SSE frames visibly update: stats climb on
// routers whose (online) exit node is carrying traffic, and one generic node
// flips online/offline. Returns when ctx is cancelled.
func (w *World) Run(ctx context.Context) {
	t := time.NewTicker(TickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick()
		}
	}
}

func (w *World) tick() {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()

	// Stats climb only when the current exit node is ONLINE (a router pointed at
	// an offline exit node keeps a stale handshake — reinforcing the warn state).
	for _, rs := range w.routers {
		if rs.currentExitIP == "" {
			continue
		}
		ex := w.findByIPLocked(rs.currentExitIP)
		if ex == nil || !ex.online {
			continue
		}
		rs.rx += 40_000 + mrand.Int64N(180_000)
		rs.tx += 8_000 + mrand.Int64N(40_000)
		rs.lastHandshake = now
	}

	// Flip a generic node so the online dot and "last seen" visibly change.
	if n := w.findByIDLocked(flipID); n != nil {
		n.online = !n.online
		if !n.online {
			n.lastSeen = now
		}
	}
}

// --- helpers (callers hold w.mu unless noted) --------------------------------

// runtimeLocked builds the RouterRuntime for addr from current device state.
func (w *World) runtimeLocked(addr string) store.RouterRuntime {
	rs := w.routers[addr]
	return store.RouterRuntime{
		Online:  true,
		Current: w.refByIPLocked(rs.currentExitIP),
		Options: w.exitOptionsLocked(),
		Stats:   store.RouterStats{RxBytes: rs.rx, TxBytes: rs.tx, LastHandshake: rs.lastHandshake},
	}
}

// refByIPLocked returns an ExitNodeRef for the node at ip, or nil for "" (Direct)
// / unknown ip.
func (w *World) refByIPLocked(ip string) *store.ExitNodeRef {
	if ip == "" {
		return nil
	}
	n := w.findByIPLocked(ip)
	if n == nil {
		return &store.ExitNodeRef{IP: ip}
	}
	return &store.ExitNodeRef{StableID: n.stableID, Name: n.name, IP: primaryIPv4(n.ips)}
}

// exitOptionsLocked lists every approved exit node (faithful RouterRuntime.Options;
// the poller ignores it, but the real client populates it).
func (w *World) exitOptionsLocked() []store.ExitNodeRef {
	var opts []store.ExitNodeRef
	for _, n := range w.nodes {
		if n.exitOpt {
			opts = append(opts, store.ExitNodeRef{StableID: n.stableID, Name: n.name, IP: primaryIPv4(n.ips)})
		}
	}
	return opts
}

func (w *World) findByIPLocked(ip string) *demoNode {
	for _, n := range w.nodes {
		for _, a := range n.ips {
			if a == ip {
				return n
			}
		}
	}
	return nil
}

func (w *World) findByIDLocked(id string) *demoNode {
	for _, n := range w.nodes {
		if n.stableID == id {
			return n
		}
	}
	return nil
}

// lockAddr serializes commands to one router (mirrors router.Client). Different
// routers proceed in parallel.
func (w *World) lockAddr(addr string) func() {
	w.muLocks.Lock()
	m := w.locks[addr]
	if m == nil {
		m = &sync.Mutex{}
		w.locks[addr] = m
	}
	w.muLocks.Unlock()
	m.Lock()
	return m.Unlock
}

func currentArg(rs *routerRuntime) string {
	if rs.currentExitIP == "" {
		return "(none)"
	}
	return rs.currentExitIP
}

// primaryIPv4 returns the first IPv4 (the 100.x), else the first IP, else "".
func primaryIPv4(ips []string) string {
	for _, ip := range ips {
		if strings.Contains(ip, ".") {
			return ip
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// --- demo group (zone) store -------------------------------------------------

// Groups is an in-memory zone store for `tsctl demo` (no file persistence). It
// satisfies BOTH poller.GroupReader (List) and api.GroupStore (full CRUD) and is
// safe for concurrent use: the poller's List runs on the poll goroutine while
// the api handlers CRUD on request goroutines. Validation + ID minting reuse the
// real groups package so demo behaves exactly like prod.
type Groups struct {
	mu    sync.Mutex
	items []store.Group
}

// NewGroups seeds the demo with two sample zones over the fixture nodes so the
// graph renders with zones present and enforcement is observable:
//
//   - "Work": office-router + warehouse-router, allowed → tokyo, frankfurt. A
//     drag to any OTHER online exit node (e.g. edge-combo) is rejected by
//     enforcement, demonstrating the zone guard; Direct (clear) is always allowed.
//   - "Lab": home-router, allowed → tokyo, frankfurt, flaky, broken. This lets the
//     scripted amber (flaky) and command-error (broken) paths run from inside a
//     zone (their targets are in the allowed set).
//
// cabin-router is intentionally left UNGROUPED so the implicit "Ungrouped"
// section is also exercised.
func NewGroups() *Groups {
	return &Groups{items: []store.Group{
		{
			ID:               "zone-work",
			Name:             "Work",
			Consumers:        []string{"n-office-router", "n-warehouse-router"},
			AllowedExitNodes: []string{"n-exit-tokyo", "n-exit-frankfurt"},
		},
		{
			ID:               "zone-lab",
			Name:             "Lab",
			Consumers:        []string{"n-home-router"},
			AllowedExitNodes: []string{"n-exit-tokyo", "n-exit-frankfurt", "n-exit-flaky", "n-exit-broken"},
		},
	}}
}

// List returns copies of every zone (poller.GroupReader + api.GroupStore).
func (g *Groups) List() []store.Group {
	g.mu.Lock()
	defer g.mu.Unlock()
	return cloneGroups(g.items)
}

// Get returns a copy of the zone with id, or ok=false.
func (g *Groups) Get(id string) (store.Group, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if i := g.indexOfLocked(id); i >= 0 {
		return cloneGroup(g.items[i]), true
	}
	return store.Group{}, false
}

// Create validates+normalizes, assigns a fresh ID, and appends (in memory only).
func (g *Groups) Create(in store.Group) (store.Group, error) {
	norm, err := groups.Normalize(in)
	if err != nil {
		return store.Group{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	id, err := groups.NewID()
	if err != nil {
		return store.Group{}, err
	}
	for g.indexOfLocked(id) >= 0 {
		if id, err = groups.NewID(); err != nil {
			return store.Group{}, err
		}
	}
	norm.ID = id
	g.items = append(g.items, norm)
	return cloneGroup(norm), nil
}

// Update validates+normalizes and replaces the zone at id (preserving id).
func (g *Groups) Update(id string, in store.Group) (store.Group, error) {
	norm, err := groups.Normalize(in)
	if err != nil {
		return store.Group{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	idx := g.indexOfLocked(id)
	if idx < 0 {
		return store.Group{}, demoGroupNotFound(id)
	}
	norm.ID = id
	g.items[idx] = norm
	return cloneGroup(norm), nil
}

// Delete removes the zone at id.
func (g *Groups) Delete(id string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	idx := g.indexOfLocked(id)
	if idx < 0 {
		return demoGroupNotFound(id)
	}
	g.items = append(g.items[:idx], g.items[idx+1:]...)
	return nil
}

func (g *Groups) indexOfLocked(id string) int {
	for i := range g.items {
		if g.items[i].ID == id {
			return i
		}
	}
	return -1
}

// demoGroupNotFound mirrors the real store's 404 (the api maps it structurally).
type demoGroupNotFound string

func (e demoGroupNotFound) Error() string   { return "group not found" }
func (e demoGroupNotFound) HTTPStatus() int { return 404 }
func (e demoGroupNotFound) Detail() string  { return "no group with id " + string(e) }

func cloneGroups(in []store.Group) []store.Group {
	out := make([]store.Group, 0, len(in))
	for _, g := range in {
		out = append(out, cloneGroup(g))
	}
	return out
}

func cloneGroup(g store.Group) store.Group {
	return store.Group{
		ID:               g.ID,
		Name:             g.Name,
		Consumers:        append([]string(nil), g.Consumers...),
		AllowedExitNodes: append([]string(nil), g.AllowedExitNodes...),
	}
}
