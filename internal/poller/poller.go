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
	"fmt"
	"strings"
	"time"

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

const (
	defaultInterval = 30 * time.Second // poll cadence while a client is connected
	defaultLinger   = 45 * time.Second // grace after the last client leaves (DESIGN §6)
)

// HTTP-ish status hints the api maps onto response codes (read structurally, so
// api stays decoupled from this concrete error type). See controlError.
const (
	statusBadRequest = 400
	statusBadGateway = 502
)

// Poller owns the refresh loop and writes Snapshots into the Store.
type Poller struct {
	store       *store.Store
	nm          Netmapper
	rc          RouterClient
	bc          Broadcaster
	routers     []string   // router 100.x IPv4s
	transitions <-chan int // client-count edges from the SSE hub (Transitions())
	interval    time.Duration
	linger      time.Duration
	logf        Logf
	group       singleflight.Group // collapse concurrent first-viewer refreshes (DESIGN §6)
}

// New constructs a Poller. transitions is the SSE hub's Transitions() channel
// (drives idle suspension). interval is the poll cadence while ≥1 client is
// connected (<=0 → default). logf must be non-nil; pass log.Printf or similar.
func New(st *store.Store, nm Netmapper, rc RouterClient, routers []string, bc Broadcaster, transitions <-chan int, interval time.Duration, logf Logf) *Poller {
	if interval <= 0 {
		interval = defaultInterval
	}
	if logf == nil {
		logf = func(string, ...any) {} // verbosity guard, not error swallowing
	}
	return &Poller{
		store:       st,
		nm:          nm,
		rc:          rc,
		bc:          bc,
		routers:     routers,
		transitions: transitions,
		interval:    interval,
		linger:      defaultLinger,
		logf:        logf,
	}
}

// controlError carries a user-facing message plus an HTTP status / detail /
// stderr the api surfaces via structural interfaces (no cross-package coupling).
type controlError struct {
	status int
	msg    string
	detail string
	stderr string
	err    error
}

func (e *controlError) Error() string   { return e.msg }
func (e *controlError) HTTPStatus() int { return e.status }
func (e *controlError) Detail() string  { return e.detail }
func (e *controlError) Stderr() string  { return e.stderr }
func (e *controlError) Unwrap() error   { return e.err }

func preflightErr(format string, args ...any) *controlError {
	return &controlError{status: statusBadRequest, msg: fmt.Sprintf(format, args...)}
}

// extractStderr pulls a router stderr out of an error chain if it exposes one.
func extractStderr(err error) string {
	var se interface{ Stderr() string }
	if errors.As(err, &se) {
		return se.Stderr()
	}
	return ""
}

// SetExitNode is the api.Controller seam (DESIGN §8): resolve routerID→addr and
// targetStableID→*ExitNodeRef from the current snapshot, pre-flight, mark the
// router pending, run the dead-man's-switch on the RouterClient, reconcile the
// ACTUAL selection into a fresh Snapshot, Broadcast, and return the updated
// RouterView. targetStableID == "" clears the exit node. Never optimistic.
func (p *Poller) SetExitNode(ctx context.Context, routerID, targetStableID string) (store.RouterView, error) {
	snap := p.store.Load()

	prevRV := findRouterViewByStableID(snap, routerID)
	if prevRV == nil {
		return store.RouterView{}, preflightErr("unknown router %q", routerID)
	}
	addr := primaryIP(prevRV.Node)
	if addr == "" {
		return store.RouterView{}, preflightErr("router %q has no Tailscale IPv4 address", routerID)
	}
	prev := prevRV.CurrentExitNode

	// Resolve + pre-flight the target (nil target == clear).
	var target *store.ExitNodeRef
	if targetStableID != "" {
		nv, ok := findNodeByStableID(snap.Nodes, targetStableID)
		if !ok {
			return store.RouterView{}, preflightErr("unknown exit node %q", targetStableID)
		}
		if nv.StableID == routerID {
			return store.RouterView{}, preflightErr("cannot route router %q through itself", routerID)
		}
		if !nv.Online {
			return store.RouterView{}, preflightErr("exit node %q is offline", displayName(nv))
		}
		if !nv.ExitNodeOption {
			return store.RouterView{}, preflightErr("node %q is not an approved exit node", displayName(nv))
		}
		ip := primaryIP(nv)
		if ip == "" {
			return store.RouterView{}, preflightErr("exit node %q has no Tailscale IPv4 address", displayName(nv))
		}
		if ip == addr {
			// The only loop we can detect from inventory: routing a router
			// through itself. Deeper path loops aren't derivable here.
			return store.RouterView{}, preflightErr("cannot route router %q through itself (loop)", routerID)
		}
		target = &store.ExitNodeRef{StableID: nv.StableID, Name: nv.Name, IP: ip}
	}

	// Show intent immediately as PENDING (intent, never success).
	pending := p.withRouter(routerID, func(rv *store.RouterView) {
		rv.Desired = target
		rv.State = store.RouterPending
		rv.LastError = ""
	})
	p.store.Store(pending)
	p.bc.Broadcast(pending)

	// Dead-man's-switch on the router (arm → apply → confirm → keep).
	rt, setErr := p.rc.SetExitNode(ctx, addr, target, prev)
	now := time.Now()

	var updated store.RouterView
	final := p.withRouter(routerID, func(rv *store.RouterView) {
		rv.Stats = rt.Stats
		switch {
		case setErr == nil: // confirmed
			rv.Reachable = true
			rv.CurrentExitNode = rt.Current
			rv.Desired = nil
			rv.State = store.RouterOK
			rv.LastError = ""
			rv.LastConfirmedAt = now
		case rt.Online: // applied but not confirmed equal (or confirm read mismatch)
			rv.Reachable = true
			rv.CurrentExitNode = rt.Current
			rv.Desired = target
			rv.State = store.RouterUnconfirmed
			rv.LastError = setErr.Error()
		default: // could not reach / apply
			rv.Reachable = false
			rv.Desired = target
			rv.State = store.RouterUnreachable
			rv.LastError = setErr.Error()
		}
		updated = *rv
	})
	p.store.Store(final)
	p.bc.Broadcast(final)

	switch {
	case setErr == nil, rt.Online:
		// Honest non-error: the RouterView's State (ok / unconfirmed) tells the
		// truth; unconfirmed is NOT shown as success by the UI.
		return updated, nil
	default:
		return updated, &controlError{
			status: statusBadGateway,
			msg:    "router command failed",
			detail: setErr.Error(),
			stderr: extractStderr(setErr),
			err:    setErr,
		}
	}
}

// Refresh builds one fresh Snapshot (inventory + per-router status), stores it,
// and broadcasts it -- gated through singleflight so concurrent first-loads
// collapse to one fetch. The returned error is the inventory error (also placed
// in Snapshot.NetmapErr); a snapshot is ALWAYS built and broadcast regardless.
func (p *Poller) Refresh(ctx context.Context) error {
	_, err, _ := p.group.Do("refresh", func() (any, error) {
		snap, invErr := p.build(ctx)
		p.store.Store(snap)
		p.bc.Broadcast(snap)
		return nil, invErr
	})
	return err
}

// build assembles a fresh immutable Snapshot. Inventory failure → NetmapErr +
// keep last-good nodes; per-router failure → that RouterView unreachable +
// LastError (never aborts the whole snapshot).
func (p *Poller) build(ctx context.Context) (*store.Snapshot, error) {
	now := time.Now()
	prev := p.store.Load()

	nodes, invErr := p.nm.Inventory(ctx)
	netmapErr := ""
	netmapAt := now
	if invErr != nil {
		netmapErr = invErr.Error()
		if prev != nil { // keep last-good inventory for continuity (DESIGN §8)
			nodes = prev.Nodes
			netmapAt = prev.NetmapAt
		}
	}

	routers := make([]store.RouterView, 0, len(p.routers))
	for _, addr := range p.routers {
		routers = append(routers, p.buildRouterView(ctx, addr, nodes, prev))
	}

	return &store.Snapshot{
		Nodes:     nodes,
		Routers:   routers,
		NetmapAt:  netmapAt,
		NetmapErr: netmapErr,
		BuiltAt:   now,
	}, invErr
}

// buildRouterView resolves one configured router to a RouterView: match its IP in
// the inventory, carry forward last-confirmed state, then read its live status.
func (p *Poller) buildRouterView(ctx context.Context, addr string, nodes []store.NodeView, prev *store.Snapshot) store.RouterView {
	var rv store.RouterView
	if nv, ok := findNodeByIP(nodes, addr); ok {
		rv.Node = nv
	} else {
		// Configured router missing from the netmap: still appears, unreachable.
		rv.Node = store.NodeView{TailscaleIPs: []string{addr}, Type: store.NodeRouter}
	}

	if prevRV := findRouterView(prev, addr); prevRV != nil {
		rv.Desired = prevRV.Desired
		rv.CurrentExitNode = prevRV.CurrentExitNode
		rv.Stats = prevRV.Stats
		rv.LastConfirmedAt = prevRV.LastConfirmedAt
	}

	rt, err := p.rc.Status(ctx, addr)
	if err != nil {
		rv.Reachable = false
		rv.State = store.RouterUnreachable
		rv.LastError = err.Error()
		return rv // keep last-confirmed CurrentExitNode/Stats as stale
	}

	rv.Reachable = true
	rv.CurrentExitNode = rt.Current
	rv.Stats = rt.Stats
	rv.LastError = ""
	rv.LastConfirmedAt = time.Now()
	reconcileState(&rv)
	return rv
}

// Run is the idle-aware loop (DESIGN §6): poll on a ticker only while ≥1 client
// is connected; do the first-viewer refresh on 0->1 (via singleflight); linger
// ~45s after the last client leaves before suspending the ticker.
func (p *Poller) Run(ctx context.Context) error {
	var (
		active  bool
		ticker  *time.Ticker
		tickC   <-chan time.Time
		linger  *time.Timer
		lingerC <-chan time.Time
	)
	startTicker := func() {
		if ticker == nil {
			ticker = time.NewTicker(p.interval)
			tickC = ticker.C
		}
	}
	stopTicker := func() {
		if ticker != nil {
			ticker.Stop()
			ticker, tickC = nil, nil
		}
	}
	armLinger := func() {
		if linger == nil {
			linger = time.NewTimer(p.linger)
			lingerC = linger.C
		}
	}
	disarmLinger := func() {
		if linger != nil {
			if !linger.Stop() {
				select {
				case <-linger.C:
				default:
				}
			}
			linger, lingerC = nil, nil
		}
	}
	defer stopTicker()
	defer func() {
		if linger != nil {
			linger.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case n := <-p.transitions:
			if n > 0 {
				disarmLinger() // a client (re)connected; cancel any pending suspend
				if !active {
					active = true
					startTicker()
					if err := p.Refresh(ctx); err != nil {
						p.logf("poller: first-viewer refresh: %v", err)
					}
				}
			} else if active {
				armLinger() // last client left; keep ticking until linger fires
			}
		case <-lingerC:
			active = false
			stopTicker()
			disarmLinger()
		case <-tickC:
			if err := p.Refresh(ctx); err != nil {
				p.logf("poller: refresh: %v", err)
			}
		}
	}
}

// withRouter returns a fresh Snapshot copied from the current one with mutate
// applied to the RouterView whose router StableID matches (immutable swap-in).
func (p *Poller) withRouter(routerID string, mutate func(*store.RouterView)) *store.Snapshot {
	cur := p.store.Load()
	routers := make([]store.RouterView, len(cur.Routers))
	copy(routers, cur.Routers)
	for i := range routers {
		if routers[i].Node.StableID == routerID {
			mutate(&routers[i])
		}
	}
	return &store.Snapshot{
		Nodes:     cur.Nodes,
		Routers:   routers,
		NetmapAt:  cur.NetmapAt,
		NetmapErr: cur.NetmapErr,
		BuiltAt:   time.Now(),
	}
}

// reconcileState derives State from the reachable/desired/current fields.
func reconcileState(rv *store.RouterView) {
	if !rv.Reachable {
		rv.State = store.RouterUnreachable
		return
	}
	if rv.Desired != nil && !sameExitNode(rv.CurrentExitNode, rv.Desired) {
		rv.State = store.RouterUnconfirmed // a pending change still hasn't landed
		return
	}
	rv.Desired = nil
	rv.State = store.RouterOK
}

func sameExitNode(a, b *store.ExitNodeRef) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.StableID != "" && b.StableID != "" {
		return a.StableID == b.StableID
	}
	return a.IP == b.IP
}

// primaryIP returns the node's 100.x IPv4 (first IPv4, else first IP, else "").
func primaryIP(n store.NodeView) string {
	for _, ip := range n.TailscaleIPs {
		if strings.Contains(ip, ".") {
			return ip
		}
	}
	if len(n.TailscaleIPs) > 0 {
		return n.TailscaleIPs[0]
	}
	return ""
}

func displayName(n store.NodeView) string {
	switch {
	case n.Name != "":
		return n.Name
	case n.Hostname != "":
		return n.Hostname
	default:
		return n.StableID
	}
}

func findNodeByIP(nodes []store.NodeView, addr string) (store.NodeView, bool) {
	for _, n := range nodes {
		for _, ip := range n.TailscaleIPs {
			if ip == addr {
				return n, true
			}
		}
	}
	return store.NodeView{}, false
}

func findNodeByStableID(nodes []store.NodeView, id string) (store.NodeView, bool) {
	for _, n := range nodes {
		if n.StableID == id {
			return n, true
		}
	}
	return store.NodeView{}, false
}

func findRouterView(snap *store.Snapshot, addr string) *store.RouterView {
	if snap == nil {
		return nil
	}
	for i := range snap.Routers {
		for _, ip := range snap.Routers[i].Node.TailscaleIPs {
			if ip == addr {
				return &snap.Routers[i]
			}
		}
	}
	return nil
}

func findRouterViewByStableID(snap *store.Snapshot, id string) *store.RouterView {
	if snap == nil {
		return nil
	}
	for i := range snap.Routers {
		if snap.Routers[i].Node.StableID == id {
			return &snap.Routers[i]
		}
	}
	return nil
}
