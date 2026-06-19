// Package poller runs the idle-aware refresh loop that builds Snapshots.
//
// It declares the consumer-side interfaces it depends on (Netmapper,
// RouterClient) and the RouterRuntime type, per DESIGN §4: interfaces live at
// the CONSUMER to avoid import cycles. The concrete *netmap.Mapper and
// *router.Client are injected by the composition root (cmd/tsctl), so this
// package never imports netmap. It does import router for one purpose only: to
// recognise a definitive *router.CommandError (a command that RAN and failed)
// so SetExitNode can tell a hard apply failure -- the change did NOT take --
// apart from an applied-but-unconfirmed result. No import cycle: router depends
// only on store, never on poller.
//
// FROZEN CONTRACT: the interface and type names below are the seam.
package poller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/lifeart/tsctl/internal/router"
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
	// ApplyExitNode runs arm→apply→confirm. On confirm it either writes the keep
	// marker inline (autoKeep=true, returns marker=="") or returns the marker for a
	// deferred KeepExitNode (autoKeep=false, the explicit-Keep gate). On any failure
	// the marker is left unwritten (the armed revert fires) and marker=="" is
	// returned with the error. (docs/design/keep-egress.md stage 2.)
	ApplyExitNode(ctx context.Context, addr string, target *store.ExitNodeRef, prev *store.ExitNodeRef, autoKeep bool) (store.RouterRuntime, string, error)
	// KeepExitNode writes the keep marker for a prior ApplyExitNode(autoKeep=false),
	// cancelling the armed revert. A non-zero exit / transport failure is returned.
	KeepExitNode(ctx context.Context, addr, marker string) error
	// Probe runs a read-only diagnostic over the same transport as Status and
	// returns its trimmed stdout (or a transport/command error). Used by the
	// "test SSH" probe endpoint.
	Probe(ctx context.Context, addr string) (string, error)
	// EgressProbe makes ONE read-only outbound request from the router (which now
	// routes through its current exit node) to test actual internet egress
	// (docs/design/keep-egress.md). ok==false with err==nil is a RESULT (no egress
	// yet); only a transport/SSH failure returns a non-nil error.
	EgressProbe(ctx context.Context, addr, url string) (bool, string, error)
}

// GroupReader supplies the current zone/group definitions (DESIGN
// docs/design/zones.md). Implemented by *groups.Store. Declared here (consumer
// side) so the poller never imports the groups package. The poller resolves them
// into Snapshot.Groups every build and enforces the allowed-exit-node set in
// SetExitNode. A nil GroupReader (or an empty list) means "no zones": no resolved
// groups and unrestricted exit-node changes.
type GroupReader interface {
	List() []store.Group
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
	statusBadRequest    = 400
	statusNotFound      = 404 // unknown router (probe / keep)
	statusConflict      = 409 // keep with no/elapsed/superseded pending entry (keep-egress)
	statusUnprocessable = 422 // zone policy refusal (docs/design/zones.md)
	statusBadGateway    = 502
)

// tsctlTag marks the tsctl control node itself; the auto-discovery fallback skips
// it so tsctl never tries to control its own host.
const tsctlTag = "tag:tsctl"

// Poller owns the refresh loop and writes Snapshots into the Store.
type Poller struct {
	store       *store.Store
	nm          Netmapper
	rc          RouterClient
	groups      GroupReader // zone/group definitions (may be nil = no zones)
	bc          Broadcaster
	routers     []string   // router 100.x IPv4s
	transitions <-chan int // client-count edges from the SSE hub (Transitions())
	interval    time.Duration
	linger      time.Duration
	logf        Logf
	group       singleflight.Group // collapse concurrent first-viewer refreshes (DESIGN §6)

	// fallbackOnce ensures the "no tag:router nodes found" auto-discovery fallback
	// is logged exactly once, not on every poll (it's an informational notice, not
	// an error).
	fallbackOnce sync.Once

	// mu serializes the read-modify-write on the atomic Store across the poller
	// (Refresh) and handler (SetExitNode) goroutines (M3). Both do Load→copy→
	// modify→Store; without this they clobber each other. Readers still Load()
	// lock-free -- mu only guards writers, never the read path.
	mu sync.Mutex

	// setSeq is a per-router (keyed by addr) monotonic counter bumped at SetExitNode
	// STEP 1 only. mySeq is captured at step 1 and re-checked at step 3 to SUPERSEDE
	// an older op's reconcile when a newer set has started (so the snapshot never
	// shows a confirmed exit node that contradicts the device). All under mu.
	setSeq map[string]uint64
	// setGen is bumped at BOTH SetExitNode step 1 AND step 3 -- i.e. on any set
	// activity (pending store and reconcile). refreshOnce captures it before its
	// slow dials and keeps the published view (not its own stale dial read) for any
	// router whose setGen changed during the dial window. setSeq alone is
	// insufficient: a set that STARTED before the capture but CONFIRMS during the
	// dial leaves setSeq unchanged, so without the step-3 bump the poll would clobber
	// the confirmed set with a stale read (a false-confirm). Guarded by mu.
	setGen map[string]uint64

	// egressCheck / egressURL configure the post-confirm egress probe
	// (docs/design/keep-egress.md, stage 1). Set ONCE via ConfigureEgress before
	// Run; the zero value (egressCheck=false) leaves egress OFF, so callers that
	// never configure it -- and existing tests -- skip the probe entirely.
	egressCheck bool
	egressURL   string

	// requireKeep gates the explicit-Keep step (docs/design/keep-egress.md stage 2).
	// Set ONCE via ConfigureKeep before Run; the zero value (false) keeps the
	// backward-compatible AUTO-keep behavior, so every existing test/behavior is
	// byte-for-byte identical when it is off.
	requireKeep bool
	// revertWindow is the dead-man's-switch deadline (router.RevertWindow) used to
	// compute a confirmed-but-unkept selection's RevertAt. A field so tests can
	// shorten it.
	revertWindow time.Duration
	// pendingKeep records, per router addr, a confirmed exit-node change that is
	// AWAITING an operator Keep within the revert window: {marker, revertAt, seq}.
	// mu-guarded (same lock as the snapshot RMW + setSeq/setGen). In-memory BY
	// DESIGN: a tsctl restart loses it -> the marker is never written -> the router
	// auto-reverts (fail-safe; the dead-man's-switch holds). seq ties the entry to
	// the SetExitNode that created it (== setSeq[addr] at step 1) so a newer set
	// supersedes a stale pending Keep.
	pendingKeep map[string]keepEntry
}

// keepEntry is one router's pending explicit-Keep (docs/design/keep-egress.md
// stage 2). marker is the router-side keep-marker path ApplyExitNode returned;
// revertAt is when the armed revert fires; seq is the owning SetExitNode's setSeq.
type keepEntry struct {
	marker   string
	revertAt time.Time
	seq      uint64
}

// New constructs a Poller. transitions is the SSE hub's Transitions() channel
// (drives idle suspension). interval is the poll cadence while ≥1 client is
// connected (<=0 → default). logf must be non-nil; pass log.Printf or similar.
// groups supplies the zone definitions (may be nil = no zones / unrestricted).
func New(st *store.Store, nm Netmapper, rc RouterClient, groups GroupReader, routers []string, bc Broadcaster, transitions <-chan int, interval time.Duration, logf Logf) *Poller {
	if interval <= 0 {
		interval = defaultInterval
	}
	if logf == nil {
		logf = func(string, ...any) {} // verbosity guard, not error swallowing
	}
	return &Poller{
		store:        st,
		nm:           nm,
		rc:           rc,
		groups:       groups,
		bc:           bc,
		routers:      routers,
		transitions:  transitions,
		interval:     interval,
		linger:       defaultLinger,
		logf:         logf,
		setSeq:       make(map[string]uint64),
		setGen:       make(map[string]uint64),
		pendingKeep:  make(map[string]keepEntry),
		revertWindow: router.RevertWindow,
	}
}

// ConfigureEgress enables (or disables) the post-confirm egress probe and sets the
// URL it fetches FROM the router. Call ONCE at startup (before Run) -- the
// composition root wires it from cfg.EgressCheck / cfg.EgressURL. The zero value
// (check=false) leaves egress OFF, preserving existing behavior.
func (p *Poller) ConfigureEgress(check bool, url string) {
	p.egressCheck = check
	p.egressURL = url
}

// ConfigureKeep enables (or disables) the explicit-Keep gate (docs/design/keep-
// egress.md stage 2). Call ONCE at startup (before Run) -- the composition root
// wires it from cfg.RequireKeep. The zero value (false) leaves the gate OFF, so a
// confirmed set auto-keeps exactly as in v1 (default behavior unchanged).
func (p *Poller) ConfigureKeep(require bool) {
	p.requireKeep = require
}

// groupList returns the current zone definitions, or nil when no GroupReader was
// injected. Centralizes the nil-guard so build/enforcement stay simple.
func (p *Poller) groupList() []store.Group {
	if p.groups == nil {
		return nil
	}
	return p.groups.List()
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
	// Defensive COPY (low fix): prevRV.CurrentExitNode aliases a pointer inside the
	// shared, stored snapshot. Hand the router layer an independent value, never an
	// alias into the immutable snapshot.
	prev := copyExitRef(prevRV.CurrentExitNode)

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
		// ZONE ENFORCEMENT (DESIGN docs/design/zones.md "Enforce"): if this
		// consumer (router StableID) belongs to ≥1 zone, the target must be in the
		// UNION of those zones' AllowedExitNodes. Direct/clear (target==nil) is
		// always allowed -- handled by being inside this targetStableID!="" block.
		// A consumer in no zone is unrestricted. The backend is the source of
		// truth; the UI guard is advisory.
		allowed, inAnyZone := p.allowedExitNodeSet(routerID)
		if inAnyZone {
			if _, ok := allowed[nv.StableID]; !ok {
				// A zone-policy refusal is a 422 (the request is well-formed but
				// violates the zone's allowed-exit-node set), per docs/design/zones.md.
				return store.RouterView{}, &controlError{
					status: statusUnprocessable,
					msg: fmt.Sprintf("exit node %q is not allowed for %q in its zone(s)",
						displayName(nv), displayName(prevRV.Node)),
				}
			}
		}
		target = &store.ExitNodeRef{StableID: nv.StableID, Name: nv.Name, IP: ip}
	}

	// Show intent immediately as PENDING (intent, never success). The RMW is
	// guarded by mu (M3) and the router is matched by its configured IP `addr`
	// (M4) -- not StableID, which goes empty for a router missing from the netmap,
	// which would make this a silent no-op that stores a blank RouterView.
	p.mu.Lock()
	p.setSeq[addr]++
	p.setGen[addr]++        // step-1 set activity (poll-guard generation)
	mySeq := p.setSeq[addr] // this op's sequence; a later set bumps it past mine
	pending, ok := p.withRouter(addr, func(rv *store.RouterView) {
		rv.Desired = target
		rv.State = store.RouterPending
		rv.LastError = ""
	})
	if ok {
		p.store.Store(pending)
	}
	p.mu.Unlock()
	if !ok {
		// The configured router is no longer in the snapshot; do not publish a
		// blank RouterView -- surface it (M4).
		return store.RouterView{}, preflightErr("router %q is no longer present in the snapshot", routerID)
	}
	p.bc.Broadcast(pending)

	// Dead-man's-switch on the router (arm → apply → confirm [→ keep]). Run OUTSIDE
	// mu: it can take the whole revert window, and must not block the poll loop.
	// Hand the router layer its OWN copy of target -- `target` is simultaneously
	// published in the pending snapshot's Desired, so sharing the pointer with the
	// router (as we already avoid for `prev`) would be a torn-read footgun for a
	// lock-free reader if any RouterClient ever mutated it.
	//
	// autoKeep mirrors the default: with -require-keep OFF the marker is written
	// inline on confirm (v1 auto-keep); with it ON the marker is returned and held
	// until an explicit operator Keep (the awaiting-keep gate below).
	// Auto-keep when -require-keep is OFF, OR when CLEARING to Direct: going Direct
	// carries no connectivity risk, so it never needs an operator Keep. Only a SET
	// with -require-keep ON enters the awaiting-keep gate.
	autoKeep := !p.requireKeep || target == nil
	// The router's revert timer starts at ARM (inside ApplyExitNode), so RevertAt is
	// measured from BEFORE the apply, not after (Finding C): otherwise the displayed
	// countdown + Keep validity would outlast the device's real revert by ~the
	// apply/confirm latency.
	armAt := time.Now()
	rt, marker, setErr := p.rc.ApplyExitNode(ctx, addr, copyExitRef(target), prev, autoKeep)
	now := time.Now()

	// Distinguish a DEFINITIVE command failure (the arm/apply command RAN and
	// exited non-zero, surfaced as *router.CommandError) from an applied-but-
	// unconfirmed result. A *router.CommandError means the change did NOT take:
	// the device kept its PREVIOUS selection and nothing is pending -- so it is
	// wrong to show it as "unconfirmed / will auto-revert". For a hard failure we
	// best-effort re-read the device's ACTUAL (unchanged) selection so the card
	// shows the truth. The re-read is a network round-trip, so it runs OUTSIDE mu.
	var cmdErr *router.CommandError
	hardFail := setErr != nil && errors.As(setErr, &cmdErr)
	var reread store.RouterRuntime
	rereadOK := false
	if hardFail {
		if rr, rrErr := p.rc.Status(ctx, addr); rrErr == nil {
			reread, rereadOK = rr, true
		}
	}

	// EGRESS PROBE (docs/design/keep-egress.md, stage 1): on a CONFIRMED SET (not a
	// clear, not a failure) and only when configured, test actual internet egress
	// THROUGH the just-selected exit node. Read-only, over the router's own runSSH
	// seam; run OUTSIDE mu (a network round-trip, like the SetExitNode/re-read
	// above) so it never blocks the poll loop. Advisory: an egress failure does NOT
	// fail or revert the set -- the selection is already applied + confirmed. A
	// transport error is surfaced (logged + carried as detail) but treated as
	// ok=false, never swallowed.
	setting := target != nil
	var (
		egressRan bool
		egressOK  bool
		egressDet string
	)
	if setErr == nil && setting && p.egressCheck {
		eok, edet, eerr := p.rc.EgressProbe(ctx, addr, p.egressURL)
		if eerr != nil {
			p.logf("poller: egress probe %s: %v", addr, eerr)
			if edet == "" {
				edet = eerr.Error()
			}
		}
		egressRan, egressOK, egressDet = true, eok, edet
	}

	var updated store.RouterView
	p.mu.Lock()
	p.setGen[addr]++ // step-3 set activity: lets a concurrent poll detect a set that
	// CONFIRMED during its dial window (setSeq is unchanged since step 1, so the
	// poll's setGen guard -- not setSeq -- is what catches this).
	// If a newer SetExitNode on this router started while our slow apply ran, our
	// captured result is stale -- do NOT publish it (it could show a confirmed exit
	// node the device is no longer on). The newest op owns the published snapshot.
	superseded := p.setSeq[addr] != mySeq
	final, ok := p.withRouter(addr, func(rv *store.RouterView) {
		rv.RevertAt = time.Time{} // only an awaiting-keep selection carries a deadline
		switch {
		case setErr == nil: // confirmed
			rv.Stats = rt.Stats
			rv.Reachable = true
			rv.CurrentExitNode = rt.Current
			rv.Desired = nil
			rv.LastError = ""
			rv.LastConfirmedAt = now
			if autoKeep {
				// Auto-keep (-require-keep OFF): the marker was written inline -> this
				// IS success. UNCHANGED v1 behavior.
				rv.State = store.RouterOK
			} else {
				// -require-keep ON: confirmed but the marker is NOT written yet. This is
				// explicitly NOT success -- the armed revert fires at RevertAt unless the
				// operator calls Keep within the window (the pending entry is recorded
				// under the SAME mu below).
				rv.State = store.RouterAwaitingKeep
				rv.RevertAt = armAt.Add(p.revertWindow)
			}
			switch {
			case !setting:
				// Confirmed CLEAR (Direct): there is no egress to test, so drop any
				// carried-forward result (docs/design/keep-egress.md).
				rv.EgressOK = nil
				rv.EgressDetail = ""
				rv.EgressCheckedAt = time.Time{}
			case egressRan:
				// Confirmed SET with egress checking on: record the probe result.
				rv.EgressOK = &egressOK
				rv.EgressDetail = egressDet
				rv.EgressCheckedAt = now
			}
			// (Confirmed SET with egress OFF: leave any carried-forward egress as-is.)
		case hardFail:
			// The apply did not take; nothing is pending. Reflect the device's
			// ACTUAL, unchanged selection from the best-effort re-read. Surface the
			// command error in LastError (never swallow) -- the HTTP layer also
			// returns it (non-2xx) via the return switch below.
			rv.Desired = nil
			rv.LastError = setErr.Error()
			if rereadOK {
				// Reachable and simply still on its previous exit node.
				rv.Reachable = true
				rv.CurrentExitNode = reread.Current
				rv.Stats = reread.Stats
				rv.State = store.RouterOK
				rv.LastConfirmedAt = now
			} else {
				// Couldn't re-read: keep the last-known selection, mark unreachable.
				rv.Reachable = false
				rv.State = store.RouterUnreachable
			}
		case rt.Online: // applied but not confirmed equal (confirm-read mismatch)
			rv.Stats = rt.Stats
			rv.Reachable = true
			rv.CurrentExitNode = rt.Current
			rv.Desired = target
			rv.State = store.RouterUnconfirmed
			rv.LastError = setErr.Error()
		default: // could not reach / apply (transport failure, not a CommandError)
			rv.Stats = rt.Stats
			rv.Reachable = false
			rv.Desired = target
			rv.State = store.RouterUnreachable
			rv.LastError = setErr.Error()
		}
		updated = *rv
	})
	// Markers whose router-side revert timer must be DISARMED (its keep-marker
	// written so the sleeping `tailscale set --exit-node=<prev>` exits) after we
	// release mu -- each `ApplyExitNode(autoKeep=false)` armed an INDEPENDENT timer,
	// so any armed-but-not-the-active-gate marker would otherwise fire ~RevertWindow
	// later and clobber the live selection. Best-effort; KeepExitNode is idempotent
	// (`: > marker`) and takes the per-addr lock fresh (we hold no lock here).
	var disarm []string
	if ok && !superseded {
		// This op is the one being published. Record/clear the gate under the SAME mu
		// as the store + setSeq/setGen guard so they stay mutually consistent.
		switch {
		case setErr == nil && !autoKeep:
			// Confirmed awaiting-keep SET: this op's marker becomes the active gate. If
			// it REPLACES a prior awaiting-keep entry, that prior timer is now orphaned.
			if prior, had := p.pendingKeep[addr]; had && prior.marker != "" && prior.marker != marker {
				disarm = append(disarm, prior.marker)
			}
			p.pendingKeep[addr] = keepEntry{marker: marker, revertAt: armAt.Add(p.revertWindow), seq: mySeq}
		case setErr == nil:
			// Confirmed auto-keep or CLEAR: no gate for this op. Disarm + drop any prior
			// awaiting-keep entry (the device is now on the new selection / Direct).
			if prior, had := p.pendingKeep[addr]; had && prior.marker != "" {
				disarm = append(disarm, prior.marker)
			}
			delete(p.pendingKeep, addr)
		default:
			// FAILURE: leave any PRIOR op's entry untouched -- it's that op's gate; a
			// later set's disarm or the poll-overlay expiry cleans it. Deleting it here
			// would orphan its armed timer (untracked). This op's OWN failed-apply timer
			// correctly reverts to prev (the dead-man's-switch) and carries no marker.
		}
		p.store.Store(final)
	} else if marker != "" {
		// SUPERSEDED, or the router vanished from the snapshot: this op is NOT being
		// published, but ApplyExitNode already armed its timer (marker != ""). Disarm
		// it so it can't fire and revert the device away from whichever op DID win.
		disarm = append(disarm, marker)
	}
	p.mu.Unlock()
	for _, m := range disarm {
		if err := p.rc.KeepExitNode(ctx, addr, m); err != nil {
			p.logf("poller: disarm orphaned keep %s: %v", addr, err)
		}
	}
	if !ok {
		// Router vanished from the snapshot between apply and reconcile (M4):
		// never return/store a blank RouterView. Surface the underlying router
		// error if there was one, else report the reconcile gap.
		if setErr != nil {
			return store.RouterView{}, routerControlError(setErr)
		}
		return store.RouterView{}, &controlError{
			status: statusBadGateway,
			msg:    "router state unavailable",
			detail: fmt.Sprintf("router %q vanished from the snapshot before its result could be reconciled", routerID),
		}
	}
	if !superseded {
		p.bc.Broadcast(final) // a superseded op never publishes; the newer op owns it
	}

	switch {
	case setErr == nil:
		return updated, nil
	case hardFail:
		// Definitive command failure: the reconciled view above already reflects
		// the device's actual, unchanged selection, but the HTTP layer MUST still
		// surface the failure (non-2xx {error,detail,stderr}) so the caller knows
		// the requested change did not take.
		return updated, routerControlError(setErr)
	case rt.Online:
		// Applied-but-unconfirmed: honest non-error -- the RouterView's State
		// (unconfirmed) tells the truth and is NOT shown as success by the UI.
		return updated, nil
	default:
		return updated, routerControlError(setErr)
	}
}

// Keep writes the keep-marker for a router currently AWAITING an explicit Keep
// (docs/design/keep-egress.md stage 2), cancelling the armed dead-man's-switch
// revert and reconciling the router to RouterOK. It mirrors SetExitNode's
// structural-controlError pattern so the api maps the status the same way:
//   - unknown router / no IP            -> 404
//   - no pending entry                  -> 409 ("no exit-node change is awaiting confirmation")
//   - the revert window already elapsed -> 409 ("the revert window elapsed; the router has reverted")
//   - a newer set superseded this one   -> 409
//   - KeepExitNode (router) failed      -> 502 (the pending entry is LEFT so the operator can retry)
//
// The slow KeepExitNode runs OUTSIDE mu; the validate-before and reconcile-after
// both run UNDER mu so the pending entry + setSeq/setGen + snapshot stay coherent.
func (p *Poller) Keep(ctx context.Context, routerID string) (store.RouterView, error) {
	snap := p.store.Load()
	rv := findRouterViewByStableID(snap, routerID)
	if rv == nil {
		return store.RouterView{}, &controlError{status: statusNotFound, msg: fmt.Sprintf("unknown router %q", routerID)}
	}
	addr := primaryIP(rv.Node)
	if addr == "" {
		return store.RouterView{}, &controlError{status: statusNotFound, msg: fmt.Sprintf("router %q has no Tailscale IPv4 address", routerID)}
	}

	// Validate the pending entry under mu: present, within the window, not superseded.
	p.mu.Lock()
	entry, has := p.pendingKeep[addr]
	switch {
	case !has:
		p.mu.Unlock()
		return store.RouterView{}, &controlError{status: statusConflict, msg: "no exit-node change is awaiting confirmation"}
	case time.Now().After(entry.revertAt):
		// The dead-man's-switch has already fired on the router; the in-memory entry is
		// stale. Drop it AND reconcile the snapshot: a fallback (never re-dialed) router
		// would otherwise stay stuck in awaiting-keep forever (picker + Keep both dead),
		// since the poll-overlay's expiry cleanup is gated on the now-deleted entry.
		// Drop it to "unprobed" (the reverted-to selection is unknown without a dial)
		// and broadcast, then tell the operator the truth. (A managed router self-heals
		// on its next dial anyway; the withRouter guard only touches a still-awaiting view.)
		delete(p.pendingKeep, addr)
		p.setGen[addr]++
		reverted, rok := p.withRouter(addr, func(rv *store.RouterView) {
			if rv.State == store.RouterAwaitingKeep {
				rv.State = store.RouterUnprobed
				rv.RevertAt = time.Time{}
				rv.CurrentExitNode = nil
				rv.Desired = nil
				rv.Reachable = false
			}
		})
		if rok {
			p.store.Store(reverted)
		}
		p.mu.Unlock()
		if rok {
			p.bc.Broadcast(reverted)
		}
		return store.RouterView{}, &controlError{status: statusConflict, msg: "the revert window elapsed; the router has reverted"}
	case entry.seq != p.setSeq[addr]:
		// A newer SetExitNode bumped setSeq past this entry; that op owns the router.
		p.mu.Unlock()
		return store.RouterView{}, &controlError{status: statusConflict, msg: "a newer exit-node change superseded this one"}
	}
	marker := entry.marker
	mySeq := entry.seq
	p.mu.Unlock()

	// SLOW: write the keep-marker on the router OUTSIDE mu (it can take an SSH round
	// trip). On failure surface a 502 and LEAVE the pending entry so the operator can
	// retry until the window elapses -- never swallowed.
	if err := p.rc.KeepExitNode(ctx, addr, marker); err != nil {
		return store.RouterView{}, routerControlError(err)
	}

	// Reconcile to ok under mu. Re-check not-superseded: a newer set may have started
	// while we wrote the marker (writing the OLD marker is harmless -- it is a stale
	// path -- but the newer op owns the published state).
	var updated store.RouterView
	p.mu.Lock()
	if p.setSeq[addr] != mySeq {
		p.mu.Unlock()
		return store.RouterView{}, &controlError{status: statusConflict, msg: "a newer exit-node change superseded this one"}
	}
	p.setGen[addr]++ // keep activity: a concurrent poll mid-dial must not clobber the ok we publish
	final, ok := p.withRouter(addr, func(rv *store.RouterView) {
		rv.State = store.RouterOK
		rv.RevertAt = time.Time{}
		rv.LastError = ""
		updated = *rv
	})
	delete(p.pendingKeep, addr)
	if ok {
		p.store.Store(final)
	}
	p.mu.Unlock()
	if !ok {
		return store.RouterView{}, &controlError{
			status: statusBadGateway,
			msg:    "router state unavailable",
			detail: fmt.Sprintf("router %q vanished from the snapshot before its keep could be reconciled", routerID),
		}
	}
	p.bc.Broadcast(final)
	return updated, nil
}

// routerControlError maps a router-layer failure to the 502 the api surfaces,
// carrying the detail + stderr structurally (extractStderr reaches a
// *router.CommandError, including through the %w-wrapped confirm-read failure).
func routerControlError(setErr error) *controlError {
	return &controlError{
		status: statusBadGateway,
		msg:    "router command failed",
		detail: setErr.Error(),
		stderr: extractStderr(setErr),
		err:    setErr,
	}
}

// Probe runs the read-only SSH diagnostic for the router identified by routerID
// (its StableID), resolved against the CURRENT snapshot. An unknown router is the
// only case that returns a non-nil Go error -- a 404 controlError (mirroring how
// SetExitNode surfaces controlError statuses) the api maps to 404. An offline
// node is reported as a RESULT ({OK:false, Error:"node is offline"}) without
// dialing. Otherwise it times rc.Probe: success -> {OK:true, Output, DurationMs};
// an SSH/command failure is a RESULT ({OK:false, Error}), NOT a returned error.
func (p *Poller) Probe(ctx context.Context, routerID string) (store.ProbeResult, error) {
	snap := p.store.Load()

	rv := findRouterViewByStableID(snap, routerID)
	if rv == nil {
		return store.ProbeResult{}, &controlError{status: statusNotFound, msg: fmt.Sprintf("unknown router %q", routerID)}
	}
	addr := primaryIP(rv.Node)
	if addr == "" {
		return store.ProbeResult{}, &controlError{status: statusNotFound, msg: fmt.Sprintf("router %q has no Tailscale IPv4 address", routerID)}
	}

	// Offline-skip: don't dial a node the netmap reports offline (it would hang to
	// the ssh timeout). Report it as a result, not an error.
	if !rv.Node.Online {
		return store.ProbeResult{OK: false, Error: "node is offline", CheckedAt: time.Now()}, nil
	}

	start := time.Now()
	out, err := p.rc.Probe(ctx, addr)
	dur := time.Since(start).Milliseconds()
	if err != nil {
		// SSH/transport/command failure is a RESULT (the probe ran and failed),
		// surfaced in Error -- never swallowed, never a returned Go error.
		return store.ProbeResult{OK: false, Error: err.Error(), DurationMs: dur, CheckedAt: time.Now()}, nil
	}
	return store.ProbeResult{OK: true, Output: out, DurationMs: dur, CheckedAt: time.Now()}, nil
}

// Refresh builds one fresh Snapshot (inventory + per-router status), stores it,
// and broadcasts it -- gated through singleflight so concurrent first-loads
// collapse to one fetch. The returned error is the inventory error (also placed
// in Snapshot.NetmapErr); a snapshot is ALWAYS built and broadcast regardless.
func (p *Poller) Refresh(ctx context.Context) error {
	_, err, _ := p.group.Do("refresh", func() (any, error) {
		return nil, p.refreshOnce(ctx)
	})
	return err
}

// refreshOnce does the SLOW poll work -- the netmap inventory and the per-router
// SSH `tailscale status` dials -- WITHOUT holding mu, then takes mu only for a fast
// merge + Store + Broadcast. This keeps a slow poll (many routers, or a hung SSH
// up to the timeout) from blocking SetExitNode / RefreshGroups, which need mu only
// briefly (L-3).
//
// Atomicity vs a concurrent SetExitNode (M3): we snapshot each router's setGen
// BEFORE the dials; at the locked merge, if a router's setGen changed, a
// SetExitNode touched it during our now-stale dial (started OR confirmed), so we
// KEEP the currently published view for that router instead of clobbering it with
// our stale read. setGen (bumped at SetExitNode step 1 AND step 3) is used rather
// than setSeq (step 1 only) precisely so a set that started before our capture but
// confirmed during the dial is still caught -- otherwise the poll would publish a
// false-confirm. Inventory failure -> NetmapErr + keep last-good nodes; a
// per-router dial failure -> that RouterView unreachable (never aborts the snapshot).
func (p *Poller) refreshOnce(ctx context.Context) error {
	now := time.Now()
	prev := p.store.Load()

	// SLOW (no mu): netmap inventory.
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

	// Router set + how it is polled:
	//   - an explicit -routers list, or tag:router nodes, are the MANAGED set: we
	//     actively poll each one (SSH `tailscale status`) every cycle.
	//   - otherwise the non-exit-node FALLBACK: a tailnet can have many devices, so
	//     we LIST them as consumers but NEVER auto-SSH them (that would be a probe
	//     storm). They stay "unprobed" until a manual Test SSH or exit-node change.
	addrs := p.routers
	usedFallback := false
	if len(addrs) == 0 {
		addrs, usedFallback = autoDiscoverRouters(nodes)
		if usedFallback && len(addrs) > 0 {
			// Log ONCE (not every poll): no tag:router nodes exist, so we LIST every
			// non-exit node without probing it. Tagging routers tag:router scopes this.
			p.fallbackOnce.Do(func() {
				p.logf("poller: no tag:router nodes found — listing all %d non-exit nodes as consumers (NOT auto-probed; use Test SSH, or tag routers with tag:router)", len(addrs))
			})
		}
	}

	// Snapshot each router's setGen BEFORE the slow dials, so the merge can detect a
	// SetExitNode that touched it during them -- including one that STARTED before
	// this capture but CONFIRMS during the dial (setGen bumps at both step 1 and
	// step 3; setSeq alone would miss that and let the poll clobber the confirmed set).
	genAt := make(map[string]uint64, len(addrs))
	p.mu.Lock()
	for _, addr := range addrs {
		genAt[addr] = p.setGen[addr]
	}
	p.mu.Unlock()

	// SLOW (no mu): per-router dials. Fallback routers are listed without dialing.
	routers := make([]store.RouterView, 0, len(addrs))
	for _, addr := range addrs {
		if usedFallback {
			routers = append(routers, p.buildListedRouterView(addr, nodes, prev))
		} else {
			routers = append(routers, p.buildRouterView(ctx, addr, nodes, prev))
		}
	}

	// FAST (mu): merge, then Store + Broadcast atomically. Broadcast is UNDER mu
	// (the hub is non-blocking) so frame order == store order (RefreshGroups too).
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.store.Load()
	for i, addr := range addrs {
		if p.setGen[addr] != genAt[addr] {
			// A SetExitNode/Keep touched this router while we were dialing (started OR
			// confirmed/kept during the window): its reconcile owns the published state.
			// Keep the current view; don't clobber it with our possibly-stale read.
			if curRV := findRouterView(cur, addr); curRV != nil {
				routers[i] = *curRV
			}
			continue
		}
		// AWAITING-KEEP gate (docs/design/keep-egress.md stage 2). A confirmed-but-
		// unkept set holds the device on the target with the keep-marker UNWRITTEN, so
		// a plain Status read looks "ok" and reconcileState would clear the gate
		// prematurely. While the pending entry is live, force awaiting-keep + the
		// countdown; once its window has passed the device has reverted, so drop the
		// stale entry and let the fresh (reverted) read settle normally to ok.
		e, hasKeep := p.pendingKeep[addr]
		if !hasKeep {
			continue
		}
		if time.Now().After(e.revertAt) {
			delete(p.pendingKeep, addr)
			if routers[i].State == store.RouterAwaitingKeep {
				// Only a carried-forward (never-dialed, fallback) router reaches here: a
				// managed router's fresh dial already settled to ok+actual. The device has
				// reverted to a now-unknown selection, and the fallback set is never
				// re-dialed -- so marking it ok would PERSIST a false-confirm on the
				// reverted-away target (Finding B). Drop to "not probed" (state unknown
				// until a manual Test SSH / set) instead.
				routers[i].State = store.RouterUnprobed
				routers[i].RevertAt = time.Time{}
				routers[i].CurrentExitNode = nil
				routers[i].Desired = nil
				routers[i].Reachable = false
			}
			continue
		}
		if routers[i].Reachable {
			routers[i].State = store.RouterAwaitingKeep
			routers[i].RevertAt = e.revertAt
		}
	}
	snap := &store.Snapshot{
		Nodes:     nodes,
		Routers:   routers,
		Groups:    buildGroupViews(p.groupList(), nodes),
		NetmapAt:  netmapAt,
		NetmapErr: netmapErr,
		BuiltAt:   now,
	}
	p.store.Store(snap)
	p.bc.Broadcast(snap)
	return invErr
}

// buildRouterView resolves one configured router to a RouterView: match its IP in
// the inventory, carry forward last-confirmed state, then read its live status.
func (p *Poller) buildRouterView(ctx context.Context, addr string, nodes []store.NodeView, prev *store.Snapshot) store.RouterView {
	var rv store.RouterView
	foundInNetmap := false
	if nv, ok := findNodeByIP(nodes, addr); ok {
		rv.Node = nv
		foundInNetmap = true
	} else {
		// Configured router missing from the netmap: still appears, unreachable.
		rv.Node = store.NodeView{TailscaleIPs: []string{addr}, Type: store.NodeRouter}
	}

	if prevRV := findRouterView(prev, addr); prevRV != nil {
		rv.Desired = prevRV.Desired
		rv.CurrentExitNode = prevRV.CurrentExitNode
		rv.Stats = prevRV.Stats
		rv.LastConfirmedAt = prevRV.LastConfirmedAt
		// Carry the egress probe result forward so it persists across polls (a poll
		// never re-probes egress; only a confirmed SetExitNode sets it).
		rv.EgressOK = prevRV.EgressOK
		rv.EgressDetail = prevRV.EgressDetail
		rv.EgressCheckedAt = prevRV.EgressCheckedAt
	}

	// Offline-skip: a node present in the netmap but reporting offline must NOT be
	// dialed -- dialing an offline tailnet peer otherwise hangs to the ssh timeout
	// for every offline device. Mark it unreachable and keep its last-confirmed
	// selection/stats as stale. (A configured router MISSING from the netmap -- the
	// else branch above -- is left to dial as before; only a known-offline node is
	// skipped.)
	if foundInNetmap && !rv.Node.Online {
		rv.Reachable = false
		rv.State = store.RouterUnreachable
		rv.LastError = "node is offline"
		return rv // keep last-confirmed CurrentExitNode/Stats as stale
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

// buildListedRouterView builds a RouterView WITHOUT contacting the device. It is
// used for the non-exit-node fallback set, which may be large: tsctl never
// auto-SSHes it (no probe storm). Precedence:
//   - netmap reports it offline   -> RouterUnreachable "node is offline" (mirrors
//     the managed path; never show a down device as "not probed");
//   - it was contacted before (a prior probe/set left a real State)  -> keep that
//     last-known state, including a failed/unconfirmed set + its LastError/Desired
//     (do NOT reset it -- LastConfirmedAt is set only on SUCCESS, so gating on it
//     would silently wipe failures across a poll);
//   - otherwise -> RouterUnprobed, the neutral "not probed yet" with Test SSH.
//
// SSH happens only on a manual probe or a SetExitNode.
func (p *Poller) buildListedRouterView(addr string, nodes []store.NodeView, prev *store.Snapshot) store.RouterView {
	var rv store.RouterView
	foundInNetmap := false
	if nv, ok := findNodeByIP(nodes, addr); ok {
		rv.Node = nv
		foundInNetmap = true
	} else {
		rv.Node = store.NodeView{TailscaleIPs: []string{addr}, Type: store.NodeGeneric}
	}
	prevRV := findRouterView(prev, addr)
	if prevRV != nil {
		// Carry last-confirmed selection/stats forward as stale context regardless.
		rv.Desired = prevRV.Desired
		rv.CurrentExitNode = prevRV.CurrentExitNode
		rv.Stats = prevRV.Stats
		rv.LastConfirmedAt = prevRV.LastConfirmedAt
		// Carry the egress probe result forward too (set only by a confirmed set).
		rv.EgressOK = prevRV.EgressOK
		rv.EgressDetail = prevRV.EgressDetail
		rv.EgressCheckedAt = prevRV.EgressCheckedAt
	}
	// Offline wins: never render a netmap-offline device as "not probed".
	if foundInNetmap && !rv.Node.Online {
		rv.Reachable = false
		rv.State = store.RouterUnreachable
		rv.LastError = "node is offline"
		return rv
	}
	// Online here. Carry forward ONLY an actual-contact result (a probe/set outcome:
	// ok / unconfirmed / pending) so it survives across polls. Crucially, a carried
	// RouterUnreachable is NOT kept: it came either from a previous offline poll or a
	// transient failed contact, and since the fallback never re-dials it would stick
	// FOREVER as a red "control error" with the picker disabled once the device comes
	// back online (devices in the fallback set flap constantly). Reset it to unprobed
	// so a flapped device recovers (picker re-enabled, re-probeable).
	switch prevState(prevRV) {
	case store.RouterOK, store.RouterUnconfirmed, store.RouterPending, store.RouterAwaitingKeep:
		rv.State = prevRV.State
		rv.Reachable = prevRV.Reachable
		rv.LastError = prevRV.LastError
		rv.RevertAt = prevRV.RevertAt // carry the countdown for an awaiting-keep listed router
		return rv
	}
	rv.State = store.RouterUnprobed
	rv.Reachable = false
	return rv
}

// prevState returns prevRV.State, or "" if prevRV is nil.
func prevState(prevRV *store.RouterView) store.RouterState {
	if prevRV == nil {
		return ""
	}
	return prevRV.State
}

// RefreshGroups rebuilds ONLY the Groups view of the current snapshot from the
// live group store and re-broadcasts it -- so a zone create/edit/delete shows up
// in the UI immediately, WITHOUT re-dialing any router (no SSH). Everything else
// in the snapshot (nodes, routers, netmap state) is carried forward unchanged.
// No-op until the first snapshot exists.
func (p *Poller) RefreshGroups() {
	p.mu.Lock()
	defer p.mu.Unlock()
	prev := p.store.Load()
	if prev == nil {
		return
	}
	snap := &store.Snapshot{
		Nodes:     prev.Nodes,
		Routers:   prev.Routers,
		Groups:    buildGroupViews(p.groupList(), prev.Nodes),
		NetmapAt:  prev.NetmapAt,
		NetmapErr: prev.NetmapErr,
		BuiltAt:   time.Now(),
	}
	p.store.Store(snap)
	// Broadcast under mu (non-blocking hub) so Store+Broadcast is atomic and frames
	// stay in store order vs a concurrent poll (Refresh does the same).
	p.bc.Broadcast(snap)
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
// applied to the RouterView for the router at addr -- its configured 100.x IP,
// the SAME key build/findRouterView use. addr is the stable identity: a router
// missing from the netmap keeps its configured IP but loses its StableID (M4),
// so matching by StableID here would silently no-op and publish a blank
// RouterView. The bool reports whether a router matched; callers must NOT
// store/return the result when it is false. Caller holds p.mu (M3).
func (p *Poller) withRouter(addr string, mutate func(*store.RouterView)) (*store.Snapshot, bool) {
	cur := p.store.Load()
	routers := make([]store.RouterView, len(cur.Routers))
	copy(routers, cur.Routers)
	matched := false
	for i := range routers {
		for _, ip := range routers[i].Node.TailscaleIPs {
			if ip == addr {
				mutate(&routers[i])
				matched = true
				break
			}
		}
	}
	return &store.Snapshot{
		Nodes:   cur.Nodes,
		Routers: routers,
		// Carry the current resolved groups forward: SetExitNode never mutates zone
		// definitions, and dropping them here would empty Snapshot.Groups on the
		// pending+final broadcasts, collapsing the UI's zone tabs until the next
		// full Refresh (~poll interval). cur.Groups is read-only, so reusing it
		// keeps the immutable snapshot whole.
		Groups:    cur.Groups,
		NetmapAt:  cur.NetmapAt,
		NetmapErr: cur.NetmapErr,
		BuiltAt:   time.Now(),
	}, matched
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

// copyExitRef returns an independent copy of ref (nil-safe) so a value handed to
// the router layer is never an alias into the stored, shared snapshot (low fix).
func copyExitRef(ref *store.ExitNodeRef) *store.ExitNodeRef {
	if ref == nil {
		return nil
	}
	cp := *ref
	return &cp
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

// allowedExitNodeSet computes the union of AllowedExitNodes (by StableID) across
// every zone whose Consumers contain the given consumer StableID. inAnyZone
// reports whether the consumer belongs to at least one zone -- when false the
// consumer is unrestricted (ungrouped). Used by SetExitNode enforcement.
func (p *Poller) allowedExitNodeSet(consumerStableID string) (set map[string]struct{}, inAnyZone bool) {
	set = make(map[string]struct{})
	for _, g := range p.groupList() {
		member := false
		for _, c := range g.Consumers {
			if c == consumerStableID {
				member = true
				break
			}
		}
		if !member {
			continue
		}
		inAnyZone = true
		for _, ex := range g.AllowedExitNodes {
			set[ex] = struct{}{}
		}
	}
	return set, inAnyZone
}

// buildGroupViews resolves the raw groups into Snapshot GroupViews: groups are
// sorted by Name then ID for a stable order; each member StableID is resolved
// against the inventory (Name/IP/Online filled, Present=true) or flagged absent
// (Present=false). Member ORDER is preserved as given. Always returns a non-nil
// (possibly empty) slice so the Snapshot's Groups field is never null.
func buildGroupViews(gs []store.Group, nodes []store.NodeView) []store.GroupView {
	byID := make(map[string]store.NodeView, len(nodes))
	for _, n := range nodes {
		byID[n.StableID] = n
	}
	sorted := append([]store.Group(nil), gs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].ID < sorted[j].ID
	})
	out := make([]store.GroupView, 0, len(sorted))
	for _, g := range sorted {
		out = append(out, store.GroupView{
			ID:               g.ID,
			Name:             g.Name,
			Consumers:        resolveMembers(g.Consumers, byID),
			AllowedExitNodes: resolveMembers(g.AllowedExitNodes, byID),
		})
	}
	return out
}

// resolveMembers maps member StableIDs to GroupMembers via the inventory index.
// A StableID absent from the netmap yields Present=false (empty Name/IP, Online
// false) -- soft membership: kept and flagged, never dropped.
func resolveMembers(ids []string, byID map[string]store.NodeView) []store.GroupMember {
	out := make([]store.GroupMember, 0, len(ids))
	for _, id := range ids {
		m := store.GroupMember{StableID: id}
		if n, ok := byID[id]; ok {
			m.Name = displayName(n)
			m.IP = primaryIP(n)
			m.Online = n.Online
			m.Present = true
		}
		out = append(out, m)
	}
	return out
}

// autoDiscoverRouters picks the routers to control when none are configured.
// First choice: every tag:router node (sorted) -> (those, usedFallback=false),
// exactly as before. If NONE exist it falls back to every node that is NOT
// exit-capable (!ExitNodeOption) and is NOT a tsctl control node (IsSelf, or any
// tag:tsctl peer), with a primary IP (sorted) -> (those, usedFallback=true). The
// fallback lets a simple single-operator tailnet control its routers without
// tagging them. Self-exclusion is structural (IsSelf), not tag-dependent, so it
// holds even if the control node somehow lacks tag:tsctl.
func autoDiscoverRouters(nodes []store.NodeView) (addrs []string, usedFallback bool) {
	for _, n := range nodes {
		if n.IsSelf || hasTag(n, tsctlTag) {
			continue // never control a tsctl control node, even if it's tag:router too
		}
		if n.Type == store.NodeRouter {
			if ip := primaryIP(n); ip != "" {
				addrs = append(addrs, ip)
			}
		}
	}
	if len(addrs) > 0 {
		sort.Strings(addrs)
		return addrs, false
	}

	// Fallback: no tag:router nodes at all -> control every plain non-exit node.
	for _, n := range nodes {
		if n.ExitNodeOption { // never try to control an exit node
			continue
		}
		if n.IsSelf || hasTag(n, tsctlTag) { // never try to control a tsctl control node
			continue
		}
		if ip := primaryIP(n); ip != "" {
			addrs = append(addrs, ip)
		}
	}
	sort.Strings(addrs)
	return addrs, true
}

// hasTag reports whether a NodeView carries the given ACL tag. (The netmap pkg
// has the equivalent for ipnstate.PeerStatus; this one works on store.NodeView.)
func hasTag(n store.NodeView, tag string) bool {
	for _, t := range n.Tags {
		if t == tag {
			return true
		}
	}
	return false
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
