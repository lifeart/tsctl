package poller

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lifeart/tsctl/internal/router"
	"github.com/lifeart/tsctl/internal/store"
)

func nopLogf(string, ...any) {}

// --- fakes --------------------------------------------------------------------

type fakeNM struct {
	nodes []store.NodeView
	err   error
}

func (f *fakeNM) Inventory(ctx context.Context) ([]store.NodeView, error) { return f.nodes, f.err }

type fakeRC struct {
	mu          sync.Mutex
	statusRT    store.RouterRuntime
	statusErr   error
	statusCalls int
	setRT       store.RouterRuntime
	setErr      error
	setCalls    int
	lastAddr    string
	lastTarget  *store.ExitNodeRef
	lastPrev    *store.ExitNodeRef
	probeOut    string
	probeErr    error
	probeCalls  int
}

func (f *fakeRC) Status(ctx context.Context, addr string) (store.RouterRuntime, error) {
	f.mu.Lock()
	f.statusCalls++
	f.mu.Unlock()
	return f.statusRT, f.statusErr
}

func (f *fakeRC) SetExitNode(ctx context.Context, addr string, target, prev *store.ExitNodeRef) (store.RouterRuntime, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls++
	f.lastAddr, f.lastTarget, f.lastPrev = addr, target, prev
	return f.setRT, f.setErr
}

func (f *fakeRC) Probe(ctx context.Context, addr string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probeCalls++
	return f.probeOut, f.probeErr
}

func (f *fakeRC) calls() int           { f.mu.Lock(); defer f.mu.Unlock(); return f.setCalls }
func (f *fakeRC) statusCallCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.statusCalls }
func (f *fakeRC) probeCallCount() int  { f.mu.Lock(); defer f.mu.Unlock(); return f.probeCalls }

type fakeBC struct {
	mu    sync.Mutex
	snaps []*store.Snapshot
	ch    chan *store.Snapshot
}

func newFakeBC() *fakeBC { return &fakeBC{ch: make(chan *store.Snapshot, 256)} }

func (f *fakeBC) Broadcast(s *store.Snapshot) {
	f.mu.Lock()
	f.snaps = append(f.snaps, s)
	f.mu.Unlock()
	select {
	case f.ch <- s:
	default:
	}
}

func (f *fakeBC) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.snaps) }

// --- tests --------------------------------------------------------------------

func TestRefresh_BuildsSnapshot(t *testing.T) {
	routerIP, exitIP := "100.64.0.10", "100.64.0.20"
	nm := &fakeNM{nodes: []store.NodeView{
		{StableID: "router1", Name: "r1", TailscaleIPs: []string{routerIP}, Online: true, Type: store.NodeRouter},
		{StableID: "exit1", Name: "e1", TailscaleIPs: []string{exitIP}, Online: true, ExitNodeOption: true, Type: store.NodeExitNode},
	}}
	rc := &fakeRC{statusRT: store.RouterRuntime{
		Online:  true,
		Current: &store.ExitNodeRef{StableID: "exit1", Name: "e1", IP: exitIP},
		Stats:   store.RouterStats{RxBytes: 100, TxBytes: 200},
	}}
	bc := newFakeBC()
	st := store.New()
	p := New(st, nm, rc, nil, []string{routerIP}, bc, make(chan int), time.Second, nopLogf)

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	snap := st.Load()
	if len(snap.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(snap.Nodes))
	}
	if len(snap.Routers) != 1 {
		t.Fatalf("routers = %d, want 1", len(snap.Routers))
	}
	rv := snap.Routers[0]
	if !rv.Reachable {
		t.Error("router should be reachable")
	}
	if rv.State != store.RouterOK {
		t.Errorf("state = %q, want ok", rv.State)
	}
	if rv.Node.StableID != "router1" {
		t.Errorf("router node matched by IP wrong: %+v", rv.Node)
	}
	if rv.CurrentExitNode == nil || rv.CurrentExitNode.StableID != "exit1" {
		t.Errorf("currentExitNode = %+v", rv.CurrentExitNode)
	}
	if rv.Stats.RxBytes != 100 {
		t.Errorf("stats not carried: %+v", rv.Stats)
	}
	if bc.count() == 0 {
		t.Error("expected a broadcast")
	}
}

func TestRefresh_AutoDiscoversRouters(t *testing.T) {
	// No configured routers (nil) -> discover every tag:router node from the netmap.
	r1, r2, exitIP := "100.64.0.10", "100.64.0.11", "100.64.0.20"
	nm := &fakeNM{nodes: []store.NodeView{
		{StableID: "rA", TailscaleIPs: []string{r2}, Online: true, Type: store.NodeRouter},
		{StableID: "rB", TailscaleIPs: []string{r1}, Online: true, Type: store.NodeRouter},
		{StableID: "exit1", TailscaleIPs: []string{exitIP}, Online: true, ExitNodeOption: true, Type: store.NodeExitNode},
		{StableID: "laptop", TailscaleIPs: []string{"100.64.0.30"}, Online: true, Type: store.NodeGeneric},
	}}
	rc := &fakeRC{statusRT: store.RouterRuntime{Online: true}}
	st := store.New()
	p := New(st, nm, rc, nil, nil /* auto-discover */, newFakeBC(), make(chan int), time.Second, nopLogf)

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	snap := st.Load()
	if len(snap.Routers) != 2 {
		t.Fatalf("auto-discovered routers = %d, want 2 (the tag:router nodes only)", len(snap.Routers))
	}
	// Sorted by IP for stability: 100.64.0.10 then 100.64.0.11.
	if got := primaryIP(snap.Routers[0].Node); got != r1 {
		t.Errorf("routers[0] IP = %q, want %q (sorted)", got, r1)
	}
	if got := primaryIP(snap.Routers[1].Node); got != r2 {
		t.Errorf("routers[1] IP = %q, want %q (sorted)", got, r2)
	}
	for _, rv := range snap.Routers {
		if rv.Node.Type != store.NodeRouter {
			t.Errorf("auto-discovered a non-router: %+v", rv.Node)
		}
	}
}

func TestRefresh_FallbackListsWithoutProbing(t *testing.T) {
	// No tag:router and no -routers: the fallback LISTS every non-exit, non-self
	// node as a consumer, but must NOT auto-SSH any of them (a tailnet can be
	// large -- probing is manual). They appear unprobed; the exit node and the
	// tsctl self node (tag:tsctl) are excluded.
	exitIP := "100.64.0.20"
	nm := &fakeNM{nodes: []store.NodeView{
		{StableID: "phone", TailscaleIPs: []string{"100.64.0.30"}, Online: true, Type: store.NodeGeneric},
		{StableID: "laptop", TailscaleIPs: []string{"100.64.0.31"}, Online: true, Type: store.NodeGeneric},
		{StableID: "exit1", TailscaleIPs: []string{exitIP}, Online: true, ExitNodeOption: true, Type: store.NodeExitNode},
		{StableID: "self", TailscaleIPs: []string{"100.64.0.5"}, Online: true, Tags: []string{"tag:tsctl"}, Type: store.NodeGeneric},
	}}
	rc := &fakeRC{statusRT: store.RouterRuntime{Online: true}}
	st := store.New()
	p := New(st, nm, rc, nil, nil /* auto-discover -> fallback */, newFakeBC(), make(chan int), time.Second, nopLogf)

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	snap := st.Load()
	if len(snap.Routers) != 2 {
		t.Fatalf("fallback listed %d routers, want 2 (non-exit, non-self)", len(snap.Routers))
	}
	for _, rv := range snap.Routers {
		if rv.State != store.RouterUnprobed {
			t.Errorf("fallback router %s state = %q, want %q", primaryIP(rv.Node), rv.State, store.RouterUnprobed)
		}
		if rv.Reachable {
			t.Errorf("fallback router %s must not be marked reachable before a probe", primaryIP(rv.Node))
		}
	}
	if n := rc.statusCallCount(); n != 0 {
		t.Errorf("fallback must NOT auto-SSH any device; Status calls = %d, want 0", n)
	}
}

func TestRefreshGroups_RebuildsAndBroadcastsWithoutDial(t *testing.T) {
	// Creating/editing a zone calls RefreshGroups: it must re-render Groups from the
	// live store and broadcast IMMEDIATELY, without re-dialing any router.
	routerIP := "100.64.0.10"
	nm := &fakeNM{nodes: []store.NodeView{
		{StableID: "r1", Name: "r1", TailscaleIPs: []string{routerIP}, Online: true, Type: store.NodeRouter},
	}}
	rc := &fakeRC{statusRT: store.RouterRuntime{Online: true}}
	grp := &fakeGroups{}
	bc := newFakeBC()
	st := store.New()
	p := New(st, nm, rc, grp, []string{routerIP}, bc, make(chan int), time.Second, nopLogf)

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := len(st.Load().Groups); got != 0 {
		t.Fatalf("groups before = %d, want 0", got)
	}
	bc.mu.Lock()
	broadcastsBefore := len(bc.snaps)
	bc.mu.Unlock()
	statusBefore := rc.statusCallCount()

	// A zone is created in the store, then RefreshGroups is invoked (as the api does).
	grp.list = []store.Group{{ID: "z1", Name: "Work", Consumers: []string{"r1"}}}
	p.RefreshGroups()

	snap := st.Load()
	if len(snap.Groups) != 1 || snap.Groups[0].Name != "Work" {
		t.Fatalf("after RefreshGroups, groups = %+v, want one named Work", snap.Groups)
	}
	if got := rc.statusCallCount(); got != statusBefore {
		t.Errorf("RefreshGroups must not dial routers: Status calls %d -> %d", statusBefore, got)
	}
	bc.mu.Lock()
	after := len(bc.snaps)
	bc.mu.Unlock()
	if after <= broadcastsBefore {
		t.Errorf("RefreshGroups must broadcast the updated snapshot: snaps %d -> %d", broadcastsBefore, after)
	}
}

func eqStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAutoDiscoverRouters_TagRouterWins(t *testing.T) {
	// tag:router nodes present -> only those (sorted), usedFallback=false. Exit
	// nodes and generic nodes are NOT discovered.
	nodes := []store.NodeView{
		{StableID: "rA", TailscaleIPs: []string{"100.64.0.11"}, Type: store.NodeRouter},
		{StableID: "rB", TailscaleIPs: []string{"100.64.0.10"}, Type: store.NodeRouter},
		{StableID: "exit1", TailscaleIPs: []string{"100.64.0.20"}, ExitNodeOption: true, Type: store.NodeExitNode},
		{StableID: "laptop", TailscaleIPs: []string{"100.64.0.30"}, Type: store.NodeGeneric},
	}
	addrs, usedFallback := autoDiscoverRouters(nodes)
	if usedFallback {
		t.Fatal("tag:router nodes present -> usedFallback must be false")
	}
	if want := []string{"100.64.0.10", "100.64.0.11"}; !eqStrs(addrs, want) {
		t.Errorf("addrs = %v, want %v (only tag:router, sorted)", addrs, want)
	}
}

func TestAutoDiscoverRouters_Fallback(t *testing.T) {
	// No tag:router nodes at all -> fallback to every non-exit, non-tsctl node that
	// has a primary IP. Excludes: exit-capable nodes, the tag:tsctl self node, and
	// any node without an IP.
	nodes := []store.NodeView{
		{StableID: "self", TailscaleIPs: []string{"100.64.0.1"}, Tags: []string{"tag:tsctl"}, Type: store.NodeGeneric},
		{StableID: "exit1", TailscaleIPs: []string{"100.64.0.20"}, ExitNodeOption: true, Type: store.NodeExitNode},
		{StableID: "nas", TailscaleIPs: []string{"100.64.0.31"}, Type: store.NodeGeneric},
		{StableID: "laptop", TailscaleIPs: []string{"100.64.0.30"}, Type: store.NodeGeneric},
		{StableID: "noip", Type: store.NodeGeneric},
	}
	addrs, usedFallback := autoDiscoverRouters(nodes)
	if !usedFallback {
		t.Fatal("no tag:router nodes -> usedFallback must be true")
	}
	if want := []string{"100.64.0.30", "100.64.0.31"}; !eqStrs(addrs, want) {
		t.Errorf("fallback addrs = %v, want %v (exclude exit-capable, tag:tsctl self, and no-IP)", addrs, want)
	}
}

// TestRefresh_OfflineRouterSkipsDial proves an offline router present in the
// netmap is marked unreachable WITHOUT dialing (no rc.Status call) and keeps its
// last-confirmed selection as stale.
func TestRefresh_OfflineRouterSkipsDial(t *testing.T) {
	routerIP, exitIP := "100.64.0.10", "100.64.0.20"
	nm := &fakeNM{nodes: []store.NodeView{
		{StableID: "router1", TailscaleIPs: []string{routerIP}, Online: false, Type: store.NodeRouter},
	}}
	rc := &fakeRC{statusRT: store.RouterRuntime{Online: true}}
	st := store.New()
	// Seed a prior confirmed selection so we can prove it's kept as stale.
	st.Store(&store.Snapshot{
		Routers: []store.RouterView{{
			Node:            store.NodeView{StableID: "router1", TailscaleIPs: []string{routerIP}},
			CurrentExitNode: &store.ExitNodeRef{StableID: "exit1", IP: exitIP},
			Reachable:       true, State: store.RouterOK,
		}},
	})
	p := New(st, nm, rc, nil, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)

	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	rv := st.Load().Routers[0]
	if rv.Reachable || rv.State != store.RouterUnreachable {
		t.Errorf("offline router: reachable=%v state=%q, want unreachable", rv.Reachable, rv.State)
	}
	if rv.LastError != "node is offline" {
		t.Errorf("lastError = %q, want %q", rv.LastError, "node is offline")
	}
	if rv.CurrentExitNode == nil || rv.CurrentExitNode.IP != exitIP {
		t.Errorf("last-confirmed selection must be kept as stale, got %+v", rv.CurrentExitNode)
	}
	if rc.statusCallCount() != 0 {
		t.Errorf("offline router must NOT be dialed, Status calls = %d", rc.statusCallCount())
	}
}

func TestProbe(t *testing.T) {
	const routerIP, exitIP = "100.64.0.10", "100.64.0.20"

	onlineRouterSnapshot := func(st *store.Store, online bool) {
		st.Store(&store.Snapshot{
			Routers: []store.RouterView{{
				Node: store.NodeView{StableID: "router1", TailscaleIPs: []string{routerIP}, Online: online},
			}},
		})
	}

	t.Run("unknown router -> 404 error, no probe", func(t *testing.T) {
		st := store.New()
		seedSnapshot(st, routerIP, exitIP, true, true)
		rc := &fakeRC{}
		p := New(st, &fakeNM{}, rc, nil, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
		_, err := p.Probe(context.Background(), "ghost")
		if err == nil {
			t.Fatal("expected an error for an unknown router")
		}
		var hs interface{ HTTPStatus() int }
		if !errors.As(err, &hs) || hs.HTTPStatus() != 404 {
			t.Fatalf("expected a 404 control error, got %v", err)
		}
		if rc.probeCallCount() != 0 {
			t.Errorf("unknown router must not be probed, calls = %d", rc.probeCallCount())
		}
	})

	t.Run("offline -> OK:false 'node is offline', no dial", func(t *testing.T) {
		st := store.New()
		onlineRouterSnapshot(st, false)
		rc := &fakeRC{probeOut: "should-not-run"}
		p := New(st, &fakeNM{}, rc, nil, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
		res, err := p.Probe(context.Background(), "router1")
		if err != nil {
			t.Fatalf("offline probe must not return a Go error: %v", err)
		}
		if res.OK {
			t.Error("offline probe OK must be false")
		}
		if res.Error != "node is offline" {
			t.Errorf("error = %q, want %q", res.Error, "node is offline")
		}
		if res.CheckedAt.IsZero() {
			t.Error("checkedAt must be set")
		}
		if rc.probeCallCount() != 0 {
			t.Errorf("offline router must NOT be dialed, probe calls = %d", rc.probeCallCount())
		}
	})

	t.Run("success -> OK:true with output", func(t *testing.T) {
		st := store.New()
		onlineRouterSnapshot(st, true)
		rc := &fakeRC{probeOut: "Linux router 5.15\n0.5 0.1 0.0"}
		p := New(st, &fakeNM{}, rc, nil, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
		res, err := p.Probe(context.Background(), "router1")
		if err != nil {
			t.Fatalf("probe: %v", err)
		}
		if !res.OK {
			t.Error("OK must be true on success")
		}
		if res.Output != "Linux router 5.15\n0.5 0.1 0.0" {
			t.Errorf("output = %q", res.Output)
		}
		if res.Error != "" {
			t.Errorf("error must be empty on success, got %q", res.Error)
		}
		if res.CheckedAt.IsZero() {
			t.Error("checkedAt must be set")
		}
		if rc.probeCallCount() != 1 {
			t.Errorf("probe calls = %d, want 1", rc.probeCallCount())
		}
	})

	t.Run("rc.Probe error -> OK:false with error (not a Go error)", func(t *testing.T) {
		st := store.New()
		onlineRouterSnapshot(st, true)
		rc := &fakeRC{probeErr: errors.New("ssh handshake failed")}
		p := New(st, &fakeNM{}, rc, nil, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
		res, err := p.Probe(context.Background(), "router1")
		if err != nil {
			t.Fatalf("an SSH failure is a RESULT, not a returned Go error: %v", err)
		}
		if res.OK {
			t.Error("OK must be false on an ssh failure")
		}
		if res.Error != "ssh handshake failed" {
			t.Errorf("error = %q, want the ssh error verbatim", res.Error)
		}
	})
}

func TestRefresh_NetmapErrSurfacedNotAborted(t *testing.T) {
	nm := &fakeNM{err: errors.New("netmap down")}
	rc := &fakeRC{statusErr: errors.New("ssh dial failed")}
	bc := newFakeBC()
	st := store.New()
	p := New(st, nm, rc, nil, []string{"100.64.0.10"}, bc, make(chan int), time.Second, nopLogf)

	err := p.Refresh(context.Background())
	if err == nil {
		t.Error("expected inventory error to be returned")
	}
	snap := st.Load()
	if snap.NetmapErr == "" {
		t.Error("NetmapErr must be set")
	}
	if len(snap.Routers) != 1 {
		t.Fatalf("router must still appear: routers = %d", len(snap.Routers))
	}
	rv := snap.Routers[0]
	if rv.Reachable {
		t.Error("router should be unreachable")
	}
	if rv.State != store.RouterUnreachable {
		t.Errorf("state = %q, want unreachable", rv.State)
	}
	if rv.LastError == "" {
		t.Error("LastError must be surfaced, never swallowed")
	}
	if bc.count() == 0 {
		t.Error("snapshot must still be broadcast on error")
	}
}

func seedSnapshot(st *store.Store, routerIP, exitIP string, exitOnline, exitApproved bool) {
	st.Store(&store.Snapshot{
		Nodes: []store.NodeView{
			{StableID: "router1", TailscaleIPs: []string{routerIP}, Online: true, Type: store.NodeRouter},
			{StableID: "exit1", Name: "e1", TailscaleIPs: []string{exitIP}, Online: exitOnline, ExitNodeOption: exitApproved, Type: store.NodeExitNode},
		},
		Routers: []store.RouterView{
			{Node: store.NodeView{StableID: "router1", TailscaleIPs: []string{routerIP}}, Reachable: true, State: store.RouterOK},
		},
	})
}

func TestSetExitNode_Success(t *testing.T) {
	routerIP, exitIP := "100.64.0.10", "100.64.0.20"
	st := store.New()
	seedSnapshot(st, routerIP, exitIP, true, true)
	rc := &fakeRC{setRT: store.RouterRuntime{Online: true, Current: &store.ExitNodeRef{StableID: "exit1", IP: exitIP}}}
	bc := newFakeBC()
	p := New(st, &fakeNM{}, rc, nil, []string{routerIP}, bc, make(chan int), time.Second, nopLogf)

	rv, err := p.SetExitNode(context.Background(), "router1", "exit1")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if rv.State != store.RouterOK {
		t.Errorf("state = %q, want ok", rv.State)
	}
	if rv.CurrentExitNode == nil || rv.CurrentExitNode.StableID != "exit1" {
		t.Errorf("currentExitNode = %+v", rv.CurrentExitNode)
	}
	if rv.Desired != nil {
		t.Errorf("desired should clear on confirmed success, got %+v", rv.Desired)
	}
	if rc.lastAddr != routerIP {
		t.Errorf("dialed addr = %q, want %q", rc.lastAddr, routerIP)
	}
	if rc.lastTarget == nil || rc.lastTarget.IP != exitIP {
		t.Errorf("target = %+v, want IP %s", rc.lastTarget, exitIP)
	}
	if bc.count() < 2 {
		t.Errorf("broadcasts = %d, want >=2 (pending + final)", bc.count())
	}
}

func TestSetExitNode_Clear(t *testing.T) {
	routerIP := "100.64.0.10"
	st := store.New()
	seedSnapshot(st, routerIP, "100.64.0.20", true, true)
	rc := &fakeRC{setRT: store.RouterRuntime{Online: true, Current: nil}}
	p := New(st, &fakeNM{}, rc, nil, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)

	rv, err := p.SetExitNode(context.Background(), "router1", "") // "" = clear
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if rv.CurrentExitNode != nil {
		t.Errorf("currentExitNode should be nil after clear, got %+v", rv.CurrentExitNode)
	}
	if rc.lastTarget != nil {
		t.Errorf("target should be nil for clear, got %+v", rc.lastTarget)
	}
	if rc.calls() != 1 {
		t.Errorf("SetExitNode calls = %d, want 1", rc.calls())
	}
}

func TestSetExitNode_PreflightRefusals(t *testing.T) {
	routerIP, exitIP := "100.64.0.10", "100.64.0.20"

	t.Run("offline target", func(t *testing.T) {
		st := store.New()
		seedSnapshot(st, routerIP, exitIP, false, true) // offline
		rc := &fakeRC{}
		p := New(st, &fakeNM{}, rc, nil, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
		_, err := p.SetExitNode(context.Background(), "router1", "exit1")
		assertPreflight(t, err)
		if rc.calls() != 0 {
			t.Errorf("router must not be touched on refusal, calls = %d", rc.calls())
		}
	})
	t.Run("unapproved target", func(t *testing.T) {
		st := store.New()
		seedSnapshot(st, routerIP, exitIP, true, false) // not ExitNodeOption
		rc := &fakeRC{}
		p := New(st, &fakeNM{}, rc, nil, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
		_, err := p.SetExitNode(context.Background(), "router1", "exit1")
		assertPreflight(t, err)
		if rc.calls() != 0 {
			t.Errorf("router must not be touched on refusal, calls = %d", rc.calls())
		}
	})
	t.Run("unknown router", func(t *testing.T) {
		st := store.New()
		seedSnapshot(st, routerIP, exitIP, true, true)
		p := New(st, &fakeNM{}, &fakeRC{}, nil, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
		_, err := p.SetExitNode(context.Background(), "ghost", "exit1")
		assertPreflight(t, err)
	})
}

func assertPreflight(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a preflight error")
	}
	var hs interface{ HTTPStatus() int }
	if !errors.As(err, &hs) || hs.HTTPStatus() != 400 {
		t.Fatalf("expected 400 preflight error, got %v", err)
	}
}

func TestSetExitNode_RouterFailureIs502WithStderr(t *testing.T) {
	routerIP, exitIP := "100.64.0.10", "100.64.0.20"
	st := store.New()
	seedSnapshot(st, routerIP, exitIP, true, true)
	// Drive the REAL router.CommandError end to end (not a look-alike fake): a
	// non-zero apply exit. This is exactly what router.Client returns, so the
	// seam (router error -> poller controlError -> api {stderr}) is exercised for
	// real. StderrText is untrimmed; Stderr() must trim it.
	cmdErr := &router.CommandError{
		Addr:       routerIP,
		Cmd:        "apply exit-node",
		StderrText: "  permission denied\n",
		Exit:       1,
	}
	// A hard apply failure means the change did NOT take: the device kept its
	// previous selection (here: Direct, from the seed) and is still reachable.
	// The poller best-effort re-reads via Status to learn that actual state.
	rc := &fakeRC{setErr: cmdErr, statusRT: store.RouterRuntime{Online: true, Current: nil}}
	bc := newFakeBC()
	p := New(st, &fakeNM{}, rc, nil, []string{routerIP}, bc, make(chan int), time.Second, nopLogf)

	rv, err := p.SetExitNode(context.Background(), "router1", "exit1")
	if err == nil {
		t.Fatal("expected a router error")
	}
	var hs interface{ HTTPStatus() int }
	if !errors.As(err, &hs) || hs.HTTPStatus() != 502 {
		t.Errorf("expected 502, got %v", err)
	}
	// The controlError the api receives must carry the trimmed router stderr in
	// its Stderr() -- this is precisely the value the {stderr} response field gets.
	var se interface{ Stderr() string }
	if !errors.As(err, &se) || se.Stderr() != "permission denied" {
		t.Errorf("stderr not surfaced through the error: %v (stderr=%q)", err, extractStderr(err))
	}
	// And the underlying *router.CommandError must still be reachable through the
	// chain (errors.As across the seam).
	var ce *router.CommandError
	if !errors.As(err, &ce) {
		t.Errorf("real *router.CommandError not reachable via errors.As: %v", err)
	}
	// MUST-FIX #1: a hard command failure is COHERENT -- the device kept its
	// previous (unchanged) selection, so State is ok (not "unconfirmed"), nothing
	// is pending (Desired cleared), and the actual selection is shown. The error
	// is still surfaced (502 above + LastError) -- never swallowed, never an
	// "auto-revert/unconfirmed" line.
	if rv.State != store.RouterOK {
		t.Errorf("state = %q, want ok (device still on its previous selection)", rv.State)
	}
	if rv.Desired != nil {
		t.Errorf("desired must be cleared on a hard failure (nothing pending), got %+v", rv.Desired)
	}
	if rv.CurrentExitNode != nil {
		t.Errorf("currentExitNode = %+v, want nil (unchanged: still Direct)", rv.CurrentExitNode)
	}
	if !rv.Reachable {
		t.Error("router should be reachable (the re-read succeeded)")
	}
	if rv.LastError == "" {
		t.Error("LastError must be set")
	}
}

// When the best-effort re-read after a hard failure ALSO fails, the poller can't
// learn the actual selection, so it keeps the last-known selection and marks the
// router unreachable (still surfacing the original command error + 502).
func TestSetExitNode_HardFailureRereadFails(t *testing.T) {
	routerIP, exitIP := "100.64.0.10", "100.64.0.20"
	st := store.New()
	seedSnapshot(st, routerIP, exitIP, true, true)
	cmdErr := &router.CommandError{Addr: routerIP, Cmd: "apply exit-node", StderrText: "permission denied", Exit: 1}
	rc := &fakeRC{setErr: cmdErr, statusErr: errors.New("ssh dial failed")}
	p := New(st, &fakeNM{}, rc, nil, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)

	rv, err := p.SetExitNode(context.Background(), "router1", "exit1")
	if err == nil {
		t.Fatal("expected a router error")
	}
	var hs interface{ HTTPStatus() int }
	if !errors.As(err, &hs) || hs.HTTPStatus() != 502 {
		t.Errorf("expected 502, got %v", err)
	}
	if rv.State != store.RouterUnreachable {
		t.Errorf("state = %q, want unreachable (re-read failed)", rv.State)
	}
	if rv.Desired != nil {
		t.Errorf("desired must be cleared on a hard failure, got %+v", rv.Desired)
	}
	if rv.LastError == "" {
		t.Error("LastError must be set")
	}
}

func TestSetExitNode_AppliedButUnconfirmed(t *testing.T) {
	routerIP, exitIP := "100.64.0.10", "100.64.0.20"
	st := store.New()
	seedSnapshot(st, routerIP, exitIP, true, true)
	// Router answered (Online true) but the error signals the confirm didn't match.
	rc := &fakeRC{
		setRT:  store.RouterRuntime{Online: true, Current: nil},
		setErr: errors.New("confirm read mismatch"),
	}
	p := New(st, &fakeNM{}, rc, nil, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)

	rv, err := p.SetExitNode(context.Background(), "router1", "exit1")
	if err != nil {
		t.Fatalf("an applied-but-unconfirmed result is reported via state, not a hard error: %v", err)
	}
	if rv.State != store.RouterUnconfirmed {
		t.Errorf("state = %q, want unconfirmed", rv.State)
	}
	if rv.LastError == "" {
		t.Error("LastError must carry the confirm failure")
	}
	if rv.Desired == nil || rv.Desired.StableID != "exit1" {
		t.Errorf("desired must remain the requested target, got %+v", rv.Desired)
	}
}

// dropMidOpRC simulates a concurrent Refresh that drops the router from the
// netmap (StableID goes empty, configured IP preserved) WHILE the dead-man's-
// switch runs -- the M4 race that used to make withRouter a silent no-op and
// publish a blank RouterView.
type dropMidOpRC struct {
	st       *store.Store
	routerIP string
	rt       store.RouterRuntime
}

func (d *dropMidOpRC) Status(ctx context.Context, addr string) (store.RouterRuntime, error) {
	return d.rt, nil
}

func (d *dropMidOpRC) Probe(ctx context.Context, addr string) (string, error) { return "", nil }

func (d *dropMidOpRC) SetExitNode(ctx context.Context, addr string, target, prev *store.ExitNodeRef) (store.RouterRuntime, error) {
	// Same IP, empty StableID -- the buildRouterView fallback for a configured
	// router missing from inventory.
	d.st.Store(&store.Snapshot{
		Routers: []store.RouterView{
			{Node: store.NodeView{TailscaleIPs: []string{d.routerIP}, Type: store.NodeRouter}},
		},
	})
	return d.rt, nil
}

func TestSetExitNode_RouterDropsFromNetmapMidOp(t *testing.T) {
	routerIP, exitIP := "100.64.0.10", "100.64.0.20"
	st := store.New()
	seedSnapshot(st, routerIP, exitIP, true, true)
	rc := &dropMidOpRC{
		st: st, routerIP: routerIP,
		rt: store.RouterRuntime{Online: true, Current: &store.ExitNodeRef{StableID: "exit1", IP: exitIP}},
	}
	p := New(st, &fakeNM{}, rc, nil, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)

	rv, err := p.SetExitNode(context.Background(), "router1", "exit1")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	// M4: matching by configured IP (not StableID) must still reconcile a real
	// RouterView -- never a blank one -- even though StableID changed mid-op.
	if rv.State != store.RouterOK {
		t.Errorf("state = %q, want ok (blank-RouterView regression)", rv.State)
	}
	if rv.CurrentExitNode == nil || rv.CurrentExitNode.IP != exitIP {
		t.Errorf("currentExitNode = %+v, want IP %s", rv.CurrentExitNode, exitIP)
	}
}

// --- zone (group) enforcement + resolution -----------------------------------

type fakeGroups struct{ list []store.Group }

func (f *fakeGroups) List() []store.Group { return f.list }

var _ GroupReader = (*fakeGroups)(nil)

// seedSnapshot2 seeds a router plus two online+approved exit nodes so zone
// enforcement (allowed vs not-allowed) can be exercised independently of the
// generic offline/unapproved pre-flight refusals.
func seedSnapshot2(st *store.Store, routerIP, exit1IP, exit2IP string) {
	st.Store(&store.Snapshot{
		Nodes: []store.NodeView{
			{StableID: "router1", TailscaleIPs: []string{routerIP}, Online: true, Type: store.NodeRouter},
			{StableID: "exit1", Name: "e1", TailscaleIPs: []string{exit1IP}, Online: true, ExitNodeOption: true, Type: store.NodeExitNode},
			{StableID: "exit2", Name: "e2", TailscaleIPs: []string{exit2IP}, Online: true, ExitNodeOption: true, Type: store.NodeExitNode},
		},
		Routers: []store.RouterView{
			{Node: store.NodeView{StableID: "router1", TailscaleIPs: []string{routerIP}}, Reachable: true, State: store.RouterOK},
		},
	})
}

func TestSetExitNode_ZoneEnforcement(t *testing.T) {
	const routerIP, exit1IP, exit2IP = "100.64.0.10", "100.64.0.20", "100.64.0.21"

	t.Run("in-zone target allowed", func(t *testing.T) {
		st := store.New()
		seedSnapshot2(st, routerIP, exit1IP, exit2IP)
		rc := &fakeRC{setRT: store.RouterRuntime{Online: true, Current: &store.ExitNodeRef{StableID: "exit1", IP: exit1IP}}}
		fg := &fakeGroups{list: []store.Group{{ID: "z", Name: "Work", Consumers: []string{"router1"}, AllowedExitNodes: []string{"exit1"}}}}
		p := New(st, &fakeNM{}, rc, fg, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
		rv, err := p.SetExitNode(context.Background(), "router1", "exit1")
		if err != nil {
			t.Fatalf("in-zone change must be allowed: %v", err)
		}
		if rv.State != store.RouterOK {
			t.Errorf("state = %q, want ok", rv.State)
		}
		if rc.calls() != 1 {
			t.Errorf("router should be touched once, calls = %d", rc.calls())
		}
	})

	t.Run("out-of-zone target rejected, no SSH issued", func(t *testing.T) {
		st := store.New()
		seedSnapshot2(st, routerIP, exit1IP, exit2IP)
		rc := &fakeRC{}
		fg := &fakeGroups{list: []store.Group{{ID: "z", Name: "Work", Consumers: []string{"router1"}, AllowedExitNodes: []string{"exit1"}}}}
		p := New(st, &fakeNM{}, rc, fg, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
		_, err := p.SetExitNode(context.Background(), "router1", "exit2") // online+approved, but NOT in zone
		// A zone-policy refusal is 422 (well-formed but violates the zone), not 400.
		var hs interface{ HTTPStatus() int }
		if !errors.As(err, &hs) || hs.HTTPStatus() != 422 {
			t.Fatalf("zone refusal must be a 422 control error, got %v", err)
		}
		if !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("error should explain the zone refusal, got %q", err.Error())
		}
		if rc.calls() != 0 {
			t.Errorf("router must NOT be touched on a zone refusal, calls = %d", rc.calls())
		}
	})

	t.Run("Direct (clear) always allowed even in a restrictive zone", func(t *testing.T) {
		st := store.New()
		seedSnapshot2(st, routerIP, exit1IP, exit2IP)
		rc := &fakeRC{setRT: store.RouterRuntime{Online: true, Current: nil}}
		fg := &fakeGroups{list: []store.Group{{ID: "z", Name: "Work", Consumers: []string{"router1"}, AllowedExitNodes: []string{"exit1"}}}}
		p := New(st, &fakeNM{}, rc, fg, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
		rv, err := p.SetExitNode(context.Background(), "router1", "") // clear
		if err != nil {
			t.Fatalf("Direct/clear must always be allowed: %v", err)
		}
		if rv.CurrentExitNode != nil {
			t.Errorf("currentExitNode should be nil after clear, got %+v", rv.CurrentExitNode)
		}
		if rc.calls() != 1 {
			t.Errorf("clear should reach the router, calls = %d", rc.calls())
		}
	})

	t.Run("ungrouped consumer is unrestricted", func(t *testing.T) {
		st := store.New()
		seedSnapshot2(st, routerIP, exit1IP, exit2IP)
		rc := &fakeRC{setRT: store.RouterRuntime{Online: true, Current: &store.ExitNodeRef{StableID: "exit2", IP: exit2IP}}}
		// A zone exists but does NOT contain router1, so router1 is ungrouped.
		fg := &fakeGroups{list: []store.Group{{ID: "z", Name: "Other", Consumers: []string{"someone-else"}, AllowedExitNodes: []string{"exit1"}}}}
		p := New(st, &fakeNM{}, rc, fg, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
		if _, err := p.SetExitNode(context.Background(), "router1", "exit2"); err != nil {
			t.Fatalf("ungrouped consumer must be unrestricted: %v", err)
		}
		if rc.calls() != 1 {
			t.Errorf("ungrouped change should reach the router, calls = %d", rc.calls())
		}
	})

	t.Run("multi-group allowed set is the union", func(t *testing.T) {
		st := store.New()
		seedSnapshot2(st, routerIP, exit1IP, exit2IP)
		rc := &fakeRC{setRT: store.RouterRuntime{Online: true, Current: &store.ExitNodeRef{StableID: "exit2", IP: exit2IP}}}
		// router1 is in BOTH zones; exit2 is allowed only by the second → union admits it.
		fg := &fakeGroups{list: []store.Group{
			{ID: "z1", Name: "A", Consumers: []string{"router1"}, AllowedExitNodes: []string{"exit1"}},
			{ID: "z2", Name: "B", Consumers: []string{"router1"}, AllowedExitNodes: []string{"exit2"}},
		}}
		p := New(st, &fakeNM{}, rc, fg, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
		if _, err := p.SetExitNode(context.Background(), "router1", "exit2"); err != nil {
			t.Fatalf("union of zones must admit exit2: %v", err)
		}
		if rc.calls() != 1 {
			t.Errorf("union-allowed change should reach the router, calls = %d", rc.calls())
		}
	})
}

func TestBuild_ResolvesGroupViews(t *testing.T) {
	const routerIP, exitIP = "100.64.0.10", "100.64.0.20"
	nm := &fakeNM{nodes: []store.NodeView{
		{StableID: "router1", Name: "r1", Hostname: "r1h", TailscaleIPs: []string{routerIP}, Online: true, Type: store.NodeRouter},
		{StableID: "exit1", Name: "e1", TailscaleIPs: []string{exitIP}, Online: true, ExitNodeOption: true, Type: store.NodeExitNode},
	}}
	rc := &fakeRC{statusRT: store.RouterRuntime{Online: true}}
	fg := &fakeGroups{list: []store.Group{
		{ID: "z2", Name: "Beta", Consumers: []string{"router1"}, AllowedExitNodes: []string{"exit1", "ghost"}},
		{ID: "z1", Name: "Alpha", Consumers: []string{"ghost"}, AllowedExitNodes: []string{"exit1"}},
	}}
	st := store.New()
	p := New(st, nm, rc, fg, []string{routerIP}, newFakeBC(), make(chan int), time.Second, nopLogf)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	snap := st.Load()
	if len(snap.Groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(snap.Groups))
	}
	// Stable order: sorted by Name (Alpha, Beta).
	if snap.Groups[0].Name != "Alpha" || snap.Groups[1].Name != "Beta" {
		t.Fatalf("groups not sorted by name: %q, %q", snap.Groups[0].Name, snap.Groups[1].Name)
	}
	beta := snap.Groups[1]
	if len(beta.Consumers) != 1 || beta.Consumers[0].StableID != "router1" || !beta.Consumers[0].Present {
		t.Fatalf("beta consumers wrong: %+v", beta.Consumers)
	}
	if beta.Consumers[0].IP != routerIP || !beta.Consumers[0].Online || beta.Consumers[0].Name != "r1" {
		t.Errorf("present member not resolved: %+v", beta.Consumers[0])
	}
	if len(beta.AllowedExitNodes) != 2 {
		t.Fatalf("allowed = %d, want 2 (order preserved)", len(beta.AllowedExitNodes))
	}
	if beta.AllowedExitNodes[0].StableID != "exit1" || !beta.AllowedExitNodes[0].Present {
		t.Errorf("exit1 should resolve present: %+v", beta.AllowedExitNodes[0])
	}
	ghost := beta.AllowedExitNodes[1]
	if ghost.StableID != "ghost" || ghost.Present || ghost.Name != "" || ghost.IP != "" || ghost.Online {
		t.Errorf("absent member must be flagged Present=false with empty Name/IP: %+v", ghost)
	}
}

func TestRun_IdleSuspension(t *testing.T) {
	routerIP := "100.64.0.10"
	nm := &fakeNM{nodes: []store.NodeView{{StableID: "router1", TailscaleIPs: []string{routerIP}, Type: store.NodeRouter}}}
	rc := &fakeRC{statusRT: store.RouterRuntime{Online: true}}
	bc := newFakeBC()
	st := store.New()
	tr := make(chan int, 1)
	p := New(st, nm, rc, nil, []string{routerIP}, bc, tr, 10*time.Millisecond, nopLogf)
	p.linger = 30 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	// No clients yet: nothing should be polled.
	time.Sleep(40 * time.Millisecond)
	if bc.count() != 0 {
		t.Fatalf("poller ran while idle: %d broadcasts", bc.count())
	}

	// 0->1: first-viewer refresh + ticking starts.
	tr <- 1
	select {
	case <-bc.ch:
	case <-time.After(time.Second):
		t.Fatal("no broadcast after 0->1 transition")
	}
	time.Sleep(60 * time.Millisecond)
	if got := bc.count(); got < 2 {
		t.Errorf("expected continued ticking while active, got %d broadcasts", got)
	}

	// 1->0: linger, then suspend.
	tr <- 0
	time.Sleep(p.linger + 80*time.Millisecond)
	c1 := bc.count()
	time.Sleep(80 * time.Millisecond)
	c2 := bc.count()
	if c2 != c1 {
		t.Errorf("polling did not suspend after linger: %d -> %d", c1, c2)
	}
}

// TestSetExitNode_PreservesGroupsInBroadcast is the regression for withRouter
// dropping Snapshot.Groups: a SetExitNode (pending + final) must keep the resolved
// zones, or the UI's zone tabs collapse until the next full Refresh.
func TestSetExitNode_PreservesGroupsInBroadcast(t *testing.T) {
	const routerIP, exitIP = "100.64.0.10", "100.64.0.20"
	st := store.New()
	// Seed a snapshot as a prior Refresh would: nodes, routers, AND resolved groups.
	st.Store(&store.Snapshot{
		Nodes: []store.NodeView{
			{StableID: "router1", TailscaleIPs: []string{routerIP}, Online: true, Type: store.NodeRouter},
			{StableID: "exit1", TailscaleIPs: []string{exitIP}, Online: true, ExitNodeOption: true, Type: store.NodeExitNode},
		},
		Routers: []store.RouterView{
			{Node: store.NodeView{StableID: "router1", TailscaleIPs: []string{routerIP}}, Reachable: true, State: store.RouterOK},
		},
		Groups: []store.GroupView{
			{ID: "z", Name: "Work",
				Consumers:        []store.GroupMember{{StableID: "router1"}},
				AllowedExitNodes: []store.GroupMember{{StableID: "exit1"}}},
		},
	})
	rc := &fakeRC{setRT: store.RouterRuntime{Online: true, Current: &store.ExitNodeRef{StableID: "exit1", IP: exitIP}}}
	fg := &fakeGroups{list: []store.Group{{ID: "z", Name: "Work", Consumers: []string{"router1"}, AllowedExitNodes: []string{"exit1"}}}}
	bc := newFakeBC()
	p := New(st, &fakeNM{}, rc, fg, []string{routerIP}, bc, make(chan int), time.Second, nopLogf)

	if _, err := p.SetExitNode(context.Background(), "router1", "exit1"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if bc.count() == 0 {
		t.Fatal("expected pending + final broadcasts")
	}
	// withRouter produces both the stored and the broadcast snapshots; the final
	// stored snapshot must still carry the resolved zones.
	if got := len(st.Load().Groups); got != 1 {
		t.Errorf("stored snapshot Groups = %d after SetExitNode, want 1 (must survive)", got)
	}
}
