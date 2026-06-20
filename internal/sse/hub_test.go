package sse

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lifeart/tsctl/internal/authz"
	"github.com/lifeart/tsctl/internal/store"
)

func testEncoder(s *store.Snapshot) ([]byte, error) { return json.Marshal(s) }

// readFrame reads one SSE frame (lines up to a blank line) from br.
func readFrame(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	var b strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read frame: %v (so far %q)", err, b.String())
		}
		if line == "\n" || line == "\r\n" {
			if b.Len() == 0 {
				continue
			}
			return strings.TrimRight(b.String(), "\r\n")
		}
		b.WriteString(line)
	}
}

func TestServeHTTP_InitialSnapshotAndHeaders(t *testing.T) {
	st := store.New()
	st.Store(&store.Snapshot{
		Nodes:   []store.NodeView{{StableID: "n-self", Name: "self"}},
		BuiltAt: time.Now(),
	})
	h := New(st, testEncoder)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	srv := httptest.NewServer(http.HandlerFunc(h.ServeHTTP))
	defer srv.Close()

	reqCtx, reqCancel := context.WithCancel(context.Background())
	defer reqCancel()
	req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
	if xa := resp.Header.Get("X-Accel-Buffering"); xa != "no" {
		t.Errorf("X-Accel-Buffering = %q, want no", xa)
	}

	br := bufio.NewReader(resp.Body)
	frame := readFrame(t, br)
	data, ok := strings.CutPrefix(frame, "data: ")
	if !ok {
		t.Fatalf("first frame is not a data frame: %q", frame)
	}
	if !strings.Contains(data, "n-self") {
		t.Errorf("initial frame missing the current snapshot: %q", data)
	}
}

func TestServeHTTP_Heartbeat(t *testing.T) {
	st := store.New()
	h := New(st, testEncoder)
	h.pingInterval = 20 * time.Millisecond // override for the test
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	srv := httptest.NewServer(http.HandlerFunc(h.ServeHTTP))
	defer srv.Close()

	reqCtx, reqCancel := context.WithCancel(context.Background())
	defer reqCancel()
	req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	_ = readFrame(t, br) // consume the initial snapshot frame

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read heartbeat: %v", err)
		}
		if strings.HasPrefix(line, ":") {
			return // got a `: ping` comment line
		}
	}
	t.Fatal("no heartbeat (`: ping`) received")
}

func TestServeHTTP_NoGoroutineLeak(t *testing.T) {
	st := store.New()
	h := New(st, testEncoder)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	srv := httptest.NewServer(http.HandlerFunc(h.ServeHTTP))
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	base := runtime.NumGoroutine()

	const n = 6
	for i := 0; i < n; i++ {
		reqCtx, reqCancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, srv.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			reqCancel()
			t.Fatalf("GET %d: %v", i, err)
		}
		br := bufio.NewReader(resp.Body)
		_ = readFrame(t, br) // ensure the handler is live
		reqCancel()          // simulate the browser disconnecting
		resp.Body.Close()
	}
	client.CloseIdleConnections()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= base+2 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutine leak after %d connect/disconnect cycles: base=%d now=%d", n, base, runtime.NumGoroutine())
}

func TestTransitions_ClientCountEdges(t *testing.T) {
	st := store.New()
	h := New(st, testEncoder)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	srv := httptest.NewServer(http.HandlerFunc(h.ServeHTTP))
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	reqCtx, reqCancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		reqCancel()
		t.Fatalf("GET: %v", err)
	}
	br := bufio.NewReader(resp.Body)
	_ = readFrame(t, br) // register happened by now

	select {
	case got := <-h.Transitions():
		if got != 1 {
			t.Errorf("0->1 transition = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no 0->1 transition emitted")
	}

	reqCancel()
	resp.Body.Close()

	select {
	case got := <-h.Transitions():
		if got != 0 {
			t.Errorf("1->0 transition = %d, want 0", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no 1->0 transition emitted")
	}
}

// TestServeHTTP_GuestFrameFiltered proves a guest connection (Subject in context,
// as RequireAuth would inject) gets a zone-filtered on-connect frame, while an
// admin (no/admin subject) gets the full snapshot -- and the shared snapshot is
// never mutated.
func TestServeHTTP_GuestFrameFiltered(t *testing.T) {
	st := store.New()
	st.Store(&store.Snapshot{
		Nodes: []store.NodeView{
			{StableID: "r1", Name: "router1"},
			{StableID: "e1", Name: "exit1"},
			{StableID: "other", Name: "secret-node"},
		},
		Routers: []store.RouterView{
			{Node: store.NodeView{StableID: "r1"}, State: store.RouterOK},
			{Node: store.NodeView{StableID: "r2"}, State: store.RouterOK},
		},
		Groups: []store.GroupView{{
			ID:               "z1",
			Name:             "Work",
			Consumers:        []store.GroupMember{{StableID: "r1", Present: true}},
			AllowedExitNodes: []store.GroupMember{{StableID: "e1", Present: true}},
		}},
		BuiltAt: time.Now(),
	})
	h := New(st, testEncoder)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	// serve injects sub into every request context, as RequireAuth would.
	serve := func(sub authz.Subject, hasSub bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hasSub {
				r = r.WithContext(authz.WithSubject(r.Context(), sub))
			}
			h.ServeHTTP(w, r)
		}))
	}
	firstFrame := func(srv *httptest.Server) string {
		reqCtx, reqCancel := context.WithCancel(context.Background())
		defer reqCancel()
		req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, srv.URL, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		return readFrame(t, bufio.NewReader(resp.Body))
	}

	// Guest: filtered to r1 + e1, never "other" or r2.
	gsrv := serve(authz.Subject{GuestID: "g1", ZoneID: "z1"}, true)
	defer gsrv.Close()
	gframe := firstFrame(gsrv)
	if !strings.Contains(gframe, "r1") || !strings.Contains(gframe, "e1") {
		t.Errorf("guest frame should include r1+e1: %q", gframe)
	}
	if strings.Contains(gframe, "secret-node") || strings.Contains(gframe, "\"r2\"") {
		t.Errorf("guest frame must NOT include out-of-zone data: %q", gframe)
	}

	// Admin (no subject): full snapshot.
	asrv := serve(authz.Subject{}, false)
	defer asrv.Close()
	aframe := firstFrame(asrv)
	if !strings.Contains(aframe, "secret-node") || !strings.Contains(aframe, "\"r2\"") {
		t.Errorf("admin frame should include the full snapshot: %q", aframe)
	}

	// The shared snapshot was never mutated by the per-connection filtering.
	cur := st.Load()
	if len(cur.Nodes) != 3 || len(cur.Routers) != 2 {
		t.Errorf("shared snapshot mutated: nodes=%d routers=%d", len(cur.Nodes), len(cur.Routers))
	}
}

// A guest's long-lived event stream must be DROPPED soon after the guest is
// disabled/deleted (the heartbeat re-checks authorization), not kept open until the
// client happens to disconnect. (Security gate finding: SSE read-revocation lag.)
func TestServeHTTP_GuestStreamClosedOnRevoke(t *testing.T) {
	st := store.New()
	st.Store(&store.Snapshot{
		Nodes:   []store.NodeView{{StableID: "r1"}},
		Routers: []store.RouterView{{Node: store.NodeView{StableID: "r1"}, State: store.RouterOK}},
		Groups:  []store.GroupView{{ID: "z1", Consumers: []store.GroupMember{{StableID: "r1", Present: true}}}},
		BuiltAt: time.Now(),
	})
	h := New(st, testEncoder)
	h.pingInterval = 10 * time.Millisecond // re-check auth fast
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	var authorized atomic.Bool
	authorized.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(authz.WithSubject(r.Context(), authz.Subject{GuestID: "g1", ZoneID: "z1"}))
		r = r.WithContext(authz.WithRevalidate(r.Context(), func() bool { return authorized.Load() }))
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()

	reqCtx, reqCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer reqCancel()
	req, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	_ = readFrame(t, br) // on-connect filtered frame -> stream is live

	authorized.Store(false) // the guest is disabled/deleted out from under the stream

	// The next heartbeat re-check fails -> the hub returns -> the body closes -> a
	// read errors. Must happen well within the request timeout.
	closed := make(chan struct{})
	go func() {
		buf := make([]byte, 256)
		for {
			if _, err := br.Read(buf); err != nil {
				close(closed)
				return
			}
		}
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("guest event stream was not closed after revocation")
	}
}
