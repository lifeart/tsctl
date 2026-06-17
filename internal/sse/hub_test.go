package sse

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

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
