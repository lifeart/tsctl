package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lifeart/tsctl/internal/api"
	"github.com/lifeart/tsctl/internal/poller"
	"github.com/lifeart/tsctl/internal/router"
	"github.com/lifeart/tsctl/internal/sse"
	"github.com/lifeart/tsctl/internal/store"
)

// --- wire-contract DTOs (PHASE_B §3), redeclared here with explicit json tags
// so that any field-name drift in the api package's encoder fails THIS test
// (decode would leave the value zero and the value assertions below would fail).

type tNode struct {
	StableID       string   `json:"stableID"`
	Name           string   `json:"name"`
	Hostname       string   `json:"hostname"`
	TailscaleIPs   []string `json:"tailscaleIPs"`
	OS             string   `json:"os"`
	Online         bool     `json:"online"`
	LastSeen       string   `json:"lastSeen"`
	ExitNodeOption bool     `json:"exitNodeOption"`
	Tags           []string `json:"tags"`
	Type           string   `json:"type"`
}

type tExitRef struct {
	StableID string `json:"stableID"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
}

type tStats struct {
	RxBytes       int64  `json:"rxBytes"`
	TxBytes       int64  `json:"txBytes"`
	LastHandshake string `json:"lastHandshake"`
}

type tRouterView struct {
	Node            tNode     `json:"node"`
	CurrentExitNode *tExitRef `json:"currentExitNode"`
	Desired         *tExitRef `json:"desired"`
	State           string    `json:"state"`
	Stats           tStats    `json:"stats"`
	Reachable       bool      `json:"reachable"`
	LastError       string    `json:"lastError"`
	LastConfirmedAt string    `json:"lastConfirmedAt"`
}

type tSnapshot struct {
	Nodes     []tNode       `json:"nodes"`
	Routers   []tRouterView `json:"routers"`
	NetmapAt  string        `json:"netmapAt"`
	NetmapErr string        `json:"netmapErr"`
	BuiltAt   string        `json:"builtAt"`
}

type tErr struct {
	Error  string `json:"error"`
	Detail string `json:"detail"`
	Stderr string `json:"stderr"`
}

type tToken struct {
	Token string `json:"token"`
}

// --- fixed fixture identities ------------------------------------------------

const (
	owner       = "owner@example.com"
	allowedHost = "tsctl.test"

	routerID = "nROUTER01"
	routerIP = "100.64.0.10"

	exitID   = "nEXIT0001"
	exitName = "exit1.example.ts.net"
	exitIP   = "100.64.0.20"
)

// --- fake Mapper: satisfies BOTH poller.Netmapper and api.WhoIser -------------

type fakeMapper struct {
	mu     sync.Mutex
	nodes  []store.NodeView
	invErr error

	login  string
	tagged bool
	whoErr error
}

func (m *fakeMapper) Inventory(ctx context.Context) ([]store.NodeView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.NodeView(nil), m.nodes...), m.invErr
}

func (m *fakeMapper) WhoIs(ctx context.Context, remoteAddr string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.login, m.tagged, m.whoErr
}

func (m *fakeMapper) setIdentity(login string, tagged bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.login, m.tagged, m.whoErr = login, tagged, err
}

// compile-time: the fake satisfies the two FROZEN consumer-side interfaces.
var (
	_ poller.Netmapper = (*fakeMapper)(nil)
	_ api.WhoIser      = (*fakeMapper)(nil)
)

// --- fake RouterClient: satisfies poller.RouterClient ------------------------

type fakeRouterClient struct {
	mu sync.Mutex

	status    store.RouterRuntime
	statusErr error

	setResult store.RouterRuntime
	setErr    error

	lastSetAddr   string
	lastSetTarget *store.ExitNodeRef
	lastSetPrev   *store.ExitNodeRef
	setCalls      int
}

func (f *fakeRouterClient) Status(ctx context.Context, addr string) (store.RouterRuntime, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, f.statusErr
}

func (f *fakeRouterClient) SetExitNode(ctx context.Context, addr string, target, prev *store.ExitNodeRef) (store.RouterRuntime, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls++
	f.lastSetAddr = addr
	f.lastSetTarget = target
	f.lastSetPrev = prev
	return f.setResult, f.setErr
}

func (f *fakeRouterClient) configureSet(rt store.RouterRuntime, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setResult, f.setErr = rt, err
}

func (f *fakeRouterClient) lastTarget() *store.ExitNodeRef {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastSetTarget
}

var _ poller.RouterClient = (*fakeRouterClient)(nil)

// --- the wired-up stack ------------------------------------------------------

type stack struct {
	srv    *httptest.Server
	mapper *fakeMapper
	rc     *fakeRouterClient
}

// newStack wires the REAL store/sse/poller/api exactly as cmd/tsctl/main.go,
// faking only the two external edges, and serves the same mux through httptest.
func newStack(t *testing.T) *stack {
	t.Helper()

	mapper := &fakeMapper{
		login: owner, // default: the authorized owner
		nodes: []store.NodeView{
			{
				StableID:     routerID,
				Name:         "router1.example.ts.net",
				Hostname:     "router1",
				TailscaleIPs: []string{routerIP},
				OS:           "linux",
				Online:       true,
				Tags:         []string{"tag:router"},
				Type:         store.NodeRouter,
			},
			{
				StableID:       exitID,
				Name:           exitName,
				Hostname:       "exit1",
				TailscaleIPs:   []string{exitIP},
				OS:             "linux",
				Online:         true,
				ExitNodeOption: true,
				Type:           store.NodeExitNode,
			},
		},
	}
	rc := &fakeRouterClient{
		// initial per-router status: reachable, no exit node selected yet.
		status: store.RouterRuntime{Online: true},
	}

	st := store.New()
	hub := sse.New(st, api.EncodeSnapshot)
	// Long poll interval: only the first-viewer refresh and the SetExitNode
	// broadcasts drive frames during the test (no surprise ticker refresh).
	pol := poller.New(st, mapper, rc, []string{routerIP}, hub, hub.Transitions(), time.Hour, t.Logf)
	apiH := api.New(st, mapper, pol, api.Config{Owner: owner, AllowedHosts: []string{allowedHost}})

	// EXACTLY the mux main.go builds (minus the irrelevant static file server).
	mux := http.NewServeMux()
	mux.Handle("/api/events", apiH.RequireOwner(apiH.RequireHost(hub)))
	mux.Handle("/api/", apiH.Routes())

	appCtx, appCancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = hub.Run(appCtx) }()
	go func() { defer wg.Done(); _ = pol.Run(appCtx) }()

	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		appCancel() // stops hub (closes done) + poller; releases SSE handlers
		wg.Wait()   // join BEFORE the test ends so t.Logf is never called late
		srv.Close()
	})

	return &stack{srv: srv, mapper: mapper, rc: rc}
}

// --- SSE client --------------------------------------------------------------

type sseConn struct {
	resp   *http.Response
	frames chan tSnapshot
	stop   chan struct{}
}

// connectSSE opens GET /api/events as the owner from an allowed Host and parses
// each `data:` frame into a tSnapshot, pushing it onto frames.
func connectSSE(t *testing.T, base, host string) *sseConn {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/api/events", nil)
	if err != nil {
		t.Fatalf("new sse request: %v", err)
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sse connect: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("sse connect status = %d, body=%q", resp.StatusCode, b)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("sse Content-Type = %q, want text/event-stream", ct)
	}

	sc := &sseConn{resp: resp, frames: make(chan tSnapshot, 64), stop: make(chan struct{})}
	go func() {
		br := bufio.NewReader(resp.Body)
		var data strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case line == "": // event terminator
				if data.Len() == 0 {
					continue
				}
				var s tSnapshot
				if json.Unmarshal([]byte(data.String()), &s) == nil {
					select {
					case sc.frames <- s:
					case <-sc.stop:
						return
					}
				}
				data.Reset()
			case strings.HasPrefix(line, ":"): // ": ping" heartbeat / comment
				continue
			case strings.HasPrefix(line, "data:"):
				data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			}
		}
	}()
	t.Cleanup(func() {
		close(sc.stop)
		resp.Body.Close()
	})
	return sc
}

// waitForSnapshot blocks until a received frame satisfies pred, or fails.
func (sc *sseConn) waitForSnapshot(t *testing.T, timeout time.Duration, what string, pred func(tSnapshot) bool) tSnapshot {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case s := <-sc.frames:
			if pred(s) {
				return s
			}
		case <-deadline:
			t.Fatalf("timeout waiting for SSE snapshot: %s", what)
		}
	}
}

// --- request helpers ---------------------------------------------------------

func req(t *testing.T, method, url, host string, body string, headers map[string]string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = bytes.NewBufferString(body)
	}
	rq, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	rq.Host = host
	for k, v := range headers {
		rq.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(rq)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return v
}

// fetchCSRF performs GET /api/csrf and returns the token + the Set-Cookie value.
func fetchCSRF(t *testing.T, base, host string) (token, cookie string) {
	t.Helper()
	resp := req(t, http.MethodGet, base+"/api/csrf", host, "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/csrf status = %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "tsctl_csrf" {
			cookie = c.Value
		}
	}
	tok := decode[tToken](t, resp)
	if tok.Token == "" {
		t.Fatal("CSRF response missing token (json tag drift on {token}?)")
	}
	if cookie == "" {
		t.Fatal("CSRF response did not set tsctl_csrf cookie")
	}
	if cookie != tok.Token {
		t.Fatalf("CSRF cookie %q != token %q", cookie, tok.Token)
	}
	return tok.Token, cookie
}

func findRouter(s tSnapshot, id string) *tRouterView {
	for i := range s.Routers {
		if s.Routers[i].Node.StableID == id {
			return &s.Routers[i]
		}
	}
	return nil
}

func findNode(s tSnapshot, id string) *tNode {
	for i := range s.Nodes {
		if s.Nodes[i].StableID == id {
			return &s.Nodes[i]
		}
	}
	return nil
}

// =============================================================================
// The single real full-stack flow: a -> b -> c -> d through one wired server
// and one connected SSE client.
// =============================================================================

func TestFullStackFlow(t *testing.T) {
	s := newStack(t)
	base := s.srv.URL

	sc := connectSSE(t, base, allowedHost)

	// (a) INVENTORY: the SSE client receives a Snapshot frame carrying the
	// router (tag:router) and the approved exit-node node, in camelCase fields.
	snap := sc.waitForSnapshot(t, 5*time.Second, "inventory frame with router present",
		func(s tSnapshot) bool { return findRouter(s, routerID) != nil })

	rv := findRouter(snap, routerID)
	if rv == nil {
		t.Fatal("(a) router missing from snapshot")
	}
	if rv.Node.Type != "router" {
		t.Errorf("(a) router type = %q, want %q", rv.Node.Type, "router")
	}
	if len(rv.Node.TailscaleIPs) == 0 || rv.Node.TailscaleIPs[0] != routerIP {
		t.Errorf("(a) router tailscaleIPs = %v, want [%s]", rv.Node.TailscaleIPs, routerIP)
	}
	if !rv.Reachable {
		t.Errorf("(a) router reachable = false, want true")
	}
	if rv.CurrentExitNode != nil {
		t.Errorf("(a) router currentExitNode = %+v, want null initially", rv.CurrentExitNode)
	}
	en := findNode(snap, exitID)
	if en == nil {
		t.Fatal("(a) exit node missing from snapshot.nodes")
	}
	if en.Type != "exit-node" {
		t.Errorf("(a) exit node type = %q, want %q", en.Type, "exit-node")
	}
	if !en.ExitNodeOption {
		t.Errorf("(a) exit node exitNodeOption = false, want true")
	}
	if len(en.TailscaleIPs) == 0 || en.TailscaleIPs[0] != exitIP {
		t.Errorf("(a) exit node tailscaleIPs = %v, want [%s]", en.TailscaleIPs, exitIP)
	}
	if en.Name == "" || en.StableID == "" {
		t.Errorf("(a) camelCase name/stableID drift: name=%q stableID=%q", en.Name, en.StableID)
	}

	// (b) SET EXIT NODE: CSRF, then POST. The fake confirms the change.
	token, cookie := fetchCSRF(t, base, allowedHost)
	s.rc.configureSet(store.RouterRuntime{
		Online:  true,
		Current: &store.ExitNodeRef{StableID: exitID, Name: exitName, IP: exitIP},
		Stats:   store.RouterStats{RxBytes: 4096, TxBytes: 2048, LastHandshake: time.Now()},
	}, nil)

	resp := req(t, http.MethodPost, base+"/api/routers/"+routerID+"/exit-node", allowedHost,
		`{"exitNode":"`+exitID+`"}`, map[string]string{
			"Content-Type": "application/json",
			"X-Tsctl-CSRF": token,
			"Cookie":       "tsctl_csrf=" + cookie,
		})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("(b) POST exit-node status = %d, body=%q, want 200", resp.StatusCode, b)
	}
	got := decode[tRouterView](t, resp)
	if got.State != "ok" {
		t.Errorf("(b) RouterView.state = %q, want %q", got.State, "ok")
	}
	if got.CurrentExitNode == nil {
		t.Fatal("(b) RouterView.currentExitNode = null, want the target")
	}
	if got.CurrentExitNode.IP != exitIP {
		t.Errorf("(b) currentExitNode.ip = %q, want %q", got.CurrentExitNode.IP, exitIP)
	}
	// The change actually traversed api -> poller -> RouterClient:
	if lt := s.rc.lastTarget(); lt == nil || lt.IP != exitIP {
		t.Errorf("(b) RouterClient.SetExitNode got target %+v, want IP %s", lt, exitIP)
	}
	// ...and the api -> poller -> store -> sse -> client path carries it back:
	sc.waitForSnapshot(t, 5*time.Second, "frame reflecting confirmed exit node", func(s tSnapshot) bool {
		r := findRouter(s, routerID)
		return r != nil && r.State == "ok" && r.CurrentExitNode != nil && r.CurrentExitNode.IP == exitIP
	})

	// (c) FAILURE SURFACING: the RouterClient returns a *router.CommandError; the
	// stderr must survive api <- poller <- router and land in the {stderr} field.
	s.rc.configureSet(store.RouterRuntime{}, &router.CommandError{
		Addr:       routerIP,
		Cmd:        "apply exit-node",
		StderrText: "permission denied",
		Exit:       1,
	})
	resp = req(t, http.MethodPost, base+"/api/routers/"+routerID+"/exit-node", allowedHost,
		`{"exitNode":"`+exitID+`"}`, map[string]string{
			"Content-Type": "application/json",
			"X-Tsctl-CSRF": token,
			"Cookie":       "tsctl_csrf=" + cookie,
		})
	if resp.StatusCode/100 == 2 {
		t.Fatalf("(c) POST exit-node status = %d, want non-2xx", resp.StatusCode)
	}
	errBody := decode[tErr](t, resp)
	if errBody.Stderr != "permission denied" {
		t.Errorf("(c) error body stderr = %q, want %q (stderr seam api<-poller<-router)", errBody.Stderr, "permission denied")
	}
	if errBody.Error == "" {
		t.Errorf("(c) error body error field empty; want a message")
	}

	// (d) SECURITY SEAMS (negative).
	postHdr := func(extra map[string]string) map[string]string {
		h := map[string]string{"Content-Type": "application/json"}
		for k, v := range extra {
			h[k] = v
		}
		return h
	}

	// (d1) disallowed Host -> 403 (RequireHost), even with valid owner+CSRF.
	resp = req(t, http.MethodPost, base+"/api/routers/"+routerID+"/exit-node", "evil.example",
		`{"exitNode":""}`, postHdr(map[string]string{
			"X-Tsctl-CSRF": token, "Cookie": "tsctl_csrf=" + cookie,
		}))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("(d1) bad Host POST status = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// (d2) missing CSRF header -> 403 (RequireCSRF), good Host + owner.
	resp = req(t, http.MethodPost, base+"/api/routers/"+routerID+"/exit-node", allowedHost,
		`{"exitNode":""}`, postHdr(nil))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("(d2) no-CSRF POST status = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// (d3) WhoIs login != owner -> 403 (RequireOwner) on a plain GET.
	s.mapper.setIdentity("intruder@example.com", false, nil)
	resp = req(t, http.MethodGet, base+"/api/nodes", allowedHost, "", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("(d3) non-owner GET /api/nodes status = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
	s.mapper.setIdentity(owner, false, nil) // restore

	// (d4) GET /api/events is ALSO host-pinned -> 403 on a bad Host.
	resp = req(t, http.MethodGet, base+"/api/events", "evil.example", "", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("(d4) bad-Host GET /api/events status = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}
