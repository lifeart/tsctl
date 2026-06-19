package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lifeart/tsctl/internal/api"
	"github.com/lifeart/tsctl/internal/groups"
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

type tGroupMember struct {
	StableID string `json:"stableID"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Online   bool   `json:"online"`
	Present  bool   `json:"present"`
}

type tGroupView struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Consumers        []tGroupMember `json:"consumers"`
	AllowedExitNodes []tGroupMember `json:"allowedExitNodes"`
}

type tSnapshot struct {
	Nodes     []tNode       `json:"nodes"`
	Routers   []tRouterView `json:"routers"`
	Groups    []tGroupView  `json:"groups"`
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
	uiPassword  = "s3cr3t-host-pw"

	routerID = "nROUTER01"
	routerIP = "100.64.0.10"

	exitID   = "nEXIT0001"
	exitName = "exit1.example.ts.net"
	exitIP   = "100.64.0.20"

	// A seeded zone wiring the router (consumer) to the exit node (allowed). The
	// router→exit change in the flow is therefore in-zone (enforcement permits it).
	groupName = "zone-a"
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

func (f *fakeRouterClient) ApplyExitNode(ctx context.Context, addr string, target, prev *store.ExitNodeRef, autoKeep bool) (store.RouterRuntime, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls++
	f.lastSetAddr = addr
	f.lastSetTarget = target
	f.lastSetPrev = prev
	// The flow runs with -require-keep OFF (no ConfigureKeep), so autoKeep is always
	// true here and no marker is deferred.
	return f.setResult, "", f.setErr
}

func (f *fakeRouterClient) KeepExitNode(ctx context.Context, addr, marker string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return nil
}

func (f *fakeRouterClient) Probe(ctx context.Context, addr string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return "Linux router 5.15.0\n0.10 0.20 0.30", nil
}

func (f *fakeRouterClient) EgressProbe(ctx context.Context, addr, url string) (bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return true, "HTTP/1.1 204 No Content", nil
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

// stackOpts tunes the wired stack for a scenario. The defaults (zero value via
// newStack) reproduce the original owner-on-tailnet setup.
type stackOpts struct {
	whoLogin   string // WhoIs login the fake reports (default: owner)
	uiPassword string // api UIPassword; non-empty enables the password/session path
}

// newStack wires the REAL store/sse/poller/api exactly as cmd/tsctl/main.go,
// faking only the two external edges, and serves the same mux through httptest.
// It uses the tailnet-owner defaults.
func newStack(t *testing.T) *stack {
	t.Helper()
	return newStackWith(t, stackOpts{whoLogin: owner})
}

// newStackWith is newStack with explicit knobs (WhoIs identity + UIPassword) so a
// test can close the tailnet path and exercise the host/password path.
func newStackWith(t *testing.T, opts stackOpts) *stack {
	t.Helper()
	if opts.whoLogin == "" {
		opts.whoLogin = owner
	}

	mapper := &fakeMapper{
		login: opts.whoLogin,
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

	// Real (temp-file) groups.Store seeded with one zone: the router is a
	// consumer and the exit node is allowed, so the flow's router→exit change is
	// in-zone (enforcement permits it) and the snapshot carries a resolved group.
	grp, err := groups.New(filepath.Join(t.TempDir(), "groups.json"))
	if err != nil {
		t.Fatalf("groups.New: %v", err)
	}
	if _, err := grp.Create(store.Group{Name: groupName, Consumers: []string{routerID}, AllowedExitNodes: []string{exitID}}); err != nil {
		t.Fatalf("seed group: %v", err)
	}

	st := store.New()
	hub := sse.New(st, api.EncodeSnapshot)
	// Long poll interval: only the first-viewer refresh and the SetExitNode
	// broadcasts drive frames during the test (no surprise ticker refresh).
	pol := poller.New(st, mapper, rc, grp, []string{routerIP}, hub, hub.Transitions(), time.Hour, t.Logf)
	apiH := api.New(st, mapper, pol, api.Config{Owner: owner, UIPassword: opts.uiPassword, AllowedHosts: []string{allowedHost}, Groups: grp})

	// EXACTLY the mux main.go builds (minus the irrelevant static file server).
	mux := http.NewServeMux()
	mux.Handle("/api/events", apiH.RequireAuth(apiH.RequireHost(hub)))
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

// connectSSE opens GET /api/events from an allowed Host and parses each `data:`
// frame into a tSnapshot, pushing it onto frames. Any cookies passed (e.g. a
// session cookie) are attached so the password path can be exercised.
func connectSSE(t *testing.T, base, host string, cookies ...*http.Cookie) *sseConn {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/api/events", nil)
	if err != nil {
		t.Fatalf("new sse request: %v", err)
	}
	req.Host = host
	for _, c := range cookies {
		req.AddCookie(c)
	}
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

	// (a') GROUPS: the snapshot carries the resolved zone with member info wired
	// through api -> poller -> store -> sse -> client.
	if len(snap.Groups) != 1 {
		t.Fatalf("(a') snapshot groups = %d, want 1", len(snap.Groups))
	}
	g := snap.Groups[0]
	if g.Name != groupName || g.ID == "" {
		t.Errorf("(a') group = {id:%q name:%q}, want name %q + non-empty id", g.ID, g.Name, groupName)
	}
	if len(g.Consumers) != 1 || g.Consumers[0].StableID != routerID || !g.Consumers[0].Present || !g.Consumers[0].Online {
		t.Errorf("(a') consumer member not resolved: %+v", g.Consumers)
	}
	if len(g.AllowedExitNodes) != 1 || g.AllowedExitNodes[0].StableID != exitID || !g.AllowedExitNodes[0].Present {
		t.Errorf("(a') allowed-exit member not resolved: %+v", g.AllowedExitNodes)
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

	// (d3) WhoIs login != owner -> 401 (RequireAuth) on a plain GET. This was 403
	// under the old RequireOwner; RequireAuth now returns 401 ("authenticate"),
	// reserving 403 for Host/CSRF failures (see d1/d2/d4).
	s.mapper.setIdentity("intruder@example.com", false, nil)
	resp = req(t, http.MethodGet, base+"/api/nodes", allowedHost, "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("(d3) non-owner GET /api/nodes status = %d, want 401", resp.StatusCode)
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

// TestPasswordPathFlow exercises the host/password auth path end to end on a
// stack whose WhoIs returns a NON-owner (so the tailnet path is closed): an
// unauthenticated request is 401, login establishes a session, the session
// authorizes reads + a CSRF'd mutation, Host pinning still applies, and logout
// returns the caller to the unauthenticated (401) state. The data wire contract,
// CSRF and Host pinning are unchanged -- only auth is additive.
func TestPasswordPathFlow(t *testing.T) {
	s := newStackWith(t, stackOpts{whoLogin: "intruder@example.com", uiPassword: uiPassword})
	base := s.srv.URL

	sessionName := "tsctl_session"

	// (a) No auth (tailnet path closed, no session) -> 401.
	resp := req(t, http.MethodGet, base+"/api/nodes", allowedHost, "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("(a) unauth GET /api/nodes = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// (b) Bootstrap: /api/csrf is reachable WITHOUT a session.
	token, csrf := fetchCSRF(t, base, allowedHost)
	csrfHdr := "tsctl_csrf=" + csrf

	// (c) Wrong password -> 401, and no session cookie issued.
	resp = req(t, http.MethodPost, base+"/api/login", allowedHost, `{"password":"WRONG"}`, map[string]string{
		"Content-Type": "application/json",
		"X-Tsctl-CSRF": token,
		"Cookie":       csrfHdr,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("(c) wrong login = %d, want 401", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionName && c.Value != "" {
			t.Error("(c) wrong login must not set a session cookie")
		}
	}
	resp.Body.Close()

	// (d) Correct password -> 200 + session cookie.
	resp = req(t, http.MethodPost, base+"/api/login", allowedHost, `{"password":"`+uiPassword+`"}`, map[string]string{
		"Content-Type": "application/json",
		"X-Tsctl-CSRF": token,
		"Cookie":       csrfHdr,
	})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("(d) correct login = %d body=%q, want 200", resp.StatusCode, b)
	}
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionName {
			session = c
		}
	}
	resp.Body.Close()
	if session == nil || session.Value == "" {
		t.Fatal("(d) correct login set no tsctl_session cookie")
	}
	if !session.HttpOnly {
		t.Error("(d) session cookie must be HttpOnly")
	}
	authCookies := csrfHdr + "; " + sessionName + "=" + session.Value

	// (e) With the session, GET /api/nodes -> 200.
	resp = req(t, http.MethodGet, base+"/api/nodes", allowedHost, "", map[string]string{"Cookie": authCookies})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("(e) session GET /api/nodes = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Connect an SSE client WITH the session so the poller's first-viewer refresh
	// populates the snapshot the exit-node POST resolves the router from.
	sc := connectSSE(t, base, allowedHost, session)
	sc.waitForSnapshot(t, 5*time.Second, "session SSE inventory frame with router present",
		func(s tSnapshot) bool { return findRouter(s, routerID) != nil })

	// (f) A CSRF'd POST /exit-node works with the session.
	s.rc.configureSet(store.RouterRuntime{
		Online:  true,
		Current: &store.ExitNodeRef{StableID: exitID, Name: exitName, IP: exitIP},
		Stats:   store.RouterStats{RxBytes: 1024, TxBytes: 512, LastHandshake: time.Now()},
	}, nil)
	resp = req(t, http.MethodPost, base+"/api/routers/"+routerID+"/exit-node", allowedHost,
		`{"exitNode":"`+exitID+`"}`, map[string]string{
			"Content-Type": "application/json",
			"X-Tsctl-CSRF": token,
			"Cookie":       authCookies,
		})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("(f) session POST exit-node = %d body=%q, want 200", resp.StatusCode, b)
	}
	got := decode[tRouterView](t, resp)
	if got.CurrentExitNode == nil || got.CurrentExitNode.IP != exitIP {
		t.Errorf("(f) currentExitNode = %+v, want IP %s", got.CurrentExitNode, exitIP)
	}

	// (g) bad Host -> 403 even with a valid session + CSRF (RequireHost intact).
	resp = req(t, http.MethodPost, base+"/api/routers/"+routerID+"/exit-node", "evil.example",
		`{"exitNode":""}`, map[string]string{
			"Content-Type": "application/json",
			"X-Tsctl-CSRF": token,
			"Cookie":       authCookies,
		})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("(g) bad-Host session POST = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// (h) logout -> the cookie is cleared; the browser then sends no session, so a
	// subsequent request is back to 401. (Sessions are stateless signed tokens; a
	// real browser drops the cleared cookie -- modelled here by omitting it.)
	resp = req(t, http.MethodPost, base+"/api/logout", allowedHost, "", map[string]string{
		"X-Tsctl-CSRF": token,
		"Cookie":       authCookies,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("(h) logout = %d, want 200", resp.StatusCode)
	}
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == sessionName && c.MaxAge < 0 {
			cleared = true
		}
	}
	resp.Body.Close()
	if !cleared {
		t.Error("(h) logout must clear the session cookie (MaxAge<0)")
	}
	resp = req(t, http.MethodGet, base+"/api/nodes", allowedHost, "", nil) // no session cookie
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("(h) post-logout GET /api/nodes = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}
