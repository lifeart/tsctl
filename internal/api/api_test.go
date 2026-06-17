package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lifeart/tsctl/internal/store"
)

// --- fakes --------------------------------------------------------------------

type fakeWhoIs struct {
	login  string
	tagged bool
	err    error
}

func (f fakeWhoIs) WhoIs(ctx context.Context, remoteAddr string) (string, bool, error) {
	return f.login, f.tagged, f.err
}

type fakeController struct {
	rv          store.RouterView
	err         error
	gotRouterID string
	gotTarget   string
}

func (f *fakeController) SetExitNode(ctx context.Context, routerID, targetStableID string) (store.RouterView, error) {
	f.gotRouterID = routerID
	f.gotTarget = targetStableID
	return f.rv, f.err
}

// ctrlErr mirrors the structural error the poller returns (status/detail/stderr).
type ctrlErr struct {
	status         int
	msg, det, serr string
}

func (e *ctrlErr) Error() string   { return e.msg }
func (e *ctrlErr) HTTPStatus() int { return e.status }
func (e *ctrlErr) Detail() string  { return e.det }
func (e *ctrlErr) Stderr() string  { return e.serr }

// --- middleware ---------------------------------------------------------------

func TestRequireOwner(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	cases := []struct {
		name  string
		who   fakeWhoIs
		owner string
		want  int
	}{
		{"whois error", fakeWhoIs{err: errors.New("x")}, "alice@example.com", 403},
		{"tagged peer", fakeWhoIs{login: "tag:tsctl", tagged: true}, "alice@example.com", 403},
		{"empty login", fakeWhoIs{login: ""}, "alice@example.com", 403},
		{"non-owner", fakeWhoIs{login: "bob@example.com"}, "alice@example.com", 403},
		{"empty owner denies all", fakeWhoIs{login: "alice@example.com"}, "", 403},
		{"owner ok", fakeWhoIs{login: "alice@example.com"}, "alice@example.com", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(store.New(), tc.who, &fakeController{}, Config{Owner: tc.owner})
			rec := httptest.NewRecorder()
			a.RequireOwner(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestRequireCSRF(t *testing.T) {
	const host = "tsctl.example.ts.net"
	a := New(store.New(), fakeWhoIs{login: "alice"}, &fakeController{}, Config{Owner: "alice", AllowedHosts: []string{host}})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := a.RequireCSRF(next)

	type opt func(*http.Request)
	build := func(opts ...opt) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/routers/x/exit-node", nil)
		req.Host = host
		req.Header.Set("X-Tsctl-CSRF", "tok")
		req.AddCookie(&http.Cookie{Name: "tsctl_csrf", Value: "tok"})
		for _, o := range opts {
			o(req)
		}
		return req
	}
	run := func(req *http.Request) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := run(httptest.NewRequest(http.MethodGet, "/api/nodes", nil)); got != 200 {
		t.Errorf("GET should bypass CSRF, got %d", got)
	}
	if got := run(build()); got != 200 {
		t.Errorf("valid POST: got %d want 200", got)
	}
	if got := run(build(func(r *http.Request) { r.Header.Del("X-Tsctl-CSRF") })); got != 403 {
		t.Errorf("missing header: got %d want 403", got)
	}
	if got := run(build(func(r *http.Request) { r.Header.Set("X-Tsctl-CSRF", "different") })); got != 403 {
		t.Errorf("mismatched token: got %d want 403", got)
	}
	if got := run(build(func(r *http.Request) { r.Header.Del("Cookie") })); got != 403 {
		t.Errorf("missing cookie: got %d want 403", got)
	}
	// Host pinning is no longer RequireCSRF's job (it moved to RequireHost, which
	// runs on every request including reads); see TestRequireHost.
	if got := run(build(func(r *http.Request) { r.Header.Set("Origin", "http://evil.example.com") })); got != 403 {
		t.Errorf("bad Origin: got %d want 403", got)
	}
	if got := run(build(func(r *http.Request) { r.Header.Set("Origin", "http://"+host) })); got != 200 {
		t.Errorf("matching Origin: got %d want 200", got)
	}
	if got := run(build(func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") })); got != 403 {
		t.Errorf("cross-site Sec-Fetch-Site: got %d want 403", got)
	}
	if got := run(build(func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") })); got != 200 {
		t.Errorf("same-origin Sec-Fetch-Site: got %d want 200", got)
	}
}

func TestRequireHost(t *testing.T) {
	const host = "tsctl.example.ts.net"
	a := New(store.New(), fakeWhoIs{login: "alice"}, &fakeController{}, Config{Owner: "alice", AllowedHosts: []string{host}})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := a.RequireHost(next)

	run := func(reqHost string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		req.Host = reqHost
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := run("evil.example.com"); got != 403 {
		t.Errorf("GET with disallowed Host: got %d want 403", got)
	}
	if got := run(host); got != 200 {
		t.Errorf("GET with allowed Host: got %d want 200", got)
	}
}

// TestRoutes_HostPinnedOnReads proves a GET read (not just a write) is rejected
// for a disallowed Host through the real Routes() chain, and passes for an
// allowed Host -- the DNS-rebinding read hole H2 closed.
func TestRoutes_HostPinnedOnReads(t *testing.T) {
	const host = "tsctl.example.ts.net"
	a := New(store.New(), fakeWhoIs{login: "alice"}, &fakeController{}, Config{Owner: "alice", AllowedHosts: []string{host}})
	h := a.Routes()

	get := func(reqHost string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		req.Host = reqHost
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := get("evil.example.com"); got != 403 {
		t.Errorf("GET /api/nodes with disallowed Host: got %d want 403", got)
	}
	if got := get(host); got != 200 {
		t.Errorf("GET /api/nodes with allowed Host: got %d want 200", got)
	}
}

// --- handlers -----------------------------------------------------------------

func TestHandleNodes(t *testing.T) {
	st := store.New()
	st.Store(&store.Snapshot{
		Nodes: []store.NodeView{{
			StableID: "n1", Name: "host1", Hostname: "h1",
			TailscaleIPs: []string{"100.64.0.1"}, OS: "linux",
			Online: true, ExitNodeOption: true, Tags: []string{"tag:x"},
			Type: store.NodeExitNode,
		}},
		NetmapErr: "boom",
		BuiltAt:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	})
	a := New(st, fakeWhoIs{login: "alice"}, &fakeController{}, Config{Owner: "alice"})
	rec := httptest.NewRecorder()
	a.handleNodes(rec, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["netmapErr"] != "boom" {
		t.Errorf("netmapErr = %v", got["netmapErr"])
	}
	if got["builtAt"] != "2026-01-02T03:04:05Z" {
		t.Errorf("builtAt = %v", got["builtAt"])
	}
	nodes, _ := got["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("nodes len = %d", len(nodes))
	}
	n0 := nodes[0].(map[string]any)
	for _, k := range []string{"stableID", "name", "hostname", "tailscaleIPs", "os", "online", "lastSeen", "exitNodeOption", "tags", "type"} {
		if _, ok := n0[k]; !ok {
			t.Errorf("node missing camelCase key %q (got %v)", k, n0)
		}
	}
	if n0["stableID"] != "n1" {
		t.Errorf("stableID = %v", n0["stableID"])
	}
	if n0["type"] != "exit-node" {
		t.Errorf("type = %v", n0["type"])
	}
}

func TestHandleRouter(t *testing.T) {
	st := store.New()
	st.Store(&store.Snapshot{
		Routers: []store.RouterView{{
			Node:            store.NodeView{StableID: "r1", Name: "router1", TailscaleIPs: []string{"100.64.0.10"}},
			CurrentExitNode: &store.ExitNodeRef{StableID: "e1", Name: "exit1", IP: "100.64.0.20"},
			State:           store.RouterOK,
			Stats:           store.RouterStats{RxBytes: 11, TxBytes: 22},
			Reachable:       true,
		}},
	})
	a := New(st, fakeWhoIs{login: "alice"}, &fakeController{}, Config{Owner: "alice"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/routers/r1", nil)
	req.SetPathValue("id", "r1")
	a.handleRouter(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code = %d body=%s", rec.Code, rec.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"node", "currentExitNode", "desired", "state", "stats", "reachable", "lastError", "lastConfirmedAt"} {
		if _, ok := got[k]; !ok {
			t.Errorf("routerView missing key %q (got %v)", k, got)
		}
	}
	if got["state"] != "ok" {
		t.Errorf("state = %v", got["state"])
	}
	cur := got["currentExitNode"].(map[string]any)
	if cur["stableID"] != "e1" || cur["ip"] != "100.64.0.20" {
		t.Errorf("currentExitNode = %v", cur)
	}
	if got["desired"] != nil {
		t.Errorf("desired should be null, got %v", got["desired"])
	}

	// 404 for an unknown id.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/routers/nope", nil)
	req2.SetPathValue("id", "nope")
	a.handleRouter(rec2, req2)
	if rec2.Code != 404 {
		t.Errorf("unknown router code = %d want 404", rec2.Code)
	}
}

func TestHandleSetExitNode_OK(t *testing.T) {
	fc := &fakeController{rv: store.RouterView{
		Node:  store.NodeView{StableID: "r1"},
		State: store.RouterOK, Reachable: true,
	}}
	a := New(store.New(), fakeWhoIs{login: "alice"}, fc, Config{Owner: "alice"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/routers/r1/exit-node", strings.NewReader(`{"exitNode":"n2"}`))
	req.SetPathValue("id", "r1")
	a.handleSetExitNode(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code = %d body=%s", rec.Code, rec.Body)
	}
	if fc.gotRouterID != "r1" || fc.gotTarget != "n2" {
		t.Errorf("controller called with (%q, %q)", fc.gotRouterID, fc.gotTarget)
	}
	var got map[string]any
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["state"] != "ok" {
		t.Errorf("state = %v", got["state"])
	}
}

func TestHandleSetExitNode_ErrorStatusAndBody(t *testing.T) {
	fc := &fakeController{err: &ctrlErr{status: 400, msg: "node offline", det: "the detail", serr: "stderr text"}}
	a := New(store.New(), fakeWhoIs{login: "alice"}, fc, Config{Owner: "alice"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/routers/r1/exit-node", strings.NewReader(`{"exitNode":"n2"}`))
	req.SetPathValue("id", "r1")
	a.handleSetExitNode(rec, req)
	if rec.Code != 400 {
		t.Fatalf("code = %d want 400", rec.Code)
	}
	var got map[string]string
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["error"] != "node offline" || got["detail"] != "the detail" || got["stderr"] != "stderr text" {
		t.Errorf("error body = %+v", got)
	}
}

func TestHandleSetExitNode_GenericErrorIs502(t *testing.T) {
	fc := &fakeController{err: errors.New("plain failure")}
	a := New(store.New(), fakeWhoIs{login: "alice"}, fc, Config{Owner: "alice"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/routers/r1/exit-node", strings.NewReader(`{}`))
	req.SetPathValue("id", "r1")
	a.handleSetExitNode(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("code = %d want 502", rec.Code)
	}
}

func TestHandleCSRF(t *testing.T) {
	a := New(store.New(), fakeWhoIs{login: "alice"}, &fakeController{}, Config{Owner: "alice"})
	rec := httptest.NewRecorder()
	a.handleCSRF(rec, httptest.NewRequest(http.MethodGet, "/api/csrf", nil))
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	var got map[string]string
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["token"] == "" {
		t.Fatal("empty token")
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "tsctl_csrf" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("tsctl_csrf cookie not set")
	}
	if cookie.Value != got["token"] {
		t.Errorf("cookie value %q != token %q", cookie.Value, got["token"])
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", cookie.SameSite)
	}
	if cookie.HttpOnly {
		t.Error("cookie must NOT be HttpOnly (the page JS must read it)")
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q, want /", cookie.Path)
	}
}

// TestRoutes_FullChain exercises owner -> CSRF -> handler through the real mux,
// proving the seam wiring works end to end (not just isolated handlers).
func TestRoutes_FullChain(t *testing.T) {
	const host = "tsctl"
	fc := &fakeController{rv: store.RouterView{Node: store.NodeView{StableID: "r1"}, State: store.RouterPending}}
	a := New(store.New(), fakeWhoIs{login: "alice"}, fc, Config{Owner: "alice", AllowedHosts: []string{host}})
	h := a.Routes()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/routers/r1/exit-node", strings.NewReader(`{"exitNode":"n2"}`))
	req.Host = host
	req.Header.Set("X-Tsctl-CSRF", "tok")
	req.AddCookie(&http.Cookie{Name: "tsctl_csrf", Value: "tok"})
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("full-chain POST code = %d body=%s", rec.Code, rec.Body)
	}
	if fc.gotRouterID != "r1" || fc.gotTarget != "n2" {
		t.Errorf("controller called with (%q, %q)", fc.gotRouterID, fc.gotTarget)
	}

	// A non-owner is rejected before reaching the handler.
	a2 := New(store.New(), fakeWhoIs{login: "bob"}, fc, Config{Owner: "alice", AllowedHosts: []string{host}})
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/routers/r1/exit-node", strings.NewReader(`{"exitNode":"n2"}`))
	req2.Host = host
	req2.Header.Set("X-Tsctl-CSRF", "tok")
	req2.AddCookie(&http.Cookie{Name: "tsctl_csrf", Value: "tok"})
	a2.Routes().ServeHTTP(rec2, req2)
	if rec2.Code != 403 {
		t.Errorf("non-owner POST code = %d want 403", rec2.Code)
	}
}
