package api

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lifeart/tsctl/internal/groups"
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

	probeRes   store.ProbeResult
	probeErr   error
	gotProbeID string

	refreshGroupsCalls int
}

func (f *fakeController) SetExitNode(ctx context.Context, routerID, targetStableID string) (store.RouterView, error) {
	f.gotRouterID = routerID
	f.gotTarget = targetStableID
	return f.rv, f.err
}

func (f *fakeController) Probe(ctx context.Context, routerID string) (store.ProbeResult, error) {
	f.gotProbeID = routerID
	return f.probeRes, f.probeErr
}

func (f *fakeController) RefreshGroups() { f.refreshGroupsCalls++ }

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

func TestRequireAuth(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	// Tailnet (WhoIs) path: only the untagged owner is admitted.
	t.Run("owner whois allows", func(t *testing.T) {
		a := New(store.New(), fakeWhoIs{login: "alice@example.com"}, &fakeController{}, Config{Owner: "alice@example.com"})
		rec := httptest.NewRecorder()
		a.RequireAuth(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
		if rec.Code != 200 {
			t.Errorf("owner: code = %d want 200", rec.Code)
		}
	})

	// Everything that is NOT the owner and has no session → 401 (fail-closed,
	// including on a WhoIs error: it must NOT grant access).
	deny := []struct {
		name  string
		who   fakeWhoIs
		owner string
	}{
		{"whois error", fakeWhoIs{err: errors.New("x")}, "alice@example.com"},
		{"tagged peer", fakeWhoIs{login: "tag:tsctl", tagged: true}, "alice@example.com"},
		{"empty login", fakeWhoIs{login: ""}, "alice@example.com"},
		{"non-owner", fakeWhoIs{login: "bob@example.com"}, "alice@example.com"},
		{"empty owner denies tailnet", fakeWhoIs{login: "alice@example.com"}, ""},
	}
	for _, tc := range deny {
		t.Run(tc.name+" -> 401", func(t *testing.T) {
			a := New(store.New(), tc.who, &fakeController{}, Config{Owner: tc.owner})
			rec := httptest.NewRecorder()
			a.RequireAuth(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
		})
	}

	// Password/session path: a valid session admits even a non-owner WhoIs.
	t.Run("valid session allows (non-owner whois)", func(t *testing.T) {
		a := New(store.New(), fakeWhoIs{login: "intruder@example.com"}, &fakeController{},
			Config{Owner: "alice@example.com", UIPassword: "hunter2"})
		val, err := a.newSessionValue()
		if err != nil {
			t.Fatalf("newSessionValue: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: val})
		rec := httptest.NewRecorder()
		a.RequireAuth(next).ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("valid session: code = %d want 200", rec.Code)
		}
	})

	// Neither path: no owner, no session → 401.
	t.Run("no owner no session -> 401", func(t *testing.T) {
		a := New(store.New(), fakeWhoIs{login: "x"}, &fakeController{}, Config{UIPassword: "hunter2"})
		rec := httptest.NewRecorder()
		a.RequireAuth(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("code = %d want 401", rec.Code)
		}
	})
}

func TestSessionSignVerify(t *testing.T) {
	a := New(store.New(), fakeWhoIs{}, &fakeController{}, Config{UIPassword: "pw"})
	withCookie := func(v string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: v})
		return r
	}

	val, err := a.newSessionValue()
	if err != nil {
		t.Fatalf("newSessionValue: %v", err)
	}
	if !a.validSession(withCookie(val)) {
		t.Error("freshly minted session should validate")
	}
	if a.validSession(httptest.NewRequest(http.MethodGet, "/api/nodes", nil)) {
		t.Error("missing cookie should not validate")
	}
	if a.validSession(withCookie("not valid base64 $$")) {
		t.Error("garbage cookie should not validate")
	}

	// Tampered MAC (flip a byte, re-encode) → reject.
	raw, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[len(raw)-1] ^= 0xFF
	if a.validSession(withCookie(base64.RawURLEncoding.EncodeToString(raw))) {
		t.Error("tampered MAC should not validate")
	}

	// A cookie signed by a different per-process secret must be rejected.
	other := New(store.New(), fakeWhoIs{}, &fakeController{}, Config{UIPassword: "pw"})
	if other.validSession(withCookie(val)) {
		t.Error("cookie from a different secret should not validate")
	}

	// Expired but correctly signed → reject.
	expired := make([]byte, sessionRawLen)
	binary.BigEndian.PutUint64(expired[:sessionExpiryLen], uint64(time.Now().Add(-time.Hour).Unix()))
	mac := a.sessionMAC(expired[:sessionExpiryLen+sessionNonceLen])
	copy(expired[sessionExpiryLen+sessionNonceLen:], mac)
	if a.validSession(withCookie(base64.RawURLEncoding.EncodeToString(expired))) {
		t.Error("expired session should not validate")
	}
}

func TestHandleLogin(t *testing.T) {
	loginFailDelay = 0 // keep the suite fast; brute-force delay is exercised in prod
	const host = "tsctl"
	newAPI := func(pw string) *API {
		return New(store.New(), fakeWhoIs{login: "nobody"}, &fakeController{},
			Config{Owner: "alice", UIPassword: pw, AllowedHosts: []string{host}})
	}
	post := func(a *API, bodyJSON string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		a.handleLogin(rec, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(bodyJSON)))
		return rec
	}

	// Correct password → 200 + a usable HttpOnly/Strict session cookie.
	a := newAPI("hunter2")
	rec := post(a, `{"password":"hunter2"}`)
	if rec.Code != 200 {
		t.Fatalf("correct login code = %d want 200 body=%s", rec.Code, rec.Body)
	}
	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			sc = c
		}
	}
	if sc == nil || sc.Value == "" {
		t.Fatal("correct login set no session cookie")
	}
	if !sc.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if sc.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie SameSite = %v want Strict", sc.SameSite)
	}
	if sc.Path != "/" {
		t.Errorf("session cookie Path = %q want /", sc.Path)
	}
	rv := httptest.NewRequest(http.MethodGet, "/", nil)
	rv.AddCookie(sc)
	if !a.validSession(rv) {
		t.Error("issued session cookie should validate")
	}

	// Wrong password → 401, no cookie. (subtle.ConstantTimeCompare in source.)
	rec = post(newAPI("hunter2"), `{"password":"nope"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong login code = %d want 401", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			t.Error("wrong login must not set a session cookie")
		}
	}

	// Password path disabled → 404 (endpoint does not exist).
	rec = post(newAPI(""), `{"password":"whatever"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabled login code = %d want 404", rec.Code)
	}
}

// TestRoutes_LoginLogoutChain proves login/logout are reachable WITHOUT a session
// but still enforce RequireHost + RequireCSRF, and that the issued session then
// authorizes a data route even when the WhoIs identity is NOT the owner.
func TestRoutes_LoginLogoutChain(t *testing.T) {
	loginFailDelay = 0
	const host = "tsctl"
	a := New(store.New(), fakeWhoIs{login: "nobody@example.com"}, &fakeController{},
		Config{Owner: "alice@example.com", UIPassword: "pw", AllowedHosts: []string{host}})
	h := a.Routes()

	login := func(reqHost string, withCSRF bool) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"password":"pw"}`))
		req.Host = reqHost
		req.Header.Set("Content-Type", "application/json")
		if withCSRF {
			req.Header.Set("X-Tsctl-CSRF", "tok")
			req.AddCookie(&http.Cookie{Name: "tsctl_csrf", Value: "tok"})
		}
		h.ServeHTTP(rec, req)
		return rec
	}

	if got := login("evil.example", true).Code; got != http.StatusForbidden {
		t.Errorf("login bad Host = %d want 403 (RequireHost)", got)
	}
	if got := login(host, false).Code; got != http.StatusForbidden {
		t.Errorf("login missing CSRF = %d want 403 (RequireCSRF)", got)
	}

	rec := login(host, true)
	if rec.Code != 200 {
		t.Fatalf("good login = %d want 200 body=%s", rec.Code, rec.Body)
	}
	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			sc = c
		}
	}
	if sc == nil {
		t.Fatal("good login set no session cookie")
	}

	// The session authorizes a data GET despite a non-owner WhoIs.
	getNodes := func(c *http.Cookie) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
		req.Host = host
		if c != nil {
			req.AddCookie(c)
		}
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := getNodes(sc); got != 200 {
		t.Errorf("session GET /api/nodes = %d want 200", got)
	}
	if got := getNodes(nil); got != http.StatusUnauthorized {
		t.Errorf("no-session GET /api/nodes = %d want 401", got)
	}

	// Logout requires Host + CSRF and clears the cookie.
	logout := func(withCSRF bool) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
		req.Host = host
		req.AddCookie(sc)
		if withCSRF {
			req.Header.Set("X-Tsctl-CSRF", "tok")
			req.AddCookie(&http.Cookie{Name: "tsctl_csrf", Value: "tok"})
		}
		h.ServeHTTP(rec, req)
		return rec
	}
	if got := logout(false).Code; got != http.StatusForbidden {
		t.Errorf("logout missing CSRF = %d want 403", got)
	}
	lrec := logout(true)
	if lrec.Code != 200 {
		t.Errorf("logout = %d want 200", lrec.Code)
	}
	cleared := false
	for _, c := range lrec.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout must clear the session cookie (MaxAge<0)")
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

func TestHandleProbe_OK(t *testing.T) {
	checkedAt := time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC)
	fc := &fakeController{probeRes: store.ProbeResult{
		OK: true, DurationMs: 42, Output: "Linux router 5.15", CheckedAt: checkedAt,
	}}
	a := New(store.New(), fakeWhoIs{login: "alice"}, fc, Config{Owner: "alice"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/routers/r1/probe", nil)
	req.SetPathValue("id", "r1")
	a.handleProbe(rec, req)

	if rec.Code != 200 {
		t.Fatalf("code = %d body=%s", rec.Code, rec.Body)
	}
	if fc.gotProbeID != "r1" {
		t.Errorf("controller called with %q, want r1", fc.gotProbeID)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["ok"] != true {
		t.Errorf("ok = %v, want true", got["ok"])
	}
	if got["durationMs"].(float64) != 42 {
		t.Errorf("durationMs = %v, want 42", got["durationMs"])
	}
	if got["output"] != "Linux router 5.15" {
		t.Errorf("output = %v", got["output"])
	}
	if got["checkedAt"] != "2026-06-18T10:00:00Z" {
		t.Errorf("checkedAt = %v, want RFC3339", got["checkedAt"])
	}
	// error is omitempty -> absent on success.
	if _, ok := got["error"]; ok {
		t.Errorf("error key must be omitted on success, got %v", got["error"])
	}
}

func TestHandleProbe_SSHFailIs200(t *testing.T) {
	checkedAt := time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC)
	// An SSH failure is a RESULT (OK:false + error), returned with 200 -- not an
	// HTTP error.
	fc := &fakeController{probeRes: store.ProbeResult{
		OK: false, DurationMs: 12, Error: "ssh handshake failed", CheckedAt: checkedAt,
	}}
	a := New(store.New(), fakeWhoIs{login: "alice"}, fc, Config{Owner: "alice"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/routers/r1/probe", nil)
	req.SetPathValue("id", "r1")
	a.handleProbe(rec, req)

	if rec.Code != 200 {
		t.Fatalf("ssh-fail probe code = %d want 200 (result, not error)", rec.Code)
	}
	var got map[string]any
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["ok"] != false {
		t.Errorf("ok = %v, want false", got["ok"])
	}
	if got["error"] != "ssh handshake failed" {
		t.Errorf("error = %v", got["error"])
	}
	// output is omitempty -> absent when empty.
	if _, ok := got["output"]; ok {
		t.Errorf("output key must be omitted when empty, got %v", got["output"])
	}
}

func TestHandleProbe_NotFoundIs404(t *testing.T) {
	fc := &fakeController{probeErr: &ctrlErr{status: 404, msg: `unknown router "ghost"`}}
	a := New(store.New(), fakeWhoIs{login: "alice"}, fc, Config{Owner: "alice"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/routers/ghost/probe", nil)
	req.SetPathValue("id", "ghost")
	a.handleProbe(rec, req)

	if rec.Code != 404 {
		t.Fatalf("code = %d want 404", rec.Code)
	}
	var got map[string]string
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["error"] == "" {
		t.Errorf("404 body must carry an error, got %v", got)
	}
}

// TestRoutes_ProbeSecurity proves the probe route runs through the SAME middleware
// as exit-node: missing CSRF -> 403, non-owner with no session -> 401, and a valid
// owner + CSRF + Host POST -> 200.
func TestRoutes_ProbeSecurity(t *testing.T) {
	const host = "tsctl"
	fc := &fakeController{probeRes: store.ProbeResult{OK: true, CheckedAt: time.Now()}}
	a := New(store.New(), fakeWhoIs{login: "alice"}, fc, Config{Owner: "alice", AllowedHosts: []string{host}})
	h := a.Routes()

	// Missing CSRF -> 403.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/routers/r1/probe", nil)
	req.Host = host
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("probe missing CSRF = %d want 403", rec.Code)
	}

	// Valid owner + CSRF + Host -> 200.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/routers/r1/probe", nil)
	req.Host = host
	req.Header.Set("X-Tsctl-CSRF", "tok")
	req.AddCookie(&http.Cookie{Name: "tsctl_csrf", Value: "tok"})
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("valid probe = %d want 200 body=%s", rec.Code, rec.Body)
	}
	if fc.gotProbeID != "r1" {
		t.Errorf("controller probed %q, want r1", fc.gotProbeID)
	}

	// Non-owner, no session -> 401 (even with valid CSRF).
	a2 := New(store.New(), fakeWhoIs{login: "bob"}, &fakeController{}, Config{Owner: "alice", AllowedHosts: []string{host}})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/routers/r1/probe", nil)
	req.Host = host
	req.Header.Set("X-Tsctl-CSRF", "tok")
	req.AddCookie(&http.Cookie{Name: "tsctl_csrf", Value: "tok"})
	a2.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("non-owner probe = %d want 401", rec.Code)
	}
}

// --- group (zone) handlers ----------------------------------------------------

// newGroupAPI wires an API over a REAL groups.Store (temp file) so the handler
// tests exercise the actual validation / 404 / structural-error seam end to end.
func newGroupAPI(t *testing.T) *API {
	t.Helper()
	gs, err := groups.New(filepath.Join(t.TempDir(), "groups.json"))
	if err != nil {
		t.Fatalf("groups.New: %v", err)
	}
	return New(store.New(), fakeWhoIs{login: "alice"}, &fakeController{},
		Config{Owner: "alice", AllowedHosts: []string{"tsctl"}, Groups: gs})
}

// TestGroupMutations_TriggerRefresh covers the zone-create-invisible fix: every
// SUCCESSFUL group mutation must call RefreshGroups (which rebuilds + broadcasts
// the snapshot so the new/edited/deleted zone shows immediately); a REJECTED
// mutation must not.
func TestGroupMutations_TriggerRefresh(t *testing.T) {
	gs, err := groups.New(filepath.Join(t.TempDir(), "groups.json"))
	if err != nil {
		t.Fatalf("groups.New: %v", err)
	}
	ctrl := &fakeController{}
	a := New(store.New(), fakeWhoIs{login: "alice"}, ctrl,
		Config{Owner: "alice", AllowedHosts: []string{"tsctl"}, Groups: gs})

	rec := httptest.NewRecorder()
	a.handleCreateGroup(rec, httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(`{"name":"work"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code = %d body=%s", rec.Code, rec.Body)
	}
	if ctrl.refreshGroupsCalls != 1 {
		t.Fatalf("a successful create must RefreshGroups once, got %d", ctrl.refreshGroupsCalls)
	}
	var created map[string]any
	json.Unmarshal(rec.Body.Bytes(), &created)
	id, _ := created["id"].(string)

	// A rejected create (empty name) must NOT refresh.
	rec = httptest.NewRecorder()
	a.handleCreateGroup(rec, httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(`{"name":"   "}`)))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid create = %d, want 422", rec.Code)
	}
	if ctrl.refreshGroupsCalls != 1 {
		t.Errorf("a rejected create must NOT RefreshGroups, calls = %d", ctrl.refreshGroupsCalls)
	}

	ureq := httptest.NewRequest(http.MethodPut, "/api/groups/"+id, strings.NewReader(`{"name":"work2"}`))
	ureq.SetPathValue("id", id)
	a.handleUpdateGroup(httptest.NewRecorder(), ureq)
	if ctrl.refreshGroupsCalls != 2 {
		t.Errorf("update must RefreshGroups, calls = %d", ctrl.refreshGroupsCalls)
	}

	dreq := httptest.NewRequest(http.MethodDelete, "/api/groups/"+id, nil)
	dreq.SetPathValue("id", id)
	a.handleDeleteGroup(httptest.NewRecorder(), dreq)
	if ctrl.refreshGroupsCalls != 3 {
		t.Errorf("delete must RefreshGroups, calls = %d", ctrl.refreshGroupsCalls)
	}
}

func TestHandleGroups_CRUD(t *testing.T) {
	a := newGroupAPI(t)

	// List empty -> 200 and a JSON ARRAY (never null).
	rec := httptest.NewRecorder()
	a.handleListGroups(rec, httptest.NewRequest(http.MethodGet, "/api/groups", nil))
	if rec.Code != 200 {
		t.Fatalf("list code = %d", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("empty list body = %q, want []", got)
	}

	// Create -> 201, returns id + echoed raw fields.
	rec = httptest.NewRecorder()
	a.handleCreateGroup(rec, httptest.NewRequest(http.MethodPost, "/api/groups",
		strings.NewReader(`{"name":"work","consumers":["n-a"],"allowedExitNodes":["n-x"]}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code = %d body=%s", rec.Code, rec.Body)
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal create: %v", err)
	}
	for _, k := range []string{"id", "name", "consumers", "allowedExitNodes"} {
		if _, ok := created[k]; !ok {
			t.Errorf("created group missing key %q (got %v)", k, created)
		}
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("create did not assign an id")
	}
	if created["name"] != "work" {
		t.Errorf("name = %v", created["name"])
	}

	// Create invalid (empty name) -> 422 {error,detail}.
	rec = httptest.NewRecorder()
	a.handleCreateGroup(rec, httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(`{"name":"   "}`)))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid create code = %d want 422", rec.Code)
	}
	var errBody map[string]string
	json.Unmarshal(rec.Body.Bytes(), &errBody)
	if errBody["error"] == "" || errBody["detail"] == "" {
		t.Errorf("422 body must carry error+detail, got %v", errBody)
	}

	// Update -> 200, id preserved, fields replaced.
	rec = httptest.NewRecorder()
	ureq := httptest.NewRequest(http.MethodPut, "/api/groups/"+id, strings.NewReader(`{"name":"work2","consumers":["n-b"]}`))
	ureq.SetPathValue("id", id)
	a.handleUpdateGroup(rec, ureq)
	if rec.Code != 200 {
		t.Fatalf("update code = %d body=%s", rec.Code, rec.Body)
	}
	var updated map[string]any
	json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated["id"] != id {
		t.Errorf("update must preserve id: %v != %v", updated["id"], id)
	}
	if updated["name"] != "work2" {
		t.Errorf("update name = %v", updated["name"])
	}

	// Update missing -> 404.
	rec = httptest.NewRecorder()
	ureq = httptest.NewRequest(http.MethodPut, "/api/groups/nope", strings.NewReader(`{"name":"x"}`))
	ureq.SetPathValue("id", "nope")
	a.handleUpdateGroup(rec, ureq)
	if rec.Code != http.StatusNotFound {
		t.Errorf("update missing code = %d want 404", rec.Code)
	}

	// List now has exactly one group.
	rec = httptest.NewRecorder()
	a.handleListGroups(rec, httptest.NewRequest(http.MethodGet, "/api/groups", nil))
	var list []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Errorf("list len = %d want 1", len(list))
	}

	// Delete -> 204 (empty body).
	rec = httptest.NewRecorder()
	dreq := httptest.NewRequest(http.MethodDelete, "/api/groups/"+id, nil)
	dreq.SetPathValue("id", id)
	a.handleDeleteGroup(rec, dreq)
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete code = %d want 204", rec.Code)
	}

	// Delete missing -> 404.
	rec = httptest.NewRecorder()
	dreq = httptest.NewRequest(http.MethodDelete, "/api/groups/"+id, nil)
	dreq.SetPathValue("id", id)
	a.handleDeleteGroup(rec, dreq)
	if rec.Code != http.StatusNotFound {
		t.Errorf("delete missing code = %d want 404", rec.Code)
	}
}

// TestGroups_WriteSecurity proves a group write goes through the SAME middleware
// as the data routes: a no-CSRF POST is 403, a bad Host is 403, an unauthenticated
// caller is 401, and a valid owner+CSRF+Host POST is 201.
func TestGroups_WriteSecurity(t *testing.T) {
	const host = "tsctl"
	gs, err := groups.New(filepath.Join(t.TempDir(), "groups.json"))
	if err != nil {
		t.Fatalf("groups.New: %v", err)
	}
	a := New(store.New(), fakeWhoIs{login: "alice"}, &fakeController{},
		Config{Owner: "alice", AllowedHosts: []string{host}, Groups: gs})
	h := a.Routes()

	post := func(reqHost string, withCSRF bool) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(`{"name":"z"}`))
		req.Host = reqHost
		req.Header.Set("Content-Type", "application/json")
		if withCSRF {
			req.Header.Set("X-Tsctl-CSRF", "tok")
			req.AddCookie(&http.Cookie{Name: "tsctl_csrf", Value: "tok"})
		}
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := post(host, false); got != http.StatusForbidden {
		t.Errorf("no-CSRF POST /api/groups = %d want 403", got)
	}
	if got := post("evil.example", true); got != http.StatusForbidden {
		t.Errorf("bad-Host POST /api/groups = %d want 403", got)
	}
	if got := post(host, true); got != http.StatusCreated {
		t.Errorf("valid owner+CSRF+Host POST /api/groups = %d want 201", got)
	}

	// Unauthenticated (non-owner WhoIs, no session) -> 401, even with valid CSRF.
	a2 := New(store.New(), fakeWhoIs{login: "intruder"}, &fakeController{},
		Config{Owner: "alice", AllowedHosts: []string{host}, Groups: gs})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(`{"name":"z"}`))
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tsctl-CSRF", "tok")
	req.AddCookie(&http.Cookie{Name: "tsctl_csrf", Value: "tok"})
	a2.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauth POST /api/groups = %d want 401", rec.Code)
	}
}

// TestEncodeSnapshot_IncludesGroups proves the SSE/REST Snapshot DTO carries the
// resolved `groups` field (camelCase) with resolved member info, and that an
// empty snapshot still emits an array (never null).
func TestEncodeSnapshot_IncludesGroups(t *testing.T) {
	snap := &store.Snapshot{
		Groups: []store.GroupView{{
			ID:   "z1",
			Name: "Work",
			Consumers: []store.GroupMember{
				{StableID: "n-a", Name: "router-a", IP: "100.64.0.10", Online: true, Present: true},
			},
			AllowedExitNodes: []store.GroupMember{
				{StableID: "n-x", Present: false},
			},
		}},
	}
	b, err := EncodeSnapshot(snap)
	if err != nil {
		t.Fatalf("EncodeSnapshot: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw, ok := got["groups"].([]any)
	if !ok {
		t.Fatalf("snapshot missing groups array (json tag drift?): %v", got["groups"])
	}
	if len(raw) != 1 {
		t.Fatalf("groups len = %d want 1", len(raw))
	}
	g0 := raw[0].(map[string]any)
	for _, k := range []string{"id", "name", "consumers", "allowedExitNodes"} {
		if _, ok := g0[k]; !ok {
			t.Errorf("groupView missing camelCase key %q (got %v)", k, g0)
		}
	}
	cons := g0["consumers"].([]any)
	if len(cons) != 1 {
		t.Fatalf("consumers len = %d", len(cons))
	}
	m0 := cons[0].(map[string]any)
	for _, k := range []string{"stableID", "name", "ip", "online", "present"} {
		if _, ok := m0[k]; !ok {
			t.Errorf("groupMember missing camelCase key %q (got %v)", k, m0)
		}
	}
	if m0["present"] != true || m0["ip"] != "100.64.0.10" || m0["online"] != true {
		t.Errorf("present member resolved wrong: %v", m0)
	}
	allowed := g0["allowedExitNodes"].([]any)
	if allowed[0].(map[string]any)["present"] != false {
		t.Errorf("absent member present should be false: %v", allowed[0])
	}

	// An empty snapshot still emits groups as [] (never null).
	b, err = EncodeSnapshot(&store.Snapshot{})
	if err != nil {
		t.Fatalf("EncodeSnapshot empty: %v", err)
	}
	json.Unmarshal(b, &got)
	if arr, ok := got["groups"].([]any); !ok || len(arr) != 0 {
		t.Errorf("empty snapshot groups = %v, want [] (non-null empty array)", got["groups"])
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

	// A non-owner with no session is rejected before reaching the handler. This
	// is now 401 ("authenticate") rather than 403: RequireOwner was replaced by
	// RequireAuth, and 403 is reserved for Host/CSRF failures.
	a2 := New(store.New(), fakeWhoIs{login: "bob"}, fc, Config{Owner: "alice", AllowedHosts: []string{host}})
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/routers/r1/exit-node", strings.NewReader(`{"exitNode":"n2"}`))
	req2.Host = host
	req2.Header.Set("X-Tsctl-CSRF", "tok")
	req2.AddCookie(&http.Cookie{Name: "tsctl_csrf", Value: "tok"})
	a2.Routes().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("non-owner POST code = %d want 401", rec2.Code)
	}
}
