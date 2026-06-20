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

	"github.com/lifeart/tsctl/internal/authz"
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

	keepRV    store.RouterView
	keepErr   error
	gotKeepID string

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

func (f *fakeController) Keep(ctx context.Context, routerID string) (store.RouterView, error) {
	f.gotKeepID = routerID
	return f.keepRV, f.keepErr
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

// adminReq returns r carrying an admin Subject in its context, simulating
// RequireAuth having authenticated an admin. Isolated handler tests that call a
// handler DIRECTLY (bypassing the Routes middleware) need this so the
// authorizeRouterWrite choke point sees an authorized caller; through the real
// Routes() chain RequireAuth injects the Subject for them.
func adminReq(r *http.Request) *http.Request {
	return r.WithContext(authz.WithSubject(r.Context(), authz.Subject{Admin: true}))
}

// guestReq returns r carrying a guest Subject bound to zoneID.
func guestReq(r *http.Request, guestID, zoneID string) *http.Request {
	return r.WithContext(authz.WithSubject(r.Context(), authz.Subject{GuestID: guestID, ZoneID: zoneID}))
}

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
		val, err := a.newSessionValue(authz.Subject{Admin: true})
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
	// valid is the post-rename predicate over parseSession (admin cookies don't
	// need the live-store re-load that resolveSubject adds for guests).
	valid := func(r *http.Request) bool {
		_, ok := a.parseSession(r)
		return ok
	}

	val, err := a.newSessionValue(authz.Subject{Admin: true})
	if err != nil {
		t.Fatalf("newSessionValue: %v", err)
	}
	if !valid(withCookie(val)) {
		t.Error("freshly minted session should validate")
	}
	if valid(httptest.NewRequest(http.MethodGet, "/api/nodes", nil)) {
		t.Error("missing cookie should not validate")
	}
	if valid(withCookie("not valid base64 $$")) {
		t.Error("garbage cookie should not validate")
	}

	// Tampered MAC (flip a byte, re-encode) → reject.
	raw, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[len(raw)-1] ^= 0xFF
	if valid(withCookie(base64.RawURLEncoding.EncodeToString(raw))) {
		t.Error("tampered MAC should not validate")
	}

	// A cookie signed by a different per-process secret must be rejected.
	other := New(store.New(), fakeWhoIs{}, &fakeController{}, Config{UIPassword: "pw"})
	if _, ok := other.parseSession(withCookie(val)); ok {
		t.Error("cookie from a different secret should not validate")
	}

	// Expired but correctly signed → reject (admin layout: header + MAC, no gid).
	expired := make([]byte, sessionHeaderLen+sessionMACLen)
	binary.BigEndian.PutUint64(expired[:sessionExpiryLen], uint64(time.Now().Add(-time.Hour).Unix()))
	expired[sessionExpiryLen+sessionNonceLen] = roleAdmin // role
	expired[sessionExpiryLen+sessionNonceLen+sessionRoleLen] = 0
	mac := a.sessionMAC(expired[:sessionHeaderLen])
	copy(expired[sessionHeaderLen:], mac)
	if valid(withCookie(base64.RawURLEncoding.EncodeToString(expired))) {
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
	if _, ok := a.parseSession(rv); !ok {
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
	// In production these read handlers always run behind RequireAuth, which injects
	// the Subject; an admin subject yields the full (unfiltered) view.
	req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	req = req.WithContext(authz.WithSubject(req.Context(), authz.Subject{Admin: true}))
	a.handleNodes(rec, req)
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
	req = req.WithContext(authz.WithSubject(req.Context(), authz.Subject{Admin: true}))
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

	// 404 for an unknown id (admin subject, so it reaches the not-found path).
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/routers/nope", nil)
	req2.SetPathValue("id", "nope")
	req2 = req2.WithContext(authz.WithSubject(req2.Context(), authz.Subject{Admin: true}))
	a.handleRouter(rec2, req2)
	if rec2.Code != 404 {
		t.Errorf("unknown router code = %d want 404", rec2.Code)
	}

	// Fail-closed: NO subject in context (must not happen behind RequireAuth) -> 401,
	// never the unfiltered view.
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/api/routers/r1", nil)
	req3.SetPathValue("id", "r1")
	a.handleRouter(rec3, req3)
	if rec3.Code != 401 {
		t.Errorf("no-subject router code = %d want 401 (fail-closed)", rec3.Code)
	}
}

// TestRouterViewDTO_Egress locks in the egress wire shape (docs/design/keep-egress.md):
// egressOk is OMITTED when nil (not checked / Direct), and present (with detail +
// rfc3339 checkedAt) when checked -- including a non-nil pointer to false (✗).
func TestRouterViewDTO_Egress(t *testing.T) {
	// nil EgressOK -> all three egress keys omitted.
	nilJSON, err := json.Marshal(routerViewDTO(store.RouterView{State: store.RouterOK}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, k := range []string{"egressOk", "egressDetail", "egressCheckedAt"} {
		if strings.Contains(string(nilJSON), k) {
			t.Errorf("egress key %q must be omitted when EgressOK is nil; got %s", k, nilJSON)
		}
	}

	// EgressOK=&false (checked, failed) -> egressOk:false present, with detail + time.
	bad := false
	checked := time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC)
	var got map[string]any
	b, err := json.Marshal(routerViewDTO(store.RouterView{
		State: store.RouterOK, EgressOK: &bad, EgressDetail: "timed out", EgressCheckedAt: checked,
	}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, ok := got["egressOk"]; !ok || v != false {
		t.Errorf("egressOk = %v (present=%v), want false present", v, ok)
	}
	if got["egressDetail"] != "timed out" {
		t.Errorf("egressDetail = %v, want %q", got["egressDetail"], "timed out")
	}
	if got["egressCheckedAt"] != "2026-06-19T10:00:00Z" {
		t.Errorf("egressCheckedAt = %v, want rfc3339 UTC", got["egressCheckedAt"])
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
	a.handleSetExitNode(rec, adminReq(req))
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
	a.handleSetExitNode(rec, adminReq(req))
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
	a.handleSetExitNode(rec, adminReq(req))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("code = %d want 502", rec.Code)
	}
}

// TestRouterViewDTO_RevertAt locks in the awaiting-keep wire shape: revertAt is
// OMITTED when zero and present (rfc3339 UTC) when set, and state flows as the
// "awaiting-keep" string (docs/design/keep-egress.md stage 2).
func TestRouterViewDTO_RevertAt(t *testing.T) {
	// Zero RevertAt -> key omitted.
	zeroJSON, err := json.Marshal(routerViewDTO(store.RouterView{State: store.RouterOK}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(zeroJSON), "revertAt") {
		t.Errorf("revertAt must be omitted when zero; got %s", zeroJSON)
	}

	// awaiting-keep with a RevertAt -> state + revertAt present.
	at := time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC)
	var got map[string]any
	b, err := json.Marshal(routerViewDTO(store.RouterView{State: store.RouterAwaitingKeep, RevertAt: at}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["state"] != "awaiting-keep" {
		t.Errorf("state = %v, want awaiting-keep", got["state"])
	}
	if got["revertAt"] != "2026-06-19T10:00:00Z" {
		t.Errorf("revertAt = %v, want rfc3339 UTC", got["revertAt"])
	}
}

func TestHandleKeep_OK(t *testing.T) {
	fc := &fakeController{keepRV: store.RouterView{
		Node:  store.NodeView{StableID: "r1"},
		State: store.RouterOK, Reachable: true,
	}}
	a := New(store.New(), fakeWhoIs{login: "alice"}, fc, Config{Owner: "alice"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/routers/r1/keep", nil)
	req.SetPathValue("id", "r1")
	a.handleKeep(rec, adminReq(req))
	if rec.Code != 200 {
		t.Fatalf("code = %d body=%s", rec.Code, rec.Body)
	}
	if fc.gotKeepID != "r1" {
		t.Errorf("controller keep called with %q, want r1", fc.gotKeepID)
	}
	var got map[string]any
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["state"] != "ok" {
		t.Errorf("state = %v, want ok", got["state"])
	}
}

func TestHandleKeep_ErrorStatuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"no/elapsed/superseded pending -> 409", &ctrlErr{status: 409, msg: "the revert window elapsed; the router has reverted"}, 409},
		{"unknown router -> 404", &ctrlErr{status: 404, msg: `unknown router "ghost"`}, 404},
		{"router command failed -> 502", &ctrlErr{status: 502, msg: "router command failed", det: "disk full", serr: "disk full"}, 502},
		{"generic error -> 502", errors.New("plain failure"), 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := &fakeController{keepErr: tc.err}
			a := New(store.New(), fakeWhoIs{login: "alice"}, fc, Config{Owner: "alice"})
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/routers/r1/keep", nil)
			req.SetPathValue("id", "r1")
			a.handleKeep(rec, adminReq(req))
			if rec.Code != tc.want {
				t.Fatalf("code = %d want %d body=%s", rec.Code, tc.want, rec.Body)
			}
			var got map[string]string
			json.Unmarshal(rec.Body.Bytes(), &got)
			if got["error"] == "" {
				t.Errorf("error body must carry a message, got %v", got)
			}
		})
	}
}

// TestRoutes_KeepSecurity proves POST /keep runs through the SAME middleware as
// exit-node: missing CSRF -> 403, valid owner+CSRF+Host -> 200.
func TestRoutes_KeepSecurity(t *testing.T) {
	const host = "tsctl"
	fc := &fakeController{keepRV: store.RouterView{Node: store.NodeView{StableID: "r1"}, State: store.RouterOK}}
	a := New(store.New(), fakeWhoIs{login: "alice"}, fc, Config{Owner: "alice", AllowedHosts: []string{host}})
	h := a.Routes()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/routers/r1/keep", nil)
	req.Host = host
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("keep missing CSRF = %d want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/routers/r1/keep", nil)
	req.Host = host
	req.Header.Set("X-Tsctl-CSRF", "tok")
	req.AddCookie(&http.Cookie{Name: "tsctl_csrf", Value: "tok"})
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("valid keep = %d want 200 body=%s", rec.Code, rec.Body)
	}
	if fc.gotKeepID != "r1" {
		t.Errorf("controller kept %q, want r1", fc.gotKeepID)
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
	a.handleProbe(rec, adminReq(req))

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
	a.handleProbe(rec, adminReq(req))

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
	a.handleProbe(rec, adminReq(req))

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

// --- guest mode ---------------------------------------------------------------

// fakeGuests is an in-memory api.GuestStore for the guest-mode tests. The plain
// passwords are stored alongside (test-only) so Authenticate can verify without
// bcrypt; the real timing/hashing parity lives in internal/guests.
type fakeGuests struct {
	byID map[string]store.Guest
	pw   map[string]string // id -> plaintext (test only)
}

func newFakeGuests() *fakeGuests {
	return &fakeGuests{byID: map[string]store.Guest{}, pw: map[string]string{}}
}

func (f *fakeGuests) add(g store.Guest, password string) {
	f.byID[g.ID] = g
	f.pw[g.ID] = password
}

func (f *fakeGuests) List() []store.Guest {
	out := make([]store.Guest, 0, len(f.byID))
	for _, g := range f.byID {
		out = append(out, g)
	}
	return out
}

func (f *fakeGuests) Get(id string) (store.Guest, bool) {
	g, ok := f.byID[id]
	return g, ok
}

func (f *fakeGuests) Create(label, zoneID, pw string) (store.Guest, error) {
	if strings.TrimSpace(label) == "" {
		return store.Guest{}, &ctrlErr{status: 422, msg: "invalid guest", det: "label must not be empty"}
	}
	id := "g-" + label
	g := store.Guest{ID: id, Label: label, ZoneID: zoneID, CreatedAt: time.Now()}
	f.add(g, pw)
	return g, nil
}

func (f *fakeGuests) SetDisabled(id string, disabled bool) (store.Guest, error) {
	g, ok := f.byID[id]
	if !ok {
		return store.Guest{}, &ctrlErr{status: 404, msg: "guest not found"}
	}
	g.Disabled = disabled
	f.byID[id] = g
	return g, nil
}

func (f *fakeGuests) Delete(id string) error {
	if _, ok := f.byID[id]; !ok {
		return &ctrlErr{status: 404, msg: "guest not found"}
	}
	delete(f.byID, id)
	delete(f.pw, id)
	return nil
}

func (f *fakeGuests) Authenticate(label, pw string) (store.Guest, bool) {
	for id, g := range f.byID {
		if strings.EqualFold(g.Label, label) {
			if f.pw[id] == pw && !g.Disabled {
				return g, true
			}
			return store.Guest{}, false
		}
	}
	return store.Guest{}, false
}

var _ GuestStore = (*fakeGuests)(nil)

// newGuestAPI wires an API over a REAL groups.Store (temp file) plus a fakeGuests,
// with one zone "Work" (consumers [r1], allowed exits [e1]) and one guest bound to
// it. It returns the API, the zone id, and the guest id.
func newGuestAPI(t *testing.T) (*API, *groups.Store, *fakeGuests, string, string) {
	t.Helper()
	gs, err := groups.New(filepath.Join(t.TempDir(), "guests-groups.json"))
	if err != nil {
		t.Fatalf("groups.New: %v", err)
	}
	zone, err := gs.Create(store.Group{Name: "Work", Consumers: []string{"r1"}, AllowedExitNodes: []string{"e1"}})
	if err != nil {
		t.Fatalf("create zone: %v", err)
	}
	fg := newFakeGuests()
	fg.add(store.Guest{ID: "guest-1", Label: "alice-guest", ZoneID: zone.ID}, "guest-password")
	a := New(store.New(), fakeWhoIs{login: "nobody"}, &fakeController{},
		Config{Owner: "admin@example.com", UIPassword: "adminpw", AllowedHosts: []string{"tsctl"}, Groups: gs, Guests: fg})
	return a, gs, fg, zone.ID, "guest-1"
}

// guestCookieReq builds a request carrying a signed guest session cookie for gid.
func guestCookieReq(t *testing.T, a *API, method, target, gid string) *http.Request {
	t.Helper()
	val, err := a.newSessionValue(authz.Subject{GuestID: gid})
	if err != nil {
		t.Fatalf("newSessionValue(guest): %v", err)
	}
	req := httptest.NewRequest(method, target, nil)
	req.Host = "tsctl"
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: val})
	return req
}

// TestGuestSessionRoundTripAndTamper proves a signed guest cookie round-trips
// through resolveSubject (resolving the live zone) and that flipping the role byte
// to admin fails the MAC (no privilege forgery).
func TestGuestSessionRoundTripAndTamper(t *testing.T) {
	a, _, _, zoneID, gid := newGuestAPI(t)

	val, err := a.newSessionValue(authz.Subject{GuestID: gid})
	if err != nil {
		t.Fatalf("newSessionValue: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: val})

	sub, ok := a.resolveSubject(req)
	if !ok {
		t.Fatal("guest cookie should resolve")
	}
	if sub.Admin {
		t.Error("guest subject must not be admin")
	}
	if sub.GuestID != gid || sub.ZoneID != zoneID {
		t.Errorf("resolved subject = %+v want guest %q zone %q", sub, gid, zoneID)
	}

	// parseSession (pre-store) carries the guest id but no zone yet.
	psReq := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	psReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: val})
	ps, ok := a.parseSession(psReq)
	if !ok || ps.Admin || ps.GuestID != gid {
		t.Errorf("parseSession = %+v ok=%v", ps, ok)
	}

	// Tamper: flip the role byte to admin -> MAC fails -> denied (no escalation).
	raw, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[sessionExpiryLen+sessionNonceLen] = roleAdmin
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	treq := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	treq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tampered})
	if _, ok := a.resolveSubject(treq); ok {
		t.Error("a guest cookie with the role byte flipped to admin must NOT resolve (MAC must reject)")
	}
}

// TestLogin_AdminVsGuest exercises both login paths through handleLogin.
func TestLogin_AdminVsGuest(t *testing.T) {
	loginFailDelay = 0
	a, _, _, zoneID, gid := newGuestAPI(t)

	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
		a.handleLogin(rec, req)
		return rec
	}
	cookieFrom := func(rec *httptest.ResponseRecorder) *http.Cookie {
		for _, c := range rec.Result().Cookies() {
			if c.Name == sessionCookieName && c.Value != "" {
				return c
			}
		}
		return nil
	}

	// Admin: empty label + correct UI password.
	rec := post(`{"password":"adminpw"}`)
	if rec.Code != 200 {
		t.Fatalf("admin login = %d body=%s", rec.Code, rec.Body)
	}
	ac := cookieFrom(rec)
	if ac == nil {
		t.Fatal("admin login set no session cookie")
	}
	areq := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	areq.AddCookie(ac)
	if sub, ok := a.resolveSubject(areq); !ok || !sub.Admin {
		t.Errorf("admin cookie resolved to %+v ok=%v", sub, ok)
	}

	// Guest: label + correct password.
	rec = post(`{"label":"alice-guest","password":"guest-password"}`)
	if rec.Code != 200 {
		t.Fatalf("guest login = %d body=%s", rec.Code, rec.Body)
	}
	gc := cookieFrom(rec)
	if gc == nil {
		t.Fatal("guest login set no session cookie")
	}
	greq := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	greq.AddCookie(gc)
	if sub, ok := a.resolveSubject(greq); !ok || sub.Admin || sub.GuestID != gid || sub.ZoneID != zoneID {
		t.Errorf("guest cookie resolved to %+v ok=%v", sub, ok)
	}

	// Wrong guest password and unknown label -> 401, no cookie.
	if rec := post(`{"label":"alice-guest","password":"nope"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong guest password = %d want 401", rec.Code)
	}
	if rec := post(`{"label":"ghost","password":"whatever"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown guest label = %d want 401", rec.Code)
	}
	// Admin path with no UI password configured -> 404 (unchanged behavior).
	aNoPw := New(store.New(), fakeWhoIs{login: "x"}, &fakeController{}, Config{Owner: "o"})
	rec = httptest.NewRecorder()
	aNoPw.handleLogin(rec, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"password":"x"}`)))
	if rec.Code != http.StatusNotFound {
		t.Errorf("admin login with no UI password = %d want 404", rec.Code)
	}
}

// TestGuestRevocation proves the per-request store re-load revokes a guest the
// instant it is disabled, deleted, or its zone is deleted.
func TestGuestRevocation(t *testing.T) {
	a, gs, fg, zoneID, gid := newGuestAPI(t)
	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		val, _ := a.newSessionValue(authz.Subject{GuestID: gid})
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: val})
		return r
	}
	if _, ok := a.resolveSubject(req()); !ok {
		t.Fatal("guest should resolve before revocation")
	}

	// Disabled -> denied.
	fg.SetDisabled(gid, true)
	if _, ok := a.resolveSubject(req()); ok {
		t.Error("disabled guest must not resolve")
	}
	fg.SetDisabled(gid, false)
	if _, ok := a.resolveSubject(req()); !ok {
		t.Fatal("re-enabled guest should resolve")
	}

	// Zone deleted out from under the guest -> denied.
	if err := gs.Delete(zoneID); err != nil {
		t.Fatalf("delete zone: %v", err)
	}
	if _, ok := a.resolveSubject(req()); ok {
		t.Error("guest whose zone was deleted must not resolve")
	}

	// Guest deleted -> denied (re-create the zone first to isolate the cause).
	gs.Create(store.Group{Name: "Work2"})
	fg.Delete(gid)
	if _, ok := a.resolveSubject(req()); ok {
		t.Error("deleted guest must not resolve")
	}
}

// TestRequireAdmin_GuestForbidden proves a guest gets 403 on admin-only routes
// through the real Routes() chain, while the owner (admin) gets 200.
func TestRequireAdmin_GuestForbidden(t *testing.T) {
	a, _, _, _, gid := newGuestAPI(t)
	h := a.Routes()

	for _, path := range []string{"/api/groups", "/api/guests"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, guestCookieReq(t, a, http.MethodGet, path, gid))
		if rec.Code != http.StatusForbidden {
			t.Errorf("guest GET %s = %d want 403", path, rec.Code)
		}
	}

	// The owner (admin via WhoIs) is allowed through to the handler (200).
	gs, _ := groups.New(filepath.Join(t.TempDir(), "g.json"))
	fg := newFakeGuests()
	aAdmin := New(store.New(), fakeWhoIs{login: "alice"}, &fakeController{},
		Config{Owner: "alice", AllowedHosts: []string{"tsctl"}, Groups: gs, Guests: fg})
	for _, path := range []string{"/api/groups", "/api/guests"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "tsctl"
		aAdmin.Routes().ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("admin GET %s = %d want 200", path, rec.Code)
		}
	}
}

// TestAuthorizeRouterWrite covers the write authorization choke point: in-zone set
// allowed, out-of-zone denied, and a shared router whose target is allowed only by
// ANOTHER zone is still denied (the guest's own zone is the stricter source).
func TestAuthorizeRouterWrite(t *testing.T) {
	gs, err := groups.New(filepath.Join(t.TempDir(), "g.json"))
	if err != nil {
		t.Fatalf("groups.New: %v", err)
	}
	// z1: r1 may use e1. z2: r1 (shared) may use e2.
	z1, _ := gs.Create(store.Group{Name: "z1", Consumers: []string{"r1"}, AllowedExitNodes: []string{"e1"}})
	gs.Create(store.Group{Name: "z2", Consumers: []string{"r1"}, AllowedExitNodes: []string{"e2"}})
	fg := newFakeGuests()
	fg.add(store.Guest{ID: "g1", Label: "g", ZoneID: z1.ID}, "pw")
	fc := &fakeController{rv: store.RouterView{Node: store.NodeView{StableID: "r1"}, State: store.RouterOK}}
	a := New(store.New(), fakeWhoIs{login: "nobody"}, fc,
		Config{Owner: "admin", AllowedHosts: []string{"tsctl"}, Groups: gs, Guests: fg})

	set := func(routerID, target string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/routers/"+routerID+"/exit-node",
			strings.NewReader(`{"exitNode":"`+target+`"}`))
		req.SetPathValue("id", routerID)
		req = guestReq(req, "g1", z1.ID)
		a.handleSetExitNode(rec, req)
		return rec.Code
	}

	// In-zone router + in-zone target -> allowed (controller drives it, 200).
	if got := set("r1", "e1"); got != 200 {
		t.Errorf("in-zone set = %d want 200", got)
	}
	// In-zone router + clear (Direct) -> allowed.
	fc2Code := set("r1", "")
	if fc2Code != 200 {
		t.Errorf("in-zone clear = %d want 200", fc2Code)
	}
	// Out-of-zone router -> 403 (uniform, no oracle).
	if got := set("r2", "e1"); got != http.StatusForbidden {
		t.Errorf("out-of-zone router set = %d want 403", got)
	}
	// Shared router, target allowed ONLY by another zone (z2) -> 403 (own zone is
	// the stricter source; deliberately stricter than the poller's cross-zone union).
	if got := set("r1", "e2"); got != http.StatusForbidden {
		t.Errorf("shared-router other-zone-target set = %d want 403", got)
	}

	// Keep + Probe also gate on zone membership (no target).
	keep := func(routerID string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/routers/"+routerID+"/keep", nil)
		req.SetPathValue("id", routerID)
		req = guestReq(req, "g1", z1.ID)
		a.handleKeep(rec, req)
		return rec.Code
	}
	if got := keep("r2"); got != http.StatusForbidden {
		t.Errorf("out-of-zone keep = %d want 403", got)
	}
	probe := func(routerID string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/routers/"+routerID+"/probe", nil)
		req.SetPathValue("id", routerID)
		req = guestReq(req, "g1", z1.ID)
		a.handleProbe(rec, req)
		return rec.Code
	}
	if got := probe("r2"); got != http.StatusForbidden {
		t.Errorf("out-of-zone probe = %d want 403", got)
	}
	if got := probe("r1"); got != 200 {
		t.Errorf("in-zone probe = %d want 200", got)
	}
}

// TestGuestFilteredReads proves handleNodes is zone-filtered for a guest and
// handleRouter is 404 for an out-of-zone router (same as missing; no oracle).
func TestGuestFilteredReads(t *testing.T) {
	gs, err := groups.New(filepath.Join(t.TempDir(), "g.json"))
	if err != nil {
		t.Fatalf("groups.New: %v", err)
	}
	z1, _ := gs.Create(store.Group{Name: "z1", Consumers: []string{"r1"}, AllowedExitNodes: []string{"e1"}})
	fg := newFakeGuests()
	fg.add(store.Guest{ID: "g1", Label: "g", ZoneID: z1.ID}, "pw")

	st := store.New()
	st.Store(&store.Snapshot{
		Nodes: []store.NodeView{
			{StableID: "r1", Name: "router1"},
			{StableID: "e1", Name: "exit1"},
			{StableID: "other", Name: "secret-node"},
		},
		Routers: []store.RouterView{
			{Node: store.NodeView{StableID: "r1", Name: "router1"}, State: store.RouterOK},
			{Node: store.NodeView{StableID: "r2", Name: "router2"}, State: store.RouterOK},
		},
		Groups: []store.GroupView{{
			ID:               z1.ID,
			Name:             "z1",
			Consumers:        []store.GroupMember{{StableID: "r1", Present: true}},
			AllowedExitNodes: []store.GroupMember{{StableID: "e1", Present: true}},
		}},
	})
	a := New(st, fakeWhoIs{login: "nobody"}, &fakeController{},
		Config{Owner: "admin", AllowedHosts: []string{"tsctl"}, Groups: gs, Guests: fg})

	// handleNodes for a guest -> only r1 + e1, NOT "other".
	rec := httptest.NewRecorder()
	a.handleNodes(rec, guestReq(httptest.NewRequest(http.MethodGet, "/api/nodes", nil), "g1", z1.ID))
	var nodesBody struct {
		Nodes []map[string]any `json:"nodes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &nodesBody); err != nil {
		t.Fatalf("unmarshal nodes: %v", err)
	}
	seen := map[string]bool{}
	for _, n := range nodesBody.Nodes {
		seen[n["stableID"].(string)] = true
	}
	if !seen["r1"] || !seen["e1"] {
		t.Errorf("guest nodes should include r1+e1, got %v", seen)
	}
	if seen["other"] {
		t.Error("guest nodes must NOT include out-of-zone node 'other'")
	}

	// Admin handleNodes (no subject / admin subject) is unfiltered.
	recA := httptest.NewRecorder()
	a.handleNodes(recA, adminReq(httptest.NewRequest(http.MethodGet, "/api/nodes", nil)))
	if !strings.Contains(recA.Body.String(), "other") {
		t.Error("admin nodes must include all nodes (no filter)")
	}

	// handleRouter: in-zone r1 -> 200, out-of-zone r2 -> 404 (same as missing).
	get := func(id string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/routers/"+id, nil)
		req.SetPathValue("id", id)
		req = guestReq(req, "g1", z1.ID)
		a.handleRouter(rec, req)
		return rec.Code
	}
	if got := get("r1"); got != 200 {
		t.Errorf("guest in-zone router = %d want 200", got)
	}
	if got := get("r2"); got != http.StatusNotFound {
		t.Errorf("guest out-of-zone router = %d want 404", got)
	}
}

// TestHandleMe_Shapes locks in the /api/me shapes for admin and guest.
func TestHandleMe_Shapes(t *testing.T) {
	a, _, _, zoneID, gid := newGuestAPI(t)

	// Admin.
	rec := httptest.NewRecorder()
	a.handleMe(rec, adminReq(httptest.NewRequest(http.MethodGet, "/api/me", nil)))
	var me map[string]any
	json.Unmarshal(rec.Body.Bytes(), &me)
	if me["role"] != "admin" {
		t.Errorf("admin /api/me role = %v want admin", me["role"])
	}
	for _, k := range []string{"role", "zoneId", "zoneName"} {
		if _, ok := me[k]; !ok {
			t.Errorf("/api/me missing key %q", k)
		}
	}

	// Guest.
	rec = httptest.NewRecorder()
	a.handleMe(rec, guestReq(httptest.NewRequest(http.MethodGet, "/api/me", nil), gid, zoneID))
	json.Unmarshal(rec.Body.Bytes(), &me)
	if me["role"] != "guest" {
		t.Errorf("guest /api/me role = %v want guest", me["role"])
	}
	if me["zoneId"] != zoneID {
		t.Errorf("guest /api/me zoneId = %v want %q", me["zoneId"], zoneID)
	}
	if me["zoneName"] != "Work" {
		t.Errorf("guest /api/me zoneName = %v want Work", me["zoneName"])
	}
}

// TestGuestCRUD_NoHashAndZoneValidation covers the admin guest CRUD handlers: the
// list/create DTOs never carry a hash, an unknown zone is rejected, and a valid
// create succeeds.
func TestGuestCRUD_NoHashAndZoneValidation(t *testing.T) {
	a, _, _, zoneID, _ := newGuestAPI(t)

	// List: array, no hash field on any item.
	rec := httptest.NewRecorder()
	a.handleListGuests(rec, adminReq(httptest.NewRequest(http.MethodGet, "/api/guests", nil)))
	if rec.Code != 200 {
		t.Fatalf("list code = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, bad := range []string{"passwordHash", "\"hash\"", "password"} {
		if strings.Contains(body, bad) {
			t.Errorf("guest list body leaks %q: %s", bad, body)
		}
	}
	var list []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("list len = %d want 1", len(list))
	}
	for _, k := range []string{"id", "label", "zoneId", "disabled", "createdAt"} {
		if _, ok := list[0][k]; !ok {
			t.Errorf("guest DTO missing key %q (got %v)", k, list[0])
		}
	}

	// Create with unknown zone -> 422.
	rec = httptest.NewRecorder()
	a.handleCreateGuest(rec, adminReq(httptest.NewRequest(http.MethodPost, "/api/guests",
		strings.NewReader(`{"label":"bob","zoneId":"does-not-exist","password":"longenough"}`))))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("create unknown-zone = %d want 422", rec.Code)
	}

	// Create with a valid zone -> 201, no hash in the response.
	rec = httptest.NewRecorder()
	a.handleCreateGuest(rec, adminReq(httptest.NewRequest(http.MethodPost, "/api/guests",
		strings.NewReader(`{"label":"bob","zoneId":"`+zoneID+`","password":"longenough"}`))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create valid = %d body=%s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "password") {
		t.Errorf("create response leaks password material: %s", rec.Body)
	}
}

// TestDeleteGroup_409WhenGuestAssigned proves the delete-guard returns 409 while a
// guest is bound to the zone, and 204 once no guest references it.
func TestDeleteGroup_409WhenGuestAssigned(t *testing.T) {
	a, gs, fg, zoneID, gid := newGuestAPI(t)
	ctrl := a.ctrl.(*fakeController)

	del := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/api/groups/"+zoneID, nil)
		req.SetPathValue("id", zoneID)
		a.handleDeleteGroup(rec, adminReq(req))
		return rec.Code
	}

	if got := del(); got != http.StatusConflict {
		t.Errorf("delete zone with guest assigned = %d want 409", got)
	}
	if ctrl.refreshGroupsCalls != 0 {
		t.Errorf("a blocked delete must NOT RefreshGroups, calls = %d", ctrl.refreshGroupsCalls)
	}

	// Remove the guest, then the delete succeeds.
	fg.Delete(gid)
	if got := del(); got != http.StatusNoContent {
		t.Errorf("delete zone after removing guest = %d want 204", got)
	}
	if _, ok := gs.Get(zoneID); ok {
		t.Error("zone should be gone after a successful delete")
	}
}
