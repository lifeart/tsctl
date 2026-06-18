// Package api is the HTTP transport: handlers plus the fail-closed security
// middleware. It declares the WhoIser interface it consumes (DESIGN §4:
// interface at the consumer) and is injected with a concrete WhoIser
// (*netmap.Mapper) and the Store by the composition root.
//
// Security posture (DESIGN §7): every data request must authenticate via
// RequireAuth, which accepts EITHER the tailnet path (WhoIs identifies the peer
// as the configured owner, untagged -- fail-closed: any WhoIs error / tagged /
// non-owner does NOT grant, it falls through) OR the host/password path (a valid
// signed tsctl_session cookie established by POST /api/login). Every request is
// additionally Host-pinned (RequireHost, rejects DNS rebinding) and every
// state-changing request requires a valid X-Tsctl-CSRF header (double-submit
// cookie) plus Origin/Sec-Fetch-Site validation. A failed authentication is 401
// ("authenticate" -- the SPA shows the login form); a Host/CSRF failure is 403.
//
// Wire contract (PHASE_B §3): response DTOs are defined HERE with camelCase JSON
// tags (the store types carry no JSON tags). EncodeSnapshot is the shared
// snapshot encoder the SSE hub uses for its frames, so REST and SSE emit the
// identical Snapshot shape.
package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lifeart/tsctl/internal/store"
)

// WhoIser identifies the tailnet peer behind a request. Implemented by
// *netmap.Mapper. login is the peer's owner login; tagged is true for tagged
// (non-user) nodes; err != nil MUST be treated as deny (fail-closed).
type WhoIser interface {
	WhoIs(ctx context.Context, remoteAddr string) (login string, tagged bool, err error)
}

// Controller performs the actual exit-node mutation: the dead-man's-switch
// sequence on the router, then reconcile + broadcast (DESIGN §8). Implemented by
// *poller.Poller. Declared here (consumer side) so api never imports poller.
// targetStableID == "" clears the exit node; it returns the reconciled
// RouterView (the device's ACTUAL state, never optimistic).
type Controller interface {
	SetExitNode(ctx context.Context, routerID, targetStableID string) (store.RouterView, error)
}

// Config carries the security configuration the middleware needs (wired from
// cmd/tsctl). Owner is the tailnet login allowed to control (may be "" when only
// the password path is used); UIPassword is the shared secret for the
// host-socket/session path ("" disables password login). AllowedHosts is the
// Host-header allowlist (tsnet hostname / MagicDNS FQDN / 100.x / listen host)
// used for DNS-rebinding defense.
type Config struct {
	Owner        string
	UIPassword   string
	AllowedHosts []string
}

// API holds the handler dependencies.
type API struct {
	store         *store.Store
	whois         WhoIser
	ctrl          Controller
	owner         string
	uiPassword    string
	sessionSecret []byte              // HMAC key for signed session cookies (per-process)
	allowedHosts  map[string]struct{} // normalized (lowercase, port-stripped)
}

// New constructs the API. cfg.Owner enables the tailnet auth path in RequireAuth;
// cfg.UIPassword enables the password/session path; cfg.AllowedHosts gates Host
// pinning in RequireHost.
//
// A random 32-byte session secret is generated here (crypto/rand): it never
// leaves the process, so a restart invalidates all outstanding sessions (an
// acceptable, documented trade-off -- users simply sign in again). A crypto/rand
// failure means the OS CSPRNG is broken; we panic rather than run with a
// predictable secret (loud, never swallowed).
func New(st *store.Store, who WhoIser, ctrl Controller, cfg Config) *API {
	allowed := make(map[string]struct{}, len(cfg.AllowedHosts))
	for _, h := range cfg.AllowedHosts {
		if n := normalizeHost(h); n != "" {
			allowed[n] = struct{}{}
		}
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("api: generating session secret: " + err.Error())
	}
	return &API{
		store:         st,
		whois:         who,
		ctrl:          ctrl,
		owner:         cfg.Owner,
		uiPassword:    cfg.UIPassword,
		sessionSecret: secret,
		allowedHosts:  allowed,
	}
}

// Routes returns the /api/* handler. The outer layers run on EVERY request:
// RequireHost (host-pinned -- a DNS-rebinding page can't even read the Snapshot,
// DESIGN §7) then RequireCSRF (a no-op for GET/HEAD; enforces double-submit +
// Origin on every state change, including login/logout).
//
// Mount order so the SPA can BOOTSTRAP without a session: /api/csrf, /api/login
// and /api/logout are reachable WITHOUT RequireAuth (they only need Host + CSRF),
// while the data routes (/api/nodes, /api/routers/{id}, .../exit-node) sit behind
// RequireAuth. (GET /api/events is mounted separately by main and wrapped in
// RequireAuth(RequireHost(...)).)
func (a *API) Routes() http.Handler {
	// Data routes: require an authenticated caller (tailnet owner OR session).
	data := http.NewServeMux()
	data.HandleFunc("GET /api/nodes", a.handleNodes)
	data.HandleFunc("GET /api/routers/{id}", a.handleRouter)
	data.HandleFunc("POST /api/routers/{id}/exit-node", a.handleSetExitNode)

	mux := http.NewServeMux()
	// Bootstrap endpoints (no session required; still Host-pinned + CSRF-checked):
	mux.HandleFunc("GET /api/csrf", a.handleCSRF)
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/logout", a.handleLogout)
	// Everything else under /api/ requires authentication.
	mux.Handle("/api/", a.RequireAuth(data))

	return a.RequireHost(a.RequireCSRF(mux))
}

// RequireHost pins the Host header to the configured allowlist on EVERY request
// regardless of method (DESIGN §7 / PHASE_B §7 step 3). GET reads and the SSE
// stream are host-checked here exactly once; the write-only double-submit /
// Origin / Sec-Fetch-Site checks stay in RequireCSRF. 403 on a Host outside the
// allowlist (rejects DNS rebinding before any data is read or mutated).
func (a *API) RequireHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.hostAllowed(r.Host) {
			writeErr(w, http.StatusForbidden, "bad Host header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Session cookie parameters. The value is base64(expiry||nonce||HMAC); see
// newSessionValue / validSession. HttpOnly (JS never needs it), SameSite=Strict,
// Path=/, Secure=false (the listeners are plain HTTP -- WireGuard encrypts the
// tailnet transport, and the host-socket path is documented as plain HTTP).
const (
	sessionCookieName = "tsctl_session"
	sessionTTL        = 7 * 24 * time.Hour
	sessionExpiryLen  = 8  // int64 unix seconds, big-endian
	sessionNonceLen   = 16 // random, makes each cookie unique
	sessionMACLen     = 32 // HMAC-SHA256
	sessionRawLen     = sessionExpiryLen + sessionNonceLen + sessionMACLen
)

// loginFailDelay is a small fixed delay applied to a wrong-password login to
// blunt online brute force. A var so tests can shorten it.
var loginFailDelay = 500 * time.Millisecond

// RequireAuth admits a request when EITHER auth path succeeds, else replies 401
// (the SPA shows the login form). It is used on BOTH listeners (tailnet + host
// socket) and gates the data routes + the SSE stream.
//
//   - tailnet path: owner configured AND WhoIs identifies the peer as that owner,
//     untagged. Fail-closed: any WhoIs error, a tagged peer, an empty or
//     non-owner login does NOT grant -- it falls through to the session check.
//   - password path: a valid signed tsctl_session cookie (HMAC + not expired).
//
// 401 means "authenticate" (reserve 403 for Host/CSRF failures, which are about
// WHICH page asked, not WHO).
func (a *API) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.authenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		writeErr(w, http.StatusUnauthorized, "login required")
	})
}

// authenticated reports whether the request satisfies either auth path. Tailnet
// (WhoIs==owner) is tried first; on any failure it falls through to the session
// cookie -- never granting on a WhoIs error (fail-closed).
func (a *API) authenticated(r *http.Request) bool {
	if a.owner != "" {
		login, tagged, err := a.whois.WhoIs(r.Context(), r.RemoteAddr)
		if err == nil && !tagged && login != "" && login == a.owner {
			return true
		}
	}
	return a.validSession(r)
}

// newSessionValue mints a signed session cookie value valid for sessionTTL:
// base64url(expiryUnix(8) || nonce(16) || HMAC-SHA256(secret, expiry||nonce)).
func (a *API) newSessionValue() (string, error) {
	raw := make([]byte, sessionRawLen)
	binary.BigEndian.PutUint64(raw[:sessionExpiryLen], uint64(time.Now().Add(sessionTTL).Unix()))
	if _, err := rand.Read(raw[sessionExpiryLen : sessionExpiryLen+sessionNonceLen]); err != nil {
		return "", err
	}
	mac := a.sessionMAC(raw[:sessionExpiryLen+sessionNonceLen])
	copy(raw[sessionExpiryLen+sessionNonceLen:], mac)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// sessionMAC is HMAC-SHA256(secret, signed) over the expiry||nonce prefix.
func (a *API) sessionMAC(signed []byte) []byte {
	mac := hmac.New(sha256.New, a.sessionSecret)
	mac.Write(signed)
	return mac.Sum(nil)
}

// validSession constant-time-verifies the tsctl_session cookie's HMAC and that
// it has not expired. Any decode/length/MAC/expiry problem → false (fail-closed).
func (a *API) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != sessionRawLen {
		return false
	}
	signed := raw[:sessionExpiryLen+sessionNonceLen]
	mac := raw[sessionExpiryLen+sessionNonceLen:]
	if subtle.ConstantTimeCompare(mac, a.sessionMAC(signed)) != 1 {
		return false
	}
	expiry := int64(binary.BigEndian.Uint64(signed[:sessionExpiryLen]))
	return time.Now().Unix() < expiry
}

// handleLogin authenticates the password path. It is mounted WITHOUT RequireAuth
// (so the SPA can sign in) but WITH RequireHost + RequireCSRF. On a correct
// password it sets the signed session cookie and returns 200 {"ok":true}; on a
// wrong password it waits loginFailDelay then returns 401. If password login is
// disabled (no UIPassword) the endpoint does not exist (404). The password and
// the cookie value are NEVER logged.
func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	if a.uiPassword == "" {
		writeErr(w, http.StatusNotFound, "password login is disabled")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeErrDetail(w, http.StatusBadRequest, "invalid request body", err.Error(), "")
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.Password), []byte(a.uiPassword)) != 1 {
		time.Sleep(loginFailDelay) // blunt brute force; never log the attempt
		writeErr(w, http.StatusUnauthorized, "invalid password")
		return
	}
	val, err := a.newSessionValue()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    val,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
		Secure:   false,
		Expires:  time.Now().Add(sessionTTL),
		MaxAge:   int(sessionTTL / time.Second),
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleLogout clears the session cookie. Mounted WITHOUT RequireAuth but WITH
// RequireHost + RequireCSRF (so a cross-origin page can't force a logout).
func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
		Secure:   false,
		MaxAge:   -1, // delete now
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// RequireCSRF guards every non-GET/HEAD (state-changing) request with, in order
// (DESIGN §7). Host pinning is NOT here -- it is enforced for EVERY request,
// reads included, by RequireHost; this middleware owns only the write-side checks:
//  1. Origin check   -- if present, its host must equal r.Host;
//  2. Sec-Fetch-Site -- if present, must be same-origin or none;
//  3. double-submit  -- X-Tsctl-CSRF header present AND equal to the tsctl_csrf
//     cookie (simple cross-origin requests can set neither).
func (a *API) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(normalizeHost(u.Host), normalizeHost(r.Host)) {
				writeErr(w, http.StatusForbidden, "bad Origin")
				return
			}
		}
		if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
			writeErr(w, http.StatusForbidden, "cross-site request blocked")
			return
		}
		hdr := r.Header.Get("X-Tsctl-CSRF")
		cookie, err := r.Cookie("tsctl_csrf")
		if hdr == "" || err != nil || cookie.Value == "" ||
			subtle.ConstantTimeCompare([]byte(hdr), []byte(cookie.Value)) != 1 {
			writeErr(w, http.StatusForbidden, "invalid CSRF token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleCSRF issues a random token and sets the double-submit cookie. The cookie
// is NOT HttpOnly (the page's JS must read it to echo it in the header) and is
// SameSite=Strict, Path=/. Not Secure: the tailnet listener is plain HTTP
// (WireGuard already encrypts the transport; there is no TLS in v1).
func (a *API) handleCSRF(w http.ResponseWriter, r *http.Request) {
	tok, err := randomToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate CSRF token")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "tsctl_csrf",
		Value:    tok,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: false,
		Secure:   false,
	})
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

// handleNodes serves the first-paint / no-SSE fallback: {nodes, builtAt, netmapErr}.
func (a *API) handleNodes(w http.ResponseWriter, r *http.Request) {
	snap := a.store.Load()
	writeJSON(w, http.StatusOK, NodesResponse{
		Nodes:     nodeDTOs(snap.Nodes),
		BuiltAt:   rfc3339(snap.BuiltAt),
		NetmapErr: snap.NetmapErr,
	})
}

// handleRouter returns one RouterView by router StableID.
func (a *API) handleRouter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	snap := a.store.Load()
	for _, rv := range snap.Routers {
		if rv.Node.StableID == id {
			writeJSON(w, http.StatusOK, routerViewDTO(rv))
			return
		}
	}
	writeErrDetail(w, http.StatusNotFound, "router not found", "no router with id "+id, "")
}

// handleSetExitNode parses {"exitNode":"<stableID>"|""} ({} or "" = clear),
// drives the controller, and returns the reconciled RouterView (200) or a
// {error,detail,stderr} body with the appropriate 4xx/5xx status.
func (a *API) handleSetExitNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		ExitNode string `json:"exitNode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeErrDetail(w, http.StatusBadRequest, "invalid request body", err.Error(), "")
		return
	}
	rv, err := a.ctrl.SetExitNode(r.Context(), id, body.ExitNode)
	if err != nil {
		// Default to 502 (the router/SSH layer failed). Structural interfaces let
		// the controller pin a status / detail / stderr without coupling api to
		// the poller's concrete error type.
		status := http.StatusBadGateway
		detail := ""
		stderr := ""
		var hs interface{ HTTPStatus() int }
		if errors.As(err, &hs) {
			status = hs.HTTPStatus()
		}
		var de interface{ Detail() string }
		if errors.As(err, &de) {
			detail = de.Detail()
		}
		var se interface{ Stderr() string }
		if errors.As(err, &se) {
			stderr = se.Stderr()
		}
		writeErrDetail(w, status, err.Error(), detail, stderr)
		return
	}
	writeJSON(w, http.StatusOK, routerViewDTO(rv))
}

// --- DTOs (PHASE_B §3, camelCase) ---------------------------------------------

// NodeDTO is the wire shape of a store.NodeView.
type NodeDTO struct {
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

// ExitNodeRefDTO is the wire shape of a *store.ExitNodeRef (null when none).
type ExitNodeRefDTO struct {
	StableID string `json:"stableID"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
}

// RouterStatsDTO is the wire shape of store.RouterStats.
type RouterStatsDTO struct {
	RxBytes       int64  `json:"rxBytes"`
	TxBytes       int64  `json:"txBytes"`
	LastHandshake string `json:"lastHandshake"`
}

// RouterViewDTO is the wire shape of a store.RouterView.
type RouterViewDTO struct {
	Node            NodeDTO         `json:"node"`
	CurrentExitNode *ExitNodeRefDTO `json:"currentExitNode"`
	Desired         *ExitNodeRefDTO `json:"desired"`
	State           string          `json:"state"`
	Stats           RouterStatsDTO  `json:"stats"`
	Reachable       bool            `json:"reachable"`
	LastError       string          `json:"lastError"`
	LastConfirmedAt string          `json:"lastConfirmedAt"`
}

// SnapshotDTO is the wire shape of a *store.Snapshot (SSE frames + seam test).
type SnapshotDTO struct {
	Nodes     []NodeDTO       `json:"nodes"`
	Routers   []RouterViewDTO `json:"routers"`
	NetmapAt  string          `json:"netmapAt"`
	NetmapErr string          `json:"netmapErr"`
	BuiltAt   string          `json:"builtAt"`
}

// NodesResponse is the GET /api/nodes body.
type NodesResponse struct {
	Nodes     []NodeDTO `json:"nodes"`
	BuiltAt   string    `json:"builtAt"`
	NetmapErr string    `json:"netmapErr"`
}

func nodeDTO(n store.NodeView) NodeDTO {
	ips := n.TailscaleIPs
	if ips == nil {
		ips = []string{}
	}
	tags := n.Tags
	if tags == nil {
		tags = []string{}
	}
	return NodeDTO{
		StableID:       n.StableID,
		Name:           n.Name,
		Hostname:       n.Hostname,
		TailscaleIPs:   ips,
		OS:             n.OS,
		Online:         n.Online,
		LastSeen:       rfc3339(n.LastSeen),
		ExitNodeOption: n.ExitNodeOption,
		Tags:           tags,
		Type:           string(n.Type),
	}
}

func nodeDTOs(ns []store.NodeView) []NodeDTO {
	out := make([]NodeDTO, 0, len(ns))
	for _, n := range ns {
		out = append(out, nodeDTO(n))
	}
	return out
}

func exitRefDTO(r *store.ExitNodeRef) *ExitNodeRefDTO {
	if r == nil {
		return nil
	}
	return &ExitNodeRefDTO{StableID: r.StableID, Name: r.Name, IP: r.IP}
}

func routerViewDTO(rv store.RouterView) RouterViewDTO {
	return RouterViewDTO{
		Node:            nodeDTO(rv.Node),
		CurrentExitNode: exitRefDTO(rv.CurrentExitNode),
		Desired:         exitRefDTO(rv.Desired),
		State:           string(rv.State),
		Stats: RouterStatsDTO{
			RxBytes:       rv.Stats.RxBytes,
			TxBytes:       rv.Stats.TxBytes,
			LastHandshake: rfc3339(rv.Stats.LastHandshake),
		},
		Reachable:       rv.Reachable,
		LastError:       rv.LastError,
		LastConfirmedAt: rfc3339(rv.LastConfirmedAt),
	}
}

func snapshotDTO(s *store.Snapshot) SnapshotDTO {
	routers := make([]RouterViewDTO, 0, len(s.Routers))
	for _, rv := range s.Routers {
		routers = append(routers, routerViewDTO(rv))
	}
	return SnapshotDTO{
		Nodes:     nodeDTOs(s.Nodes),
		Routers:   routers,
		NetmapAt:  rfc3339(s.NetmapAt),
		NetmapErr: s.NetmapErr,
		BuiltAt:   rfc3339(s.BuiltAt),
	}
}

// EncodeSnapshot marshals a Snapshot into its wire JSON. The SSE hub uses it for
// frame bodies so REST and SSE emit the identical Snapshot shape (PHASE_B §3).
func EncodeSnapshot(s *store.Snapshot) ([]byte, error) {
	return json.Marshal(snapshotDTO(s))
}

// --- helpers ------------------------------------------------------------------

// rfc3339 renders t as RFC3339 UTC, or "" for the zero time (i.e. "never").
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// normalizeHost lowercases, strips any port, and removes IPv6 brackets.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.Trim(h, "[]")
}

func (a *API) hostAllowed(host string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	_, ok := a.allowedHosts[h]
	return ok
}

// randomToken returns 32 bytes of crypto-random hex.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// writeJSON encodes v as JSON with the given status. A post-header encode error
// cannot be returned to the client, so it is logged -- never swallowed.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("api: encode response: %v", err)
	}
}

// writeErr emits {"error":msg} with the given status (middleware / simple errors).
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeErrDetail emits the {error,detail,stderr} shape from PHASE_B §3.
func writeErrDetail(w http.ResponseWriter, status int, errMsg, detail, stderr string) {
	writeJSON(w, status, map[string]string{
		"error":  errMsg,
		"detail": detail,
		"stderr": stderr,
	})
}
