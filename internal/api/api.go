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

	"github.com/lifeart/tsctl/internal/authz"
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
	// Keep writes the keep-marker for a router AWAITING an explicit Keep (docs/design/
	// keep-egress.md stage 2), cancelling the armed revert and reconciling to ok. It
	// returns the reconciled RouterView, or a structural control error (404 unknown,
	// 409 no/elapsed/superseded pending keep, 502 router failure).
	Keep(ctx context.Context, routerID string) (store.RouterView, error)
	// Probe runs a read-only SSH diagnostic against the router. An SSH failure is
	// a RESULT (ProbeResult.OK=false), not an error; only a router-not-found (or
	// similar) returns a non-nil error (mapped to its HTTP status).
	Probe(ctx context.Context, routerID string) (store.ProbeResult, error)
	// RefreshGroups re-renders the snapshot's zone (group) view from the live store
	// and broadcasts it, so a group create/edit/delete is reflected immediately
	// (no router SSH). The api calls it after every successful group mutation.
	RefreshGroups()
}

// GroupStore is the CRUD seam for zone/group definitions (DESIGN
// docs/design/zones.md). Implemented by *groups.Store. Declared here (consumer
// side) so the api never imports the groups package; a validation/not-found
// error is surfaced via the same structural HTTPStatus()/Detail() interfaces the
// Controller uses, so the api stays decoupled from the concrete error type.
type GroupStore interface {
	List() []store.Group
	Get(id string) (store.Group, bool)
	Create(g store.Group) (store.Group, error)
	Update(id string, g store.Group) (store.Group, error)
	Delete(id string) error
}

// GuestStore is the CRUD + authentication seam for "guest mode" credentials.
// Implemented by *guests.Store. Declared here (consumer side) so the api never
// imports the guests package; the bcrypt hash is encapsulated there and NEVER
// crosses this interface -- every method returns the hash-free store.Guest.
// Authenticate verifies a (label,password) and returns the guest on success
// (false on unknown label / wrong password / disabled). The api re-loads a guest
// via Get on EVERY request so a delete/disable revokes access on the next call.
type GuestStore interface {
	List() []store.Guest
	Get(id string) (store.Guest, bool)
	Create(label, zoneID, pw string) (store.Guest, error)
	SetDisabled(id string, disabled bool) (store.Guest, error)
	Delete(id string) error
	Authenticate(label, pw string) (store.Guest, bool)
}

// Config carries the security configuration the middleware needs (wired from
// cmd/tsctl). Owner is the tailnet login allowed to control (may be "" when only
// the password path is used); UIPassword is the shared secret for the
// host-socket/session path ("" disables password login). AllowedHosts is the
// Host-header allowlist (tsnet hostname / MagicDNS FQDN / 100.x / listen host)
// used for DNS-rebinding defense. Groups is the zone CRUD store (may be nil when
// no group routes are exercised, e.g. in narrow unit tests).
type Config struct {
	Owner        string
	UIPassword   string
	AllowedHosts []string
	Groups       GroupStore
	// Guests is the optional guest-credential store (may be nil -- when nil the
	// guest CRUD routes are not registered and only the admin auth path exists, so
	// behavior is byte-for-byte as before guest mode).
	Guests GuestStore
}

// API holds the handler dependencies.
type API struct {
	store         *store.Store
	whois         WhoIser
	ctrl          Controller
	groups        GroupStore
	guests        GuestStore
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
		groups:        cfg.Groups,
		guests:        cfg.Guests,
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
	// RequireAuth (wrapping the whole `data` mux below) injects the resolved
	// Subject into the context, so the per-request handlers and RequireAdmin can
	// read it. The router write/probe handlers ADDITIONALLY call
	// authorizeRouterWrite (the server-side authorization choke point) so a guest
	// can only act within its own zone.
	data := http.NewServeMux()
	data.HandleFunc("GET /api/nodes", a.handleNodes)
	data.HandleFunc("GET /api/routers/{id}", a.handleRouter)
	data.HandleFunc("POST /api/routers/{id}/exit-node", a.handleSetExitNode)
	// Explicit-Keep gate (docs/design/keep-egress.md stage 2). Same data mux ->
	// identical middleware (RequireAuth here + RequireHost + RequireCSRF outer) as
	// exit-node: a state-changing POST that needs auth + a valid CSRF token + Host.
	data.HandleFunc("POST /api/routers/{id}/keep", a.handleKeep)
	// Read-only "test SSH + get router stats" probe. Registered on the SAME data
	// mux as exit-node, so it inherits the identical middleware stack: RequireAuth
	// (here) + RequireHost + RequireCSRF (outer) -- a state-changing POST requires
	// auth + a valid CSRF token + an allowed Host, exactly like exit-node.
	data.HandleFunc("POST /api/routers/{id}/probe", a.handleProbe)
	// Who am I: role + (for a guest) the bound zone. Behind RequireAuth only (a
	// guest must be able to read its own role/zone); not admin-gated.
	data.HandleFunc("GET /api/me", a.handleMe)
	// Zone/group CRUD (DESIGN docs/design/zones.md). ADMIN ONLY: wrapped in
	// RequireAdmin so a guest gets 403, not zone-management power. Same outer
	// middleware as the data routes (RequireAuth + RequireHost + RequireCSRF).
	// Registered only when a group store is wired (it's optional in narrow unit
	// tests); otherwise the routes 404 instead of nil-panicking in the handlers.
	if a.groups != nil {
		data.Handle("GET /api/groups", a.RequireAdmin(http.HandlerFunc(a.handleListGroups)))
		data.Handle("POST /api/groups", a.RequireAdmin(http.HandlerFunc(a.handleCreateGroup)))
		data.Handle("PUT /api/groups/{id}", a.RequireAdmin(http.HandlerFunc(a.handleUpdateGroup)))
		data.Handle("DELETE /api/groups/{id}", a.RequireAdmin(http.HandlerFunc(a.handleDeleteGroup)))
	}
	// Guest CRUD (guest mode). ADMIN ONLY (RequireAdmin). Registered only when a
	// guest store is wired; the list/create DTOs never carry the password hash.
	if a.guests != nil {
		data.Handle("GET /api/guests", a.RequireAdmin(http.HandlerFunc(a.handleListGuests)))
		data.Handle("POST /api/guests", a.RequireAdmin(http.HandlerFunc(a.handleCreateGuest)))
		data.Handle("POST /api/guests/{id}/disabled", a.RequireAdmin(http.HandlerFunc(a.handleSetGuestDisabled)))
		data.Handle("DELETE /api/guests/{id}", a.RequireAdmin(http.HandlerFunc(a.handleDeleteGuest)))
	}

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

// Session cookie parameters. The value is base64url(SIGNED || HMAC) where the
// SIGNED region is expiry(8) || nonce(16) || role(1) || guestIDLen(1) ||
// guestID(N) and the HMAC-SHA256 covers ALL of SIGNED (so the role + guest id are
// unforgeable -- a tampered role fails the constant-time MAC). See
// newSessionValue / parseSession. HttpOnly (JS never needs it), SameSite=Strict,
// Path=/, Secure=false (the listeners are plain HTTP -- WireGuard encrypts the
// tailnet transport, and the host-socket path is documented as plain HTTP).
const (
	sessionCookieName = "tsctl_session"
	sessionTTL        = 7 * 24 * time.Hour
	sessionExpiryLen  = 8  // int64 unix seconds, big-endian
	sessionNonceLen   = 16 // random, makes each cookie unique
	sessionRoleLen    = 1  // role byte (see roleAdmin/roleGuest)
	sessionGIDLenLen  = 1  // length-prefix byte for the guest id
	sessionMACLen     = 32 // HMAC-SHA256
	// sessionHeaderLen is the fixed-size prefix of the SIGNED region before the
	// variable-length guest id (admin: guestIDLen=0, no guest id bytes follow).
	sessionHeaderLen = sessionExpiryLen + sessionNonceLen + sessionRoleLen + sessionGIDLenLen
)

// Session roles encoded in the cookie's signed region (1 byte). The session can
// only ASSERT admin via a valid MAC over role==roleAdmin; the tailnet-owner admin
// path is WhoIs-only and is never expressed through the cookie, so a guest cookie
// can never escalate by being presented on the tailnet listener.
const (
	roleAdmin byte = 0
	roleGuest byte = 1
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
		sub, ok := a.resolveSubject(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "login required")
			return
		}
		// Inject the Subject + a revalidation closure. The closure re-runs the full
		// auth resolution for THIS request on demand; the sse hub calls it on its
		// heartbeat so a guest's long-lived event stream is dropped within one ping
		// interval after the guest is disabled/deleted (REST writes already revoke
		// instantly via resolveSubject). Cheap for admin; a guest re-check is two
		// in-memory store lookups.
		ctx := authz.WithSubject(r.Context(), sub)
		ctx = authz.WithRevalidate(ctx, func() bool { _, ok := a.resolveSubject(r); return ok })
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin gates a handler to the full-access admin role. It MUST sit inside
// RequireAuth (which injects the Subject); a missing subject or a guest subject is
// 403 ("admin only" -- the resource exists, the caller just isn't allowed; 401 is
// reserved for "authenticate"). This is the second authorization choke point: it
// guards all zone/group CRUD and all guest CRUD.
func (a *API) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub, ok := authz.SubjectFromContext(r.Context())
		if !ok || !sub.Admin {
			writeErr(w, http.StatusForbidden, "admin only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// resolveSubject authenticates a request and returns the authorized Subject.
// Order (fail-closed throughout):
//
//   - tailnet owner first: WhoIs identifies the untagged configured owner -> admin
//     (the tailnet admin is WhoIs-only and never cookie-assertable);
//   - else the signed session cookie: an admin cookie -> admin; a guest cookie is
//     re-validated against the LIVE stores on EVERY request -- the guest must still
//     exist, not be disabled, and its zone must still exist -- which makes a
//     delete/disable/zone-delete revoke access on the very next request (no TTL).
//
// On any failure ok=false (the caller replies 401).
func (a *API) resolveSubject(r *http.Request) (authz.Subject, bool) {
	if a.owner != "" {
		login, tagged, err := a.whois.WhoIs(r.Context(), r.RemoteAddr)
		if err == nil && !tagged && login != "" && login == a.owner {
			return authz.Subject{Admin: true}, true
		}
	}
	sub, ok := a.parseSession(r)
	if !ok {
		return authz.Subject{}, false
	}
	if sub.Admin {
		return sub, true
	}
	// Guest cookie: re-load from the live store (instant revocation + live zone
	// binding). Deny if the guest store is absent, the guest is gone or disabled,
	// or its bound zone no longer exists.
	if a.guests == nil {
		return authz.Subject{}, false
	}
	g, ok := a.guests.Get(sub.GuestID)
	if !ok || g.Disabled {
		return authz.Subject{}, false
	}
	if a.groups == nil {
		return authz.Subject{}, false
	}
	if _, ok := a.groups.Get(g.ZoneID); !ok {
		return authz.Subject{}, false // zone deleted out from under the guest
	}
	return authz.Subject{GuestID: g.ID, ZoneID: g.ZoneID}, true
}

// newSessionValue mints a signed session cookie value valid for sessionTTL for
// the given Subject. Layout (see the session const block): base64url(expiry(8) ||
// nonce(16) || role(1) || guestIDLen(1) || guestID(N) || HMAC-SHA256(secret, all
// preceding bytes)). Only Admin and GuestID are encoded; the zone is re-resolved
// per request, never trusted from the cookie.
func (a *API) newSessionValue(sub authz.Subject) (string, error) {
	role := roleAdmin
	var gid []byte
	if !sub.Admin {
		role = roleGuest
		gid = []byte(sub.GuestID)
	}
	if len(gid) > 255 {
		return "", errors.New("guest id too long for session cookie")
	}
	signedLen := sessionHeaderLen + len(gid)
	raw := make([]byte, signedLen+sessionMACLen)
	binary.BigEndian.PutUint64(raw[:sessionExpiryLen], uint64(time.Now().Add(sessionTTL).Unix()))
	if _, err := rand.Read(raw[sessionExpiryLen : sessionExpiryLen+sessionNonceLen]); err != nil {
		return "", err
	}
	raw[sessionExpiryLen+sessionNonceLen] = role
	raw[sessionExpiryLen+sessionNonceLen+sessionRoleLen] = byte(len(gid))
	copy(raw[sessionHeaderLen:signedLen], gid)
	mac := a.sessionMAC(raw[:signedLen])
	copy(raw[signedLen:], mac)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// sessionMAC is HMAC-SHA256(secret, signed) over the WHOLE signed region.
func (a *API) sessionMAC(signed []byte) []byte {
	mac := hmac.New(sha256.New, a.sessionSecret)
	mac.Write(signed)
	return mac.Sum(nil)
}

// parseSession constant-time-verifies the tsctl_session cookie's HMAC and expiry
// and returns the carried Subject (without resolving the zone -- resolveSubject
// does that against the live store). Any decode/length/MAC/expiry/role problem ->
// ok=false (fail-closed). The guestIDLen byte is read only to locate the MAC
// boundary; a tampered length yields a different signed region whose MAC fails.
func (a *API) parseSession(r *http.Request) (authz.Subject, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return authz.Subject{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) < sessionHeaderLen+sessionMACLen {
		return authz.Subject{}, false
	}
	gidLen := int(raw[sessionExpiryLen+sessionNonceLen+sessionRoleLen])
	signedLen := sessionHeaderLen + gidLen
	if len(raw) != signedLen+sessionMACLen {
		return authz.Subject{}, false
	}
	signed := raw[:signedLen]
	mac := raw[signedLen:]
	if subtle.ConstantTimeCompare(mac, a.sessionMAC(signed)) != 1 {
		return authz.Subject{}, false
	}
	expiry := int64(binary.BigEndian.Uint64(signed[:sessionExpiryLen]))
	if time.Now().Unix() >= expiry {
		return authz.Subject{}, false
	}
	role := signed[sessionExpiryLen+sessionNonceLen]
	switch role {
	case roleAdmin:
		if gidLen != 0 {
			return authz.Subject{}, false // admin carries no guest id
		}
		return authz.Subject{Admin: true}, true
	case roleGuest:
		if gidLen == 0 {
			return authz.Subject{}, false // guest must carry an id
		}
		return authz.Subject{GuestID: string(signed[sessionHeaderLen:signedLen])}, true
	default:
		return authz.Subject{}, false
	}
}

// handleLogin authenticates a login. It is mounted WITHOUT RequireAuth (so the
// SPA can sign in) but WITH RequireHost + RequireCSRF. The body is {label?,
// password}: an EMPTY label is the ADMIN path (constant-time compare vs the shared
// UIPassword); a non-empty label is the GUEST path (guests.Authenticate, which
// includes a dummy bcrypt compare on an unknown label for timing parity). On
// success it sets the signed session cookie carrying the resolved role/guest and
// returns 200 {"ok":true}; on failure it waits loginFailDelay then returns 401
// (a uniform message -- no admin-vs-guest oracle). If the admin path is requested
// while password login is disabled (no UIPassword) the endpoint reports 404, as
// before. The label, password, and cookie value are NEVER logged.
func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label    string `json:"label"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeErrDetail(w, http.StatusBadRequest, "invalid request body", err.Error(), "")
		return
	}

	var sub authz.Subject
	if strings.TrimSpace(body.Label) == "" {
		// Admin path (unchanged): empty label compares against the shared UI password.
		if a.uiPassword == "" {
			writeErr(w, http.StatusNotFound, "password login is disabled")
			return
		}
		if subtle.ConstantTimeCompare([]byte(body.Password), []byte(a.uiPassword)) != 1 {
			time.Sleep(loginFailDelay) // blunt brute force; never log the attempt
			writeErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		sub = authz.Subject{Admin: true}
	} else {
		// Guest path: one bcrypt verify per attempt (no fan-out). guests.Authenticate
		// rejects unknown label / wrong password / disabled with timing parity.
		if a.guests == nil {
			time.Sleep(loginFailDelay)
			writeErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		g, ok := a.guests.Authenticate(body.Label, body.Password)
		if !ok {
			time.Sleep(loginFailDelay)
			writeErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		sub = authz.Subject{GuestID: g.ID, ZoneID: g.ZoneID}
	}

	val, err := a.newSessionValue(sub)
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

// handleMe reports the caller's role and (for a guest) its bound zone. Behind
// RequireAuth, so the Subject is always present. Admin -> {role:"admin"} with an
// empty zone; guest -> {role:"guest", zoneId, zoneName} (the name resolved live
// from the group store). The shape always carries all three keys.
func (a *API) handleMe(w http.ResponseWriter, r *http.Request) {
	sub, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		// RequireAuth should make this unreachable; fail closed if it ever isn't.
		writeErr(w, http.StatusUnauthorized, "login required")
		return
	}
	if sub.Admin {
		writeJSON(w, http.StatusOK, MeResponse{Role: "admin"})
		return
	}
	zoneName := ""
	if a.groups != nil {
		if g, ok := a.groups.Get(sub.ZoneID); ok {
			zoneName = g.Name
		}
	}
	writeJSON(w, http.StatusOK, MeResponse{Role: "guest", ZoneID: sub.ZoneID, ZoneName: zoneName})
}

// handleNodes serves the first-paint / no-SSE fallback: {nodes, builtAt, netmapErr}.
// For a guest it returns the zone-filtered node set (defense-in-depth; writes are
// independently authorized); for an admin, the full set. A MISSING subject fails
// closed (401) -- this handler must run behind RequireAuth, which always injects one.
func (a *API) handleNodes(w http.ResponseWriter, r *http.Request) {
	sub, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "login required")
		return
	}
	snap := a.store.Load()
	if !sub.Admin {
		snap = authz.FilterSnapshotToZone(snap, sub.ZoneID)
	}
	writeJSON(w, http.StatusOK, NodesResponse{
		Nodes:     nodeDTOs(snap.Nodes),
		BuiltAt:   rfc3339(snap.BuiltAt),
		NetmapErr: snap.NetmapErr,
	})
}

// handleRouter returns one RouterView by router StableID. For a guest a router
// outside its zone is 404 -- the SAME response as a truly missing router, so it is
// not an oracle for which routers exist elsewhere on the fleet.
func (a *API) handleRouter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sub, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "login required") // fail-closed (must be behind RequireAuth)
		return
	}
	if !sub.Admin && !a.routerInZone(sub.ZoneID, id) {
		writeErrDetail(w, http.StatusNotFound, "router not found", "no router with id "+id, "")
		return
	}
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
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeErrDetail(w, http.StatusBadRequest, "invalid request body", err.Error(), "")
		return
	}
	// AUTHORIZATION CHOKE POINT (source of truth): a guest may only set an in-zone
	// router to an exit node in its OWN zone's allowed list (or clear it). Admin is
	// unrestricted here (the poller still enforces zones as a second layer).
	if !a.authorizeRouterWrite(w, r, id, body.ExitNode) {
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

// handleKeep confirms (keeps) a router awaiting an explicit Keep and returns the
// reconciled RouterView (200). There is no request body. It mirrors
// handleSetExitNode's structural status/detail/stderr error mapping: 404 unknown
// router, 409 no/elapsed/superseded pending keep, 502 router-command failure.
func (a *API) handleKeep(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// AUTHORIZATION CHOKE POINT: a guest may only Keep an in-zone router (no
	// target). Admin is unrestricted.
	if !a.authorizeRouterWrite(w, r, id, "") {
		return
	}
	rv, err := a.ctrl.Keep(r.Context(), id)
	if err != nil {
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

// handleProbe runs the read-only "test SSH" diagnostic for the router {id} and
// returns the ProbeResult as JSON (200). There is no request body. An SSH/command
// failure is a RESULT (ProbeResult.OK=false) returned with 200; only a control
// error (e.g. unknown router) maps to a 4xx via the SAME structural status/detail/
// stderr mapping as handleSetExitNode.
func (a *API) handleProbe(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// AUTHORIZATION CHOKE POINT: a guest may only probe an in-zone router (the
	// auto-resolve path). Admin is unrestricted.
	if !a.authorizeRouterWrite(w, r, id, "") {
		return
	}
	res, err := a.ctrl.Probe(r.Context(), id)
	if err != nil {
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
	// res IS the frozen wire shape (store.ProbeResult carries the JSON tags), so it
	// is written directly: {ok, durationMs, output?, error?, checkedAt}.
	writeJSON(w, http.StatusOK, res)
}

// --- guest authorization (the server-side source of truth) --------------------

// authorizeRouterWrite is the per-request authorization choke point for the
// router write/probe endpoints (exit-node, keep, probe). It returns true (allow)
// or writes a UNIFORM 403 and returns false.
//
//   - Admin: always allowed (the poller still enforces zones as a second layer).
//   - Guest: allowed only when routerID is a Consumer of the guest's OWN zone AND,
//     for a non-empty target, target is in that zone's AllowedExitNodes. Clearing
//     (target=="") needs only zone membership. The zone is read LIVE from the group
//     store (a.groups), deliberately STRICTER than the poller's cross-zone allowed
//     union (poller.allowedExitNodeSet) -- a guest is confined to its single zone.
//
// Every denial is an identical 403 with no detail: a guest cannot distinguish
// "not your router" from "not an allowed target" from "your zone is gone" (no
// oracle). Authorization here is INDEPENDENT of the snapshot filter, so a filter
// bug can never grant a write.
func (a *API) authorizeRouterWrite(w http.ResponseWriter, r *http.Request, routerID, target string) bool {
	sub, ok := authz.SubjectFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusForbidden, "forbidden")
		return false
	}
	if sub.Admin {
		return true
	}
	if a.groups == nil {
		writeErr(w, http.StatusForbidden, "forbidden")
		return false
	}
	g, ok := a.groups.Get(sub.ZoneID)
	if !ok {
		writeErr(w, http.StatusForbidden, "forbidden")
		return false
	}
	if !containsStr(g.Consumers, routerID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return false
	}
	if target != "" && !containsStr(g.AllowedExitNodes, target) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}

// routerInZone reports whether routerID is a Consumer of zoneID, read live from
// the group store. Used by handleRouter to 404 an out-of-zone router for a guest.
func (a *API) routerInZone(zoneID, routerID string) bool {
	if a.groups == nil {
		return false
	}
	g, ok := a.groups.Get(zoneID)
	if !ok {
		return false
	}
	return containsStr(g.Consumers, routerID)
}

// containsStr reports whether ss contains s.
func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// --- group (zone) CRUD handlers (DESIGN docs/design/zones.md) ------------------

// groupReqLimit caps a group request body (defense-in-depth; member lists are
// small StableID arrays).
const groupReqLimit = 1 << 16 // 64 KiB

// groupRequest is the POST/PUT body for a group write.
type groupRequest struct {
	Name             string   `json:"name"`
	Consumers        []string `json:"consumers"`
	AllowedExitNodes []string `json:"allowedExitNodes"`
}

// handleListGroups returns every RAW group as a JSON array (never null).
func (a *API) handleListGroups(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, groupDTOs(a.groups.List()))
}

// handleCreateGroup creates a group from {name,consumers,allowedExitNodes} and
// returns the created RAW group (201). Validation errors → 422 {error,detail}.
func (a *API) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeGroupBody(w, r)
	if !ok {
		return
	}
	g, err := a.groups.Create(store.Group{
		Name:             body.Name,
		Consumers:        body.Consumers,
		AllowedExitNodes: body.AllowedExitNodes,
	})
	if err != nil {
		writeGroupErr(w, err)
		return
	}
	a.ctrl.RefreshGroups() // re-render + broadcast so the new zone appears at once
	writeJSON(w, http.StatusCreated, groupDTO(g))
}

// handleUpdateGroup replaces the group at {id} and returns it (200). 404 if
// missing; validation errors → 422.
func (a *API) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	body, ok := decodeGroupBody(w, r)
	if !ok {
		return
	}
	g, err := a.groups.Update(id, store.Group{
		Name:             body.Name,
		Consumers:        body.Consumers,
		AllowedExitNodes: body.AllowedExitNodes,
	})
	if err != nil {
		writeGroupErr(w, err)
		return
	}
	a.ctrl.RefreshGroups() // re-render + broadcast so the edit appears at once
	writeJSON(w, http.StatusOK, groupDTO(g))
}

// handleDeleteGroup deletes the group at {id} (204). 404 if missing. A zone with
// a guest still assigned to it is 409 (delete/reassign the guest first) -- this
// guards against orphaning a guest (whose next request would otherwise 401 once
// its zone vanished); the revocation safety net still holds, but the 409 makes the
// dependency explicit to the admin.
func (a *API) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if a.guests != nil {
		for _, g := range a.guests.List() {
			if g.ZoneID == id {
				writeErrDetail(w, http.StatusConflict, "zone in use",
					"a guest is assigned to this zone; delete or reassign the guest first", "")
				return
			}
		}
	}
	if err := a.groups.Delete(id); err != nil {
		writeGroupErr(w, err)
		return
	}
	a.ctrl.RefreshGroups() // re-render + broadcast so the deletion appears at once
	w.WriteHeader(http.StatusNoContent)
}

// decodeGroupBody reads a JSON group request via a LimitReader. On a malformed
// body it writes a 400 {error,detail} and reports ok=false (a missing/empty body
// is allowed -- it decodes to the zero request, which validation then rejects).
func decodeGroupBody(w http.ResponseWriter, r *http.Request) (groupRequest, bool) {
	var body groupRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, groupReqLimit)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeErrDetail(w, http.StatusBadRequest, "invalid request body", err.Error(), "")
		return groupRequest{}, false
	}
	return body, true
}

// writeGroupErr maps a GroupStore error to its response. The status/detail are
// read structurally (HTTPStatus()/Detail()) so the api never imports the groups
// package -- 404 for a missing group, 422 for a validation failure; default 422.
func writeGroupErr(w http.ResponseWriter, err error) {
	status := http.StatusUnprocessableEntity
	if hs, ok := asHTTPStatus(err); ok {
		status = hs
	}
	detail := ""
	var de interface{ Detail() string }
	if errors.As(err, &de) {
		detail = de.Detail()
	}
	writeErrDetail(w, status, err.Error(), detail, "")
}

// asHTTPStatus extracts a structural HTTP status from an error chain.
func asHTTPStatus(err error) (int, bool) {
	var hs interface{ HTTPStatus() int }
	if errors.As(err, &hs) {
		return hs.HTTPStatus(), true
	}
	return 0, false
}

// --- guest (guest mode) CRUD handlers, ADMIN ONLY (RequireAdmin) ---------------

// guestReqLimit caps a guest request body (defense-in-depth).
const guestReqLimit = 1 << 14 // 16 KiB

// handleListGuests returns every guest as a JSON array (never null). The DTO has
// NO password-hash field -- the hash never leaves the guests package and never
// reaches the wire.
func (a *API) handleListGuests(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, guestDTOs(a.guests.List()))
}

// handleCreateGuest creates a guest from {label, zoneId, password} and returns
// the created guest (201, no hash). An unknown zoneId is rejected (422) -- a guest
// must be bound to a real zone. Validation errors (empty/duplicate label, weak
// password) are 422 {error,detail}. The password is NEVER logged.
func (a *API) handleCreateGuest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label    string `json:"label"`
		ZoneID   string `json:"zoneId"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, guestReqLimit)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeErrDetail(w, http.StatusBadRequest, "invalid request body", err.Error(), "")
		return
	}
	// The zone must exist (the group store is the source of truth). Reject before
	// hashing so an unknown zone never creates a credential.
	zoneID := strings.TrimSpace(body.ZoneID)
	if a.groups == nil {
		writeErrDetail(w, http.StatusUnprocessableEntity, "invalid guest", "no zones are configured", "")
		return
	}
	if _, ok := a.groups.Get(zoneID); !ok {
		writeErrDetail(w, http.StatusUnprocessableEntity, "invalid guest", "no zone with id "+body.ZoneID, "")
		return
	}
	g, err := a.guests.Create(body.Label, zoneID, body.Password)
	if err != nil {
		writeGroupErr(w, err) // same structural status/detail mapping as groups
		return
	}
	writeJSON(w, http.StatusCreated, guestDTO(g))
}

// handleSetGuestDisabled toggles a guest's disabled flag from {disabled:bool} and
// returns the updated guest (200). 404 if missing. Disabling revokes the guest on
// its very next request (the api re-loads the guest each request).
func (a *API) handleSetGuestDisabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Disabled bool `json:"disabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, guestReqLimit)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeErrDetail(w, http.StatusBadRequest, "invalid request body", err.Error(), "")
		return
	}
	g, err := a.guests.SetDisabled(r.PathValue("id"), body.Disabled)
	if err != nil {
		writeGroupErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, guestDTO(g))
}

// handleDeleteGuest deletes the guest at {id} (204). 404 if missing. Deletion
// revokes the guest on its very next request.
func (a *API) handleDeleteGuest(w http.ResponseWriter, r *http.Request) {
	if err := a.guests.Delete(r.PathValue("id")); err != nil {
		writeGroupErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	// RevertAt (rfc3339) is the armed-revert deadline; only meaningful (and only
	// emitted) while state == "awaiting-keep" (docs/design/keep-egress.md stage 2).
	RevertAt string `json:"revertAt,omitempty"`
	// Egress probe result (docs/design/keep-egress.md). egressOk is omitted when
	// nil (not checked / Direct); a non-nil pointer to false still serializes (✗).
	EgressOK        *bool  `json:"egressOk,omitempty"`
	EgressDetail    string `json:"egressDetail,omitempty"`
	EgressCheckedAt string `json:"egressCheckedAt,omitempty"`
}

// GroupDTO is the RAW wire shape of a store.Group (the /api/groups CRUD body).
type GroupDTO struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Consumers        []string `json:"consumers"`
	AllowedExitNodes []string `json:"allowedExitNodes"`
}

// GroupMemberDTO is the wire shape of a store.GroupMember (resolved member).
type GroupMemberDTO struct {
	StableID string `json:"stableID"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Online   bool   `json:"online"`
	Present  bool   `json:"present"`
}

// GroupViewDTO is the wire shape of a store.GroupView (resolved zone in the
// snapshot): the group plus its members resolved for rendering.
type GroupViewDTO struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Consumers        []GroupMemberDTO `json:"consumers"`
	AllowedExitNodes []GroupMemberDTO `json:"allowedExitNodes"`
}

// SnapshotDTO is the wire shape of a *store.Snapshot (SSE frames + seam test).
type SnapshotDTO struct {
	Nodes     []NodeDTO       `json:"nodes"`
	Routers   []RouterViewDTO `json:"routers"`
	Groups    []GroupViewDTO  `json:"groups"`
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

// MeResponse is the GET /api/me body: the caller's role and, for a guest, the
// bound zone. zoneId/zoneName are empty for an admin (the keys are always present
// so the shape is stable).
type MeResponse struct {
	Role     string `json:"role"`
	ZoneID   string `json:"zoneId"`
	ZoneName string `json:"zoneName"`
}

// GuestDTO is the wire shape of a store.Guest (the /api/guests CRUD body). It
// carries NO password hash -- the hash never leaves the guests package.
type GuestDTO struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	ZoneID    string `json:"zoneId"`
	Disabled  bool   `json:"disabled"`
	CreatedAt string `json:"createdAt"`
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
		RevertAt:        rfc3339(rv.RevertAt),
		EgressOK:        rv.EgressOK,
		EgressDetail:    rv.EgressDetail,
		EgressCheckedAt: rfc3339(rv.EgressCheckedAt),
	}
}

// groupDTO is the RAW wire shape of one store.Group (slices never null).
func groupDTO(g store.Group) GroupDTO {
	consumers := g.Consumers
	if consumers == nil {
		consumers = []string{}
	}
	allowed := g.AllowedExitNodes
	if allowed == nil {
		allowed = []string{}
	}
	return GroupDTO{
		ID:               g.ID,
		Name:             g.Name,
		Consumers:        consumers,
		AllowedExitNodes: allowed,
	}
}

func groupDTOs(gs []store.Group) []GroupDTO {
	out := make([]GroupDTO, 0, len(gs))
	for _, g := range gs {
		out = append(out, groupDTO(g))
	}
	return out
}

// guestDTO is the hash-free wire shape of one store.Guest.
func guestDTO(g store.Guest) GuestDTO {
	return GuestDTO{
		ID:        g.ID,
		Label:     g.Label,
		ZoneID:    g.ZoneID,
		Disabled:  g.Disabled,
		CreatedAt: rfc3339(g.CreatedAt),
	}
}

func guestDTOs(gs []store.Guest) []GuestDTO {
	out := make([]GuestDTO, 0, len(gs))
	for _, g := range gs {
		out = append(out, guestDTO(g))
	}
	return out
}

func groupMemberDTOs(ms []store.GroupMember) []GroupMemberDTO {
	out := make([]GroupMemberDTO, 0, len(ms))
	for _, m := range ms {
		out = append(out, GroupMemberDTO{
			StableID: m.StableID,
			Name:     m.Name,
			IP:       m.IP,
			Online:   m.Online,
			Present:  m.Present,
		})
	}
	return out
}

func groupViewDTOs(gvs []store.GroupView) []GroupViewDTO {
	out := make([]GroupViewDTO, 0, len(gvs))
	for _, gv := range gvs {
		out = append(out, GroupViewDTO{
			ID:               gv.ID,
			Name:             gv.Name,
			Consumers:        groupMemberDTOs(gv.Consumers),
			AllowedExitNodes: groupMemberDTOs(gv.AllowedExitNodes),
		})
	}
	return out
}

func snapshotDTO(s *store.Snapshot) SnapshotDTO {
	routers := make([]RouterViewDTO, 0, len(s.Routers))
	for _, rv := range s.Routers {
		routers = append(routers, routerViewDTO(rv))
	}
	return SnapshotDTO{
		Nodes:     nodeDTOs(s.Nodes),
		Routers:   routers,
		Groups:    groupViewDTOs(s.Groups),
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
