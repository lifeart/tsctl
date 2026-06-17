// Package api is the HTTP transport: handlers plus the fail-closed security
// middleware. It declares the WhoIser interface it consumes (DESIGN §4:
// interface at the consumer) and is injected with a concrete WhoIser
// (*netmap.Mapper) and the Store by the composition root.
//
// Security posture (DESIGN §7): every request is identified via WhoIs
// (fail-closed -- deny on ANY error, deny tagged/unknown, require login==owner),
// and every state-changing request additionally requires a valid X-Tsctl-CSRF
// header (double-submit cookie) plus Host pinning and Origin/Sec-Fetch-Site
// validation against an allowlist (DNS-rebinding defense).
//
// Wire contract (PHASE_B §3): response DTOs are defined HERE with camelCase JSON
// tags (the store types carry no JSON tags). EncodeSnapshot is the shared
// snapshot encoder the SSE hub uses for its frames, so REST and SSE emit the
// identical Snapshot shape.
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
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
// cmd/tsctl). Owner is the single tailnet login allowed to control; AllowedHosts
// is the Host-header allowlist (tsnet hostname / MagicDNS FQDN / 100.x / listen
// host) used for DNS-rebinding defense.
type Config struct {
	Owner        string
	AllowedHosts []string
}

// API holds the handler dependencies.
type API struct {
	store        *store.Store
	whois        WhoIser
	ctrl         Controller
	owner        string
	allowedHosts map[string]struct{} // normalized (lowercase, port-stripped)
}

// New constructs the API. cfg.Owner gates RequireOwner; cfg.AllowedHosts gates
// the Host pinning in RequireCSRF.
func New(st *store.Store, who WhoIser, ctrl Controller, cfg Config) *API {
	allowed := make(map[string]struct{}, len(cfg.AllowedHosts))
	for _, h := range cfg.AllowedHosts {
		if n := normalizeHost(h); n != "" {
			allowed[n] = struct{}{}
		}
	}
	return &API{store: st, whois: who, ctrl: ctrl, owner: cfg.Owner, allowedHosts: allowed}
}

// Routes returns the /api/* handler, wrapped fail-closed in the owner + CSRF
// middleware. Mount it at "/api/" in the composition root. (GET /api/events is
// mounted separately by main and wrapped in RequireOwner only.)
func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/csrf", a.handleCSRF)
	mux.HandleFunc("GET /api/nodes", a.handleNodes)
	mux.HandleFunc("GET /api/routers/{id}", a.handleRouter)
	mux.HandleFunc("POST /api/routers/{id}/exit-node", a.handleSetExitNode)
	return a.RequireOwner(a.RequireCSRF(mux))
}

// RequireOwner identifies the caller via WhoIs and fails closed: deny on any
// error, on a tagged peer, on an empty login, or on a login that is not the
// configured owner (DESIGN §7). An empty configured owner denies everyone.
func (a *API) RequireOwner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		login, tagged, err := a.whois.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil || tagged || login == "" || login != a.owner {
			writeErr(w, http.StatusForbidden, "Not authorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireCSRF guards every non-GET/HEAD request with, in order (DESIGN §7):
//  1. Host pinning   -- r.Host must be in the allowlist (rejects DNS rebinding);
//  2. Origin check   -- if present, its host must equal r.Host;
//  3. Sec-Fetch-Site -- if present, must be same-origin or none;
//  4. double-submit  -- X-Tsctl-CSRF header present AND equal to the tsctl_csrf
//     cookie (simple cross-origin requests can set neither).
func (a *API) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		if !a.hostAllowed(r.Host) {
			writeErr(w, http.StatusForbidden, "bad Host header")
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
