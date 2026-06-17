// Package api is the HTTP transport: handlers plus the fail-closed security
// middleware. It declares the WhoIser interface it consumes (DESIGN §4:
// interface at the consumer) and is injected with a concrete WhoIser
// (*netmap.Mapper) and the Store by the composition root.
//
// Security posture (DESIGN §7): every request is identified via WhoIs
// (fail-closed -- deny on ANY error, deny tagged/unknown), and every
// state-changing request additionally requires a valid X-Tsctl-CSRF header plus
// Host/Origin validation. The scaffold wires the middleware (so the seam and
// the fail-closed default are real) and returns explicit 501s from the handler
// bodies. Phase B fills in the real handlers and the Host/Origin checks.
package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/lifeart/tsctl/internal/store"
)

// WhoIser identifies the tailnet peer behind a request. Implemented by
// *netmap.Mapper. login is the peer's owner login; tagged is true for tagged
// (non-user) nodes; err != nil MUST be treated as deny (fail-closed).
type WhoIser interface {
	WhoIs(ctx context.Context, remoteAddr string) (login string, tagged bool, err error)
}

// API holds the handler dependencies.
type API struct {
	store *store.Store
	whois WhoIser
}

// New constructs the API.
func New(st *store.Store, who WhoIser) *API {
	return &API{store: st, whois: who}
}

// Routes returns the /api/* handler, wrapped fail-closed in the owner + CSRF
// middleware. Mount it at "/api/" in the composition root.
func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/nodes", a.handleNodes)
	mux.HandleFunc("GET /api/routers/{id}", a.handleRouter)
	mux.HandleFunc("POST /api/routers/{id}/exit-node", a.handleSetExitNode)
	return a.RequireOwner(a.RequireCSRF(mux))
}

// RequireOwner identifies the caller via WhoIs and fails closed: deny on any
// error, on a tagged peer, or on an empty login. Phase B adds the
// login==owner comparison.
func (a *API) RequireOwner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		login, tagged, err := a.whois.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil || tagged || login == "" {
			writeErr(w, http.StatusForbidden, "Not authorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireCSRF requires a non-empty X-Tsctl-CSRF header on state-changing
// requests (simple cross-origin requests cannot set custom headers). Phase B
// adds Host/Origin/Sec-Fetch-Site validation against the expected MagicDNS
// name / 100.x (DESIGN §7, DNS-rebinding defense).
func (a *API) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-Tsctl-CSRF") == "" {
				writeErr(w, http.StatusForbidden, "missing X-Tsctl-CSRF")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// GET /api/nodes -> {nodes, builtAt, netmapErr}
func (a *API) handleNodes(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusNotImplemented, "not implemented: api.nodes")
}

// GET /api/routers/{id} -> RouterView
func (a *API) handleRouter(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusNotImplemented, "not implemented: api.router")
}

// POST /api/routers/{id}/exit-node body {"exitNode":"<stableID>"|""}
func (a *API) handleSetExitNode(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusNotImplemented, "not implemented: api.setExitNode")
}

// writeErr emits a JSON error and the given status -- errors are surfaced to the
// client, never swallowed (DESIGN §8).
func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
