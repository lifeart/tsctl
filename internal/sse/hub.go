// Package sse is the server-sent-events hub: ONE goroutine owns the client set
// and communicates via register/unregister/broadcast channels -- no mutex over
// the map (DESIGN §6). Each client gets a cap-1, latest-wins channel so a slow
// browser can never backpressure the poller. Frames are full Snapshots; `: ping`
// heartbeats keep the stream alive. Phase B (the api+sse+poller agent) fills in
// the bodies.
package sse

import (
	"context"
	"errors"
	"net/http"

	"github.com/lifeart/tsctl/internal/store"
)

// Hub fans out Snapshot frames to connected browsers.
type Hub struct {
	// Phase B: register/unregister/broadcast chans + the client set, all owned
	// by the single Run goroutine.
}

// New constructs a Hub.
func New() *Hub { return &Hub{} }

// Run is the single owner goroutine. The scaffold blocks until ctx is cancelled
// by the composition root's ordered shutdown; Phase B adds the select loop over
// register/unregister/broadcast and the connected-client-count transitions.
func (h *Hub) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// Broadcast hands the latest full Snapshot to the hub for fan-out (cap-1,
// latest-wins per client). Phase B implements it.
func (h *Hub) Broadcast(snap *store.Snapshot) {
	// Phase B: send on the broadcast channel owned by Run.
	_ = snap
}

// ServeHTTP is the GET /api/events handler. Phase B sets text/event-stream,
// Cache-Control: no-cache, X-Accel-Buffering: no, WriteTimeout-free streaming
// (set on the http.Server), sends the current snapshot immediately, then loops
// on r.Context().Done() and the per-client channel. The scaffold returns an
// explicit 501 (never a silent stub -- DESIGN §7/§8).
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, errors.New("not implemented: sse.Hub.ServeHTTP").Error(), http.StatusNotImplemented)
}
