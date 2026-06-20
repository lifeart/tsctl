// Package sse is the server-sent-events hub: ONE goroutine (Run) owns the client
// set and communicates via register/unregister/broadcast channels -- no mutex
// over the map (DESIGN §6). Each client gets a cap-1, latest-wins channel so a
// slow browser can never backpressure the poller. Frames are full Snapshots;
// `: ping` heartbeats keep the stream alive.
//
// The hub also owns the connected-client COUNT and emits 0->1 / 1->0 transitions
// on the channel returned by Transitions(), which the poller consumes to suspend
// polling while idle (DESIGN §6).
package sse

import (
	"context"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/lifeart/tsctl/internal/authz"
	"github.com/lifeart/tsctl/internal/store"
)

// SnapshotEncoder marshals a Snapshot into a wire-format frame body. Injected by
// the composition root (api.EncodeSnapshot) so the hub stays decoupled from the
// wire contract / api package.
type SnapshotEncoder func(*store.Snapshot) ([]byte, error)

// client is one connected browser. ch is cap-1 latest-wins, written ONLY by the
// Run goroutine and drained by the client's ServeHTTP goroutine.
//
// filter, when non-nil, scopes each frame to a guest's zone before encoding. It
// runs in the per-client ServeHTTP goroutine (writeFrame), never in Run -- so Run
// keeps broadcasting the single shared snapshot (unchanged single-owner model)
// and the per-connection filtering adds zero work for admin clients (filter==nil).
type client struct {
	ch     chan *store.Snapshot
	filter func(*store.Snapshot) *store.Snapshot
}

// Hub fans out Snapshot frames to connected browsers.
type Hub struct {
	store        *store.Store
	encode       SnapshotEncoder
	register     chan *client
	unregister   chan *client
	broadcast    chan *store.Snapshot
	transitions  chan int      // 0->1 emits 1, 1->0 emits 0 (cap-1, latest-wins)
	done         chan struct{} // closed when Run returns (unblocks handlers)
	pingInterval time.Duration
	writeTimeout time.Duration // per-write deadline; detects half-open peers (M5)
}

// defaultWriteTimeout bounds a single frame/ping write. The server keeps
// WriteTimeout:0 (a server-wide deadline would silently kill long-lived SSE
// streams, DESIGN §2); instead each write gets a fresh deadline via
// http.ResponseController so a peer that vanished without a FIN is detected --
// the write errors, the handler returns, and the client is unregistered (so the
// poller's active count can reach 0). Without this such a connection blocks the
// write for minutes and stays registered (M5).
const defaultWriteTimeout = 10 * time.Second

// New constructs a Hub. st supplies the current snapshot sent on connect; encode
// produces frame bodies.
func New(st *store.Store, encode SnapshotEncoder) *Hub {
	return &Hub{
		store:        st,
		encode:       encode,
		register:     make(chan *client),
		unregister:   make(chan *client),
		broadcast:    make(chan *store.Snapshot, 1),
		transitions:  make(chan int, 1),
		done:         make(chan struct{}),
		pingInterval: 20 * time.Second,
		writeTimeout: defaultWriteTimeout,
	}
}

// Transitions returns the channel the poller consumes for client-count edge
// events: 1 on the first client (0->1), 0 on the last leaving (1->0).
func (h *Hub) Transitions() <-chan int { return h.transitions }

// Run is the single owner goroutine: it owns the client set and the count, and
// processes register/unregister/broadcast until ctx is cancelled.
func (h *Hub) Run(ctx context.Context) error {
	defer close(h.done)
	clients := make(map[*client]struct{})
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case c := <-h.register:
			clients[c] = struct{}{}
			if h.store != nil {
				h.send(c, h.store.Load()) // immediate current snapshot on connect
			}
			if len(clients) == 1 {
				h.emit(1)
			}
		case c := <-h.unregister:
			if _, ok := clients[c]; ok {
				delete(clients, c)
				if len(clients) == 0 {
					h.emit(0)
				}
			}
		case snap := <-h.broadcast:
			for c := range clients {
				h.send(c, snap)
			}
		}
	}
}

// send pushes snap onto a client's cap-1 channel, latest-wins. Non-blocking: the
// Run goroutine must never block on a slow client. Only Run sends on c.ch.
func (h *Hub) send(c *client, snap *store.Snapshot) {
	select {
	case c.ch <- snap:
		return
	default:
	}
	// Channel full: drop the stale frame, then put the latest.
	select {
	case <-c.ch:
	default:
	}
	select {
	case c.ch <- snap:
	default:
	}
}

// emit reports a count-edge to the poller, latest-wins so Run never blocks even
// if the poller is mid-refresh. The latest value is always the current truth.
func (h *Hub) emit(count int) {
	select {
	case h.transitions <- count:
		return
	default:
	}
	select {
	case <-h.transitions:
	default:
	}
	select {
	case h.transitions <- count:
	default:
	}
}

// Broadcast hands the latest full Snapshot to the hub for fan-out. Non-blocking
// + latest-wins so the poller is never backpressured by the hub.
func (h *Hub) Broadcast(snap *store.Snapshot) {
	select {
	case h.broadcast <- snap:
		return
	default:
	}
	select {
	case <-h.broadcast:
	default:
	}
	select {
	case h.broadcast <- snap:
	default:
	}
}

// ServeHTTP is GET /api/events. It registers, streams the current snapshot
// immediately (pushed by Run on register), then loops on the per-client channel
// and a heartbeat ticker, selecting on r.Context().Done() and the hub's done so
// it never leaks a goroutine on disconnect or shutdown.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering
	w.Header().Set("Connection", "keep-alive")

	rc := http.NewResponseController(w)
	c := &client{ch: make(chan *store.Snapshot, 1)}

	// A guest connection (Subject injected by RequireAuth, which wraps this hub in
	// main.go) gets a per-connection zone filter applied to every frame, including
	// the on-connect snapshot. Admin (or no subject) -> nil filter, zero overhead.
	// It also carries a revalidation hook: a streaming GET authenticates only once
	// at connect, so without this a disabled/deleted guest's open stream would keep
	// delivering its zone until the client disconnects. The heartbeat below re-checks
	// it, ending the stream within one ping interval (writes already revoke instantly).
	var revalidate authz.Revalidate
	if sub, ok := authz.SubjectFromContext(r.Context()); ok && !sub.Admin {
		zoneID := sub.ZoneID
		c.filter = func(s *store.Snapshot) *store.Snapshot {
			return authz.FilterSnapshotToZone(s, zoneID)
		}
		if fn, ok := authz.RevalidateFromContext(r.Context()); ok {
			revalidate = fn
		}
	}

	// Register (Run pushes the current snapshot into c.ch as it adds us).
	select {
	case h.register <- c:
	case <-h.done:
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	case <-r.Context().Done():
		return
	}
	defer func() {
		select {
		case h.unregister <- c:
		case <-h.done:
		}
	}()

	ping := time.NewTicker(h.pingInterval)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-h.done:
			return
		case snap := <-c.ch:
			if !h.writeFrame(w, rc, c, snap) {
				return
			}
		case <-ping.C:
			// Re-check a guest stream's authorization (disabled/deleted guest or
			// deleted zone -> drop the stream within one ping interval). Admin streams
			// have revalidate==nil and are unaffected.
			if revalidate != nil && !revalidate() {
				return
			}
			// Fresh per-write deadline (M5): a dead peer makes this write block
			// otherwise; with the deadline it errors and we return + unregister.
			if err := rc.SetWriteDeadline(time.Now().Add(h.writeTimeout)); err != nil {
				log.Printf("sse: set write deadline: %v", err)
				return
			}
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}
}

// writeFrame encodes and writes one `data: <json>\n\n` frame and flushes. It
// returns false (caller returns, unregisters) on any write/flush error. An
// encode failure is logged and the frame skipped (the stream survives). For a
// guest client (c.filter != nil) the shared snapshot is scoped to the guest's
// zone HERE, in the per-client goroutine, before encoding -- Run never sees the
// filtered copy and the shared snapshot is never mutated.
func (h *Hub) writeFrame(w http.ResponseWriter, rc *http.ResponseController, c *client, snap *store.Snapshot) bool {
	if c.filter != nil {
		snap = c.filter(snap)
	}
	data, err := h.encode(snap)
	if err != nil {
		log.Printf("sse: encode snapshot: %v", err)
		return true // skip this frame; keep the stream open
	}
	// Fresh per-write deadline (M5) so a vanished peer can't block this frame for
	// minutes; on a dead peer the writes below error and the caller unregisters.
	if err := rc.SetWriteDeadline(time.Now().Add(h.writeTimeout)); err != nil {
		log.Printf("sse: set write deadline: %v", err)
		return false
	}
	if _, err := io.WriteString(w, "data: "); err != nil {
		return false
	}
	if _, err := w.Write(data); err != nil {
		return false
	}
	if _, err := io.WriteString(w, "\n\n"); err != nil {
		return false
	}
	if err := rc.Flush(); err != nil {
		return false
	}
	return true
}
