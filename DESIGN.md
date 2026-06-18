# tsctl — Tailscale exit-node manager

Single Go binary. Joins the tailnet as its own node (tsnet), serves a small web UI **over the tailnet only**, lists Tailscale nodes, and lets the user set which exit node each OpenWRT router uses — in real time. Low-resource: nothing runs on the routers but the Tailscale they already have.

> This file is the **locked design** and the **single source of truth**. It is the synthesis of three independent expert reviews (Tailscale/networking, Go architecture, security/ops). Implementation agents MUST build against the contract in §4 and obey the rules in §6–§8. If you believe something here is wrong, STOP and flag it — do not silently diverge.

---

## 1. Scope (v1)

- **In:** list nodes with type + status (online/lastSeen) from the local netmap; per-router current exit node, available exit-node options, and stats; set/clear a router's exit node safely; live updates to the browser.
- **Out (v1):** approving *new* exit nodes (admin action needing central-API write), multi-user/roles, persistent history/DB.

## 2. Key decisions (and why)

| Decision | Rationale (from reviews) |
|---|---|
| **No central Tailscale API in v1.** Source inventory + `online` + `ExitNodeOption` from `LocalClient.Status()`. | The devices API has **no real-time `online`** (only `lastSeen`; the omit-when-connected heuristic caused an incident 2025-10-10). The tsnet node's own netmap is more accurate, needs no OAuth, has no rate limits, and removes a long-lived secret. |
| **tsnet node, persistent + tagged + non-ephemeral.** | A control service must survive restarts and offline windows. Tagged nodes have key-expiry disabled by default → never needs re-auth. State dir is the crown jewel (see §7). |
| **Reach routers via Tailscale SSH from Go** (`tsnet.Dial(router:22)` + `x/crypto/ssh`, `none` auth). | Verified pattern; real precedent `derekg/ts-ssh`. No keys to distribute. |
| **ACL: tag the tsnet node `tag:tsctl`, routers `tag:router`; ssh rule `action:"accept"`, `users:["root"]`.** | A **tagged** source *cannot* use `check` mode → `accept` is guaranteed and automation never needs a browser. OpenWRT logs in as **root**; `autogroup:nonroot` excludes root → silent denial if omitted. |
| **Connect-per-poll/per-action SSH (no persistent connection).** | At 1–3 routers, idle-suspended, slow cadence, a long-lived `*ssh.Client` (keepalives, dead-conn detection, reconnect/backoff, command serialization) is the most bug-prone, lowest-value code in the system. Dial fresh, run, close. |
| **`--exit-node` by 100.x IPv4, not MagicDNS name.** | A router about to route through an exit node is the worst place to depend on DNS. |
| **Cache = immutable `atomic.Pointer[Snapshot]`; SSE hub = single goroutine owning the client set via channels.** | Lock-free reads; avoids the classic broadcast-under-mutex deadlock. |
| **SSE, not WebSocket.** Server→client only; mutations over POST. | Free `EventSource` reconnect, no upgrade handshake, rides plain HTTP/1.1 tsnet listener. |
| **`http.Server.WriteTimeout = 0` for the SSE path.** | A write deadline silently kills long-lived SSE streams — classic footgun. |

## 3. Architecture

```
 browser (tailnet) ──SSE──┐         ┌──────────────────────────────────────┐
        │  POST (+CSRF)    │         │  tsctl (single Go binary)             │
        └──────────────────┼────────►│  api(CSRF+WhoIs allowlist) → store    │
                           SSE◄───────┤  sse hub (1 goroutine)                │
                                      │  poller (idle-aware, singleflight)    │
   localhost:PORT ──/healthz─────────►│  netmap(LocalClient.Status)           │
                                      │  router(SSH over tsnet.Dial) ─────────┼─SSH─► OpenWRT routers
                                      │  tsnet node (tag:tsctl, persistent)   │       tailscale status --json (read)
                                      └──────────────────────────────────────┘       tailscale set --exit-node (write)
```

- **Inventory / type / online / exit-node-capability** ← `LocalClient.Status()` (the tsnet node's netmap; needs ACL visibility to the peers — see §7 risk).
- **A router's *current* exit-node selection + stats** ← SSH `tailscale status --json` on that router (device-local; not in any central API).
- **Set exit node** ← SSH `tailscale set --exit-node=<100.x IPv4>` (empty clears) on the router, with the dead-man's-switch in §8.

## 4. The contract (freeze before parallel work)

The **scaffold agent** finalizes these as compiling Go and commits them; all other agents build against the committed versions. Shapes below are the intent; exact field/method names are frozen once committed.

```go
// internal/store — immutable snapshot, lock-free reads via atomic.Pointer[Snapshot]
type NodeType string // "exit-node" | "router" | "generic"

type NodeView struct {
    StableID       string   // tailcfg.StableNodeID
    Name, Hostname string
    TailscaleIPs   []string // [0] is the 100.x IPv4
    OS             string
    Online         bool
    LastSeen       time.Time
    ExitNodeOption bool     // advertised AND approved → selectable as exit node
    Tags           []string
    Type           NodeType
}
type ExitNodeRef struct{ StableID, Name, IP string } // IP = 100.x IPv4
type RouterState string // "ok" | "pending" | "unconfirmed" | "unreachable"
type RouterStats struct{ RxBytes, TxBytes int64; LastHandshake time.Time }
type RouterView struct {
    Node            NodeView
    CurrentExitNode *ExitNodeRef // actual, from the router's own status (source of truth)
    Desired         *ExitNodeRef // pending intent; never shown as success until confirmed
    State           RouterState
    Stats           RouterStats
    Reachable       bool
    LastError       string       // "" = healthy; NEVER swallow — surface here
    LastConfirmedAt time.Time
}
type Snapshot struct {
    Nodes     []NodeView
    Routers   []RouterView
    NetmapAt  time.Time
    NetmapErr string // "" = healthy
    BuiltAt   time.Time
}
type Store struct{ /* atomic.Pointer[Snapshot] */ }
func (s *Store) Load() *Snapshot        // lock-free
func (s *Store) Store(snap *Snapshot)

// Interfaces declared at the CONSUMER side (avoid import cycles):

// consumed by poller
type Netmapper interface { Inventory(ctx context.Context) ([]NodeView, error) }
type RouterClient interface {
    Status(ctx context.Context, addr string) (RouterRuntime, error) // current exit node + options + stats
    SetExitNode(ctx context.Context, addr string, target *ExitNodeRef, prev *ExitNodeRef) (RouterRuntime, error)
}
// consumed by api middleware
type WhoIser interface { WhoIs(ctx context.Context, remoteAddr string) (login string, tagged bool, err error) }
```

`RouterRuntime` = parsed result of `tailscale status --json` (current exit node, `[]ExitNodeRef` options where `ExitNodeOption==true`, stats). **Parsing is a pure function** `router.ParseStatus([]byte) (RouterRuntime, error)` — golden-fixture tested, version-tolerant.

### HTTP surface
- `GET /api/nodes` → `{nodes, builtAt, netmapErr}`
- `GET /api/routers/{id}` → `RouterView`
- `POST /api/routers/{id}/exit-node` body `{"exitNode":"<stableID>"|""}` (`""` = clear) → re-read result; **requires** `X-Tsctl-CSRF` header
- `GET /api/events` (SSE) → full-`Snapshot` frames + `: ping` heartbeats
- `GET /healthz` on **127.0.0.1** host socket (separate from tsnet listener) → init/tsnet health

`status --json` field reference (from `tailscale.com/ipn/ipnstate`): `PeerStatus.ExitNode` (bool, is the selected one), `ExitNodeOption` (bool, selectable), `RxBytes`/`TxBytes` (int64), `LastHandshake`, `Online`, `LastSeen`; top-level `Status.ExitNodeStatus` (nil = none) has `ID`, `Online`, `TailscaleIPs`.

## 5. Package layout & file ownership (no two agents touch the same dir)

```
cmd/tsctl/main.go        composition root: tsnet Up→Listen, localhost healthz, wiring, graceful shutdown   [SCAFFOLD]
internal/store/          Snapshot types + atomic.Pointer Store + pure helpers                              [AGENT: store+netmap]
internal/netmap/         Netmapper impl over LocalClient.Status(); classify NodeType                       [AGENT: store+netmap]
internal/router/         SSH over tsnet.Dial; ParseStatus (pure); Status/SetExitNode; CommandRunner iface  [AGENT: router]
internal/sse/            single-goroutine hub; register/unregister/broadcast chans; count transitions      [AGENT: api+sse+poller]
internal/poller/         idle-aware loop; singleflight first-refresh; builds Snapshots                     [AGENT: api+sse+poller]
internal/api/            handlers + CSRF middleware + WhoIs allowlist (fail-closed)                         [AGENT: api+sse+poller]
web/                     embedded SPA (vanilla/Preact); node list, badges, picker, pending/actual, SSE     [AGENT: frontend]
config.go / flags+env    config (no committed secrets)                                                     [SCAFFOLD]
deploy/tsctl.service     hardened systemd unit                                                             [SCAFFOLD]
```

## 6. Concurrency rules (Go review — mandatory)

- **Store:** poller builds a *fresh immutable* `Snapshot` and `atomic.Pointer.Store`s it. Readers `Load()` lock-free. Never hand out a shared mutable map.
- **SSE hub:** ONE goroutine owns the client set. Communicate via `register`/`unregister`/`broadcast` channels — no mutex over the map. Per-client **cap-1, latest-wins** buffered channel (drop/replace stale frame; never let a slow browser backpressure the poller). Each SSE handler goroutine `select`s on `r.Context().Done()` **and** its channel; unregister + return on disconnect or write error (no leaks).
- **SSE transport:** `WriteTimeout: 0`; `: ping\n\n` every ~20s; flush via `http.NewResponseController(w).Flush()`; headers `text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`. On connect, immediately send the current snapshot (no replay buffer needed — every frame is full state).
- **Idle suspension:** the hub owns the connected-client count and emits `0→1` / `1→0` transitions on a channel; one coordinator starts/stops the poll loop. Add a **~45s linger** after the last client leaves (so a refresh doesn't churn). Gate the first-viewer refresh through `golang.org/x/sync/singleflight` so concurrent first-loads collapse to one fetch; surface snapshot freshness (`BuiltAt`) in the UI.
- **SSH:** connect-per-poll/per-action. Every dial/exec has a context timeout; cancel by closing the session/conn on `ctx.Done()` (sessions predate context). Capture **stdout + stderr + exit code** (`*ssh.ExitError`). Serialize commands per router (one in flight at a time).

## 7. Security rules (security + networking reviews — mandatory)

- **CSRF / DNS-rebinding (Critical).** "On the tailnet" + WhoIs does NOT protect the control UI — a cross-origin page on the user's own node can POST with ambient authority. Every state-changing request MUST: be POST; carry a valid `X-Tsctl-CSRF` token (issued to the page, simple cross-origin requests can't set custom headers); pass **`Host` header validation** against the expected MagicDNS name / 100.x (rejects rebinding); pass `Origin`/`Sec-Fetch-Site` checks.
- **WhoIs allowlist, fail-closed.** Identify the caller via `LocalClient.WhoIs(ctx, r.RemoteAddr)`; require `login` == owner; **deny on any WhoIs error** and deny tagged/shared/unknown peers. WhoIs is the *who*, CSRF is *which page asked* — need both.
- **No passwordless root sprawl (Critical, mitigated).** Tag the tsnet node so the ACL `src` is `tag:tsctl` → `check` impossible, `accept` guaranteed. v1 logs in as `root` on OpenWRT (no sudo there); document the **future hardening** (dedicated router user + restricted-shell command whitelist allowing only `tailscale status --json` and `tailscale set --exit-node=…`). Treat the **tsnet state dir as a private key** (0700, dedicated user) — it *is* root on the fleet.
- **HostKeyCallback.** Raw `x/crypto/ssh` over `tsnet.Dial` has no `known_hosts`; use `ssh.InsecureIgnoreHostKey()` **deliberately** (WireGuard already authenticates the peer) — comment it; this is NOT a silent skip.
- **Secrets.** Only secret in v1 is the **one-time tagged auth key** for first enrollment (after that the node key lives in the state dir; drop the key from config). Load via systemd `LoadCredential=` (tmpfs), never env/log. Non-reusable, short-expiry, pre-approved, tagged.
- **Listener scope.** Use tsnet `Listen` only (userspace netstack → tailnet-only by construction; cannot leak to LAN). NEVER `ListenFunnel`. The `/healthz` host socket binds **127.0.0.1** only.
- **ACL visibility footgun.** When you add the ssh rule, ensure the tsnet node still has ACL visibility to every router/peer you inventory, or nodes silently vanish from the list.
- **systemd hardening:** dedicated user, `StateDirectory=tsctl` (0700), `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, empty `CapabilityBoundingSet` (netstack needs no caps), `SystemCallFilter=@system-service`, `Restart=on-failure`, `WatchdogSec`, `LoadCredential=` for the key.

## 8. Safe exit-node change — desired vs actual + dead-man's-switch

The **device's actual selection is the source of truth**; the UI never shows success for an unconfirmed change.

1. **Pre-flight:** refuse if target is offline or `ExitNodeOption==false` (unapproved), or if it would create a loop (target reached *through* this router). Record current exit node (`prev`).
2. **Arm local revert on the router BEFORE applying** (backend can't revert if the link dies): `(sleep 60; tailscale set --exit-node=<prev-or-empty>) &` (or an `at`/cron one-shot). State → `pending`.
3. **Apply:** `tailscale set --exit-node=<targetIP>`. `set` is **incremental** (unlike `up`, which resets unspecified prefs), so the router's advertise-routes, accept-routes, `--ssh`, accept-dns, hostname, advertise-tags, etc. are all **preserved** on the change *and* on the revert. The only non-exit-node pref tsctl can touch is `--exit-node-allow-lan-access`, and by default it is **preserved** too (not written); `-exit-node-lan-access=true|false` opts tsctl into managing it (it's buggy on OpenWRT — don't rely on it; keep an out-of-band recovery path).
4. **Confirm:** re-read `status --json` over the tailnet; reconcile `actual`. Exit-node changes do NOT sever the tailnet/SSH control path (only internet egress is routed), so this read should succeed.
5. On confirmed success → **cancel the scheduled revert** and require explicit user **"Keep"** within the window; else the router self-heals. On unknown/failed → keep last-confirmed `actual` + explicit error; rely on `set` idempotency to retry.

### Failure-mode table (every branch surfaces to UI or to journald — never swallowed)
| Condition | Behavior | UI |
|---|---|---|
| Router offline | disable control, show last-confirmed exit node stale | "Offline (last seen …) — control disabled" |
| SSH drops mid-`set` | outcome UNKNOWN; re-read; idempotent retry | "Result unknown — verifying…" |
| `set` ok but confirm read fails | state `unconfirmed`; backoff retry | "Sent but not confirmed" (amber) |
| Selected node offline/unapproved | pre-flight refuse | "Cannot use <node>: offline / not approved" |
| Netmap error | mark `NetmapErr`; keep last good + staleness | "Inventory stale as of … " |
| tsnet won't start / key expired | fatal, non-zero exit, `Restart=on-failure` | out-of-band: journald + `curl localhost/healthz` |
| WhoIs error / non-owner | fail closed | 403 "Not authorized" |

## 9. Build phases (manager-orchestrated)

- **Phase A — scaffold (sequential):** go.mod with ALL deps imported & tidied (frozen), §4 contract as compiling Go, stub impls, `main.go` wiring, localhost `/healthz`, systemd unit, embedded "hello" page. `go build ./...` + `go vet` pass. Also a `tsctl spike` subcommand (tsnet Up → `tsnet.Dial(router:22)` → `tailscale status --json` → print) so the **user** can prove the SSH path in their real tailnet. Commit.
- **Phase B — parallel (after A, disjoint dirs, no go.mod edits):** (1) store+netmap, (2) router, (3) api+sse+poller, (4) frontend. Each builds its own package + unit tests (pure `ParseStatus` golden fixtures; hub leak test; CSRF/WhoIs middleware tests with fakes).
- **Phase C — seam verification (after B):** build everything; diff every caller↔handler / frontend↔API / interface↔impl boundary (zero mismatches); mock-driven flow test through the full stack.

### Verification honesty
No agent here has a live tailnet or OpenWRT router. "Verified" in this repo means: `go build ./... && go vet ./...` pass, unit tests pass, and the seam diff is clean. The **real end-to-end** (UI → pick exit node → router's actual `tailscale status` switches → UI reflects it) MUST be run by the user against their tailnet using `tsctl spike` first, then the full binary, with the ACL from §7. Do not claim e2e success without it.
