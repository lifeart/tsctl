# Phase B — implementation spec (build against this + DESIGN.md)

Phase A scaffold + seam freeze are committed and compile. Phase B fills in the
bodies. **Read DESIGN.md (the locked design) first; this file is the wiring +
ownership + acceptance spec layered on top.**

## Ground rules (all agents)

- **Toolchain is pinned. Do NOT** run `go get -u`, bump `tailscale.com` (frozen at **v1.94.2** — newer needs Go ≥1.26.4, we are on 1.25.5), or change the `go` directive. If you think you need a new dependency, STOP and report instead.
- **Own only your directory** (see ownership). Do not edit other packages' files. Only the api+sse+poller agent touches `cmd/tsctl/main.go`.
- **Frozen cross-agent seams — never change these signatures:** the interfaces `poller.Netmapper`, `poller.RouterClient`, `poller.Broadcaster`, `api.WhoIser`, `api.Controller`; all `store` types incl. `store.RouterRuntime`; and the HTTP/JSON wire contract in §3. Constructor arities (`api.New`, `poller.New`) are owned by the api+sse+poller agent (it owns both the constructors and `main.go`), so it may extend them (e.g. add a config param) as long as it keeps the frozen interfaces and updates `main.go`.
- **No silent error swallowing** (global rule + DESIGN §8). Every error path surfaces: into `Snapshot.NetmapErr`, `RouterView.LastError`, an HTTP error body, or a log line — never an empty `catch`/ignored `err`.
- **Verify before done:** `go build ./...`, `go vet ./...`, and `go test ./<your-pkg>/...` must pass. Paste the output in your report. No live tailnet exists here — do not claim runtime/e2e success; prove it with unit tests + golden fixtures + fakes.

## 1. Ownership (disjoint — safe to run in parallel)

| Agent | Owns (only) | Implements |
|---|---|---|
| **A: netmap** | `internal/netmap/` | `Inventory` (LocalClient.Status→[]NodeView), `WhoIs`, `classify` |
| **B: router** | `internal/router/` | `ParseStatus` (pure), `Status`, `SetExitNode` (dead-man's-switch), `runSSH` |
| **C: server** | `internal/api/`, `internal/sse/`, `internal/poller/`, `cmd/tsctl/main.go` | handlers + CSRF/owner middleware, SSE hub, idle-aware poll loop, `poller.SetExitNode` controller |
| **D: frontend** | `web/` | the SPA (`index.html` + JS/CSS, embedded) |

All four depend only on the leaf `store` package (already complete) — none depends on another's in-flight code.

## 2. Server-side control flow (agent C)

```
EventSource GET /api/events ─┐
                             ├─ first client (0→1) → poller.Refresh (singleflight) → Store snapshot → hub.Broadcast
GET /api/nodes ──────────────┘                                                     (poll loop runs only while ≥1 client; ~45s linger after last leaves)
POST /api/routers/{id}/exit-node {exitNode} ─ RequireOwner+RequireCSRF ─→ poller.SetExitNode(id, stableID)
        └─ resolve id→addr, stableID→ExitNodeRef from snapshot; pre-flight (target online & ExitNodeOption, no loop);
           rc.SetExitNode(addr,target,prev) [arm revert→apply→confirm→keep]; reconcile ACTUAL into fresh snapshot; Broadcast; return RouterView
```

- **Refresh** builds a `Snapshot`: `nm.Inventory(ctx)` → `[]NodeView`; pick the routers (see §5) and `rc.Status(ctx,addr)` each (errors → that `RouterView.Reachable=false` + `LastError`, never abort the whole snapshot); set `NetmapErr` on inventory failure (keep last-good nodes if you have them). Then `Store` + `bc.Broadcast`.
- **Idle suspension:** the hub owns the connected-client count and emits `0→1`/`1→0` on a channel; the poller's `Run` starts/stops the ticker loop accordingly, with a ~45s linger. Gate the first refresh through the existing `singleflight.Group`.
- **SSE hub:** single goroutine owns the client set via `register`/`unregister`/`broadcast` channels (no mutex over the map). Per-client cap-1 latest-wins channel. On connect: send the current snapshot immediately, then stream. `: ping\n\n` every ~20s; flush via `http.NewResponseController(w).Flush()`. Headers: `text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`. Select on `r.Context().Done()` AND the channel; unregister + return on disconnect/write-error (no leak).

## 3. HTTP / JSON wire contract (agent C ↔ agent D — FROZEN)

Define response DTOs in `api` (don't put json tags on store types). camelCase fields.

```
GET  /api/csrf            → 200 {"token": string}   + sets cookie tsctl_csrf=<token> (SameSite=Strict, Path=/, not HttpOnly)
GET  /api/nodes           → 200 {"nodes": Node[], "builtAt": rfc3339, "netmapErr": string}  (first paint / no-SSE fallback)
GET  /api/events  (SSE)   → data: Snapshot\n\n frames + ": ping" heartbeats
POST /api/routers/{id}/exit-node   body {"exitNode": "<stableID>" | ""}   ({} = clear)
       → 200 RouterView   |  4xx/5xx {"error": string, "detail": string, "stderr": string}
         (id = router StableID; requires header X-Tsctl-CSRF == cookie)

Node       = {stableID,name,hostname,tailscaleIPs:[],os,online,lastSeen(rfc3339),exitNodeOption,tags:[],type}
             type ∈ "exit-node" | "router" | "generic"
ExitNodeRef= {stableID,name,ip}                       // null when none
RouterView = {node:Node, currentExitNode:ExitNodeRef|null, desired:ExitNodeRef|null,
              state:"ok"|"pending"|"unconfirmed"|"unreachable",
              stats:{rxBytes,txBytes,lastHandshake(rfc3339)}, reachable, lastError, lastConfirmedAt(rfc3339)}
Snapshot   = {nodes:Node[], routers:RouterView[], netmapAt, netmapErr, builtAt}
```

The live UI consumes the **SSE Snapshot frames** as primary truth (it carries routers too); REST is for first paint, CSRF token, and the mutation.

## 4. NodeType classification (agent A, `classify`)

Precedence (first match wins): `Tags` contains `tag:router` → `NodeRouter`; else `ExitNodeOption == true` → `NodeExitNode`; else `NodeGeneric`. (`ExitNodeOption` is still exposed as its own field regardless of type, so the picker can offer any approved exit node.) Map from `ipnstate.PeerStatus`: `Online`, `LastSeen`, `OS`, `HostName`→Hostname, `DNSName`→Name, `TailscaleIPs`→strings ([0] = 100.x IPv4), `ID`→StableID, `Tags`, and `ExitNodeOption`. Include `Self` in the inventory too. On `lc.Status` error: return the error (agent C turns it into `NetmapErr`).

## 5. Router identification (agent C)

`cfg.Routers` (the configured 100.x IPv4 addresses) is the authoritative set of controllable routers. For each, find the matching `NodeView` by IP to populate `RouterView.Node`; the SSH `addr` is that configured IP. A configured router missing from the netmap still appears as a `RouterView` with `Reachable=false`.

## 6. Dead-man's-switch (agent B, inside `router.Client.SetExitNode`) — DESIGN §8

Self-contained in one call: **arm → apply → confirm → keep**, so connectivity loss self-heals on the router. Use a per-op marker file; `time.Now()` in real Go is fine for the id.

```
id      := unique (e.g. unixnano + rand hex)
marker  := "/tmp/tsctl-keep-" + id
prevArg := prev.IP (or "" to clear)        targetArg := target.IP (or "" to clear)
window  := 60s (const)

# 1. ARM (one exec) — revert unless keep-marker appears within the window:
nohup sh -c 'sleep 60; [ -f <marker> ] && exit 0; tailscale set --exit-node=<prevArg>' >/dev/null 2>&1 &

# 2. APPLY (one exec):
tailscale set --exit-node=<targetArg> [--exit-node-allow-lan-access=true when setting, not clearing]

# 3. CONFIRM: re-read `tailscale status --json` (reuse Status logic); ok = reachable && actual exit node == target
# 4. KEEP on success only (one exec): : > <marker>     # the sleeping revert sees the file and exits without reverting
#    on failure: DO NOT touch the marker → the revert fires; return the runtime you could read + a non-nil error
```

`runSSH`: dial `addr:22` via the injected `DialFunc`, `ssh.NewClientConn` with `Auth:nil` (none) + `ssh.InsecureIgnoreHostKey()` (already commented as deliberate), capture **stdout+stderr+exit code** (`*ssh.ExitError`), context-cancel by closing the session on `ctx.Done()`. `ParseStatus`: unmarshal `ipnstate.Status`; `Current` from `ExitNodeStatus`/the peer with `ExitNode==true`; `Options` = peers with `ExitNodeOption==true`; `Stats` from the relevant peer's `RxBytes/TxBytes/LastHandshake`. Golden-fixture tests with a captured `status --json`.

## 7. CSRF + Host/Origin (agent C, `RequireCSRF`) — DESIGN §7

Double-submit cookie + Host pinning + Origin check on every non-GET/HEAD:
1. `GET /api/csrf` issues a random token, sets cookie `tsctl_csrf` (SameSite=Strict, Path=/, not HttpOnly), returns `{token}`.
2. On state change: require header `X-Tsctl-CSRF` present AND equal to the `tsctl_csrf` cookie (simple cross-origin requests can set neither).
3. **Host pinning:** `r.Host` must be in an allowlist (config: tsnet hostname / MagicDNS FQDN / 100.x / `cfg.Listen` host) — rejects DNS-rebinding.
4. **Origin:** if `Origin` present, its host must equal `r.Host`; reject `Sec-Fetch-Site` values other than `same-origin`/`none`.

`RequireOwner` additionally compares the WhoIs `login` to the configured owner (add owner to api config). Frontend (agent D) fetches `/api/csrf` on load and sends `X-Tsctl-CSRF` on POST.

## 8. Frontend (agent D)

Vanilla JS (no build step) embedded via the existing `web` package. On load: `GET /api/csrf` (store token), open `EventSource('/api/events')`, render from Snapshot frames (fall back to `GET /api/nodes` if SSE not yet open). Show: node list with type badge + online/lastSeen + IPs/OS; for each `RouterView`, current exit node + a picker of the approved exit-node options (nodes with `exitNodeOption`), stats, and `state`. On pick → `POST /api/routers/{id}/exit-node` with the CSRF header; reflect the returned/streamed **actual** state — show `pending`/`unconfirmed` distinctly, never optimistic success. Surface `lastError`/`netmapErr` and snapshot staleness (`builtAt`). Keep it lightweight.

### 8a. Visual design — Apple-like (required)

Model the look on Apple HIG (macOS/iOS Settings). Restraint over decoration; hierarchy from type weight + spacing, not borders. Still no build step / no external assets / no CDN — pure CSS, system fonts, inline SVG only.

- **Type:** system stack `-apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", system-ui, sans-serif`; tabular figures (`font-variant-numeric: tabular-nums`) for stats/IPs. Hierarchy via weight (600 headings / 400 body) and size, generous line-height.
- **Color via CSS variables, light + dark (`prefers-color-scheme`):** layered neutral surfaces (light: `#f2f2f7` bg / `#ffffff` card; dark: `#000` bg / `#1c1c1e` / `#2c2c2e`), single accent Apple blue (`#007AFF` light / `#0A84FF` dark). Semantic: green online/ok, orange/amber pending·unconfirmed, red offline·error. Hairline separators (1px, low-opacity label color).
- **Layout:** centered max-width column, generous whitespace, grouped **inset rounded cards/lists** (radius ~12–16px) like iOS Settings; section headers small, uppercase-ish, secondary color.
- **Controls:** pill/rounded buttons; status as soft **tinted badges** (light tint bg + saturated text); the exit-node picker reads as a clean native-feeling select or tidy custom dropdown; 44px hit targets; visible accessible focus rings. Online state = small colored dot.
- **Materials & motion:** sticky top bar with subtle `backdrop-filter: blur()` translucency + hairline bottom border; soft shadows (not heavy); transitions ~200–250ms ease-out; spinner for `pending`; **respect `prefers-reduced-motion`**.
- **States:** tasteful empty/loading/reconnecting; error/staleness as a soft inset banner (amber/red tint), never a raw alert.

Accessibility: sufficient contrast in both themes, semantic HTML, keyboard operable, `aria-live` on the status banner.

## 9. Tests required per agent

- **A netmap:** `classify` table tests; `Inventory` mapping with a fake `lc.Status` payload (or a thin seam over the status call).
- **B router:** `ParseStatus` golden fixtures (with/without exit node, multiple options, stats); `SetExitNode`/`Status` against a fake `DialFunc`/`CommandRunner` asserting the exact arm/apply/keep command sequence + that failure leaves the marker untouched.
- **C server:** SSE hub — initial-snapshot frame, heartbeat, and goroutine-leak check (NumGoroutine delta) on client cancel; `RequireOwner`/`RequireCSRF` with fakes (deny on WhoIs error/tagged, missing/mismatched token, bad Host/Origin); `httptest` handler tests with an injected snapshot; idle 0→1/1→0 transition.
- **D frontend:** no Go tests; keep DOM logic small and defensive.
