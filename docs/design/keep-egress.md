# Design: explicit-Keep gate + egress probe (Sec-M4)

Closes the two v1 limitations in README "Known limitations": confirmation is
selection + tailnet reachability (not egress), and there is no explicit operator
"Keep" (v1 auto-keeps on confirmation). DESIGN §8 step 5 envisaged both.

## Current flow (v1)

`router.Client.SetExitNode` runs, under the per-router lock, a synchronous
**arm → apply → confirm → keep**:

1. **ARM** — `nohup sh -c 'sleep 60; [ -f MARKER ] && exit 0; tailscale set --exit-node=PREV' &` (detached on the router; reverts to PREV unless MARKER appears within 60s).
2. **APPLY** — `tailscale set --exit-node=TARGET` (incremental; preserves other prefs).
3. **CONFIRM** — re-read `tailscale status --json`; require the device reports TARGET selected.
4. **KEEP** — `: > MARKER` (cancels the armed revert). **Done automatically on confirm.**

Gap: no internet-egress check; no operator decision point (auto-keep).

## New flow

Insert an **EGRESS probe** after CONFIRM, and make **KEEP** an explicit, separate
operator action when opted in:

```
arm → apply → confirm → egress-probe → [ auto-keep ]  (default, current behavior)
                                      └ [ AWAIT operator Keep ] (opt-in: -require-keep)
```

- The **egress probe** runs whenever a TARGET is set (not on clear). It is
  reported either way; it never auto-reverts on its own (a router may legitimately
  have no egress yet). It is advisory unless `-require-keep` is on, where the
  operator sees it before deciding to Keep.
- With **`-require-keep`** (env `TSCTL_REQUIRE_KEEP`, default **off** =
  backward-compatible auto-keep): after confirm+egress, tsctl does **NOT** write
  the marker. The RouterView becomes `awaiting-keep` with the revert deadline; the
  armed revert will fire unless the operator calls Keep within the window. This is
  the strongest form of the dead-man's-switch (an operator who lost connectivity to
  the changed router can't Keep, so it auto-reverts).

## Egress probe

A read-only command run on the router AFTER apply (so its own traffic now routes
through the new exit node), testing actual outbound reachability:

```
uclient-fetch -q -T 5 -O /dev/null http://captive.tailscale.com/generate_204 2>&1; echo "egress_exit=$?"
```

Portable note: prefer `uclient-fetch` (OpenWRT default), fall back to `wget`; the
endpoint is a stable 204 generator. Result parsed to `EgressOK bool` +
`EgressDetail string` (the exit code / error). Timeout 5s, bounded output, same
runSSH seam + per-addr lock as Status/Probe. **Egress failure does not fail the
set** (the selection is still applied/confirmed) — it is surfaced for the operator.

Risk note: this makes the router itself reach an external endpoint. It is opt-in
in spirit (only runs on a deliberate exit-node *set*) and read-only.

## Router-layer API change

Split the synchronous SetExitNode keep step so Keep can be deferred:

```go
// ApplyExitNode does arm → apply → confirm → egress-probe and returns the marker
// (so Keep can be issued later) WITHOUT keeping. autoKeep=true writes the marker
// inline (preserves v1 behavior).
func (c *Client) ApplyExitNode(ctx, addr, target, prev *ExitNodeRef, autoKeep bool) (ApplyResult, error)
// ApplyResult = { Runtime RouterRuntime; Marker string; Egress EgressResult; Kept bool }

// KeepExitNode writes the keep-marker for a prior ApplyExitNode (cancels revert).
func (c *Client) KeepExitNode(ctx, addr, marker string) error
```

(SetExitNode becomes a thin wrapper: `ApplyExitNode(..., autoKeep=true)`.)

## Poller / state

- New `store.RouterState = "awaiting-keep"` — confirmed selection within the revert
  window, marker not yet written. Carries `RevertAt time.Time` (deadline) so the UI
  can count down. Also new RouterView fields: `EgressOK *bool` (nil = not probed /
  cleared) + `EgressError string`.
- The poller keeps an **in-memory** pending-keep map keyed by addr →
  `{marker string, revertAt time.Time, targetSeq uint64}`. In-memory by design:
  a tsctl restart loses it → the marker is never written → the router auto-reverts
  (fail-safe; the dead-man's-switch holds).
- `SetExitNode` (poller): when `-require-keep` is off → unchanged (auto-keep). When
  on → ApplyExitNode(autoKeep=false); on confirm, store `awaiting-keep` + RevertAt +
  egress, and record the pending-keep entry. The existing `setSeq` guard still
  protects against concurrent sets (a newer set supersedes the pending keep).
- New `Poller.Keep(ctx, routerID) (RouterView, error)`: look up the pending-keep
  entry; if expired (now > revertAt) → 409/410 "revert window elapsed; the router
  has reverted"; else `KeepExitNode(marker)` → on success reconcile to `ok` + clear
  the pending entry + broadcast.
- On window expiry (no Keep): the router reverts itself; the next poll's Status read
  shows the reverted selection; the poller clears the stale pending-keep entry and
  the RouterView settles to `ok` on the reverted node (surfaced as "reverted").

## API

- `POST /api/routers/{id}/keep` (auth + Host + CSRF, like exit-node) → `Controller.Keep`
  → 200 RouterView, or 409 if the window elapsed, 404 unknown / no pending keep.
- Snapshot DTO gains `state:"awaiting-keep"`, `revertAt`, `egressOk`, `egressError`.

## UI

- After a set in `-require-keep` mode: card/graph show **"Applied — egress OK/✗ —
  Keep within Ns"** with a live countdown + a **Keep** button (and the existing
  picker disabled while awaiting). Keep → POST /keep → `ok`. Countdown hits 0 →
  show "reverted" (the SSE frame from the next poll confirms).
- Egress indicator (✓/✗ + detail) shown on confirm regardless of keep mode.
- Never-optimistic preserved: `awaiting-keep` is explicitly NOT success; success is
  only `ok` after Keep (or after auto-keep in default mode).

## Edge cases

- **Restart between apply and keep** → pending map lost → router reverts (safe).
- **Window expiry before Keep** → Keep returns 409; poll shows reverted.
- **Concurrent set on the same router** → setSeq bump supersedes the pending keep
  (the older op's keep is dropped; the newer op owns the router).
- **Keep on a router with no pending entry** (e.g., default auto-keep mode, or
  already kept) → 404/409, no-op.
- **Egress probe failure / timeout** → `EgressOK=false` + detail; does NOT block
  Keep (operator decides) and does NOT auto-revert.

## Rollout

Stage 1: egress probe (always reported; additive; lower risk).
Stage 2: explicit-Keep gate behind `-require-keep` (default off).
Each stage gets its own concurrency/seam review gate before commit.
