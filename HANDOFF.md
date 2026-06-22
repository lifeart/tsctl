# tsctl — handoff

State at the **v0.4.0** release (live-state correctness + guest UX). Published tags
(GHCR + GitHub Release): **v0.1.0**, **v0.2.4**, **v0.3.0**, **v0.4.0**; the
intermediate v0.2.0–v0.2.3 builds were local images only (Synology Container
Manager). The Synology compose tracks the latest local `tsctl:v0.4.0` tarball.

## What it is

`tsctl` is a single Go binary that joins a tailnet as its own userspace `tsnet`
node (`tag:tsctl`) and lets you set, in real time, which **exit node** each OpenWRT
**router** (`tag:router`) uses — over Tailscale SSH (default), or an opt-in
password transport: `tailnet-password` (password over the tailnet, no Tailscale
SSH, no LAN map) or `ip-password` (password to a LAN endpoint). It serves a live
SPA (drag-to-rewire **zone graph** is the
default view) over the tailnet and, optionally, a password-protected host port.
Nothing runs on the routers but the Tailscale they already have.

Authoritative specs: **`DESIGN.md`** (locked), **`PHASE_B.md`** (§3 wire contract,
§4 types), and `docs/design/{zones,ip-password-ssh,keep-egress,guest-mode}.md`.
**Read those before changing the seam** — interface/field names are a frozen contract.

Toolchain: **Go 1.26.4**, **tailscale.com v1.100.0**. 152 test funcs; CI runs
gofmt / vet / build / `go test -race` / `go mod tidy` check on every push.

## Architecture (the load-bearing invariants — do not break these)

- **Lock-free snapshot.** `internal/store` holds an immutable `*Snapshot` in an
  `atomic.Pointer`. Exactly ONE writer (the poller) ever `Store()`s, always a brand-
  new `*Snapshot`; readers `Load()` lock-free and must treat everything reachable as
  read-only. No published snapshot's slices/pointees are ever mutated in place.
- **`poller.mu`** serializes the writers' read-modify-write (`Refresh`/`SetExitNode`/
  `Keep`/`RefreshGroups`). Slow network I/O (inventory, per-router SSH) runs OUTSIDE
  `mu`; only the fast merge+Store+Broadcast is under it (the L-3 refactor).
- **Two per-router counters, both `mu`-guarded, are central to correctness:**
  - `setSeq` (bumped at SetExitNode **step 1**): a stale reconcile that finds
    `setSeq` advanced is SUPERSEDED and must not publish.
  - `setGen` (bumped at step 1 **and** step 3, and on Keep): the poll captures it
    before its dials and keeps the published view (not its stale read) for any router
    whose `setGen` changed — catches a set that *confirmed during* the poll's dial.
  Getting these wrong = a false-confirm. Three review gates found several; see below.
- **Never-optimistic.** The device's ACTUAL selection (`CurrentExitNode`) is the
  source of truth; the UI never shows success for an unconfirmed change. States:
  `ok`/`pending`/`unconfirmed`/`unreachable`/`unprobed`/`awaiting-keep`. `unconfirmed`
  is **time-bounded** (v0.4.0): a still-pending `Desired` carries a `DesiredSince`, and
  once a FRESH read (managed re-dial / probe) past one revert window still mismatches,
  `reconcileState` drops the stale intent and accepts the device's actual selection —
  the device may have changed it out-of-band, or its dead-man's switch reverted the
  set. No router stays stuck `unconfirmed` forever (it even survived a reload before).
  `DesiredSince` is poll-internal (carried under `mu` on a fresh `*Snapshot`), never on
  the wire; the fallback path never re-reads, so it can never flip a stale view to `ok`.
- **Dead-man's-switch** (`internal/router`, DESIGN §8): set = arm a detached
  `nohup sleep N; [ -f marker ] || revert` on the router, apply, confirm by re-read,
  then KEEP (write the marker to cancel the revert). If the link dies, the router
  self-heals. The split is `ApplyExitNode(autoKeep)` + `KeepExitNode(marker)`.
- **Auth (fail-closed, DESIGN §7):** tailnet `WhoIs`==owner OR a signed session
  cookie (password path); every request Host-pinned (anti-rebinding) + CSRF on
  writes. 401 = login, 403 = Host/CSRF. **Two roles** resolved per request into an
  `authz.Subject`: full-access **admin** (owner or `UIPassword`) or a zone-scoped
  **guest** (guest mode, below); the role rides inside the cookie's HMAC region.

## Features (what shipped this cycle, newest first)

- **Live-state correctness + guest UX (v0.4.0).** Four fixes so the live state never
  dead-ends a user:
  - **Re-read & adjust:** `unconfirmed` is now time-bounded (see the never-optimistic
    invariant above) — a router whose set never confirmed, or that changed exit node
    on its own, self-heals to its actual selection after one revert window instead of
    staying stuck forever, even across a page reload. Regression-pinned by
    `TestRefresh_Unconfirmed{AdjustsToDeviceSelfChangeAfterGrace,KeptWithinGraceWindow}`.
    An adversarial poller-review gate caught a transient false-`ok`: `SetExitNode`
    step 1 must reset `DesiredSince` (else a new set on an already-stale router could,
    in a step-1↔step-3 poll race, publish a green `ok` on the old selection) — fixed +
    pinned by `TestSetExitNode_PendingResetsStaleDesiredSinceNoFalseOK`.
  - **Unconfirmed is actionable again:** the graph card + Devices `<select>` no longer
    disable on `unconfirmed` (only genuinely in-flight states do); the user can retry,
    switch, or clear. Re-selecting the device's ACTUAL current node re-issues the set
    to clear a stuck `Desired` (the `acceptCurrent` path in `confirmExitNodeChange`).
  - **Graph Keep, all roles:** the explicit-Keep affordance (live countdown + Keep
    button) now lives on the graph consumer node, not only the Devices view — so a
    **guest** under `-require-keep` (who can't open Devices) can confirm, and an admin
    isn't forced out of the default graph. Shown only while live; hidden (never greyed)
    once a Keep is in flight or the window has elapsed.
  - **Guest Sign out:** a guest session always shows the Sign out affordance — it was
    hidden after a reload, since `sessionActive` is set only on a fresh login, and a
    guest is always a password session (no tailnet-guest). Plus a Guests-panel row
    layout polish (right-aligned actions).
  All UI except the poll-internal `DesiredSince`; SSE fan-out already pushes one
  guest's change to every other client in the zone, per-connection zone-filtered.

- **Guest mode** (per-zone scoped credentials, `docs/design/guest-mode.md`): an
  admin-managed, **bcrypt(cost 12)** credential type (persisted
  `$STATE_DIR/guests.json`, 0600; hash never leaves `internal/guests`) layered on
  the existing admin auth. A guest = `{label, one zone, password}`, signs in with
  `{label,password}`, and may ONLY see + re-exit that one zone (server-filtered),
  within its allowed list. Server-side authz is the source of truth: `RequireAdmin`
  on all group/guest CRUD, `authorizeRouterWrite` on set/keep/probe vs the guest's
  OWN zone (stricter than the poller's cross-zone union → closes shared-router
  escalation), zone-filtered reads (404/no-oracle). Role rides inside the signed
  cookie's HMAC region; the zone is re-resolved live each request → instant
  revocation (one SSE heartbeat for the live stream). Default = byte-for-byte
  unchanged when no guests exist; **no flag**. An independent security gate + a
  zone-escape audit (two findings fixed: SSE read-revocation lag, fail-open reads).
- **`tailnet-password` transport** (`TSCTL_ROUTER_TRANSPORT=tailnet-password` +
  `TSCTL_SSH_PASSWORD`): password SSH to the router's `100.x` over the tailnet —
  no Tailscale SSH, no LAN-endpoint map. Works from a bridged Docker container
  (NAS) that can't route `100.x` with a plain dialer. Needs a `tcp` ACL grant to
  `:22` + a router root password.
- **Explicit-Keep gate** (`keep-egress` stage 2, **opt-in `-require-keep`, default
  OFF**): a confirmed set holds the router armed (`awaiting-keep` + countdown) until
  the operator `POST /api/routers/{id}/keep` within the window, else it auto-reverts.
  In-memory `pendingKeep` map (lost on restart → router reverts = fail-safe).
- **Egress probe** (stage 1, `-egress-check`, default on): after a confirmed set,
  one read-only outbound request FROM the router (now routing through its new exit)
  to `-egress-url`; UI shows ✓/✗.
- **Non-exit-node fallback** (auto): with NO `tag:router` nodes, list every non-exit
  device as a consumer — but **never auto-SSH them** (a tailnet can be large); they
  show "not probed" until a manual **Test SSH** / set. Only `tag:router`/`-routers`
  get the background poll.
- **Manual SSH probe** ("Test SSH" button) per router; **router auto-discovery**;
  **zones** (graph + enforced allowed-exit-nodes); **ip-password** transport.
- **L-3:** moved the slow poll `Status` dials out of `mu` (no head-of-line blocking).

## Build, run, release

```sh
go build ./... && go vet ./... && go test -race ./...   # must stay green
./tsctl demo            # offline scripted preview on http://127.0.0.1:8089 (real SPA + mock)
./tsctl spike 100.x     # prove the router SSH transport against ONE real router
```

- **Local images / Synology tarballs:** `scripts/release.sh [version]` builds cross-
  compiled binaries + a multi-arch image (no push unless `PUSH=1`). For Synology,
  `scripts/synology-tarballs.sh [version]` builds each arch and rewrites the tarball
  `RepoTags` to a bare `tsctl:<ver>` (no registry → `pull_policy: never` works) into
  `./dist/` (gitignored) — so a NAS `docker load` matches `image: tsctl:<ver>`.
  Current local build: **v0.4.0** (`dist/tsctl-v0.4.0-linux-{amd64,arm64}-image.tar.gz`;
  the Synology compose points at the v0.4.0 local image).
- **Publish a release:** `git tag vX.Y.Z && git push --tags` → `.github/workflows/
  release.yml` builds + pushes `ghcr.io/lifeart/tsctl:<tag>`+`:latest` and attaches
  binaries to a GitHub Release. **v0.4.0 is published** (tag pushed); bump the minor
  for the next feature.
- **Deploy:** `deploy/tsctl.service` (hardened systemd, `LoadCredential` for the
  auth key) or `docker-compose.yml` (NAS) / `deploy/docker-compose.synology.yml`
  (Container Manager, UI on :8087, runs as root for the state-volume perms, loads
  the local tarball). Config: flags + env only — see the README table.

## First-run gotchas (all in README "Troubleshooting")

`TS_AUTHKEY` must be `tskey-auth-`/`tskey-client-` (NOT `tskey-api-`) carrying
`tag:tsctl`; ACL needs `tagOwners` + the `ssh` accept rule (`tag:tsctl`→`tag:router`
root) + a `:22` grant; Tailscale SSH enabled on each router; the state dir must be
writable by the container (Synology: run as root or chown to uid 65532); host-port
UI needs the browsed host in `TSCTL_ALLOWED_HOSTS` (else 403) and is plain HTTP
(front with TLS on untrusted nets).

## Known limitations / next candidate (documented in docs/design/keep-egress.md)

- The **explicit-Keep gate is opt-in/experimental.** Default OFF is byte-for-byte
  v1, proven by three review gates. The ON path was hardened across those gates (7
  concurrency bugs found + fixed, each regression-test-pinned) but carries a few
  accepted Lows that all err toward safe-revert.
- **Pre-existing, the top next-fix candidate:** for two *concurrent* SetExitNode
  calls to the SAME router, the published result is ordered by `setSeq` (step-1 `mu`
  order) but the device's last write is ordered by the per-router SSH lock — a
  preemption can reverse them → a transient false-confirm (self-heals next poll for
  managed routers; persists until the gate fires for fallback). **This is present on
  the default v1 path too**, not just the Keep gate. Fix = serialize the whole
  arm→apply→confirm per router, or order the applies by `setSeq`.
- v1 confirmation is selection + tailnet-reachability (egress probe is advisory, not
  a gate); no explicit "Keep" unless `-require-keep`.

## Working discipline that kept this correct

The poller/dead-man's-switch is concurrency-sensitive and `-race` does NOT catch
its bugs (they're logical, not data, races). The pattern that worked:

1. Build to a **frozen contract** (often parallel backend+frontend agents on non-
   overlapping files), then **seam-verify** field names across store↔api↔web↔mock.
2. **Run an adversarial review gate** on any dead-man's-switch / poller change
   BEFORE committing — every gate found a real false-confirm/leak.
3. For each fix, add a **regression test proven to fail without the fix** (revert
   the fix, watch it fail, restore).
4. **Browser-verify** the user flow on `tsctl demo` (don't trust "compiles").
5. Keep `app.js` clean UTF-8 (a past NUL-byte sentinel flagged it "binary" and broke
   grep — verify with `file web/app.js`).

## Layout

```
cmd/tsctl/     composition root: config, tsnet Up→Listen, healthz, wiring, serve/spike/demo
internal/store/   immutable Snapshot + atomic Store (frozen contract)
internal/netmap/  inventory + WhoIs over LocalClient
internal/router/  SSH transport (tailscale-ssh | tailnet-password | ip-password); dead-man's-switch; Probe; EgressProbe
internal/poller/  the refresh loop + SetExitNode/Keep/RefreshGroups; setSeq/setGen guards
internal/sse/     single-goroutine, latest-wins broadcast hub (per-connection guest zone filter + heartbeat revalidation)
internal/api/     handlers + fail-closed auth/CSRF/Host middleware; wire DTOs; RequireAdmin + authorizeRouterWrite + guest CRUD
internal/authz/   cross-cutting Subject (admin|guest) + context + pure FilterSnapshotToZone (shared by api + sse, no cycle)
internal/groups/  persisted zone store (atomic JSON)
internal/guests/  persisted guest-credential store ($STATE_DIR/guests.json, 0600; bcrypt cost 12; hash never leaves the package)
internal/demo/    scripted offline World for `tsctl demo`
web/              embedded SPA (app.js, index.html, style.css)
demo/             GitHub-Pages live demo (mock.js monkeypatches fetch+EventSource)
deploy/           systemd unit + Synology compose
docs/design/      zones, ip-password-ssh, keep-egress, guest-mode
```
