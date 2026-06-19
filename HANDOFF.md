# tsctl — handoff

State as of `978daaa`. Released tag: **v0.1.0** (on GHCR + GitHub Release). Current
HEAD is materially ahead; a **v0.2.0** image is built **locally** (not tagged/pushed
yet — see "Build & release").

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
§4 types), and `docs/design/{zones,ip-password-ssh,keep-egress}.md`. **Read those
before changing the seam** — interface/field names are a frozen contract.

Toolchain: **Go 1.26.4**, **tailscale.com v1.100.0**. 122 test funcs; CI runs
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
  `ok`/`pending`/`unconfirmed`/`unreachable`/`unprobed`/`awaiting-keep`.
- **Dead-man's-switch** (`internal/router`, DESIGN §8): set = arm a detached
  `nohup sleep N; [ -f marker ] || revert` on the router, apply, confirm by re-read,
  then KEEP (write the marker to cancel the revert). If the link dies, the router
  self-heals. The split is `ApplyExitNode(autoKeep)` + `KeepExitNode(marker)`.
- **Auth (fail-closed, DESIGN §7):** tailnet `WhoIs`==owner OR a signed session
  cookie (password path); every request Host-pinned (anti-rebinding) + CSRF on
  writes. 401 = login, 403 = Host/CSRF.

## Features (what shipped this cycle, newest first)

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
  compiled binaries + a multi-arch image (no push unless `PUSH=1`). For Synology I
  build per-arch + rewrite the tarball `RepoTags` to a bare `tsctl:<ver>` (no
  registry → `pull_policy: never` works) into `./dist/` (gitignored). Current local
  build: **v0.2.0** (`dist/tsctl-v0.2.0-linux-{amd64,arm64}-image.tar.gz`).
- **Publish a release:** `git tag vX.Y.Z && git push --tags` → `.github/workflows/
  release.yml` builds + pushes `ghcr.io/lifeart/tsctl:<tag>`+`:latest` and attaches
  binaries to a GitHub Release. **v0.2.0 is NOT yet tagged/pushed** — do this when
  ready to publish the current HEAD.
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
internal/sse/     single-goroutine, latest-wins broadcast hub
internal/api/     handlers + fail-closed auth/CSRF/Host middleware; wire DTOs
internal/groups/  persisted zone store (atomic JSON)
internal/demo/    scripted offline World for `tsctl demo`
web/              embedded SPA (app.js, index.html, style.css)
demo/             GitHub-Pages live demo (mock.js monkeypatches fetch+EventSource)
deploy/           systemd unit + Synology compose
docs/design/      zones, ip-password-ssh, keep-egress
```
