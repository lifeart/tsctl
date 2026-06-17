# tsctl — Tailscale exit-node manager

Single Go binary. Joins the tailnet as its own `tsnet` node (`tag:tsctl`,
persistent, non-ephemeral), serves a small web UI **over the tailnet only**,
lists Tailscale nodes, and lets you set which exit node each OpenWRT router uses
— in real time. Nothing runs on the routers but the Tailscale they already have.

See [DESIGN.md](DESIGN.md) — the locked single source of truth.

> **Status: feature-complete (v1), verified in-repo.** All packages (netmap,
> router, poller, sse, api, the SPA) are implemented; `go build ./...`,
> `go vet ./...`, and `go test -race ./...` pass, including a full-stack
> integration test (`internal/integration`) that drives api→poller→router→
> store→SSE end to end. The **live** UI→router→UI flow still needs a real
> tailnet — see [End-to-end verification](#end-to-end-verification). Known v1
> limitations are listed at the bottom.

## Building

Requires **Go 1.26.4+** (the `go` directive in `go.mod`); with `GOTOOLCHAIN=auto`
(the default) an older `go` will fetch the right toolchain automatically. Built
against **tailscale.com v1.100.0**. CI (`.github/workflows/ci.yml`) runs gofmt,
`go vet`, `go build`, `go test -race`, and a `go mod tidy` check on every push/PR.

```sh
go build ./...                 # build everything
go vet  ./...                  # vet everything
go test -race ./...            # tests, race detector on
go build -o tsctl ./cmd/tsctl  # produce the binary
```

Preview the web UI offline (no tsnet, no tailnet, no router) with scripted,
time-varying fixtures — `./tsctl demo` serves the real SPA + API on
<http://127.0.0.1:8089> (Ctrl-C to stop). What you see is what prod renders.


Run the server (serves the SPA + API over the tailnet, `/healthz` on loopback):

```sh
# First enrollment needs a one-time tagged auth key (see ACL below).
export TS_AUTHKEY=tskey-auth-xxxxx
./tsctl \
  -hostname tsctl \
  -state-dir ./tsnet-state \
  -listen :80 \
  -healthz 127.0.0.1:8088 \
  -routers 100.64.0.10,100.64.0.11 \
  -ssh-user root
```

Config is **flags + env only** (no YAML, no committed secrets). Each flag has an
env equivalent: `TSCTL_HOSTNAME`, `TSCTL_STATE_DIR`, `TSCTL_LISTEN`,
`TSCTL_HEALTH_ADDR`, `TSCTL_ROUTERS`, `TSCTL_SSH_USER`, `TSCTL_DEBUG`, and
`TS_AUTHKEY`. After first enrollment the node key lives in the state dir and the
auth key is no longer needed — drop it.

Health check (loopback only, never exposed to the tailnet or LAN):

```sh
curl http://127.0.0.1:8088/healthz
```

## `tsctl spike` — prove the SSH path on your real tailnet

No agent here has a live tailnet or router. **You** must prove the
SSH-over-tailnet path before trusting the full binary. `spike` brings tsnet up,
dials the router's `:22` over the tailnet, SSHes with `none` auth, runs
`tailscale status --json`, and prints stdout/stderr/exit code:

```sh
export TS_AUTHKEY=tskey-auth-xxxxx        # first run only
./tsctl spike 100.64.0.10                 # the router's 100.x IPv4
```

If this prints the router's status JSON, the ACL and SSH path are correct.

## Required ACL

The tsnet node is tagged `tag:tsctl`; routers are tagged `tag:router`. A
**tagged** source cannot use SSH `check` mode, so `action:"accept"` is
guaranteed and automation never needs a browser. OpenWRT logs in as **root**;
`autogroup:nonroot` would silently exclude root, so `users` MUST list `root`.

```jsonc
{
  "tagOwners": {
    "tag:tsctl":  ["autogroup:admin"],
    "tag:router": ["autogroup:admin"]
  },
  "acls": [
    // tsctl must reach each router's SSH port over the tailnet.
    { "action": "accept", "src": ["tag:tsctl"], "dst": ["tag:router:22"] }
  ],
  "ssh": [
    {
      "action": "accept",                 // tagged src => check mode impossible
      "src":    ["tag:tsctl"],
      "dst":    ["tag:router"],
      "users":  ["root"]                  // OpenWRT logs in as root
    }
  ]
}
```

Also ensure the `tsctl` node retains ACL **visibility** to every router/peer you
inventory, or nodes silently vanish from the list (DESIGN §7).

## End-to-end verification

No agent has a live tailnet, so the real UI → router → UI flow can only be run by
**you**. The unit + seam tests prove the wiring; this proves the world. Run the
steps in order — each gates the next.

1. **Apply the ACL** above (`tag:tsctl` src → `tag:router:22` dst for the SSH
   transport, plus the `ssh` rule `action:"accept"`, `users:["root"]`). A tagged
   src cannot use `check` mode, so `accept` is guaranteed and unattended.
2. **Enable Tailscale SSH on each router.** The ACL only grants access; the
   router must also be running the Tailscale SSH server, or the dial reaches
   `:22` but no SSH responds:

   ```sh
   # on each OpenWRT router (logged in as root)
   tailscale set --ssh        # or: tailscale up --ssh ...
   tailscale status           # confirm the node is up and tagged tag:router
   ```

3. **Prove the SSH path with `spike`** before trusting the full binary:

   ```sh
   ./tsctl spike 100.64.0.10        # the router's 100.x IPv4
   ```

   It must print the router's `tailscale status --json`. If it errors, fix the
   ACL / SSH-enable (steps 1–2) before going further — the full binary uses the
   exact same path.

4. **Run the full binary** (see “Build & run”) and open the UI at the tsctl
   node's MagicDNS name over the tailnet (e.g. `http://tsctl/`). You should see
   the node list and a card per configured router.
5. **Exercise the control flow and observe all three layers:**
   - In the UI, on a router card, **pick an exit node** from the picker. The card
     shows `pending` / `applying` (never optimistic success).
   - On that router, `tailscale status` (or `tailscale status --json`) shows the
     **exit node actually switched** to the one you picked.
   - The UI **reflects the confirmed state**: the card flips to `ok` with the new
     `currentExitNode`, fed live by the SSE Snapshot stream. Picking “none”
     clears it the same way.

   If the change can't be confirmed within the revert window, the router's
   dead-man's-switch self-heals to the previous selection and the UI shows
   `unconfirmed` / `unreachable` with the error — never a false success.

Do not claim e2e success without completing steps 3–5 against a real router.

## Known limitations (v1)

- **Confirmation is selection + tailnet reachability, not egress.** When you set
  a router's exit node, the dead-man's-switch (DESIGN §8) re-reads the router's
  `tailscale status --json` and treats the change as confirmed when the device
  reports the target exit node **selected** and **reachable over the tailnet**.
  It does **not** probe actual internet **egress** through that exit node — a
  router that selected the exit node but cannot reach the internet through it
  still shows as `ok`.
- **No explicit user "Keep".** DESIGN §8 step 5 envisages an explicit operator
  "Keep" within the revert window. v1 instead **auto-keeps on confirmation**: the
  armed local revert fires only if the device can't be confirmed **at all** (the
  apply failed, the confirm read failed, or the selection didn't take). It does
  not fire merely because egress is broken while the selection looks correct.
- **Planned:** an explicit-user "Keep" gate plus an egress-reachability probe
  before keeping (tracked as Sec-M4).

## Deploy (systemd)

[`deploy/tsctl.service`](deploy/tsctl.service) is hardened per DESIGN §7:
`DynamicUser`, `StateDirectory=tsctl` (0700, treated as a private key — it *is*
root on the fleet), `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, empty `CapabilityBoundingSet`, `SystemCallFilter=@system-service`,
`Restart=on-failure`, `WatchdogSec`, and `LoadCredential=ts_authkey` (tmpfs —
the key never touches env or logs). The binary speaks `sd_notify`
(`READY=1` / `WATCHDOG=1`) so `Type=notify` + `WatchdogSec` work.

```sh
sudo install -m0755 tsctl /usr/local/bin/tsctl
sudo install -d -m0700 /etc/tsctl
sudo install -m0600 your.authkey /etc/tsctl/ts_authkey   # one-time, then remove
sudo install -m0644 deploy/tsctl.service /etc/systemd/system/tsctl.service
sudo systemctl daemon-reload && sudo systemctl enable --now tsctl
```

## Layout

```
cmd/tsctl/        composition root: config, tsnet Up->Listen, healthz, wiring, shutdown, spike
internal/store/   immutable Snapshot types + atomic.Pointer Store (the frozen contract)
internal/netmap/  Netmapper + WhoIser impl over LocalClient (stub)
internal/router/  SSH over tsnet.Dial; ParseStatus (pure); Status/SetExitNode (stub)
internal/poller/  declares Netmapper/RouterClient/RouterRuntime; idle-aware loop (stub)
internal/sse/     single-goroutine SSE hub (stub)
internal/api/     declares WhoIser; handlers + CSRF + WhoIs middleware (stub, fail-closed)
web/              embedded SPA (placeholder)
deploy/           hardened systemd unit
```
