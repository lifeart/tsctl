# tsctl — Tailscale exit-node manager

Single Go binary. Joins the tailnet as its own `tsnet` node (`tag:tsctl`,
persistent, non-ephemeral), serves a small web UI **over the tailnet only**,
lists Tailscale nodes, and lets you set which exit node each OpenWRT router uses
— in real time. Nothing runs on the routers but the Tailscale they already have.

See [DESIGN.md](DESIGN.md) — the locked single source of truth.

> **Status: Phase A scaffold.** The contract (`internal/store` types + the
> consumer-side interfaces), the composition root, the embedded SPA placeholder,
> the systemd unit, and a real `spike` subcommand are in place and compile.
> Package bodies (netmap, router, poller, sse, api handlers, the SPA) are stubs
> that return explicit `not implemented` errors — filled in Phase B.

## Build & run

```sh
go build ./...                 # build everything
go vet  ./...                  # vet everything
go build -o tsctl ./cmd/tsctl  # produce the binary
```

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
