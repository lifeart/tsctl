# tsctl — Tailscale exit-node manager

Single Go binary. Joins the tailnet as its own `tsnet` node (`tag:tsctl`,
persistent, non-ephemeral), serves a small web UI **over the tailnet** (and,
optionally, a password-protected host port), lists Tailscale nodes, and lets you
set which exit node each OpenWRT router uses — in real time, in a drag-to-rewire
**zone graph**. Nothing runs on the routers but the Tailscale they already have.

**▶ Live demo (no install, no backend):** <https://lifeart.github.io/tsctl/> —
the real web UI driven entirely by mock data in your browser. *(Deploys from
[`.github/workflows/pages.yml`](.github/workflows/pages.yml) once GitHub Pages is
enabled for the repo: Settings → Pages → Source: GitHub Actions. You can also run
it locally with `tsctl demo`.)*

See [DESIGN.md](DESIGN.md) — the locked single source of truth.

> **Status: feature-complete (v1), verified in-repo.** Implemented: tailnet
> inventory (netmap) + per-router exit-node control over SSH with a dead-man's
> switch (poller/router); a live SPA with a **zone graph** as the default view;
> **server-side zones** (groups) with enforced allowed-exit-nodes; auth on **two
> paths** (tailnet `WhoIs` owner *and* an optional password-protected host port),
> plus opt-in per-zone **guest credentials** ([guest mode](#guest-mode)); two
> router transports (**Tailscale SSH** default, opt-in **ip-password**);
> router auto-discovery. `go build ./...`, `go vet ./...`, and `go test -race ./...`
> pass, including a full-stack integration test (`internal/integration`). The
> **live** UI→router→UI flow needs a real tailnet — see
> [End-to-end verification](#end-to-end-verification); v1 limitations are at the
> bottom.

## Web UI — the zone graph

The default view is a **bipartite graph**: the routers you control on the left
(*consumers*), the exit nodes on the right, and a wire from each router to the
exit node it's currently using. Drag a router's wire onto another exit node (or
focus it and press Enter for a keyboard menu) and confirm — the change runs the
dead-man's-switch on the router and the wire only moves once the device confirms
(never optimistic). A wire is colored by the device's real state (ok / applying /
unconfirmed / control-error / offline).

```
   ZONE: Work ▾     [ New zone ] [ Edit ] [ Delete ]
   CONSUMERS                          EXIT NODES
   ┌────────────────────┐            ┌──────────────────────┐
   │ office-router    ● ●───────────▶● exit-tokyo      online│
   │   → exit-tokyo       │       ┌──▶● exit-frankfurt  online│
   │ warehouse-router ● ●─┘ (out of zone, dashed)
   │   → exit-london      │          ● exit-london   offline │  ← out of zone
   └────────────────────┘            ┌──────────────────────┐
                                      │ Direct — no exit node│
                                      └──────────────────────┘
   drag a consumer onto an exit node, or press Enter for the menu
```

**Zones** (groups) scope and **enforce** the graph: a zone is a named set of
consumers + the exit nodes they're *allowed* to use. The backend rejects an
out-of-zone target (the union of a consumer's zones), so the policy holds no
matter how the change is issued. Zones are server-side (`$STATE_DIR/groups.json`)
and edited in the UI; a "Devices" tab shows the classic per-router cards.

Each router card (and consumer) has a **Test SSH** button: a one-off, read-only
diagnostic over the configured router transport that proves connectivity *end to
end* (dial → auth → exec) and prints live stats (kernel, uptime, load, memory).
On success you get `✓ SSH OK · <ms>` + the output; on failure the **exact reason**
(auth / host-key mismatch / offline / no address mapping). It is **manual** — tsctl
never auto-probes; this is how you check a device, especially one the non-exit-node
fallback listed as "not probed".

Try all of it — drag, zones, the offline/unconfirmed/control-error states, the
enforcement rejection — in the [live demo](https://lifeart.github.io/tsctl/) or
locally via `tsctl demo`.

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

`tsctl version` prints the build version (stamped at release time); `tsctl help`
lists the subcommands. Unknown commands fail loudly (they are never silently
ignored).

### Releases

[`scripts/release.sh`](scripts/release.sh) builds cross-compiled static binaries
(`dist/tsctl-<ver>-<os>-<arch>` + `SHA256SUMS`) and a **multi-arch** container
image named with a fully-qualified registry path — so podman never adds a
`localhost/` prefix:

```sh
scripts/release.sh v0.1.0                  # binaries + local linux/amd64+arm64 image
PUSH=1 scripts/release.sh v0.1.0           # also push to ghcr.io
PLATFORMS=linux/amd64 scripts/release.sh   # amd64-only (e.g. an Intel NAS)
```

It works with podman (manifest) or docker buildx. The image cross-compiles via
`$BUILDPLATFORM`, so an arm64 host builds linux/amd64 with no QEMU. CI
(`.github/workflows/release.yml`) does the same automatically on a `v*` tag:
attaches the binaries to a GitHub Release and pushes
`ghcr.io/<owner>/tsctl:<tag>` + `:latest`.


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

### What you need to authenticate (checklist)

Everything required to bring tsctl up, in one place. A copy-paste template is in
[`.env.example`](.env.example).

1. **A Tailscale enrollment token** (`TS_AUTHKEY`) — one of:
   - **OAuth client secret** (recommended, never expires): admin console →
     OAuth clients → scope **`auth_keys`**, tag **`tag:tsctl`** → use the
     `tskey-client-…` secret.
   - **Tagged auth key**: Keys → Generate, tag **`tag:tsctl`** (+ Pre-approved
     if device approval is on) → `tskey-auth-…`.
   - Needed only for the first run; after that the node key lives in the state
     dir. (An API token `tskey-api-…` will **not** enroll a node.)
2. **The owner login** (`TSCTL_OWNER`) — your exact tailnet email; the only
   identity allowed to view/control (everyone else is denied, fail-closed).
3. **Router IPs** (`TSCTL_ROUTERS`) — *optional.* Leave empty and tsctl
   auto-discovers every `tag:router` node; set it only to pin an explicit subset.
   **No `tag:router` nodes at all?** tsctl falls back to listing *every non-exit
   node* as a controllable consumer (so you needn't tag anything) — but it does
   **not** auto-SSH them; a tailnet can have many devices. They show **"not
   probed"** until you click **Test SSH** or set an exit node (both contact the
   device on demand). Only `tag:router`/`TSCTL_ROUTERS` devices are actively
   polled — tag your routers (or pin them) to scope that set.
4. **The ACL** below (`tag:tsctl` → `tag:router`, ssh `accept`, `users:["root"]`).
5. **Tailscale SSH enabled on each router** (`tailscale set --ssh`).

### Configuration (flags & env)

Config is **flags + env only** (no YAML, no committed secrets); every flag has an
env equivalent.

| Flag | Env | Default | Required | Purpose |
|---|---|---|---|---|
| *(token)* | `TS_AUTHKEY` | — | first run | Tailscale enrollment token (see above); or systemd `LoadCredential` `ts_authkey` |
| `-owner` | `TSCTL_OWNER` | — | one of† | tailnet login allowed to control (tailnet auth path) |
| `-ui-password` | `TSCTL_UI_PASSWORD` | — | one of† | shared password for the host-port/session auth path; **required** when `-http-listen` is set |
| `-http-listen` | `TSCTL_HTTP_LISTEN` | — (off) | no | ALSO serve the UI+API on this host socket, e.g. `:8080` (separate from `/healthz`); requires `-ui-password` |
| `-routers` | `TSCTL_ROUTERS` | — (auto) | no | comma-separated router `100.x` IPv4s; **empty = auto-discover all `tag:router` nodes** (or, if none exist, list every non-exit node as an unprobed consumer — see the checklist) |
| `-hostname` | `TSCTL_HOSTNAME` | `tsctl` | no | node hostname; the UI URL `http://<hostname>/` |
| `-state-dir` | `TSCTL_STATE_DIR` | `./tsnet-state` (or systemd `STATE_DIRECTORY`) | no | node key store — **must persist** (treat as a private key) |
| `-listen` | `TSCTL_LISTEN` | `:80` | no | tailnet-side listen address |
| `-healthz` | `TSCTL_HEALTH_ADDR` | `127.0.0.1:8088` | no | loopback-only health endpoint |
| `-ssh-user` | `TSCTL_SSH_USER` | `root` | no | router SSH login |
| `-router-transport` | `TSCTL_ROUTER_TRANSPORT` | `tailscale-ssh` | no | router command transport: `tailscale-ssh` (default) \| `tailnet-password` \| `ip-password` (opt-in; see [Router transport](#router-transport)) |
| `-router-hostkey-mode` | `TSCTL_ROUTER_HOSTKEY_MODE` | `tofu` | no | ip-password host-key verification: `tofu`\|`strict`\|`pin`\|`insecure` |
| `-router-addrs` | `TSCTL_ROUTER_ADDRS` | — | for `ip-password` | `100.x=host[:port]` LAN-endpoint map; the `100.x` stays the router identity (unmapped routers fail loudly) |
| *(secret)* | `TSCTL_SSH_PASSWORD` | — | for `ip-password` / `tailnet-password` | router SSH password; env or systemd `LoadCredential`/Docker secret `ssh_password` — **never a flag, never logged** |
| `-exit-node-lan-access` | `TSCTL_EXIT_NODE_LAN_ACCESS` | `preserve` | no | manage `--exit-node-allow-lan-access`: `preserve`\|`true`\|`false` |
| `-allowed-hosts` | `TSCTL_ALLOWED_HOSTS` | — | no | extra Host values to allow (rebinding defense); hostname/MagicDNS/`100.x` auto-trusted |
| `-poll-interval` | `TSCTL_POLL_INTERVAL` | `30s` | no | refresh cadence while a client is connected |
| `-ssh-timeout` | `TSCTL_SSH_TIMEOUT` | `15s` | no | per dial/exec SSH deadline |
| `-debug` | `TSCTL_DEBUG` | off | no | verbose tsnet backend logs |

† **At least one auth method is required.** serve needs `TSCTL_OWNER` (the
tailnet path: a request is admitted when Tailscale's `WhoIs` identifies the
caller as this owner) and/or `TSCTL_UI_PASSWORD` (the password path: sign in to
get a signed-cookie session). With both, either works; the tailnet owner is never
shown the login form. A failed auth is **401** (the SPA shows a login form);
**403** is reserved for Host/CSRF (DNS-rebinding) failures. Sessions are signed
with a random per-process secret, so a restart invalidates them (sign in again).

Both of those auth paths yield a **full-access admin**. There is also a second,
lower-privilege access level — per-zone **guest** credentials — see
[Guest mode](#guest-mode) below. It needs no config (it's managed in the UI) and
nothing changes until you create a guest.

After first enrollment the node key lives in the state dir and `TS_AUTHKEY` is no
longer needed — drop it.

**Your router's other settings are preserved.** Changing an exit node runs an
incremental `tailscale set --exit-node=…` on the router — never `tailscale up`
(which would reset unspecified prefs). So advertise-routes, accept-routes,
`--ssh`, accept-dns, hostname, advertise-tags, etc. survive both the change and
the dead-man's-switch revert. The one exception is `--exit-node-allow-lan-access`:
by default tsctl **preserves** it too (`TSCTL_EXIT_NODE_LAN_ACCESS=preserve`); set
it to `true`/`false` only if you want tsctl to manage that single flag.

### Router transport

How tsctl reaches a router to read/set its exit node. The default is
**`tailscale-ssh`** and you should keep it: tsctl dials the router's `:22` over
the tailnet with `none` auth, gated by the [ACL](#required-acl). There is no
router-side password, and the host key is implicitly trusted because WireGuard
already authenticates the peer.

The opt-in **`tailnet-password`** transport
(`TSCTL_ROUTER_TRANSPORT=tailnet-password` + `TSCTL_SSH_PASSWORD`) keeps dialing
the router's **`100.x` over the tailnet** (via tsctl's own tsnet node, exactly
like `tailscale-ssh`) but authenticates with a **password** to the router's own
sshd/dropbear. This is the option to reach for when you want password auth and
**don't** want to enable Tailscale SSH on the routers: there is **no LAN-endpoint
map** and **no `tailscale set --ssh`** needed. Because tsnet reaches the `100.x`
directly, it works from any network position — notably a **bridged Docker
container** (e.g. on a NAS) whose host can't route to `100.x` with a plain dialer.
The host key is implicitly trusted (WireGuard authenticates the peer, as for
`tailscale-ssh`); the password just authenticates *tsctl* to the router and travels
inside the encrypted tunnel. It needs an ACL **`tcp` grant to `:22`** on the
routers (the regular port — *not* the Tailscale-SSH `ssh` action), and a router
**root password set** (`passwd`; dropbear rejects empty passwords). Same secret
handling as below.

The opt-in **`ip-password`** transport (`TSCTL_ROUTER_TRANSPORT=ip-password`)
instead SSHes to the router's **LAN IP** with a shared password — useful to skip
the router-side Tailscale-SSH plumbing (the ACL `ssh` rule, the `tag:router` SSH
grant, `tailscale set --ssh` on every router). It does **not** remove Tailscale:
the tsnet node still provides inventory, online state, exit-node candidates, the
UI listener, and owner identity — only the *router command transport* changes.
Understand the trade-offs before enabling it:

- **Weaker than Tailscale SSH.** It swaps ACL-governed, per-identity, revocable
  access for a flat reusable root secret with no central revocation, no per-source
  ACL, and no audit trail. Reasonable only on a **trusted, single-operator LAN**.
  **Keys still beat passwords** — prefer SSH keys / `dropbear authorized_keys`
  even here.
- **Host-key verification is mandatory** (and on by default). Over plain LAN there
  is no WireGuard peer auth, so an unverified host key lets an active MITM complete
  the handshake and harvest the root password. Modes:
  - **`tofu`** (default) — trust-on-first-use: a new router's host key is recorded
    in `$STATE_DIR/known_hosts` (0600) and accepted; a **changed** key is refused
    hard ("possible MITM") and **never** auto-trusted.
  - **`strict`** — accept only host keys already present in `known_hosts` (you
    pre-seed it); unknown hosts fail.
  - **`pin`** — v1: identical to `strict` against a pre-seeded per-router entry
    (the pinned key is the only match).
  - **`insecure`** — no host-key verification. tsctl logs a loud startup warning;
    use only for throwaway testing on a trusted segment.
- **Identity stays the 100.x.** The router's `100.x` IPv4 remains its identity
  everywhere (inventory, `--exit-node` arg, store keys). You map each router to a
  LAN endpoint with `TSCTL_ROUTER_ADDRS=100.x=host[:port]` (`:22` assumed when no
  port). A router with **no mapping fails loudly** at use-time — tsctl never
  silently falls back to the tailnet path. (Routers may be auto-discovered, so the
  mapping is checked per router when used, not at startup.)
- **The password is a secret**, loaded like the auth key: `TSCTL_SSH_PASSWORD`
  env, or systemd `LoadCredential` / a Docker secret read via
  `$CREDENTIALS_DIRECTORY/ssh_password` (tmpfs) — never a flag, never logged. tsctl
  refuses to start `ip-password` without a password. (OpenWRT/dropbear: password
  auth works only once a **root password is set** — `passwd` first; fresh OpenWRT
  rejects empty passwords.)

Prove it before trusting the full binary with `tsctl spike` (below) — for
`ip-password` it dials the mapped LAN endpoint with the password and host-key
check, no tailnet required.

Health check (loopback only, never exposed to the tailnet or LAN):

```sh
curl http://127.0.0.1:8088/healthz
```

### Guest mode

Both auth paths above make you a **full-access admin**. **Guest mode** adds a
second, lower-privilege access level so you can **hand someone a password for one
zone without admin concerns** — they can flip that zone's routers between its
allowed exit nodes, and see and do nothing else on the fleet. There is **no flag
or config** for it: it's managed in the UI, and behavior is unchanged until you
create the first guest. Full design: [docs/design/guest-mode.md](docs/design/guest-mode.md).

**Create / revoke a guest (admin, in the UI).** As an admin, open the **Guests**
panel and create a guest with a **label**, the **one zone** it manages, and a
**password** (8–72 chars). The password is bcrypt-hashed on the server
(`$STATE_DIR/guests.json`, 0600) and the hash never leaves the server or appears
in any response — so the list only ever shows label / zone / created date /
enabled-or-disabled status (never a password or hash).
**Disable** (toggle) or **delete** a guest to revoke it; either takes effect on
the guest's very next request (you can't delete a zone while a guest is still
assigned to it — reassign or remove the guest first).

**Signing in as a guest.** On the login form, enter the **guest label** and its
password (leaving the label empty is the admin/`UIPassword` path). A guest then
sees a single-zone view:

- **Can:** see only their zone — its routers and that zone's allowed exit nodes —
  and change those routers' exit nodes (restricted to the allowed list; the
  current exit node is auto-resolved, so there's no manual *Test SSH*).
- **Can't:** see or touch any other zone or router, edit zones, manage guests, or
  use the device tools. Those affordances are hidden, but the **server**, not the
  UI, is what enforces it.

**Security properties.** Enforcement is **server-side**: every guest write is
re-checked against the guest's *own* live zone (allowed routers + allowed exit
nodes — stricter than the cross-zone poller check), all zone/guest management is
admin-only (403 for a guest), and out-of-zone reads are filtered or return a 404
with no oracle. The role is carried unforgeably inside the signed session cookie
(a tampered role fails the HMAC; a guest cookie can never assert admin), and the
zone binding is re-resolved from the store on every request, so a disable/delete
revokes access immediately (within one heartbeat, ~20s, for the live event
stream). Passwords are bcrypt (cost 12); the hash never reaches the wire or the
logs.

> ⚠️ **Plain-HTTP caveat (same as the admin's).** Guest passwords and session
> cookies travel exactly like the admin's: over the tailnet WireGuard protects
> them, but the optional **host port is plain HTTP** — on any shared/untrusted
> network, front the host port with a **TLS reverse proxy** (see the host-port
> note under [Run on a NAS](#run-on-a-nas-docker)). Guest mode does not
> change the transport; it relies on the same protection.

## `tsctl spike` — prove the router transport on your real network

No agent here has a live tailnet or router. **You** must prove the router
transport before trusting the full binary. `spike` honors the **configured
transport** — it builds the same `router.Client` the server uses, runs
`tailscale status --json` against ONE router, and prints a summary (online state,
the current exit node, and the available options):

```sh
export TS_AUTHKEY=tskey-auth-xxxxx        # tailscale-ssh: first run only
./tsctl spike 100.64.0.10                 # the router's 100.x IPv4
```

- **`tailscale-ssh` (default):** brings tsnet up and dials the router's `:22`
  over the tailnet with `none` auth. If it prints the router's status, the ACL
  and SSH path are correct.
- **`ip-password`:** with `TSCTL_ROUTER_TRANSPORT=ip-password` (plus
  `TSCTL_SSH_PASSWORD` and a `TSCTL_ROUTER_ADDRS` mapping for that `100.x`), it
  dials the **mapped LAN endpoint** with the password and host-key verification —
  **no tsnet needed**, so it proves the password path in isolation. On first
  contact under `tofu` it records the router's host key in
  `$STATE_DIR/known_hosts`.

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
   `unconfirmed` / `unreachable` with the error — never a false success. Once the
   device settles on an actual selection (its previous exit node after a revert, or
   any node you set on it directly), tsctl **re-reads and adjusts** the view to that
   selection after one revert window — `unconfirmed` is never a permanent state.

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

## Run on a NAS (Docker)

tsctl is a great NAS workload: `tsnet` does **userspace** networking, so the
container needs **no `NET_ADMIN`, no `/dev/net/tun`, no host networking** — just
outbound internet to reach Tailscale. The image is a ~24 MB static binary on
distroless, running **nonroot**. Works on Synology Container Manager, QNAP
Container Station, Unraid, TrueNAS, Portainer, or plain `docker`/`podman`.
**Synology users:** a ready-made Container Manager project (UI on port 8087) is in
[`deploy/docker-compose.synology.yml`](deploy/docker-compose.synology.yml).

```sh
docker build -t tsctl:latest .                 # or pull a published image
```

Two things are mandatory for a NAS deployment:

1. **Persist the state directory.** Mount a volume at `/var/lib/tsctl`. It holds
   the node's identity key; if it's lost, the node re-registers as a brand-new
   device on every restart (new IP, ACL churn). The compose file uses a named
   volume `tsctl-state`.
2. **Make that volume writable by the container.** The image runs **nonroot**
   (uid `65532`). If the volume or bind dir is **root-owned** — common on
   Synology/DSM — tsnet fails at boot with `permission denied` on
   `/var/lib/tsctl/…`. Fix it by **running the container as root** (`user: "0:0"`,
   which the [Synology compose](deploy/docker-compose.synology.yml) does — the
   container is the security boundary), **or** by making the dir writable by
   `65532` (bind mount → `chown -R 65532:65532 <hostdir>`; named volume →
   `docker run --rm -v tsctl-state:/s busybox chown -R 65532:65532 /s`).
3. **Authenticate headlessly** (no interactive login on a NAS — see below).

Then, with [`docker-compose.yml`](docker-compose.yml):

```sh
export TS_AUTHKEY=tskey-client-XXXX            # see auth options below
export TSCTL_OWNER=you@example.com             # tailnet login allowed to control
export TSCTL_ROUTERS=100.64.0.10,100.64.0.11   # your OpenWRT routers' 100.x IPv4s
# Host-port UI (the shipped compose publishes one — see below):
export TSCTL_UI_PASSWORD='a-strong-password'   # required to expose the UI on a host port
export TSCTL_ALLOWED_HOSTS=nas.local,192.168.1.50  # the NAS hostname/IP you browse to (no port)
docker compose up -d
docker compose logs -f tsctl                   # watch enrollment
```

**Reaching the UI — two ways:**

1. **Over the tailnet (always on).** From any device on your tailnet, open
   `http://tsctl/` (the `-hostname`, via MagicDNS) or the node's `100.x` IP. On
   this path you're authenticated by your Tailscale identity (`TSCTL_OWNER`) — no
   password prompt.
2. **From your LAN, on a published host port (optional, password-protected).**
   Set `TSCTL_HTTP_LISTEN` (the shipped compose uses `:8080`) and publish it with
   `ports: ["8088:8080"]`, then browse to `http://<nas>:8088/`. Because this
   socket can be reached without a tailnet identity, it **requires a password**
   (`TSCTL_UI_PASSWORD`) — tsctl refuses to start an unauthenticated host UI — and
   you get a sign-in form. **You MUST add the hostname/IP you browse to (without
   the port) to `TSCTL_ALLOWED_HOSTS`** (e.g. `nas.local`, `192.168.1.50`), or the
   anti-DNS-rebinding Host check blocks the page. The `TSCTL_HTTP_LISTEN` host and
   the tsnet hostname/MagicDNS/`100.x` are trusted automatically.

   > ⚠️ **The host port is plain HTTP** — unlike the tailnet path (encrypted by
   > WireGuard), the password and the session cookie cross this socket in the
   > clear. That's fine on a trusted home LAN, but on any shared/untrusted network
   > **front it with a TLS reverse proxy** (Caddy / Nginx Proxy Manager / your
   > NAS's HTTPS) and point browsers at the HTTPS endpoint. Sessions are signed,
   > HttpOnly, `SameSite=Strict`, and reset on restart, but TLS is what protects
   > the password in transit.

`/healthz` stays bound to loopback *inside* the container by design (it's a
security boundary, not a NAS health endpoint, and is separate from the host-port
UI); rely on the container restart policy + the Tailscale admin console for
liveness.

### Authenticating Tailscale on a headless NAS

tsctl joins the tailnet as a **tagged** node (`tag:tsctl`). Tagged nodes can't be
brought up by an ordinary interactive user login, so you give it a **token once**
via `TS_AUTHKEY`. After first enrollment the node key lives in the `tsctl-state`
volume and the token is no longer used — you can delete it from the environment.
Tagged nodes have **key expiry disabled by default**, so it never needs re-auth.

Pick one (in the [Tailscale admin console](https://login.tailscale.com/admin)):

- **OAuth client secret — recommended for a NAS.** Settings → OAuth clients →
  generate a client with the **`auth_keys`** scope and tag **`tag:tsctl`**. Use
  its secret (`tskey-client-…`) as `TS_AUTHKEY`. OAuth client secrets **don't
  expire**, so even a wiped state volume re-enrolls with no manual step.
- **Tagged auth key — simplest.** Settings → Keys → Generate auth key; enable
  **Pre-approved** (if device approval is on) and add the tag **`tag:tsctl`**. Use
  the `tskey-auth-…` value as `TS_AUTHKEY`. Auth keys expire in ≤90 days, but
  since it's only needed for the one-time enrollment that's fine.
- **Interactive web login — possible, not ideal.** If you start tsctl with **no**
  `TS_AUTHKEY`, tsnet prints an `https://login.tailscale.com/…` URL to its logs
  (`docker compose logs tsctl`); open it in a browser and approve. Caveat: a user
  login won't apply `tag:tsctl` unless you're a tag owner, so you'd then have to
  tag the device in the console. The token paths above avoid that — prefer them.

> Note on token types: `tskey-auth-…` (auth key) and `tskey-client-…` (OAuth
> client secret) both work as `TS_AUTHKEY`. An **API access token**
> (`tskey-api-…`) is for the REST API and will **not** enroll a node — don't use
> it here. tsctl v1 needs no API token at all.

Don't forget the [Required ACL](#required-acl) and to enable Tailscale SSH on the
routers (see [End-to-end verification](#end-to-end-verification)) — the NAS host
only needs outbound internet; everything else rides the tailnet.

## Troubleshooting

tsctl logs to stderr and fails **loud** (no silent swallowing); with a restart
policy it will loop on a fatal startup error. Match the log line:

| Log line | Cause | Fix |
|---|---|---|
| `logpolicy.Config.Save … /var/lib/tsctl/…: permission denied` | The state volume isn't writable by the nonroot uid `65532` — NAS/DSM often creates it root-owned. | Run as root (`user: "0:0"`, as the Synology compose does) **or** `chown` the dir to `65532` — see [Run on a NAS](#run-on-a-nas-docker) step 2. |
| `tsnet.Up: backend: invalid key: unable to validate API key` | `TS_AUTHKEY` is bad: an **API token** (`tskey-api-…`, can't enroll a node), a typo / stray character (e.g. a doubled `t`), expired, revoked, single-use already used, or from another tailnet. | Use a **`tskey-auth-…`** auth key or **`tskey-client-…`** OAuth secret (never `tskey-api-…`); paste it whole, no spaces/line-breaks; regenerate if expired. See [authenticating headlessly](#authenticating-tailscale-on-a-headless-nas). |
| `tsnet.Up: backend: requested tags [tag:tsctl] are invalid or not permitted` | The tag can't be applied: `tag:tsctl` is **missing from the ACL `tagOwners`**, and/or the auth key **doesn't carry `tag:tsctl`**. | Add `tag:tsctl` (+ `tag:router`) to `tagOwners` (see [Required ACL](#required-acl)), **and** generate the auth key / OAuth client **with the `tag:tsctl` tag**. Both are required. |
| `LocalBackend state is NeedsLogin` repeating with one of the above | Not enrolled yet; tsnet keeps retrying the bad `TS_AUTHKEY`. | Fix the key/tag error above — it enrolls once, then persists and stops needing the token. If it still loops after a known-good key, the state volume may hold stale partial state: clear `tsctl-state` and retry. |
| UI on the host port shows a blank/blocked page; logs show a **403** | The anti-DNS-rebinding **Host check** rejected the address you browsed to. | Add that hostname/IP (without the port) to `TSCTL_ALLOWED_HOSTS` — see [Reaching the UI](#run-on-a-nas-docker). |
| Router shows **"Control error"** (online, but tsctl can't drive it) | SSH to the router failed: wrong `ssh`/`ip-password` setup — bad password, host-key mismatch, missing `TSCTL_ROUTER_ADDRS` mapping, or the ACL/`tailscale set --ssh` not done. | Click **Test SSH** on the router card for the exact reason, or prove the path in isolation with [`tsctl spike <100.x>`](#tsctl-spike--prove-the-router-transport-on-your-real-network). |

When in doubt, prove the two external dependencies separately before running the
full server: **enrollment** (the token + tags + ACL — the node appears in your
admin console tagged `tag:tsctl`) and the **router transport** (`tsctl spike`).

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
