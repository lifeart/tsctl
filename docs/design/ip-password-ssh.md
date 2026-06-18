# Design: over-IP SSH to routers with username/password (opt-in transport)

Status: **researched, not yet implemented.** Captures the exploration so it can be
built later. Recommendation: ship as an **opt-in** transport; keep Tailscale-SSH the default.

## Why (and the limit)
Today tsctl reaches routers via Tailscale SSH (`tsnet.Dial` + `none` auth). An
over-IP password transport would let an operator skip the fiddliest onboarding:
the ACL `ssh` `action:"accept"` rule, `tag:router`'s SSH grant, and
`tailscale set --ssh` on every router.

**It does NOT remove Tailscale.** tsctl uses the tailnet for two things — (1) the
router command transport (what this replaces) and (2) inventory + online state +
exit-node candidates (`LocalClient.Status()`) + the UI listener + owner identity
(`WhoIs`). Only (1) is replaced; the tsnet node and `tag:tsctl` stay. So the win is
"drop the router-side SSH plumbing," not "drop Tailscale."

## How (small, fits the existing seam)
The `commandRunner` / `DialFunc` seam already isolates the transport. Recommended:
parameterize `runSSH` with two fields on `Client` — `authMethods []ssh.AuthMethod`
and `hostKey ssh.HostKeyCallback` — and switch them by transport:
- **tailscale-ssh (default):** `dial = srv.Dial`, `authMethods = nil`, `hostKey = InsecureIgnoreHostKey()` (safe: WireGuard authenticates the peer).
- **ip-password:** `dial = (&net.Dialer{}).DialContext`, `authMethods = [ssh.Password(pw), ssh.KeyboardInteractive(...)]` (dropbear fallback), `hostKey =` a verifying callback (below).

Everything else — `ParseStatus`, the arm→apply→confirm→keep dead-man's-switch,
`applyCmd`, the per-addr lock, `cappedBuffer`, `CommandError`, `exitArg` — is
unchanged. The 100.x IPv4 stays the canonical router identity (netmap correlation,
`exitArg`, store keys); an optional `identity → SSH endpoint` map lets SSH target a
LAN IP without changing identity. Translate identity→endpoint ONLY at the `runSSH`
boundary (seam-verification note).

## OpenWRT / dropbear
- Root password auth is on by default **once a root password is set** (fresh
  OpenWRT has none and rejects empty passwords). `passwd` first.
- Modern dropbear advertises the `password` method directly → `ssh.Password` works;
  include `ssh.KeyboardInteractive` (answer every prompt with the password) as a
  fallback for older builds. Connection limits are irrelevant (one in-flight cmd
  per router via the existing lock).
- **Keys beat passwords** even here (`ssh.PublicKeys`, dropbear `authorized_keys`) —
  recommend them within this mode.

## Host-key trust (the critical security delta)
Over plain LAN there's no WireGuard peer auth, so `InsecureIgnoreHostKey` is **NOT**
acceptable for password auth — an active MITM completes the handshake and harvests
the root password. Use `golang.org/x/crypto/ssh/knownhosts`:
- Default mode **`tofu`** (trust-on-first-use): on first contact persist the key to
  `$STATE_DIR/known_hosts` (0600) and accept; on a **mismatch** hard-fail loudly
  ("host key changed — possible MITM"), never auto-trust.
- `strict` (pre-seeded known_hosts), `pin` (per-router fingerprint via
  `ssh.FixedHostKey`), and `insecure` (explicit opt-in, logged) modes.

## Config & secrets
- `-router-transport` / `TSCTL_ROUTER_TRANSPORT` = `tailscale-ssh` (default) | `ip-password`.
- `-router-hostkey-mode` / `TSCTL_ROUTER_HOSTKEY_MODE` = `tofu` | `strict` | `pin` | `insecure`.
- Credentials: `TSCTL_SSH_PASSWORD` (shared) loaded like `loadAuthKey()` (env or
  systemd `LoadCredential` on tmpfs; never logged), or a per-router 0600 JSON
  credentials file (user/password/hostKey/keyFile), or keys.
- `validate()`: if transport=ip-password, REQUIRE a credential and a non-`insecure`
  host-key mode by default (fail-closed).

## Security posture
- The password is SSH-encrypted in transit (not cleartext on the wire); the real
  risk is MITM without host-key verification → mandatory host-key checking above.
- Weaker than Tailscale-SSH's ACL-governed identity: a flat reusable root secret,
  no central revocation, no per-source ACL, no audit trail. Acceptable on a
  trusted, single-operator LAN with host-key pinning + ideally keys. NOT for
  untrusted L2, WAN-facing dropbear, or multi-tenant/compliance.

## Implementation plan (when greenlit)
1. `internal/router/router.go` — add `authMethods` + `hostKey` to `Client`; in
   `runSSH` swap only `Auth:` and `HostKeyCallback:`; change `New` to an options
   struct (the frozen `commandRunner`/`RouterClient` seams are unaffected).
2. `internal/router/hostkey.go` (new) — knownhosts wrapper with tofu/strict/pin/
   insecure; concurrency-safe append to `known_hosts`; distinguish
   `KeyError.Want==""` (unknown → TOFU add) vs non-empty (mismatch → hard fail).
3. `cmd/tsctl/config.go` + `main.go` — new flags/env, `loadSSHPassword()`, build
   `router.Options`; optionally a `spike --ip-password` to prove the path.
4. `deploy/tsctl.service` (`LoadCredential=ssh_password`), `docker-compose.yml`
   (`secrets:`), `.env.example`, README (transport + host-key modes + LAN-trust
   caveats).
5. Tests: pure host-key-layer unit tests (tofu add / mismatch reject / pin / strict);
   the existing fake-runner command-sequence tests stay unchanged; a dropbear-
   container or `spike` integration smoke for real password auth.

Default stays `tailscale-ssh`. Document loudly that `ip-password` trades
ACL-governed identity for a flat secret and requires host-key verification.
