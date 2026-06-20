# Design: guest mode (per-zone scoped credentials)

Adds a second, lower-privilege access level on top of the existing admin auth.
Until now tsctl had exactly one access level: anyone who passes auth (tailnet
`WhoIs` owner, or the shared `UIPassword`) gets **full** control of the whole
fleet. Guest mode lets an admin hand someone a password for **one zone** —
"manage these routers' exit nodes and nothing else" — without trusting them with
the rest of the network.

Default behavior is **byte-for-byte unchanged when no guests exist**: the guest
store is created but empty, the admin paths are untouched, and the guest CRUD
routes are dormant. Implemented in `internal/guests`, `internal/authz`, and the
`internal/api` / `internal/sse` request paths (no new flag — guest mode is
always available in `serve`, but does nothing until the admin creates a guest).

## The model

Exactly **two roles**, resolved on every request into an `authz.Subject`:

- **Admin** — the tailnet owner (`WhoIs` == `TSCTL_OWNER`, untagged) **or** the
  shared `TSCTL_UI_PASSWORD`. Unchanged, always full-access. The tailnet-owner
  admin is `WhoIs`-only and is **never** expressible through a cookie.
- **Guest** — `Subject{Admin:false, GuestID, ZoneID}`, bound to exactly **one
  zone** (a `groups.Store` group). A guest may:
  - **see** only its zone — its consumer routers and that zone's allowed exit
    nodes; everything else on the fleet is filtered out;
  - **change** those routers' exit nodes, restricted to the zone's
    `AllowedExitNodes` (or clear/Direct).

  A guest may **not**: see or touch any other zone or router, edit zones, manage
  guests, or use the device tools. In the UI the manual **Test SSH** button is
  hidden and the current exit node is auto-resolved (a single zone-scoped probe
  on first load) instead.

The server is the source of truth. The SPA gating and the filtered snapshot are
defense-in-depth only; every guest **write** is independently authorized.

## The credential store (`internal/guests`)

Mirrors `internal/groups` structurally: a mutex-guarded, file-backed store
persisted atomically (temp + fsync + rename) to **`$STATE_DIR/guests.json`**,
**0600** (it holds password hashes). A missing file is an empty set; a corrupt
file is **fatal** at startup (never silently start empty and clobber the
operator's guests). A guest record:

```
{ id, label, zoneId, passwordHash, disabled, createdAt }
```

- `passwordHash` is **bcrypt, cost 12**. The hash **never leaves the package**:
  every public accessor returns the hash-free `store.Guest` projection, the
  `api.GuestStore` interface (declared consumer-side) carries no hash, and no DTO
  has a hash field. Only `Authenticate` ever touches a hash, internally.
- `Authenticate(label, pw)` always runs **one** bcrypt compare — the real one for
  a known label, a precomputed **dummy** compare for an unknown label — so a
  missing label costs ~the same CPU (no user-enumeration timing oracle). A
  disabled guest is rejected **after** the compare (disabled vs wrong-password are
  indistinguishable by timing). Nothing is ever logged.
- Validation: non-empty label, unique label (case-insensitive), real zone,
  password **8–72 bytes** (bcrypt consumes only the first 72). IDs are 8 random
  bytes (16 hex chars).

## The session-subject cookie

The signed `tsctl_session` cookie is extended so the **role + guest id live
inside the HMAC-covered region**:

```
SIGNED = expiry(8) || nonce(16) || role(1) || guestIDLen(1) || guestID(N)
cookie = base64url( SIGNED || HMAC-SHA256(secret, SIGNED) )
```

- The MAC covers the role byte and the guest id, so a tampered role fails the
  constant-time compare — a guest cookie can never assert admin. Parsing is
  fail-closed on any decode/length/MAC/expiry/role problem.
- The secret is a random per-process 32 bytes (a restart drops all sessions).
  TTL 7 days; `HttpOnly`, `SameSite=Strict`, `Path=/`. `Secure=false` — the
  listeners are plain HTTP (WireGuard encrypts the tailnet; the host port is
  documented plain HTTP, see the caveat below).
- **The zone is NOT in the cookie.** Only `Admin` and `GuestID` are encoded; the
  `ZoneID` is re-resolved live from the guest store on **every request**
  (`resolveSubject`). This is what makes revocation instant and the zone binding
  always current.
- Login body is `{label, password}`: an **empty label** is the admin path
  (constant-time compare vs `UIPassword`); a non-empty label is the guest path
  (`guests.Authenticate`). One bcrypt verify per attempt (no fan-out DoS), a
  uniform 401 on failure (no admin-vs-guest oracle), the existing
  `loginFailDelay` kept. `GET /api/me` reports `{role, zoneId, zoneName}`.

## The three authorization choke points (server-side source of truth)

1. **`RequireAdmin`** — wraps **all** group CRUD and **all** guest CRUD
   (`GET/POST /api/groups`, `…/groups/{id}`, `GET/POST /api/guests`,
   `…/guests/{id}/disabled`, `DELETE …/guests/{id}`). A guest gets **403**, not
   zone-management or guest-management power.

2. **`authorizeRouterWrite`** — at the top of every router write/probe:
   `handleSetExitNode`, `handleKeep`, `handleProbe`. Admin → allow. Guest →
   re-load its **own** zone live from the group store and require
   `routerID ∈ zone.Consumers` and, for a set, `target ∈ zone.AllowedExitNodes`
   (clear needs only membership). Every denial is an **identical 403 with no
   detail** (no oracle: "not your router" / "not allowed target" / "zone gone"
   are indistinguishable). This is **deliberately stricter than the poller's
   `allowedExitNodeSet`** (the union across all zones a consumer belongs to): a
   guest is confined to its **single** zone, which closes the shared-router
   escalation where a router in two zones could otherwise be sent to the *other*
   zone's allowed target. The poller's enforcement stays as a second layer.
   Authorization here is **independent of the snapshot filter**, so a filter bug
   can never grant a write.

3. **Zone-scoped reads (no oracle)** — `GET /api/nodes` returns only the guest's
   zone-filtered node set; `GET /api/routers/{id}` for an out-of-zone router
   returns **404**, identical to a truly missing router (not an oracle for what
   exists elsewhere); `/api/groups` and `/api/guests` are admin-only. Reads
   **fail closed** on a missing subject (401), matching the write path.

## The per-connection snapshot filter (defense-in-depth)

`authz.FilterSnapshotToZone(snap, zoneID)` is a **pure** scoper: it never mutates
the shared snapshot (the single value the poller owns), returning a new one with
just that zone's `GroupView`, the nodes in its `Consumers ∪ AllowedExitNodes`
(offline allowed exits **kept** so the guest's picker matches the admin's), and
the routers whose node is a consumer. `NetmapAt`/`NetmapErr`/`BuiltAt` carry
through; an unknown/empty zone yields an empty-but-non-nil snapshot (fail-closed).

It backs the filtered `GET /api/nodes` and the **SSE** stream: the hub keeps
broadcasting the single shared snapshot, and each guest connection applies its
filter in the per-client goroutine (`writeFrame`), including the on-connect
frame. Admin connections carry a nil filter (zero overhead).

This filter is **NOT the access control** — writes are authorized independently
at choke point 2. A bug here can leak a *read* at worst, never grant a *write*.

## Revocation

The guest is re-resolved against the live store on every request, so
disable/delete/zone-delete revokes access **on the very next request** — no
session table, no TTL wait:

- **Writes and REST reads** revoke **instantly** (`resolveSubject` re-loads the
  guest, denies if missing/disabled or if its zone is gone → 401).
- The **SSE stream** authenticates only once at connect, so each heartbeat
  (`~20s` ping) calls an `authz.Revalidate` closure that re-runs the full auth
  resolution and drops the stream once it fails — revoked **within one ping
  interval**.
- Deleting a zone that still has a guest assigned is a **409** (delete or
  reassign the guest first) — making the dependency explicit; the revocation
  safety net still holds if a zone vanishes anyway.

## Security review

An independent adversarial security review plus a separate sandbox-escape
(zone-escape) audit were run on the backend before any UI was trusted. Two
findings, both **fixed and regression-tested**:

- **[MEDIUM] SSE read-revocation lag** — a disabled/deleted guest's long-lived
  event stream kept delivering its zone until the client disconnected (writes
  already revoked instantly). Fixed: the heartbeat now re-checks authorization
  via `authz.Revalidate` and drops the stream within one ping interval
  (`GuestStreamClosedOnRevoke`).
- **[LOW] fail-open reads** — `handleNodes`/`handleRouter` served the unfiltered
  view on a missing subject. Fixed: they now fail closed (401), matching the
  write path.

**Verdict:** no zone escape via any id — role is unforgeable (inside the signed
cookie region), every write is re-checked against the guest's own live zone
(stricter than the poller union), out-of-zone reads are 404/filtered with no
oracle, the hash never reaches the wire, and revocation is immediate (one
heartbeat for the live stream).
</content>
</invoke>
