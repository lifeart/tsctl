# Design: zones (groups) + graph UI

Status: **locked design, not yet built.** From the agreed decisions:
- **Consumers = controllable routers only** (the `tag:router`/SSH-reachable nodes whose exit node tsctl can actually set). Left column.
- **Enforce** — a consumer may only be wired to an exit node allowed by its group(s).
- **Server-side, shared** group definitions (persisted; same on every device/login).
- **Graph is the default view.**

## Concept
A **zone/group** (e.g. "work") = a named set of **consumers** + a set of **allowed exit nodes**. The graph draws a **wire** from each consumer to its *current* exit node; drag a wire to a different (allowed) exit node → **confirm** → the existing dead-man's-switch `SetExitNode` runs. Default view = your groups (consumers not in any group fall into an implicit "Ungrouped" section so nothing is hidden).

Terminology note: the user's "clients/consumers" = tsctl's `tag:router` nodes (what we control); the user's "exit nodes" = `ExitNodeOption` nodes. No model change — a re-presentation + a grouping/enforcement layer.

## Data model
```go
// internal/groups
type Group struct {
    ID               string   // stable id (server-assigned, e.g. random hex)
    Name             string   // user label, unique-ish
    Consumers        []string // node StableIDs (must be tag:router)
    AllowedExitNodes []string // node StableIDs (must be ExitNodeOption-capable)
}
```
- Persisted as `$STATE_DIR/groups.json` (0600), atomic write (temp + rename), loaded at startup, guarded by a mutex. A small `groups.Store` with `List/Get/Create/Update/Delete`.
- Validation on write: names non-empty; member StableIDs are well-formed; **soft-validate** membership against the current netmap (a member that's not currently visible is kept but flagged "missing" in the view, not rejected — devices come and go).

## API (owner/password gated + Host + CSRF, like everything else)
- `GET /api/groups` → `[]GroupView`
- `POST /api/groups` `{name, consumers[], allowedExitNodes[]}` → created GroupView (201)
- `PUT /api/groups/{id}` → updated GroupView
- `DELETE /api/groups/{id}` → 204
- Groups are also included in the **SSE snapshot** so the graph updates live: add `Groups []GroupView` to `store.Snapshot` (additive field; JSON `groups`). `GroupView` carries the group + resolved member display info (name/IP/online) for rendering.

## Enforcement (control path — the "Enforce" decision)
In `poller.SetExitNode` pre-flight: compute the consumer's **allowed set** = union of `AllowedExitNodes` across all groups containing that consumer.
- If the consumer is in ≥1 group: the target must be in the allowed set (by StableID). **"Direct" (clear) is always allowed.** Otherwise reject with a clear 422 ("exit node X is not allowed for <consumer> in its zone(s)").
- If the consumer is in no group: unrestricted (current behavior).
This is UI-independent (the API enforces regardless of which view issued the change). The graph also refuses to draw/drop a disallowed wire (UI guard), but the backend is the source of truth.

## Frontend (graph as default view)
- New primary view: a **bipartite graph** — consumers (left), exit nodes (right), inline **SVG wires** = each consumer's current exit node. A group selector (tabs/dropdown) scopes which consumers + exit nodes show; "Ungrouped" catches the rest.
- **Drag-to-rewire:** grab a consumer's wire endpoint, drop on an allowed exit node (disallowed targets are non-droppable/greyed) → the existing **confirm dialog** → POST. Reflect the device's **actual** state (never-optimistic): wire shows pending/animating until confirmed, snaps back on failure.
- **Group editor:** create/rename a zone; add/remove consumers (from the controllable set) and allowed exit nodes; delete a zone.
- The current **card list becomes a secondary/detail view** (toggle), reusing the existing RouterView rendering + states.
- Keep Apple design language, a11y (keyboard alternative to drag — a per-consumer picker still works), reduced-motion, the login overlay, CSRF header on writes.

## Build phases
1. **Backend groups** — `internal/groups` store (+ tests: atomic write, CRUD, load), `store.Snapshot.Groups`, api group handlers (+ tests), enforcement in `poller.SetExitNode` (+ tests: in-zone allowed, out-of-zone rejected, Direct always ok, ungrouped unrestricted). Demo fixtures: a couple of sample zones.
2. **Frontend graph** — bipartite SVG graph as default, group selector, drag-to-rewire + confirm, group editor, card view as secondary; consume `groups` from the SSE snapshot.
3. **Review gate** (correctness + a11y + enforcement-can't-be-bypassed) → browser-verify via `tsctl demo` (sample zones + drag a wire) → commit/push.

## Open sub-decisions (sensible defaults; flag at build)
- A consumer may belong to multiple groups (allowed set = union). If you want single-membership, say so.
- Deleting a node from the netmap leaves stale group members (flagged "missing", kept) — a "prune" action could clean them up later.
