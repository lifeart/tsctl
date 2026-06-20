// tsctl LIVE DEMO — client-side mock backend.
//
// This file MUST load BEFORE web/app.js. It monkeypatches window.fetch and
// window.EventSource so the UNMODIFIED SPA runs fully client-side on a static
// host (GitHub Pages) with no tailnet / router / backend. The fixtures and the
// scripted SetExitNode outcomes mirror `tsctl demo` (internal/demo/demo.go), and
// the wire shapes match PHASE_B.md §3 exactly (the SPA reads `state`, never
// optimistic). No external/CDN resources, clean UTF-8, no inline-handler trickery.
//
// What it serves:
//   GET    /api/csrf                       -> {token:"demo"} + tsctl_csrf cookie
//   GET    /api/nodes                      -> {nodes, builtAt, netmapErr:""}
//   GET    /api/groups                     -> raw Group[]
//   POST   /api/groups                     -> create (201 raw Group | 422)
//   PUT    /api/groups/{id}                -> update (200 raw Group | 404 | 422)
//   DELETE /api/groups/{id}                -> 204 | 404
//   POST   /api/routers/{id}/exit-node     -> scripted ok / unconfirmed / broken /
//                                             zone-enforcement reject / clear. A
//                                             CONFIRMED normal set adds internet-egress
//                                             fields (egressOk/egressDetail/
//                                             egressCheckedAt; stage-1 keep-egress —
//                                             office-router reports ✗) and, in
//                                             -require-keep mode, enters state
//                                             "awaiting-keep" + revertAt (stage 2).
//   POST   /api/routers/{id}/keep          -> stage-2 explicit-Keep gate: 200 kept
//                                             (state ok) | 409 window elapsed (router
//                                             auto-reverts) / nothing awaiting | 404
//   POST   /api/routers/{id}/probe         -> SSH probe: 200 {ok,durationMs,output|
//                                             error,checkedAt} (online OK / control-
//                                             error / offline) | 404 unknown id
//   GET    /api/me                         -> {role, zoneId, zoneName} (admin/guest)
//   POST   /api/login                      -> body {label,password}: empty label =
//                                             admin; a label = guest (matched by
//                                             label) -> sets the demo session role
//   POST   /api/logout                     -> 200, clears the demo session (401 next)
//   GET    /api/guests                     -> GuestDTO[] (admin; NO password hash)
//   POST   /api/guests                     -> create {label,zoneId,password} (201|422)
//   POST   /api/guests/{id}/disabled       -> toggle {disabled} (200|404)
//   DELETE /api/guests/{id}                -> 204 | 404
//   (anything else under /api/)            -> 404
//
// Guest session: when "logged in as a guest" the snapshot + /api/nodes are
// zone-FILTERED (filterSnapshotToZone mirrors Go authz.FilterSnapshotToZone) so the
// gh-pages demo shows guest mode end to end (gating + one-zone view + auto-resolve).
//   EventSource /api/events                -> full Snapshot frame on connect, then
//                                             a fresh frame every ~3s (stats tick,
//                                             one generic node flips online/offline)
(function () {
  "use strict";

  // ----------------------------------------------------------- timings -----
  var APPLY_MS = 1200;     // scripted SetExitNode latency (UI shows "Applying…")
  var PREFLIGHT_MS = 140;  // a pre-flight rejection resolves quickly
  var GROUP_MS = 450;      // zone create/save/delete latency (UI shows "Saving…"/"Deleting…")
  var PROBE_MIN_MS = 600;  // artificial SSH-probe latency floor (UI shows "Probing…")
  var PROBE_VAR_MS = 300;  // + up to this much jitter (~600-900ms total)
  var OPEN_MS = 120;       // EventSource "connect" delay (well under the 8s watchdog)
  var TICK_MS = 3000;      // SSE frame cadence + world time-variation

  // Stage-2 explicit-Keep gate (docs/design/keep-egress.md). The demo runs in
  // -require-keep mode: a CONFIRMED normal set enters "awaiting-keep" with a short
  // revert window, so the gate + live countdown + Keep button are demoable (and the
  // auto-revert fires if the operator never Keeps).
  var REQUIRE_KEEP = true;     // run the demo as if started with -require-keep
  var KEEP_WINDOW_MS = 35000;  // revert window: long enough to read + Keep, short to demo

  // -------------------------------------------------- fixture addresses ----
  // Mirrors internal/demo/demo.go (plus one extra "control error" router).
  var r1IP = "100.64.0.10"; // home-router      — online, Direct
  var r2IP = "100.64.0.11"; // office-router    — online, via tokyo, stats tick
  var r3IP = "100.64.0.12"; // cabin-router     — OFFLINE (control disabled)
  var r4IP = "100.64.0.13"; // warehouse-router — online, current exit OFFLINE+out-of-zone -> warn
  var r5IP = "100.64.0.14"; // depot-router     — ONLINE but CONTROL ERROR (reachable:false)
  var r6IP = "100.64.0.15"; // garage-pi        — online, UNPROBED (fallback-listed, never auto-SSHed)

  var tokyoIP = "100.64.0.20";     // online exit node (normal -> confirmed)
  var frankfurtIP = "100.64.0.21"; // online exit node (normal -> confirmed)
  var londonIP = "100.64.0.22";    // OFFLINE exit node -> "(offline)" in picker
  var comboIP = "100.64.0.23";     // exit node that is ALSO tag:router
  var flakyIP = "100.64.0.24";     // scripted -> applied-but-unconfirmed (amber)
  var brokenIP = "100.64.0.25";    // scripted -> command error (permission denied)

  var aliceIP = "100.64.0.30"; // generic, online
  var bobIP = "100.64.0.31";   // generic — FLIPS online/offline each tick
  var kioskIP = "100.64.0.32"; // generic, online, very long hostname

  var FLIP_ID = "n-bob-iphone"; // the generic node the ticker toggles

  // The configured, controllable router set (order = stable card/row order).
  var ROUTER_IPS = [r1IP, r2IP, r3IP, r4IP, r5IP, r6IP];

  var now0 = Date.now();
  function ago(ms) { return new Date(now0 - ms); }

  // ------------------------------------------------------- node fixtures ---
  // type ∈ "router" | "exit-node" | "generic". exitOpt = advertised+approved.
  var nodes = [
    // --- controllable routers (tag:router) ---
    { stableID: "n-home-router", name: "home-router.tail-demo.ts.net", hostname: "home-router",
      ips: [r1IP], os: "linux", online: true, lastSeen: null, exitOpt: false, tags: ["tag:router"], type: "router" },
    { stableID: "n-office-router", name: "office-router.tail-demo.ts.net", hostname: "office-router",
      ips: [r2IP], os: "linux", online: true, lastSeen: null, exitOpt: false, tags: ["tag:router"], type: "router" },
    { stableID: "n-cabin-router", name: "cabin-router.tail-demo.ts.net", hostname: "cabin-router",
      ips: [r3IP], os: "linux", online: false, lastSeen: ago(37 * 60000), exitOpt: false, tags: ["tag:router"], type: "router" },
    { stableID: "n-warehouse-router",
      name: "warehouse-router-with-an-intentionally-very-long-hostname-for-truncation.tail-demo.ts.net",
      hostname: "warehouse-router-with-an-intentionally-very-long-hostname-for-truncation",
      ips: [r4IP], os: "linux", online: true, lastSeen: null, exitOpt: false, tags: ["tag:router"], type: "router" },
    { stableID: "n-depot-router", name: "depot-router.tail-demo.ts.net", hostname: "depot-router",
      ips: [r5IP], os: "linux", online: true, lastSeen: null, exitOpt: false, tags: ["tag:router"], type: "router" },
    // Fallback-listed device: NO tag:router — surfaced as a consumer but never
    // auto-probed (shows "not probed" until a manual Test SSH / exit-node set).
    { stableID: "n-garage-pi", name: "garage-pi.tail-demo.ts.net", hostname: "garage-pi",
      ips: [r6IP], os: "linux", online: true, lastSeen: null, exitOpt: false, tags: [], type: "generic" },

    // --- approved exit nodes (exitNodeOption=true) ---
    { stableID: "n-exit-tokyo", name: "exit-tokyo.tail-demo.ts.net", hostname: "exit-tokyo",
      ips: [tokyoIP], os: "linux", online: true, lastSeen: null, exitOpt: true, tags: [], type: "exit-node" },
    { stableID: "n-exit-frankfurt", name: "exit-frankfurt.tail-demo.ts.net", hostname: "exit-frankfurt",
      ips: [frankfurtIP], os: "linux", online: true, lastSeen: null, exitOpt: true, tags: [], type: "exit-node" },
    { stableID: "n-exit-london", name: "exit-london.tail-demo.ts.net", hostname: "exit-london",
      ips: [londonIP], os: "linux", online: false, lastSeen: ago(12 * 60000), exitOpt: true, tags: [], type: "exit-node" },
    // exit node that is ALSO tag:router: tag:router wins classification, but
    // exitNodeOption stays true so it still appears in the picker.
    { stableID: "n-exit-combo", name: "edge-combo.tail-demo.ts.net", hostname: "edge-combo",
      ips: [comboIP], os: "linux", online: true, lastSeen: null, exitOpt: true, tags: ["tag:router"], type: "router" },
    { stableID: "n-exit-flaky", name: "exit-flaky.tail-demo.ts.net", hostname: "exit-flaky",
      ips: [flakyIP], os: "linux", online: true, lastSeen: null, exitOpt: true, tags: [], type: "exit-node" },
    { stableID: "n-exit-broken", name: "exit-broken.tail-demo.ts.net", hostname: "exit-broken",
      ips: [brokenIP], os: "linux", online: true, lastSeen: null, exitOpt: true, tags: [], type: "exit-node" },

    // --- generic nodes ---
    { stableID: "n-alice-mbp", name: "alices-macbook-pro.tail-demo.ts.net", hostname: "alices-macbook-pro",
      ips: [aliceIP], os: "macOS", online: true, lastSeen: null, exitOpt: false, tags: [], type: "generic" },
    { stableID: FLIP_ID, name: "bobs-iphone.tail-demo.ts.net", hostname: "bobs-iphone",
      ips: [bobIP], os: "iOS", online: false, lastSeen: ago(3 * 60000), exitOpt: false, tags: [], type: "generic" },
    { stableID: "n-kiosk",
      name: "front-lobby-conference-room-A-information-kiosk-display.tail-demo.ts.net",
      hostname: "front-lobby-conference-room-A-information-kiosk-display",
      ips: [kioskIP], os: "linux", online: true, lastSeen: null, exitOpt: false, tags: [], type: "generic" },
  ];

  // --------------------------------------------- per-router device state ---
  // Mirrors internal/demo routerRuntime: the router's "own tailscale status".
  //   cur          : current exit-node IP ("" = Direct)
  //   desired      : pending intent IP ("" = none) — set only for unconfirmed (flaky)
  //   rx/tx/hs     : exit-node peer counters + last handshake (Date|null)
  //   controlError : online in the netmap but tsctl can't control it (reachable:false)
  //   lastError    : surfaced control/transport error ("" = healthy)
  //   egressOk     : internet-egress probe result, set ONLY after a confirmed SET to
  //                  an exit node (true|false; null = Direct / not probed) — stage-1
  //                  keep-egress. routerViewDTO emits egressOk/egressDetail/
  //                  egressCheckedAt only while it's non-null + an exit node is set.
  //   egressDetail : probe output / error string (shown on the ✗ state)
  //   egressCheckedAt : Date of the egress probe (null = none)
  var routers = {};
  routers[r1IP] = { cur: "", desired: "", rx: 0, tx: 0, hs: null, controlError: false, lastError: "", egressOk: null, egressDetail: "", egressCheckedAt: null };
  routers[r2IP] = { cur: tokyoIP, desired: "", rx: 18400000, tx: 4200000, hs: ago(9000), controlError: false, lastError: "", egressOk: null, egressDetail: "", egressCheckedAt: null };
  routers[r3IP] = { cur: "", desired: "", rx: 0, tx: 0, hs: null, controlError: false, lastError: "", egressOk: null, egressDetail: "", egressCheckedAt: null };
  routers[r4IP] = { cur: londonIP, desired: "", rx: 940000, tx: 210000, hs: ago(11 * 60000), controlError: false, lastError: "", egressOk: null, egressDetail: "", egressCheckedAt: null };
  routers[r5IP] = { cur: frankfurtIP, desired: "", rx: 0, tx: 0, hs: null, controlError: true, egressOk: null, egressDetail: "", egressCheckedAt: null,
    lastError: "ssh: handshake failed: host key mismatch for " + r5IP +
      " (tsctl can reach the device but cannot authenticate to control it)" };
  // Fallback-listed device: online but never auto-probed -> neutral "not probed"
  // until a manual Test SSH or an exit-node set (it has no tag:router). It is
  // ACTUALLY routing through frankfurt; a Test SSH resolves that (card + graph wire).
  routers[r6IP] = { unprobed: true, cur: frankfurtIP, desired: "", rx: 0, tx: 0, hs: null, controlError: false, lastError: "", egressOk: null, egressDetail: "", egressCheckedAt: null };

  // Stage-2 explicit-Keep gate runtime (docs/design/keep-egress.md, -require-keep):
  //   awaitingKeep : a CONFIRMED set is applied but NOT kept yet (armed revert pending)
  //   revertAt     : Date the armed revert fires (null = none)
  //   prevExit     : exit-node IP to auto-revert to if not kept in time ("" = Direct)
  Object.keys(routers).forEach(function (ip) {
    routers[ip].awaitingKeep = false;
    routers[ip].revertAt = null;
    routers[ip].prevExit = "";
  });

  // Designated "no internet egress" router for the demo (office-router): after a
  // CONFIRMED set to an exit node it reaches the device but can't fetch the captive-
  // portal probe through the exit node, so egressOk:false with a realistic detail.
  // Every other router reports egress OK. Mirrors the stage-1 keep-egress contract.
  var NO_EGRESS_IP = r2IP;
  function setEgress(rt, ip) {
    rt.egressCheckedAt = new Date();
    if (ip === NO_EGRESS_IP) {
      rt.egressOk = false;
      rt.egressDetail = "tsctl_egress_exit=4 (uclient-fetch: download timed out)";
    } else {
      rt.egressOk = true;
      rt.egressDetail = "tsctl_egress_exit=0";
    }
  }
  function clearEgress(rt) {
    rt.egressOk = null;
    rt.egressDetail = "";
    rt.egressCheckedAt = null;
  }

  // Auto-revert an awaiting-keep router to its previous exit node (the dead-man's-
  // switch firing). A revert is NOT a deliberate set, so it clears the keep arming
  // and the egress probe; the router settles back to a clean "ok" on the prev node.
  function revertAwaitingKeep(rt) {
    rt.cur = rt.prevExit || "";
    rt.desired = "";
    rt.awaitingKeep = false;
    rt.revertAt = null;
    rt.prevExit = "";
    rt.lastError = "";
    clearEgress(rt);
    if (rt.cur) { rt.rx = 96000; rt.tx = 24000; rt.hs = new Date(); }
    else { rt.rx = 0; rt.tx = 0; rt.hs = null; }
  }

  // ---------------------------------------------------- in-memory zones ----
  // RAW groups (member arrays = StableID strings), mirroring internal/demo
  // NewGroups. cabin-router + depot-router are intentionally left UNGROUPED.
  var groups = [
    { id: "zone-work", name: "Work",
      consumers: ["n-office-router", "n-warehouse-router"],
      allowedExitNodes: ["n-exit-tokyo", "n-exit-frankfurt"] },
    { id: "zone-lab", name: "Lab",
      consumers: ["n-home-router"],
      allowedExitNodes: ["n-exit-tokyo", "n-exit-frankfurt", "n-exit-flaky", "n-exit-broken"] },
  ];

  // ---------------------------------------------------------- guest mode ----
  // In-memory guest credentials (guest mode). The DTO is HASH-FREE — mirroring the
  // Go store.Guest / GuestDTO, the demo never models or exposes a password hash. One
  // seeded guest so the admin panel shows a populated list and a visitor can sign in
  // as "contractor-alex" (any password) to try the guest view end to end.
  var guests = [
    { id: "guest-seed-1", label: "contractor-alex", zoneId: "zone-work",
      disabled: false, createdAt: rfc3339(ago(2 * 24 * 60 * 60000)) },
  ];

  // The demo "session": who the SPA is currently signed in as. Default ADMIN so the
  // demo loads straight into the full UI (no login wall) — matching the prior demo.
  //   role : "admin" | "guest" | null (signed out, after /api/logout)
  //   zoneId / zoneName : the bound zone for a guest session
  var session = { role: "admin", zoneId: "", zoneName: "" };

  function zoneNameById(id) {
    for (var i = 0; i < groups.length; i++) if (groups[i].id === id) return groups[i].name;
    return "";
  }
  function findGuestIndex(id) {
    for (var i = 0; i < guests.length; i++) if (guests[i].id === id) return i;
    return -1;
  }
  function newGuestID() {
    var hex = "guest-";
    for (var i = 0; i < 12; i++) hex += Math.floor(Math.random() * 16).toString(16);
    for (var j = 0; j < guests.length; j++) if (guests[j].id === hex) return newGuestID();
    return hex;
  }
  // Hash-free wire shape, matching the Go GuestDTO (api.go:1140).
  function guestDTO(g) {
    return { id: g.id, label: g.label, zoneId: g.zoneId, disabled: g.disabled, createdAt: g.createdAt };
  }

  // ---------------------------------------------------------- lookups ------
  function nodeByID(id) {
    for (var i = 0; i < nodes.length; i++) if (nodes[i].stableID === id) return nodes[i];
    return null;
  }
  function nodeByIP(ip) {
    for (var i = 0; i < nodes.length; i++) {
      for (var j = 0; j < nodes[i].ips.length; j++) if (nodes[i].ips[j] === ip) return nodes[i];
    }
    return null;
  }
  function primaryIPv4(ips) {
    for (var i = 0; i < ips.length; i++) if (ips[i].indexOf(".") !== -1) return ips[i];
    return ips.length ? ips[0] : "";
  }
  function displayName(n) { return n.name || n.hostname || n.stableID; }

  // --------------------------------------------------------- formatting ----
  // RFC3339 (seconds precision, UTC, "Z"); "" for a missing/zero time.
  function rfc3339(d) {
    if (!d) return "";
    return new Date(d).toISOString().replace(/\.\d{3}Z$/, "Z");
  }

  // ----------------------------------------------------------- DTO build ---
  function nodeDTO(n) {
    return {
      stableID: n.stableID,
      name: n.name,
      hostname: n.hostname,
      tailscaleIPs: n.ips.slice(),
      os: n.os,
      online: n.online,
      lastSeen: n.online ? "" : rfc3339(n.lastSeen),
      exitNodeOption: n.exitOpt,
      tags: n.tags.slice(),
      type: n.type,
    };
  }

  // ExitNodeRef DTO ({stableID,name,ip}) or null for "" / unknown.
  function refByIP(ip) {
    if (!ip) return null;
    var n = nodeByIP(ip);
    if (!n) return { stableID: "", name: "", ip: ip };
    return { stableID: n.stableID, name: n.name, ip: primaryIPv4(n.ips) };
  }

  function routerViewDTO(ip) {
    var node = nodeByIP(ip);
    var rt = routers[ip];
    // A configured router missing from the netmap still appears (defensive).
    if (!node) {
      return {
        node: { stableID: "", name: "", hostname: "", tailscaleIPs: [ip], os: "", online: false,
          lastSeen: "", exitNodeOption: false, tags: [], type: "router" },
        currentExitNode: null, desired: null, state: "unreachable",
        stats: { rxBytes: 0, txBytes: 0, lastHandshake: "" },
        reachable: false, lastError: "router not present in the netmap", lastConfirmedAt: "",
      };
    }
    // Fallback-listed but never auto-probed: neutral "unprobed" (not an error, not
    // offline). Resolved by a manual Test SSH or an exit-node set.
    if (rt.unprobed) {
      return {
        node: nodeDTO(node),
        currentExitNode: null, desired: null, state: "unprobed",
        stats: { rxBytes: 0, txBytes: 0, lastHandshake: "" },
        reachable: false, lastError: "", lastConfirmedAt: "",
      };
    }
    var reachable = node.online && !rt.controlError;
    var stats = { rxBytes: rt.rx, txBytes: rt.tx, lastHandshake: rfc3339(rt.hs) };
    var rv = {
      node: nodeDTO(node),
      currentExitNode: refByIP(rt.cur),
      desired: null,
      state: "ok",
      stats: stats,
      reachable: reachable,
      lastError: "",
      lastConfirmedAt: "",
    };
    if (!reachable) {
      // Genuine offline OR control error: both render reachable:false. The SPA
      // distinguishes control error as (node.online === true && reachable === false).
      rv.state = "unreachable";
      rv.desired = refByIP(rt.desired);
      rv.lastError = rt.lastError || ("dial " + ip + ":22: connect: host is down (demo: router offline)");
      return rv;
    }
    // Stage-2 explicit-Keep gate (docs/design/keep-egress.md, -require-keep): the set
    // is applied + confirmed (cur = target) but NOT kept — the armed revert fires at
    // revertAt unless the operator Keeps. Carries revertAt + still reports egress.
    // Explicitly NOT "ok" (success is only after Keep).
    if (rt.awaitingKeep) {
      rv.state = "awaiting-keep";
      rv.desired = null;
      rv.lastError = "";
      rv.lastConfirmedAt = rfc3339(rt.egressCheckedAt || new Date());
      rv.revertAt = rfc3339(rt.revertAt);
      if (rt.cur && rt.egressOk != null) {
        rv.egressOk = rt.egressOk;
        rv.egressDetail = rt.egressDetail || "";
        rv.egressCheckedAt = rfc3339(rt.egressCheckedAt);
      }
      return rv;
    }
    // Reachable: derive state from cur vs desired (never optimistic).
    if (rt.desired && rt.desired !== rt.cur) {
      rv.state = "unconfirmed";
      rv.desired = refByIP(rt.desired);
      rv.lastError = rt.lastError;
    } else {
      rv.state = "ok";
      rv.desired = null;
      rv.lastError = "";
      rv.lastConfirmedAt = rfc3339(new Date());
    }
    // Stage-1 internet-egress (docs/design/keep-egress.md): emitted ONLY when an
    // exit node is set + confirmed (state ok, cur != "") AND a probe has actually
    // run (egressOk non-null). Direct/cleared, unconfirmed, or never-set-in-session
    // routers carry no egress fields — matches the backend contract.
    if (rv.state === "ok" && rt.cur && rt.egressOk != null) {
      rv.egressOk = rt.egressOk;
      rv.egressDetail = rt.egressDetail || "";
      rv.egressCheckedAt = rfc3339(rt.egressCheckedAt);
    }
    return rv;
  }

  function groupMemberDTO(id) {
    var n = nodeByID(id);
    if (!n) return { stableID: id, name: "", ip: "", online: false, present: false };
    return { stableID: id, name: displayName(n), ip: primaryIPv4(n.ips), online: n.online, present: true };
  }
  // Resolved GroupView for the SSE snapshot (sorted by name then id, like the poller).
  function groupViewDTOs() {
    var sorted = groups.slice().sort(function (a, b) {
      if (a.name !== b.name) return a.name < b.name ? -1 : 1;
      return a.id < b.id ? -1 : (a.id > b.id ? 1 : 0);
    });
    return sorted.map(function (g) {
      return {
        id: g.id,
        name: g.name,
        consumers: (g.consumers || []).map(groupMemberDTO),
        allowedExitNodes: (g.allowedExitNodes || []).map(groupMemberDTO),
      };
    });
  }
  // RAW Group DTO for GET /api/groups + create/update responses.
  function rawGroupDTO(g) {
    return {
      id: g.id,
      name: g.name,
      consumers: (g.consumers || []).slice(),
      allowedExitNodes: (g.allowedExitNodes || []).slice(),
    };
  }

  // Zone-filter a full snapshot down to one zone — the client-side mirror of the Go
  // authz.FilterSnapshotToZone (Phase 4): Groups = [that one zone]; allowed set =
  // its Consumers ∪ AllowedExitNodes; Nodes = nodes in that set (offline allowed
  // exits kept so the picker matches admin); Routers = routers whose node is a
  // Consumer. Never mutates the inputs; carries netmapAt/Err/builtAt through.
  function filterSnapshotToZone(snap, zoneID) {
    var raw = null;
    for (var i = 0; i < groups.length; i++) if (groups[i].id === zoneID) raw = groups[i];
    if (!raw) {
      // Zone gone (the guest would be revoked server-side): an empty filtered view.
      return { nodes: [], routers: [], groups: [], netmapAt: snap.netmapAt, netmapErr: snap.netmapErr, builtAt: snap.builtAt };
    }
    var allow = {}, cons = {};
    (raw.consumers || []).forEach(function (id) { allow[id] = true; cons[id] = true; });
    (raw.allowedExitNodes || []).forEach(function (id) { allow[id] = true; });
    return {
      nodes: snap.nodes.filter(function (n) { return allow[n.stableID]; }),
      routers: snap.routers.filter(function (rv) { return rv.node && cons[rv.node.stableID]; }),
      groups: snap.groups.filter(function (gv) { return gv.id === zoneID; }),
      netmapAt: snap.netmapAt,
      netmapErr: snap.netmapErr,
      builtAt: snap.builtAt,
    };
  }

  function buildSnapshot() {
    var iso = rfc3339(new Date());
    var full = {
      nodes: nodes.map(nodeDTO),
      routers: ROUTER_IPS.map(routerViewDTO),
      groups: groupViewDTOs(),
      netmapAt: iso,
      netmapErr: "",
      builtAt: iso,
    };
    // A guest session sees ONLY its zone (server-side filtering in the real backend).
    if (session.role === "guest") return filterSnapshotToZone(full, session.zoneId);
    return full;
  }

  // ----------------------------------------------- zone enforcement set ----
  // Union of AllowedExitNodes (by StableID) across every zone whose Consumers
  // include consumerID; inAnyZone=false => unrestricted (ungrouped).
  function allowedExitNodeSet(consumerID) {
    var set = {}, inAnyZone = false;
    groups.forEach(function (g) {
      if ((g.consumers || []).indexOf(consumerID) === -1) return;
      inAnyZone = true;
      (g.allowedExitNodes || []).forEach(function (e) { set[e] = true; });
    });
    return { set: set, inAnyZone: inAnyZone };
  }

  // --------------------------------------------------- time variation ------
  function rnd(n) { return Math.floor(Math.random() * n); }
  function tick() {
    var now = new Date();
    // Stage-2 keep gate (docs/design/keep-egress.md): any router whose revert window
    // has elapsed without a Keep auto-reverts to its previous exit node on this tick
    // — the demo's dead-man's-switch firing (mirrors the poller clearing a stale
    // pending-keep entry on the next poll). The fresh frame shows the reverted "ok".
    ROUTER_IPS.forEach(function (ip) {
      var rt = routers[ip];
      if (rt.awaitingKeep && rt.revertAt && now.getTime() > new Date(rt.revertAt).getTime()) {
        revertAwaitingKeep(rt);
      }
    });
    // Stats climb only when the current exit node is ONLINE and the router is
    // reachable (a router pointed at an offline exit keeps a stale handshake).
    ROUTER_IPS.forEach(function (ip) {
      var rt = routers[ip];
      var node = nodeByIP(ip);
      if (!node || !node.online || rt.controlError || !rt.cur) return;
      var ex = nodeByIP(rt.cur);
      if (!ex || !ex.online) return;
      rt.rx += 40000 + rnd(180000);
      rt.tx += 8000 + rnd(40000);
      rt.hs = now;
    });
    // Flip a generic node so the online dot + "last seen" visibly change.
    var bob = nodeByID(FLIP_ID);
    if (bob) {
      bob.online = !bob.online;
      if (!bob.online) bob.lastSeen = now;
    }
  }

  // ============================================== EventSource mock ==========
  var openSources = [];
  var tickTimer = null;

  function ensureTicker() {
    if (tickTimer) return;
    tickTimer = setInterval(function () {
      tick();
      broadcast(buildSnapshot());
    }, TICK_MS);
  }
  function maybeStopTicker() {
    if (!openSources.length && tickTimer) { clearInterval(tickTimer); tickTimer = null; }
  }
  function broadcast(snap) {
    // Copy the list — a handler may close() (mutating openSources) mid-iteration.
    openSources.slice().forEach(function (s) { s._send(snap); });
  }

  function MockEventSource(url) {
    this.url = String(url);
    this.withCredentials = false;
    this.readyState = MockEventSource.CONNECTING; // 0
    this.onopen = null;
    this.onmessage = null;
    this.onerror = null;
    this._listeners = { open: [], message: [], error: [] };
    var self = this;
    openSources.push(self);
    ensureTicker();
    // Asynchronously "connect": fire onopen, then the initial full snapshot frame.
    setTimeout(function () {
      if (self.readyState === MockEventSource.CLOSED) return;
      self.readyState = MockEventSource.OPEN; // 1
      self._dispatch("open", { type: "open" });
      self._send(buildSnapshot());
    }, OPEN_MS);
  }
  MockEventSource.CONNECTING = 0;
  MockEventSource.OPEN = 1;
  MockEventSource.CLOSED = 2;
  MockEventSource.prototype.CONNECTING = 0;
  MockEventSource.prototype.OPEN = 1;
  MockEventSource.prototype.CLOSED = 2;

  MockEventSource.prototype.addEventListener = function (type, fn) {
    if (this._listeners[type] && typeof fn === "function") this._listeners[type].push(fn);
  };
  MockEventSource.prototype.removeEventListener = function (type, fn) {
    var list = this._listeners[type];
    if (!list) return;
    var i = list.indexOf(fn);
    if (i !== -1) list.splice(i, 1);
  };
  MockEventSource.prototype._dispatch = function (type, ev) {
    var on = this["on" + type];
    if (typeof on === "function") { try { on.call(this, ev); } catch (e) { reportError(e); } }
    this._listeners[type].slice().forEach(function (fn) {
      try { fn.call(this, ev); } catch (e) { reportError(e); }
    }, this);
  };
  MockEventSource.prototype._send = function (snap) {
    if (this.readyState !== MockEventSource.OPEN) return;
    this._dispatch("message", {
      type: "message",
      data: JSON.stringify(snap),
      lastEventId: "",
      origin: location.origin,
    });
  };
  MockEventSource.prototype.close = function () {
    this.readyState = MockEventSource.CLOSED;
    var i = openSources.indexOf(this);
    if (i !== -1) openSources.splice(i, 1);
    maybeStopTicker();
  };
  // Surface listener errors instead of swallowing them (global rule).
  function reportError(e) {
    if (typeof console !== "undefined" && console.error) console.error("tsctl demo mock:", e);
  }

  // ================================================= fetch mock =============
  var origFetch = (typeof window.fetch === "function") ? window.fetch.bind(window) : null;

  function json(status, obj) {
    return new Response(obj === null ? null : JSON.stringify(obj), {
      status: status,
      headers: { "Content-Type": "application/json" },
    });
  }
  function noContent() { return new Response(null, { status: 204 }); }
  function errBody(error, detail, stderr) {
    return { error: error || "", detail: detail || "", stderr: stderr || "" };
  }
  function delay(ms, value) {
    return new Promise(function (resolve) { setTimeout(function () { resolve(value); }, ms); });
  }

  // Validate/normalize a zone write body, mirroring groups.Normalize + the
  // case-insensitive name-uniqueness check. Returns {ok, group} or {ok:false, status, body}.
  function normalizeGroup(body, excludeID) {
    var name = String((body && body.name) || "").trim();
    if (!name) return { ok: false, status: 422, body: errBody("invalid group", "name must not be empty", "") };
    var consumers = normMembers(body && body.consumers, "consumers");
    if (consumers.err) return { ok: false, status: 422, body: errBody("invalid group", consumers.err, "") };
    var allowed = normMembers(body && body.allowedExitNodes, "allowedExitNodes");
    if (allowed.err) return { ok: false, status: 422, body: errBody("invalid group", allowed.err, "") };
    for (var i = 0; i < groups.length; i++) {
      if (groups[i].id === excludeID) continue;
      if (groups[i].name.toLowerCase() === name.toLowerCase()) {
        return { ok: false, status: 422, body: errBody("invalid group", 'a zone named "' + name + '" already exists', "") };
      }
    }
    return { ok: true, group: { name: name, consumers: consumers.out, allowedExitNodes: allowed.out } };
  }
  function normMembers(ids, field) {
    var seen = {}, out = [];
    ids = Array.isArray(ids) ? ids : [];
    for (var i = 0; i < ids.length; i++) {
      var id = String(ids[i] == null ? "" : ids[i]).trim();
      if (!id) return { err: field + " contains an empty member StableID" };
      if (seen[id]) continue;
      seen[id] = true;
      out.push(id);
    }
    return { out: out };
  }
  function newGroupID() {
    var hex = "";
    for (var i = 0; i < 16; i++) hex += Math.floor(Math.random() * 16).toString(16);
    // Guarantee uniqueness within the current set.
    for (var j = 0; j < groups.length; j++) if (groups[j].id === hex) return newGroupID();
    return hex;
  }
  function findGroupIndex(id) {
    for (var i = 0; i < groups.length; i++) if (groups[i].id === id) return i;
    return -1;
  }

  // --- the scripted exit-node mutation (the heart of the demo) -------------
  function setExitNode(routerID, targetID) {
    var node = nodeByID(routerID);
    if (!node || !node.ips.length || ROUTER_IPS.indexOf(node.ips[0]) === -1) {
      return delay(PREFLIGHT_MS, json(400, errBody('unknown router "' + routerID + '"', "", "")));
    }
    var ip = node.ips[0];
    var rt = routers[ip];

    // Pre-flight: resolve + validate the target (target "" = clear/Direct, always allowed).
    if (targetID) {
      var t = nodeByID(targetID);
      if (!t) return delay(PREFLIGHT_MS, json(400, errBody('unknown exit node "' + targetID + '"', "", "")));
      if (t.stableID === routerID) return delay(PREFLIGHT_MS, json(400, errBody('cannot route router "' + routerID + '" through itself', "", "")));
      if (!t.online) return delay(PREFLIGHT_MS, json(400, errBody('exit node "' + displayName(t) + '" is offline', "", "")));
      if (!t.exitOpt) return delay(PREFLIGHT_MS, json(400, errBody('node "' + displayName(t) + '" is not an approved exit node', "", "")));
      var tIP = primaryIPv4(t.ips);
      if (!tIP) return delay(PREFLIGHT_MS, json(400, errBody('exit node "' + displayName(t) + '" has no Tailscale IPv4 address', "", "")));
      if (tIP === ip) return delay(PREFLIGHT_MS, json(400, errBody('cannot route router "' + routerID + '" through itself (loop)', "", "")));
      // ZONE ENFORCEMENT (docs/design/zones.md): if the consumer is in >=1 zone,
      // the target must be in the union of those zones' allowed exit nodes.
      var pol = allowedExitNodeSet(routerID);
      if (pol.inAnyZone && !pol.set[t.stableID]) {
        return delay(PREFLIGHT_MS, json(422, errBody(
          'exit node "' + displayName(t) + '" is not allowed for "' + displayName(node) + '" in its zone(s)', "", "")));
      }
    }

    // A router that can't be controlled can't apply (UI disables this, but be safe).
    if (!node.online || rt.controlError) {
      return delay(PREFLIGHT_MS, json(502, errBody("router command failed",
        rt.lastError || ("dial " + ip + ":22: connect: host is down (demo: router offline)"), "")));
    }

    // Apply after the scripted latency, then broadcast a fresh frame (the SPA
    // reads the device's ACTUAL state from the returned RouterView + SSE).
    return delay(APPLY_MS, null).then(function () {
      // A set CONTACTS the device, so it's no longer "unprobed" — mirrors the real
      // backend, where SetExitNode reconciles a fallback device to a real state.
      rt.unprobed = false;
      // A new set supersedes any prior pending-keep arming (setSeq-bump analog): the
      // newer op owns the router. The normal-target branch below re-arms when needed.
      rt.awaitingKeep = false; rt.revertAt = null; rt.prevExit = "";
      var resp;
      if (!targetID) {
        // Clear -> confirmed Direct. No egress probe on a clear.
        rt.cur = ""; rt.desired = ""; rt.rx = 0; rt.tx = 0; rt.hs = null; rt.lastError = "";
        clearEgress(rt);
        resp = json(200, routerViewDTO(ip));
      } else if (targetID === "n-exit-flaky") {
        // Applied but NOT confirmed: leave current at prev, mark unconfirmed (amber).
        // Egress probe runs only after CONFIRM, so no egress here.
        rt.desired = flakyIP;
        rt.lastError = "router " + ip + ": exit-node not confirmed (revert will fire): want " +
          flakyIP + ", got " + (rt.cur || "(none)");
        clearEgress(rt);
        resp = json(200, routerViewDTO(ip)); // state:"unconfirmed"
      } else if (targetID === "n-exit-broken") {
        // The apply command itself failed: the change did NOT take (current
        // unchanged); surface a non-2xx {error,detail,stderr}. Egress untouched —
        // the previous confirmed selection (and its egress, if any) still stands.
        var detail = "router " + ip + ": apply exit-node exited 1: permission denied";
        resp = json(502, errBody("router command failed", detail, "permission denied"));
      } else {
        // Normal target -> confirmed. Egress probe runs after CONFIRM (keep-egress
        // stage 1): office-router reports ✗ no egress, every other router ✓ OK.
        var t2 = nodeByID(targetID);
        var prevExit = rt.cur;                 // remembered so the auto-revert can restore it
        rt.cur = primaryIPv4(t2.ips); rt.desired = ""; rt.rx = 96000; rt.tx = 24000;
        rt.hs = new Date(); rt.lastError = "";
        setEgress(rt, ip);
        if (REQUIRE_KEEP) {
          // Stage 2 (-require-keep): confirmed but NOT kept — arm the dead-man's-switch.
          // The router reverts to prevExit at revertAt unless the operator Keeps.
          rt.awaitingKeep = true;
          rt.prevExit = prevExit;
          rt.revertAt = new Date(Date.now() + KEEP_WINDOW_MS);
        }
        resp = json(200, routerViewDTO(ip));
      }
      broadcast(buildSnapshot());
      return resp;
    });
  }

  // --- the scripted SSH probe ("Test SSH") --------------------------------
  // Mirrors the backend's POST /api/routers/{id}/probe contract: a 200 with
  // {ok,durationMs,output|error,checkedAt} for every reachable/unreachable router,
  // a 404 for an unknown id. The states mirror the fixtures: a healthy online
  // router returns a realistic multi-line stats blob; the depot router (online but
  // reachable:false) fails the SSH handshake; the cabin router (offline) reports it.
  function probeOutput(node) {
    var host = node.hostname || node.stableID || "router";
    return "Linux " + host + " 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n" +
      " 14:32:07 up 6 days,  3:11,  1 user,  load average: 0.12, 0.09, 0.05\n" +
      "0.12 0.09 0.05 1/214 18922\n" +
      "MemTotal:        256000 kB\n" +
      "MemAvailable:    180240 kB";
  }
  function probeRouter(routerID) {
    var wait = PROBE_MIN_MS + rnd(PROBE_VAR_MS);
    var checkedAt = rfc3339(new Date());
    var node = nodeByID(routerID);
    // Unknown id, or a node that isn't one of the configured routers → 404.
    if (!node || !node.ips.length || ROUTER_IPS.indexOf(node.ips[0]) === -1) {
      return delay(wait, json(404, errBody('unknown router "' + routerID + '"', "", "")));
    }
    var ip = node.ips[0];
    var rt = routers[ip];
    // OFFLINE router (cabin): no SSH attempt at all — no durationMs (per contract).
    if (!node.online) {
      return delay(wait, json(200, { ok: false, error: "node is offline", checkedAt: checkedAt }));
    }
    // ONLINE but control error (depot): tsctl can dial it but can't authenticate.
    if (rt.controlError) {
      return delay(wait, json(200, {
        ok: false,
        durationMs: 80 + rnd(25),
        error: "ssh: handshake failed: ssh: unable to authenticate (no supported methods remain)",
        checkedAt: checkedAt,
      }));
    }
    // Healthy online router: SSH OK + a multi-line stats sample. A successful probe
    // also RESOLVES the device's exit node and lifts it out of "unprobed" (mirrors
    // the backend's resolveAfterProbe) -- broadcast a fresh frame so the card + graph
    // show real routing, not just the probe panel.
    return delay(wait, null).then(function () {
      rt.unprobed = false;
      broadcast(buildSnapshot());
      return json(200, {
        ok: true,
        durationMs: 110 + rnd(40),
        output: probeOutput(node),
        checkedAt: checkedAt,
      });
    });
  }

  // --- the explicit-Keep gate (stage 2, docs/design/keep-egress.md) -------
  // POST /api/routers/{id}/keep: confirm an awaiting-keep selection (write the keep
  // marker / cancel the armed revert). Mirrors the backend contract:
  //   200 RouterView (kept -> state "ok") | 404 unknown id |
  //   409 if the window elapsed / nothing is awaiting a keep. On an elapsed window
  //   the router auto-reverts to its previous exit node (so the revert is demoable).
  function keepRouter(routerID) {
    var node = nodeByID(routerID);
    if (!node || !node.ips.length || ROUTER_IPS.indexOf(node.ips[0]) === -1) {
      return delay(PREFLIGHT_MS, json(404, errBody('unknown router "' + routerID + '"', "", "")));
    }
    var ip = node.ips[0];
    var rt = routers[ip];
    // Nothing awaiting a keep (already kept / never armed / superseded) -> 409.
    if (!rt.awaitingKeep) {
      return delay(PREFLIGHT_MS, json(409, errBody("nothing to keep",
        "this router is not awaiting a keep (already kept, superseded, or never armed)", "")));
    }
    // Window elapsed -> the router has reverted; surface 409 and perform the revert so
    // the demo visibly shows the auto-revert on the next frame.
    if (rt.revertAt && Date.now() > new Date(rt.revertAt).getTime()) {
      return delay(PREFLIGHT_MS, null).then(function () {
        revertAwaitingKeep(rt);
        broadcast(buildSnapshot());
        return json(409, errBody("revert window elapsed",
          "the revert window elapsed; the router has reverted to its previous exit node", ""));
      });
    }
    // Keep: cancel the armed revert and settle to a confirmed "ok" on the kept node.
    return delay(PREFLIGHT_MS, null).then(function () {
      rt.awaitingKeep = false;
      rt.revertAt = null;
      rt.prevExit = "";
      broadcast(buildSnapshot());
      return json(200, routerViewDTO(ip));
    });
  }

  // --- guest CRUD (admin-only; guest mode) --------------------------------
  // Mirrors the Go handlers: POST {label,zoneId,password} -> 201 GuestDTO (no hash)
  // | 422 validation; the password is accepted but NEVER stored as a hash here (the
  // demo authenticates a guest by label alone). An unknown zoneId is rejected.
  function createGuest(body) {
    var label = String((body && body.label) || "").trim();
    var zoneId = String((body && body.zoneId) || "").trim();
    var password = String((body && body.password) || "");
    if (!label) return Promise.resolve(json(422, errBody("invalid guest", "label must not be empty", "")));
    if (password.length < 8) return Promise.resolve(json(422, errBody("invalid guest", "password must be at least 8 characters", "")));
    if (!zoneId || findGroupIndex(zoneId) === -1) {
      return Promise.resolve(json(422, errBody("invalid guest", "no zone with id " + zoneId, "")));
    }
    for (var i = 0; i < guests.length; i++) {
      if (guests[i].label.toLowerCase() === label.toLowerCase()) {
        return Promise.resolve(json(422, errBody("invalid guest", 'a guest labeled "' + label + '" already exists', "")));
      }
    }
    var created = { id: newGuestID(), label: label, zoneId: zoneId, disabled: false, createdAt: rfc3339(new Date()) };
    return delay(GROUP_MS, null).then(function () {
      guests.push(created);
      return json(201, guestDTO(created));
    });
  }
  function setGuestDisabled(id, body) {
    var idx = findGuestIndex(id);
    if (idx === -1) return Promise.resolve(json(404, errBody("guest not found", "no guest with id " + id, "")));
    var disabled = !!(body && body.disabled);
    return delay(GROUP_MS, null).then(function () {
      guests[idx].disabled = disabled;
      return json(200, guestDTO(guests[idx]));
    });
  }
  function deleteGuest(id) {
    var idx = findGuestIndex(id);
    if (idx === -1) return Promise.resolve(json(404, errBody("guest not found", "no guest with id " + id, "")));
    return delay(GROUP_MS, null).then(function () {
      guests.splice(idx, 1);
      return noContent();
    });
  }

  // --- router table -------------------------------------------------------
  function route(method, path, bodyText) {
    var body = null;
    if (bodyText != null && bodyText !== "") {
      try { body = JSON.parse(bodyText); } catch (e) { body = null; }
    }

    if (path === "/api/csrf" && method === "GET") {
      document.cookie = "tsctl_csrf=demo; path=/; SameSite=Strict";
      return Promise.resolve(json(200, { token: "demo" }));
    }
    if (path === "/api/nodes" && method === "GET") {
      // Signed out -> 401 (the SPA shows the login overlay), as the real backend does.
      if (!session.role) return Promise.resolve(json(401, errBody("login required", "", "")));
      // buildSnapshot already zone-filters for a guest session.
      var snap = buildSnapshot();
      return Promise.resolve(json(200, { nodes: snap.nodes, builtAt: snap.builtAt, netmapErr: snap.netmapErr }));
    }
    // Who am I: role + (for a guest) the bound zone. Mirrors GET /api/me (MeResponse).
    if (path === "/api/me" && method === "GET") {
      if (session.role === "guest") {
        return Promise.resolve(json(200, { role: "guest", zoneId: session.zoneId, zoneName: session.zoneName }));
      }
      if (session.role === "admin") {
        return Promise.resolve(json(200, { role: "admin", zoneId: "", zoneName: "" }));
      }
      return Promise.resolve(json(401, errBody("login required", "", "")));
    }
    // Login: body {label, password}. Empty label = ADMIN (any password in the demo);
    // a non-empty label = GUEST (matched by label against a non-disabled guest; the
    // demo ignores the password). An unknown/disabled label -> uniform 401.
    if (path === "/api/login" && method === "POST") {
      var label = (body && typeof body.label === "string") ? body.label.trim() : "";
      if (label === "") {
        session = { role: "admin", zoneId: "", zoneName: "" };
        return Promise.resolve(json(200, { ok: true }));
      }
      var g = null;
      for (var gi = 0; gi < guests.length; gi++) {
        if (guests[gi].label === label && !guests[gi].disabled) { g = guests[gi]; break; }
      }
      if (!g) return delay(PREFLIGHT_MS, json(401, errBody("invalid credentials", "", "")));
      session = { role: "guest", zoneId: g.zoneId, zoneName: zoneNameById(g.zoneId) };
      return Promise.resolve(json(200, { ok: true }));
    }
    if (path === "/api/logout" && method === "POST") {
      session = { role: null, zoneId: "", zoneName: "" };
      return Promise.resolve(json(200, { ok: true }));
    }

    // Guest CRUD (admin-only -> 403 for a guest session, mirroring RequireAdmin).
    if (path === "/api/guests" && method === "GET") {
      if (session.role !== "admin") return Promise.resolve(json(403, errBody("admin only", "", "")));
      return Promise.resolve(json(200, guests.map(guestDTO)));
    }
    if (path === "/api/guests" && method === "POST") {
      if (session.role !== "admin") return Promise.resolve(json(403, errBody("admin only", "", "")));
      return createGuest(body);
    }
    var gdm = path.match(/^\/api\/guests\/([^/]+)\/disabled$/);
    if (gdm && method === "POST") {
      if (session.role !== "admin") return Promise.resolve(json(403, errBody("admin only", "", "")));
      return setGuestDisabled(decodeURIComponent(gdm[1]), body);
    }
    var gxm = path.match(/^\/api\/guests\/([^/]+)$/);
    if (gxm && method === "DELETE") {
      if (session.role !== "admin") return Promise.resolve(json(403, errBody("admin only", "", "")));
      return deleteGuest(decodeURIComponent(gxm[1]));
    }

    // Zone (group) CRUD.
    if (path === "/api/groups" && method === "GET") {
      return Promise.resolve(json(200, groups.map(rawGroupDTO)));
    }
    if (path === "/api/groups" && method === "POST") {
      var nc = normalizeGroup(body, "");
      if (!nc.ok) return Promise.resolve(json(nc.status, nc.body));
      var created = { id: newGroupID(), name: nc.group.name, consumers: nc.group.consumers, allowedExitNodes: nc.group.allowedExitNodes };
      return delay(GROUP_MS, null).then(function () {
        groups.push(created);
        broadcast(buildSnapshot());
        return json(201, rawGroupDTO(created));
      });
    }
    var gm = path.match(/^\/api\/groups\/([^/]+)$/);
    if (gm) {
      var gid = decodeURIComponent(gm[1]);
      var idx = findGroupIndex(gid);
      if (method === "PUT") {
        if (idx === -1) return Promise.resolve(json(404, errBody("group not found", "no group with id " + gid, "")));
        var nu = normalizeGroup(body, gid);
        if (!nu.ok) return Promise.resolve(json(nu.status, nu.body));
        return delay(GROUP_MS, null).then(function () {
          groups[idx] = { id: gid, name: nu.group.name, consumers: nu.group.consumers, allowedExitNodes: nu.group.allowedExitNodes };
          broadcast(buildSnapshot());
          return json(200, rawGroupDTO(groups[idx]));
        });
      }
      if (method === "DELETE") {
        if (idx === -1) return Promise.resolve(json(404, errBody("group not found", "no group with id " + gid, "")));
        return delay(GROUP_MS, null).then(function () {
          groups.splice(idx, 1);
          broadcast(buildSnapshot());
          return noContent();
        });
      }
    }

    // Exit-node mutation.
    // Guest write-authorization, mirroring the Go authorizeRouterWrite: a guest may
    // act ONLY on routers in its OWN zone, and (for a set) only target that zone's
    // allowed exit nodes (or clear). Admin is unrestricted. 403 (uniform, no oracle)
    // otherwise -- so the demo faithfully shows the server sandbox, not just the UI.
    function guestWriteDenied(routerID, target) {
      if (session.role !== "guest") return null;
      var g = groups[findGroupIndex(session.zoneId)];
      if (!g || (g.consumers || []).indexOf(routerID) === -1) {
        return json(403, errBody("forbidden", "", ""));
      }
      if (target && (g.allowedExitNodes || []).indexOf(target) === -1) {
        return json(403, errBody("forbidden", "", ""));
      }
      return null;
    }

    var rm = path.match(/^\/api\/routers\/([^/]+)\/exit-node$/);
    if (rm && method === "POST") {
      var routerID = decodeURIComponent(rm[1]);
      var target = (body && typeof body.exitNode === "string") ? body.exitNode : "";
      var dEx = guestWriteDenied(routerID, target);
      if (dEx) return Promise.resolve(dEx);
      return setExitNode(routerID, target);
    }

    // SSH probe ("Test SSH").
    var pm = path.match(/^\/api\/routers\/([^/]+)\/probe$/);
    if (pm && method === "POST") {
      var probeID = decodeURIComponent(pm[1]);
      var dPr = guestWriteDenied(probeID, "");
      if (dPr) return Promise.resolve(dPr);
      return probeRouter(probeID);
    }

    // Explicit-Keep gate (stage 2): confirm an awaiting-keep selection.
    var km = path.match(/^\/api\/routers\/([^/]+)\/keep$/);
    if (km && method === "POST") {
      var keepID = decodeURIComponent(km[1]);
      var dKp = guestWriteDenied(keepID, "");
      if (dKp) return Promise.resolve(dKp);
      return keepRouter(keepID);
    }

    // Any other /api/ path: 404 (mirrors the backend's unknown-route behavior).
    if (path.indexOf("/api/") === 0) {
      return Promise.resolve(json(404, errBody("not found", "no handler for " + method + " " + path, "")));
    }

    // Non-API request: pass through to the real network (e.g. nothing else here).
    if (origFetch) return origFetch.apply(null, arguments.length > 3 ? [].slice.call(arguments, 3) : []);
    return Promise.resolve(new Response("", { status: 404 }));
  }

  // window.fetch replacement. Accepts (string|Request, init) like the real API;
  // the SPA only ever passes string URLs with an init object.
  function mockFetch(input, init) {
    init = init || {};
    var url, method, bodyText;
    if (input && typeof input === "object" && typeof input.url === "string") {
      url = input.url;
      method = (init.method || input.method || "GET");
      bodyText = (init.body != null) ? init.body : null;
    } else {
      url = String(input);
      method = (init.method || "GET");
      bodyText = (init.body != null) ? init.body : null;
    }
    method = String(method).toUpperCase();
    var path;
    try { path = new URL(url, location.href).pathname; } catch (e) { path = url; }

    // Non-API: defer to the real fetch with the ORIGINAL arguments.
    if (path.indexOf("/api/") !== 0) {
      if (origFetch) return origFetch(input, init);
      return Promise.resolve(new Response("", { status: 404 }));
    }
    return route(method, path, typeof bodyText === "string" ? bodyText : null);
  }

  // ---------------------------------------------------------- install ------
  window.fetch = mockFetch;
  window.EventSource = MockEventSource;

  if (typeof console !== "undefined" && console.info) {
    console.info("tsctl LIVE DEMO mock active — fetch + EventSource are mocked, no backend.");
  }
})();
