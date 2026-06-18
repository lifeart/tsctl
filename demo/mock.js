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
//                                             zone-enforcement reject / clear
//   POST   /api/login, /api/logout         -> 200 (no auth in the demo)
//   (anything else under /api/)            -> 404
//   EventSource /api/events                -> full Snapshot frame on connect, then
//                                             a fresh frame every ~3s (stats tick,
//                                             one generic node flips online/offline)
(function () {
  "use strict";

  // ----------------------------------------------------------- timings -----
  var APPLY_MS = 1200;     // scripted SetExitNode latency (UI shows "Applying…")
  var PREFLIGHT_MS = 140;  // a pre-flight rejection resolves quickly
  var OPEN_MS = 120;       // EventSource "connect" delay (well under the 8s watchdog)
  var TICK_MS = 3000;      // SSE frame cadence + world time-variation

  // -------------------------------------------------- fixture addresses ----
  // Mirrors internal/demo/demo.go (plus one extra "control error" router).
  var r1IP = "100.64.0.10"; // home-router      — online, Direct
  var r2IP = "100.64.0.11"; // office-router    — online, via tokyo, stats tick
  var r3IP = "100.64.0.12"; // cabin-router     — OFFLINE (control disabled)
  var r4IP = "100.64.0.13"; // warehouse-router — online, current exit OFFLINE+out-of-zone -> warn
  var r5IP = "100.64.0.14"; // depot-router     — ONLINE but CONTROL ERROR (reachable:false)

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
  var ROUTER_IPS = [r1IP, r2IP, r3IP, r4IP, r5IP];

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
  var routers = {};
  routers[r1IP] = { cur: "", desired: "", rx: 0, tx: 0, hs: null, controlError: false, lastError: "" };
  routers[r2IP] = { cur: tokyoIP, desired: "", rx: 18400000, tx: 4200000, hs: ago(9000), controlError: false, lastError: "" };
  routers[r3IP] = { cur: "", desired: "", rx: 0, tx: 0, hs: null, controlError: false, lastError: "" };
  routers[r4IP] = { cur: londonIP, desired: "", rx: 940000, tx: 210000, hs: ago(11 * 60000), controlError: false, lastError: "" };
  routers[r5IP] = { cur: frankfurtIP, desired: "", rx: 0, tx: 0, hs: null, controlError: true,
    lastError: "ssh: handshake failed: host key mismatch for " + r5IP +
      " (tsctl can reach the device but cannot authenticate to control it)" };

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

  function buildSnapshot() {
    var iso = rfc3339(new Date());
    return {
      nodes: nodes.map(nodeDTO),
      routers: ROUTER_IPS.map(routerViewDTO),
      groups: groupViewDTOs(),
      netmapAt: iso,
      netmapErr: "",
      builtAt: iso,
    };
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
      var resp;
      if (!targetID) {
        // Clear -> confirmed Direct.
        rt.cur = ""; rt.desired = ""; rt.rx = 0; rt.tx = 0; rt.hs = null; rt.lastError = "";
        resp = json(200, routerViewDTO(ip));
      } else if (targetID === "n-exit-flaky") {
        // Applied but NOT confirmed: leave current at prev, mark unconfirmed (amber).
        rt.desired = flakyIP;
        rt.lastError = "router " + ip + ": exit-node not confirmed (revert will fire): want " +
          flakyIP + ", got " + (rt.cur || "(none)");
        resp = json(200, routerViewDTO(ip)); // state:"unconfirmed"
      } else if (targetID === "n-exit-broken") {
        // The apply command itself failed: the change did NOT take (current
        // unchanged); surface a non-2xx {error,detail,stderr}.
        var detail = "router " + ip + ": apply exit-node exited 1: permission denied";
        resp = json(502, errBody("router command failed", detail, "permission denied"));
      } else {
        // Normal target -> confirmed.
        var t2 = nodeByID(targetID);
        rt.cur = primaryIPv4(t2.ips); rt.desired = ""; rt.rx = 96000; rt.tx = 24000;
        rt.hs = new Date(); rt.lastError = "";
        resp = json(200, routerViewDTO(ip));
      }
      broadcast(buildSnapshot());
      return resp;
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
      return Promise.resolve(json(200, {
        nodes: nodes.map(nodeDTO), builtAt: rfc3339(new Date()), netmapErr: "",
      }));
    }
    if (path === "/api/login" && method === "POST") {
      return Promise.resolve(json(200, { ok: true }));
    }
    if (path === "/api/logout" && method === "POST") {
      return Promise.resolve(json(200, { ok: true }));
    }

    // Zone (group) CRUD.
    if (path === "/api/groups" && method === "GET") {
      return Promise.resolve(json(200, groups.map(rawGroupDTO)));
    }
    if (path === "/api/groups" && method === "POST") {
      var nc = normalizeGroup(body, "");
      if (!nc.ok) return Promise.resolve(json(nc.status, nc.body));
      var created = { id: newGroupID(), name: nc.group.name, consumers: nc.group.consumers, allowedExitNodes: nc.group.allowedExitNodes };
      groups.push(created);
      broadcast(buildSnapshot());
      return Promise.resolve(json(201, rawGroupDTO(created)));
    }
    var gm = path.match(/^\/api\/groups\/([^/]+)$/);
    if (gm) {
      var gid = decodeURIComponent(gm[1]);
      var idx = findGroupIndex(gid);
      if (method === "PUT") {
        if (idx === -1) return Promise.resolve(json(404, errBody("group not found", "no group with id " + gid, "")));
        var nu = normalizeGroup(body, gid);
        if (!nu.ok) return Promise.resolve(json(nu.status, nu.body));
        groups[idx] = { id: gid, name: nu.group.name, consumers: nu.group.consumers, allowedExitNodes: nu.group.allowedExitNodes };
        broadcast(buildSnapshot());
        return Promise.resolve(json(200, rawGroupDTO(groups[idx])));
      }
      if (method === "DELETE") {
        if (idx === -1) return Promise.resolve(json(404, errBody("group not found", "no group with id " + gid, "")));
        groups.splice(idx, 1);
        broadcast(buildSnapshot());
        return Promise.resolve(noContent());
      }
    }

    // Exit-node mutation.
    var rm = path.match(/^\/api\/routers\/([^/]+)\/exit-node$/);
    if (rm && method === "POST") {
      var routerID = decodeURIComponent(rm[1]);
      var target = (body && typeof body.exitNode === "string") ? body.exitNode : "";
      return setExitNode(routerID, target);
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
