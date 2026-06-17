// tsctl SPA — vanilla JS, no build step, no external requests.
// Consumes the wire contract in PHASE_B.md §3. SSE Snapshot frames are the
// primary source of truth; REST is used only for first paint, the CSRF token,
// and the exit-node mutation. The device's ACTUAL state always drives the UI —
// a change is never shown as success until the backend confirms it.
(function () {
  "use strict";

  var STALE_SECS = 90; // builtAt older than this → "may be stale" banner
  var RECONNECT_MS = 3000;
  var TICK_MS = 10000; // refresh relative times / staleness without new frames

  // ---------------------------------------------------------------- state ---
  var state = {
    csrfToken: null,
    snapshot: null, // last full SSE Snapshot {nodes, routers, netmapAt, netmapErr, builtAt}
    nodesOnly: null, // {nodes, builtAt, netmapErr} from /api/nodes first-paint fallback
    gotSseFrame: false,
    connection: "connecting", // connecting | open | reconnecting
    globalError: "",
    busyRouters: {}, // stableID -> true while a POST is in flight (local "applying")
    busyTarget: {}, // stableID -> the value the user picked while busy
    actionErrors: {}, // stableID -> {error, detail, stderr}
    es: null,
    reconnectTimer: null,
  };

  // diff-friendly element registries (keyed by stableID)
  var nodeEls = {};
  var routerEls = {};

  // --------------------------------------------------------------- helpers ---
  function $(sel) { return document.querySelector(sel); }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  // inline SVG icons — no external assets, no icon fonts ------------------
  var SVGNS = "http://www.w3.org/2000/svg";
  function svgEl(tag, attrs) {
    var n = document.createElementNS(SVGNS, tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    return n;
  }
  function dotIcon(cls) {
    var s = svgEl("svg", { viewBox: "0 0 10 10", width: "10", height: "10", "aria-hidden": "true" });
    s.setAttribute("class", "dot " + (cls || ""));
    s.appendChild(svgEl("circle", { cx: "5", cy: "5", r: "5" }));
    return s;
  }
  // SVG elements expose className as a read-only SVGAnimatedString, so the
  // online state must be applied with setAttribute, not .className.
  function setDot(node, online) {
    node.setAttribute("class", "dot " + (online ? "dot-on" : "dot-off"));
    node.setAttribute("role", "img");
    node.setAttribute("aria-label", online ? "online" : "offline");
  }
  function arrowIcon() {
    var s = svgEl("svg", { viewBox: "0 0 16 16", width: "14", height: "14", "aria-hidden": "true" });
    s.setAttribute("class", "arrow-icon");
    s.appendChild(svgEl("path", {
      d: "M2.5 8h9M8 4.5L11.5 8 8 11.5",
      fill: "none", stroke: "currentColor", "stroke-width": "1.6",
      "stroke-linecap": "round", "stroke-linejoin": "round",
    }));
    return s;
  }
  function chevronIcon() {
    var s = svgEl("svg", { viewBox: "0 0 16 16", width: "13", height: "13", "aria-hidden": "true" });
    s.setAttribute("class", "select-chevron");
    s.appendChild(svgEl("path", {
      d: "M4.5 6.5L8 3l3.5 3.5M4.5 9.5L8 13l3.5-3.5",
      fill: "none", stroke: "currentColor", "stroke-width": "1.5",
      "stroke-linecap": "round", "stroke-linejoin": "round",
    }));
    return s;
  }
  function spinnerIcon(cls) {
    var s = svgEl("svg", { viewBox: "0 0 16 16", width: "14", height: "14", "aria-hidden": "true" });
    s.setAttribute("class", "spinner " + (cls || ""));
    s.appendChild(svgEl("circle", {
      cx: "8", cy: "8", r: "6", fill: "none", stroke: "currentColor",
      "stroke-width": "2", "stroke-linecap": "round",
      "stroke-dasharray": "30", "stroke-dashoffset": "10",
    }));
    return s;
  }

  function setText(node, text) {
    text = text == null ? "" : String(text);
    if (node.textContent !== text) node.textContent = text;
  }

  function parseTime(iso) {
    if (!iso) return null;
    var t = new Date(iso);
    if (isNaN(t.getTime())) return null;
    if (t.getUTCFullYear() <= 1) return null; // Go zero time → "0001-01-01T00:00:00Z"
    return t;
  }

  function relTime(iso) {
    var t = parseTime(iso);
    if (!t) return "never";
    var secs = Math.round((Date.now() - t.getTime()) / 1000);
    if (secs < 0) secs = 0;
    if (secs < 60) return secs + "s ago";
    var m = Math.floor(secs / 60);
    if (m < 60) return m + "m ago";
    var h = Math.floor(m / 60);
    if (h < 24) return h + "h ago";
    return Math.floor(h / 24) + "d ago";
  }

  function humanBytes(n) {
    if (typeof n !== "number" || !isFinite(n) || n < 0) return "–";
    var units = ["B", "KB", "MB", "GB", "TB", "PB"];
    var i = 0, v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + " " + units[i];
  }

  function exitRefLabel(ref) {
    if (!ref) return "none (direct)";
    var name = ref.name || ref.stableID || ref.ip || "unknown";
    return ref.ip ? name + " (" + ref.ip + ")" : name;
  }

  function targetLabel(ref) {
    if (!ref) return "Direct";
    return ref.name || ref.stableID || ref.ip || "exit node";
  }

  function badgeLabel(type) {
    if (type === "exit-node") return "exit node";
    if (type === "router") return "router";
    return "node";
  }

  // generic keyed reconcile: create/update in place, remove stale (no full rebuild)
  function reconcile(container, items, keyFn, createFn, updateFn, registry) {
    var seen = {};
    items.forEach(function (item) {
      var key = keyFn(item);
      seen[key] = true;
      var rec = registry[key];
      if (!rec) {
        rec = createFn(item);
        registry[key] = rec;
        container.appendChild(rec.root);
      }
      updateFn(rec, item);
    });
    Object.keys(registry).forEach(function (key) {
      if (!seen[key]) {
        var rec = registry[key];
        if (rec.root && rec.root.parentNode) rec.root.parentNode.removeChild(rec.root);
        delete registry[key];
      }
    });
  }

  // ----------------------------------------------------------- node cards ---
  function createNodeCard() {
    var root = el("div", "node");
    var head = el("div", "node-head");
    var dot = dotIcon();
    var badge = el("span", "badge");
    var name = el("span", "node-name");
    head.appendChild(dot);
    head.appendChild(badge);
    head.appendChild(name);

    var ips = el("div", "node-ips");
    var meta = el("div", "node-meta");
    var os = el("span", "node-os");
    var seen = el("span", "node-seen");
    meta.appendChild(os);
    meta.appendChild(seen);

    root.appendChild(head);
    root.appendChild(ips);
    root.appendChild(meta);
    return { root: root, dot: dot, badge: badge, name: name, ips: ips, os: os, seen: seen };
  }

  function updateNodeCard(rec, n) {
    var type = n.type || "generic";
    setText(rec.badge, badgeLabel(type));
    rec.badge.className = "badge badge-" + type;

    var online = n.online === true;
    setDot(rec.dot, online);

    setText(rec.name, n.name || n.hostname || n.stableID || "(unknown)");

    var ips = Array.isArray(n.tailscaleIPs) ? n.tailscaleIPs : [];
    setText(rec.ips, ips.length ? ips.join(", ") : "no IPs");

    setText(rec.os, n.os || "unknown OS");
    setText(rec.seen, online ? "online" : "last seen " + relTime(n.lastSeen));
  }

  // --------------------------------------------------------- router cards ---
  function createRouterCard(rv) {
    var sid = (rv.node && rv.node.stableID) || "";
    var root = el("div", "router");

    var head = el("div", "router-head");
    var dot = dotIcon();
    var name = el("span", "router-name");
    var stateBadge = el("span", "state");
    head.appendChild(dot);
    head.appendChild(name);
    head.appendChild(stateBadge);

    var ips = el("div", "router-ips");
    var currentLine = el("div", "current");
    currentLine.appendChild(arrowIcon());
    var currentText = el("span", "current-text");
    currentLine.appendChild(currentText);

    var picker = el("div", "picker");
    var label = el("label", "picker-label", "Exit node");
    var selectWrap = el("div", "select-wrap");
    var select = el("select", "exit-select");
    select.id = "sel-" + String(sid).replace(/[^a-zA-Z0-9_-]/g, "_");
    label.htmlFor = select.id;
    selectWrap.appendChild(select);
    selectWrap.appendChild(chevronIcon());
    var pending = el("span", "pending hidden");
    picker.appendChild(label);
    picker.appendChild(selectWrap);
    picker.appendChild(pending);

    var stats = el("div", "stats");
    var errBox = el("div", "error-box hidden");

    root.appendChild(head);
    root.appendChild(ips);
    root.appendChild(currentLine);
    root.appendChild(picker);
    root.appendChild(stats);
    root.appendChild(errBox);

    select.addEventListener("change", function () { onPick(sid, select.value); });

    return {
      root: root, dot: dot, name: name, stateBadge: stateBadge, ips: ips,
      currentLine: currentLine, currentText: currentText, select: select, pending: pending,
      stats: stats, errBox: errBox, optionsSig: null,
    };
  }

  function applyStateBadge(node, st) {
    var map = {
      ok: ["ok", "state-ok"],
      pending: ["pending", "state-pending"],
      unconfirmed: ["unconfirmed", "state-unconfirmed"],
      unreachable: ["unreachable", "state-unreachable"],
    };
    var m = map[st] || [String(st || "?"), "state-unknown"];
    setText(node, m[0]);
    node.className = "state " + m[1];
  }

  function setPending(rec, kind, text) {
    rec.pending.textContent = "";
    if (kind === "none") {
      rec.pending.className = "pending hidden";
      return;
    }
    rec.pending.className = "pending " + (kind === "amber" ? "pending-amber" : "pending-spin");
    if (kind === "spin") rec.pending.appendChild(spinnerIcon());
    if (text) rec.pending.appendChild(document.createTextNode(" " + text));
  }

  // build the shared exit-node option list from the snapshot's nodes
  function exitOptionsFor(snap, selfID) {
    var opts = [{ value: "", label: "Direct (no exit node)" }];
    var nodes = snap && Array.isArray(snap.nodes) ? snap.nodes : [];
    nodes.forEach(function (n) {
      if (n.exitNodeOption === true && n.stableID && n.stableID !== selfID) {
        var label = n.name || n.hostname || n.stableID;
        if (n.online !== true) label += " (offline)";
        opts.push({ value: n.stableID, label: label });
      }
    });
    return opts;
  }

  function rebuildOptions(rec, optList, rv) {
    var cur = rv.currentExitNode;
    var des = rv.desired;
    var sig = optList.map(function (o) { return o.value + "|" + o.label; }).join("")
      + "#" + (cur && cur.stableID ? cur.stableID : "")
      + "#" + (des && des.stableID ? des.stableID : "");
    if (rec.optionsSig === sig) return;
    rec.optionsSig = sig;

    var sel = rec.select;
    while (sel.firstChild) sel.removeChild(sel.firstChild);
    var present = {};
    optList.forEach(function (o) {
      var opt = document.createElement("option");
      opt.value = o.value;
      opt.textContent = o.label;
      sel.appendChild(opt);
      present[o.value] = true;
    });
    // make sure the actual/desired selection is always representable
    [cur, des].forEach(function (ref) {
      if (ref && ref.stableID && !present[ref.stableID]) {
        var opt = document.createElement("option");
        opt.value = ref.stableID;
        opt.textContent = exitRefLabel(ref) + " (unavailable)";
        sel.appendChild(opt);
        present[ref.stableID] = true;
      }
    });
  }

  function ensureOption(sel, value) {
    if (value == null) value = "";
    for (var i = 0; i < sel.options.length; i++) {
      if (sel.options[i].value === value) return;
    }
    var opt = document.createElement("option");
    opt.value = value;
    opt.textContent = value || "Direct";
    sel.appendChild(opt);
  }

  function refreshSelect(rec, rv) {
    var sel = rec.select;
    var node = rv.node || {};
    var sid = node.stableID;
    var st = rv.state || "";
    var localBusy = !!state.busyRouters[sid];
    var reachable = rv.reachable !== false && node.online === true;
    var hasBusyTarget = Object.prototype.hasOwnProperty.call(state.busyTarget, sid);

    // pending indicator (always safe to update)
    if (localBusy) setPending(rec, "spin", "Applying…");
    else if (st === "pending") setPending(rec, "spin", "Applying " + targetLabel(rv.desired) + " — awaiting confirmation");
    else if (st === "unconfirmed") setPending(rec, "amber", "Sent but not confirmed: " + targetLabel(rv.desired));
    else setPending(rec, "none", "");

    // never fight the user while they have the dropdown focused
    if (document.activeElement === sel) return;

    var showDesired = localBusy || st === "pending" || st === "unconfirmed";
    var val, disabled;
    if (showDesired) {
      val = hasBusyTarget ? state.busyTarget[sid] : (rv.desired ? rv.desired.stableID : "");
      disabled = true;
    } else {
      // ok / unreachable / unknown → reflect the device's ACTUAL current selection
      val = rv.currentExitNode ? rv.currentExitNode.stableID : "";
      disabled = !reachable;
    }
    ensureOption(sel, val);
    if (sel.value !== (val == null ? "" : val)) sel.value = val == null ? "" : val;
    sel.disabled = disabled;
  }

  function updateRouterCard(rec, rv, optList) {
    var node = rv.node || {};
    var online = node.online === true;
    var st = rv.state || (online ? "ok" : "unreachable");

    setText(rec.name, node.name || node.hostname || node.stableID || "(router)");
    setDot(rec.dot, online);
    applyStateBadge(rec.stateBadge, st);

    var ips = Array.isArray(node.tailscaleIPs) ? node.tailscaleIPs : [];
    var ipText = ips.length ? ips.join(", ") : "no IPs";
    setText(rec.ips, (node.os ? node.os + " · " : "") + ipText);

    setText(rec.currentText, "Current exit node: " + exitRefLabel(rv.currentExitNode));

    rebuildOptions(rec, optList, rv);
    refreshSelect(rec, rv);

    var s = rv.stats || {};
    setText(rec.stats, "rx " + humanBytes(s.rxBytes) + " · tx " + humanBytes(s.txBytes)
      + " · handshake " + relTime(s.lastHandshake)
      + " · confirmed " + relTime(rv.lastConfirmedAt));

    // surface errors (server-side lastError + last POST failure) — never swallow
    var parts = [];
    if (rv.lastError) parts.push(rv.lastError);
    var ae = state.actionErrors[node.stableID];
    if (ae) {
      var msg = ae.error || "Request failed";
      if (ae.detail) msg += " — " + ae.detail;
      if (ae.stderr) msg += "\n" + ae.stderr;
      parts.push(msg);
    }
    if (parts.length) {
      setText(rec.errBox, parts.join("\n"));
      rec.errBox.className = "error-box";
    } else {
      setText(rec.errBox, "");
      rec.errBox.className = "error-box hidden";
    }
  }

  // ------------------------------------------------------------- mutation ---
  function setActionError(sid, info) { state.actionErrors[sid] = info; }
  function clearActionError(sid) { delete state.actionErrors[sid]; }

  function onPick(sid, value) {
    if (!sid) return;
    if (!state.csrfToken) {
      setActionError(sid, { error: "No CSRF token yet — reload the page" });
      render();
      return;
    }
    state.busyRouters[sid] = true;
    state.busyTarget[sid] = value;
    clearActionError(sid);
    render(); // show "Applying…" immediately (NOT optimistic success)
    postExitNode(sid, value);
  }

  function mergeRouterView(rv) {
    if (!state.snapshot) state.snapshot = { nodes: [], routers: [] };
    if (!Array.isArray(state.snapshot.routers)) state.snapshot.routers = [];
    var id = rv.node && rv.node.stableID;
    var arr = state.snapshot.routers;
    for (var i = 0; i < arr.length; i++) {
      if (arr[i].node && arr[i].node.stableID === id) { arr[i] = rv; return; }
    }
    arr.push(rv);
  }

  function postExitNode(sid, value) {
    fetch("/api/routers/" + encodeURIComponent(sid) + "/exit-node", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Tsctl-CSRF": state.csrfToken,
      },
      body: JSON.stringify({ exitNode: value }),
    })
      .then(function (resp) {
        return resp.text().then(function (body) {
          var data = null;
          try { data = body ? JSON.parse(body) : null; } catch (e) { data = null; }
          if (!resp.ok) {
            setActionError(sid, (data && (data.error || data.detail || data.stderr))
              ? data
              : { error: "HTTP " + resp.status, detail: body || "" });
          } else {
            clearActionError(sid);
            if (data) mergeRouterView(data); // reflect ACTUAL returned state
          }
        });
      })
      .catch(function (err) {
        setActionError(sid, { error: "Network error", detail: String((err && err.message) || err) });
      })
      .then(function () {
        delete state.busyRouters[sid];
        delete state.busyTarget[sid];
        render();
      });
  }

  // --------------------------------------------------------------- render ---
  function renderConn() {
    var c = $("#conn-status");
    if (!c) return;
    var map = {
      open: ["live", "conn conn-live"],
      connecting: ["connecting…", "conn conn-wait"],
      reconnecting: ["reconnecting…", "conn conn-wait"],
    };
    var m = map[state.connection] || map.connecting;
    c.textContent = "";
    if (state.connection === "open") c.appendChild(dotIcon("dot-on"));
    else c.appendChild(spinnerIcon());
    c.appendChild(document.createTextNode(" " + m[0]));
    c.className = m[1];
  }

  function renderGlobalError() {
    var b = $("#global-error");
    if (state.globalError) { setText(b, state.globalError); b.classList.remove("hidden"); }
    else { setText(b, ""); b.classList.add("hidden"); }
  }

  function renderNetmapErr(snap) {
    var b = $("#netmap-err");
    var err = snap && snap.netmapErr;
    if (err) { setText(b, "Inventory error: " + err); b.classList.remove("hidden"); }
    else { setText(b, ""); b.classList.add("hidden"); }
  }

  function renderStale(snap) {
    var b = $("#stale-banner");
    var u = $("#updated");
    var t = parseTime(snap && snap.builtAt);
    if (!t) {
      b.classList.add("hidden");
      if (u) setText(u, state.gotSseFrame ? "" : "Waiting for first update…");
      return;
    }
    if (u) setText(u, "Updated " + relTime(snap.builtAt));
    var age = Math.round((Date.now() - t.getTime()) / 1000);
    if (age > STALE_SECS) {
      setText(b, "Data may be stale — last updated " + relTime(snap.builtAt) + ".");
      b.classList.remove("hidden");
    } else {
      b.classList.add("hidden");
    }
  }

  function render() {
    renderConn();
    renderGlobalError();

    var snap = state.snapshot;
    renderNetmapErr(snap || state.nodesOnly);
    renderStale(snap || state.nodesOnly);

    // node list: prefer the live snapshot; fall back to /api/nodes for first paint
    var nodes = snap && Array.isArray(snap.nodes) ? snap.nodes
      : (state.nodesOnly && Array.isArray(state.nodesOnly.nodes) ? state.nodesOnly.nodes : []);
    reconcile(
      $("#nodes"), nodes,
      function (n) { return n.stableID || (n.name || "") + "|" + (n.hostname || ""); },
      createNodeCard, updateNodeCard, nodeEls
    );
    $("#nodes-empty").classList.toggle("hidden", nodes.length > 0);

    // routers only come from the SSE Snapshot
    var routers = snap && Array.isArray(snap.routers) ? snap.routers : [];
    var optList = exitOptionsFor(snap);
    reconcile(
      $("#routers"), routers,
      function (rv) { return (rv.node && rv.node.stableID) || JSON.stringify(rv.node || {}); },
      createRouterCard,
      function (rec, rv) { updateRouterCard(rec, rv, optList); },
      routerEls
    );
    $("#routers-empty").classList.toggle("hidden", routers.length > 0 || !state.gotSseFrame);
  }

  // ----------------------------------------------------------- networking ---
  function fetchCSRF() {
    return fetch("/api/csrf", { headers: { Accept: "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("CSRF HTTP " + r.status); return r.json(); })
      .then(function (d) {
        state.csrfToken = (d && d.token) || null;
        if (!state.csrfToken) throw new Error("CSRF response missing token");
        state.globalError = "";
        renderGlobalError();
      })
      .catch(function (e) {
        state.globalError = "Could not obtain CSRF token — exit-node changes are disabled: "
          + ((e && e.message) || e);
        renderGlobalError();
      });
  }

  function fetchNodesFallback() {
    fetch("/api/nodes", { headers: { Accept: "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("nodes HTTP " + r.status); return r.json(); })
      .then(function (d) { if (!state.gotSseFrame) { state.nodesOnly = d; render(); } })
      .catch(function (e) {
        if (!state.gotSseFrame) {
          state.globalError = "First-paint fetch failed (waiting for live stream): "
            + ((e && e.message) || e);
          renderGlobalError();
        }
      });
  }

  function connectSSE() {
    var es;
    try {
      es = new EventSource("/api/events");
    } catch (e) {
      state.connection = "reconnecting";
      renderConn();
      scheduleReconnect();
      return;
    }
    state.es = es;

    es.onopen = function () {
      state.connection = "open";
      renderConn();
    };

    es.onmessage = function (ev) {
      if (!ev || !ev.data) return;
      var snap;
      try { snap = JSON.parse(ev.data); } catch (e) {
        state.globalError = "Received a malformed live update frame.";
        renderGlobalError();
        return;
      }
      state.gotSseFrame = true;
      state.connection = "open";
      state.globalError = "";
      state.snapshot = snap;
      render();
    };

    es.onerror = function () {
      // EventSource auto-reconnects while readyState === CONNECTING(0); only when
      // it has fully CLOSED(2) do we recreate it ourselves.
      state.connection = "reconnecting";
      renderConn();
      if (es.readyState === EventSource.CLOSED) {
        try { es.close(); } catch (e) { /* already closed */ }
        scheduleReconnect();
      }
    };
  }

  function scheduleReconnect() {
    if (state.reconnectTimer) return;
    state.reconnectTimer = setTimeout(function () {
      state.reconnectTimer = null;
      connectSSE();
    }, RECONNECT_MS);
  }

  // ------------------------------------------------------------------ init ---
  function init() {
    render();
    fetchCSRF();
    fetchNodesFallback();
    connectSSE();
    setInterval(render, TICK_MS); // keep relative times / staleness fresh
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
