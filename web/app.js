// tsctl SPA — vanilla JS, no build step, no external requests, CSP-friendly
// (no inline handlers; all listeners attached in code; all fetches same-origin).
//
// Consumes the wire contract in PHASE_B.md §3. SSE Snapshot frames are the
// primary source of truth; REST is used only for first paint, the CSRF token,
// and the exit-node mutation. The device's ACTUAL state always drives the UI —
// a change is NEVER shown as success until the backend confirms it.
(function () {
  "use strict";

  // ----------------------------------------------------------- constants ---
  var STALE_SECS = 90;        // builtAt older than this → "may be stale" banner
  var REVERT_WINDOW = 60;     // dead-man's-switch window (s) for the countdown
  var TICK_MS = 1000;         // re-render cadence for relative times + countdown
  var RECONNECT_MIN = 1000;   // SSE reconnect backoff floor
  var RECONNECT_MAX = 15000;  // SSE reconnect backoff ceiling
  var OPEN_WATCHDOG_MS = 8000; // no live stream within this → poll fallback
  var POLL_FALLBACK_MS = 5000; // GET /api/nodes cadence while SSE is unavailable
  var SEARCH_THRESHOLD = 6;   // show the device filter when more than this many

  var CHIPS = [
    { id: "all", label: "All" },
    { id: "online", label: "Online" },
    { id: "router", label: "Routers" },
    { id: "exit", label: "Exit nodes" },
    { id: "generic", label: "Other" },
  ];

  // ---------------------------------------------------------------- state ---
  var state = {
    csrfToken: null,
    snapshot: null,    // last full SSE Snapshot {nodes, routers, groups, netmapAt, netmapErr, builtAt}
    nodesOnly: null,   // {nodes, builtAt, netmapErr} from GET /api/nodes
    gotSseFrame: false,
    connection: "connecting", // connecting | open | reconnecting | offline
    globalError: "",
    authError: false,   // 403: request BLOCKED by Host/CSRF (DNS-rebinding) — full view
    authDetail: "",
    needsLogin: false,  // 401: authenticate — show the password login overlay
    loginBusy: false,   // a POST /api/login is in flight
    loginError: "",     // last login failure message (e.g. "Incorrect password.")
    loginDisabled: false, // server has no UI password (login returns 404) — tailnet-only
    sessionActive: false, // signed in via password → show the "Sign out" affordance
    busyRouters: {},   // stableID -> true while a POST is in flight
    busyTarget: {},    // stableID -> the value picked while busy
    actionErrors: {},  // stableID -> {error, detail, stderr}
    pendingSince: {},  // stableID -> ms when the pending/applying began (countdown)
    es: null,
    reconnectTimer: null,
    reconnectDelay: RECONNECT_MIN,
    sseEverOpened: false,
    openWatchdog: null,
    pollFallback: false,
    pollTimer: null,
    filter: { text: "", type: "all" },
    view: "graph",        // "graph" (zone graph, default) | "cards" (router/device list)
    selectedZone: null,   // selected zone id, or UNGROUPED, or null (= default)
    graphDrag: null,      // active drag descriptor while rewiring by drag
  };

  var nodeEls = {};       // stableID -> node card record
  var routerEls = {};     // stableID -> router card record
  var consumerEls = {};   // stableID -> graph consumer-node record (left column)
  var exitEls = {};       // key      -> graph exit-node record (right column)
  var zoneTabEls = {};    // zone id  -> zone selector tab record
  var activeModal = null;
  var activeMenu = null;  // open per-consumer rewire menu (keyboard/click path)
  var rafPending = false; // resize redraw coalescing

  // --------------------------------------------------------------- helpers ---
  function $(sel) { return document.querySelector(sel); }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function setText(node, text) {
    text = text == null ? "" : String(text);
    if (node.textContent !== text) node.textContent = text;
  }

  function show(node, visible) { node.classList.toggle("hidden", !visible); }

  // inline SVG icons — no external assets, no icon fonts -------------------
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
  // SVG className is a read-only SVGAnimatedString → use setAttribute.
  function setDot(node, online) {
    node.setAttribute("class", "dot " + (online ? "dot-on" : "dot-off"));
    node.setAttribute("role", "img");
    node.setAttribute("aria-label", online ? "online" : "offline");
  }
  function arrowIcon() {
    var s = svgEl("svg", { viewBox: "0 0 16 16", width: "14", height: "14", "aria-hidden": "true" });
    s.setAttribute("class", "arrow-icon");
    s.appendChild(svgEl("path", {
      d: "M2.5 8h9M8 4.5L11.5 8 8 11.5", fill: "none", stroke: "currentColor",
      "stroke-width": "1.6", "stroke-linecap": "round", "stroke-linejoin": "round",
    }));
    return s;
  }
  function chevronIcon() {
    var s = svgEl("svg", { viewBox: "0 0 16 16", width: "13", height: "13", "aria-hidden": "true" });
    s.setAttribute("class", "select-chevron");
    s.appendChild(svgEl("path", {
      d: "M4.5 6.5L8 3l3.5 3.5M4.5 9.5L8 13l3.5-3.5", fill: "none", stroke: "currentColor",
      "stroke-width": "1.5", "stroke-linecap": "round", "stroke-linejoin": "round",
    }));
    return s;
  }
  function spinnerIcon(cls) {
    var s = svgEl("svg", { viewBox: "0 0 16 16", width: "14", height: "14", "aria-hidden": "true" });
    s.setAttribute("class", "spinner " + (cls || ""));
    s.appendChild(svgEl("circle", {
      cx: "8", cy: "8", r: "6", fill: "none", stroke: "currentColor", "stroke-width": "2",
      "stroke-linecap": "round", "stroke-dasharray": "30", "stroke-dashoffset": "10",
    }));
    return s;
  }
  function warnIcon() {
    var s = svgEl("svg", { viewBox: "0 0 16 16", width: "15", height: "15", "aria-hidden": "true" });
    s.setAttribute("class", "warn-icon");
    s.appendChild(svgEl("path", {
      d: "M8 1.6 15 14H1L8 1.6Z", fill: "none", stroke: "currentColor",
      "stroke-width": "1.4", "stroke-linejoin": "round",
    }));
    s.appendChild(svgEl("path", { d: "M8 6.2v3.4M8 11.6v.01", fill: "none", stroke: "currentColor", "stroke-width": "1.5", "stroke-linecap": "round" }));
    return s;
  }
  function checkIcon() {
    var s = svgEl("svg", { viewBox: "0 0 16 16", width: "16", height: "16", "aria-hidden": "true" });
    s.setAttribute("class", "toast-icon");
    s.appendChild(svgEl("path", { d: "M3 8.5 6.5 12 13 4.5", fill: "none", stroke: "currentColor", "stroke-width": "1.8", "stroke-linecap": "round", "stroke-linejoin": "round" }));
    return s;
  }
  function alertIcon() {
    var s = svgEl("svg", { viewBox: "0 0 16 16", width: "16", height: "16", "aria-hidden": "true" });
    s.setAttribute("class", "toast-icon");
    s.appendChild(svgEl("circle", { cx: "8", cy: "8", r: "6.4", fill: "none", stroke: "currentColor", "stroke-width": "1.4" }));
    s.appendChild(svgEl("path", { d: "M8 4.6v4M8 11v.01", fill: "none", stroke: "currentColor", "stroke-width": "1.6", "stroke-linecap": "round" }));
    return s;
  }

  // time / formatting ------------------------------------------------------
  function parseTime(iso) {
    if (!iso) return null;
    var t = new Date(iso);
    if (isNaN(t.getTime())) return null;
    if (t.getUTCFullYear() <= 1) return null; // Go zero time
    return t;
  }
  // Clock-skew safe: a time in the future (negative age) clamps to "just now".
  function relTime(iso) {
    var t = parseTime(iso);
    if (!t) return "never";
    var secs = Math.round((Date.now() - t.getTime()) / 1000);
    if (secs <= 2) return "just now";
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
    if (!ref) return "Direct (no exit node)";
    var name = ref.name || ref.stableID || ref.ip || "unknown";
    return ref.ip ? name + " (" + ref.ip + ")" : name;
  }
  function shortLabel(ref) {
    if (!ref) return "Direct";
    return ref.name || ref.stableID || ref.ip || "exit node";
  }
  function badgeLabel(type) {
    if (type === "exit-node") return "exit node";
    if (type === "router") return "router";
    return "device";
  }
  function nodeLabelById(snap, sid) {
    if (!sid) return "Direct (no exit node)";
    var nodes = snap && Array.isArray(snap.nodes) ? snap.nodes : [];
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].stableID === sid) return nodes[i].name || nodes[i].hostname || sid;
    }
    return sid;
  }
  function findNodeById(snap, sid) {
    var nodes = snap && Array.isArray(snap.nodes) ? snap.nodes : [];
    for (var i = 0; i < nodes.length; i++) if (nodes[i].stableID === sid) return nodes[i];
    return null;
  }
  function findRouterView(sid) {
    var rs = state.snapshot && Array.isArray(state.snapshot.routers) ? state.snapshot.routers : [];
    for (var i = 0; i < rs.length; i++) if (rs[i].node && rs[i].node.stableID === sid) return rs[i];
    return null;
  }

  // keyed reconcile; optional DOM reordering to match `items` order ---------
  function reconcile(container, items, keyFn, createFn, updateFn, registry, ordered) {
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
    if (ordered) {
      for (var i = 0; i < items.length; i++) {
        var rec2 = registry[keyFn(items[i])];
        if (rec2 && container.children[i] !== rec2.root) {
          container.insertBefore(rec2.root, container.children[i] || null);
        }
      }
    }
  }

  // --------------------------------------------------------------- toasts ---
  function toast(kind, title, body) {
    var box = $("#toasts");
    if (!box) return;
    var t = el("div", "toast toast-" + kind);
    // No role here: #toasts is the single aria-live="polite" region (a nested
    // live region would double-announce, like the banners wrapper).
    t.appendChild(kind === "ok" ? checkIcon() : (kind === "err" ? alertIcon() : warnIcon()));
    var bodyWrap = el("div", "toast-body");
    if (title) bodyWrap.appendChild(el("div", "toast-title", title));
    if (body) bodyWrap.appendChild(document.createTextNode(body));
    t.appendChild(bodyWrap);
    var close = el("button", "toast-close", "×");
    close.type = "button";
    close.setAttribute("aria-label", "Dismiss");
    close.addEventListener("click", function () { dismissToast(t); });
    t.appendChild(close);
    box.appendChild(t);
    var ttl = kind === "err" ? 9000 : (kind === "warn" ? 7000 : 4500);
    t._timer = setTimeout(function () { dismissToast(t); }, ttl);
  }
  function dismissToast(t) {
    if (t._timer) { clearTimeout(t._timer); t._timer = null; }
    if (!t.parentNode) return;
    t.classList.add("toast-out");
    setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 220);
  }

  // ---------------------------------------------------------------- modal ---
  function openModal(opts) {
    closeModal();
    var prevFocus = opts.returnFocus || document.activeElement;
    var backdrop = el("div", "modal-backdrop");
    var dialog = el("div", "modal");
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    var uid = "m" + Date.now();
    var titleEl = el("h2", "modal-title", opts.title);
    titleEl.id = uid + "-t";
    dialog.setAttribute("aria-labelledby", titleEl.id);
    var bodyEl = el("div", "modal-body");
    bodyEl.id = uid + "-b";
    if (typeof opts.body === "string") bodyEl.textContent = opts.body;
    else if (opts.body) bodyEl.appendChild(opts.body);
    dialog.setAttribute("aria-describedby", bodyEl.id);
    var actions = el("div", "modal-actions");
    var cancelBtn = el("button", "btn btn-secondary", opts.cancelLabel || "Cancel");
    cancelBtn.type = "button";
    var confirmBtn = el("button", "btn btn-primary", opts.confirmLabel || "Confirm");
    confirmBtn.type = "button";
    actions.appendChild(cancelBtn);
    actions.appendChild(confirmBtn);
    dialog.appendChild(titleEl);
    dialog.appendChild(bodyEl);
    dialog.appendChild(actions);
    backdrop.appendChild(dialog);
    document.body.appendChild(backdrop);

    function finish(cb) {
      closeModal();
      if (prevFocus && prevFocus.focus) { try { prevFocus.focus(); } catch (e) { /* element gone */ } }
      if (cb) cb();
    }
    cancelBtn.addEventListener("click", function () { finish(opts.onCancel); });
    confirmBtn.addEventListener("click", function () { finish(opts.onConfirm); });
    backdrop.addEventListener("mousedown", function (e) { if (e.target === backdrop) finish(opts.onCancel); });
    dialog.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { e.preventDefault(); finish(opts.onCancel); return; }
      if (e.key === "Tab") {
        var f = dialog.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
        if (!f.length) return;
        var first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    });
    activeModal = backdrop;
    confirmBtn.focus();
  }
  function closeModal() {
    if (activeModal && activeModal.parentNode) activeModal.parentNode.removeChild(activeModal);
    activeModal = null;
  }

  // ----------------------------------------------------------- node cards ---
  function createNodeCard() {
    var root = el("div", "node");
    var head = el("div", "node-head");
    var dot = dotIcon();
    var badge = el("span", "badge");
    var name = el("span", "node-name");
    head.appendChild(dot);
    head.appendChild(name);
    head.appendChild(badge);
    var ips = el("div", "node-ips");
    var meta = el("div", "node-meta");
    var os = el("span", "node-os");
    var seen = el("span", "node-seen");
    meta.appendChild(os);
    meta.appendChild(seen);
    root.appendChild(head);
    root.appendChild(ips);
    root.appendChild(meta);
    return { root: root, dot: dot, badge: badge, name: name, ips: ips, os: os, seen: seen, data: null };
  }
  function updateNodeCard(rec, n) {
    rec.data = n;
    var type = n.type || "generic";
    setText(rec.badge, badgeLabel(type));
    rec.badge.className = "badge badge-" + type;
    var online = n.online === true;
    setDot(rec.dot, online);
    var nm = n.name || n.hostname || n.stableID || "(unknown)";
    setText(rec.name, nm);
    rec.name.title = nm;
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

    var warn = el("div", "router-warn hidden");
    warn.appendChild(warnIcon());
    var warnText = el("span", "warn-text");
    warn.appendChild(warnText);

    var offlineNote = el("div", "offline-note hidden");

    var picker = el("div", "picker");
    var label = el("label", "picker-label", "Route internet through:");
    var selectWrap = el("div", "select-wrap");
    var select = el("select", "exit-select");
    select.id = "sel-" + String(sid).replace(/[^a-zA-Z0-9_-]/g, "_");
    label.htmlFor = select.id;
    selectWrap.appendChild(select);
    selectWrap.appendChild(chevronIcon());
    picker.appendChild(label);
    picker.appendChild(selectWrap);

    var pickerHint = el("div", "picker-hint hidden");
    var pending = el("div", "pending hidden");
    var stats = el("div", "stats");
    var errBox = el("div", "error-box hidden");

    root.appendChild(head);
    root.appendChild(ips);
    root.appendChild(currentLine);
    root.appendChild(warn);
    root.appendChild(offlineNote);
    root.appendChild(picker);
    root.appendChild(pickerHint);
    root.appendChild(pending);
    root.appendChild(stats);
    root.appendChild(errBox);

    select.addEventListener("change", function () { onSelectChange(sid, select); });

    return {
      root: root, dot: dot, name: name, stateBadge: stateBadge, ips: ips,
      currentLine: currentLine, currentText: currentText, warn: warn, warnText: warnText,
      offlineNote: offlineNote, picker: picker, pickerHint: pickerHint, select: select, pending: pending,
      stats: stats, errBox: errBox, optionsSig: null,
    };
  }

  function applyStateBadge(node, st) {
    var map = {
      ok: ["connected", "state-ok"],
      pending: ["applying", "state-pending"],
      unconfirmed: ["unconfirmed", "state-unconfirmed"],
      unreachable: ["offline", "state-unreachable"],
    };
    var m = map[st] || [String(st || "?"), "state-unknown"];
    setText(node, m[0]);
    node.className = "state " + m[1];
  }

  function setPending(rec, kind, text) {
    rec.pending.textContent = "";
    if (kind === "none") { rec.pending.className = "pending hidden"; return; }
    rec.pending.className = "pending " + (kind === "amber" ? "pending-amber" : "pending-spin");
    if (kind === "spin") rec.pending.appendChild(spinnerIcon());
    if (text) rec.pending.appendChild(document.createTextNode(" " + text));
  }

  function countdownSuffix(sid) {
    var since = state.pendingSince[sid];
    if (!since) return "";
    var rem = REVERT_WINDOW - Math.floor((Date.now() - since) / 1000);
    if (rem < 0) rem = 0;
    return " — auto-reverts in ~" + rem + "s if not confirmed";
  }

  // approved exit-node options for one router: Direct + approved nodes, minus
  // the router itself; offline options are marked "(offline)" (PHASE_B §8).
  function exitOptionsFor(snap, routerSid) {
    var opts = [{ value: "", label: "Direct (no exit node)" }];
    var nodes = snap && Array.isArray(snap.nodes) ? snap.nodes : [];
    nodes.forEach(function (n) {
      if (n.exitNodeOption === true && n.stableID && n.stableID !== routerSid) {
        var label = n.name || n.hostname || n.stableID;
        if (n.online !== true) label += " (offline)";
        opts.push({ value: n.stableID, label: label });
      }
    });
    return opts;
  }

  function rebuildOptions(rec, optList, rv) {
    var cur = rv.currentExitNode, des = rv.desired;
    var sig = optList.map(function (o) { return o.value + "|" + o.label; }).join("")
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
    for (var i = 0; i < sel.options.length; i++) if (sel.options[i].value === value) return;
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

    var showDesired = localBusy || st === "pending" || st === "unconfirmed";

    // The value is only written when it actually differs (diff guard below), so
    // background frames never disrupt a browsing user unless the device's actual
    // selection truly changed. We update even while focused: the confirm modal
    // returns focus here, so pending must show the disabled desired target and
    // settled states must re-sync to the actual selection.
    var val, disabled;
    if (showDesired) {
      val = hasBusyTarget ? state.busyTarget[sid] : (rv.desired ? rv.desired.stableID : "");
      disabled = true;
    } else {
      val = rv.currentExitNode ? rv.currentExitNode.stableID : "";
      disabled = !reachable;
    }
    ensureOption(sel, val);
    if (sel.value !== (val == null ? "" : val)) sel.value = val == null ? "" : val;
    sel.disabled = disabled;
  }

  function updateRouterCard(rec, rv, snap) {
    var node = rv.node || {};
    var sid = node.stableID;
    var online = node.online === true;
    var reachable = rv.reachable !== false && online;
    var st = rv.state || (online ? "ok" : "unreachable");
    var localBusy = !!state.busyRouters[sid];

    var routerName = node.name || node.hostname || sid || "(router)";
    setText(rec.name, routerName);
    rec.name.title = routerName;
    var pickerLabel = "Route " + routerName + "’s internet through";
    if (rec.select.getAttribute("aria-label") !== pickerLabel) rec.select.setAttribute("aria-label", pickerLabel);
    setDot(rec.dot, online);
    applyStateBadge(rec.stateBadge, st);

    var ips = Array.isArray(node.tailscaleIPs) ? node.tailscaleIPs : [];
    var ipText = ips.length ? ips.join(", ") : "no IPs";
    setText(rec.ips, (node.os ? node.os + " · " : "") + ipText);

    // current exit node line (greyed/last-known when offline)
    var curRef = rv.currentExitNode;
    if (!reachable) {
      setText(rec.currentText, curRef ? "Last known: routing through " + shortLabel(curRef) : "Last known: direct");
      rec.currentLine.classList.add("is-stale");
    } else {
      setText(rec.currentText, curRef ? "Routing through " + exitRefLabel(curRef) : "Direct — no exit node");
      rec.currentLine.classList.remove("is-stale");
    }

    // offline note (control disabled)
    if (!reachable) {
      var lastSeen = node.lastSeen ? relTime(node.lastSeen) : "unknown";
      setText(rec.offlineNote, "Offline — last seen " + lastSeen + ". Control disabled until it’s back online.");
      show(rec.offlineNote, true);
    } else {
      show(rec.offlineNote, false);
    }

    // warn: current exit node is itself offline while selected
    var warnOn = false;
    if (reachable && curRef && curRef.stableID) {
      var exNode = findNodeById(snap, curRef.stableID);
      if (exNode && exNode.online !== true) {
        warnOn = true;
        setText(rec.warnText, "Its current exit node, " + shortLabel(curRef) + ", is offline — internet through it is likely down. Pick another exit node or go Direct.");
      }
    }
    show(rec.warn, warnOn);

    // pending / unconfirmed indicator + countdown bookkeeping
    var isPending = localBusy || st === "pending";
    if (isPending && !state.pendingSince[sid]) state.pendingSince[sid] = Date.now();
    if (!isPending) delete state.pendingSince[sid];
    if (localBusy) {
      setPending(rec, "spin", "Applying…" + countdownSuffix(sid));
    } else if (st === "pending") {
      setPending(rec, "spin", "Applying " + shortLabel(rv.desired) + countdownSuffix(sid));
    } else if (st === "unconfirmed") {
      setPending(rec, "amber", "Sent to " + shortLabel(rv.desired) + ", but not confirmed — the router will auto-revert if it can’t confirm.");
    } else {
      setPending(rec, "none", "");
    }

    // picker: disabled while offline or an action is in flight (corner case K)
    var optList = exitOptionsFor(snap, sid);
    rebuildOptions(rec, optList, rv);
    refreshSelect(rec, rv);

    // No approved exit nodes to choose from (only "Direct" in the list).
    if (reachable && optList.length <= 1) {
      setText(rec.pickerHint, "No approved exit nodes available. Approve one for this tailnet in the Tailscale admin console, then it’ll appear here.");
      show(rec.pickerHint, true);
    } else {
      show(rec.pickerHint, false);
    }

    // stats
    var s = rv.stats || {};
    if (curRef && reachable) {
      setText(rec.stats, "rx " + humanBytes(s.rxBytes) + " · tx " + humanBytes(s.txBytes)
        + " · handshake " + relTime(s.lastHandshake));
    } else if (reachable) {
      setText(rec.stats, "No exit-node traffic (direct).");
    } else {
      setText(rec.stats, "");
    }

    // errors: the last POST failure (richer, action-specific) takes precedence;
    // otherwise the server's lastError. Never both — they describe the same
    // failed action and double-printing reads as contradictory. (For the genuine
    // applied-but-unconfirmed state the amber pending line already explains it, so
    // the raw lastError is suppressed there.) Never swallowed.
    var parts = [];
    var ae = state.actionErrors[sid];
    if (ae) {
      var msg = ae.error || "Request failed";
      // Prefer the router's stderr (the meaningful bit) over the verbose detail.
      if (ae.stderr) msg += " — " + ae.stderr;
      else if (ae.detail && ae.detail !== ae.error) msg += " — " + ae.detail;
      msg += " — kept the previous exit node.";
      parts.push(msg);
    } else if (rv.lastError && st !== "unconfirmed") {
      parts.push(rv.lastError);
    }
    if (parts.length) {
      setText(rec.errBox, parts.join("\n"));
      rec.errBox.className = "error-box";
    } else {
      setText(rec.errBox, "");
      rec.errBox.className = "error-box hidden";
    }
  }

  // --------------------------------------------------- pick + confirm flow ---
  function onSelectChange(sid, select) {
    var value = select.value;
    var rv = findRouterView(sid);
    var current = rv && rv.currentExitNode ? rv.currentExitNode.stableID : "";
    // Reset the control to the ACTUAL selection immediately (never optimistic);
    // the change only takes effect after the user confirms.
    if (sel_safe(select) && select.value !== current) select.value = current;
    confirmExitNodeChange(sid, value, select);
  }

  // Shared confirm + POST flow used by BOTH the card picker and the zone graph
  // (drag + keyboard menu). Opens the EXISTING confirm dialog, then onPick (which
  // is never-optimistic: it shows "Applying…" and reflects the device's actual
  // state). value === "" clears the exit node (Direct).
  function confirmExitNodeChange(sid, value, returnFocus) {
    var rv = findRouterView(sid);
    var current = rv && rv.currentExitNode ? rv.currentExitNode.stableID : "";
    if (value === current) return;       // no change
    if (state.busyRouters[sid]) return;  // a change is already in flight

    var routerName = (rv && rv.node && (rv.node.name || rv.node.hostname)) || sid;
    var targetLabelText = nodeLabelById(state.snapshot, value);
    var body = el("div");
    if (value === "") {
      body.appendChild(document.createTextNode("Stop routing "));
      body.appendChild(el("strong", null, routerName));
      body.appendChild(document.createTextNode("’s internet through an exit node (go direct)."));
    } else {
      body.appendChild(document.createTextNode("Route "));
      body.appendChild(el("strong", null, routerName));
      body.appendChild(document.createTextNode("’s internet through "));
      body.appendChild(el("strong", null, targetLabelText));
      body.appendChild(document.createTextNode("."));
    }
    body.appendChild(el("p", "modal-note", "This disrupts the router’s internet while it switches. It auto-reverts in ~" + REVERT_WINDOW + "s if the device can’t be confirmed."));

    openModal({
      title: "Change exit node?",
      body: body,
      confirmLabel: value === "" ? "Go direct" : "Change exit node",
      cancelLabel: "Cancel",
      returnFocus: returnFocus,
      onConfirm: function () { onPick(sid, value); },
      onCancel: function () { /* never optimistic — nothing moved, nothing to undo */ },
    });
  }

  // guard: select may have been removed from the DOM between frames
  function sel_safe(select) { return select && select.isConnected; }

  function setActionError(sid, info) { state.actionErrors[sid] = info; }
  function clearActionError(sid) { delete state.actionErrors[sid]; }

  function onPick(sid, value) {
    if (!sid) return;
    state.busyRouters[sid] = true;
    state.busyTarget[sid] = value;
    state.pendingSince[sid] = Date.now();
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

  function doPostExitNode(sid, value, retried) {
    return fetch("/api/routers/" + encodeURIComponent(sid) + "/exit-node", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Tsctl-CSRF": state.csrfToken || "",
      },
      body: JSON.stringify({ exitNode: value }),
    }).then(function (resp) {
      return resp.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
        // Session expired / not authenticated → show the login overlay.
        if (resp.status === 401) { promptLogin(); return; }
        // CSRF 403: transparently refresh the token and retry ONCE.
        if (resp.status === 403 && !retried) {
          return fetchCSRF().then(function () { return doPostExitNode(sid, value, true); });
        }
        if (!resp.ok) {
          var info = (data && (data.error || data.detail || data.stderr)) ? data
            : { error: "HTTP " + resp.status, detail: text || "" };
          setActionError(sid, info);
          // Never-optimistic: a failed change took NO effect, so the device kept
          // its previous exit node. Say so plainly (no "unconfirmed/auto-revert").
          var targetName = value === "" ? "Direct (no exit node)" : nodeLabelById(state.snapshot, value);
          var reason = info.stderr || info.detail || info.error || "the router rejected the change";
          toast("err", "Couldn’t switch to " + targetName,
            reason + " — kept the previous exit node.");
          return;
        }
        clearActionError(sid);
        if (data) {
          mergeRouterView(data); // reflect ACTUAL returned state
          announceResult(sid, value, data);
        }
      });
    });
  }

  function announceResult(sid, value, rv) {
    var st = rv.state;
    var routerName = (rv.node && (rv.node.name || rv.node.hostname)) || sid;
    if (st === "ok") {
      if (rv.currentExitNode) toast("ok", "Exit node updated", "Now routing " + routerName + " through " + shortLabel(rv.currentExitNode) + ".");
      else toast("ok", "Exit node cleared", routerName + " is now direct (no exit node).");
    } else if (st === "unconfirmed") {
      toast("warn", "Sent, not confirmed", "The change was applied to " + routerName + " but couldn’t be confirmed. It will auto-revert if it can’t confirm.");
    } else if (st === "unreachable") {
      toast("err", routerName + " unreachable", rv.lastError || "The router could not be reached.");
    }
  }

  function postExitNode(sid, value) {
    ensureCSRF()
      .then(function () { return doPostExitNode(sid, value, false); })
      .catch(function (err) {
        setActionError(sid, { error: "Network error", detail: String((err && err.message) || err) });
        toast("err", "Network error", String((err && err.message) || err));
      })
      .then(function () {
        delete state.busyRouters[sid];
        delete state.busyTarget[sid];
        render();
      });
  }

  // ============================================================= zone graph ===
  // The DEFAULT view: a bipartite graph of consumers (left) ⟷ exit nodes (right),
  // scoped by a selected zone (group) or the implicit "Ungrouped" set. Wires show
  // each consumer's ACTUAL current exit node (never the chosen target). Rewire by
  // DRAG or by an accessible per-consumer menu; both funnel into the SAME confirm +
  // POST flow as the cards, and are never-optimistic + zone-enforced.

  var UNGROUPED = "__tsctl_ungrouped__"; // sentinel zone id for the implicit section
  var DIRECT_KEY = "__tsctl_direct__";   // key for the "Direct" drop target
  var DRAG_THRESHOLD = 6;            // px of movement before a click becomes a drag

  function snapGroups() { var s = state.snapshot; return s && Array.isArray(s.groups) ? s.groups : []; }
  function snapRouters() { var s = state.snapshot; return s && Array.isArray(s.routers) ? s.routers : []; }
  function snapNodes() { var s = state.snapshot; return s && Array.isArray(s.nodes) ? s.nodes : []; }
  function isExitCapable(n) { return !!n && (n.exitNodeOption === true || n.type === "exit-node"); }

  // Routers not present in ANY group's consumers (the implicit "Ungrouped" set).
  function ungroupedRouters() {
    var inGroup = {};
    snapGroups().forEach(function (g) {
      (g.consumers || []).forEach(function (m) { if (m && m.stableID) inGroup[m.stableID] = true; });
    });
    return snapRouters().filter(function (rv) { return rv.node && rv.node.stableID && !inGroup[rv.node.stableID]; });
  }

  // Ordered zone list for the selector: every group, then "Ungrouped" (shown when
  // it has members, or when there are NO groups at all so there is always a tab).
  function zoneList() {
    var zones = snapGroups().map(function (g) { return { id: g.id, name: g.name || "(unnamed zone)", group: g }; });
    if (ungroupedRouters().length > 0 || zones.length === 0) {
      zones.push({ id: UNGROUPED, name: "Ungrouped", group: null });
    }
    return zones;
  }

  function resolveSelectedZone() {
    var zones = zoneList();
    if (!zones.length) return null;
    for (var i = 0; i < zones.length; i++) if (zones[i].id === state.selectedZone) return zones[i];
    // A stored selection that isn't present yet (e.g. a just-created zone awaiting
    // the next snapshot): show the default but DON'T clobber it, so it auto-selects
    // once it arrives. Only fall back to the default when nothing is stored.
    if (state.selectedZone == null) state.selectedZone = zones[0].id; // first group, else Ungrouped
    for (var j = 0; j < zones.length; j++) if (zones[j].id === state.selectedZone) return zones[j];
    return zones[0];
  }

  // Resolve the selected zone into left (consumers) + right (exit nodes) columns,
  // plus the allowed-target set. A present:false member renders greyed "missing".
  function columnsFor(zone) {
    var consumers, exits, allowed = {}, ungrouped = false;
    if (!zone || zone.id === UNGROUPED) {
      ungrouped = true;
      consumers = ungroupedRouters().map(function (rv) {
        return { key: rv.node.stableID, sid: rv.node.stableID, rv: rv, present: true };
      });
      exits = snapNodes().filter(isExitCapable).map(function (n) {
        allowed[n.stableID] = true;
        return { key: n.stableID, sid: n.stableID, node: n, present: true, allowed: true };
      });
    } else {
      var g = zone.group;
      consumers = (g.consumers || []).map(function (m) {
        var rv = findRouterView(m.stableID);
        return { key: m.stableID, sid: m.stableID, rv: rv, member: m, present: m.present === true && !!rv };
      });
      exits = (g.allowedExitNodes || []).map(function (m) {
        var node = findNodeById(state.snapshot, m.stableID);
        allowed[m.stableID] = true;
        return { key: m.stableID, sid: m.stableID, node: node, member: m, present: m.present === true && !!node, allowed: true };
      });
    }
    // A consumer's CURRENT exit node that isn't in the allowed column still renders,
    // flagged "out of zone" (display only — never an allowed drop/menu target).
    var have = {};
    exits.forEach(function (e) { have[e.sid] = true; });
    consumers.forEach(function (c) {
      var cur = c.rv && c.rv.currentExitNode;
      if (!cur || !cur.stableID || have[cur.stableID]) return;
      have[cur.stableID] = true;
      var node = findNodeById(state.snapshot, cur.stableID);
      exits.push({ key: cur.stableID, sid: cur.stableID, node: node, ref: cur, present: !!node, allowed: false, outOfZone: true });
    });
    return { consumers: consumers, exits: exits, allowed: allowed, ungrouped: ungrouped };
  }

  // Derive the wire/visual state from the device's ACTUAL RouterView state (the
  // same never-optimistic machine the cards use), plus whether its current exit
  // node is out of the zone's allowed set.
  function consumerStatus(c, allowed) {
    var rv = c.rv;
    if (!c.present || !rv) return { missing: true, wire: "off" };
    var node = rv.node || {};
    var online = node.online === true;
    var reachable = rv.reachable !== false && online;
    var st = rv.state || (online ? "ok" : "unreachable");
    var localBusy = !!state.busyRouters[c.sid];
    var cur = rv.currentExitNode;
    var wire;
    if (localBusy || st === "pending") wire = "pending";
    else if (st === "unconfirmed") wire = "unconfirmed";
    else if (!reachable || st === "unreachable") wire = "off";
    else wire = "ok";
    var outOfZone = !!(cur && cur.stableID && allowed && !allowed[cur.stableID]);
    return { online: online, reachable: reachable, st: st, localBusy: localBusy, cur: cur, wire: wire, outOfZone: outOfZone };
  }

  function createConsumerNode(item) {
    var sid = item.sid;
    var root = el("div", "gnode gnode-consumer");
    root.setAttribute("data-consumer", sid);
    var head = el("div", "gnode-head");
    var dot = dotIcon();
    var name = el("span", "gnode-name");
    var grip = el("span", "gnode-grip", "⋮⋮");
    grip.setAttribute("aria-hidden", "true");
    head.appendChild(dot);
    head.appendChild(name);
    head.appendChild(grip);
    var sub = el("div", "gnode-sub");
    var stBadge = el("span", "gnode-state");
    root.appendChild(head);
    root.appendChild(sub);
    root.appendChild(stBadge);
    var rec = { root: root, dot: dot, name: name, sub: sub, state: stBadge, sid: sid, interactive: false };
    // Keyboard path (a11y): Enter/Space opens the picker menu. Pointer path:
    // pointerdown may begin a drag, or (no movement) opens the same menu.
    root.addEventListener("keydown", function (e) {
      if (!rec.interactive) return;
      if (e.key === "Enter" || e.key === " " || e.key === "Spacebar") {
        e.preventDefault();
        openZoneMenu(sid, root);
      }
    });
    root.addEventListener("pointerdown", function (e) { onConsumerPointerDown(e, rec); });
    return rec;
  }

  function updateConsumerNode(rec, item, allowed) {
    var s = consumerStatus(item, allowed);
    var rv = item.rv;
    var node = (rv && rv.node) || {};
    var nm = node.name || node.hostname || (item.member && item.member.name) || item.sid || "(router)";
    setText(rec.name, nm);
    rec.root.title = nm;

    if (s.missing) {
      rec.root.className = "gnode gnode-consumer is-missing";
      rec.dot.setAttribute("class", "dot dot-off");
      rec.dot.setAttribute("role", "img");
      rec.dot.setAttribute("aria-label", "missing");
      setText(rec.sub, "Not currently in the netmap");
      setText(rec.state, "missing");
      rec.state.className = "gnode-state state-unknown";
      rec.interactive = false;
      rec.root.removeAttribute("tabindex");
      rec.root.removeAttribute("role");
      rec.root.removeAttribute("aria-haspopup");
      rec.root.setAttribute("aria-label", nm + ": not currently in the netmap");
      return;
    }

    setDot(rec.dot, s.online);
    var stMap = { ok: "connected", pending: "applying", unconfirmed: "unconfirmed", unreachable: "offline" };
    setText(rec.state, stMap[s.st] || s.st);
    rec.state.className = "gnode-state state-" + (stMap[s.st] ? s.st : "unknown");

    var subText, ariaConn;
    if (s.localBusy) { subText = "Applying…" + countdownSuffix(item.sid); ariaConn = "applying a change"; }
    else if (s.st === "pending") { subText = "Applying " + shortLabel(rv.desired) + countdownSuffix(item.sid); ariaConn = "applying " + shortLabel(rv.desired); }
    else if (s.st === "unconfirmed") { subText = "Sent to " + shortLabel(rv.desired) + " — not confirmed"; ariaConn = "sent to " + shortLabel(rv.desired) + ", not confirmed"; }
    else if (!s.reachable) { subText = "Offline — control disabled"; ariaConn = "offline, control disabled"; }
    else if (s.cur) { subText = "→ " + shortLabel(s.cur) + (s.outOfZone ? " (out of zone)" : ""); ariaConn = "routing through " + shortLabel(s.cur) + (s.outOfZone ? ", out of zone" : ""); }
    else { subText = "Direct — no exit node"; ariaConn = "direct, no exit node"; }
    setText(rec.sub, subText);

    // Disabled while settling (busy/pending/unconfirmed) or offline — mirrors the
    // card picker; the never-optimistic machine owns the transition.
    var settling = s.localBusy || s.st === "pending" || s.st === "unconfirmed";
    var interactive = s.reachable && !settling;
    rec.interactive = interactive;
    rec.root.className = "gnode gnode-consumer"
      + (settling ? " is-busy" : "")
      + (s.reachable ? "" : " is-off")
      + (interactive ? " is-actionable" : "");
    if (interactive) {
      rec.root.setAttribute("tabindex", "0");
      rec.root.setAttribute("role", "button");
      rec.root.setAttribute("aria-haspopup", "menu");
      rec.root.setAttribute("aria-label", nm + ", " + ariaConn + ". Activate to change its exit node.");
    } else {
      rec.root.removeAttribute("tabindex");
      rec.root.removeAttribute("role");
      rec.root.removeAttribute("aria-haspopup");
      rec.root.setAttribute("aria-label", nm + ", " + ariaConn + ".");
    }
  }

  function createExitNode() {
    var root = el("div", "gnode gnode-exit");
    var head = el("div", "gnode-head");
    var dot = dotIcon();
    var name = el("span", "gnode-name");
    head.appendChild(dot);
    head.appendChild(name);
    var sub = el("div", "gnode-sub");
    root.appendChild(head);
    root.appendChild(sub);
    return { root: root, dot: dot, name: name, sub: sub };
  }

  function updateExitNode(rec, item) {
    var dot = rec.dot;
    if (item.direct) {
      rec.root.className = "gnode gnode-exit gnode-direct";
      rec.root.setAttribute("data-drop", "");            // "" => clear (Direct)
      dot.setAttribute("class", "dot hidden");
      setText(rec.name, "Direct");
      setText(rec.sub, "No exit node");
      rec.root.setAttribute("aria-label", "Direct, no exit node. Drop a consumer here to clear its exit node.");
      return;
    }
    var node = item.node, ref = item.ref, m = item.member;
    var nm = (node && (node.name || node.hostname)) || (m && m.name) || (ref && (ref.name || ref.ip)) || item.sid;
    setText(rec.name, nm);
    rec.root.title = nm;
    var cls = "gnode gnode-exit";
    var bits = [];
    if (!item.present) { cls += " is-missing"; bits.push("not in netmap"); dot.setAttribute("class", "dot dot-off"); }
    else {
      var online = node ? node.online === true : false;
      setDot(dot, online);
      bits.push(online ? "online" : "offline");
      if (!online) cls += " is-off";
    }
    if (item.outOfZone) { cls += " is-outofzone"; bits.push("out of zone"); }
    rec.root.className = cls;
    var ip = (node && (node.tailscaleIPs || [])[0]) || (m && m.ip) || (ref && ref.ip) || "";
    setText(rec.sub, (ip ? ip + " · " : "") + bits.join(" · "));
    if (item.allowed) {
      rec.root.setAttribute("data-drop", item.sid);
      rec.root.setAttribute("aria-label", nm + ", exit node, " + bits.join(", ") + ". Drop a consumer here to route it through " + nm + ".");
    } else {
      rec.root.removeAttribute("data-drop");
      rec.root.setAttribute("aria-label", nm + ", exit node, " + bits.join(", ") + ".");
    }
  }

  function renderGraph() {
    if (state.graphDrag && state.graphDrag.active) return; // never reconcile mid-drag

    // Routers + groups come ONLY from the live snapshot (like the card view).
    if (!state.gotSseFrame) {
      showGraphMessage(state.pollFallback
        ? "The zone graph needs the live stream, which is currently unavailable. Reconnecting…"
        : "Loading zones…");
      // Clear any stale columns so a reconnect repaints cleanly.
      reconcile($("#gcol-consumers"), [], function (it) { return it.key; }, createConsumerNode, function () {}, consumerEls, true);
      reconcile($("#gcol-exits"), [], function (it) { return it.key; }, createExitNode, updateExitNode, exitEls, true);
      return;
    }

    var zones = zoneList();
    renderZoneTabs(zones);
    var zone = resolveSelectedZone();
    renderZoneActions(zone);

    show($("#graph-empty"), false);
    $("#graph-grid").hidden = false;
    $("#graph-hint").hidden = false;

    var cols = columnsFor(zone);

    // Right column: the "Direct" drop target first, then the zone's exit nodes.
    var exitItems = [{ key: DIRECT_KEY, direct: true }].concat(cols.exits);
    reconcile($("#gcol-exits"), exitItems, function (it) { return it.key; },
      createExitNode, updateExitNode, exitEls, true);

    reconcile($("#gcol-consumers"), cols.consumers, function (it) { return it.key; },
      createConsumerNode, function (rec, it) { updateConsumerNode(rec, it, cols.allowed); }, consumerEls, true);

    var cEmpty = $("#consumers-empty");
    if (!cols.consumers.length) {
      setText(cEmpty, cols.ungrouped ? "No ungrouped routers — every router is in a zone." : "No consumers in this zone yet. Use Edit to add some.");
      show(cEmpty, true);
    } else show(cEmpty, false);
    var xEmpty = $("#exits-empty");
    if (!cols.exits.length) {
      setText(xEmpty, cols.ungrouped ? "No approved exit nodes in the tailnet." : "No allowed exit nodes in this zone yet. Use Edit to add some.");
      show(xEmpty, true);
    } else show(xEmpty, false);

    drawWires(cols);
  }

  function showGraphMessage(msg) {
    var e = $("#graph-empty");
    setText(e, msg);
    show(e, true);
    $("#graph-grid").hidden = true;
    $("#graph-hint").hidden = true;
  }

  // --- wires --------------------------------------------------------------
  function drawWires(cols) {
    var svg = $("#wires");
    var grid = $("#graph-grid");
    if (!svg || !grid) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    var gridRect = grid.getBoundingClientRect();
    cols.consumers.forEach(function (c) {
      var s = consumerStatus(c, cols.allowed);
      if (s.missing || !s.cur || !s.cur.stableID) return; // no current exit node => Direct => no wire
      var consRec = consumerEls[c.key], exitRec = exitEls[s.cur.stableID];
      if (!consRec || !exitRec) return;
      var a = anchorOf(consRec.root, "right", gridRect);
      var b = anchorOf(exitRec.root, "left", gridRect);
      var path = svgEl("path", { d: wirePath(a, b), fill: "none", "class": "wire wire-" + s.wire });
      path.setAttribute("role", "img");
      var nm = (c.rv && c.rv.node && (c.rv.node.name || c.rv.node.hostname)) || c.sid;
      path.setAttribute("aria-label", nm + " connected to " + shortLabel(s.cur) + " (" + wireLabel(s.wire) + ")");
      svg.appendChild(path);
    });
    if (state.graphDrag && state.graphDrag.active) drawGhost();
  }

  function wireLabel(w) {
    return w === "ok" ? "connected" : w === "pending" ? "applying" : w === "unconfirmed" ? "not confirmed" : "offline";
  }
  function anchorOf(elem, side, gridRect) {
    var r = elem.getBoundingClientRect();
    return {
      x: (side === "right" ? r.right : r.left) - gridRect.left,
      y: r.top + r.height / 2 - gridRect.top,
    };
  }
  function wirePath(a, b) {
    var dx = Math.max(36, Math.abs(b.x - a.x) / 2);
    return "M " + a.x + " " + a.y + " C " + (a.x + dx) + " " + a.y + ", " + (b.x - dx) + " " + b.y + ", " + b.x + " " + b.y;
  }
  function drawWiresForCurrent() {
    if (state.view !== "graph" || !state.gotSseFrame) return;
    var zone = resolveSelectedZone();
    if (zone) drawWires(columnsFor(zone));
  }

  // --- drag-to-rewire (pointer events; touch-friendly) --------------------
  function onConsumerPointerDown(e, rec) {
    if (!rec.interactive) return;
    if (e.button != null && e.button !== 0) return; // primary button only
    closeZoneMenu();
    var grid = $("#graph-grid");
    var gridRect = grid.getBoundingClientRect();
    state.graphDrag = {
      sid: rec.sid, root: rec.root, pointerId: e.pointerId,
      startX: e.clientX, startY: e.clientY, gridRect: gridRect,
      origin: anchorOf(rec.root, "right", gridRect),
      cur: { x: e.clientX - gridRect.left, y: e.clientY - gridRect.top },
      active: false, over: null,
    };
    try { rec.root.setPointerCapture(e.pointerId); } catch (err) { /* capture unsupported; document listeners still fire */ }
    document.addEventListener("pointermove", onGraphPointerMove, true);
    document.addEventListener("pointerup", onGraphPointerUp, true);
    document.addEventListener("pointercancel", onGraphPointerUp, true);
  }

  function onGraphPointerMove(e) {
    var d = state.graphDrag;
    if (!d || e.pointerId !== d.pointerId) return;
    if (!d.active) {
      if (Math.abs(e.clientX - d.startX) < DRAG_THRESHOLD && Math.abs(e.clientY - d.startY) < DRAG_THRESHOLD) return;
      d.active = true;
      d.root.classList.add("is-dragging");
      document.body.classList.add("graph-dragging");
    }
    e.preventDefault();
    d.cur = { x: e.clientX - d.gridRect.left, y: e.clientY - d.gridRect.top };
    var target = dropTargetAt(e.clientX, e.clientY);
    if (target !== d.over) {
      if (d.over) d.over.classList.remove("is-drop-hover");
      d.over = target;
      if (target) target.classList.add("is-drop-hover");
    }
    drawGhost();
  }

  function onGraphPointerUp(e) {
    var d = state.graphDrag;
    if (!d || e.pointerId !== d.pointerId) return;
    document.removeEventListener("pointermove", onGraphPointerMove, true);
    document.removeEventListener("pointerup", onGraphPointerUp, true);
    document.removeEventListener("pointercancel", onGraphPointerUp, true);
    try { d.root.releasePointerCapture(d.pointerId); } catch (err) { /* nothing to release */ }
    d.root.classList.remove("is-dragging");
    document.body.classList.remove("graph-dragging");
    if (d.over) d.over.classList.remove("is-drop-hover");
    var wasActive = d.active, target = d.over, sid = d.sid;
    state.graphDrag = null;
    removeGhost();

    if (!wasActive) { // a tap/click, not a drag → open the accessible picker menu
      var anchor = document.querySelector('[data-consumer="' + cssEscape(sid) + '"]');
      openZoneMenu(sid, anchor || document.activeElement);
      return;
    }
    if (e.type === "pointercancel" || !target) { drawWiresForCurrent(); return; }
    // The right column IS the allowed set (UI guard) — any in-column drop is fine.
    confirmExitNodeChange(sid, target.getAttribute("data-drop"), target);
    drawWiresForCurrent();
  }

  function dropTargetAt(clientX, clientY) {
    var node = document.elementFromPoint(clientX, clientY); // pointer-events:none SVG is skipped
    while (node && node !== document.body) {
      if (node.hasAttribute && node.hasAttribute("data-drop")) return node;
      node = node.parentNode;
    }
    return null;
  }
  function drawGhost() {
    var d = state.graphDrag, svg = $("#wires");
    if (!d || !d.active || !svg) return;
    removeGhost();
    var path = svgEl("path", { d: wirePath(d.origin, d.cur), fill: "none", "class": "wire wire-ghost", "data-ghost": "1" });
    path.setAttribute("aria-hidden", "true");
    svg.appendChild(path);
  }
  function removeGhost() {
    var svg = $("#wires");
    if (!svg) return;
    var g = svg.querySelector('[data-ghost="1"]');
    if (g && g.parentNode) g.parentNode.removeChild(g);
  }
  function cssEscape(s) {
    if (window.CSS && CSS.escape) return CSS.escape(s);
    return String(s).replace(/["\\]/g, "\\$&");
  }

  // --- keyboard/click rewire menu (drag is NOT the only path — a11y) -------
  function zoneMenuOptions(sid) {
    var cols = columnsFor(resolveSelectedZone());
    var rv = findRouterView(sid);
    var curSid = rv && rv.currentExitNode ? rv.currentExitNode.stableID : "";
    var opts = [{ value: "", label: "Direct (no exit node)", current: curSid === "", disabled: false }];
    cols.exits.forEach(function (e) {
      if (!e.allowed) return; // never offer a disallowed (out-of-zone) target — enforcement guard
      var node = e.node;
      var nm = (node && (node.name || node.hostname)) || (e.member && e.member.name) || e.sid;
      var disabled = false, suffix = "";
      if (!e.present) { disabled = true; suffix = " (missing)"; }
      else if (!(node && node.online === true)) { suffix = " (offline)"; }
      opts.push({ value: e.sid, label: nm + suffix, current: curSid === e.sid, disabled: disabled });
    });
    return opts;
  }

  function openZoneMenu(sid, anchorEl) {
    closeZoneMenu();
    var rv = findRouterView(sid);
    if (!rv) return;
    var routerName = (rv.node && (rv.node.name || rv.node.hostname)) || sid;
    var menu = el("div", "zone-menu");
    menu.setAttribute("role", "menu");
    menu.setAttribute("aria-label", "Choose an exit node for " + routerName);
    var items = [];
    zoneMenuOptions(sid).forEach(function (o) {
      var b = el("button", "zone-menu-item" + (o.current ? " is-current" : ""));
      b.type = "button";
      b.setAttribute("role", "menuitemradio");
      b.setAttribute("aria-checked", o.current ? "true" : "false");
      var label = el("span", "zone-menu-label", o.label);
      b.appendChild(label);
      if (o.current) { var ck = el("span", "zone-menu-check", "✓"); ck.setAttribute("aria-hidden", "true"); b.appendChild(ck); }
      if (o.disabled) {
        b.disabled = true;
      } else {
        b.addEventListener("click", function () { closeZoneMenu(); confirmExitNodeChange(sid, o.value, anchorEl); });
        items.push(b);
      }
      menu.appendChild(b);
    });
    document.body.appendChild(menu);
    positionMenu(menu, anchorEl);

    function onKey(e) {
      var idx = items.indexOf(document.activeElement);
      if (e.key === "Escape") { e.preventDefault(); closeZoneMenu(); focusBack(anchorEl); }
      else if (e.key === "ArrowDown") { e.preventDefault(); if (items.length) items[(idx + 1 + items.length) % items.length].focus(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); if (items.length) items[(idx - 1 + items.length) % items.length].focus(); }
      else if (e.key === "Home") { e.preventDefault(); if (items.length) items[0].focus(); }
      else if (e.key === "End") { e.preventDefault(); if (items.length) items[items.length - 1].focus(); }
      else if (e.key === "Tab") { e.preventDefault(); } // trap within the menu
    }
    function onDocDown(e) { if (!menu.contains(e.target)) closeZoneMenu(); }
    menu.addEventListener("keydown", onKey);
    document.addEventListener("pointerdown", onDocDown, true);
    activeMenu = { el: menu, onDocDown: onDocDown };
    if (items.length) items[0].focus();
  }

  function focusBack(elem) { if (elem && elem.focus) { try { elem.focus(); } catch (e) { /* element gone */ } } }

  function positionMenu(menu, anchorEl) {
    var vw = window.innerWidth, vh = window.innerHeight;
    var mr = menu.getBoundingClientRect();
    var top = 12, left = 12;
    if (anchorEl && anchorEl.getBoundingClientRect) {
      var r = anchorEl.getBoundingClientRect();
      left = r.right + 8;
      if (left + mr.width > vw - 8) left = r.left - mr.width - 8;     // flip to the left
      if (left < 8) left = Math.max(8, (vw - mr.width) / 2);          // last resort: center
      top = Math.min(r.top, Math.max(8, vh - mr.height - 8));
    }
    menu.style.left = Math.round(left) + "px";
    menu.style.top = Math.round(top) + "px";
  }

  function closeZoneMenu() {
    if (!activeMenu) return;
    document.removeEventListener("pointerdown", activeMenu.onDocDown, true);
    if (activeMenu.el && activeMenu.el.parentNode) activeMenu.el.parentNode.removeChild(activeMenu.el);
    activeMenu = null;
  }

  // --- zone selector tabs -------------------------------------------------
  function renderZoneTabs(zones) {
    var box = $("#zone-tabs");
    if (!box) return;
    reconcile(box, zones, function (z) { return z.id; }, function (z) {
      var b = el("button", "zone-tab");
      b.type = "button";
      b.setAttribute("role", "tab");
      var zid = z.id;
      b.addEventListener("click", function () { selectZone(zid); });
      b.addEventListener("keydown", function (e) { onZoneTabKey(e, zid); });
      return { root: b, id: zid };
    }, function (rec, z) {
      setText(rec.root, z.name);
      var sel = z.id === state.selectedZone;
      rec.root.setAttribute("aria-selected", sel ? "true" : "false");
      rec.root.setAttribute("tabindex", sel ? "0" : "-1");
      rec.root.classList.toggle("is-selected", sel);
    }, zoneTabEls, true);
  }

  function selectZone(id) {
    if (state.selectedZone === id) return;
    state.selectedZone = id;
    closeZoneMenu();
    render();
  }

  function onZoneTabKey(e, zid) {
    var zones = zoneList();
    var i = -1;
    for (var k = 0; k < zones.length; k++) if (zones[k].id === zid) { i = k; break; }
    if (i < 0) return;
    var next;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") next = (i + 1) % zones.length;
    else if (e.key === "ArrowLeft" || e.key === "ArrowUp") next = (i - 1 + zones.length) % zones.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = zones.length - 1;
    else return;
    e.preventDefault();
    var nz = zones[next];
    selectZone(nz.id);
    var rec = zoneTabEls[nz.id];
    if (rec && rec.root) rec.root.focus();
  }

  function renderZoneActions(zone) {
    var isGroup = !!(zone && zone.id !== UNGROUPED && zone.group);
    var editBtn = $("#zone-edit"), delBtn = $("#zone-delete");
    if (editBtn) { show(editBtn, isGroup); editBtn.hidden = !isGroup; }
    if (delBtn) { show(delBtn, isGroup); delBtn.hidden = !isGroup; }
  }

  // --- zone CRUD ----------------------------------------------------------
  function groupErrText(res) {
    var d = res && res.data;
    if (d && (d.detail || d.error)) return d.detail || d.error;
    return "HTTP " + (res ? res.status : "?");
  }

  // Authenticated, CSRF-protected JSON write (mirrors the exit-node POST flow):
  // 401 → login overlay; 403 → refresh the CSRF token and retry once. Resolves to
  // {ok, status, data, text}; resolves undefined when the login overlay took over.
  function apiWrite(method, url, body, retried) {
    return ensureCSRF().then(function () {
      var opts = {
        method: method,
        headers: { "Accept": "application/json", "X-Tsctl-CSRF": state.csrfToken || "" },
      };
      if (body != null) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(body);
      }
      return fetch(url, opts);
    }).then(function (resp) {
      return resp.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
        if (resp.status === 401) { promptLogin(); return undefined; }
        if (resp.status === 403 && !retried) { return fetchCSRF().then(function () { return apiWrite(method, url, body, true); }); }
        return { ok: resp.ok, status: resp.status, data: data, text: text };
      });
    });
  }

  function confirmDeleteZone(group) {
    var body = el("div");
    body.appendChild(document.createTextNode("Delete the zone "));
    body.appendChild(el("strong", null, group.name || "(unnamed)"));
    body.appendChild(document.createTextNode("? Its consumers move to Ungrouped. No exit-node changes are made."));
    openModal({
      title: "Delete zone?",
      body: body,
      confirmLabel: "Delete zone",
      cancelLabel: "Cancel",
      onConfirm: function () { deleteZone(group.id); },
    });
  }

  function deleteZone(id) {
    apiWrite("DELETE", "/api/groups/" + encodeURIComponent(id), null)
      .then(function (res) {
        if (!res) return; // login overlay took over
        if (res.ok || res.status === 204) {
          if (state.selectedZone === id) state.selectedZone = null; // re-default next render
          toast("ok", "Zone deleted", "");
        } else if (res.status === 404) {
          toast("warn", "Zone already gone", "It may have been deleted elsewhere.");
        } else {
          toast("err", "Couldn’t delete zone", groupErrText(res));
        }
      })
      .catch(function (err) { toast("err", "Network error", String((err && err.message) || err)); });
  }

  // --- zone editor (create / rename / membership) -------------------------
  function consumerPickItems(group) {
    var present = {};
    var items = snapRouters().map(function (rv) {
      var sid = rv.node.stableID;
      present[sid] = true;
      var checked = false;
      if (group) (group.consumers || []).forEach(function (m) { if (m.stableID === sid) checked = true; });
      return { sid: sid, label: rv.node.name || rv.node.hostname || sid, sub: (rv.node.tailscaleIPs || [])[0] || "", checked: checked, missing: false };
    });
    if (group) (group.consumers || []).forEach(function (m) {
      if (!present[m.stableID]) items.push({ sid: m.stableID, label: m.name || m.stableID, sub: "not in netmap", checked: true, missing: true });
    });
    return items;
  }

  function exitPickItems(group) {
    var present = {};
    var items = snapNodes().filter(isExitCapable).map(function (n) {
      present[n.stableID] = true;
      var checked = false;
      if (group) (group.allowedExitNodes || []).forEach(function (m) { if (m.stableID === n.stableID) checked = true; });
      return { sid: n.stableID, label: n.name || n.hostname || n.stableID, sub: ((n.tailscaleIPs || [])[0] || "") + (n.online ? "" : " · offline"), checked: checked, missing: false };
    });
    if (group) (group.allowedExitNodes || []).forEach(function (m) {
      if (!present[m.stableID]) items.push({ sid: m.stableID, label: m.name || m.stableID, sub: "not in netmap", checked: true, missing: true });
    });
    return items;
  }

  function buildMemberPicker(title, items, idPrefix) {
    var field = el("div", "editor-field");
    field.appendChild(el("div", "editor-label", title));
    var list = el("div", "member-list");
    var inputs = [];
    if (!items.length) list.appendChild(el("p", "member-empty", "None available."));
    items.forEach(function (it, i) {
      var row = el("label", "member-item" + (it.missing ? " is-missing" : ""));
      var cb = el("input");
      cb.type = "checkbox";
      cb.className = "member-cb";
      cb.checked = !!it.checked;
      cb.value = it.sid;
      cb.id = idPrefix + "-" + i;
      var txt = el("span", "member-text");
      txt.appendChild(el("span", "member-name", it.label + (it.missing ? " (missing)" : "")));
      if (it.sub) txt.appendChild(el("span", "member-sub", it.sub));
      row.appendChild(cb);
      row.appendChild(txt);
      list.appendChild(row);
      inputs.push(cb);
    });
    field.appendChild(list);
    return {
      field: field,
      selected: function () {
        var out = [];
        inputs.forEach(function (cb) { if (cb.checked) out.push(cb.value); });
        return out;
      },
    };
  }

  function openEditor(group) {
    closeZoneMenu();
    var isNew = !group;
    var prevFocus = document.activeElement;
    var backdrop = el("div", "modal-backdrop");
    var dialog = el("div", "modal editor");
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    var uid = "ed" + Date.now();

    var titleEl = el("h2", "modal-title", isNew ? "New zone" : "Edit zone");
    titleEl.id = uid + "-t";
    dialog.setAttribute("aria-labelledby", titleEl.id);
    dialog.appendChild(titleEl);

    var bodyEl = el("div", "modal-body editor-body");
    var nameField = el("div", "editor-field");
    var nameLbl = el("label", "editor-label", "Zone name");
    nameLbl.htmlFor = uid + "-name";
    var nameInput = el("input", "editor-input");
    nameInput.id = uid + "-name";
    nameInput.type = "text";
    nameInput.autocomplete = "off";
    nameInput.spellcheck = false;
    nameInput.value = group ? (group.name || "") : "";
    nameInput.setAttribute("placeholder", "e.g. Work");
    nameField.appendChild(nameLbl);
    nameField.appendChild(nameInput);
    bodyEl.appendChild(nameField);

    var consBox = buildMemberPicker("Consumers (routers)", consumerPickItems(group), uid + "-c");
    bodyEl.appendChild(consBox.field);
    var exitBox = buildMemberPicker("Allowed exit nodes", exitPickItems(group), uid + "-e");
    bodyEl.appendChild(exitBox.field);

    var errEl = el("div", "editor-error hidden");
    errEl.setAttribute("role", "alert");
    bodyEl.appendChild(errEl);
    dialog.appendChild(bodyEl);

    var actions = el("div", "modal-actions editor-actions");
    var delBtn = null;
    if (!isNew) {
      delBtn = el("button", "btn btn-danger editor-del", "Delete");
      delBtn.type = "button";
      actions.appendChild(delBtn);
    }
    actions.appendChild(el("div", "editor-spacer"));
    var cancelBtn = el("button", "btn btn-secondary", "Cancel");
    cancelBtn.type = "button";
    var saveBtn = el("button", "btn btn-primary", isNew ? "Create zone" : "Save");
    saveBtn.type = "button";
    actions.appendChild(cancelBtn);
    actions.appendChild(saveBtn);
    dialog.appendChild(actions);

    backdrop.appendChild(dialog);
    document.body.appendChild(backdrop);

    function closeEditor() {
      if (activeModal === backdrop) activeModal = null;
      if (backdrop.parentNode) backdrop.parentNode.removeChild(backdrop);
    }
    function done() { closeEditor(); focusBack(prevFocus); }
    function showErr(msg) { setText(errEl, msg || ""); show(errEl, !!msg); }
    function setBusy(b) { saveBtn.disabled = b; cancelBtn.disabled = b; if (delBtn) delBtn.disabled = b; }

    cancelBtn.addEventListener("click", done);
    backdrop.addEventListener("mousedown", function (e) { if (e.target === backdrop) done(); });
    dialog.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { e.preventDefault(); done(); return; }
      if (e.key === "Tab") {
        var f = dialog.querySelectorAll('button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])');
        if (!f.length) return;
        var first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    });
    if (delBtn) delBtn.addEventListener("click", function () { done(); confirmDeleteZone(group); });

    saveBtn.addEventListener("click", function () {
      var name = (nameInput.value || "").trim();
      if (!name) { showErr("Please enter a zone name."); nameInput.focus(); return; }
      var payload = { name: name, consumers: consBox.selected(), allowedExitNodes: exitBox.selected() };
      setBusy(true);
      showErr("");
      var method = isNew ? "POST" : "PUT";
      var url = isNew ? "/api/groups" : "/api/groups/" + encodeURIComponent(group.id);
      apiWrite(method, url, payload).then(function (res) {
        if (!res) return; // login overlay took over
        if (res.ok) {
          if (res.data && res.data.id) state.selectedZone = res.data.id; // auto-select on the next snapshot
          toast("ok", isNew ? "Zone created" : "Zone saved", (res.data && res.data.name) || "");
          done();
          render();
          return;
        }
        setBusy(false);
        if (res.status === 404) showErr("This zone no longer exists (it may have been deleted).");
        else showErr(groupErrText(res)); // 422 validation {error/detail}, 400, etc.
      }).catch(function (err) {
        setBusy(false);
        showErr("Network error: " + ((err && err.message) || err));
      });
    });

    activeModal = backdrop;
    nameInput.focus();
  }

  // --- view toggle (graph <-> cards) --------------------------------------
  function setView(view) {
    if (view !== "graph" && view !== "cards") return;
    if (state.view === view) return;
    state.view = view;
    closeZoneMenu();
    render();
  }
  function renderViewToggle() {
    var z = $("#tab-zones"), d = $("#tab-devices");
    var graph = state.view === "graph";
    if (z) { z.setAttribute("aria-selected", graph ? "true" : "false"); z.setAttribute("tabindex", graph ? "0" : "-1"); z.classList.toggle("is-selected", graph); }
    if (d) { d.setAttribute("aria-selected", graph ? "false" : "true"); d.setAttribute("tabindex", graph ? "-1" : "0"); d.classList.toggle("is-selected", !graph); }
  }

  function wireGraph() {
    var z = $("#tab-zones"), d = $("#tab-devices");
    if (z) z.addEventListener("click", function () { setView("graph"); });
    if (d) d.addEventListener("click", function () { setView("cards"); });
    function segKey(e, other) {
      if (e.key === "ArrowRight" || e.key === "ArrowLeft" || e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault(); other.focus(); other.click();
      }
    }
    if (z && d) {
      z.addEventListener("keydown", function (e) { segKey(e, d); });
      d.addEventListener("keydown", function (e) { segKey(e, z); });
    }
    var nb = $("#zone-new"); if (nb) nb.addEventListener("click", function () { openEditor(null); });
    var eb = $("#zone-edit"); if (eb) eb.addEventListener("click", function () { var zn = resolveSelectedZone(); if (zn && zn.group) openEditor(zn.group); });
    var db = $("#zone-delete"); if (db) db.addEventListener("click", function () { var zn = resolveSelectedZone(); if (zn && zn.group) confirmDeleteZone(zn.group); });
    // Wires depend on element positions — redraw on resize (coalesced; skipped mid-drag).
    window.addEventListener("resize", function () {
      if (state.view !== "graph") return;
      if (state.graphDrag && state.graphDrag.active) return;
      if (rafPending) return;
      rafPending = true;
      window.requestAnimationFrame(function () { rafPending = false; drawWiresForCurrent(); });
    });
  }

  // --------------------------------------------------------------- render ---
  function metaSource() {
    if (state.pollFallback && state.nodesOnly) return state.nodesOnly;
    return state.snapshot || state.nodesOnly;
  }
  function currentNodes() {
    if (state.pollFallback && state.nodesOnly && Array.isArray(state.nodesOnly.nodes)) return state.nodesOnly.nodes;
    if (state.snapshot && Array.isArray(state.snapshot.nodes)) return state.snapshot.nodes;
    if (state.nodesOnly && Array.isArray(state.nodesOnly.nodes)) return state.nodesOnly.nodes;
    return [];
  }

  function renderConn() {
    var c = $("#conn-status");
    if (!c) return;
    var map = {
      open: ["Live", "conn conn-live"],
      connecting: ["connecting…", "conn conn-wait"],
      reconnecting: ["reconnecting…", "conn conn-wait"],
      offline: ["offline", "conn conn-off"],
    };
    var m = map[state.connection] || map.connecting;
    c.textContent = "";
    if (state.connection === "open") c.appendChild(dotIcon("dot-on"));
    else if (state.connection === "offline") c.appendChild(dotIcon("dot-off"));
    else c.appendChild(spinnerIcon());
    c.appendChild(document.createTextNode(" " + m[0]));
    c.className = m[1];
  }

  function renderUpdated() {
    var u = $("#updated");
    if (!u) return;
    var src = metaSource();
    var t = parseTime(src && src.builtAt);
    setText(u, t ? "Updated " + relTime(src.builtAt) : (state.gotSseFrame || state.nodesOnly ? "" : "Waiting for data…"));
  }

  function renderGlobalError() {
    var b = $("#global-error");
    if (state.globalError) { setText(b, state.globalError); show(b, true); }
    else { setText(b, ""); show(b, false); }
  }

  function renderFallbackBanner() {
    var b = $("#fallback-banner");
    if (state.pollFallback) {
      setText(b, "Live updates unavailable — showing periodic device snapshots every "
        + (POLL_FALLBACK_MS / 1000) + "s. Router controls need the live stream and may be stale.");
      show(b, true);
    } else { setText(b, ""); show(b, false); }
  }

  function renderNetmapErr() {
    var b = $("#netmap-err");
    var src = metaSource();
    var err = src && src.netmapErr;
    if (err) {
      setText(b, "Inventory may be stale — the netmap couldn’t be refreshed: " + err + " (showing the last good data).");
      show(b, true);
    } else { setText(b, ""); show(b, false); }
  }

  function renderStale() {
    var b = $("#stale-banner");
    var src = metaSource();
    var t = parseTime(src && src.builtAt);
    if (!t) { show(b, false); return; }
    var age = Math.round((Date.now() - t.getTime()) / 1000);
    if (age > STALE_SECS) {
      setText(b, "Data may be stale — last updated " + relTime(src.builtAt) + ".");
      show(b, true);
    } else { show(b, false); }
  }

  function renderRouters() {
    var emptyEl = $("#routers-empty");
    if (!state.gotSseFrame) {
      // router status comes only from the live stream
      reconcile($("#routers"), [], routerKey, createRouterCard, function () {}, routerEls, false);
      setText(emptyEl, state.pollFallback
        ? "Router controls need the live stream, which is currently unavailable. Reconnecting…"
        : "Loading routers…");
      show(emptyEl, true);
      return;
    }
    var snap = state.snapshot;
    var routers = snap && Array.isArray(snap.routers) ? snap.routers : [];
    reconcile($("#routers"), routers, routerKey, createRouterCard,
      function (rec, rv) { updateRouterCard(rec, rv, snap); }, routerEls, false);
    if (routers.length === 0) {
      var msg = el("span");
      msg.appendChild(document.createTextNode("No routers configured. Start tsctl with "));
      msg.appendChild(el("code", null, "-routers <100.x IPv4,…>"));
      msg.appendChild(document.createTextNode(" (and tag those devices "));
      msg.appendChild(el("code", null, "tag:router"));
      msg.appendChild(document.createTextNode(") to manage their exit nodes here."));
      emptyEl.textContent = "";
      emptyEl.appendChild(msg);
      show(emptyEl, true);
    } else { show(emptyEl, false); }
  }
  function routerKey(rv) { return (rv.node && rv.node.stableID) || JSON.stringify(rv.node || {}); }

  function matchesFilter(n) {
    var f = state.filter;
    if (f.type === "online" && n.online !== true) return false;
    if (f.type === "router" && n.type !== "router") return false;
    if (f.type === "exit" && n.exitNodeOption !== true) return false;
    if (f.type === "generic" && n.type !== "generic") return false;
    var q = f.text.trim().toLowerCase();
    if (!q) return true;
    var hay = [n.name, n.hostname, n.os, n.type].concat(n.tailscaleIPs || []).join(" ").toLowerCase();
    return hay.indexOf(q) !== -1;
  }

  function renderNodes() {
    var nodes = currentNodes().slice();
    nodes.sort(function (a, b) {
      if ((b.online === true) - (a.online === true) !== 0) return (b.online === true) - (a.online === true);
      return (a.name || a.hostname || "").localeCompare(b.name || b.hostname || "");
    });
    reconcile($("#nodes"), nodes, function (n) { return n.stableID || (n.name || "") + "|" + (n.hostname || ""); },
      createNodeCard, updateNodeCard, nodeEls, true);

    // apply the search/type filter and count visibility
    var total = nodes.length, visible = 0;
    Object.keys(nodeEls).forEach(function (k) {
      var rec = nodeEls[k];
      var ok = rec.data ? matchesFilter(rec.data) : true;
      rec.root.classList.toggle("is-filtered", !ok);
      if (ok) visible++;
    });

    var anyFilter = state.filter.type !== "all" || state.filter.text.trim() !== "";
    show($("#nodes-tools"), total > SEARCH_THRESHOLD);
    setText($("#nodes-count"), total === 0 ? "" : (anyFilter ? visible + " of " + total : total + (total === 1 ? " device" : " devices")));

    var emptyEl = $("#nodes-empty");
    if (total === 0) {
      setText(emptyEl, state.gotSseFrame || state.nodesOnly ? "No devices in the netmap yet. Check that tsctl can see your tailnet peers (ACL visibility)." : "Loading devices…");
      show(emptyEl, true);
    } else if (visible === 0) {
      setText(emptyEl, "No devices match your filter.");
      show(emptyEl, true);
    } else { show(emptyEl, false); }
  }

  // 403 full view: a request was blocked by Host/CSRF (DNS-rebinding) protection.
  function renderAuth() {
    var ae = $("#auth-error");
    if (!ae) return;
    if (state.authError) {
      var d = $("#auth-error-detail");
      if (d && state.authDetail) {
        d.textContent = "This request was rejected by tsctl’s anti-DNS-rebinding protection "
          + "(the page’s host isn’t on the allowlist). Open the UI at the tsctl node’s MagicDNS name, "
          + "its 100.x address, or a host you’ve added to TSCTL_ALLOWED_HOSTS. "
          + "(Server said: " + state.authDetail + ")";
      }
      ae.hidden = false; show(ae, true);
    } else { ae.hidden = true; show(ae, false); }
  }

  // 401 overlay: prompt for the UI password (or explain that password sign-in is
  // disabled on a tailnet-only server).
  function renderLogin() {
    var ov = $("#login-overlay");
    if (!ov) return;
    if (!state.needsLogin) {
      ov.hidden = true; show(ov, false);
      ov._shown = false;
      var clear = $("#login-password");
      if (clear) clear.value = "";
      return;
    }
    ov.hidden = false; show(ov, true);
    var desc = $("#login-desc");
    var input = $("#login-password");
    var submit = $("#login-submit");
    var errEl = $("#login-error");
    if (state.loginDisabled) {
      setText(desc, "Password sign-in is disabled on this server. Access requires signing in to the tailnet as the configured owner.");
      if (input) input.disabled = true;
      if (submit) { submit.disabled = true; setText(submit, "Sign in"); }
      setText(errEl, "");
    } else {
      setText(desc, "Enter the tsctl password to continue.");
      if (input) input.disabled = state.loginBusy;
      if (submit) { submit.disabled = state.loginBusy; setText(submit, state.loginBusy ? "Signing in…" : "Sign in"); }
      setText(errEl, state.loginError || "");
    }
    // Focus the field once, when the overlay first appears.
    if (!ov._shown && input && !input.disabled) {
      ov._shown = true;
      try { input.focus(); } catch (e) { /* not focusable yet */ }
    }
  }

  // "Sign out" is only meaningful when a password session is in use.
  function renderSignout() {
    var b = $("#signout-btn");
    if (!b) return;
    var vis = state.sessionActive && !state.needsLogin && !state.authError;
    show(b, vis);
    b.hidden = !vis;
  }

  function render() {
    renderAuth();
    renderLogin();
    renderSignout();
    renderConn();
    // A blocking overlay (403 forbidden or 401 login) owns the screen; don't
    // also paint the (stale/empty) data behind it.
    if (state.authError || state.needsLogin) return;

    renderUpdated();
    renderGlobalError();
    renderFallbackBanner();
    renderNetmapErr();
    renderStale();

    var hasData = state.gotSseFrame || !!state.nodesOnly;
    $("#loading").hidden = hasData;
    var viewbar = $("#viewbar");
    if (viewbar) { show(viewbar, hasData); viewbar.hidden = !hasData; }
    if (!hasData) {
      $("#graph-section").hidden = true;
      $("#routers-section").hidden = true;
      $("#nodes-section").hidden = true;
      return;
    }

    renderViewToggle();
    var graphView = state.view === "graph";
    $("#graph-section").hidden = !graphView;
    $("#routers-section").hidden = graphView;
    $("#nodes-section").hidden = graphView;
    if (graphView) {
      renderGraph();
    } else {
      renderRouters();
      renderNodes();
    }
  }

  // ----------------------------------------------------------- networking ---
  // A blocking overlay is up (401 login or 403 forbidden): suppress SSE
  // reconnects and the poll fallback so we don't hammer a closed door.
  function blocked() { return state.authError || state.needsLogin; }

  // Map an /api auth failure to the right overlay: 401 → authenticate (login
  // form); 403 → blocked by Host/CSRF (DNS-rebinding) full view.
  function handleAuthFailure(status, body) {
    if (status === 401) { promptLogin(); }
    else { showForbidden(body); }
  }

  // 403: request blocked (Host/CSRF). Full-screen, no retry — it's a config/URL
  // problem, not a credential the user can supply here.
  function showForbidden(body) {
    state.authError = true;
    state.authDetail = (body && body.error) || "";
    state.needsLogin = false;
    stopPollFallback();
    if (state.es) { try { state.es.close(); } catch (e) { /* already closed */ } state.es = null; }
    render();
  }

  // 401: show the login overlay. errMsg (optional) replaces the current message;
  // omit it to keep whatever's there (e.g. a background 401 shouldn't say
  // "incorrect password").
  function promptLogin(errMsg) {
    state.needsLogin = true;
    if (errMsg !== undefined) state.loginError = errMsg;
    stopPollFallback();
    if (state.es) { try { state.es.close(); } catch (e) { /* already closed */ } state.es = null; }
    render();
  }

  // POST the password to /api/login (CSRF-protected). On success, drop the
  // overlay and resume the normal data flow; on failure, explain in the overlay.
  function submitLogin(password) {
    state.loginBusy = true;
    state.loginError = "";
    state.loginDisabled = false;
    renderLogin();
    ensureCSRF()
      .then(function () {
        return fetch("/api/login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Tsctl-CSRF": state.csrfToken || "",
          },
          body: JSON.stringify({ password: password }),
        });
      })
      .then(function (resp) {
        return resp.text().then(function (text) {
          var data = null;
          try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
          if (resp.ok) {
            state.needsLogin = false;
            state.loginError = "";
            state.loginDisabled = false;
            state.sessionActive = true;
            resumeAfterLogin();
            return;
          }
          if (resp.status === 404) {
            // Password sign-in is disabled (tailnet-only server).
            state.loginDisabled = true;
            state.loginError = "";
          } else if (resp.status === 401) {
            state.loginError = "Incorrect password.";
          } else if (resp.status === 403) {
            state.loginError = (data && data.error) || "Request blocked.";
          } else {
            state.loginError = (data && data.error) || ("Sign-in failed (HTTP " + resp.status + ").");
          }
        });
      })
      .catch(function (err) {
        state.loginError = "Network error: " + ((err && err.message) || err);
      })
      .then(function () {
        state.loginBusy = false;
        renderLogin();
      });
  }

  // After a successful login: hide the overlay and re-bootstrap the data flow.
  function resumeAfterLogin() {
    render();
    fetchNodes();   // first paint with the new session
    connectSSE();   // re-open the live stream
  }

  // "Sign out": clear the server session, then fall back to the login overlay.
  function doLogout() {
    ensureCSRF()
      .then(function () {
        return fetch("/api/logout", {
          method: "POST",
          headers: { "Accept": "application/json", "X-Tsctl-CSRF": state.csrfToken || "" },
        });
      })
      .then(function () {
        state.sessionActive = false;
        state.snapshot = null;
        state.nodesOnly = null;
        state.gotSseFrame = false;
        promptLogin("");
      })
      .catch(function (err) {
        toast("err", "Sign out failed", String((err && err.message) || err));
      });
  }

  function fetchCSRF() {
    return fetch("/api/csrf", { headers: { Accept: "application/json" } })
      .then(function (r) {
        if (r.status === 401 || r.status === 403) {
          return r.json().catch(function () { return {}; }).then(function (b) { handleAuthFailure(r.status, b); });
        }
        if (!r.ok) throw new Error("CSRF HTTP " + r.status);
        return r.json().then(function (d) {
          state.csrfToken = (d && d.token) || null;
          if (!state.csrfToken) throw new Error("CSRF response missing token");
          state.globalError = "";
          renderGlobalError();
        });
      })
      .catch(function (e) {
        state.globalError = "Could not obtain a CSRF token — exit-node changes are disabled: " + ((e && e.message) || e);
        renderGlobalError();
      });
  }
  function ensureCSRF() {
    if (state.csrfToken) return Promise.resolve();
    return fetchCSRF();
  }

  function fetchNodes() {
    return fetch("/api/nodes", { headers: { Accept: "application/json" } })
      .then(function (r) {
        if (r.status === 401 || r.status === 403) {
          return r.json().catch(function () { return {}; }).then(function (b) { handleAuthFailure(r.status, b); });
        }
        if (!r.ok) throw new Error("nodes HTTP " + r.status);
        return r.json().then(function (d) { state.nodesOnly = d; render(); });
      })
      .catch(function (e) {
        if (!state.gotSseFrame && !state.pollFallback) {
          state.globalError = "First-paint fetch failed (waiting for the live stream): " + ((e && e.message) || e);
          renderGlobalError();
        }
      });
  }

  function startPollFallback() {
    if (state.pollFallback) return;
    state.pollFallback = true;
    if (!state.sseEverOpened) state.connection = "offline";
    fetchNodes();
    state.pollTimer = setInterval(fetchNodes, POLL_FALLBACK_MS);
    render();
  }
  function stopPollFallback() {
    if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
    state.pollFallback = false;
  }

  function armOpenWatchdog() {
    if (state.openWatchdog || state.pollFallback) return;
    state.openWatchdog = setTimeout(function () {
      state.openWatchdog = null;
      if (!blocked()) startPollFallback(); // never opened / long outage → poll
    }, OPEN_WATCHDOG_MS);
  }
  function clearOpenWatchdog() {
    if (state.openWatchdog) { clearTimeout(state.openWatchdog); state.openWatchdog = null; }
  }

  function connectSSE() {
    if (blocked()) return;
    var es;
    try { es = new EventSource("/api/events"); }
    catch (e) { state.connection = "reconnecting"; renderConn(); scheduleReconnect(); return; }
    state.es = es;
    armOpenWatchdog();

    es.onopen = function () {
      state.sseEverOpened = true;
      state.connection = "open";
      state.reconnectDelay = RECONNECT_MIN;
      clearOpenWatchdog();
      stopPollFallback();
      renderConn();
    };
    es.onmessage = function (ev) {
      if (!ev || !ev.data) return;
      var snap;
      try { snap = JSON.parse(ev.data); }
      catch (e) { state.globalError = "Received a malformed live update frame."; renderGlobalError(); return; }
      // First frame after (re)connect is a full snapshot → clean reconcile.
      state.gotSseFrame = true;
      state.connection = "open";
      state.globalError = "";
      clearOpenWatchdog();
      stopPollFallback();
      state.snapshot = snap;
      render();
    };
    es.onerror = function () {
      if (blocked()) return;
      state.connection = state.pollFallback ? "offline" : "reconnecting";
      renderConn();
      armOpenWatchdog();
      if (es.readyState === EventSource.CLOSED) {
        try { es.close(); } catch (e) { /* already closed */ }
        scheduleReconnect();
      }
    };
  }

  function scheduleReconnect() {
    if (state.reconnectTimer || blocked()) return;
    var delay = state.reconnectDelay;
    state.reconnectDelay = Math.min(state.reconnectDelay * 2, RECONNECT_MAX);
    state.reconnectTimer = setTimeout(function () {
      state.reconnectTimer = null;
      connectSSE();
    }, delay);
  }

  // ------------------------------------------------------------ UI wiring ---
  function buildChips() {
    var box = $("#filter-chips");
    if (!box) return;
    CHIPS.forEach(function (c) {
      var b = el("button", "chip", c.label);
      b.type = "button";
      b.setAttribute("aria-pressed", c.id === state.filter.type ? "true" : "false");
      b.addEventListener("click", function () {
        state.filter.type = c.id;
        var all = box.querySelectorAll(".chip");
        for (var i = 0; i < all.length; i++) all[i].setAttribute("aria-pressed", "false");
        b.setAttribute("aria-pressed", "true");
        renderNodes();
      });
      box.appendChild(b);
    });
  }

  function wireControls() {
    var help = $("#help-btn");
    var legend = $("#legend");
    if (help && legend) {
      help.addEventListener("click", function () {
        var open = legend.hasAttribute("hidden") || legend.classList.contains("hidden");
        if (open) { legend.hidden = false; legend.classList.remove("hidden"); help.setAttribute("aria-expanded", "true"); }
        else { legend.hidden = true; legend.classList.add("hidden"); help.setAttribute("aria-expanded", "false"); }
      });
    }
    var search = $("#node-search");
    if (search) {
      search.addEventListener("input", function () { state.filter.text = search.value || ""; renderNodes(); });
    }
    // Login overlay: submit the password (CSRF-protected) on form submit.
    var loginForm = $("#login-form");
    if (loginForm) {
      loginForm.addEventListener("submit", function (e) {
        e.preventDefault();
        if (state.loginBusy || state.loginDisabled) return;
        var input = $("#login-password");
        submitLogin(input ? input.value : "");
      });
    }
    // "Sign out" (only shown when a password session is in use).
    var signout = $("#signout-btn");
    if (signout) signout.addEventListener("click", doLogout);
    // Esc closes any open modal even if focus drifted off the dialog.
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && activeModal) {
        var cancel = activeModal.querySelector(".btn-secondary");
        if (cancel) cancel.click();
      }
    });
  }

  // ------------------------------------------------------------------ init ---
  function init() {
    buildChips();
    wireControls();
    wireGraph();
    render();
    fetchCSRF();
    fetchNodes();   // first paint (also the no-SSE fallback seed)
    connectSSE();
    setInterval(render, TICK_MS); // keep relative times / countdowns fresh
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
