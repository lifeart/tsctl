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
    snapshot: null,    // last full SSE Snapshot {nodes, routers, netmapAt, netmapErr, builtAt}
    nodesOnly: null,   // {nodes, builtAt, netmapErr} from GET /api/nodes
    gotSseFrame: false,
    connection: "connecting", // connecting | open | reconnecting | offline
    globalError: "",
    authError: false,
    authDetail: "",
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
  };

  var nodeEls = {};   // stableID -> node card record
  var routerEls = {}; // stableID -> router card record
  var activeModal = null;

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
    if (value === current) return;
    if (state.busyRouters[sid]) return;

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
      returnFocus: select,
      onConfirm: function () { onPick(sid, value); },
      onCancel: function () { /* selection already reset to actual */ },
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

  function renderAuth() {
    var ae = $("#auth-error");
    if (state.authError) {
      var d = $("#auth-error-detail");
      if (d && state.authDetail) {
        // keep the standard explanation, append the server's words if useful
        d.textContent = "Your tailnet identity isn’t the configured owner, so tsctl won’t show or change anything. "
          + "Sign in to the tailnet as the owner account, or update the owner setting on the server. "
          + "(Server said: " + state.authDetail + ")";
      }
      ae.hidden = false; show(ae, true);
    } else { ae.hidden = true; show(ae, false); }
  }

  function render() {
    renderAuth();
    if (state.authError) { renderConn(); return; }

    renderConn();
    renderUpdated();
    renderGlobalError();
    renderFallbackBanner();
    renderNetmapErr();
    renderStale();

    var hasData = state.gotSseFrame || !!state.nodesOnly;
    $("#loading").hidden = hasData;
    $("#routers-section").hidden = !hasData;
    $("#nodes-section").hidden = !hasData;
    if (!hasData) return;

    renderRouters();
    renderNodes();
  }

  // ----------------------------------------------------------- networking ---
  function handleAuth403(body) {
    state.authError = true;
    state.authDetail = (body && body.error) || "";
    stopPollFallback();
    if (state.es) { try { state.es.close(); } catch (e) { /* already closed */ } state.es = null; }
    render();
  }

  function fetchCSRF() {
    return fetch("/api/csrf", { headers: { Accept: "application/json" } })
      .then(function (r) {
        if (r.status === 403) { return r.json().catch(function () { return {}; }).then(handleAuth403); }
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
        if (r.status === 403) { return r.json().catch(function () { return {}; }).then(handleAuth403); }
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
      if (!state.authError) startPollFallback(); // never opened / long outage → poll
    }, OPEN_WATCHDOG_MS);
  }
  function clearOpenWatchdog() {
    if (state.openWatchdog) { clearTimeout(state.openWatchdog); state.openWatchdog = null; }
  }

  function connectSSE() {
    if (state.authError) return;
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
      if (state.authError) return;
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
    if (state.reconnectTimer || state.authError) return;
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
