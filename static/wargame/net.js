// static/wargame/net.js
// Thin client bindings + realtime (SSE) for Wargame.
//
// Exposes a single global: window.WGNet
// Back-compat aliases are included for older UIs (e.g., wgPinPlane(rowOrId)).
// Usage:
//   WGNet.init({ sessionId: 1, base: "" });
//   await WGNet.join("Kameron");
//   const flights = await WGNet.wgGetOutboundFlights();
//   WGNet.connectEvents(); // starts SSE
//   WGNet.onEvent("wg:plane_*", (ev) => { console.log(ev.topic, ev.data); });
//
(function () {
  // -------------------- Structured API Error --------------------
  class ApiError extends Error {
    constructor(code, message, data, status) {
      super(message || code || "Request failed");
      this.name = "ApiError";
      this.code = code || "http_error";
      this.data = data || null;
      this.status = status || null;
      this.isApiError = true;
    }
  }

  // Known realtime topics (keep in sync with server)
  const KNOWN_TOPICS = [
    "wg:plane_pin",
    "wg:plane_unselect",
    "wg:plane_status",
    "wg:plane_loaded",
    "wg:plane_paperwork_complete",
  ];

  function _qs(params) {
    const p = [];
    for (const [k, v] of Object.entries(params || {})) {
      if (v === undefined || v === null || v === "") continue;
      p.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
    }
    return p.length ? `?${p.join("&")}` : "";
  }

  // Canonicalize any plane id-ish value to the wire format "plane:<n>"
  function _canonPlaneId(v) {
    if (v == null) return null;
    if (typeof v === "number") {
      const n = Math.trunc(v);
      return Number.isFinite(n) && n > 0 ? `plane:${n}` : null;
    }
    const s = String(v).trim();
    if (!s) return null;
    // Accept "2", "plane:2", "Plane#2"
    let m = s.match(/^(?:plane[:#])?(\d+)$/i);
    if (m) return `plane:${m[1]}`;
    return null; // reject "NaN" and other garbage
  }

  // Read active plane id from the Plane Panel DOM if available (returns "plane:<n>" or null)
  function _parsePlaneIdFromDom() {
    try {
      const el = document.getElementById('wg-plane-panel');
      // Prefer explicit data attribute; accept either number-like or "plane:<n>"
      if (el && el.dataset && el.dataset.planeId != null) {
        const pid = _canonPlaneId(el.dataset.planeId);
        if (pid) return pid;
      }
      // Fallback: title text "Plane 12"
      const t = (document.getElementById('wgpp-title')?.textContent || "");
      const m = t.match(/plane\s*:?\s*(\d+)/i);
      if (m) {
        const pid = _canonPlaneId(m[1]);
        if (pid) return pid;
      }
    } catch(_) {}
    return null;
  }
  function _patternToRe(pat) {
    // Escape regex, then expand single '*' wildcards to '.*'
    const esc = String(pat)
      .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
      .replace(/\\\*/g, ".*");
    return new RegExp(`^${esc}$`);
  }

  const Net = {
    // ---- Core config / state ----
    sessionId: 1,
    playerId: null,
    base: "",
    _lastPosSentAt: 0,
    _lastPos: { x: NaN, y: NaN, dir: "" },

    // SSE
    _es: null,
    _handlers: [], // [{pattern, re, fn}]
    _topicListeners: new Map(), // topic -> listener fn
    // simple in-memory cache so panels re-open hydrated
    _pins: new Map(), // plane_id -> { pin, status, diff }
    // (cache key is String(plane_id))

    init(opts) {
      opts = opts || {};
      this.sessionId = opts.sessionId || 1;
      this.base = opts.base || "";
      return this;
    },

    // ---- HTTP helpers ----
    async _get(path) {
      const url = `${this.base}${path}`;
      const res = await fetch(url, { credentials: "same-origin" });
      if (!res.ok) {
        // Try to parse JSON error payloads so we can map codes in UX
        let payload = null, txt = "";
        try { payload = await res.json(); } catch { try { txt = await res.text(); } catch {} }
        if (payload && (payload.code || payload.error || (payload.error && payload.error.code))) {
          const code = payload.code || payload.error?.code || payload.error || "http_error";
          const message = payload.message || payload.error?.message || txt || `GET ${path} failed`;
          throw new ApiError(code, message, payload, res.status);
        }
        throw new ApiError("http_error", (txt || `GET ${path} failed`).trim(), { raw: txt }, res.status);
      }
      return res.json();
    },

    async _post(path, body) {
      const url = `${this.base}${path}`;
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(body || {}),
      });
      if (!res.ok) {
        // Try to parse JSON error payloads so we can map codes in UX
        let payload = null, txt = "";
        try { payload = await res.json(); } catch { try { txt = await res.text(); } catch {} }
        if (payload && (payload.code || payload.error || (payload.error && payload.error.code))) {
          const code = payload.code || payload.error?.code || payload.error || "http_error";
          const message = payload.message || payload.error?.message || txt || `POST ${path} failed`;
          throw new ApiError(code, message, payload, res.status);
        }
        throw new ApiError("http_error", (txt || `POST ${path} failed`).trim(), { raw: txt }, res.status);
      }
      return res.json();
    },

    // ---- Read-only adapters ----
    getStockpile() { return this._get(`/api/wargame/stockpile`); },
    getTrucks()    { return this._get(`/api/wargame/trucks`); },
    getQueues()    { return this._get(`/api/wargame/queues`); },
    getRampRequests() { return this._get(`/api/wargame/requests`); },

    // ---- World snapshot ----
    getState(sinceId) {
      const q = Number.isFinite(sinceId) && sinceId > 0 ? `&since_id=${sinceId}` : "";
      return this._get(`/wargame/state?session_id=${this.sessionId}${q}`);
    },
    getPlayers() { return this._get(`/wargame/players?session_id=${this.sessionId}`); },

    // ---- Presence / identity ----
    async join(name) {
      const j = await this._post(`/wargame/join`, { session_id: this.sessionId, name });
      this.playerId = j.player_id;
      return j;
    },
    rename(name) {
      if (!this.playerId) throw new Error("join first");
      return this._post(`/wargame/rename`, { session_id: this.sessionId, player_id: this.playerId, name });
    },

    // ---- Position updates (throttled + threshold + heartbeat) ----
    async sendPos(x, y, dir, hz = 8) {
      if (!this.playerId) return;

      const now = performance.now();
      const minDt = 1000 / Math.max(1, hz);
      const heartbeatDt = 600;
      const dx = x - this._lastPos.x;
      const dy = y - this._lastPos.y;
      const dist = Math.hypot(isNaN(dx) ? 999 : dx, isNaN(dy) ? 999 : dy);
      const dirChanged = (dir || "") !== (this._lastPos.dir || "");

      const elapsed = now - this._lastPosSentAt;
      const shouldHeartbeat = elapsed >= heartbeatDt;
      const shouldSend = elapsed >= minDt && (dist >= 0.75 || dirChanged || shouldHeartbeat);
      if (!shouldSend) return;

      this._lastPosSentAt = now;
      this._lastPos = { x, y, dir };

      return this._post(`/wargame/pos`, {
        session_id: this.sessionId,
        player_id: this.playerId,
        x, y, dir
      });
    },

    // ---- Claims (world events) ----
    postClaim(payload) {
      const body = Object.assign({ session_id: this.sessionId, player_id: this.playerId }, payload || {});
      return this._post(`/wargame/claim`, body);
    },

    // ---- Convenience helpers for claims ----
    async findTruck(truckId) {
      const trucks = await this.getTrucks();
      const all = [];
      (trucks && trucks.inbound || []).forEach(t => all.push(t));
      (trucks && trucks.outbound || []).forEach(t => all.push(t));
      return all.find(t => String(t.truck_id) === String(truckId));
    },
    async claimTakeFromTruck({ truck_id, size, qty, display_name, unit_lb, item_key }) {
      const payload = {
        action: "take",
        carrier_type: "truck",
        carrier_index: -1,
        carrier_uid: truck_id,
        item_key: item_key || "box",
        size, qty, display_name, unit_lb
      };
      if (window.postClaimSerial) return window.postClaimSerial(payload);
      return this.postClaim(payload);
    },
    async claimDropToStockpile({ size, qty, display_name, unit_lb, item_key }) {
      return this.postClaim({
        action: "stockpile_add",
        item_key: item_key || "box",
        size, qty, display_name, unit_lb
      });
    },

    // =============================================================================
    // v6 Wargame: Client API bindings (Step 6)
    // =============================================================================

    // Flights (read-only)
  async wgGetOutboundFlights() {
      // Replace "outbound flights" list with Cargo Requests rendered as flights.
      // Keeps existing UIs working without touching game.js.
      try {
        const data = await this._get(`/api/wargame/requests`);
        const reqs = (data && data.requests) || [];
        return _reqsToFlightish(reqs);
      } catch (e) {
        // Fallback to the real flights list if requests are unavailable.
        const data = await this._get(`/api/wargame/outbound_flights`);
        const rows = (data && data.flights) || [];
        return _normalizeFlights(rows);
      }
    },

    // Panel label helper (legacy UIs can opt-in to read this)
    wgGetOutboundPanelLabel(lastWasRequests = true) {
      return lastWasRequests ? "Cargo Requests" : "Outbound Flights";
    },

    // Plane selection / lifecycle
    // Payload expected by server:
    //   {
    //     plane_id, session_id, player_id,
    //     flight_ref: { request_id? , flight_id? }
    //   }
    async wgPlanePin(plane_id, selected, session_id, player_id) {
      // Resolve canonical plane id ("plane:<n>") from arg or DOM
      const resolvedPlane = _canonPlaneId(plane_id) || _parsePlaneIdFromDom();
      if (!resolvedPlane) {
        throw new ApiError(
          "missing_plane_id",
          "No active plane selected. Stand at a plane and open its panel first.",
          { selected },
          400
        );
      }
      const body = {
        plane_id: resolvedPlane, // string: "plane:<n>"
        session_id: session_id != null ? session_id : this.sessionId,
        player_id: player_id != null ? player_id : this.playerId,
        flight_ref: {}
      };
      const rawId = selected && (selected.id ?? selected.flight_id ?? selected.request_id);
      const n = rawId != null ? Number(rawId) : NaN;

      // Heuristics to detect a "request row" even if the caller didn't use our surrogate ids
      const looksLikeRequest =
        !!(selected && (
          selected._wg_is_request === true ||
          (Array.isArray(selected.lines) && !selected.tail_number && selected.destination !== undefined)
        ));

      if (looksLikeRequest && Number.isFinite(n)) {
        // Prefer explicit request id when the row is request-shaped
        body.flight_ref.request_id = (_isReqSurrogate(n) ? _reqIdFromSurrogate(n) : n);
      } else if (Number.isFinite(n)) {
        // Fallback to the original behavior: surrogate => request, else treat as flight
        if (_isReqSurrogate(n)) body.flight_ref.request_id = _reqIdFromSurrogate(n);
        else body.flight_ref.flight_id = n;
      }

      // If nothing set yet but we have an embedded request hint, use it.
      if (!body.flight_ref.request_id && selected && selected._wg_request_id != null) {
        body.flight_ref.request_id = Number(selected._wg_request_id);
      }
      // Do NOT send tail_number at top level (or at all here).
      const res = await this._post(`/api/wargame/plane/pin`, body);
      // Immediately notify listeners so the UI can render the manifest without SSE.
      try {
        if (res && res.ok && res.pin) {
          this._emit("wg:plane_pin", { plane_id: resolvedPlane, pin: res.pin });
          // Also compute status/diff so legacy panels flip to “pinned/ready”
          try {
            const st = await this.wgPlaneStatus(resolvedPlane,
              session_id != null ? session_id : this.sessionId);
            // st: { pin, diff, status }
            // normalize local cache/event payload just like wgPlaneStatus does
            const pin    = (st && st.pin) || null;
            const status = (st && st.status) || (pin && pin.status) || "idle";
            const diff   = (st && st.diff) || { shortages: [], excess: [] };
            this._pins.set(String(resolvedPlane), { pin, status, diff });
            this._emit("wg:plane_status", { plane_id: resolvedPlane, pin, status, diff });
          } catch (e) {
            // non-fatal; UI still has pin.required
          }
        }
      } catch (_) {
        // swallow; network consumers can still await wgPlanePin() result
      }
      return res;
    },

    wgPlaneStatus(plane_id, session_id, cart_id) {
      const pid = _canonPlaneId(plane_id) || _parsePlaneIdFromDom();
      if (!pid) {
        return Promise.reject(new ApiError("missing_plane_id", "No active plane selected.", null, 400));
      }
      const qs = _qs({
        plane_id: pid,
        session_id: session_id != null ? session_id : this.sessionId,
        cart_id: cart_id || undefined
      });
      return this._get(`/api/wargame/plane/status${qs}`).then((res) => {
        try {
          const pin    = (res && res.pin) || null;
          const status = (res && res.status) || (pin && pin.status) || "idle";
          const diff   = (res && res.diff) || { shortages: [], excess: [] };
          this._pins.set(String(pid), { pin, status, diff });
          this._emit("wg:plane_status", { plane_id: pid, pin, status, diff });
        } catch {}
        return res;
      });
    },

    wgPlaneLoad(plane_id, session_id, cart_id, player_id) {
      const pid = _canonPlaneId(plane_id) || _parsePlaneIdFromDom();
      if (!pid) {
        return Promise.reject(new ApiError("missing_plane_id", "No active plane selected.", null, 400));
      }
      const body = {
        plane_id: pid,
        session_id: session_id != null ? session_id : this.sessionId,
        player_id: player_id != null ? player_id : this.playerId
      };
      if (cart_id != null) body.cart_id = cart_id;
      return this._post(`/api/wargame/plane/load`, body);
    },

    wgPlaneUnselect(plane_id, session_id, player_id, opts) {
      const pid = _canonPlaneId(plane_id) || _parsePlaneIdFromDom();
      if (!pid) {
        return Promise.reject(new ApiError("missing_plane_id", "No active plane selected.", null, 400));
      }
      const body = {
        plane_id: pid,
        session_id: session_id != null ? session_id : this.sessionId,
        player_id: player_id != null ? player_id : this.playerId
      };
      if (opts && typeof opts.force !== "undefined") {
        body.force = !!opts.force;
      }
      return this._post(`/api/wargame/plane/unselect`, body).then((res) => {
        try {
          this._pins.delete(String(pid));
          this._emit("wg:plane_unselect", { plane_id: pid });
        } catch {}
        return res;
      });
    },

    wgPlanePaperworkComplete(plane_id, session_id, player_id) {
      const pid = _canonPlaneId(plane_id) || _parsePlaneIdFromDom();
      if (!pid) {
        return Promise.reject(new ApiError("missing_plane_id", "No active plane selected.", null, 400));
      }
      const body = {
        plane_id: pid,
        session_id: session_id != null ? session_id : this.sessionId,
        player_id: player_id != null ? player_id : this.playerId
      };
      return this._post(`/api/wargame/plane/paperwork_complete`, body);
    },

    // -------------------------------------------------------------------------
    // Back-compat shim: older UIs call WGNet.wgPinPlane(rowOrId) and expect the
    // client to derive plane_id and translate request-surrogate ids.
    // New code should call wgPlanePin(plane_id, selectedRow, ...).
    // -------------------------------------------------------------------------
    async wgPinPlane(rowOrId) {
      // Derive canonical plane id from DOM (Plane Panel) if not provided by UI.
      const planeId = _parsePlaneIdFromDom();
      // Normalize a "selected row" shape so wgPlanePin can do the right thing.
      let selected = null;
      let raw = rowOrId;
      // If a primitive "id" was passed, wrap it like a flight-ish row.
      if (typeof raw === 'number' || typeof raw === 'string') {
      const str = String(raw).trim();
        // Accept "REQ-<N>" form too
        const m = str.match(/^REQ-(\d+)$/i);
        if (m) {
          selected = { id: Number(m[1]), _wg_is_request: true, _wg_request_id: Number(m[1]) };
        } else {
        const n = Number(str);
        selected = { id: n };
        // If the “outbound flights” table is actually requests, treat bare numbers as requests.
        if (this.outboundIsRequests && this.outboundIsRequests()) {
          selected._wg_is_request = true;
          selected._wg_request_id = _isReqSurrogate(n) ? _reqIdFromSurrogate(n) : n;
        }
        }
      } else if (raw && typeof raw === 'object') {
        selected = raw;
        // If table code only gave us {tail:"REQ-400000123"} infer it
        if (!selected._wg_request_id && typeof selected.tail === 'string') {
          const m2 = selected.tail.match(/^REQ-(\d+)$/i);
          if (m2) selected._wg_request_id = Number(m2[1]);
        }
      }
      const res = await this.wgPlanePin(
        planeId,
        selected || null,
        this.sessionId,
        this.playerId
      );
      return res;
    },

    // =============================================================================
    // Realtime: Server-Sent Events wiring
    // =============================================================================

    connectEvents(opts) {
      opts = opts || {};
      const sessionId = opts.sessionId != null ? opts.sessionId : this.sessionId;
      const topics = Array.isArray(opts.topics) && opts.topics.length ? opts.topics : KNOWN_TOPICS;

      // If already connected with same filters, do nothing
      if (this._es && this._es.readyState !== 2 /* CLOSED */) {
        return this._es;
      }

      const url = `${this.base}/api/wargame/events${_qs({
        session_id: sessionId,
        topics: topics.join(",")
      })}`;

      const es = new EventSource(url); // cookies sent same-origin by default
      this._es = es;

      // Install per-topic listeners (so MessageEvent.type === topic)
      // Each forwards to local wildcard dispatcher via _emit(...)
      const install = (topic) => {
        if (this._topicListeners.has(topic)) return;
        const cb = (ev) => {
          let data = {};
          try { data = ev && ev.data ? JSON.parse(ev.data) : {}; } catch { /* noop */ }
          this._emit(topic, data);
        };
        this._topicListeners.set(topic, cb);
        es.addEventListener(topic, cb);
      };
      topics.forEach(install);

      // Optional hooks
      if (typeof opts.onOpen === "function") {
        es.addEventListener("open", opts.onOpen, { once: true });
      }
      if (typeof opts.onError === "function") {
        es.addEventListener("error", opts.onError);
      }

      return es;
    },

    disconnectEvents() {
      if (this._es) {
        try {
          // Remove listeners to avoid leaks
          for (const [topic, cb] of this._topicListeners.entries()) {
            try { this._es.removeEventListener(topic, cb); } catch {}
          }
          this._topicListeners.clear();
          this._es.close();
        } catch {}
        this._es = null;
      }
    },

    onEvent(pattern, handler) {
      if (typeof pattern !== "string") throw new Error("pattern must be a string");
      if (typeof handler !== "function") throw new Error("handler must be a function");
      const re = _patternToRe(pattern);
      this._handlers.push({ pattern, re, fn: handler });
      return () => this.offEvent(handler); // unsubscribe convenience
    },

    onceEvent(pattern, handler) {
      const off = this.onEvent(pattern, (...args) => {
        try { handler(...args); } finally { off(); }
      });
      return off;
    },

    offEvent(handlerOrPattern) {
      if (!handlerOrPattern) {
        this._handlers = [];
        return;
      }
      if (typeof handlerOrPattern === "function") {
        this._handlers = this._handlers.filter(h => h.fn !== handlerOrPattern);
      } else if (typeof handlerOrPattern === "string") {
        this._handlers = this._handlers.filter(h => h.pattern !== handlerOrPattern);
      }
    },

    _emit(topic, data) {
      // Dispatch to wildcard handlers
      const ev = { topic, data };
      for (const h of this._handlers) {
        try {
          if (h.re.test(topic)) h.fn(ev);
        } catch (e) {
          // Don't break the fanout if one handler throws
          (console && console.warn && console.warn("WGNet.onEvent handler error:", e)) || void 0;
        }
      }
    },
  };

  // ---- Request<->Flight surrogate mapping (client-only) --------------------
  // We represent a cargo request in UIs that still expect "flights" by minting
  // a large, obviously synthetic flight_id. Server never sees this number.
  const REQ_OFFSET = 400000000; // keep >= 1e8 to avoid collisions with real flight ids
  function _isReqSurrogate(id) {
    const n = Number(id);
    return Number.isFinite(n) && n >= REQ_OFFSET;
  }
  function _reqIdFromSurrogate(id) {
    return Number(id) - REQ_OFFSET;
  }
  function _surrogateFromReqId(rid) {
    return REQ_OFFSET + Number(rid);
  }

  function _reqsToFlightish(reqs) {
    const list = Array.isArray(reqs) ? reqs : [];
    return list.map(r => {
      const rid = Number(r.id);
      const lines = Array.isArray(r.lines) ? r.lines : [];
      // compute total weight if not provided
      let w = Number(r.requested_weight || 0);
      if (!w) {
        for (const ln of lines) {
          const ulb = Number((ln.unit_lb ?? ln.size_lb) || 0) || 0;
          const qty = Number(ln.qty || 0) || 0;
          w += ulb * qty;
        }
      }
      // Let older UI detect that "outbound flights" actually shows cargo requests
      try { window.WG_OUTBOUND_IS_REQUESTS = true; } catch {}
      return {
        // Synthetic flight-ish row
        id: _surrogateFromReqId(rid),
        tail_number: "",                    // no tail for a request
        airfield_takeoff: "",               // not applicable
        airfield_landing: String(r.destination || ""),
        pilot: "",
        pax: 0,
        eta: null,
        cargo_type: "Mixed",
        cargo_weight: Math.round(w),
        has_manifest: true,
        complete: false,
        // Carry-through for consumers that learn about the surrogate:
        _wg_is_request: true,
        _wg_request_id: rid,
        _wg_lines: lines
      };
    });
  }

  // ---- Normalizers ----------------------------------------------------------
  function _normalizeFlights(rows) {
    const list = Array.isArray(rows) ? rows : [];
    return list.map(it => ({
      id: Number(it.id),
      tail_number: String(it.tail_number || ''),
      airfield_takeoff: String(it.airfield_takeoff || ''),
      airfield_landing: String(it.airfield_landing || ''),
      pilot: String(it.pilot || ''),
      pax: Number(it.pax || 0),
      eta: it.eta || null,
      cargo_type: it.cargo_type ?? null,
      cargo_weight: Number(it.cargo_weight || 0) || 0,
      has_manifest: !!it.has_manifest,
      complete: !!it.complete
    }));
  }

  function _normalizeFlight(row) {
    const it = row || {};
    return {
      id: Number(it.id),
      tail_number: String(it.tail_number || ''),
      airfield_takeoff: String(it.airfield_takeoff || ''),
      airfield_landing: String(it.airfield_landing || ''),
      pilot: String(it.pilot || ''),
      pax: Number(it.pax || 0),
      eta: it.eta || null,
      takeoff_time: it.takeoff_time || null,
      cargo_type: it.cargo_type ?? null,
      cargo_weight: Number(it.cargo_weight || 0) || 0,
      has_manifest: !!it.has_manifest,
      complete: !!it.complete
    };
  }

  function _normalizeManifest(res) {
    const lines = Array.isArray(res && res.lines) ? res.lines : [];
    return {
      // Accept BOTH old shape ({name,size_lb,qty}) and new normalized
      // shape ({display_name,unit_lb,size,qty}).
      lines: lines.map(ln => {
        const name =
          (typeof ln.display_name === "string" && ln.display_name.length > 0)
            ? ln.display_name
            : (ln.name || "");
        const size_lb = Number(
          (Number.isFinite(ln.unit_lb) ? ln.unit_lb : ln.size_lb) || 0
        ) || 0;
        const qty = Number(ln.qty || 0) || 0;
        const notes = ln.notes != null ? String(ln.notes) : null;
        // keep 'size' if provided by server (harmless extra for UIs that want it)
        const size = ln.size ? String(ln.size).toUpperCase() : null;
        return {
          name: String(name || ""),
          size_lb,
          qty,
          notes,
          ...(size ? { size } : {})
        };
      })
    };
  }

  // ---- Legacy helpers kept intact (inbound & per-flight reads) --------------
  Net.fetchInboundFlights = async function () {
    const data = await Net._get(`/api/wargame/inbound_flights`);
    const rows = (data && data.flights) || [];
    return _normalizeFlights(rows);
  };

  Net.fetchFlight = async function (flightId) {
    const data = await Net._get(`/api/wargame/flight/${flightId}`);
    const row = data && data.flight;
    return _normalizeFlight(row);
  };

  Net.fetchManifest = async function (flightId) {
    // If this is a request-surrogate id, synthesize a manifest from the request lines.
    if (_isReqSurrogate(flightId)) {
      try {
        const rid = _reqIdFromSurrogate(flightId);
        // Prefer single-request endpoint; fall back to list scan.
        let data;
        try {
          data = await Net._get(`/api/wargame/request/${rid}/manifest`);
        } catch {
          const all = await Net._get(`/api/wargame/requests`);
          const hit = (all.requests || []).find(r => Number(r.id) === Number(rid));
          data = { lines: hit ? hit.lines || [] : [] };
        }
        return _normalizeManifest(data);
      } catch (e) {
        throw new Net.ApiError("request_manifest_error", "Failed to derive request manifest", { cause: String(e) }, null);
      }
    }
    // Real flight id → server manifest
    const data = await Net._get(`/api/wargame/manifest/${flightId}`);
    return _normalizeManifest(data);
  };

  // Export
  Net.ApiError = ApiError;
  Net.parseError = function (e) {
    if (!e) return { code: "unknown", message: "Unknown error", data: null, status: null };
    if (e.isApiError) return { code: e.code || "http_error", message: e.message || "", data: e.data || null, status: e.status || null };
    // Heuristic fallback for plain Error with a JSON-like message
    const m = String(e.message || "").trim();
    try {
      const maybe = JSON.parse(m);
      if (maybe && (maybe.code || maybe.error)) {
        return { code: maybe.code || maybe.error, message: maybe.message || m, data: maybe, status: null };
      }
    } catch {}
    return { code: "unknown", message: m || "Unknown error", data: null, status: null };
  };

  // Small helpers UIs can use without importing more code
  Net.wgGetCachedPin = function (plane_id) {
    const pid = _canonPlaneId(plane_id) || _canonPlaneId(String(plane_id)) || String(plane_id || "");
    return this._pins.get(pid) || null;
  };
  Net.outboundIsRequests = function () {
    try { return !!window.WG_OUTBOUND_IS_REQUESTS; } catch (_) { return false; }
  };
  // Expose offset so page shims (and templates) can stay in sync
  Net.REQ_OFFSET = REQ_OFFSET;
  // Handy for console diagnostics
  Net.canonPlaneId = _canonPlaneId;
  window.WGNet = Net;
})();
