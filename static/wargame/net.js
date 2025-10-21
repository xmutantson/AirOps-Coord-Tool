// static/wargame/net.js
(function () {
  const Net = {
    sessionId: 1,
    playerId: null,
    base: "",
    _lastPosSentAt: 0,
    _lastPos: { x: NaN, y: NaN, dir: "" },

    init(opts) {
      opts = opts || {};
      this.sessionId = opts.sessionId || 1;
      this.base = opts.base || "";
      return this;
    },

    async _get(path) {
      const url = `${this.base}${path}`;
      const res = await fetch(url, { credentials: "same-origin" });
      if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
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
      if (!res.ok) throw new Error(`POST ${path} → ${res.status}`);
      return res.json();
    },

    // ---- Read-only adapters ----
    getStockpile() { return this._get(`/api/wargame/stockpile`); },
    getTrucks()    { return this._get(`/api/wargame/trucks`); },
    getQueues()    { return this._get(`/api/wargame/queues`); },

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
  };

  window.WGNet = Net;
})();
