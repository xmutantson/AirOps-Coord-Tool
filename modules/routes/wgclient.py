# modules/routes/wgclient.py
# Multiplayer event hub for Wargame (SSE-based)
#
# Exposes:
#   - GET  /api/wargame/events        (Server-Sent Events stream)
#        Query params:
#          session_id: int (default 1)
#          topics: comma-separated list (e.g. wg:plane_pin,wg:plane_status); empty = all
#        Headers honored:
#          Last-Event-ID: <int> (resume from last seen id, if buffered)
#
#   - broadcast(topic, payload, *, session_id: int|None = None) -> dict
#       Publish a real-time event to all subscribers (optionally scoped to a session_id).
#
#   - Convenience notifiers (optional wrappers):
#       notify_plane_pin(plane_id, pin, *, session_id)
#       notify_plane_unselect(plane_id, *, session_id)
#       notify_plane_status(plane_id, status, required, cart_id=None, diff=None, *, session_id)
#       notify_plane_loaded(plane_id, loaded_manifest, *, session_id)
#       notify_plane_paperwork_complete(plane_id, *, session_id)
#
# Notes:
#   • Keep messages tiny, JSON serializable.
#   • Call broadcast/notify *inside* the wargame_api LOCK, after mutating state.
#   • Works behind common reverse proxies; emits periodic heartbeats to avoid idle timeouts.

from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Generator, Iterable, Optional, Set, Tuple

from flask import Blueprint, Response, render_template, request, session, stream_with_context

try:
    from flask_login import current_user  # optional
except Exception:  # pragma: no cover
    current_user = None  # type: ignore

bp = Blueprint("wgclient", __name__)

# ──────────────────────────────────────────────────────────────────────────────
# Display name helper (kept from the original file)
# ──────────────────────────────────────────────────────────────────────────────

def _display_name() -> str:
    """
    Pick a friendly display name from session or flask_login current_user.
    Falls back to 'Guest'.
    """
    for key in ("display_name", "name", "username", "user"):
        val = session.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    try:
        if current_user and getattr(current_user, "is_authenticated", False):
            for attr in ("display_name", "name", "username", "email"):
                val = getattr(current_user, attr, None)
                if isinstance(val, str) and val.strip():
                    return val.strip()
    except Exception:
        pass
    return "Guest"

@bp.get("/wargame/play")
def wargame_play():
    player_name = _display_name()
    return render_template("wargame_play.html", player_name=player_name, active="wargame_play")

# ──────────────────────────────────────────────────────────────────────────────
# SSE Hub
# ──────────────────────────────────────────────────────────────────────────────

HEARTBEAT_SEC = float((__import__("os").getenv("WG_SSE_HEARTBEAT_SEC") or "20"))
BUFFER_MAX = int((__import__("os").getenv("WG_SSE_BUFFER_MAX") or "1000"))
SUB_QUEUE_MAX = int((__import__("os").getenv("WG_SSE_SUB_QUEUE_MAX") or "256"))

def _now_ts_iso() -> str:
    # UTC ISO-8601 with Z
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

@dataclass(eq=False)  # hash by identity so instances can live in a set()
class _Event:
    id: int
    topic: str
    data: Dict[str, Any]
    session_id: Optional[int] = None
    ts: str = field(default_factory=_now_ts_iso)

@dataclass(eq=False)  # hash by identity so instances can live in a set()
class _Subscriber:
    topics: Optional[Set[str]]  # None => subscribe to all topics
    session_id: Optional[int]   # None => global stream; else only that session_id
    queue: Deque[_Event] = field(default_factory=lambda: deque(maxlen=SUB_QUEUE_MAX))
    alive: bool = True

    def accepts(self, ev: _Event) -> bool:
        if (self.session_id is not None) and (ev.session_id != self.session_id):
            return False
        if (self.topics is not None) and (ev.topic not in self.topics):
            return False
        return True

class _Hub:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._subs: Set[_Subscriber] = set()
        self._next_id: int = 1
        self._buffer: Deque[_Event] = deque(maxlen=BUFFER_MAX)  # global ring buffer for resumable delivery

    # ---- publish / subscribe -------------------------------------------------

    def publish(self, topic: str, data: Dict[str, Any], *, session_id: Optional[int] = None) -> Dict[str, Any]:
        with self._lock:
            ev = _Event(id=self._next_id, topic=topic, data=data, session_id=session_id)
            self._next_id += 1
            self._buffer.append(ev)
            # Fan-out to all matching subscribers; prune any that died
            dead: list[_Subscriber] = []
            for sub in list(self._subs):
                if not sub.alive:
                    dead.append(sub)
                    continue
                if sub.accepts(ev):
                    # append non-blocking (deque drops oldest if full)
                    sub.queue.append(ev)
            # Remove dead subs after iteration
            for sub in dead:
                try:
                    self._subs.discard(sub)
                except Exception:
                    pass
            return {"id": ev.id, "topic": ev.topic, "session_id": ev.session_id, "ts": ev.ts}

    def subscribe(self, *, topics: Optional[Iterable[str]], session_id: Optional[int], last_id: Optional[int]) -> _Subscriber:
        tset = None if topics is None else {t.strip() for t in topics if t and t.strip()}
        sub = _Subscriber(topics=tset, session_id=session_id)
        with self._lock:
            # Seed with backlog if Last-Event-ID provided
            if last_id is not None:
                for ev in self._buffer:
                    if ev.id > last_id and sub.accepts(ev):
                        sub.queue.append(ev)
            self._subs.add(sub)
        return sub

    def unsubscribe(self, sub: _Subscriber) -> None:
        with self._lock:
            sub.alive = False
            self._subs.discard(sub)

    # ---- stream generator ----------------------------------------------------

    def sse_stream(self, sub: _Subscriber) -> Generator[bytes, None, None]:
        """
        Stream events to the client with periodic heartbeats.
        """
        try:
            # Advise the browser to retry quickly on disconnects (milliseconds)
            # This is an SSE control line, not HTTP header.
            yield b"retry: 2000\n\n"
            hb_deadline = time.time() + HEARTBEAT_SEC
            while sub.alive:
                # drain queued events
                while sub.queue:
                    ev = sub.queue.popleft()
                    # Build SSE frame: id, event (topic), data (JSON), time
                    payload = dict(ev.data)
                    # auto-include a timestamp if caller didn't put one
                    payload.setdefault("ts", ev.ts)
                    # ensure bytes
                    data_str = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
                    frame = f"id: {ev.id}\nevent: {ev.topic}\ndata: {data_str}\n\n"
                    yield frame.encode("utf-8")
                    hb_deadline = time.time() + HEARTBEAT_SEC

                # heartbeat to keep proxies/load-balancers happy
                now = time.time()
                if now >= hb_deadline:
                    yield b": ping\n\n"  # SSE comment heartbeat
                    hb_deadline = now + HEARTBEAT_SEC

                # tiny sleep to avoid hot loop; also lets Flask flush
                time.sleep(0.1)
        finally:
            self.unsubscribe(sub)

HUB = _Hub()

# ──────────────────────────────────────────────────────────────────────────────
# Public API (import these from other modules)
# ──────────────────────────────────────────────────────────────────────────────

def broadcast(topic: str, payload: Dict[str, Any], *, session_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Publish a raw event to all connected clients. Returns a small metadata dict.
    Typical usage from wargame_api.py (inside LOCK, after state mutation):
        broadcast("wg:plane_pin", {"plane_id": plane_id, "pin": pin}, session_id=session_id)
    """
    try:
        return HUB.publish(topic, payload, session_id=session_id)
    except Exception:
        # Never let telemetry/broadcasting break the main flow
        return {"id": -1, "topic": topic, "session_id": session_id, "ts": _now_ts_iso()}

# Convenience wrappers (pure sugar); use if you like consistency at callsites.
def notify_plane_pin(plane_id: str, pin: Dict[str, Any], *, session_id: int) -> Dict[str, Any]:
    return broadcast("wg:plane_pin", {"plane_id": plane_id, "pin": pin}, session_id=session_id)

def notify_plane_unselect(plane_id: str, *, session_id: int) -> Dict[str, Any]:
    return broadcast("wg:plane_unselect", {"plane_id": plane_id}, session_id=session_id)

def notify_plane_status(
    plane_id: str,
    status: str,
    required: Any,
    cart_id: Optional[str] = None,
    diff: Optional[Dict[str, Any]] = None,
    *,
    session_id: int,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"plane_id": plane_id, "pin": {"status": status, "required": required}}
    if cart_id is not None:
        payload["pin"]["cart_id"] = cart_id
    if diff is not None:
        payload["pin"]["diff"] = diff
    return broadcast("wg:plane_status", payload, session_id=session_id)

def notify_plane_loaded(plane_id: str, loaded_manifest: Any, *, session_id: int) -> Dict[str, Any]:
    return broadcast("wg:plane_loaded", {"plane_id": plane_id, "loaded_manifest": loaded_manifest}, session_id=session_id)

def notify_plane_paperwork_complete(plane_id: str, *, session_id: int) -> Dict[str, Any]:
    return broadcast("wg:plane_paperwork_complete", {"plane_id": plane_id}, session_id=session_id)

# ──────────────────────────────────────────────────────────────────────────────
# SSE endpoint
# ──────────────────────────────────────────────────────────────────────────────

@bp.get("/api/wargame/events")
def sse_events():
    """
    Server-Sent Events stream for Wargame updates.

    Query params:
      - session_id: int (default 1)
      - topics: comma-separated list (e.g. "wg:plane_pin,wg:plane_status"); empty → all

    Resume:
      - Provide Last-Event-ID header (or ?last_event_id=) to replay buffered events > id.
    """
    # Parse filters
    try:
        session_id = int(request.args.get("session_id") or "1")
    except Exception:
        session_id = 1

    topics_raw = (request.args.get("topics") or "").strip()
    topics: Optional[Iterable[str]] = None
    if topics_raw:
        topics = [t.strip() for t in topics_raw.split(",") if t.strip()]

    # Resume support via Last-Event-ID or query
    last_id: Optional[int] = None
    hdr_last_id = (request.headers.get("Last-Event-ID") or "").strip()
    qry_last_id = (request.args.get("last_event_id") or "").strip()
    try:
        if hdr_last_id:
            last_id = int(hdr_last_id)
        elif qry_last_id:
            last_id = int(qry_last_id)
    except Exception:
        last_id = None

    sub = HUB.subscribe(topics=topics, session_id=session_id, last_id=last_id)

    resp = Response(
        stream_with_context(HUB.sse_stream(sub)),
        mimetype="text/event-stream",
    )
    # Standard SSE / proxy-safe headers
    resp.headers["Cache-Control"] = "no-cache, no-transform"
    # Nginx specific: disable proxy buffering for this route if present
    resp.headers["X-Accel-Buffering"] = "no"
    return resp

# ──────────────────────────────────────────────────────────────────────────────
# (Optional) simple health/ping endpoint (useful for ALB/LB health checks)
# ──────────────────────────────────────────────────────────────────────────────

@bp.get("/api/wargame/events/ping")
def sse_ping():
    return {"ok": True, "ts": _now_ts_iso(), "next_id": getattr(HUB, "_next_id", 0)}
