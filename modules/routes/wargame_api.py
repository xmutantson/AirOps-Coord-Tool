# modules/routes/wargame_api.py
from __future__ import annotations
from flask import Blueprint, jsonify, request, g, current_app
from flask import Response
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timezone
import re as _re
import threading
import time
import sqlite3
import os
import math
from modules.utils.common import get_preference  # for tunable delivery truck pose
from modules.utils.common import iso8601_ceil_utc
from modules.utils.common import _parse_manifest as _common_parse_manifest
try:
    # Preferred size classifier used elsewhere in the app
    from modules.services.wargame import size_class_for as _size_for
    # Optional telemetry builder (no-append centralizer)
    from modules.services.wargame import add_claim as _make_claim
except Exception:
    # Conservative fallback thresholds
    def _size_for(w: float) -> str:
        try:
            w = float(w)
        except Exception:
            w = 0.0
        return "S" if w < 5 else "M" if w < 20 else "L" if w < 50 else "XL"
    def _make_claim(event: str, **fields):
        d = {"event": event}
        d.update(fields)
        return d

# --- lightweight DB helpers --------------------------------------------------
try:
    from app import DB_FILE
except Exception:
    # Test fixture /app/data/app.db is not used in-prod; default to the real DB.
    DB_FILE = os.getenv("DB_FILE", "/app/data/aircraft_ops.db")

bp = Blueprint("wargame_api", __name__)  # concrete paths below (no url_prefix)
LOCK = threading.RLock()

def _log_info(msg: str, **fields) -> None:
    """Best-effort structured logging without hard-failing if logger missing."""
    try:
        if current_app and current_app.logger:
            if fields:
                current_app.logger.info("%s | %s", msg, ", ".join(f"{k}={v}" for k,v in fields.items()))
            else:
                current_app.logger.info("%s", msg)
    except Exception:
        pass

def _has_column(conn: sqlite3.Connection, table: str, col: str) -> bool:
    """SQLite PRAGMA-based column presence check."""
    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        return any((row["name"] or "").lower() == col.lower() for row in cur.fetchall())
    except Exception:
        return False

def _first_present_key(row: sqlite3.Row, names: list[str], default=None):
    """
    Return row[name] for the first name that exists in row.keys() and is not None/''.
    """
    try:
        keys = set(row.keys())
        for n in names:
            if n in keys and row[n] is not None and row[n] != "":
                return row[n]
    except Exception:
        pass
    return default

def _iso_or_raw(t):
    """
    Ensure datetimes serialize as UTC ISO-8601 with 'Z'. Leave strings/None as-is.
    """
    if isinstance(t, datetime):
        try:
            return t.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            return t.isoformat()
    return t

# --- Tunables ---------------------------------------------------------------
CLAIMS_MAX = int(os.getenv("WGAPI_CLAIMS_MAX", "4000"))
STALE_SEC  = 15.0
VALID_SIZES = ("S", "M", "L", "XL")

# Which inbound truck index is the Delivery truck (0 or 1). Env overrideable.
DELIVERY_TRUCK_INDEX = int(os.getenv("WG_DELIVERY_TRUCK_INDEX", "0"))
# How long to hide (soft-despawn) an empty truck in the API. 0 → never hide.
EMPTY_TRUCK_HIDE_SEC = float(os.getenv("WG_EMPTY_TRUCK_HIDE_SEC", "0"))

# --- Error taxonomy (string codes → human-ish messages) ----------------------
# Keep codes stable; clients can branch on these.
ERRORS: Dict[str, str] = {
    "no_selection":       "No outbound flight is pinned for this plane.",
    "not_ready":          "Cart does not exactly match required lines.",
    "line_not_found":     "Requested line not found.",
    "bad_qty":            "Quantity invalid.",
    "insufficient_cart":  "Not enough items in the cart.",
    "held_mismatch":      "Held bundle does not match target.",
    "not_holding":        "Player is not holding a bundle.",
    "already_pinned":     "Plane is already pinned.",
    "missing_manifest":   "No manifest/required cargo found for this flight.",
    "bad_request_ref":    "Request id is required (pin by request).",
    "mismatch":           "Cart and required manifest do not match.",
}

# --- Manifest parsing adapter -----------------------------------------------
def parse_adv_manifest(text: str) -> list[dict]:
    """
    Parse freeform remarks text into canonical manifest lines:
      [{'display_name': str, 'unit_lb': float, 'size': 'S|M|L|XL', 'qty': int}, ...]
    Uses modules.utils.common._parse_manifest (name/size_lb/qty), then maps size via size_class_for.
    Now more tolerant of inputs like 'water 20 lbx3' and 'lbs'.
    """
    if not text:
        return []

    # ── Pre-normalize common human formats: 'lbx3'/'lbs' → 'lb x3'
    try:
        t = str(text)
        # '20 lbx3' → '20 lb x3'
        t = _re.sub(r'(?i)\blbx(?=\d)', 'lb x', t)
        # 'lbs' → 'lb'
        t = _re.sub(r'(?i)\blbs\b', 'lb', t)
        # collapse weird whitespace
        t = _re.sub(r'\s+', ' ', t).strip()
    except Exception:
        t = text

    # Primary parser
    try:
        raw = _common_parse_manifest(t) or []
    except Exception:
        raw = []

    # Fallback: quick regex per clause (handles "name 20 lb x3")
    if not raw:
        raw = []
        for part in _re.split(r'[;\n]+', t):
            m = _re.search(
                r'^\s*(?P<name>.+?)\s+'
                r'(?P<unit>\d+(?:\.\d+)?)\s*lb\s*(?:[x×]\s*(?P<qty>\d+))?\s*$',
                part, flags=_re.I
            )
            if not m:
                continue
            name = (m.group('name') or '').strip()
            try: unit = float(m.group('unit') or 0.0)
            except Exception: unit = 0.0
            try: qty  = int(m.group('qty') or 1)
            except Exception: qty  = 1
            if name and qty > 0:
                raw.append({'name': name, 'size_lb': unit, 'qty': qty})
    out: list[dict] = []
    for it in raw:
        name = (it.get("name") or "").strip()
        try: unit = float(it.get("size_lb") or 0.0)
        except Exception: unit = 0.0
        try: qty = int(it.get("qty") or 0)
        except Exception: qty = 0
        if not name or qty <= 0:
            continue
        out.append({"display_name": name, "unit_lb": unit, "size": _size_for(unit), "qty": qty})
    return out

# Anchor points (px) used to decide which inbound truck is 'delivery' vs 'retrieval'.
# Defaults to your requested coordinates; overridable via preferences.
def _anchor_xy(prefix: str, dx: int, dy: int) -> tuple[int,int]:
    try:
        x = get_preference(f"wargame_{prefix}_anchor_x")
        y = get_preference(f"wargame_{prefix}_anchor_y")
        xi = int(x) if x not in (None,"") else dx
        yi = int(y) if y not in (None,"") else dy
        return xi, yi
    except Exception:
        return dx, dy

DELIVERY_ANCHOR_X, DELIVERY_ANCHOR_Y = _anchor_xy("delivery", 1276, 427)
OUTBOUND_ANCHOR_X, OUTBOUND_ANCHOR_Y = _anchor_xy("outbound", 1276, 657)

def _dist2(p: dict, x: int, y: int) -> float:
    try:
        px = float((p or {}).get("x", 0))
        py = float((p or {}).get("y", 0))
        dx = px - float(x); dy = py - float(y)
        return dx*dx + dy*dy
    except Exception:
        return 1e12

# --- sqlite utilities (no SQLAlchemy required) -------------------------------
def _connect_sqlite():
    c = sqlite3.connect(DB_FILE)
    c.row_factory = sqlite3.Row
    return c

def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    try:
        cur = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND lower(name)=lower(?) LIMIT 1;", (name,))
        return cur.fetchone() is not None
    except Exception:
        return False

def _fetch_request_lines_db(conn: sqlite3.Connection, req_id: int) -> list[dict]:
    """
    Tolerant read of cargo_request_lines → [{'display_name','unit_lb','size','qty'}, ...]
    Accepts columns: (display_name|name|item), (unit_lb|size_lb|weight_per_unit), (size), (qty|quantity)
    """
    lines: list[dict] = []
    if not _table_exists(conn, "cargo_request_lines"):
        return lines
    cur = conn.execute("SELECT * FROM cargo_request_lines WHERE request_id = ?", (int(req_id),))
    for r in cur.fetchall():
        name = (
            r["display_name"] if "display_name" in r.keys()
            else r["name"] if "name" in r.keys()
            else (r["item"] if "item" in r.keys() else "")
        ) or ""
        unit = r["unit_lb"] if "unit_lb" in r.keys() else r["size_lb"] if "size_lb" in r.keys() else r["weight_per_unit"] if "weight_per_unit" in r.keys() else 0.0
        qty  = r["qty"] if "qty" in r.keys() else r["quantity"] if "quantity" in r.keys() else 0
        raw_size = r["size"] if "size" in r.keys() else None
        sz   = _norm_size(raw_size) or _size_for(unit)
        try: unit = float(unit)
        except Exception: unit = 0.0
        try: qty = int(qty)
        except Exception: qty = 0
        if name and qty > 0:
            lines.append({"display_name": str(name).strip(), "unit_lb": unit, "size": sz, "qty": qty})
    return lines

def _fetch_ramp_requests_db(conn: sqlite3.Connection) -> list[dict]:
    """
    Read open requests from wargame_ramp_requests.
    Supports two shapes:
      A) Aggregate-per-request (current schema): id, created_at, destination, requested_weight, manifest TEXT, satisfied_at?
         → parse 'manifest' into lines via parse_adv_manifest(...)
      B) Legacy line-granular rows (older experiments)
    Returns: [{'id','destination','created_at','lines':[{'display_name','unit_lb','size','qty'}],'requested_weight':float}]
    """
    out: list[dict] = []
    if not _table_exists(conn, "wargame_ramp_requests"):
        return out
    # Detect aggregate mode using presence of 'manifest' column
    try:
        pragma = list(conn.execute("PRAGMA table_info(wargame_ramp_requests)"))
        colnames = [r["name"] for r in pragma]
    except Exception:
        colnames = []
    aggregate_mode = ("manifest" in colnames)

    if aggregate_mode:
        has_satisfied = _has_column(conn, "wargame_ramp_requests", "satisfied_at")
        sql = "SELECT id, created_at, destination, requested_weight, manifest"
        if has_satisfied:
            sql += ", satisfied_at"
        sql += " FROM wargame_ramp_requests"
        if has_satisfied:
            sql += " WHERE COALESCE(satisfied_at,'') = ''"
        cur = conn.execute(sql)
        for r in cur.fetchall():
            rid     = int(r["id"])
            dest    = (r["destination"] or "").strip()
            created = r["created_at"]
            text    = (r["manifest"] or "").strip()
            try:
                lines = parse_adv_manifest(text) or []
            except Exception:
                lines = []
            # prefer DB requested_weight; else compute from lines
            try:
                total = float(r["requested_weight"] or 0.0)
            except Exception:
                total = 0.0
            if total <= 0.0 and lines:
                s = 0.0
                for ln in lines:
                    try:
                        s += float(ln.get("unit_lb") or 0.0) * int(ln.get("qty") or 0)
                    except Exception:
                        pass
                total = s
            out.append({
                "id": rid,
                "destination": dest,
                "created_at": created,
                "lines": lines,
                "requested_weight": float(total or 0.0),
            })
        try:
            out.sort(key=lambda r: (r.get("created_at") or "", int(r.get("id") or 0)))
        except Exception:
            pass
        return out

    # ---- Legacy line-granular fallback ---------------------------------------
    cur = conn.execute("SELECT * FROM wargame_ramp_requests")
    rows = cur.fetchall()
    if not rows:
        return out
    keys = rows[0].keys()
    def choose(candidates: list[str]) -> Optional[str]:
        for n in candidates:
            if n in keys:
                return n
        return None
    id_col      = choose(["request_id","group_id","ticket_id","batch_id","id"])
    dest_col    = choose(["destination","dest","dest_airport","airport_canon","airport","airfield_landing"])
    created_col = choose(["created_at","created","requested_at","timestamp","ts","created_on"])
    name_col    = choose(["display_name","name","item","sanitized_name"])
    unit_col    = choose(["unit_lb","size_lb","weight_per_unit","unit_weight_lb","weight_lb","unit_weight"])
    size_col    = choose(["size","bin","size_class"])
    qty_col     = choose(["qty","quantity","requested_qty","units","count"])
    status_col  = choose(["status","state"])
    complete_col= choose(["complete","fulfilled","is_complete"])
    closed_col  = choose(["closed_at","closed","completed_at","cancelled_at"])

    bucket: dict[int, dict] = {}
    for r in rows:
        rid = r[id_col] if id_col else None
        if rid is None or rid == "":
            rid = f"{_first_present_key(r,[dest_col],'')}-{_first_present_key(r,[created_col],'')}"
        try:
            rid_int = int(rid)
        except Exception:
            rid_int = abs(hash(str(rid))) % 2147483647

        is_open = True
        if status_col and r[status_col] is not None:
            try:
                is_open = str(r[status_col]).lower() in ("open","queued","pending","new","active")
            except Exception:
                is_open = True
        if complete_col and r[complete_col] is not None:
            try:
                is_open = is_open and (int(r[complete_col]) == 0)
            except Exception:
                pass
        if closed_col and r[closed_col]:
            is_open = False
        if not is_open:
            continue

        dest    = (_first_present_key(r, [dest_col], "") or "")
        created = _first_present_key(r, [created_col], None)
        dn  = (_first_present_key(r, [name_col], "") or "").strip()
        try: ulb = float(_first_present_key(r, [unit_col], 0.0) or 0.0)
        except Exception: ulb = 0.0
        raw_sz = _first_present_key(r, [size_col], None)
        sz  = _norm_size(raw_sz) or _size_for(ulb)
        try: q   = int(_first_present_key(r, [qty_col], 0) or 0)
        except Exception: q = 0

        ent = bucket.setdefault(rid_int, {"id": rid_int, "destination": dest, "created_at": created, "lines": []})
        if dn and q > 0:
            ent["lines"].append({"display_name": str(dn), "unit_lb": ulb, "size": sz, "qty": q})

    out = list(bucket.values())
    try:
        out.sort(key=lambda r: (r.get("created_at") or "", int(r.get("id") or 0)))
    except Exception:
        pass
    return out

def _fetch_open_cargo_requests_db(conn: sqlite3.Connection) -> list[dict]:
    """
    Returns [{'id', 'destination', 'created_at', 'lines':[...]}] for open/active requests.
    Open-ness is best-effort: status in ('open','queued') OR complete=0 OR closed_at IS NULL.
    """
    # 1) Prefer the ramp-flow table used by the Wargame UI
    if _table_exists(conn, "wargame_ramp_requests"):
        return _fetch_ramp_requests_db(conn)

    # 2) Legacy/aggregate models (kept for future compatibility)
    out: list[dict] = []
    if not _table_exists(conn, "cargo_requests"):
        return out
    # Pull all, then filter by whatever "open" signal exists.
    cur = conn.execute("SELECT * FROM cargo_requests")
    rows = cur.fetchall()
    for r in rows:
        # Determine PK & fields on the fly (cargo_requests schema varies)
        rid = None
        for k in ("id","request_id"):
            if k in r.keys():
                try: rid = int(r[k]); break
                except Exception: pass
        if rid is None:
            continue
        dest = _first_present_key(r, ["destination","dest","dest_airport","airport_canon","airport","airfield_landing"], "") or ""
        created = _first_present_key(r, ["created_at","created","created_on","ts","timestamp"], None)
        # heuristics for open:
        status = (r["status"] if "status" in r.keys() else "") or ""
        complete = int(r["complete"]) if "complete" in r.keys() and r["complete"] is not None else 0
        closed_at = r["closed_at"] if "closed_at" in r.keys() else None
        is_open = (status.lower() in ("open","queued")) or (complete == 0) or (closed_at in (None, ""))
        if not is_open:
            continue
        # Old model had a separate lines table; if it's missing we'll emit empty lines.
        lines = _fetch_request_lines_db(conn, rid)
        out.append({"id": rid, "destination": dest or "", "created_at": created, "lines": lines})
    return out

@bp.get("/api/wargame/events")
def api_wargame_events():
    """
    Minimal SSE heartbeat so the client EventSource has a valid stream.
    (Topics are ignored server-side for now; this just keeps the pipe open.)
    """
    def _stream():
        while True:
            yield "event: ping\\ndata: {}\\n\\n"
            time.sleep(15)
    # Add SSE-friendly headers so proxies don’t buffer/close the stream
    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return Response(_stream(), mimetype="text/event-stream", headers=headers)

def _guess_tasks_table(conn: sqlite3.Connection) -> str:
    # Prefer a table like "wargame_tasks" but fall back to the first that looks right
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND lower(name) LIKE 'wargame%task%';"
    )
    row = cur.fetchone()
    return row["name"] if row else "wargame_tasks"

def _key_to_flight_id(key: str) -> int | None:
    if not key:
        return None
    m = _re.match(r"^flight:(\d+)$", key.strip())
    return int(m.group(1)) if m else None

# --- Normalizers (plane_id / flight_ref) -------------------------------------
# Strict canonicalizer: only positive integers; no implicit remap to 0/alpha.
def _canon_plane_id_or_none(v) -> Optional[str]:
    s = str(v if v is not None else "").strip().lower()
    m = _re.match(r'^(?:plane[:#])?(\d+)$', s)
    return f"plane:{m.group(1)}" if m else None

# --- Normalizers (plane_id / flight_ref) -------------------------------------
def _canon_plane_id(v) -> str:
    """
    Accepts: 2 / "2" / "plane:2" / "plane#2" / "Plane:2"  → "plane:2"
    Falls back to "plane:0" on empty/None.
    """
    if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
        return f"plane:{int(v)}"
    s = str(v or "").strip()
    if not s:
        return "plane:0"
    m = _re.match(r"(?i)^(?:plane[:#])?(\w+)$", s)
    if m:
        token = m.group(1)
        if token.isdigit():
            return f"plane:{int(token)}"
        # already like plane:alpha -> ensure prefix
        return f"plane:{token}" if not s.lower().startswith("plane:") else s
    return s

def _normalize_flight_ref(payload: dict) -> dict:
    """
    Accepts a wide variety of inputs and returns one of:
      {"flight_id": N} | {"queue_id": N} | {"request_id": N} | {}
    Inputs tolerated:
      - payload["flight_ref"] as dict above
      - payload["flight_ref"] as "flight:12" / "queue:3" / "request:7"
      - payload["key"] as same strings (common in task UIs)
      - top-level payload["flight_id"] / ["queue_id"] / ["queued_flight_id"] / ["request_id"]
    """
    p = payload or {}
    fr = p.get("flight_ref") or {}
    # string forms: "flight:12", etc.
    if isinstance(fr, str):
        m = _re.match(r"(?i)^(flight|queue|request)[:#](\d+)$", fr.strip())
        if m:
            kind, n = m.group(1).lower(), int(m.group(2))
            return {"flight_id": n} if kind == "flight" else ({"queue_id": n} if kind == "queue" else {"request_id": n})
        fr = {}
    # top-level "key": "flight:12"
    if not fr and isinstance(p.get("key"), str):
        m = _re.match(r"(?i)^(flight|queue|request)[:#](\d+)$", p["key"].strip())
        if m:
            kind, n = m.group(1).lower(), int(m.group(2))
            return {"flight_id": n} if kind == "flight" else ({"queue_id": n} if kind == "queue" else {"request_id": n})
    # lift common top-level aliases
    for k in ("flight_id", "queue_id", "request_id", "queued_flight_id"):
        if k in p and p[k] is not None:
            return {"queue_id": int(p[k])} if k == "queued_flight_id" else {k: int(p[k])}
    return fr if isinstance(fr, dict) else {}

# --- In-memory state ----------------------------------------------------------
# Helpers to compute the Delivery truck pose from preferences (editable later)
def _pref_int(name: str, default: int) -> int:
    try:
        v = get_preference(name)
        return int(v) if v not in (None, "",) else default
    except Exception:
        return default

def _pref_str(name: str, default: str) -> str:
    try:
        v = get_preference(name)
        return (v or "").strip() or default
    except Exception:
        return default

def _delivery_truck_anchor_pose() -> dict:
    """
    Pose (pixels) for the Delivery truck. Defaults match prior layout; we can
    nudge later without code changes by setting these preferences:
      - wargame_delivery_truck_x
      - wargame_delivery_truck_y
      - wargame_delivery_truck_facing  (e.g., 'right' or 'left')
    """
    x = _pref_int("wargame_delivery_truck_x", DELIVERY_ANCHOR_X)
    y = _pref_int("wargame_delivery_truck_y", DELIVERY_ANCHOR_Y)
    facing = _pref_str("wargame_delivery_truck_facing", "right")
    return {"x": x, "y": y, "facing": facing}

def _mk_inbound_trucks():
    """
    Build the two inbound trucks with explicit roles. The Delivery truck
    gets the tunable anchor pose; the other keeps its legacy pose.
    """
    # Poses: align to your anchors by default (overridable via prefs above).
    # Use the full delivery pose helper so 'facing' and any x/y overrides apply.
    t0_pose = _delivery_truck_anchor_pose()
    # Allow a tunable facing for the outbound/retrieval truck too.
    t1_pose = {
        "x": OUTBOUND_ANCHOR_X,
        "y": OUTBOUND_ANCHOR_Y,
        "facing": _pref_str("wargame_outbound_truck_facing", "right"),
    }

    inbound = [
        {
            "truck_id": 0,
            "bay": "E1",
            "role": "", #assigned below
            "pose": t0_pose,
            "manifest": {"box": {"S": 0, "M": 0, "L": 0, "XL": 0}},
            "claims": {},
            "lines": [],
            "spawned": {},
            "empty_since": None,
        },
        {
            "truck_id": 1,
            "bay": "E2",
            "role": "", #assigned below
            "pose": t1_pose,
            "manifest": {"box": {"S": 0, "M": 0, "L": 0, "XL": 0}},
            "claims": {},
            "lines": [],
            "spawned": {},
            "empty_since": None,
        },
    ]

    # Assign roles by proximity to anchors (closest to delivery anchor = 'delivery')
    try:
        if len(inbound) >= 2:
            i0, i1 = inbound[0], inbound[1]
            d0 = _dist2(i0.get("pose", {}), DELIVERY_ANCHOR_X, DELIVERY_ANCHOR_Y)
            d1 = _dist2(i1.get("pose", {}), DELIVERY_ANCHOR_X, DELIVERY_ANCHOR_Y)
            if d0 <= d1:
                i0["role"], i1["role"] = "delivery", "retrieval"
            else:
                i0["role"], i1["role"] = "retrieval", "delivery"
        else:
            inbound[0]["role"] = "delivery"
    except Exception:
        inbound[0]["role"] = inbound[0].get("role") or "delivery"
        if len(inbound) > 1:
            inbound[1]["role"] = inbound[1].get("role") or "retrieval"
    return inbound

STATE = {
    # session_id -> {"players": {id: {...}}, "next_player_id": int, "next_claim_id": int}
    "sessions": {},
    "trucks_epoch": 0,   # bumped whenever trucks change so clients can refresh
    "adapters": {
        # Matches client-side default: +4 S, +5 M, +8 L, +10 XL for one generic SKU "box"
        "stockpile": {
            "updated_at": datetime.utcnow().isoformat() + "Z",
            # NEW: unique-item registry; keys = "{display_name}|{unit_lb}|{size}"
            "registry": {},
            # bins still exist, but reflect VARIETY counts per size (derived from registry)
            "bins": {
                "box": {"S": 0, "M": 0, "L": 0, "XL": 0},
            },
        },
        # Two inbound trucks with explicit roles; Delivery gets a tunable pose
        "trucks": {
            "inbound": _mk_inbound_trucks(),
            "outbound": [],
        },
        "queues": {"loads_waiting": 0, "requests": []},  # requests: [{id, lines:[{display_name,unit_lb,size,qty}], ...}]
        # Visual-only aircraft positions for completeness (same as original client)
        "planes": [
            {"id": 0, "plane_id": 0, "pose": {"x": 244, "y": 290, "facing": "right"}},  # 24+220, 450-160
            {"id": 1, "plane_id": 1, "pose": {"x": 244, "y": 610, "facing": "right"}},  # 24+220, 450+160
        ],
    },
    # session_id -> list of carts (with poses); matches client default
    "carts": {},
    # session_id -> ordered list of claim dicts
    "claims": {},
    "plane_pins": {},   # NEW: plane_id → pin state (see helpers below)
}

# --- Helpers -----------------------------------------------------------------
def _utc_iso():
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

def _touch_stockpile():
    STATE["adapters"]["stockpile"]["updated_at"] = _utc_iso()

def _seed_stockpile_from_inventory_if_empty() -> int:
    """
    One-time lazy pre-seed: mirror current Inventory into the in-memory
    stockpile so the Wargame starts with boxes matching pre-seeded items.
    Tries a couple of service entry points; no-ops if unavailable.
    """
    st = STATE["adapters"]["stockpile"]
    reg = st.setdefault("registry", {})
    if reg:  # already seeded/used
        return 0
    fetch = None
    try:
        from modules.services.inventory import get_wargame_seed_items as fetch  # preferred
    except Exception:
        try:
            from modules.services.inventory import get_inventory_summary as fetch  # fallback
        except Exception:
            fetch = None
    if not fetch:
        return 0
    try:
        items = fetch() or []
    except Exception:
        return 0

    # late import to avoid cycles and compute size from unit weight when needed
    try:
        from modules.services.wargame import size_class_for
    except Exception:
        size_class_for = lambda w: "M"

    def _coerce_item(it):
        """
        Accept dicts or tuples:
          tuple: (category_display_name, item_name, weight_lb, qty)
          dict:  expects keys ~ display_name/name/item, unit_lb/unit_weight_lb, size/bin, qty/quantity
        Returns (display_name, unit_lb, size(S/M/L/XL), qty) or None.
        """
        # tuple/list path
        if isinstance(it, (tuple, list)) and len(it) >= 4:
            _cat, name, ulb, qty = it[0], it[1], it[2], it[3]
            try: ulb = float(ulb)
            except Exception: ulb = 0.0
            try: qty = int(qty)
            except Exception: qty = 0
            size = size_class_for(ulb)
            return (str(name or "").strip(), ulb, size, qty)
        # dict path
        if isinstance(it, dict):
            dn  = (it.get("display_name") or it.get("name") or it.get("item") or "").strip()
            try: ulb = float(it.get("unit_lb") or it.get("unit_weight_lb") or 0.0)
            except Exception: ulb = 0.0
            raw_sz = (it.get("size") or it.get("bin") or None)
            size = (_norm_size(raw_sz) or size_class_for(ulb) or "M")
            try: qty = int(it.get("qty") or it.get("quantity") or 0)
            except Exception: qty = 0
            return (dn, ulb, size, qty)
        return None

    seeded = 0
    for it in items:
        meta = _coerce_item(it)
        if not meta:
            continue
        dn, ulb, sz, qty = meta
        if dn and qty > 0:
            _stockpile_add_unique(dn, ulb, sz, qty)
            seeded += 1
    return seeded

def _ensure_session(session_id: int):
    with LOCK:
        sess = STATE["sessions"].setdefault(
            session_id,
            {"players": {}, "next_player_id": 1, "next_claim_id": 1},
        )
        # Seed carts per session to mirror the client default layout:
        # cart:0 has 2× M at y=410; cart:1 empty at y=636 (≈ xl.h*5+16 below).
        carts = STATE["carts"].setdefault(session_id, [])
        if not carts:
            carts.extend([
                {
                    "id": "cart:0",
                    "capacity_lb": 600,
                    "contents": {"box": {"M": 2}},
                    "preview": [],
                    "pose": {"x": 544, "y": 410, "facing": "left"},  # 24+520, 450-40
                },
                {
                    "id": "cart:1",
                    "capacity_lb": 600,
                    "contents": {},
                    "preview": [],
                    "pose": {"x": 544, "y": 636, "facing": "left"},  # ~ (450-40)+(42*5+16)
                },
            ])
        STATE["claims"].setdefault(session_id, [])
        return sess

def _prune_stale_players(session_id: int):
    now = time.time()
    with LOCK:
        sess = _ensure_session(session_id)
        dead = [pid for pid, p in sess["players"].items() if now - float(p.get("last_seen", 0)) > STALE_SEC]
        for pid in dead:
            # Optional: auto-return any held bundle before removal
            p = sess["players"].get(pid)
            if p:
                _reap_player_held(session_id, p)
            sess["players"].pop(pid, None)

# --- truck epoch --------------------------------------------------------------
def _bump_trucks_epoch(delta: int = 1) -> None:
    try:
        STATE["trucks_epoch"] = int(STATE.get("trucks_epoch", 0)) + int(delta or 1)
    except Exception:
        STATE["trucks_epoch"] = 1

# size normalization: accept letters & human words
_SIZE_MAP = {
    "s":"S","small":"S",
    "m":"M","medium":"M",
    "l":"L","large":"L","lg":"L",
    "xl":"XL","x-l":"XL","xlarge":"XL","x-large":"XL","extra large":"XL","extra-large":"XL",
}
def _norm_size(s: str) -> str | None:
    if not s: return None
    s = str(s).strip().lower()
    return _SIZE_MAP.get(s, s.upper() if s.upper() in VALID_SIZES else None)

# --- Simple display-name normalization ---------------------------------------
# Collapse trivial variants: punctuation/spacing/case and naive plural 's'
def _name_norm(s: str) -> str:
    s = (s or "").strip().lower()
    # strip non-alnum
    s = _re.sub(r"[^a-z0-9]+", "", s)
    # naive singularize: antennas -> antenna (keep words ≥4 chars)
    if len(s) > 3 and s.endswith("s"):
        s = s[:-1]
    return s

def _manifest_get(manifest: dict, item_key: str, size: str) -> int:
    return int(((manifest.get(item_key) or {}).get(size) or 0))

def _manifest_add(manifest: dict, item_key: str, size: str, delta: int) -> bool:
    size = _norm_size(size) or ""
    if size not in VALID_SIZES:
        return False
    bins = manifest.setdefault(item_key, {s: 0 for s in VALID_SIZES})
    cur = int(bins.get(size) or 0)
    if delta < 0 and cur < -delta:
        return False
    bins[size] = cur + delta
    return True

def _stockpile_add(item_key: str, size: str, delta: int) -> bool:
    sp = STATE["adapters"]["stockpile"]["bins"]
    ok = _manifest_add(sp, item_key, size, delta)
    if ok:
        _touch_stockpile()
    return ok

# ── Unique-item stockpile helpers (variety, not quantity) ────────────────────
def _stockpile_key(display_name: str, unit_lb: float, size: str) -> str:
    size = _norm_size(size) or "M"
    try: u = float(unit_lb or 0.0)
    except Exception: u = 0.0
    # use normalized name so plural/case/punct variants collapse
    return f"{_name_norm(display_name)}|{u:.6f}|{size}"

def _stockpile_recount_bins() -> None:
    """Recompute bins.box per size from the unique-item registry (qty>0 only)."""
    st = STATE["adapters"]["stockpile"]
    reg = st.setdefault("registry", {})
    counts = {s: 0 for s in VALID_SIZES}
    for meta in reg.values():
        sz = _norm_size(meta.get("size")) or "M"
        # count only visible categories (qty > 0)
        if sz in counts and int(meta.get("qty") or 0) > 0:
            counts[sz] += 1
    bins = st.setdefault("bins", {}).setdefault("box", {})
    for s in VALID_SIZES:
        bins[s] = counts.get(s, 0)
    _touch_stockpile()

def _stockpile_register_unique(display_name: str, unit_lb: float, size: str) -> bool:
    """Compat: ensure presence with qty=1 (legacy call sites)."""
    return _stockpile_add_unique(display_name, unit_lb, size, 1)

def _stockpile_add_unique(display_name: str, unit_lb: float, size: str, qty: int) -> bool:
    """
    Merge/increment a unique item (name+unit+size) in the stockpile registry.
    Returns True if a new entry was created; False if merged into existing.
    """
    st = STATE["adapters"]["stockpile"]
    reg = st.setdefault("registry", {})
    key = _stockpile_key(display_name, unit_lb, size)
    q = max(0, int(qty or 0))
    if key in reg:
        reg[key]["qty"] = int(reg[key].get("qty") or 0) + q
        _stockpile_recount_bins()
        return False
    reg[key] = {
        "display_name": (display_name or "").strip(),
        "unit_lb": float(unit_lb or 0.0),
        "size": _norm_size(size) or "M",
        "qty": q,
        "created_at": iso8601_ceil_utc(),
    }
    _stockpile_recount_bins()
    return True

def _stockpile_remove_unique(display_name: str, unit_lb: float, size: str, qty: int) -> int:
    """
    Decrement qty from a unique item; delete when qty hits 0.
    Returns actual quantity removed.
    """
    st  = STATE["adapters"]["stockpile"]
    reg = st.setdefault("registry", {})
    key = _stockpile_key(display_name, unit_lb, size)
    ent = reg.get(key)
    if not ent:
        return 0
    have = int(ent.get("qty") or 0)
    take = min(have, max(0, int(qty or 0)))
    ent["qty"] = have - take
    if ent["qty"] <= 0:
        reg.pop(key, None)
    _stockpile_recount_bins()
    return take

def _is_delivery_truck(truck: dict) -> bool:
    try:
        return (truck or {}).get("role","").lower() == "delivery"
    except Exception:
        return False

def _line_key(display_name: str, unit_lb: float, size: str) -> str:
    """Key compatible with stockpile unique registry (name|unit|size)."""
    return _stockpile_key(display_name, unit_lb, size)

def _assign_to_requests(truck: dict, display_name: str, unit_lb: float, size: str, qty: int) -> None:
    """
    Greedily assign deposited outbound cargo to open requests in arrival order.
    Boxes remain on the truck until the ENTIRE request is satisfied; then they
    are despawned automatically.
    """
    q = max(0, int(qty or 0))
    if q <= 0:
        return
    queues = STATE["adapters"]["queues"]
    reqs = list(queues.get("requests") or [])
    if not reqs:
        return
    truck.setdefault("assignments", {})  # request_id -> {key -> qty}
    key = _line_key(display_name, unit_lb, size)
    for req in reqs:
        rid = req.get("id")
        lines = list(req.get("lines") or [])
        # Find matching line and its remaining shortfall
        for ln in lines:
            if ((ln.get("display_name") == display_name) and
                abs(float(ln.get("unit_lb") or 0.0) - float(unit_lb)) < 1e-6 and
                (ln.get("size") or "").upper() == (size or "").upper()):
                need = max(0, int(ln.get("qty") or 0))
                assigned = int((req.setdefault("assigned", {}).get(key) or 0))
                short = max(0, need - assigned)
                if short <= 0:
                    continue
                take = min(q, short)
                if take <= 0:
                    continue
                # Track on request
                req["assigned"][key] = assigned + take
                # Track on truck
                bucket = truck["assignments"].setdefault(rid, {})
                bucket[key] = int(bucket.get(key) or 0) + take
                q -= take
                if q <= 0:
                    break
        if q <= 0:
            break

def _request_fully_assigned(req: dict) -> bool:
    lines = list(req.get("lines") or [])
    assigned = req.get("assigned") or {}
    for ln in lines:
        key = _line_key(ln.get("display_name") or "", float(ln.get("unit_lb") or 0.0), ln.get("size") or "M")
        need = max(0, int(ln.get("qty") or 0))
        if int(assigned.get(key) or 0) < need:
            return False
    return True

def _despawn_for_request(truck: dict, req: dict) -> None:
    """
    Remove the cargo allocated to this request from the outbound truck (both
    manifest and lines), then drop the request from the queue.
    """
    rid = req.get("id")
    assigned_on_truck = (truck.get("assignments") or {}).get(rid) or {}
    if not assigned_on_truck:
        return
    # Reduce truck lines & manifest
    lines = truck.setdefault("lines", [])
    manifest = truck.setdefault("manifest", {"box": {s: 0 for s in VALID_SIZES}})
    # Build a quick index for matching lines
    def _matches(line, k):
        kk = _line_key(line.get("display_name") or "", float(line.get("unit_lb") or 0.0), line.get("size") or "M")
        return kk == k
    for key, take in assigned_on_truck.items():
        want = int(take or 0)
        if want <= 0:
            continue
        # find line
        i = 0
        while i < len(lines) and want > 0:
            ln = lines[i]
            if not _matches(ln, key):
                i += 1
                continue
            have = int(ln.get("qty") or 0)
            used = min(have, want)
            ln["qty"] = have - used
            # decrement manifest bin
            _manifest_add(manifest, "box", (ln.get("size") or "M"), -used)
            if ln["qty"] <= 0:
                lines.pop(i)
            else:
                i += 1
            want -= used
    # Clear assignment bucket for this request
    truck.setdefault("assignments", {}).pop(rid, None)
    # Remove the request from queue
    queues = STATE["adapters"]["queues"]
    queues["requests"] = [r for r in (queues.get("requests") or []) if r.get("id") != rid]
    _update_truck_empty_since(truck)
    _bump_trucks_epoch()

def _find_truck(carrier_index=None, carrier_uid=None):
    """Return (truck_dict, side) or (None, None). Accepts uid=int truck_id."""
    trucks = STATE["adapters"]["trucks"]
    # uid (truck_id) path first
    try:
        if carrier_uid is not None:
            uid_int = int(carrier_uid)
            for side in ("inbound", "outbound"):
                for t in trucks.get(side, []):
                    if int(t.get("truck_id", -1)) == uid_int:
                        return t, side
    except Exception:
        pass
    # index path
    try:
        if carrier_index is not None:
            idx = int(carrier_index)
            side = "inbound"
            arr = trucks.get(side, [])
            if 0 <= idx < len(arr):
                return arr[idx], side
    except Exception:
        pass
    return None, None

def _find_or_create_cart(session_id: int, cart_id):
    # normalize cart ids (accept 0 / "0" / "cart:0")
    if isinstance(cart_id, int) or (isinstance(cart_id, str) and cart_id.isdigit()):
        cart_id = f"cart:{int(cart_id)}"
    carts = STATE["carts"].setdefault(session_id, [])
    for c in carts:
        if c.get("id") == cart_id:
            c.setdefault("contents", {})
            c.setdefault("preview", [])
            return c
    c = {"id": cart_id, "capacity_lb": 600, "contents": {}, "preview": []}
    carts.append(c)
    return c

def _append_claim(session_id: int, entry: dict) -> dict:
    sess = _ensure_session(session_id)
    e = dict(entry)
    e["id"] = sess["next_claim_id"]
    # Ensure ts + created_at (keep both for backward compat; identical values)
    if "ts" in e and e["ts"]:
        ts = str(e["ts"])
    else:
        ts = _utc_iso()
        e["ts"] = ts
    e.setdefault("created_at", ts)
    sess["next_claim_id"] += 1
    claims = STATE["claims"].setdefault(session_id, [])
    claims.append(e)
    overflow = len(claims) - max(0, CLAIMS_MAX)
    if overflow > 0:
        STATE["claims"][session_id] = claims[overflow:]
    return e

# ── Plane-pin helpers (shared, concurrency-safe with LOCK) ───────────────────
def _plane_pin_get(plane_id: str) -> dict:
    """
    Get (and initialize if missing) the pin object for a plane.
    Shape:
      {
        "flight_ref": {"flight_id": int} or {"queue_id": int} or None,
        "pinned_by": int|None,
        "pinned_at": ISO8601|None,
        "status": "idle"|"pinned"|"ready"|"loaded"|"paperwork",
        "required": [ {display_name, unit_lb, size, qty}, ... ],
        "cart_id": "cart:<id>"|None,
        "loaded_manifest": [ ... ],
        "paperwork": {"url": str|None, "html_path": str|None, "pdf_path": str|None},
      }
    """
    with LOCK:
        pins = STATE.setdefault("plane_pins", {})
        pin = pins.get(plane_id)
        if not pin:
            pin = {
                "flight_ref": None,
                "pinned_by": None,
                "pinned_at": None,
                "status": "idle",
                "required": [],
                "cart_id": None,
                "loaded_manifest": [],
                "paperwork": {"url": None, "html_path": None, "pdf_path": None},
            }
            pins[plane_id] = pin
        return pin

def _plane_pin_clear(plane_id: str) -> None:
    """Reset a plane pin back to idle defaults."""
    with LOCK:
        pins = STATE.setdefault("plane_pins", {})
        pins[plane_id] = {
            "flight_ref": None,
            "pinned_by": None,
            "pinned_at": None,
            "status": "idle",
            "required": [],
            "cart_id": None,
            "loaded_manifest": [],
            "paperwork": {"url": None, "html_path": None, "pdf_path": None},
        }

def _plane_pin_clear_by_flight_ref(flight_ref: str) -> bool:
    """
    Find and clear any plane that has the given flight_ref.
    Returns True if a plane was found and cleared, False otherwise.
    """
    with LOCK:
        pins = STATE.setdefault("plane_pins", {})
        for plane_id, pin in pins.items():
            if pin.get("flight_ref") == flight_ref:
                _plane_pin_clear(plane_id)
                return True
        return False

def _cart_aggregate_lines(cart: dict) -> Dict[str, int]:
    """
    Aggregate a cart's lines into { key(name|unit|size) -> qty }.
    Non-fatal on malformed carts.
    """
    out: Dict[str, int] = {}
    try:
        for ln in list(cart.get("lines") or []):
            dn = (ln.get("display_name") or "").strip()
            try: ulb = float(ln.get("unit_lb") or 0.0)
            except Exception: ulb = 0.0
            sz  = _norm_size(ln.get("size") or "M") or "M"
            q   = int(ln.get("qty") or 0)
            if not dn or q <= 0:
                continue
            k = _line_key(dn, ulb, sz)
            out[k] = out.get(k, 0) + q
    except Exception:
        pass
    return out

def _plane_compute_required(flight_ref: dict) -> List[dict]:
    """
    Resolve required manifest lines for an outbound flight reference:
      1) queued_flights + flight_cargo (preferred when present)
      2) flights(id) with remarks text parsed via parse_adv_manifest(...)
      3) fallback returns []
    Normalizes to: {display_name:str, unit_lb:float, size:'S|M|L|XL', qty:int}
    Never raises; returns [] on errors/missing data.
    """
    # Normalize alternative shapes early (accept strings/keys/aliases) before bailing.
    fr = flight_ref
    if isinstance(fr, str):
        m = _re.match(r"(?i)^(flight|queue|request)[:#](\d+)$", fr.strip())
        if m:
            kind, n = m.group(1).lower(), int(m.group(2))
            fr = {"flight_id": n} if kind == "flight" else ({"queue_id": n} if kind == "queue" else {"request_id": n})
        else:
            fr = {}
    elif isinstance(fr, dict):
        # tolerate {'flight': 12} or {'queued_flight_id': 99}
        if "flight" in fr and fr["flight"] is not None and "flight_id" not in fr:
            try: fr["flight_id"] = int(fr["flight"])
            except Exception: pass
        if "queued_flight_id" in fr and fr["queued_flight_id"] is not None and "queue_id" not in fr:
            try: fr["queue_id"] = int(fr["queued_flight_id"])
            except Exception: pass
    else:
        fr = {}

    # Adopt normalized value and bail if nothing useful
    flight_ref = fr
    if not flight_ref:
        return []

    # --- Path R: in-memory cargo request queue (STATE["adapters"]["queues"]["requests"]) ---
    # Allow the client to pin a "request" instead of a DB flight by passing flight_ref = {"request_id": N}
    try:
        if "request_id" in flight_ref and flight_ref["request_id"] is not None:
            rid = int(flight_ref.get("request_id"))
            # a) Try in-memory queue first
            with LOCK:
                reqs = list(STATE["adapters"].get("queues", {}).get("requests", []))
            for r in reqs:
                try:
                    if int(r.get("id")) != rid:
                        continue
                except Exception:
                    continue
                out: List[dict] = []
                for ln in list(r.get("lines") or []):
                    dn = (ln.get("display_name") or ln.get("name") or "").strip()
                    try: ulb = float(ln.get("unit_lb") if "unit_lb" in ln else ln.get("size_lb") or 0.0)
                    except Exception: ulb = 0.0
                    try: q = int(ln.get("qty") or 0)
                    except Exception: q = 0
                    if not dn or q <= 0:
                        continue
                    sz = _norm_size(ln.get("size")) or _size_for(ulb)
                    out.append({"display_name": dn, "unit_lb": ulb, "size": sz, "qty": q})
                return out
            # b) DB fallback
            with _connect_sqlite() as c:
                # Prefer legacy line table if present
                lines = _fetch_request_lines_db(c, rid)
                if lines:
                    return [ln for ln in lines if int(ln.get("qty") or 0) > 0]
                # Otherwise read the aggregate ramp-requests row and parse its manifest
                try:
                    if _table_exists(c, "wargame_ramp_requests") and _has_column(c, "wargame_ramp_requests", "manifest"):
                        cur = c.execute(
                            "SELECT manifest FROM wargame_ramp_requests WHERE id = ?",
                            (rid,)
                        )
                        row = cur.fetchone()
                        if row:
                            text = (row["manifest"] or "").strip()
                            parsed = parse_adv_manifest(text) or []
                            if parsed:
                                return [ln for ln in parsed if int(ln.get("qty") or 0) > 0]
                except Exception:
                    pass
    except Exception:
        pass

    def _norm_line(name, unit, qty) -> Optional[dict]:
        dn = (name or "").strip()
        try: ulb = float(unit or 0.0)
        except Exception: ulb = 0.0
        try: q = int(qty or 0)
        except Exception: q = 0
        if not dn or q <= 0:
            return None
        sz = _size_for(ulb)
        return {"display_name": dn, "unit_lb": ulb, "size": sz, "qty": q}

    out: List[dict] = []
    try:
        with _connect_sqlite() as c:
            # --- Path A: queued flight with flight_cargo rows ----------------
            qid = flight_ref.get("queue_id")
            if qid is not None:
                # Try common join shapes
                # 1) flight_cargo has queue_id
                try:
                    cur = c.execute(
                        """
                        SELECT display_name, sanitized_name, unit_lb, weight_per_unit, qty, quantity, size
                        FROM flight_cargo
                        WHERE queue_id = ?
                        """,
                        (int(qid),),
                    )
                    for row in cur.fetchall():
                        name = row["display_name"] or row["sanitized_name"]
                        unit = row["unit_lb"] if "unit_lb" in row.keys() else row["weight_per_unit"]
                        qty  = row["qty"] if "qty" in row.keys() else row["quantity"]
                        ln = _norm_line(name, unit, qty)
                        if ln:
                            # trust DB size if present and valid; else recompute
                            rsz = _norm_size(row["size"]) if "size" in row.keys() else None
                            if rsz in VALID_SIZES:
                                ln["size"] = rsz
                            out.append(ln)
                except Exception:
                    pass
                if out:
                    return out
                # 2) flight_cargo keyed by queued_flight_id
                try:
                    cur = c.execute(
                        """
                        SELECT display_name, sanitized_name, unit_lb, weight_per_unit, qty, quantity, size
                        FROM flight_cargo
                        WHERE queued_flight_id = ?
                        """,
                        (int(qid),),
                    )
                    for row in cur.fetchall():
                        name = row["display_name"] or row["sanitized_name"]
                        unit = row["unit_lb"] if "unit_lb" in row.keys() else row["weight_per_unit"]
                        qty  = row["qty"] if "qty" in row.keys() else row["quantity"]
                        ln = _norm_line(name, unit, qty)
                        if ln:
                            rsz = _norm_size(row["size"]) if "size" in row.keys() else None
                            if rsz in VALID_SIZES:
                                ln["size"] = rsz
                            out.append(ln)
                except Exception:
                    pass
                if out:
                    return out

            # --- Path B: flights(row) remarks text → parse_adv_manifest ------
            fid = flight_ref.get("flight_id")
            if fid is not None:
                try:
                    cur = c.execute("SELECT remarks FROM flights WHERE id = ?", (int(fid),))
                    row = cur.fetchone()
                    if row:
                        remarks = (row["remarks"] or "") if row["remarks"] is not None else ""
                        lines = parse_adv_manifest(remarks)
                        # lines already normalized
                        if isinstance(lines, list):
                            parsed = [ln for ln in lines if int(ln.get("qty") or 0) > 0]
                            if parsed:
                                return parsed
                except Exception:
                    pass
                # ---- Fallback: interpret flight_id as a request id when flight has no manifest ----
                try:
                    rid = int(fid)
                except Exception:
                    rid = None
                if rid is not None:
                    # (a) Dedicated lines table if present
                    try:
                        lines = _fetch_request_lines_db(c, rid)
                        if lines:
                            return [ln for ln in lines if int(ln.get("qty") or 0) > 0]
                    except Exception:
                        pass
                    # (b) Ramp-requests aggregate (manifest text) or legacy line-granular rows
                    try:
                        if _table_exists(c, "wargame_ramp_requests"):
                            # Prefer aggregate manifest parsing via helper
                            for r in (_fetch_ramp_requests_db(c) or []):
                                try:
                                    if int(r.get("id")) == rid:
                                        req_lines = list(r.get("lines") or [])
                                        req_lines = [ln for ln in req_lines if int(ln.get("qty") or 0) > 0]
                                        if req_lines:
                                            return req_lines
                                except Exception:
                                    continue
                    except Exception:
                        pass
                    # (c) Older cargo_requests + cargo_request_lines
                    try:
                        if _table_exists(c, "cargo_requests"):
                            lines = _fetch_request_lines_db(c, rid)
                            if lines:
                                return [ln for ln in lines if int(ln.get("qty") or 0) > 0]
                    except Exception:
                        pass
    except Exception:
        # swallow errors, return best-effort below
        pass
    return out

# carrier parsing: accepts "truck:0", "truck#101", "cart:alpha"
_CUID_RE = _re.compile(r"^(truck|cart)[:#](.+)$", _re.I)
def _parse_carrier(carrier_type, carrier_index, carrier_uid):
    """
    Return normalized (ctype, cidx, cuid).  TRUCK cuid is an int; CART cuid is "cart:<id>".
    """
    ctype = (carrier_type or "").strip().lower() or None
    cidx  = carrier_index
    cuid  = carrier_uid
    if isinstance(cidx, str):
        try: cidx = int(cidx)
        except Exception: cidx = None
    if isinstance(cuid, str):
        m = _CUID_RE.match(cuid.strip())
        if m:
            ctype = m.group(1).lower()
            rest  = m.group(2).strip()
            if rest.isdigit():
                n = int(rest)
                if ctype == "truck":
                    cuid = n
                    cidx = n if cidx is None else cidx
                else:
                    # carts must keep the "cart:" prefix for canonical ID
                    cuid = f"cart:{n}"
            else:
                # ensure "cart:" prefix for non-numeric cart IDs
                cuid = rest if rest.startswith("cart:") else f"cart:{rest}"
        else:
            if cuid.isdigit() and ctype in (None, "truck"):
                ctype = ctype or "truck"
                cidx = int(cuid)
                cuid = None
    return ctype, cidx, cuid

def _carrier_canon_str(ctype: str | None, cuid) -> str:
    """
    Canonical, client-friendly carrier string:
      truck:<id>   (id is int)
      cart:<id>    (id already normalized, e.g. 'cart:0' or 'cart:alpha')
    """
    ct = (ctype or "").lower()
    if ct == "truck":
        try: return f"truck:{int(cuid)}"
        except Exception: return "truck"
    if ct == "cart":
        cu = str(cuid or "")
        return cu if cu.startswith("cart:") else f"cart:{cu}"
    return ""

# Mark WG API requests for app-level fast-lane skips (auth/prefs)
@bp.before_request
def _wgapi_fastlane_flag():
    try:
        g.WGAPI_FASTLANE = True
    except Exception:
        pass

# --- Read-only adapters ------------------------------------------------------
@bp.get("/api/wargame/stockpile")
def api_stockpile():
    with LOCK:
        # Lazy pre-seed from Inventory the first time this is fetched.
        try:
            _seed_stockpile_from_inventory_if_empty()
        except Exception:
            pass
        return jsonify(STATE["adapters"]["stockpile"])

@bp.get("/api/wargame/trucks")
def api_trucks():
    with LOCK:
        src = STATE["adapters"]["trucks"]
        # If no soft-despawn, return as-is
        if EMPTY_TRUCK_HIDE_SEC <= 0:
            # Add a computed "hidden" hint without mutating state (use shallow copies)
            now = time.time()
            def annotate(t):
                out = dict(t)
                ts = out.get("empty_since")
                try:
                    if ts:
                        dt = datetime.fromisoformat(ts.replace("Z","+00:00")).timestamp()
                        if now - dt >= 0:
                            out.setdefault("hidden", False)
                except Exception:
                    pass
                return out
            return jsonify({
                "inbound": [annotate(t) for t in src.get("inbound", [])],
                "outbound": [annotate(t) for t in src.get("outbound", [])],
            })

        now = time.time()
        def should_hide(t):
            ts = t.get("empty_since")
            if not ts:
                return False
            try:
                dt = datetime.fromisoformat(ts.replace("Z","+00:00")).timestamp()
                return (now - dt) >= EMPTY_TRUCK_HIDE_SEC
            except Exception:
                return False

        # Return filtered shallow copies (omit hidden trucks for visual polish)
        inbound = [dict(t) for t in src.get("inbound", []) if not should_hide(t)]
        outbound = [dict(t) for t in src.get("outbound", []) if not should_hide(t)]
        return jsonify({"inbound": inbound, "outbound": outbound})

@bp.get("/api/wargame/queues")
def api_queues():
    with LOCK:
        return jsonify(STATE["adapters"]["queues"])

# New: list open cargo requests (normalized and weight-summed)
@bp.get("/api/wargame/requests")
def api_requests():
    def _norm_req(r: dict) -> dict:
        lines = list(r.get("lines") or [])
        total = 0.0
        for ln in lines:
            try:
                ulb = float(ln.get("unit_lb") if "unit_lb" in ln else ln.get("size_lb") or 0.0)
            except Exception:
                ulb = 0.0
            try:
                qty = int(ln.get("qty") or 0)
            except Exception:
                qty = 0
            total += (ulb * qty)
        # If no lines or computed total is zero, respect precomputed requested_weight (DB)
        if (total <= 0.0) and ("requested_weight" in r):
            try:
                total = float(r.get("requested_weight") or 0.0)
            except Exception:
                total = 0.0
        return {
            "id": r.get("id"),
            "destination": r.get("destination") or r.get("dest") or "",
            "requested_weight": float(total),
            "created_at": r.get("created_at") or None,
            "lines": lines,
        }
    # Gather STATE first
    with LOCK:
        state_reqs = list(STATE["adapters"].get("queues", {}).get("requests", []))
    db_reqs: list[dict] = []
    try:
        with _connect_sqlite() as c:
            db_reqs = _fetch_open_cargo_requests_db(c)
    except Exception:
        db_reqs = []
    # Merge (STATE wins to preserve 'assigned' buckets, etc.)
    merged: dict[int, dict] = {}
    for r in db_reqs:
        try: rid = int(r.get("id"))
        except Exception: continue
        merged[rid] = {**r}
    for r in state_reqs:
        try: rid = int(r.get("id"))
        except Exception: continue
        merged[rid] = {**merged.get(rid, {}), **r}
    result = [_norm_req(r) for r in merged.values()]
    # If STATE was empty and DB had items, reflect into STATE so assignment logic can see them
    if not state_reqs and merged:
        with LOCK:
            queues = STATE["adapters"].setdefault("queues", {})
            queues["requests"] = list(merged.values())
    # Sort by created_at (if present), else by id
    try:
        result.sort(key=lambda r: (r["created_at"] or "", int(r["id"] or 0)))
    except Exception:
        pass
    # Include default origin from preferences
    origin = (get_preference("default_origin") or "").strip().upper()
    return jsonify({"requests": result, "origin": origin})

# Convenience: manifest for a single request id (lines only)
@bp.get("/api/wargame/request/<int:req_id>/manifest")
def api_request_manifest(req_id: int):
    # 1) Try in-memory STATE
    with LOCK:
        reqs = list(STATE["adapters"].get("queues", {}).get("requests", []))
    for r in reqs:
        try:
            if int(r.get("id")) == int(req_id):
                return jsonify({"lines": list(r.get("lines") or [])})
        except Exception:
            continue
    # 2) DB fallback
    try:
        with _connect_sqlite() as c:
            # Prefer ramp-requests (aggregate or line-granular) if available
            if _table_exists(c, "wargame_ramp_requests"):
                # Aggregate-per-request: parse single-row manifest
                if _has_column(c, "wargame_ramp_requests", "manifest"):
                    cur = c.execute(
                        "SELECT manifest FROM wargame_ramp_requests WHERE id = ?",
                        (int(req_id),),
                    )
                    row = cur.fetchone()
                    if row:
                        text = (row["manifest"] or "").strip()
                        try:
                            lines = parse_adv_manifest(text) or []
                        except Exception:
                            lines = []
                        return jsonify({"lines": lines})
                # Legacy fallback: group line-granular rows by request id
                cur = c.execute("SELECT * FROM wargame_ramp_requests")
                rows = cur.fetchall()
                if rows:
                    keys = rows[0].keys()
                    def choose(cols): 
                        for n in cols:
                            if n in keys: return n
                        return None
                    id_col   = choose(["request_id","group_id","ticket_id","batch_id","id"])
                    name_col = choose(["display_name","name","item","sanitized_name"])
                    unit_col = choose(["unit_lb","size_lb","weight_per_unit","unit_weight_lb","weight_lb","unit_weight"])
                    size_col = choose(["size","bin","size_class"])
                    qty_col  = choose(["qty","quantity","requested_qty","units","count"])
                    lines: list[dict] = []
                    for r in rows:
                        try:
                            rid = r[id_col] if id_col else None
                            rid_int = int(rid) if rid is not None else None
                        except Exception:
                            rid_int = None
                        if rid_int != int(req_id):
                            continue
                        dn = (_first_present_key(r,[name_col], "") or "").strip()
                        try: ulb = float(_first_present_key(r,[unit_col], 0.0) or 0.0)
                        except Exception: ulb = 0.0
                        sz = _norm_size(_first_present_key(r,[size_col], None)) or _size_for(ulb)
                        try: q = int(_first_present_key(r,[qty_col], 0) or 0)
                        except Exception: q = 0
                        if dn and q > 0:
                            lines.append({"display_name": dn, "unit_lb": ulb, "size": sz, "qty": q})
                    return jsonify({"lines": lines})
            if not _table_exists(c, "cargo_requests"):
                return jsonify({"error": "not_found"}), 404
            cur = c.execute("SELECT 1 FROM cargo_requests WHERE id = ?", (int(req_id),))
            if cur.fetchone() is None:
                return jsonify({"error": "not_found"}), 404
            lines = _fetch_request_lines_db(c, int(req_id))
            return jsonify({"lines": lines})
    except Exception:
        pass
    return jsonify({"error": "not_found"}), 404

# New: planes endpoint so the client can hydrate visuals purely from server
@bp.get("/api/wargame/planes")
def api_planes():
    with LOCK:
        return jsonify({"planes": STATE["adapters"].get("planes", [])})

# ── Read-only flight endpoints (DB-backed) ───────────────────────────────────
@bp.get("/api/wargame/inbound_flights")
def api_inbound_flights():
    """
    Flights with open inbound ramp tasks:
      role='ramp' AND kind='inbound' AND complete=0
      where task.key == 'flight:<id>'.
      Implemented with sqlite3 to avoid SQLAlchemy symbols.
    """
    with _connect_sqlite() as c:
        tasks_table = _guess_tasks_table(c)
        # 1) get all matching task keys (schema-aware: 'complete' may not exist)
        has_task_complete = _has_column(c, tasks_table, "complete")
        sql_tasks = f"SELECT key FROM {tasks_table} WHERE role = ? AND kind = ?"
        params = ["ramp", "inbound"]
        if has_task_complete:
            sql_tasks += " AND COALESCE(complete,0) = 0"
        _log_info("wgapi.inbound_flights.tasks_query", has_task_complete=has_task_complete, tasks_table=tasks_table)
        cur = c.execute(sql_tasks, params)
        keys = [row["key"] for row in cur.fetchall() if row and row["key"]]
        flight_ids = []
        for k in keys:
            fid = _key_to_flight_id(k)
            if fid is not None:
                flight_ids.append(fid)
        if not flight_ids:
            return jsonify({"flights": []})

        # 2) fetch those flights (order by eta, tail_number) — schema-aware 'complete'
        has_flight_complete = _has_column(c, "flights", "complete")
        cols = (
            "id, tail_number, airfield_takeoff, airfield_landing, "
            "pilot, pax, eta, cargo_type, cargo_weight, remarks"
        )
        if has_flight_complete:
            cols += ", complete"
        else:
            cols += ", 0 AS complete"
        _log_info("wgapi.inbound_flights.flights_query", has_flight_complete=has_flight_complete)
        placeholders = ",".join("?" for _ in flight_ids)
        cur = c.execute(
            f"SELECT {cols} FROM flights WHERE id IN ({placeholders}) ORDER BY eta ASC, tail_number ASC",
            flight_ids,
        )
        flights = []
        for f in cur.fetchall():
            remarks = (f["remarks"] or "") if f["remarks"] is not None else ""
            try:
                has_manifest = bool(parse_adv_manifest(remarks))
            except Exception:
                has_manifest = bool(remarks)
            flights.append({
                "id": f["id"],
                "tail_number": f["tail_number"],
                "airfield_takeoff": f["airfield_takeoff"],
                "airfield_landing": f["airfield_landing"],
                "pilot": f["pilot"],
                "pax": int(f["pax"] or 0),
                "eta": _iso_or_raw(f["eta"]),
                "cargo_type": f["cargo_type"],
                "cargo_weight": int(f["cargo_weight"] or 0),
                "has_manifest": has_manifest,
                "complete": bool(f["complete"]),
            })
        return jsonify({"flights": flights})

@bp.get("/api/wargame/flight/<int:flight_id>")
def api_get_flight(flight_id: int):
    with _connect_sqlite() as c:
        has_flight_complete = _has_column(c, "flights", "complete")
        cols = (
            "id, tail_number, airfield_takeoff, airfield_landing, pilot, "
            "pax, eta, takeoff_time, cargo_type, cargo_weight, remarks"
        )
        if has_flight_complete:
            cols += ", complete"
        else:
            cols += ", 0 AS complete"
        _log_info("wgapi.get_flight.flights_query", has_flight_complete=has_flight_complete, flight_id=flight_id)
        cur = c.execute(
            f"SELECT {cols} FROM flights WHERE id = ?",
            (flight_id,),
        )
        f = cur.fetchone()
        if not f:
            return jsonify({"error": "not_found"}), 404
        remarks = (f["remarks"] or "") if f["remarks"] is not None else ""
        try:
            has_manifest = bool(parse_adv_manifest(remarks))
        except Exception:
            has_manifest = bool(remarks)
        flight = {
            "id": f["id"],
            "tail_number": f["tail_number"],
            "airfield_takeoff": f["airfield_takeoff"],
            "airfield_landing": f["airfield_landing"],
            "pilot": f["pilot"],
            "pax": int(f["pax"] or 0),
            "eta": _iso_or_raw(f["eta"]),
            "takeoff_time": _iso_or_raw(f["takeoff_time"]),
            "cargo_type": f["cargo_type"],
            "cargo_weight": int(f["cargo_weight"] or 0),
            "has_manifest": has_manifest,
            "complete": bool(f["complete"]),
        }
        return jsonify({"flight": flight})

@bp.get("/api/wargame/manifest/<int:flight_id>")
def api_get_manifest(flight_id: int):
    with _connect_sqlite() as c:
        cur = c.execute("SELECT remarks FROM flights WHERE id = ?", (flight_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "not_found"}), 404
        remarks = (row["remarks"] or "") if row["remarks"] is not None else ""
        try:
            lines = parse_adv_manifest(remarks)  # [{name,size_lb,qty,notes?}, ...]
        except Exception:
            try:
                # We already import current_app at top
                if current_app and current_app.logger:
                    current_app.logger.exception("parse_adv_manifest failed")
            except Exception:
                pass
            lines = []
        return jsonify({"lines": lines})

def _expose_trucks_epoch() -> int:
    return int(STATE.get("trucks_epoch", 0))

# ─────────────────────────────────────────────────────────────────────────────
# Delivery truck spawn/pack helper (called by background job; no DB mutations)
# ─────────────────────────────────────────────────────────────────────────────
def _get_delivery_truck():
    """Return the inbound truck dict that has role='delivery' (fallback to index)."""
    inbound = STATE["adapters"]["trucks"].get("inbound", [])
    for t in inbound:
        if (t.get("role") or "").lower() == "delivery":
            return t
    if 0 <= DELIVERY_TRUCK_INDEX < len(inbound):
        return inbound[DELIVERY_TRUCK_INDEX]
    return inbound[0] if inbound else None

def _merge_line(lines: list, display_name: str, unit_lb: float, size: str, inc_qty: int, source_item_id: int | None = None) -> None:
    """
    Merge by (display_name, unit_lb, size); mutate lines in-place.
    Also accumulates per-source provenance in line['sources'] = [{item_id, qty}, ...].
    """
    for ln in lines:
        if (ln.get("display_name") == display_name and
            abs(float(ln.get("unit_lb", 0.0)) - float(unit_lb)) < 1e-6 and
            (ln.get("size") or "").upper() == (size or "").upper()):
            ln["qty"] = int(ln.get("qty", 0)) + int(inc_qty)
            # provenance bucket merge
            if source_item_id is not None:
                srcs = ln.setdefault("sources", [])
                for s in srcs:
                    if int(s.get("item_id") or 0) == int(source_item_id):
                        s["qty"] = int(s.get("qty") or 0) + int(inc_qty)
                        break
                else:
                    srcs.append({"item_id": int(source_item_id), "qty": int(inc_qty)})
            return
    lines.append({
        "display_name": display_name,
        "unit_lb": float(unit_lb),
        "size": (size or "M").upper(),
        "qty": int(inc_qty),
        "sources": ([{"item_id": int(source_item_id), "qty": int(inc_qty)}] if source_item_id is not None else []),
    })

def _truck_all_bins_zero(m):
    try:
        b = (m or {}).get("box") or {}
        return all(int(b.get(s,0)) == 0 for s in VALID_SIZES)
    except Exception:
        return True

def _line_sources_decrement(line: dict, qty: int) -> None:
    """
    Remove 'qty' units from line['sources'] in FIFO order so per-source
    tallies roughly track what remains on-truck. Non-fatal on malformed data.
    """
    try:
        need = int(qty or 0)
        if need <= 0:
            return
        srcs = list(line.get("sources") or [])
        i = 0
        while need > 0 and i < len(srcs):
            have = int(srcs[i].get("qty") or 0)
            take = min(have, need)
            srcs[i]["qty"] = have - take
            if srcs[i]["qty"] <= 0:
                srcs.pop(i)
            else:
                i += 1
        line["sources"] = srcs
    except Exception:
        pass

def _reap_player_held(session_id: int, player: dict) -> None:
    """On stale reap, put the player's held bundle back somewhere sensible."""
    try:
        held = (player or {}).get("held")
        if not held:
            return
        qty = int(held.get("qty") or 1)
        if qty <= 0:
            return
        size = _norm_size(held.get("size") or "M") or "M"
        item_key = (held.get("item_key") or "box").strip() or "box"

        display_name = (held.get("display_name") or "").strip()
        has_meta = bool(display_name) and ("unit_lb" in held)
        unit_lb = 0.0
        try:
            unit_lb = float(held.get("unit_lb") or 0.0)
        except Exception:
            unit_lb = 0.0

        if has_meta:
            # Prefer to return to Delivery truck when we know the exact line meta
            truck = _get_delivery_truck()
            if truck:
                lines = truck.setdefault("lines", [])
                manifest = truck.setdefault("manifest", {"box": {s: 0 for s in VALID_SIZES}})
                _merge_line(lines, display_name, unit_lb, size, qty, None)
                _manifest_add(manifest, "box", size, +qty)
                _update_truck_empty_since(truck)
                player["held"] = None
                return

        # Fallback: return to stockpile (track numeric quantity)
        if has_meta and qty > 0:
            _stockpile_add_unique(display_name, unit_lb, size, qty)
        # If no metadata, just drop it (clear).
        # Do not touch numeric stockpile bins in Phase 1 fallback.
        player["held"] = None
    except Exception:
        # Non-fatal; on failure we just skip return
        pass

def _update_truck_empty_since(truck: dict) -> None:
    """Set or clear empty_since depending on lines[] and manifest bins."""
    try:
        lines = truck.get("lines") or []
        manifest = truck.get("manifest") or {}
        if (not lines) and _truck_all_bins_zero(manifest):
            if not truck.get("empty_since"):
                truck["empty_since"] = iso8601_ceil_utc()
        else:
            truck["empty_since"] = None
    except Exception:
        pass

def pack_delivery_truck_spawn_once(max_boxes: int = 16) -> int:
    """
    Pull open spawn tickets and place up to max_boxes 'box equivalents'
    onto the Delivery truck. Merges lines, and increments manifest S/M/L/XL.
    Does NOT mutate DB — only the in-memory world state.
    Returns: number of units added this tick.
    """
    try:
        # Lazy import to avoid circulars at app boot
        from modules.services.wargame import get_open_spawn_tickets
    except Exception:
        return 0

    with LOCK:
        truck = _get_delivery_truck()
        if not truck:
            return 0
        lines    = truck.setdefault("lines", [])
        spawned  = truck.setdefault("spawned", {})  # item_id -> qty already spawned to truck
        manifest = truck.setdefault("manifest", {"box": {s: 0 for s in VALID_SIZES}})

        tickets = get_open_spawn_tickets() or []
        remaining_quanta = max(0, int(max_boxes or 0))
        added = 0
        for tk in tickets:
            if remaining_quanta <= 0:
                break
            src = (tk.get("source") or {})
            item_id = int(src.get("item_id") or 0)
            if item_id <= 0:
                continue
            req = int(tk.get("qty_remaining") or 0)
            if req <= 0:
                continue
            done = int(spawned.get(item_id) or 0)
            still_needed = max(0, req - done)
            if still_needed <= 0:
                continue
            take = min(still_needed, remaining_quanta)
            if take <= 0:
                continue

            display_name = str(tk.get("display_name") or "").strip()
            unit_lb = float(tk.get("unit_lb") or 0.0)
            size    = (tk.get("size") or "M").upper()
            _merge_line(lines, display_name, unit_lb, size, take, item_id)
            _manifest_add(manifest, "box", size, take)
            spawned[item_id] = done + take

            remaining_quanta -= take
            added += take

        # housekeeping for visuals: mark empty_since when truly empty
        _update_truck_empty_since(truck)
        if added > 0:
            _bump_trucks_epoch()
        return added

# Dev helper: on-demand pack pass (behind feature flag)
@bp.post("/api/wargame/spawn/refresh")
def api_spawn_refresh():
    should = (get_preference('wargame_spawn_from_generators') or 'yes').strip().lower() == 'yes'
    if not should:
        return jsonify({"ok": False, "added": 0, "reason": "pref_off"}), 400
    try:
        n = int(request.args.get("n") or 0)
    except Exception:
        n = 0
    quanta = n if n > 0 else int((get_preference('wargame_truck_spawn_quanta') or 16))
    added = int(pack_delivery_truck_spawn_once(quanta) or 0)
    with LOCK:
        t = _get_delivery_truck()
        return jsonify({"ok": True, "added": added, "truck": t})

# --- Admin/reset helpers ------------------------------------------------------
def _reset_world_state(clear_db: bool = False) -> None:
    """Reset in-memory trucks/stockpile; optionally clear open spawn batches."""
    with LOCK:
        # trucks: restore to fresh roles/poses, clear lines/manifest/etc.
        STATE["adapters"]["trucks"]["inbound"] = _mk_inbound_trucks()
        STATE["adapters"]["trucks"]["outbound"] = []
        # stockpile: wipe registry and zero bins
        st = STATE["adapters"]["stockpile"]
        st["registry"] = {}
        st.setdefault("bins", {}).setdefault("box", {})
        for s in VALID_SIZES:
            st["bins"]["box"][s] = 0
        _touch_stockpile()
        _bump_trucks_epoch()
    if clear_db:
        try:
            import sqlite3
            from app import DB_FILE
            with sqlite3.connect(DB_FILE) as c:
                c.execute("DELETE FROM wargame_inventory_batch_items")
                c.execute("DELETE FROM wargame_inventory_batches")
                c.commit()
        except Exception:
            pass

@bp.post("/api/wargame/reset")
def api_wargame_reset():
    """Reset world state. Optional ?clear_db=1 wipes open inbound batches."""
    clear_db = (str(request.args.get("clear_db") or "0").strip() == "1")
    _reset_world_state(clear_db=clear_db)
    return jsonify({"ok": True, "cleared_db": bool(clear_db), "trucks_epoch": _expose_trucks_epoch()})

# --- Multiplayer presence/state ----------------------------------------------
@bp.get("/wargame/state")
def wargame_state():
    session_id = int(request.args.get("session_id", "1"))
    try:
        since_id = int(request.args.get("since_id", "0") or 0)
    except Exception:
        since_id = 0

    _prune_stale_players(session_id)
    with LOCK:
        sess = _ensure_session(session_id)
        players     = list(sess["players"].values())
        carts       = STATE["carts"][session_id]
        all_claims  = STATE["claims"][session_id]
        claims      = [c for c in all_claims if int(c.get("id", 0)) > since_id] if since_id > 0 else all_claims
        badges      = {"queue": STATE["adapters"]["queues"].get("loads_waiting", 0)}
        return jsonify({
            "server_time": time.time(),
            "players": players,
            "carts": carts,
            "claims": claims,
            "badges": badges,
            "next_claim_id": sess["next_claim_id"],
            "trucks_epoch": _expose_trucks_epoch(),
        })

@bp.get("/wargame/players")
def wargame_players():
    session_id = int(request.args.get("session_id", "1"))
    _prune_stale_players(session_id)
    with LOCK:
        sess = _ensure_session(session_id)
        return jsonify({"players": list(sess["players"].values())})

@bp.post("/wargame/join")
def wargame_join():
    data = request.get_json(force=True) or {}
    session_id = int(data.get("session_id", 1))
    name = (data.get("name") or "Guest").strip()[:24]
    now = time.time()
    with LOCK:
        sess = _ensure_session(session_id)
        pid  = sess["next_player_id"]; sess["next_player_id"] = pid + 1
        color_index = (pid - 1) % 8
        player = {
            "id": pid, "name": name or f"Player {pid}",
            "x": 800, "y": 450, "dir": "S",
            "last_seen": now, "pos_seq": 0,
            "color_index": color_index, "joined_at": _utc_iso(),
            "held": None,
        }
        sess["players"][pid] = player
        return jsonify({"player_id": pid, "name": player["name"], "color_index": color_index})

@bp.post("/wargame/rename")
def wargame_rename():
    data = request.get_json(force=True) or {}
    session_id = int(data.get("session_id", 1))
    player_id  = int(data.get("player_id"))
    new_name   = (data.get("name") or "").strip()[:24]
    with LOCK:
        sess = _ensure_session(session_id)
        if player_id in sess["players"]:
            sess["players"][player_id]["name"] = new_name or sess["players"][player_id]["name"]
            return jsonify({"ok": True, "player": sess["players"][player_id]})
        return jsonify({"ok": False, "error": "not_found"}), 404

@bp.post("/wargame/pos")
def wargame_pos():
    data = request.get_json(force=True) or {}
    session_id = int(data.get("session_id", 1))
    player_id  = int(data.get("player_id"))
    x = float(data.get("x", 0)); y = float(data.get("y", 0))
    dir_ = (data.get("dir") or "S")[:2]
    now = time.time()
    with LOCK:
        sess = _ensure_session(session_id)
        p = sess["players"].get(player_id)
        if not p:
            sess["players"][player_id] = p = {
                "id": player_id, "name": f"Player {player_id}",
                "x": x, "y": y, "dir": dir_,
                "last_seen": now, "pos_seq": 1,
                "color_index": (player_id - 1) % 8, "joined_at": _utc_iso(),
                "held": None,
            }
        else:
            p["x"], p["y"], p["dir"] = x, y, dir_
            p["last_seen"] = now
            p["pos_seq"] = int(p.get("pos_seq", 0)) + 1
        return jsonify({"ok": True, "pos_seq": p["pos_seq"]})

# --- Claims & atomic mutations -----------------------------------------------
@bp.post("/wargame/claim")
def wargame_claim():
    """
    Authoritative world changes with server-side size & carrier normalization.
    Accepts actions: 'stockpile_add' | 'stockpile_remove' | 'carrier_add' | 'carrier_remove'
    """
    data = request.get_json(force=True) or {}
    session_id = int(data.get("session_id", 1))
    with LOCK:
        sess = _ensure_session(session_id)

        # Preferred modern payload
        if "action" in data:
            action        = (data.get("action") or "").lower().strip()
            player_id     = int(data.get("player_id") or 0)
            item_key      = (data.get("item_key") or data.get("item") or "").strip()
            # accept size either top-level or nested under 'line'
            size_in       = (data.get("size") or (data.get("line") or {}).get("size"))
            size          = _norm_size(size_in or "")
            # accept single-field 'carrier' (e.g. "truck:0") as well as split fields
            ctype, cidx, cuid = _parse_carrier(
                data.get("carrier_type"),
                data.get("carrier_index"),
                (data.get("carrier_uid") or data.get("carrier"))
            )

            if not item_key:
                return jsonify({"ok": False, "error": "bad_item"}), 400
            if size not in VALID_SIZES:
                return jsonify({"ok": False, "error": "bad_size", "got": size_in}), 400
            if action not in ("stockpile_add","stockpile_remove","carrier_add","carrier_remove","take"):
                return jsonify({"ok": False, "error": "bad_action"}), 400

            player = sess["players"].get(player_id)
            if not player:
                return jsonify({"ok": False, "error": "no_player"}), 404
            held = player.get("held")

            def make_entry(extra: dict):
                base = {"action": action, "player_id": player_id, "item_key": item_key, "size": size, "qty": 1}
                base.update(extra or {})
                return base

            # STOCKPILE TAKE (by unique line; default is sweep-all)
            if action == "stockpile_remove":
                if player.get("held"):
                    return jsonify({"ok": False, "error": "already_holding"}), 409
                # allow nested 'line' metadata
                ln = (data.get("line") or {})
                display_name = (data.get("display_name") or ln.get("display_name") or "").strip()
                try: unit_lb = float((data.get("unit_lb") if "unit_lb" in data else ln.get("unit_lb")) or 0.0)
                except Exception: unit_lb = 0.0
                if not display_name:
                    return jsonify({"ok": False, "error": "bad_display_name"}), 400
                # Determine available from registry
                reg = STATE["adapters"]["stockpile"].setdefault("registry", {})
                key = _stockpile_key(display_name, unit_lb, size)
                ent = reg.get(key)
                have = int((ent or {}).get("qty") or 0)
                if have <= 0:
                    return jsonify({"ok": False, "error": "insufficient_stockpile"}), 409
                # 'count' accepted as alias for 'qty'
                req = (data.get("qty") if "qty" in data else data.get("count"))
                take = int(req or have)  # sweep-all by default
                if take <= 0 or take > have:
                    return jsonify({"ok": False, "error": "bad_qty"}), 400
                took = _stockpile_remove_unique(display_name, unit_lb, size, take)
                if took <= 0:
                    return jsonify({"ok": False, "error": "insufficient_stockpile"}), 409
                # grant held bundle with metadata
                player["held"] = {
                    "item_key": item_key,
                    "size": size,
                    "qty": took,
                    "display_name": display_name,
                    "unit_lb": unit_lb,
                }
                entry = _append_claim(session_id, {
                    "action": "stockpile_remove",
                    "player_id": player_id,
                    "item_key": item_key,
                    "size": size,
                    "qty": took,
                    "display_name": display_name,
                    "unit_lb": unit_lb,
                    "created_at": _utc_iso(),
                })
                return jsonify({"ok": True, "claim": entry, "player": player, "stockpile": STATE["adapters"]["stockpile"]})

            # STOCKPILE PUT (unique-item registry + variety bins)
            if action == "stockpile_add":
                qty = int((data.get("qty") if "qty" in data else data.get("count") or 1))
                if qty <= 0:
                    return jsonify({"ok": False, "error": "bad_qty"}), 400
                # allow nested 'line' metadata
                ln = (data.get("line") or {})
                display_name = (data.get("display_name") or ln.get("display_name") or "").strip()
                try: unit_lb = float((data.get("unit_lb") if "unit_lb" in data else ln.get("unit_lb")) or 0.0)
                except Exception: unit_lb = 0.0
                if not held:
                    return jsonify({"ok": False, "error": "not_holding"}), 409
                # Require metadata match with what the player is holding
                same_item = (held.get("item_key") == item_key)
                same_size = ((held.get("size") or "").upper() == size)
                try:
                    same_unit = (abs(float(held.get("unit_lb") or 0.0) - unit_lb) < 1e-6)
                except Exception:
                    same_unit = False
                same_name = (_name_norm(held.get("display_name") or "") == _name_norm(display_name))
                if not (same_item and same_size and same_unit and same_name):
                    return jsonify({"ok": False, "error": "held_mismatch"}), 409
                # Unique-item registry update (track numeric qty)
                _stockpile_add_unique(display_name, unit_lb, size, qty)
                player["held"] = None
                entry = _append_claim(session_id, make_entry({
                    "qty": qty,
                    "display_name": display_name,
                    "unit_lb": unit_lb,
                }))
                with LOCK:
                    return jsonify({"ok": True, "claim": entry, "player": player, "stockpile": STATE["adapters"]["stockpile"]})

            # TAKE (truck only): always take the entire matching line (max)
            if action == "take":
                if held:
                    return jsonify({"ok": False, "error": "already_holding"}), 409
                if ctype not in (None, "truck"):  # default to truck if omitted
                    return jsonify({"ok": False, "error": "bad_carrier_type"}), 400
                truck, side = _find_truck(cidx, cuid)
                if not truck:
                    return jsonify({"ok": False, "error": "no_truck"}), 404
                # Phase 1: only Delivery truck is active
                if not _is_delivery_truck(truck):
                    return jsonify({"ok": False, "error": "truck_not_delivery"}), 403
                ln = (data.get("line") or {})
                display_name = (data.get("display_name") or ln.get("display_name") or "").strip()
                try: unit_lb = float((data.get("unit_lb") if "unit_lb" in data else ln.get("unit_lb")) or 0.0)
                except Exception: unit_lb = 0.0
                lines = truck.setdefault("lines", [])
                target = None
                for ln in lines:
                    if (ln.get("display_name") == display_name and
                        abs(float(ln.get("unit_lb") or 0.0) - unit_lb) < 1e-6 and
                        (ln.get("size") or "").upper() == size):
                        target = ln
                        break
                if not target:
                    return jsonify({"ok": False, "error": "line_not_found"}), 404
                line_qty = int(target.get("qty") or 0)
                if line_qty <= 0:
                    return jsonify({"ok": False, "error": "insufficient_truck"}), 409
                qty = line_qty  # always take all
                # Apply decrements (manifest first to guard underflow)
                if not _manifest_add(truck.setdefault("manifest", {}), "box", size, -qty):
                    return jsonify({"ok": False, "error": "insufficient_truck"}), 409
                # Remove line entirely
                lines.remove(target)
                _line_sources_decrement(target, qty)
                # set held metadata
                player["held"] = {
                    "item_key": item_key,
                    "size": size,
                    "qty": qty,
                    "display_name": display_name,
                    "unit_lb": unit_lb,
                }
                # Broadcast as carrier_remove for client compatibility
                entry = _append_claim(session_id, {
                    "action": "carrier_remove",
                    "player_id": player_id,
                    "item_key": item_key,
                    "size": size,
                    "qty": qty,
                    "carrier_type": "truck",
                    "carrier_uid": truck.get("truck_id"),
                    "carrier": _carrier_canon_str("truck", truck.get("truck_id")),
                    "display_name": display_name,
                    "unit_lb": unit_lb,
                    "created_at": _utc_iso(),
                })
                _update_truck_empty_since(truck)
                _bump_trucks_epoch()
                return jsonify({"ok": True, "claim": entry, "player": player, "trucks": STATE["adapters"]["trucks"]})

            # CARRIER sanity
            if action.startswith("carrier_") and not ctype:
                return jsonify({"ok": False, "error": "missing_carrier_type"}), 400

            # CARRIER TAKE (truck/cart). Truck supports qty + line metadata.
            if action == "carrier_remove":
                if held:
                    return jsonify({"ok": False, "error": "already_holding"}), 409

                if ctype == "truck":
                    truck, side = _find_truck(cidx, cuid)
                    if not truck:
                        return jsonify({"ok": False, "error": "no_truck"}), 404
                    # Extended: find the target line by metadata; default to sweep-all if qty not provided
                    ln = (data.get("line") or {})
                    display_name = (data.get("display_name") or ln.get("display_name") or "").strip()
                    try: unit_lb = float((data.get("unit_lb") if "unit_lb" in data else ln.get("unit_lb")) or 0.0)
                    except Exception: unit_lb = 0.0
                    qty_req = (data.get("qty") if "qty" in data else data.get("count"))
                    lines = truck.setdefault("lines", [])
                    target = None
                    for ln in lines:
                        if (ln.get("display_name") == display_name and
                            abs(float(ln.get("unit_lb") or 0.0) - unit_lb) < 1e-6 and
                            (ln.get("size") or "").upper() == size):
                            target = ln
                            break
                    if not target:
                        return jsonify({"ok": False, "error": "line_not_found"}), 404
                    line_qty = int(target.get("qty") or 0)
                    if line_qty <= 0:
                        return jsonify({"ok": False, "error": "insufficient_truck"}), 409
                    qty = int(qty_req or line_qty)  # sweep-all default
                    if qty <= 0 or qty > line_qty:
                        return jsonify({"ok": False, "error": "bad_qty"}), 400
                    # Apply decrements (manifest first to guard underflow)
                    if not _manifest_add(truck.setdefault("manifest", {}), "box", size, -qty):
                        return jsonify({"ok": False, "error": "insufficient_truck"}), 409
                    new_line_qty = line_qty - qty
                    if new_line_qty > 0:
                        target["qty"] = new_line_qty
                    else:
                        # remove line entirely
                        lines.remove(target)
                    # Decrement provenance buckets to reflect removal
                    _line_sources_decrement(target if new_line_qty > 0 else {"sources": target.get("sources", [])}, qty)
                    # set held metadata
                    player["held"] = {
                        "item_key": item_key,
                        "size": size,
                        "qty": qty,
                        "display_name": display_name,
                        "unit_lb": unit_lb,
                    }
                    entry = _append_claim(session_id, make_entry({
                        "carrier_type": "truck",
                        "carrier_uid": truck.get("truck_id"),
                        "carrier": _carrier_canon_str("truck", truck.get("truck_id")),
                        "qty": qty,
                        "display_name": display_name,
                        "unit_lb": unit_lb,
                    }))
                    # Re-evaluate emptiness/despawn window
                    _update_truck_empty_since(truck)
                    _bump_trucks_epoch()
                    return jsonify({"ok": True, "claim": entry, "player": player, "trucks": STATE["adapters"]["trucks"]})

                if ctype == "cart":
                    cart_id = cuid if cuid is not None else cidx
                    if cart_id is None:
                        return jsonify({"ok": False, "error": "no_cart_id"}), 400
                    cart = _find_or_create_cart(session_id, cart_id)
                    if not _manifest_add(cart.setdefault("contents", {}), item_key, size, -1):
                        return jsonify({"ok": False, "error": "insufficient_cart"}), 409
                    player["held"] = {"item_key": item_key, "size": size, "qty": 1}
                    # publish canonical id so all clients match
                    entry = _append_claim(session_id, make_entry({
                        "carrier_type": "cart",
                        "carrier_uid": cart.get("id"),
                        "carrier": _carrier_canon_str("cart", cart.get("id"))
                    }))
                    return jsonify({"ok": True, "claim": entry, "player": player, "carts": STATE["carts"][session_id]})

                return jsonify({"ok": False, "error": "bad_carrier_type"}), 400

            # CARRIER PUT
            if action == "carrier_add":
                if not held or held.get("item_key") != item_key or held.get("size") != size:
                    return jsonify({"ok": False, "error": "not_holding"}), 409

                if ctype == "truck":
                    truck, side = _find_truck(cidx, cuid)
                    if not truck:
                        return jsonify({"ok": False, "error": "no_truck"}), 404
                    add_n = int(held.get("qty") or 1)
                    if add_n <= 0:
                        return jsonify({"ok": False, "error": "bad_qty"}), 400

                    # Delivery (inbound) truck: legacy behavior (put-back)
                    if _is_delivery_truck(truck):
                        # If we have metadata, also merge back into lines for accurate UI
                        if "display_name" in held and "unit_lb" in held:
                            try:
                                dn = (held.get("display_name") or "").strip()
                                ulb = float(held.get("unit_lb") or 0.0)
                                _merge_line(truck.setdefault("lines", []), dn, ulb, size, add_n, None)
                            except Exception:
                                pass
                        if not _manifest_add(truck.setdefault("manifest", {}), item_key, size, +add_n):
                            return jsonify({"ok": False, "error": "truck_update_failed"}), 500
                        player["held"] = None
                        entry = _append_claim(session_id, make_entry({
                            "carrier_type": "truck",
                            "carrier_uid": truck.get("truck_id"),
                            "carrier": _carrier_canon_str("truck", truck.get("truck_id")),
                            "qty": add_n
                        }))
                        _update_truck_empty_since(truck)
                        _bump_trucks_epoch()
                        return jsonify({"ok": True, "claim": entry, "player": player, "trucks": STATE["adapters"]["trucks"]})

                    # Outbound (retrieval) truck: accept cargo, assign to requests, and
                    # auto-despawn when a request becomes fully satisfied.
                    dn = (held.get("display_name") or "").strip()
                    try: ulb = float(held.get("unit_lb") or 0.0)
                    except Exception: ulb = 0.0
                    if not dn:
                        return jsonify({"ok": False, "error": "missing_metadata"}), 409
                    # Add cargo to the truck first (visible until fulfilled)
                    _merge_line(truck.setdefault("lines", []), dn, ulb, size, add_n, None)
                    if not _manifest_add(truck.setdefault("manifest", {}), item_key, size, +add_n):
                        return jsonify({"ok": False, "error": "truck_update_failed"}), 500
                    player["held"] = None
                    entry = _append_claim(session_id, make_entry({
                        "carrier_type": "truck",
                        "carrier_uid": truck.get("truck_id"),
                        "carrier": _carrier_canon_str("truck", truck.get("truck_id")),
                        "qty": add_n,
                        "display_name": dn,
                        "unit_lb": ulb,
                    }))
                    # Assign newly added cargo to requests and auto-fulfill if possible
                    try:
                        _assign_to_requests(truck, dn, ulb, size, add_n)
                        # Fulfill any request that is now fully assigned
                        for req in list(STATE["adapters"]["queues"].get("requests") or []):
                            if _request_fully_assigned(req):
                                _despawn_for_request(truck, req)
                    except Exception:
                        pass
                    _update_truck_empty_since(truck)
                    _bump_trucks_epoch()
                    return jsonify({"ok": True, "claim": entry, "player": player, "trucks": STATE["adapters"]["trucks"]})

                if ctype == "cart":
                    cart_id = cuid if cuid is not None else cidx
                    if cart_id is None:
                        return jsonify({"ok": False, "error": "no_cart_id"}), 400
                    cart = _find_or_create_cart(session_id, cart_id)
                    add_n = int(held.get("qty") or 1)
                    if add_n <= 0:
                        return jsonify({"ok": False, "error": "bad_qty"}), 400
                    # Add individual line entries (one per box) instead of merging
                    try:
                        dn = (held.get("display_name") or "").strip()
                        ulb = float(held.get("unit_lb") or 0.0)
                        if dn:
                            # Create individual line entries for each box
                            lines = cart.setdefault("lines", [])
                            for _ in range(add_n):
                                lines.append({
                                    "display_name": dn,
                                    "unit_lb": ulb,
                                    "size": (size or "M").upper(),
                                    "qty": 1,
                                    "sources": [],
                                })
                    except Exception:
                        pass
                    if not _manifest_add(cart.setdefault("contents", {}), item_key, size, +add_n):
                        return jsonify({"ok": False, "error": "cart_update_failed"}), 500
                    player["held"] = None
                    entry = _append_claim(session_id, make_entry({
                        "carrier_type": "cart",
                        "carrier_uid": cart.get("id"),
                        "carrier": _carrier_canon_str("cart", cart.get("id")),
                        "qty": add_n,
                        "display_name": (held.get("display_name") or ""),
                        "unit_lb": float(held.get("unit_lb") or 0.0),
                    }))
                    return jsonify({"ok": True, "claim": entry, "player": player, "carts": STATE["carts"][session_id]})

                return jsonify({"ok": False, "error": "bad_carrier_type"}), 400

            return jsonify({"ok": False, "error": "unhandled"}), 400

        # --- Legacy fallback (create/release) --------------------------------
        claims = STATE["claims"][session_id]
        op = (data.get("op") or "create").lower()
        if op == "release":
            pid = int(data.get("player_id", 0))
            item_key = data.get("item_key")
            size     = _norm_size(data.get("size") or "")
            STATE["claims"][session_id] = [
                c for c in claims
                if not (c.get("player_id") == pid and c.get("item_key") == item_key and _norm_size(c.get("size")) == size)
            ]
            return jsonify({"ok": True, "claims": STATE["claims"][session_id]})
        else:
            entry = dict(data)
            entry["size"] = _norm_size(entry.get("size") or "")
            entry["created_at"] = _utc_iso()
            e = _append_claim(session_id, entry)
            return jsonify({"ok": True, "claim": e})

# --- Cart preview (legacy helpers) -------------------------------------------
@bp.post("/wargame/cart/drop")
def wargame_cart_drop():
    data = request.get_json(force=True) or {}
    session_id = int(data.get("session_id", 1))
    cart_id = data.get("cart_id")
    with LOCK:
        cart = _find_or_create_cart(session_id, cart_id)
        cart.setdefault("preview", []).append({
            "item_key": data.get("item_key"),
            "size": _norm_size(data.get("size") or ""),
            "qty": int(data.get("qty", 1)),
            "unit_lb": int(data.get("unit_lb", 0)),
        })
        return jsonify({"ok": True, "cart": cart})

@bp.post("/wargame/cart/clear")
def wargame_cart_clear():
    data = request.get_json(force=True) or {}
    session_id = int(data.get("session_id", 1))
    cart_id = data.get("cart_id")
    with LOCK:
        cart = _find_or_create_cart(session_id, cart_id)
        cart["preview"] = []
        return jsonify({"ok": True, "cart": cart})

# ─────────────────────────────────────────────────────────────────────────────
# v6 API endpoints (WG fast-lane)
# ─────────────────────────────────────────────────────────────────────────────

# -- Internal helpers (diff & cart ops) ---------------------------------------
def _lines_to_map(lines: List[dict]) -> Dict[str, int]:
    """{key(name|unit|size) -> qty} from normalized line dicts."""
    out: Dict[str, int] = {}
    for ln in list(lines or []):
        dn = (ln.get("display_name") or "").strip()
        try: ulb = float(ln.get("unit_lb") or 0.0)
        except Exception: ulb = 0.0
        sz  = _norm_size(ln.get("size") or "M") or "M"
        q   = int(ln.get("qty") or 0)
        if dn and q > 0:
            k = _line_key(dn, ulb, sz)
            out[k] = out.get(k, 0) + q
    return out

def _required_meta_map(lines: List[dict]) -> Dict[str, dict]:
    """{key -> {'display_name','unit_lb','size'}} derived from required lines."""
    meta = {}
    for ln in list(lines or []):
        dn = (ln.get("display_name") or "").strip()
        try: ulb = float(ln.get("unit_lb") or 0.0)
        except Exception: ulb = 0.0
        sz  = _norm_size(ln.get("size") or "M") or "M"
        k = _line_key(dn, ulb, sz)
        meta[k] = {"display_name": dn, "unit_lb": ulb, "size": sz}
    return meta

def _cart_meta_map(cart: dict) -> Dict[str, dict]:
    """{key -> {'display_name','unit_lb','size'}} from cart.lines (best effort)."""
    meta = {}
    for ln in list((cart or {}).get("lines") or []):
        dn = (ln.get("display_name") or "").strip()
        try: ulb = float(ln.get("unit_lb") or 0.0)
        except Exception: ulb = 0.0
        sz  = _norm_size(ln.get("size") or "M") or "M"
        k = _line_key(dn, ulb, sz)
        meta.setdefault(k, {"display_name": dn, "unit_lb": ulb, "size": sz})
    return meta

def _diff_required_vs_cart(required_lines: List[dict], cart: dict) -> dict:
    """
    Compute shortages & excess between required manifest and aggregated cart.
    Returns {'shortages': [...], 'excess': [...]} (lists of line-shaped dicts).
    """
    req_map  = _lines_to_map(required_lines)
    cart_map = _cart_aggregate_lines(cart)
    req_meta = _required_meta_map(required_lines)
    cart_meta= _cart_meta_map(cart)

    shortages, excess = [], []
    # shortages: keys in required where cart < required
    for k, req_q in req_map.items():
        have = int(cart_map.get(k) or 0)
        if have < req_q:
            m = req_meta.get(k, {})
            shortages.append({
                "display_name": m.get("display_name",""),
                "unit_lb": float(m.get("unit_lb") or 0.0),
                "size": m.get("size","M"),
                "required": int(req_q),
                "have": int(have),
                "short": int(req_q - have),
            })
    # excess: (a) keys present in cart only; (b) keys where cart > required
    for k, have in cart_map.items():
        req_q = int(req_map.get(k) or 0)
        if have > req_q:
            m = (req_meta.get(k) or cart_meta.get(k) or {})
            excess.append({
                "display_name": m.get("display_name",""),
                "unit_lb": float(m.get("unit_lb") or 0.0),
                "size": m.get("size","M"),
                "required": int(req_q),
                "have": int(have),
                "extra": int(have - req_q),
            })
        elif req_q == 0:
            # no requirement for this key at all
            m = cart_meta.get(k, {})
            excess.append({
                "display_name": m.get("display_name",""),
                "unit_lb": float(m.get("unit_lb") or 0.0),
                "size": m.get("size","M"),
                "required": 0,
                "have": int(have),
                "extra": int(have),
            })
    return {"shortages": shortages, "excess": excess}

def _lines_remove_from_cart(cart: dict, lines: List[dict]) -> bool:
    """
    Remove exactly the quantities for 'lines' from cart.lines and cart.contents.
    Returns True on success; False if any line cannot be satisfied.
    """
    if not cart:
        return False
    # index cart lines by key
    idx = {}
    for i, ln in enumerate(list(cart.setdefault("lines", []))):
        dn = (ln.get("display_name") or "").strip()
        try: ulb = float(ln.get("unit_lb") or 0.0)
        except Exception: ulb = 0.0
        sz  = _norm_size(ln.get("size") or "M") or "M"
        k = _line_key(dn, ulb, sz)
        idx.setdefault(k, []).append((i, ln))
    # check feasibility
    need_map = _lines_to_map(lines)
    for k, need in need_map.items():
        have = sum(int(ln.get("qty") or 0) for _, ln in idx.get(k, []))
        if have < int(need):
            return False
    # apply decrements
    for k, need in need_map.items():
        left = int(need)
        buckets = idx.get(k, [])
        j = 0
        while left > 0 and j < len(buckets):
            i, ln = buckets[j]
            q = int(ln.get("qty") or 0)
            take = min(q, left)
            ln["qty"] = q - take
            if ln["qty"] <= 0:
                # will clean up after loop
                pass
            # also reduce numeric manifest bins
            sz = _norm_size(ln.get("size") or "M") or "M"
            _manifest_add(cart.setdefault("contents", {}), "box", sz, -take)
            left -= take
            j += 1
        # safety; should never trigger due to feasibility check
        if left > 0:
            return False
    # purge zero-qty lines
    cart["lines"] = [ln for ln in cart.get("lines", []) if int(ln.get("qty") or 0) > 0]
    # clear previews (visual polish)
    cart["preview"] = []
    return True

def _manifest_string(lines: List[dict]) -> str:
    """
    "Manifest: NAME UNIT_LB lb×QTY; ..." (order preserved).
    """
    parts = []
    for ln in list(lines or []):
        dn = (ln.get("display_name") or "").strip()
        try:
            ulb = float(ln.get("unit_lb") or 0.0)
            # trim floats like 10.0 -> 10
            ulb_str = str(int(ulb)) if abs(ulb - int(ulb)) < 1e-6 else f"{ulb:g}"
        except Exception:
            ulb_str = "0"
        qty = int(ln.get("qty") or 0)
        if dn and qty > 0:
            parts.append(f"{dn} {ulb_str} lb×{qty}")
    return "Manifest: " + "; ".join(parts) if parts else "Manifest:"

# 1) GET /api/wargame/outbound_flights
@bp.get("/api/wargame/outbound_flights")
def api_outbound_flights():
    """
    Returns outbound candidates (soonest first) with has_manifest.
    Mirrors inbound_flights but filters kind='outbound'.
    """
    with _connect_sqlite() as c:
        tasks_table = _guess_tasks_table(c)
        # Schema-aware: tasks.complete may not exist
        has_task_complete = _has_column(c, tasks_table, "complete")
        sql_tasks = f"SELECT key FROM {tasks_table} WHERE role = ? AND kind = ?"
        params = ["ramp", "outbound"]
        if has_task_complete:
            sql_tasks += " AND COALESCE(complete,0) = 0"
        _log_info("wgapi.outbound_flights.tasks_query", has_task_complete=has_task_complete, tasks_table=tasks_table)
        cur = c.execute(sql_tasks, params)
        keys = [row["key"] for row in cur.fetchall() if row and row["key"]]
        flight_ids = []
        for k in keys:
            fid = _key_to_flight_id(k)
            if fid is not None:
                flight_ids.append(fid)
        if not flight_ids:
            return jsonify({"flights": []})

        # Schema-aware: flights.complete may not exist
        has_flight_complete = _has_column(c, "flights", "complete")
        cols = (
            "id, tail_number, airfield_takeoff, airfield_landing, "
            "pilot, pax, eta, cargo_type, cargo_weight, remarks"
        )
        if has_flight_complete:
            cols += ", complete"
        else:
            cols += ", 0 AS complete"
        _log_info(
            "wgapi.outbound_flights.flights_query",
            has_flight_complete=has_flight_complete
        )

        placeholders = ",".join("?" for _ in flight_ids)
        cur = c.execute(
            f"SELECT {cols} FROM flights WHERE id IN ({placeholders}) ORDER BY eta ASC, tail_number ASC",
            flight_ids,
        )
        flights = []
        for f in cur.fetchall():
            remarks = (f["remarks"] or "") if f["remarks"] is not None else ""
            try:
                has_manifest = bool(parse_adv_manifest(remarks))
            except Exception:
                has_manifest = bool(remarks)
            flights.append({
                "id": f["id"],
                "tail_number": f["tail_number"],
                "airfield_takeoff": f["airfield_takeoff"],
                "airfield_landing": f["airfield_landing"],
                "pilot": f["pilot"],
                "pax": int(f["pax"] or 0),
                "eta": _iso_or_raw(f["eta"]),
                "cargo_type": f["cargo_type"],
                "cargo_weight": int(f["cargo_weight"] or 0),
                "has_manifest": has_manifest,
                "complete": bool(f["complete"]),
            })
        return jsonify({"flights": flights})

# 2) POST /api/wargame/plane/pin
@bp.post("/api/wargame/plane/pin")
def api_plane_pin():
    data = request.get_json(force=True) or {}
    # Strict: accept only positive ints (2/"2"/"plane:2"/"plane#2") → "plane:2"
    plane_id   = _canon_plane_id_or_none(data.get("plane_id"))
    if not plane_id:
        return jsonify({"error": "bad_plane_id"}), 400
    session_id = int(data.get("session_id") or 1)
    player_id  = int(data.get("player_id") or 0)

    # 🔒 Step 1: pin strictly by REQUEST, not by flight/queue.
    # Normalize and enforce presence of request_id.
    flight_ref = _normalize_flight_ref(data)  # may include request_id / queue_id / flight_id
    request_id = flight_ref.get("request_id")
    if request_id is None:
        # Also accept explicit "request" or "requestId" aliases if present
        for alias in ("request", "requestId"):
            if alias in data and str(data[alias]).isdigit():
                request_id = int(data[alias])
                break
    if request_id is None:
        return jsonify({"error": "bad_request_ref"}), 400
    # Resolve required lines for this request only
    required = _plane_compute_required({"request_id": int(request_id)}) or []
    if not required:
        # Return a tiny bit of echo to help manual debugging in dev tools
        return jsonify({
            "error": "missing_manifest",
            "ref_echo": {"request_id": request_id},
            "plane_id": plane_id
        }), 400
    with LOCK:
        _ensure_session(session_id)
        pin = _plane_pin_get(plane_id)
        # Store only request_id going forward (request-only pin policy)
        pin["flight_ref"] = {"request_id": int(request_id)}
        pin["pinned_by"]  = player_id or None
        pin["pinned_at"]  = _utc_iso()
        pin["required"]   = required
        pin["status"]     = "pinned"
        pin["cart_id"]    = None
        pin["loaded_manifest"] = []
        pin["paperwork"]  = {"url": None, "html_path": None, "pdf_path": None}
        # Telemetry: plane_select
        try:
            _append_claim(session_id, _make_claim(
                "plane_select", plane_id=plane_id, player_id=player_id, flight_ref=pin["flight_ref"]
            ))
        except Exception: pass
        return jsonify({"ok": True, "pin": pin})

# 3) GET /api/wargame/plane/status
@bp.get("/api/wargame/plane/status")
def api_plane_status():
    plane_id   = _canon_plane_id_or_none(request.args.get("plane_id"))
    if not plane_id:
        return jsonify({"error": "bad_plane_id"}), 400
    try:
        session_id = int(request.args.get("session_id") or 1)
    except Exception:
        session_id = 1
    cart_id    = request.args.get("cart_id")
    with LOCK:
        _ensure_session(session_id)
        pin = _plane_pin_get(plane_id)
        required = list(pin.get("required") or [])
        # if no selection yet
        if not pin.get("flight_ref"):
            return jsonify({"error": "no_selection"}), 400
        cart = _find_or_create_cart(session_id, cart_id or pin.get("cart_id") or "cart:0")
        # compute diff
        diff = _diff_required_vs_cart(required, cart)
        exact = (len(diff["shortages"]) == 0 and len(diff["excess"]) == 0)
        # update pin status + cart_id
        pin["cart_id"] = cart.get("id")
        if exact:
            pin["status"] = "ready"
        elif pin.get("status") == "ready":
            # if cart changed and no longer exact, fall back to pinned
            pin["status"] = "pinned"
        return jsonify({"pin": pin, "diff": diff, "status": pin.get("status")})

# 4) POST /api/wargame/plane/load
@bp.post("/api/wargame/plane/load")
def api_plane_load():
    data = request.get_json(force=True) or {}
    plane_id   = _canon_plane_id_or_none(data.get("plane_id"))
    if not plane_id:
        return jsonify({"error": "bad_plane_id"}), 400
    try:
        session_id = int(data.get("session_id") or 1)
    except Exception:
        session_id = 1
    cart_id    = data.get("cart_id") or "cart:0"
    player_id  = int(data.get("player_id") or 0)

    with LOCK:
        _ensure_session(session_id)
        pin = _plane_pin_get(plane_id)
        if not pin.get("flight_ref"):
            return jsonify({"error": "no_selection"}), 400
        required = list(pin.get("required") or [])
        cart = _find_or_create_cart(session_id, cart_id)
        # validate exact match at load time
        diff = _diff_required_vs_cart(required, cart)
        if diff["shortages"] or diff["excess"]:
            # Telemetry attempt (mismatch)
            try:
                _append_claim(session_id, _make_claim(
                    "plane_load", plane_id=plane_id, player_id=player_id,
                    flight_ref=pin.get("flight_ref"), cart_id=cart.get("id"),
                    diff=diff
                ))
            except Exception: pass
            return jsonify({"error": "mismatch", "diff": diff}), 409
        # remove from cart
        if not _lines_remove_from_cart(cart, required):
            # unexpected underflow; re-check and fail safe
            try:
                _append_claim(session_id, _make_claim("plane_load", plane_id=plane_id, player_id=player_id, flight_ref=pin.get("flight_ref"), cart_id=cart.get("id"), diff=_diff_required_vs_cart(required, cart)))
            except Exception: pass
            return jsonify({"error": "mismatch", "diff": _diff_required_vs_cart(required, cart)}), 409
        # freeze manifest and mark loaded
        pin["loaded_manifest"] = required
        pin["status"] = "loaded"
        pin["cart_id"] = cart.get("id")
        # prepare paperwork stub
        manifest_str = _manifest_string(required)
        pin["paperwork"] = {
            "url": "/ramp_boss",
            "html_path": None,
            "pdf_path": None,
            "manifest_string": manifest_str,
            "prepared_at": _utc_iso(),
            "prepared_by": player_id or None,
        }
        return jsonify({
            "ok": True,
            "pin": pin,
            "paperwork_url": "/ramp_boss",
        })
        # Telemetry (success) — note: this will not run due to the early return above.
        # Keeping for clarity if return structure ever changes:
        # try:
        #     _append_claim(session_id, _make_claim("plane_load", plane_id=plane_id, player_id=player_id, flight_ref=pin.get("flight_ref"), cart_id=cart.get("id")))
        # except Exception: pass

# 5) POST /api/wargame/plane/paperwork_complete
@bp.post("/api/wargame/plane/paperwork_complete")
def api_plane_paperwork_complete():
    data = request.get_json(force=True) or {}
    plane_id   = _canon_plane_id_or_none(data.get("plane_id"))
    if not plane_id:
        return jsonify({"error": "bad_plane_id"}), 400
    try:
        session_id = int(data.get("session_id") or 1)
    except Exception:
        session_id = 1
    player_id = int(data.get("player_id") or 0)
    with LOCK:
        _ensure_session(session_id)
        pin = _plane_pin_get(plane_id)
        if pin.get("status") != "loaded":
            return jsonify({"error": "not_ready"}), 400
        # Telemetry: paperwork_complete (capture before clearing)
        try:
            _append_claim(session_id, _make_claim(
                "paperwork_complete",
                plane_id=plane_id,
                player_id=player_id,
                flight_ref=pin.get("flight_ref")
            ))
        except Exception: pass
        # return plane to idle and clear selection
        _plane_pin_clear(plane_id)
        return jsonify({"ok": True, "pin": _plane_pin_get(plane_id)})

# 6) POST /api/wargame/plane/unselect  (restored from v1)
@bp.post("/api/wargame/plane/unselect")
def api_plane_unselect():
    data = request.get_json(force=True) or {}
    plane_id   = _canon_plane_id_or_none(data.get("plane_id"))
    if not plane_id:
        return jsonify({"error": "bad_plane_id"}), 400
    try:
        session_id = int(data.get("session_id") or 1)
    except Exception:
        session_id = 1
    player_id = int(data.get("player_id") or 0)
    force = str(data.get("force") or "false").strip().lower() in ("1","true","yes")
    with LOCK:
        _ensure_session(session_id)
        pin = _plane_pin_get(plane_id)
        if pin.get("status") == "paperwork" and not force:
            return jsonify({"ok": False, "error": "paperwork_lock"}), 409
        # Telemetry: plane_unselect (report the last flight_ref before clearing)
        try:
            _append_claim(session_id, _make_claim(
                "plane_unselect",
                plane_id=plane_id,
                player_id=player_id,
                flight_ref=pin.get("flight_ref")
            ))
        except Exception: pass
        _plane_pin_clear(plane_id)
        return jsonify({"ok": True, "pin": {"status": "idle"}})
