# modules/api_aggregate.py
from __future__ import annotations

import os
import json
import hashlib
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Tuple

from flask import Blueprint, jsonify, make_response, request

# Only import SAFE utilities (no writers) and the DB path helper.
from modules.utils.common import get_db_file, canonical_airport_code
from modules.utils.common import (
    cr2_get_ramp_summary,
    cr2_get_airport_detail,
    cr2_delete_group,
    cr2_delete_airport,
    PRIORITY_LABELS,  # kept for parity with your diff (unused here but harmless)
    dict_rows,
)
from modules.services.webeoc.ingest_rr import parse_saved_data, ingest_items
from modules.utils.comms import insert_comm

aggregate_bp = Blueprint("aggregate", __name__)

# ----------------------- Config (env-driven) --------------------------------
# ADS-B default cap when no explicit tails are requested
_AGG_ADSB_MAX = int(os.getenv("AGG_ADSB_MAX", "200") or 200)

# Default sections if client doesn't pass ?sections=...
# Override with AGG_DEFAULT_SECTIONS (comma-separated).
_AGG_DEFAULT_SECTIONS = (
    os.getenv(
        "AGG_DEFAULT_SECTIONS",
        # sensible “kitchen sink” default for analytics; adjust in env if you want fewer
        "flights,inventory,cargo_requests,aircraft,staff,comms,locates,queues,adsb,preferences"
    ).strip()
)
# Preferences whitelist (safe keys only). Override with AGG_PREFS_ALLOW=key1,key2,...
_AGG_PREFS_ALLOW = {
    k.strip()
    for k in (os.getenv("AGG_PREFS_ALLOW", "") or
              "mission_number,embedded_url,embedded_name,embedded_mode,"
              "wargame_mode,show_debug_logs,enable_1090_distances").split(",")
    if k.strip()
}

# ----------------------- Read-only DB helpers -------------------------------
def _ro_connect(timeout: int = 30) -> sqlite3.Connection:
    # Always open SQLite in read-only mode
    db = get_db_file()
    uri = f"file:{db}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=timeout)
    conn.row_factory = sqlite3.Row
    return conn


def _rows(conn: sqlite3.Connection, sql: str, params: Tuple[Any, ...] = ()) -> List[dict]:
    cur = conn.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]

def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    try:
        cur = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (name,)
        )
        return cur.fetchone() is not None
    except Exception:
        return False

def _table_columns(conn: sqlite3.Connection, name: str) -> List[str]:
    try:
        cur = conn.execute(f"PRAGMA table_info({name})")
        return [str(r["name"]) for r in cur.fetchall()]
    except Exception:
        return []

def _ordered_select_all(conn: sqlite3.Connection, tbl: str, limit: int,
                        order_candidates: List[str] | None = None) -> List[dict]:
    cols = _table_columns(conn, tbl)
    order_col = None
    for c in (order_candidates or []):
        if c in cols:
            order_col = c
            break
    # Always safe fallback
    if order_col:
        sql = f"SELECT * FROM {tbl} ORDER BY {order_col} ASC LIMIT ?"
    else:
        # ORDER BY rowid keeps it deterministic-ish without schema assumptions
        sql = f"SELECT * FROM {tbl} ORDER BY rowid ASC LIMIT ?"
    return _rows(conn, sql, (int(limit),))

# ----------------------- Section fetchers (all read-only) -------------------
def _fetch_flights(conn: sqlite3.Connection, *, open_only: bool, since_iso: str | None, limit: int) -> List[dict]:
    where = []
    args: List[Any] = []
    if open_only:
        where.append("complete=0")
    if since_iso:
        where.append("IFNULL(timestamp,'') >= ?")
        args.append(since_iso)
    sql = f"""
      SELECT id, tail_number, airfield_takeoff, takeoff_time,
             airfield_landing, eta, cargo_type, cargo_weight, cargo_weight_real,
             remarks, direction, is_ramp_entry, sent, complete, timestamp, flight_code
        FROM flights
       {"WHERE " + " AND ".join(where) if where else ""}
       ORDER BY IFNULL(timestamp,'') DESC, id DESC
       LIMIT ?
    """
    args.append(int(limit))
    return _rows(conn, sql, tuple(args))


def _fetch_inventory_snapshot(conn: sqlite3.Connection, *, limit: int) -> List[dict]:
    # Net on-hand by (name,size), pending suppressed
    sql = """
      SELECT
        sanitized_name AS name,
        ROUND(weight_per_unit, 3) AS size_lb,
        CAST(SUM(CASE WHEN direction='in'  THEN quantity
                      WHEN direction='out' THEN -quantity END) AS INTEGER) AS qty,
        ROUND(SUM(CASE WHEN direction='in'  THEN total_weight
                       WHEN direction='out' THEN -total_weight END), 3) AS net_weight_lb
      FROM inventory_entries
      WHERE pending=0
      GROUP BY sanitized_name, weight_per_unit
      HAVING ABS(qty) > 0
      ORDER BY name ASC, size_lb ASC
      LIMIT ?
    """
    return _rows(conn, sql, (int(limit),))


def _fetch_cargo_requests(conn: sqlite3.Connection, *, limit: int) -> List[dict]:
    sql = """
      SELECT airport_canon, sanitized_name AS name,
             ROUND(requested_lb, 1) AS requested_lb,
             ROUND(fulfilled_lb, 1) AS fulfilled_lb,
             ROUND(requested_lb - fulfilled_lb, 1) AS remaining_lb,
             updated_at
        FROM cargo_requests
       ORDER BY airport_canon ASC, remaining_lb DESC
       LIMIT ?
    """
    return _rows(conn, sql, (int(limit),))


def _fetch_ramp_requests(conn: sqlite3.Connection, *, limit: int) -> List[dict]:
    sql = """
      SELECT id, created_at, destination, requested_weight, manifest, satisfied_at, assigned_tail
        FROM wargame_ramp_requests
       ORDER BY (satisfied_at IS NULL) DESC, created_at DESC
       LIMIT ?
    """
    return _rows(conn, sql, (int(limit),))


def _fetch_inbound_schedule(conn: sqlite3.Connection, *, limit: int) -> List[dict]:
    sql = """
      SELECT id, tail_number, airfield_takeoff, airfield_landing,
             scheduled_at, eta, cargo_type, cargo_weight, manifest
        FROM wargame_inbound_schedule
       ORDER BY eta ASC
       LIMIT ?
    """
    return _rows(conn, sql, (int(limit),))


def _fetch_radio_queue(conn: sqlite3.Connection, *, limit: int) -> List[dict]:
    sql = """
      SELECT generated_at, scheduled_for, message_id, size_bytes,
             source, sender, recipient, subject, body
        FROM wargame_radio_schedule
       ORDER BY scheduled_for ASC, generated_at ASC
       LIMIT ?
    """
    return _rows(conn, sql, (int(limit),))


def _fetch_weather_meta(conn: sqlite3.Connection, *, limit: int) -> List[dict]:
    sql = """
      SELECT key, display_name, mime,
             received_at_utc, updated_at_utc,
             content_hash AS etag,
             LENGTH(content) AS size_bytes
        FROM weather_products
       ORDER BY updated_at_utc DESC
       LIMIT ?
    """
    return _rows(conn, sql, (int(limit),))


def _fetch_remote_inventory(conn: sqlite3.Connection, *, limit: int) -> List[dict]:
    sql = """
      SELECT airport_canon, snapshot_at, received_at, summary_text
        FROM remote_inventory
       ORDER BY received_at DESC
       LIMIT ?
    """
    return _rows(conn, sql, (int(limit),))


def _fetch_adsb_latest(conn: sqlite3.Connection, *, tails: List[str] | None, max_rows: int) -> List[dict]:
    if tails:
        tails = [t.strip().upper() for t in tails if t.strip()]
        if not tails:
            return []
        placeholders = ",".join("?" for _ in tails)
        sql = f"""
          WITH latest AS (
            SELECT tail, MAX(sample_ts_utc) AS max_ts
              FROM adsb_sightings
             WHERE UPPER(tail) IN ({placeholders})
             GROUP BY tail
          )
          SELECT s.tail, s.sample_ts_utc, s.lat, s.lon, s.track_deg, s.speed_kt, s.alt_ft,
                 s.receiver_airport, s.receiver_call, s.source
            FROM adsb_sightings s
            JOIN latest L ON s.tail=L.tail AND s.sample_ts_utc=L.max_ts
          ORDER BY s.sample_ts_utc DESC
        """
        return _rows(conn, sql, tuple(tails))
    else:
        # Top-N latest per tail overall
        sql = """
          WITH latest AS (
            SELECT tail, MAX(sample_ts_utc) AS max_ts
              FROM adsb_sightings
             GROUP BY tail
          )
          SELECT s.tail, s.sample_ts_utc, s.lat, s.lon, s.track_deg, s.speed_kt, s.alt_ft,
                 s.receiver_airport, s.receiver_call, s.source
            FROM adsb_sightings s
            JOIN latest L ON s.tail=L.tail AND s.sample_ts_utc=L.max_ts
           ORDER BY s.sample_ts_utc DESC
           LIMIT ?
        """
        return _rows(conn, sql, (int(max_rows),))

def _fetch_aircraft(conn: sqlite3.Connection, *, limit: int) -> List[dict]:
    # Try canonical table first; fall back if not present
    for tbl in ("aircraft", "aircraft_list"):
        if _table_exists(conn, tbl):
            # prefer ordering by tail_number / callsign when present
            return _ordered_select_all(conn, tbl, limit, ["tail_number", "callsign", "id"])
    return []

def _fetch_staff(conn: sqlite3.Connection, *, limit: int) -> List[dict]:
    for tbl in ("duty_roster", "staff_roster", "staff"):
        if _table_exists(conn, tbl):
            return _ordered_select_all(conn, tbl, limit, ["shift_start", "name", "id"])
    return []

def _fetch_comms(conn: sqlite3.Connection, *, since_iso: str | None, limit: int) -> List[dict]:
    # Supports several possible table names; tries to sort by a plausible time column
    for tbl in ("comms", "comms_log", "communications"):
        if _table_exists(conn, tbl):
            cols = set(_table_columns(conn, tbl))
            where = []
            args: List[Any] = []
            # Try common timestamp column names if caller asked for "since"
            ts_col = None
            for c in ("created_at", "timestamp", "ts", "logged_at", "time_utc"):
                if c in cols:
                    ts_col = c
                    break
            if since_iso and ts_col:
                where.append(f"IFNULL({ts_col},'') >= ?")
                args.append(since_iso)
            order_col = ts_col or ("id" if "id" in cols else None)
            sql = f"SELECT * FROM {tbl} "
            if where:
                sql += "WHERE " + " AND ".join(where) + " "
            if order_col:
                sql += f"ORDER BY {order_col} DESC "
            else:
                sql += "ORDER BY rowid DESC "
            sql += "LIMIT ?"
            args.append(int(limit))
            return _rows(conn, sql, tuple(args))
    return []

def _fetch_locates(conn: sqlite3.Connection, *, limit: int) -> List[dict]:
    for tbl in ("locate_requests", "locates", "flight_locates"):
        if _table_exists(conn, tbl):
            # Order by “newest first” if we can guess the ts column
            cols = _table_columns(conn, tbl)
            order_col = None
            for c in ("requested_at", "created_at", "timestamp", "ts", "id"):
                if c in cols:
                    order_col = c
                    break
            if order_col:
                sql = f"SELECT * FROM {tbl} ORDER BY {order_col} DESC LIMIT ?"
            else:
                sql = f"SELECT * FROM {tbl} ORDER BY rowid DESC LIMIT ?"
            return _rows(conn, sql, (int(limit),))
    return []

def _fetch_preferences(conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    Export a {key: value} map from the `preferences` table, tolerating schema differences.
    Tries common key/value column names; if not found, returns {}.
    """
    if not _table_exists(conn, "preferences"):
        return {}
    cols = set(_table_columns(conn, "preferences"))
    key_candidates = ("key", "name", "pref", "preference", "pref_key")
    val_candidates = ("value", "val", "setting", "pref_value", "data", "json_value", "text")
    key_col = next((c for c in key_candidates if c in cols), None)
    val_col = next((c for c in val_candidates if c in cols), None)
    if not key_col or not val_col:
        # No sensible pair to export
        return {}
    sql = f"SELECT {key_col} AS k, {val_col} AS v FROM preferences LIMIT 10000"
    rows = _rows(conn, sql)
    out: Dict[str, Any] = {}
    for r in rows:
        k = (r.get("k") or "").strip()
        if not k or k not in _AGG_PREFS_ALLOW:
            continue
        out[k] = r.get("v")
    return out

def _fetch_queues(conn: sqlite3.Connection, *, limit: int) -> Dict[str, Any]:
    # Compose known queues under one section
    return {
        "radio": _fetch_radio_queue(conn, limit=limit),
        "ramp": _fetch_ramp_requests(conn, limit=limit),
    }

# ----------------------- The endpoint ---------------------------------------
@aggregate_bp.route("/", methods=["GET"])
def get_aggregate():
    # Parse params
    sections = [s.strip().lower() for s in (request.args.get("sections") or _AGG_DEFAULT_SECTIONS).split(",") if s.strip()]
    if "all" in sections or "*" in sections:
        # expand to everything we know how to serve
        sections = [
            "flights","inventory","cargo_requests","aircraft","staff","comms",
            "locates","queues","ramp","inbound","radio","weather","remote","adsb","preferences"
        ]
    limit = int(request.args.get("limit", "500") or 500)
    open_only = (request.args.get("open", "1") in ("1", "true", "yes"))
    since_iso = request.args.get("since") or None
    adsb_max = int(request.args.get("adsb_max", str(_AGG_ADSB_MAX)) or _AGG_ADSB_MAX)
    tails_arg = request.args.get("tails") or ""
    tails = [t for t in tails_arg.split(",")] if tails_arg else None

    payload: Dict[str, Any] = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "sections": {},
        "params": {
            "sections": sections,
            "limit": limit,
            "open": open_only,
            "since": since_iso,
            "adsb_max": adsb_max,
            "tails": tails or [],
        },
    }

    # Collect data (all read-only)
    with _ro_connect() as conn:
        if "flights" in sections:
            payload["sections"]["flights"] = _fetch_flights(conn, open_only=open_only, since_iso=since_iso, limit=limit)
        if "inventory" in sections:
            payload["sections"]["inventory"] = _fetch_inventory_snapshot(conn, limit=limit)
        if "cargo_requests" in sections:
            payload["sections"]["cargo_requests"] = _fetch_cargo_requests(conn, limit=limit)
        if "aircraft" in sections:
            payload["sections"]["aircraft"] = _fetch_aircraft(conn, limit=limit)
        if "staff" in sections:
            payload["sections"]["staff"] = _fetch_staff(conn, limit=limit)
        if "comms" in sections:
            payload["sections"]["comms"] = _fetch_comms(conn, since_iso=since_iso, limit=limit)
        if "locates" in sections:
            payload["sections"]["locates"] = _fetch_locates(conn, limit=limit)
        if "queues" in sections:
            payload["sections"]["queues"] = _fetch_queues(conn, limit=limit)
        if "ramp" in sections:
            payload["sections"]["ramp"] = _fetch_ramp_requests(conn, limit=limit)
        if "inbound" in sections:
            payload["sections"]["inbound"] = _fetch_inbound_schedule(conn, limit=limit)
        if "radio" in sections:
            payload["sections"]["radio"] = _fetch_radio_queue(conn, limit=limit)
        if "weather" in sections:
            payload["sections"]["weather"] = _fetch_weather_meta(conn, limit=limit)
        if "remote" in sections:
            payload["sections"]["remote"] = _fetch_remote_inventory(conn, limit=limit)
        if "adsb" in sections:
            payload["sections"]["adsb"] = _fetch_adsb_latest(conn, tails=tails, max_rows=adsb_max)
        if "preferences" in sections:
            payload["sections"]["preferences"] = _fetch_preferences(conn)

    # Strong-ish ETag from a stable serialization (compact, sorted)
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    etag = 'W/"agg-%s"' % hashlib.sha256(body).hexdigest()[:32]

    inm = request.headers.get("If-None-Match")
    if inm and inm == etag:
        resp = make_response("", 304)
    else:
        resp = make_response(body, 200)
        resp.headers["Content-Type"] = "application/json; charset=utf-8"

    # CORS for Power BI / external tools
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["ETag"] = etag
    # Light caching to enable conditional GETs to work nicely
    resp.headers["Cache-Control"] = "public, max-age=5, must-revalidate"
    return resp

# ----------------------- Cargo Requests v2 (read-only) ----------------------
@aggregate_bp.route("/ramp/v2", methods=["GET"])
def ramp_v2_summary():
    """JSON: [{airport, max_pri, has_life_saving, outstanding_lb}]"""
    return jsonify(cr2_get_ramp_summary())

@aggregate_bp.route("/ramp/v2/<string:airport>", methods=["GET"])
def ramp_v2_airport_detail(airport: str):
    """
    JSON: [{'priority_code','priority_label','need','requested_lb','shipped_lb','outstanding_lb','sources':[...]}]
    """
    return jsonify(cr2_get_airport_detail(airport))

# POST /inventory/requests/import/webeoc
@aggregate_bp.post("/inventory/requests/import/webeoc")
def inventory_requests_import_webeoc():
    text = (request.form.get("payload") or "").strip()
    # Whatever the user typed when asked for "ICAO-4" — we will normalize again on the server.
    user_airport_entry = (request.form.get("icao4") or
                          request.form.get("airport") or
                          request.form.get("airport_override") or "").strip()
    if not text:
        return jsonify({"ok": False, "errors": ["missing payload"]}), 400
    parsed = parse_saved_data(text)
    errs   = parsed.get("errors") or []
    items  = parsed.get("items") or []

    # If no items but user provided an override, try to inject and reparse.
    if not items and user_airport_entry:
        try:
            norm = (canonical_airport_code(user_airport_entry) or user_airport_entry.strip().upper())
            raw0 = json.loads(text)
            if isinstance(raw0, dict):
                raw2 = dict(raw0); raw2.setdefault("Input20", norm)
                reparsed = parse_saved_data(json.dumps(raw2, ensure_ascii=False))
                if (reparsed.get("items") or []):
                    parsed, items, errs = reparsed, (reparsed.get("items") or []), (reparsed.get("errors") or [])
        except Exception:
            pass

    if not items:
        # Still nothing usable → hard fail
        return jsonify({"ok": False, "errors": (errs or ["no valid items"])}), 400

    # Create a single Comms entry for the successful import
    comm_id = insert_comm(
        timestamp_utc=None,
        method="Resource Request (WebEOC)",
        direction="in",
        from_party=None,
        to_party=None,
        subject="RR — WebEOC import",
        body="Imported WebEOC saved-data payload.",
        operator=None,
        notes=None,
        metadata={"kind":"resource_request"}
    )
    added = ingest_items(
        items, parsed.get("raw") or {},
        source_comm_id=comm_id,
        airport_override=(user_airport_entry or None),
        allow_raw_airport=True,    # ← non-blocking fallback
    )
    # include a tiny hint for the UI (optional)
    hint_in  = user_airport_entry or ""
    hint_icao= canonical_airport_code(hint_in) if hint_in else None
    return jsonify({
        "ok": True,
        "comm_id": comm_id,
        "inserted_count": int(added),
        "warnings": errs,  # non-fatal parse issues (if any)
        "airport_hint": {
            "input": hint_in,
            "icao4": hint_icao,
            "normalized": bool(hint_icao),
            "label_used": (hint_icao or hint_in or "").upper() if (hint_in or hint_icao) else None
        }
    })

@aggregate_bp.get("/airports/normalize")
def airports_normalize():
    """
    Live preview helper:
      GET /aggregate/airports/normalize?q=ANYTHING
    Returns: {"input": str, "icao4": str|None, "normalized": bool, "label": str}
    """
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"input": "", "icao4": None, "normalized": False, "label": ""})
    icao = canonical_airport_code(q)
    label = (icao or q).strip().upper()
    return jsonify({"input": q, "icao4": icao, "normalized": bool(icao), "label": label})

# GET /inventory/requests/agg.json
@aggregate_bp.get("/inventory/requests/agg.json")
def inventory_requests_agg():
    airports = dict_rows("""
      SELECT airport_canon AS airport, MAX(priority_code) AS highest_priority
        FROM cargo_requests_v2
       GROUP BY airport_canon
    """)
    result = {"airports": []}
    for a in airports:
        ap = a["airport"]
        groups = []
        for g in cr2_get_airport_detail(ap):
            group_id = f"{ap}|{int(g['priority_code'])}|{g['need']}"
            need_label = (g["need"] or "").strip().title()
            src_ids = [int(s["id"]) for s in (g.get("sources") or [])]
            comm_ids = sorted({int(s["comm_id"]) for s in (g.get("sources") or []) if s.get("comm_id")})
            groups.append({
                "group_id": group_id,
                "priority_code": int(g["priority_code"]),
                "need_label": need_label,
                "need_sanitized": g["need"],
                "requested_lb": g["requested_lb"],
                "unknown_qty_count": g.get("unknown_qty_count", 0),
                "shipped_lb": g["shipped_lb"],
                "outstanding_lb": g["outstanding_lb"],
                "deliver_to": ap,
                "source_request_ids": src_ids,
                "source_comm_ids": comm_ids,
            })
        groups.sort(key=lambda r: (-int(r["priority_code"]), r["need_label"]))
        result["airports"].append({
            "airport": ap,
            "highest_priority": int(a["highest_priority"] or 1),
            "groups": groups
        })
    result["airports"].sort(key=lambda r: (-int(r["highest_priority"]), r["airport"]))
    return jsonify(result)

# GET /inventory/requests/group/<group_id>.json
@aggregate_bp.get("/inventory/requests/group/<path:group_id>.json")
def inventory_requests_group(group_id: str):
    try:
        ap, pri, need = group_id.split("|", 2)
        pri = int(pri)
    except Exception:
        return jsonify({"ok": False, "error": "bad group_id"}), 400
    rows = cr2_get_airport_detail(ap)
    match = next((r for r in rows if int(r["priority_code"])==pri and r["need"]==need), None)
    if not match:
        return jsonify({"ok": True, "rows": [], "unknown_qty_count": 0})
    sources = dict_rows("""
      SELECT l.qty_lb AS qty_lb, s.id AS id, s.source_comm_id AS comm_id, s.source_ref AS ref
        FROM cargo_request_links l
        JOIN cargo_request_sources s ON s.id = l.source_id
       WHERE l.airport_canon=? AND l.priority_code=? AND l.need_sanitized=?
       ORDER BY s.id DESC
    """, (ap, pri, need))
    return jsonify({
        "ok": True,
        "unknown_qty_count": int(match.get("unknown_qty_count") or 0),
        "rows": [
            {"id": int(r["id"]), "comm_id": r["comm_id"], "ref": r["ref"], "qty_lb": r["qty_lb"]}
            for r in sources
        ]
    })

# ----------------------- Cargo Requests v2 DELETE endpoints -------------------
@aggregate_bp.route("/ramp/v2/<string:airport>/<int:priority>/<path:need>", methods=["DELETE", "POST"])
def ramp_v2_delete_group(airport: str, priority: int, need: str):
    """
    Delete a specific cargo request group.
    DELETE /aggregate/ramp/v2/KBLI/1/water
    POST with ?_method=DELETE also works for browsers.
    """
    # Allow POST with _method=DELETE for browsers that don't support DELETE
    if request.method == "POST" and request.args.get("_method", "").upper() != "DELETE":
        return jsonify({"ok": False, "error": "use DELETE method or ?_method=DELETE"}), 405
    deleted = cr2_delete_group(airport, priority, need)
    return jsonify({"ok": True, "deleted": deleted})

@aggregate_bp.route("/ramp/v2/<string:airport>/all", methods=["DELETE", "POST"])
def ramp_v2_delete_airport(airport: str):
    """
    Delete all cargo requests for an airport.
    DELETE /aggregate/ramp/v2/KBLI/all
    POST with ?_method=DELETE also works for browsers.
    """
    if request.method == "POST" and request.args.get("_method", "").upper() != "DELETE":
        return jsonify({"ok": False, "error": "use DELETE method or ?_method=DELETE"}), 405
    deleted = cr2_delete_airport(airport)
    return jsonify({"ok": True, "deleted": deleted})
