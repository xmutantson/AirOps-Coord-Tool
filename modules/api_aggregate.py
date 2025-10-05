# modules/api_aggregate.py
from __future__ import annotations

import os
import json
import time
import hashlib
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Tuple

from flask import Blueprint, jsonify, make_response, request

# Only import SAFE utilities (no writers) and the DB path helper.
from modules.utils.common import get_db_file

aggregate_bp = Blueprint("aggregate", __name__)

# ----------------------- Config (env-driven) --------------------------------
# Rate limit: requests per minute per IP (0 disables). Example: AGG_LIMIT_RPM=120
_AGG_LIMIT_RPM = int(os.getenv("AGG_LIMIT_RPM", "0") or 0)
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

# In-memory, best-effort per-process limiter (simple + dependency-free).
# For multi-process / multi-host deployments, put a reverse-proxy rate limit in front.
_RL_HITS: Dict[str, List[float]] = {}
_RL_WINDOW_S = 60.0


def _check_rate_limit(ip: str) -> int | None:
    if _AGG_LIMIT_RPM <= 0:
        return None
    now = time.time()
    bucket = _RL_HITS.setdefault(ip, [])
    # prune old
    cutoff = now - _RL_WINDOW_S
    i = 0
    for t in bucket:
        if t >= cutoff:
            break
        i += 1
    if i:
        del bucket[:i]
    # check
    if len(bucket) >= _AGG_LIMIT_RPM:
        return int(max(1, cutoff + _RL_WINDOW_S - now))  # seconds until window clears
    bucket.append(now)
    return None


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
    # Optional: basic per-IP rate limit (process-local)
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0").split(",")[0].strip()
    retry_in = _check_rate_limit(ip)
    if retry_in is not None:
        resp = make_response(jsonify({"error": "rate_limited", "retry_after_s": retry_in}), 429)
        resp.headers["Retry-After"] = str(retry_in)
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

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
