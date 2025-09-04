# modules/utils/comms.py
# Unified Communications utilities for AOCT
# - Schema creation (idempotent)
# - Insert helper with light validation & UTC coercion
# - List/filter helper for views
# - (CSV projection removed; use /exports/communications.csv)
#
# Canonical metadata keys written into `metadata_json` (when present):
#   - tail_number   : "N123AB" (aircraft tail)
#   - flight_code   : any free-form flight/mission code
#   - operator_call : operator/callsign string
#   - wgid          : optional wargame id (if applicable)
#   - source        : producer hint (e.g. "winlink_rx", "radio_ui", "manual_comms")
# Keep additions small and snake_case; exporters treat `metadata_json` as an opaque string.

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple
import json
import sqlite3
from datetime import datetime, timezone, timedelta

# Reuse common app helpers (db path, ISO utils, small validators)
from modules.utils.common import (
    get_db_file,
    dict_rows,
    blankish_to_none,
    iso8601_ceil_utc,
)

# ──────────────────────────────────────────────────────────────────────────────
# Schema (idempotent)

DDL_COMMUNICATIONS = """
CREATE TABLE IF NOT EXISTS communications (
  id INTEGER PRIMARY KEY,
  timestamp_utc TEXT NOT NULL,
  method TEXT NOT NULL,
  direction TEXT,
  from_party TEXT,
  to_party TEXT,
  subject TEXT,
  body TEXT,
  related_flight_id INTEGER,
  operator TEXT,
  notes TEXT,
  metadata_json TEXT
);
"""

DDL_COMM_TS_INDEX = "CREATE INDEX IF NOT EXISTS idx_comm_ts ON communications(timestamp_utc);"
DDL_COMM_METHOD_DIR_TS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_comm_method_dir_ts
  ON communications(method, direction, timestamp_utc);
"""
DDL_COMM_FROM_TO_TS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_comm_from_to_ts
  ON communications(from_party, to_party, timestamp_utc);
"""

def ensure_comms_tables() -> None:
    """
    Create the communications table & index if missing.
    Staff tables are owned by modules/utils/staff.py.
    Safe to call many times (startup, first /comms hit, etc.).
    """
    db = get_db_file()
    with sqlite3.connect(db, timeout=30) as c:
        c.execute("PRAGMA busy_timeout=30000;")
        c.execute(DDL_COMMUNICATIONS)
        c.execute(DDL_COMM_TS_INDEX)
        c.execute(DDL_COMM_METHOD_DIR_TS_INDEX)
        c.execute(DDL_COMM_FROM_TO_TS_INDEX)

# ──────────────────────────────────────────────────────────────────────────────
# Inserts & queries
_VALID_DIRECTIONS = {"in", "out", "internal"}

# Public, canonical window options for comms filters
# Used by routes to render ICS-309 headers and to keep behavior consistent.
COMM_WINDOWS: Dict[str, Optional[int]] = {
    "12h": 12,
    "24h": 24,
    "72h": 72,
    "all": None,
}

def parse_comm_filters(req: Any) -> Dict[str, str]:
    """
    Parse request → normalized communications filters.
    Accepts a Flask `request` or any object with `.args` mapping (or a plain dict).
    Returns: {'window','direction','method','q'}
    """
    def _get(qs: Dict[str, str], key: str, default: str = "") -> str:
        v = qs.get(key) if isinstance(qs, dict) else ""
        return (v or default)

    # Support Flask request (preferred) or dict
    if hasattr(req, "args") and hasattr(req.args, "get"):
        gs = req.args
        win = (gs.get("window") or "24h").lower()
        direction = (gs.get("direction") or "any").lower()
        method = (gs.get("method") or "").strip()
        q = (gs.get("q") or "").strip()
    else:
        # treat `req` as a dict-like
        win = (str(_get(req, "window", "24h"))).lower()
        direction = (str(_get(req, "direction", "any"))).lower()
        method = (str(_get(req, "method", ""))).strip()
        q = (str(_get(req, "q", ""))).strip()

    if win not in COMM_WINDOWS:
        win = "24h"
    if direction not in ("in", "out", "any", "both"):
        direction = "any"

    return {"window": win, "direction": direction, "method": method, "q": q}

def sql_for_comm_filters(filters: Dict[str, str]) -> Tuple[str, List[Any]]:
    """
    Build (WHERE SQL, params) for communications filters.
    Matches behavior previously duplicated in routes.
    """
    parts: List[str] = []
    params: List[Any] = []

    hours = COMM_WINDOWS.get(filters.get("window", "24h"), 24)
    if hours is not None:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        parts.append("timestamp_utc >= ?")
        params.append(since)

    method = (filters.get("method") or "").strip()
    if method:
        parts.append("method = ?")
        params.append(method)

    direction = (filters.get("direction") or "").lower()
    if direction in ("in", "out"):
        parts.append("direction = ?")
        params.append(direction)

    q = filters.get("q") or ""
    if q:
        like = f"%{q}%"
        parts.append("("
                     "IFNULL(subject,'') LIKE ? OR "
                     "IFNULL(body,'') LIKE ? OR "
                     "IFNULL(from_party,'') LIKE ? OR "
                     "IFNULL(to_party,'') LIKE ? OR "
                     "IFNULL(operator,'') LIKE ?"
                     ")")
        params += [like, like, like, like, like]

    where_sql = ("WHERE " + " AND ".join(parts)) if parts else ""
    return where_sql, params


def _coerce_iso_utc(value: Optional[str]) -> str:
    """
    Accepts:
      • None -> now (UTC, second-precision, 'Z')
      • ISO8601 string -> normalized to UTC 'Z' (second-precision)
      • Any other -> raises ValueError
    """
    if not value:
        return iso8601_ceil_utc()

    s = str(value).strip()
    # If it already ends with 'Z' or an offset, try parse→UTC normalize
    try:
        # datetime.fromisoformat handles 'YYYY-MM-DDTHH:MM:SS[.ffffff][±HH:MM]'
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        # ceil to whole second for stable keys
        out = dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        return out
    except Exception:
        # last-ditch: if only a plain 'YYYY-MM-DD HH:MM:SS' → assume UTC
        try:
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        except Exception as e:
            raise ValueError(f"timestamp_utc is not ISO8601: {s}") from e


def _norm_direction(d: Optional[str]) -> Optional[str]:
    if not d:
        return None
    v = str(d).strip().lower()
    return v if v in _VALID_DIRECTIONS else None


def _as_metadata_text(meta: Any) -> Optional[str]:
    if meta is None:
        return None
    if isinstance(meta, str):
        s = meta.strip()
        # Heuristic: treat empty/placeholder as null
        return s or None
    try:
        return json.dumps(meta, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        # As a last resort, store a string repr
        return str(meta)


def insert_comm(
    *,
    timestamp_utc: Optional[str] = None,
    method: str,
    direction: Optional[str] = None,
    from_party: Optional[str] = None,
    to_party: Optional[str] = None,
    subject: Optional[str] = None,
    body: Optional[str] = None,
    related_flight_id: Optional[int] = None,
    operator: Optional[str] = None,
    notes: Optional[str] = None,
    metadata: Any = None,  # dict | str | None
) -> int:
    """
    Insert a communications row. Minimal validation:
      • method required (non-blank)
      • timestamp coerced/normalized to UTC
      • direction limited to {'in','out','internal'} or NULL
      • related_flight_id coerced to int or NULL
    Returns the new row id.
    """
    ensure_comms_tables()  # safe idempotent call

    m = (method or "").strip()
    if not m:
        raise ValueError("method is required")

    ts = _coerce_iso_utc(timestamp_utc)
    dirv = _norm_direction(direction)
    rfid = int(related_flight_id) if (related_flight_id is not None and str(related_flight_id).strip()) else None

    row = {
        "timestamp_utc": ts,
        "method": m,
        "direction": dirv,
        "from_party": blankish_to_none(from_party),
        "to_party": blankish_to_none(to_party),
        "subject": blankish_to_none(subject),
        "body": blankish_to_none(body),
        "related_flight_id": rfid,
        "operator": blankish_to_none(operator),
        "notes": blankish_to_none(notes),
        "metadata_json": _as_metadata_text(metadata),
    }

    cols = ", ".join(row.keys())
    placeholders = ", ".join(["?"] * len(row))
    vals = list(row.values())

    with sqlite3.connect(get_db_file()) as c:
        cur = c.execute(f"INSERT INTO communications ({cols}) VALUES ({placeholders})", vals)
        return int(cur.lastrowid)


def list_comms(
    *,
    start_utc: Optional[str] = None,
    end_utc: Optional[str] = None,
    methods: Optional[Iterable[str]] = None,
    directions: Optional[Iterable[str]] = None,
    q: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """
    Filter & return communications rows for UI.
    - start_utc / end_utc: inclusive bounds (ISO strings), coerced to UTC
    - methods: iterable of method strings (case-insensitive)
    - directions: iterable subset of {'in','out','internal'}
    - q: free-text over from/to/subject/body/notes/method/direction
    - limit/offset: pagination
    """
    ensure_comms_tables()

    where = []
    params: List[Any] = []

    if start_utc:
        where.append("timestamp_utc >= ?")
        params.append(_coerce_iso_utc(start_utc))
    if end_utc:
        where.append("timestamp_utc <= ?")
        params.append(_coerce_iso_utc(end_utc))

    if methods:
        meth = [str(m).strip() for m in methods if str(m).strip()]
        if meth:
            placeholders = ", ".join(["?"] * len(meth))
            where.append(f"LOWER(method) IN ({placeholders})")
            params.extend([m.lower() for m in meth])

    if directions:
        dirs = [d for d in (str(x).lower().strip() for x in directions) if d in _VALID_DIRECTIONS]
        if dirs:
            placeholders = ", ".join(["?"] * len(dirs))
            where.append(f"direction IN ({placeholders})")
            params.extend(dirs)

    if q:
        needle = f"%{q.strip().lower()}%"
        where.append(
            "("
            "LOWER(IFNULL(from_party,'')) LIKE ? OR "
            "LOWER(IFNULL(to_party,'')) LIKE ? OR "
            "LOWER(IFNULL(subject,'')) LIKE ? OR "
            "LOWER(IFNULL(body,'')) LIKE ? OR "
            "LOWER(IFNULL(notes,'')) LIKE ? OR "
            "LOWER(IFNULL(method,'')) LIKE ? OR "
            "LOWER(IFNULL(direction,'')) LIKE ?"
            ")"
        )
        params.extend([needle] * 7)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    sql = (
        "SELECT id, timestamp_utc, method, direction, from_party, to_party, "
        "subject, body, related_flight_id, operator, notes, metadata_json "
        "FROM communications" + where_sql +
        " ORDER BY timestamp_utc DESC, id DESC LIMIT ? OFFSET ?"
    )
    params.extend([int(limit), int(offset)])

    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        rows = [dict(r) for r in c.execute(sql, params)]
        return rows

# (CSV helper removed — exporter routes now own CSV shape)
