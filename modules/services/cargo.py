# modules/services/cargo.py
from __future__ import annotations

import sqlite3
from datetime import datetime

# Reuse the single source of truth from common.py
from modules.utils.common import (
    get_db_file,
    canonical_airport_code,   # airport → canonical code (ICAO/IATA/local)
    cr_sanitize_item,         # item name → normalized “sanitized_name”
    ensure_cargo_request_tables,
)

# ────────────────────────────── internal helpers ──────────────────────────────
def _now_iso() -> str:
    # UTC ISO8601 without microseconds, with trailing Z
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def _to_float(x) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0

def _to_int(x) -> int:
    try:
        return int(float(x))  # round toward zero
    except Exception:
        return 0

# ──────────────────────────────── public API ─────────────────────────────────
def upsert_request(
    airport: str,
    item_raw: str,
    requested_lb: float,
    source_email_id: str | None,
) -> None:
    """
    Normalize airport & item; increment requested_lb (insert on first sight),
    and bump timestamps. Safe to pass negative requested_lb for adjustments.

    Schema aligned to modules.utils.common._create_tables_cargo_requests:
      (airport_canon, sanitized_name, requested_lb, fulfilled_lb,
       created_at, updated_at, last_source_id)
    """
    ensure_cargo_request_tables()
    ap = canonical_airport_code(airport or "")
    nm = cr_sanitize_item(item_raw or "")
    delta = _to_float(requested_lb)
    if not ap or not nm or delta == 0.0:
        return
    now = _now_iso()

    with sqlite3.connect(get_db_file()) as conn:
        conn.execute(
            """
            INSERT INTO cargo_requests(
                airport_canon, sanitized_name,
                requested_lb,  fulfilled_lb,
                created_at,    updated_at,    last_source_id
            )
            VALUES (?, ?, ?, 0.0, ?, ?, ?)
            ON CONFLICT(airport_canon, sanitized_name) DO UPDATE SET
                requested_lb  = cargo_requests.requested_lb + excluded.requested_lb,
                updated_at    = excluded.updated_at,
                last_source_id= COALESCE(excluded.last_source_id, cargo_requests.last_source_id)
            """,
            (ap, nm, delta, now, now, source_email_id),
        )
        # Auto-prune any lines that are already fully satisfied (edge-case)
        conn.execute(
            "DELETE FROM cargo_requests WHERE airport_canon=? AND fulfilled_lb >= requested_lb",
            (ap,),
        )
        conn.commit()

def get_summary() -> list[dict]:
    """
    Return outstanding request lines grouped by airport and include per-airport
    totals on each line. Only lines with outstanding > 0 are returned.

    Output lines:
      {
        'airport': 'KAAA',
        'item_sanitized': 'rice',      # ← matches sanitized_name
        'requested_lb': 120.0,
        'fulfilled_lb': 30.0,
        'outstanding_lb': 90.0,
        'airport_outstanding_lb_total': 250.0,
        'airport_outstanding_lines': 4,
      }
    """
    ensure_cargo_request_tables()
    lines: list[dict] = []
    with sqlite3.connect(get_db_file()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT airport_canon AS airport,
                   sanitized_name,
                   IFNULL(requested_lb, 0.0) AS requested_lb,
                   IFNULL(fulfilled_lb, 0.0) AS fulfilled_lb
              FROM cargo_requests
            """
        ).fetchall()

    tmp_by_airport: dict[str, list[dict]] = {}
    for r in rows:
        requested = _to_float(r["requested_lb"])
        fulfilled = _to_float(r["fulfilled_lb"])
        outstanding = requested - fulfilled
        if outstanding <= 1e-9:
            continue
        line = {
            "airport": (r["airport"] or "").strip().upper(),
            "item_sanitized": (r["sanitized_name"] or "").strip().lower(),
            "requested_lb": round(requested, 2),
            "fulfilled_lb": round(fulfilled, 2),
            "outstanding_lb": round(outstanding, 2),
        }
        tmp_by_airport.setdefault(line["airport"], []).append(line)

    for ap, group in tmp_by_airport.items():
        total_lb = round(sum(l["outstanding_lb"] for l in group), 2)
        count = len(group)
        for l in group:
            l["airport_outstanding_lb_total"] = total_lb
            l["airport_outstanding_lines"] = count
            lines.append(l)

    lines.sort(key=lambda d: (d["airport"], d["item_sanitized"]))
    return lines

def delete_line(airport: str, item_sanitized: str) -> None:
    """
    Hard-delete a single (airport, item) request.
    """
    ensure_cargo_request_tables()
    ap = canonical_airport_code(airport or "")
    nm = cr_sanitize_item(item_sanitized or "")
    if not ap or not nm:
        return
    with sqlite3.connect(get_db_file()) as conn:
        conn.execute(
            "DELETE FROM cargo_requests WHERE airport_canon=? AND sanitized_name=?",
            (ap, nm),
        )
        conn.commit()

def delete_airport(airport: str) -> int:
    """
    Hard-delete all lines for an airport. Returns the number of rows deleted.
    """
    ensure_cargo_request_tables()
    ap = canonical_airport_code(airport or "")
    if not ap:
        return 0
    with sqlite3.connect(get_db_file()) as conn:
        cur = conn.execute("DELETE FROM cargo_requests WHERE airport_canon=?", (ap,))
        conn.commit()
        return int(cur.rowcount or 0)

# ───────────────────────────── availability helper ───────────────────────────
def match_availability(advance_json: dict) -> dict:
    """
    (unchanged behavior)
    Given the /inventory/_advance_data JSON, compute availability by sanitized_name
    across all categories. Result: { item_key → {'qty': int, 'weight_lbs': float|None} }
    """
    data = advance_json or {}
    all_items = []

    if isinstance(data.get("rows"), list):
        all_items.extend(data["rows"])

    cats = data.get("categories")
    if isinstance(cats, list):
        for cat in cats:
            items = (cat or {}).get("items") or (cat or {}).get("rows") or []
            if isinstance(items, list):
                all_items.extend(items)
    elif isinstance(cats, dict):
        for _k, cat in cats.items():
            items = (cat or {}).get("items") or (cat or {}).get("rows") or []
            if isinstance(items, list):
                all_items.extend(items)

    out: dict[str, dict] = {}
    presence_only: dict[str, bool] = {}

    def _to_float_local(x):
        try:
            return float(x)
        except Exception:
            return 0.0

    def _to_int_local(x):
        try:
            return int(float(x))
        except Exception:
            return 0

    for it in all_items:
        if not isinstance(it, dict):
            continue
        name = (it.get("sanitized_name")) or cr_sanitize_item(it.get("name") or it.get("display_name") or "")
        if not name:
            continue
        qty = _to_int_local(it.get("qty") if it.get("qty") is not None else it.get("quantity"))
        unit_w = _to_float_local(
            it.get("unit_weight_lbs")
            if it.get("unit_weight_lbs") is not None
            else it.get("weight_per_unit")
        )
        total_w = 0.0
        used_weight = False
        if qty > 0 and unit_w > 0:
            total_w = qty * unit_w
            used_weight = True
        else:
            tw = _to_float_local(it.get("weight_lbs"))
            if tw > 0:
                total_w = tw
                used_weight = True

        node = out.setdefault(name, {"qty": 0, "weight_lbs": 0.0})
        node["qty"] += max(0, qty)
        if used_weight:
            node["weight_lbs"] = _to_float_local(node["weight_lbs"]) + total_w
        else:
            presence_only[name] = presence_only.get(name, False) or (qty > 0 or True)

    for k, v in out.items():
        w = _to_float_local(v.get("weight_lbs"))
        if w <= 0.0:
            if presence_only.get(k, False):
                v["weight_lbs"] = None
            else:
                v["weight_lbs"] = 0.0
        else:
            v["weight_lbs"] = round(w, 2)

    return out
