import sqlite3
from app import DB_FILE

DDL = """
CREATE TABLE IF NOT EXISTS remote_inventory_rows (
  airport TEXT NOT NULL,
  generated_at TEXT NOT NULL,
  received_at  TEXT NOT NULL,
  category TEXT NOT NULL,
  sanitized_name TEXT NOT NULL,
  weight_per_unit_lb REAL NOT NULL,
  quantity INTEGER NOT NULL,
  total_weight_lb REAL NOT NULL,
  source_callsign TEXT
);
"""

INDEXES = [
  "CREATE INDEX IF NOT EXISTS idx_remote_airport ON remote_inventory_rows(airport)",
  "CREATE INDEX IF NOT EXISTS idx_remote_airport_time ON remote_inventory_rows(airport, generated_at)"
]

def ensure_remote_inventory_tables():
    with sqlite3.connect(DB_FILE) as c:
        c.executescript(DDL)
        for stmt in INDEXES:
            c.execute(stmt)
        c.commit()

# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: Snapshot builder (server-local)
# ─────────────────────────────────────────────────────────────────────────────
from typing import List, Dict, Tuple, Optional
from modules.utils.common import dict_rows, iso8601_ceil_utc, get_preference
from datetime import datetime
import csv
import io
import re

_tok_re = re.compile(r"[^a-z0-9]+")

def _sanitize_token(s: str) -> str:
    """Lowercase, strip, collapse non-alphanumerics → single hyphens."""
    s = (s or "").strip().lower()
    return _tok_re.sub("-", s).strip("-")

def _now_iso() -> str:
    try:
        return iso8601_ceil_utc(datetime.utcnow())
    except Exception:
        return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def build_inventory_snapshot(category_tokens: Optional[List[str]] = None) -> Tuple[Dict, str, str]:
    """
    Build a snapshot of committed stock (pending=0) grouped by
    (category_id, sanitized_name, weight_per_unit).
    Optionally filter by sanitized category tokens (case-insensitive).
    Returns: (python_struct, human_summary_str, csv_str)
    """
    # Load rolled-up stock (same semantics as UI/export).
    rows = dict_rows("""
      SELECT c.display_name     AS category,
             e.sanitized_name   AS item,
             e.weight_per_unit  AS unit_weight_lb,
             SUM(CASE WHEN e.direction='in' THEN e.quantity
                      WHEN e.direction='out' THEN -e.quantity END) AS qty
        FROM inventory_entries e
        JOIN inventory_categories c ON c.id = e.category_id
       WHERE e.pending = 0
       GROUP BY e.category_id, e.sanitized_name, e.weight_per_unit
       HAVING qty > 0
       ORDER BY c.display_name, e.sanitized_name, e.weight_per_unit
    """)

    # Optional category filter on sanitized display_name
    want = None
    if category_tokens:
        want = { _sanitize_token(t) for t in category_tokens if (t or "").strip() }

    data_rows: List[Dict] = []
    total_weight = 0.0
    per_cat: Dict[str, float] = {}
    for r in rows:
        cat = r.get("category") or ""
        if want and _sanitize_token(cat) not in want:
            continue
        qty = int(r.get("qty") or 0)
        wpu = float(r.get("unit_weight_lb") or 0.0)
        tw  = round(qty * wpu, 1)
        total_weight += tw
        per_cat[cat] = per_cat.get(cat, 0.0) + tw
        data_rows.append({
            "category": cat,
            "item": r.get("item") or "",
            "unit_weight_lb": wpu,
            "quantity": qty,
            "total_weight_lb": tw,
        })

    # Python struct
    snapshot = {
        "generated_at": _now_iso(),
        "airport": (get_preference("default_origin") or "").strip().upper(),
        "filters": {
            "categories": list(want) if want else [],
        },
        "rows": data_rows,
        "totals": {
            "total_weight_lb": round(total_weight, 1),
            "categories": { k: round(v, 1) for k, v in per_cat.items() },
            "lines": len(data_rows),
        }
    }

    # Human summary string
    lines: List[str] = []
    airport = snapshot["airport"] or "UNKNOWN"
    lines.append(f"AOCT cargo snapshot for {airport} @ {snapshot['generated_at']}")
    if want:
        lines.append("Categories: " + ", ".join(sorted(want)))
    lines.append(f"Lines: {len(data_rows)}   Total weight: {round(total_weight,1)} lb")
    if per_cat:
        lines.append("By category:")
        for cat, w in sorted(per_cat.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"  • {cat}: {round(w,1)} lb")
    human = "\n".join(lines)

    # CSV string (category,item,unit_weight_lb,quantity,total_weight_lb)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["category", "item", "unit_weight_lb", "quantity", "total_weight_lb"])
    for r in data_rows:
        w.writerow([r["category"], r["item"], r["unit_weight_lb"], r["quantity"], r["total_weight_lb"]])
    csv_text = buf.getvalue().strip()

    return snapshot, human, csv_text

# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: Receiving Remote Status (parse + upsert)
# ─────────────────────────────────────────────────────────────────────────────
from modules.utils.common import canonical_airport_code  # add alongside existing imports
import json

REMOTE_TBL_DDL = """
CREATE TABLE IF NOT EXISTS remote_inventory (
  airport_canon TEXT PRIMARY KEY,
  snapshot_at   TEXT NOT NULL,   -- timestamp embedded in snapshot (if known)
  received_at   TEXT NOT NULL,   -- when we stored this snapshot locally
  summary_text  TEXT NOT NULL,   -- human-readable summary body
  csv_text      TEXT NOT NULL    -- CSV (plain text) for parsing
);
"""

def ensure_remote_inventory_tables():
    """Create both detailed rows and the last-snapshot table."""
    with sqlite3.connect(DB_FILE) as c:
        c.executescript(DDL + REMOTE_TBL_DDL)
        for stmt in INDEXES:
            c.execute(stmt)
        c.commit()

def _extract_csv_block(body: str) -> str | None:
    """
    Find the CSV block. Prefer lines after a 'CSV:' marker; otherwise accept
    a body that already starts at the CSV header.
    """
    if not body:
        return None
    lines = body.splitlines()
    # 1) Look for an explicit CSV: marker
    for i, ln in enumerate(lines):
        if ln.strip().lower().startswith("csv:"):
            block = "\n".join(lines[i+1:]).strip()
            if "category,item,unit_weight_lb,quantity,total_weight_lb" in block.lower():
                return block
            # If marker exists but header isn't on the next line, try to locate header below
            for j in range(i+1, len(lines)):
                hdr = lines[j].strip().lower()
                if hdr.startswith("category,item,unit_weight_lb,quantity,total_weight_lb"):
                    return "\n".join(lines[j:]).strip()
            return None
    # 2) No marker → accept if body itself looks like CSV
    body_l = body.strip().lower()
    if body_l.startswith("category,item,unit_weight_lb,quantity,total_weight_lb"):
        return body.strip()
    # 3) Fallback: find header anywhere inside
    idx = body_l.find("category,item,unit_weight_lb,quantity,total_weight_lb")
    if idx >= 0:
        return body[idx:].strip()
    return None

_human_hdr_re = re.compile(
    r"(?im)^\s*AOCT\s+cargo\s+snapshot\s+for\s+([A-Z0-9\-]{3,6})\s*@\s*([0-9TZ:\-\.+ ]+)"
)

def _parse_human_snapshot(body: str) -> tuple[str | None, str | None, dict]:
    """
    Parse the human preamble to extract airport, generated_at, and totals.
    Returns (airport, generated_at, totals_dict). Missing values are None.
    """
    if not body:
        return None, None, {}
    airport = None
    generated_at = None
    m = _human_hdr_re.search(body or "")
    if m:
        airport = (m.group(1) or "").strip().upper()
        generated_at = (m.group(2) or "").strip()

    totals: dict = {}
    # Lines: 12   Total weight: 345.6 lb
    m2 = re.search(r"(?im)^\s*Lines:\s*(\d+).+?Total\s+weight:\s*([\d.]+)\s*lb", body or "")
    if m2:
        totals["lines"] = int(m2.group(1))
        try:
            totals["total_weight_lb"] = round(float(m2.group(2)), 1)
        except Exception:
            pass

    # By category section
    cats: dict[str, float] = {}
    sect = re.search(r"(?im)^\s*By\s+category:\s*$", body or "")
    if sect:
        after = body[sect.end():]
        for ln in after.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            # bullets like "• Food: 120.0 lb" or "Food: 120 lb"
            m3 = re.search(r"^\W*\s*(.+?):\s*([\d.]+)\s*lb\b", ln, re.I)
            if not m3:
                # likely end of the section
                break
            cat = m3.group(1).strip()
            val = float(m3.group(2))
            cats[cat] = round(val, 1)
        if cats:
            totals["categories"] = {k: round(v, 1) for k, v in cats.items()}
    return airport, generated_at, totals

def _parse_csv_snapshot(csv_text: str) -> list[dict]:
    """CSV → list of row dicts with numeric fields coerced."""
    if not csv_text:
        return []
    rows: list[dict] = []
    rdr = csv.DictReader(io.StringIO(csv_text))
    for r in rdr:
        try:
            unit = float(r.get("unit_weight_lb") or r.get("unit_weight_lbs") or 0.0)
        except Exception:
            unit = 0.0
        try:
            qty = int(r.get("quantity") or 0)
        except Exception:
            qty = 0
        try:
            tw = float(r.get("total_weight_lb") or 0.0)
        except Exception:
            tw = round(unit * qty, 1)
        rows.append({
            "category": (r.get("category") or "").strip(),
            "item": (r.get("item") or "").strip(),
            "unit_weight_lb": unit,
            "quantity": qty,
            "total_weight_lb": round(tw, 1),
        })
    return rows

def _infer_airport_from_sender(sender_call: str | None) -> str | None:
    """
    Use preferences mapping 'airport_call_mappings' (lines 'AAA: CALL1')
    to reverse map a sender callsign → airport code.
    """
    if not sender_call:
        return None
    raw = (get_preference("airport_call_mappings") or "").strip()
    want = (sender_call or "").strip().upper()
    for ln in raw.splitlines():
        if ":" not in ln:
            continue
        ap, call = (x.strip().upper() for x in ln.split(":", 1))
        if call == want and ap:
            return ap
    return None

def parse_remote_snapshot(subject: str, body: str, sender_call: str | None = None) -> tuple[str | None, dict, str, str]:
    """
    Try CSV first; if not present, parse the human section.
    Returns: (airport_canon, snapshot_dict, summary_text, csv_text)
      • airport_canon may be None if we couldn't determine an airport
      • snapshot_dict keys: generated_at, airport, filters, rows, totals
      • summary_text is whatever human portion we found (or whole body)
      • csv_text is the raw CSV ('' if none)
    """
    body = body or ""
    csv_text = _extract_csv_block(body) or ""
    # summary is everything before 'CSV:' if present; otherwise the whole body
    summary_text = body.split("\nCSV:", 1)[0].strip() if "CSV:" in body else (body or "")

    # Human header is where airport/timestamp live
    ap_from_human, generated_at, totals_human = _parse_human_snapshot(body)

    rows = _parse_csv_snapshot(csv_text) if csv_text else []
    # Compute totals if CSV present
    totals = {}
    if rows:
        totals["lines"] = len(rows)
        totals["total_weight_lb"] = round(sum(r["total_weight_lb"] for r in rows), 1)
        per_cat: dict[str, float] = {}
        for r in rows:
            per_cat[r["category"]] = per_cat.get(r["category"], 0.0) + float(r["total_weight_lb"])
        if per_cat:
            totals["categories"] = {k: round(v, 1) for k, v in per_cat.items()}
    elif totals_human:
        totals = totals_human

    # Airport inference: human header → subject hint → sender mapping
    airport = (ap_from_human or "").strip().upper()
    if not airport:
        # try subject like "… — ABC" or trailing token ABC
        m = re.search(r"[—-]\s*([A-Z0-9]{3,4})\b", subject or "")
        if m:
            airport = m.group(1).strip().upper()
    if not airport:
        airport = (_infer_airport_from_sender(sender_call) or "").strip().upper()

    snapshot = {
        "generated_at": (generated_at or "").strip() or _now_iso(),
        "airport": airport,
        "filters": {"categories": []},
        "rows": rows,
        "totals": totals or {},
    }
    canon = canonical_airport_code(airport) if airport else None
    return canon, snapshot, summary_text, csv_text

def upsert_remote_inventory(airport_canon: str | None, snapshot: dict, received_at_iso: str,
                            summary_text: str = "", csv_text: str = "", source_callsign: str | None = None) -> None:
    """
    Store latest snapshot for an airport (remote_inventory) and expand per-item
    rows into remote_inventory_rows for analytics/UI.
    """
    if not airport_canon:
        return
    ensure_remote_inventory_tables()
    snap_at = (snapshot.get("generated_at") or _now_iso()).strip()
    with sqlite3.connect(DB_FILE) as c:
        # Keep the "last snapshot per airport" table up to date
        c.execute("""
          INSERT INTO remote_inventory(airport_canon, snapshot_at, received_at, summary_text, csv_text)
          VALUES (?,?,?,?,?)
          ON CONFLICT(airport_canon) DO UPDATE SET
            snapshot_at = excluded.snapshot_at,
            received_at = excluded.received_at,
            summary_text= excluded.summary_text,
            csv_text    = excluded.csv_text
        """, (airport_canon, snap_at, received_at_iso, summary_text or "", csv_text or ""))

        # If we have rows, refresh the detailed table for this (airport, generated_at)
        rows = snapshot.get("rows") or []
        if rows:
            c.execute("DELETE FROM remote_inventory_rows WHERE airport=? AND generated_at=?", (airport_canon, snap_at))
            for r in rows:
                c.execute("""
                  INSERT INTO remote_inventory_rows(
                    airport, generated_at, received_at,
                    category, sanitized_name, weight_per_unit_lb, quantity, total_weight_lb,
                    source_callsign
                  ) VALUES (?,?,?,?,?,?,?,?,?)
                """, (
                  airport_canon, snap_at, received_at_iso,
                  r.get("category") or "",
                  r.get("item") or "",
                  float(r.get("unit_weight_lb") or 0.0),
                  int(r.get("quantity") or 0),
                  float(r.get("total_weight_lb") or 0.0),
                  (source_callsign or None)
                ))
        c.commit()
