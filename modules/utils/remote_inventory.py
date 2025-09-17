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
  "CREATE INDEX IF NOT EXISTS idx_remote_airport_time ON remote_inventory_rows(airport, generated_at)",
  "CREATE INDEX IF NOT EXISTS idx_remote_airport_cat_time ON remote_inventory_rows(airport, category, generated_at)"
]

# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: Snapshot builder (server-local)
# ─────────────────────────────────────────────────────────────────────────────
import logging
from typing import List, Dict, Tuple, Optional
from modules.utils.common import dict_rows, iso8601_ceil_utc, get_preference, sanitize_name
from datetime import datetime
import csv
import io
import re

_tok_re = re.compile(r"[^a-z0-9]+")
log = logging.getLogger(__name__)

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

    # If specific categories were requested, include empty categories with qty 0 (spec §2)
    if want:
        # Map sanitized token -> canonical category display name
        cat_rows = dict_rows("SELECT display_name FROM inventory_categories")
        tok2cat = { _sanitize_token(cr['display_name']): (cr['display_name'] or "") for cr in cat_rows }
        requested_cats = [tok2cat[t] for t in want if t in tok2cat]
        present_cats = { dr["category"] for dr in data_rows }
        for cat in requested_cats:
            if cat not in present_cats:
                data_rows.append({
                    "category": cat,
                    "item": "-",
                    "unit_weight_lb": 0.0,
                    "quantity": 0,
                    "total_weight_lb": 0.0,
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

    # Human summary (spec format)
    lines: List[str] = []
    airport = snapshot["airport"] or "UNKNOWN"
    lines.append(f"AOCT inventory @ {airport} (as of {snapshot['generated_at']})")
    lines.append("Units: pounds")
    lines.append("")  # blank line before category sections
    # group items by category
    by_cat: Dict[str, List[Dict]] = {}
    for r in data_rows:
        by_cat.setdefault(r["category"], []).append(r)
    for cat in sorted(by_cat.keys()):
        lines.append(f"{cat}")
        for r in by_cat[cat]:
            name = r["item"]
            wpu  = float(r["unit_weight_lb"])
            qty  = int(r["quantity"])
            tot  = float(r["total_weight_lb"])
            lines.append(f"  • {name} — {wpu:.1f} lb × {qty} = {tot:.1f} lb")
        lines.append("")  # blank line after each category block
    # trim potential trailing blank
    while lines and not lines[-1].strip():
        lines.pop()
    human = "\n".join(lines)

    # CSV block (spec format) including airport column, and prefixed with literal "CSV" line
    csv_buf = io.StringIO()
    csv_w   = csv.writer(csv_buf)
    csv_w.writerow(["airport","category","sanitized_name","weight_per_unit_lb","quantity","total_lb"])
    for r in data_rows:
        csv_w.writerow([
            airport,
            r["category"],
            r["item"],
            r["unit_weight_lb"],
            r["quantity"],
            r["total_weight_lb"],
        ])
    csv_text = "CSV\n" + csv_buf.getvalue().strip()

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
    Pull the CSV portion out of an AOCT reply/status body.
    Strategy:
      1) If a line equals 'CSV' or 'CSV:', take everything after it.
      2) Else, locate the first known header anywhere and take from there.
    Accepts Rev-B and legacy headers. Returns None if no header found.
    """
    if not body:
        return None
    # normalize newlines and strip common leading/trailing junk
    text = body.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.splitlines()
    # 1) look for explicit CSV marker
    for i, ln in enumerate(lines):
        if ln.strip().lower() in ("csv", "csv:"):
            after = "\n".join(lines[i+1:]).strip()
            # possibly there are blank lines before the header; find the header inside
            lower = after.lower()
            for hdr in (
                "airport,category,sanitized_name,weight_per_unit_lb,quantity,total_lb",
                "category,item,unit_weight_lb,quantity,total_weight_lb",
            ):
                j = lower.find(hdr)
                if j >= 0:
                    log.debug("AOCT parse: CSV marker found; header starts with %s", hdr.split(",")[0])
                    return after[j:].strip()
            # no header below marker → treat as no CSV
            log.debug("AOCT parse: CSV marker present but no known header below it")
            return None
    # 2) no marker: try to find a header anywhere in the body
    lower_body = text.lower()
    for hdr in (
        "airport,category,sanitized_name,weight_per_unit_lb,quantity,total_lb",
        "category,item,unit_weight_lb,quantity,total_weight_lb",
    ):
        k = lower_body.find(hdr)
        if k >= 0:
            log.debug("AOCT parse: CSV header found without marker; header starts with %s", hdr.split(",")[0])
            return text[k:].strip()
    return None

_human_hdr_re  = re.compile(r"(?im)^\s*AOCT\s+cargo\s+snapshot\s+for\s+([A-Z0-9\-]{3,6})\s*@\s*([0-9TZ:\-\.+ ]+)")
# spec header: "AOCT inventory @ <AP> (as of <ISO>Z)"
_human_hdr_re2 = re.compile(r"(?im)^\s*AOCT\s+inventory\s*@\s*([A-Z0-9\-]{3,6})\s*\(\s*as\s+of\s+([0-9TZ:\-\.+ ]+)\s*\)")

def _parse_human_snapshot(body: str) -> tuple[str | None, str | None, dict]:
    """
    Parse the human preamble to extract airport, generated_at, and totals.
    Returns (airport, generated_at, totals_dict). Missing values are None.
    """
    if not body:
        return None, None, {}
    airport = None
    generated_at = None
    m = _human_hdr_re.search(body or "") or _human_hdr_re2.search(body or "")
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
    # tolerate stray BOMs/ZWSPs
    cleaned = csv_text.replace("\ufeff", "").replace("\u200b", "")
    rdr = csv.DictReader(io.StringIO(cleaned))
    for r in rdr:
        # normalize field names across legacy/spec
        name = (r.get("item") or r.get("sanitized_name") or "").strip()
        try:
            unit = float(
                r.get("unit_weight_lb")
                or r.get("weight_per_unit_lb")
                or r.get("unit_weight_lbs")
                or 0.0
            )
        except Exception:
            unit = 0.0
        try:
            qty = int(r.get("quantity") or 0)
        except Exception:
            qty = 0
        try:
            tw = float(r.get("total_weight_lb") or r.get("total_lb") or 0.0)
        except Exception:
            tw = round(unit * qty, 1)
        rows.append({
            "category": (r.get("category") or "").strip(),
            "item": name,
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
    # summary is everything before a CSV marker line (CSV or CSV:)
    summary_text = body
    for splitter in ("\nCSV:\n", "\nCSV\n"):
        if splitter in body:
            summary_text = body.split(splitter, 1)[0]
            break
    summary_text = summary_text.strip()

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
    # Fallback: if we have an airport string but couldn't canonicalize it, accept it as-is
    if not canon and airport:
        canon = airport

    try:
        log.debug(
            "AOCT parse: airport=%s canon=%s rows=%d has_csv=%s",
            airport, canon, len(rows), bool(csv_text)
        )
    except Exception:
        pass
    return canon, snapshot, summary_text, csv_text

def upsert_remote_inventory(
    airport_canon: str | None,
    snapshot: dict,
    received_at_iso: str,
    summary_text: str = "",
    csv_text: str = "",
    source_callsign: str | None = None,
    *,
    mode: str | None = None,
    coverage_categories: Optional[List[str]] = None,
    is_full: Optional[bool] = None,
) -> None:
    """
    Store latest snapshot for an airport (remote_inventory) and expand per-item rows.

    Optional kwargs (ignored safely if callers don’t provide them):
      • mode: 'status' (full) or 'reply' (partial). Defaults to 'reply'.
      • coverage_categories: list of category names covered by this snapshot (strings).
      • is_full: explicit boolean full-snapshot flag. If True, overrides mode to full.
    Partial updates delete only covered categories for that airport; full updates
    replace all rows for the airport.
    """
    if not airport_canon:
        return
    ensure_remote_inventory_tables()
    snap_at = (snapshot.get("generated_at") or _now_iso()).strip()

    # Normalize update intent
    m = (mode or "").strip().lower()
    if m not in ("status", "reply"):
        m = "reply"
    full = bool(is_full) or (m == "status")
    cov = sorted({
        (c or "").strip().upper()
        for c in (coverage_categories or [])
        if (c or "").strip()
    })

    # If this is a partial reply but caller didn't pass coverage categories,
    # derive them from the snapshot rows so we only replace what we cover.
    if not full and not cov:
        try:
            cov = sorted({
                (r.get("category") or "").strip().upper()
                for r in (snapshot.get("rows") or [])
                if (r.get("category") or "").strip()
            })
        except Exception:
            cov = []

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

        # Retention for per-item rows
        if full:
            # Full replacement (status): clear everything for this airport
            c.execute("DELETE FROM remote_inventory_rows WHERE airport=?", (airport_canon,))
        elif cov:
            # Partial/layered: delete only rows for covered categories
            placeholders = ",".join("?" for _ in cov)
            params = [airport_canon] + cov
            c.execute(
                f"DELETE FROM remote_inventory_rows WHERE airport=? AND UPPER(category) IN ({placeholders})",
                params
            )
        rows = snapshot.get("rows") or []
        for r in rows:
            # Skip empty/placeholder lines so they don't render as blank rows
            try:
                qty = int(r.get("quantity") or 0)
                tot = float(r.get("total_weight_lb") or 0.0)
                if qty <= 0 and tot <= 0:
                    continue
            except Exception:
                pass
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

def get_layered_remote_rows(airport_canon: str) -> tuple[list[dict], dict]:
    """
    Build a merged, per-category-latest view for a remote airport.
    Returns (rows, meta) where:
      - rows: item rows at the newest generated_at *per category*
              (so partial replies layer on top of older/full snapshots)
              Each row includes 'updated_at' (that category's timestamp).
      - meta: {
          'last_full_at': best-effort time of the most recent 'full' snapshot
                          (heuristic: the newest generated_at that has rows
                          for *all* currently-known categories),
          'per_category': {CategoryName: ISO-ish timestamp}
        }
    """
    ensure_remote_inventory_tables()
    if not airport_canon:
        return [], {}
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        # Per-category latest timestamp
        per_cat = dict_rows("""
          WITH last_per_cat AS (
            SELECT UPPER(category) AS ucat, MAX(generated_at) AS g
              FROM remote_inventory_rows
             WHERE airport = ?
             GROUP BY UPPER(category)
          )
          SELECT r.category, l.g AS updated_at
            FROM last_per_cat l
            JOIN remote_inventory_rows r
              ON r.airport = ?
             AND UPPER(r.category) = l.ucat
             AND r.generated_at = l.g
           GROUP BY r.category
           ORDER BY r.category
        """, (airport_canon, airport_canon))
        # Materialize a map Category -> updated_at
        cat_ts: dict[str, str] = {r['category']: r['updated_at'] for r in per_cat}

        # Pull all item rows at those category timestamps
        rows = dict_rows("""
          WITH last_per_cat AS (
            SELECT UPPER(category) AS ucat, MAX(generated_at) AS g
              FROM remote_inventory_rows
             WHERE airport = ?
             GROUP BY UPPER(category)
          )
          SELECT r.airport,
                 r.generated_at,
                 r.category,
                 r.sanitized_name,
                 r.weight_per_unit_lb AS wpu,
                 r.quantity           AS qty,
                 r.total_weight_lb    AS total
            FROM remote_inventory_rows r
            JOIN last_per_cat l
              ON UPPER(r.category) = l.ucat
             AND r.generated_at    = l.g
           WHERE r.airport = ?
           ORDER BY r.category, r.sanitized_name, r.weight_per_unit_lb
        """, (airport_canon, airport_canon))
        # Attach per-category updated_at to each row
        for r in rows:
            r['updated_at'] = cat_ts.get(r['category'], r.get('generated_at', ''))

        # Heuristic "last full" time: newest timestamp that has rows for
        # all categories we currently know about (from per_cat).
        last_full_at = ""
        try:
            want_cats = len(cat_ts) or 0
            if want_cats:
                cur = c.execute("""
                  WITH stamp_counts AS (
                    SELECT generated_at, COUNT(DISTINCT UPPER(category)) AS cats
                      FROM remote_inventory_rows
                     WHERE airport = ?
                     GROUP BY generated_at
                  )
                  SELECT MAX(generated_at) FROM stamp_counts WHERE cats >= ?
                """, (airport_canon, want_cats)).fetchone()
                last_full_at = (cur[0] or "") if cur else ""
        except Exception:
            last_full_at = ""

    meta = {"last_full_at": last_full_at, "per_category": cat_ts}
    return rows, meta

def on_hand_lb_by_name(airport_canon: str) -> dict[str, float]:
    """
    Aggregate on-hand total pounds by sanitized item name for an airport,
    using the layered remote_inventory_rows view.
    """
    rows, _ = get_layered_remote_rows(airport_canon)
    totals: dict[str, float] = {}
    for r in rows or []:
        key = sanitize_name(r.get("sanitized_name") or r.get("item") or "")
        try:
            tot = float(r.get("total") or r.get("total_weight_lb") or 0.0)
        except Exception:
            tot = 0.0
        if not key or tot <= 0:
            continue
        totals[key] = totals.get(key, 0.0) + tot
    return totals
