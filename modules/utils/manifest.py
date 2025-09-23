"""
Manifest & Pilot Ack utilities
 - get/set ack status (flights or queued_flights)
 - HTML manifest builder (snapshot of the queue/flight card)
 - WeasyPrint PDF rendering + persistence
 - provide build_manifest_pdf(app, queue_row) that saves to
           data/manifests/<YYYY>/<MM>/<queue_id>.pdf
"""
from __future__ import annotations
import os, io, re, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from flask import render_template, current_app
from typing import Optional, Tuple, Dict, Any

from modules.utils.common import dict_rows, get_db_file, ensure_trailing_semicolon, format_airport

try:
    # Optional dependency: only used when printing a PDF
    from weasyprint import HTML, CSS
except Exception:  # keep import-time safe if WeasyPrint isn't present yet
    HTML = None  # type: ignore
    CSS = None   # type: ignore

# Legacy directory (kept for back-compat helpers below)
DATA_DIR = os.path.join(os.path.dirname(get_db_file()), "")
MANIFEST_DIR = os.path.join(DATA_DIR, "manifests")
os.makedirs(MANIFEST_DIR, exist_ok=True)

# ──────────────────────────────────────────────────────────────────────────
# storage convention
#   data/manifests/<YYYY>/<MM>/<queue_id>.pdf
# ──────────────────────────────────────────────────────────────────────────
STORE_ROOT = Path('data/manifests')

def _sanitize_tail(t: str) -> str:
    """
    Keep a compact, filesystem/URL-friendly tail tag.
    - Uppercase
    - Replace any non [A-Z0-9-] with nothing
    - Fallback to 'TAIL' if empty
    """
    import re
    tag = re.sub(r'[^A-Z0-9-]+', '', (t or '').upper())
    return tag or 'TAIL'

def _ensure_dir(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)

def _parse_manifest_items(txt: str) -> list[dict]:
    """
    Parse strings like:
      'Manifest: rice 1.5 lb×3; water 2 lb×6'
    Tolerates 'x' or '×', optional unit (lb|lbs|kg). Returns rows shaped for our template:
      [{category_name:'', sanitized_name, wpu, qty, total}]
    """
    if not txt:
        return []
    s = txt.strip()
    m = re.search(r'manifest\s*:\s*(.*)$', s, re.IGNORECASE | re.DOTALL)
    if m:
        s = m.group(1)
    parts = [p.strip() for p in re.split(r'[;,\n]+', s) if p.strip()]
    out = []
    for part in parts:
        rx = re.compile(
            r'^\s*(?P<name>.*?)(?<!\S)'
            r'(?P<wpu>\d+(?:\.\d+)?)\s*'
            r'(?P<unit>lb|lbs|kg)?\s*'
            r'[x×]\s*'
            r'(?P<qty>\d+)\s*$',
            re.IGNORECASE
        )
        mm = rx.match(part)
        if not mm:
            continue
        name = (mm.group('name') or '').strip()
        try:
            wpu = float(mm.group('wpu'))
        except Exception:
            continue
        unit = (mm.group('unit') or 'lb').lower()
        try:
            qty = int(mm.group('qty'))
        except Exception:
            continue
        if unit == 'kg':
            wpu *= 2.20462
        total = round(wpu * qty, 1)
        out.append({"category_name": "", "sanitized_name": name, "wpu": round(wpu, 2), "qty": qty, "total": total})
    return out

def build_manifest_pdf(app, queue_row) -> tuple[bytes, str]:
    """
    Render the manifest HTML template and persist the PDF using the Step-8 path
    convention. Returns (pdf_bytes, absolute_path).
      - queue_row must include fields referenced by templates/reports/manifest.html.j2
        (we pass it as "q" to the template for compatibility).
    """
    if HTML is None:
        raise RuntimeError("WeasyPrint is not installed; unable to render PDF")
    # Build itemized rows from snapshot (if any)
    import sqlite3
    qid = int(queue_row['id'])
    rows_db: list[dict] = []
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        rows_db = c.execute("""
          SELECT
            IFNULL(ic.display_name,'')                               AS category_name,
            fc.sanitized_name                                       AS sanitized_name,
            fc.weight_per_unit                                      AS wpu,
            fc.quantity                                             AS qty,
            COALESCE(NULLIF(fc.total_weight,0),
                     COALESCE(fc.weight_per_unit,0)*COALESCE(fc.quantity,0)) AS total
          FROM flight_cargo fc
          LEFT JOIN inventory_categories ic ON ic.id = fc.category_id
          WHERE fc.queued_id = ?
          ORDER BY ic.display_name COLLATE NOCASE,
                   fc.sanitized_name COLLATE NOCASE,
                   fc.weight_per_unit
        """, (qid,)).fetchall()
        rows_db = [dict(r) for r in rows_db]

    # Normalize DB rows and compute totals if missing
    rows: list[dict] = []
    for r in rows_db:
        name = (r.get("sanitized_name") or "").strip()
        cat  = (r.get("category_name") or "").strip()
        # qty
        try:
            qty_i = int(float(r.get("qty") or 0))
        except Exception:
            qty_i = 0
        # wpu
        try:
            wpu_f = float(r.get("wpu") or 0.0)
        except Exception:
            wpu_f = 0.0
        # total (prefer stored; else derive)
        total_raw = r.get("total")
        try:
            total_f = float(total_raw) if total_raw is not None and str(total_raw) != "" else 0.0
        except Exception:
            total_f = 0.0
        if total_f <= 0 and wpu_f > 0 and qty_i > 0:
            total_f = wpu_f * qty_i
        if name and qty_i > 0 and total_f > 0:
            rows.append({
                "category_name": cat,
                "sanitized_name": name,
                "wpu": round(wpu_f, 2) if wpu_f else None,
                "qty": qty_i,
                "total": round(total_f, 1),
            })

    # Fallback: parse "Manifest: …" from cargo_type/remarks if no normalized rows exist
    if not rows:
        cargo_txt   = (queue_row.get('cargo_type') or '').strip()
        remarks_txt = (queue_row.get('remarks') or '').strip()
        parsed = _parse_manifest_items(" ".join([cargo_txt, remarks_txt]).strip())
        rows = parsed

    # Totals for the PDF (grand total weight & quantity)
    try:
        total_weight = round(sum(float(r.get("total") or 0) for r in rows), 1)
    except Exception:
        total_weight = 0.0
    try:
        total_qty = sum(int(r.get("qty") or 0) for r in rows)
    except Exception:
        total_qty = 0

    # Template render (uses same template already in repo)
    html = render_template(
        'reports/manifest.html.j2',
        q=queue_row,
        items=rows,
        items_total_weight=total_weight,   # preferred name
        grand_total_weight=total_weight,   # alias for safety
        total_weight=total_weight,         # legacy alias if template uses this
        items_total_qty=total_qty,
        generated_at_utc=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    )
    # Use filesystem base so WeasyPrint can resolve assets; include site CSS for print styles
    base_dir = getattr(app, "root_path", None) or getattr(current_app, "root_path", ".")
    stylesheets = []
    try:
        css_path = os.path.join(base_dir, "static", "style.css")
        if CSS is not None and os.path.exists(css_path):
            stylesheets.append(CSS(filename=css_path))
    except Exception:
        pass
    pdf_bytes = HTML(string=html, base_url=base_dir).write_pdf(stylesheets=stylesheets)

    # Canonical path (timestamped filename to avoid collisions/regens)
    dt = datetime.now(timezone.utc)
    tail = _sanitize_tail(queue_row.get('tail_number') or '')
    fname = f"{dt:%Y%m%d-%H%M%S}_{tail}_Q{qid}.pdf"
    out = STORE_ROOT / f"{dt.year:04d}" / f"{dt.month:02d}" / fname
    _ensure_dir(out)
    out.write_bytes(pdf_bytes)
    return pdf_bytes, str(out)

# ---------------------------------------------------------------------------
# Pilot Ack status
# ---------------------------------------------------------------------------
def get_pilot_ack_status(*, flight_id: int | None = None, queue_id: int | None = None) -> Dict[str, Any]:
    """
    Return {'ack': bool, 'name': str|None, 'signed_at': str|None, 'method': 'typed'|'drawn'|None}
    for either flights.id or queued_flights.id.
    """
    if not (flight_id or queue_id):
        return {'ack': False}
    if flight_id:
        rows = dict_rows("""
          SELECT pilot_ack_name AS name, pilot_ack_method AS method, pilot_ack_signed_at AS signed_at
            FROM flights WHERE id=? LIMIT 1
        """, (int(flight_id),))
    else:
        rows = dict_rows("""
          SELECT pilot_ack_name AS name, pilot_ack_method AS method, pilot_ack_signed_at AS signed_at
            FROM queued_flights WHERE id=? LIMIT 1
        """, (int(queue_id),))
    r = rows[0] if rows else {}
    ack = bool((r.get('name') or '').strip() and (r.get('signed_at') or '').strip())
    return {'ack': ack, 'name': r.get('name'), 'method': r.get('method'), 'signed_at': r.get('signed_at')}

def set_pilot_acknowledged(*, flight_id: int | None, queue_id: int | None,
                           user: str, when_iso: Optional[str] = None, method: str = "typed",
                           signature_b64_or_datauri: Optional[str] = None) -> None:
    """
    Convenience wrapper that writes to the right table.
    """
    from modules.utils.common import set_pilot_ack_for_flight, set_pilot_ack_for_queue
    ts = when_iso or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")
    if flight_id:
        set_pilot_ack_for_flight(int(flight_id), name=user, method=method,
                                 signature_b64_or_datauri=signature_b64_or_datauri,
                                 signed_at_iso=ts)
    elif queue_id:
        set_pilot_ack_for_queue(int(queue_id), name=user, method=method,
                                signature_b64_or_datauri=signature_b64_or_datauri,
                                signed_at_iso=ts)

# ---------------------------------------------------------------------------
# Manifest HTML/PDF
# ---------------------------------------------------------------------------
def _manifest_context_from_row(row: dict) -> dict:
    # Normalize fields used in the printed manifest
    def _fmt(code: str) -> str:
        # Prefer ICAO on printed paperwork
        try:
            return format_airport(code or '', 'icao4') or (code or '')
        except Exception:
            return code or ''
    return {
        "tail": row.get("tail_number") or "",
        "origin": _fmt(row.get("airfield_takeoff") or ""),
        "dest": _fmt(row.get("airfield_landing") or ""),
        "tko": row.get("takeoff_time") or "",
        "eta": row.get("eta") or "",
        "pilot": row.get("pilot_name") or "",
        "pax": row.get("pax_count") or "",
        "cargo_type": row.get("cargo_type") or "",
        "cargo_weight": row.get("cargo_weight") or "",
        "remarks": row.get("remarks") or "",
        "signed_name": row.get("pilot_ack_name") or "",
        "signed_at": row.get("pilot_ack_signed_at") or "",
    }

def get_or_build_manifest_html(*, flight_id: int | None = None, queue_id: int | None = None) -> str:
    """
    Build simple, self-contained HTML that mirrors the on-screen manifest.
    (No template dependency; safe for WeasyPrint.)
    """
    if not (flight_id or queue_id):
        return "<html><body><p>No manifest.</p></body></html>"
    if flight_id:
        rows = dict_rows("SELECT * FROM flights WHERE id=? LIMIT 1", (int(flight_id),))
    else:
        rows = dict_rows("SELECT * FROM queued_flights WHERE id=? LIMIT 1", (int(queue_id),))
    if not rows:
        return "<html><body><p>No manifest.</p></body></html>"
    ctx = _manifest_context_from_row(rows[0])
    # Keep the CSS tiny so it renders reliably offline
    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Flight Manifest</title>
  <style>
    body {{ font-family: Arial, sans-serif; font-size: 12px; }}
    h1 {{ font-size: 18px; margin: 0 0 6px 0; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 6px; margin-bottom: 10px; }}
    .box {{ border: 1px solid #888; padding: 6px; border-radius: 4px; }}
    .label {{ color: #555; font-size: 10px; text-transform: uppercase; letter-spacing: .04em; }}
    .value {{ font-size: 14px; font-weight: 600; }}
    .remarks {{ min-height: 48px; white-space: pre-wrap; }}
    .sigline {{ margin-top: 18px; }}
  </style>
  </head>
  <body>
    <h1>Aircraft Ops — Pilot Manifest</h1>
    <div class="grid">
      <div class="box"><div class="label">Tail #</div><div class="value">{ctx['tail']}</div></div>
      <div class="box"><div class="label">Pilot</div><div class="value">{ctx['pilot']}</div></div>
      <div class="box"><div class="label">PAX</div><div class="value">{ctx['pax']}</div></div>
      <div class="box"><div class="label">From</div><div class="value">{ctx['origin']}</div></div>
      <div class="box"><div class="label">To</div><div class="value">{ctx['dest']}</div></div>
      <div class="box"><div class="label">Cargo Type</div><div class="value">{ctx['cargo_type']}</div></div>
      <div class="box"><div class="label">T/O</div><div class="value">{ctx['tko']}</div></div>
      <div class="box"><div class="label">ETA</div><div class="value">{ctx['eta']}</div></div>
      <div class="box"><div class="label">Cargo Weight</div><div class="value">{ctx['cargo_weight']}</div></div>
    </div>
    <div class="box remarks"><div class="label">Remarks / Manifest</div>
      <div>{ctx['remarks']}</div>
    </div>
    <div class="sigline">
      <div class="label">Pilot Acknowledgement</div>
      <div class="value">{ctx['signed_name'] or '—'} &nbsp; <span style="font-weight:400;">{ctx['signed_at'] or ''}</span></div>
    </div>
  </body>
</html>"""
    return html

def render_manifest_pdf(html: str) -> Tuple[str, bytes]:
    """
    Render HTML to PDF bytes via WeasyPrint. Returns (suggested_filename, pdf_bytes).
    """
    if not HTML:
        raise RuntimeError("WeasyPrint is not installed; unable to render PDF")
    doc = HTML(string=html)
    pdf_bytes = doc.write_pdf()
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return (f"manifest-{ts}.pdf", pdf_bytes)

def persist_manifest_copy(pdf_bytes: bytes, *, flight_id: int | None = None, queue_id: int | None = None) -> str:
    """
    Save PDF under data/manifests/ and stamp its path onto the row.
    Returns absolute file path.
    """
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    if flight_id:
        # Keep legacy folder for flights, but use new filename convention
        fname = f"{ts}_FLIGHT_{int(flight_id)}.pdf"
        path = os.path.join(MANIFEST_DIR, fname)
        with open(path, "wb") as f:
            f.write(pdf_bytes)
        with sqlite3.connect(get_db_file()) as c:
            c.execute("UPDATE flights SET manifest_pdf_path=? WHERE id=?", (path, int(flight_id)))
        return path
    if queue_id:
        # Step-8 canonical path with timestamp + tail + queue id
        with sqlite3.connect(get_db_file()) as c:
            c.row_factory = sqlite3.Row
            row = c.execute("SELECT tail_number FROM queued_flights WHERE id=? LIMIT 1",
                            (int(queue_id),)).fetchone()
        tail = _sanitize_tail((row['tail_number'] if row else '') or '')
        dt = datetime.utcnow()
        fname = f"{dt:%Y%m%d-%H%M%S}_{tail}_Q{int(queue_id)}.pdf"
        canonical = STORE_ROOT / f"{dt.year:04d}" / f"{dt.month:02d}" / fname
        _ensure_dir(canonical)
        Path(canonical).write_bytes(pdf_bytes)
        with sqlite3.connect(get_db_file()) as c:
            c.execute("UPDATE queued_flights SET manifest_pdf_path=? WHERE id=?", (str(canonical), int(queue_id)))
        return str(canonical)
    # fallback (no id)
    path = os.path.join(MANIFEST_DIR, f"manifest-{ts}.pdf")
    with open(path, "wb") as f:
        f.write(pdf_bytes)
    return path
