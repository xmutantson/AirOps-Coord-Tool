
import sqlite3, csv, io, zipfile, json, os, re, base64, glob
import urllib.request, urllib.error
import urllib.parse
from pathlib import Path

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from app import DB_FILE
from flask import Blueprint, current_app, render_template
from flask import flash, redirect, request, url_for, send_file, session, Response, jsonify, abort
from datetime import datetime, timedelta, timezone
from modules.utils.comms import parse_comm_filters, sql_for_comm_filters, COMM_WINDOWS
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

# HTML → PDF (pure-Python)
from weasyprint import HTML, CSS

# Toggle slow HTTP fallback for WinLink attachments.
# Default OFF (disk-first only). Set AOCT_EXPORT_WINLINK_HTTP_FALLBACK=1 to enable.
HTTP_FALLBACK = (os.getenv("AOCT_EXPORT_WINLINK_HTTP_FALLBACK", "0").strip().lower() in ("1","true","yes","y","on"))

@bp.get('/exports/ramp/manifest/<int:queue_id>.pdf')
def exports_ramp_manifest_passthrough(queue_id: int):
    """Optional: serve Ramp Manifest PDFs beneath /exports/…"""
    try:
        from modules.routes.ramp import _manifest_pdf_path  # late import to avoid circulars
    except Exception:
        abort(404)
    path = _manifest_pdf_path(queue_id)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, mimetype='application/pdf',
                     as_attachment=True,
                     download_name=f"manifest_q{queue_id}.pdf")

def _manifests_root() -> str:
    """Canonical manifests root: data/manifests"""
    d = os.path.join(_data_root(), "manifests")
    os.makedirs(d, exist_ok=True)
    return d

def _zip_add_manifests(zf: zipfile.ZipFile) -> int:
    """
    Add all manifest PDFs into the provided ZipFile.
    Sources:
      1) Files under data/manifests/** (canonical tree)
      2) Any DB rows (queued_flights / flights) that have manifest_pdf_path set
         and point to an existing file (covers legacy paths).
    Returns the count of files added.
    """
    count = 0
    root = Path(_manifests_root())
    # 1) Canonical tree
    if root.exists():
        for pdf in root.rglob("*.pdf"):
            rel = pdf.relative_to(root)
            arc = Path("manifests") / rel  # preserve YYYY/MM/... inside zip
            try:
                zf.write(str(pdf), str(arc).replace("\\","/"))
                count += 1
            except Exception:
                current_app.logger.exception("Failed adding manifest to zip: %s", pdf)
    # 2) Legacy DB paths (if any)
    try:
        with sqlite3.connect(DB_FILE) as c:
            c.row_factory = sqlite3.Row
            # queued_flights
            rows_q = c.execute(
                "SELECT manifest_pdf_path FROM queued_flights WHERE manifest_pdf_path IS NOT NULL"
            ).fetchall()
            # flights (some deployments may also stamp here)
            rows_f = c.execute(
                "SELECT manifest_pdf_path FROM flights WHERE manifest_pdf_path IS NOT NULL"
            ).fetchall()
            for r in list(rows_q or []) + list(rows_f or []):
                p = (r["manifest_pdf_path"] or "").strip()
                if not p or not os.path.isfile(p):
                    continue
                # Put these under manifests/_legacy/<filename>
                arc = Path("manifests/_legacy") / os.path.basename(p)
                try:
                    zf.write(p, str(arc).replace("\\","/"))
                    count += 1
                except Exception:
                    current_app.logger.exception("Failed adding legacy manifest to zip: %s", p)
    except Exception:
        # Never break export-all if DB is odd
        pass
    return count

# ─────────────────────────────────────────────────────────────────────────────
# WinLink message export helpers (per-message folders with body + attachments)
# ─────────────────────────────────────────────────────────────────────────────

def _seq_prefix(n: int, width: int = 6) -> str:
    """
    Zero-padded sequence prefix for filenames/folders so they sort chronologically.
    """
    try: return f"{int(n):0{width}d}"
    except Exception: return f"{n}"

def _safe_fs_name(s: str, maxlen: int = 120) -> str:
    """
    Make a filename/folder name that's broadly filesystem-safe while keeping it readable.
    Keeps letters, numbers, spaces, basic punctuation; removes control + disallowed chars.
    Also trims and collapses whitespace and replaces slashes with ' - '.
    """
    s = (s or "").strip()
    # Replace path separators explicitly first
    s = s.replace("/", " - ").replace("\\", " - ")
    # Collapse whitespace
    s = re.sub(r"\s+", " ", s)
    # Strip leading/trailing dots/spaces
    s = s.strip(" .")
    # Remove control chars and characters commonly invalid on Windows/macOS
    s = re.sub(r'[\x00-\x1f<>:"\|\?\*]+', "", s)
    # Trim again
    s = s.strip(" .")
    # Ensure not empty and clamp length
    if not s:
        return ""
    if len(s) > maxlen:
        s = s[:maxlen].rstrip()
    return s

def _candidate_attach_dirs_for(msg_id: int) -> list[str]:
    """
    Likely attachment directories for a given WinLink message id.
    Adjust here if your deployment stores attachments differently.
    """
    root = _data_root()
    msg_dir = f"msg_{int(msg_id)}"
    cand = [
        # observed host layout: data/winlink/attachments/msg_<id>/**
        os.path.join(root, "winlink", "attachments", msg_dir),
        # other common variants
        os.path.join(root, "winlink", "attachments", str(msg_id)),
        os.path.join(root, "winlink", "msgs", str(msg_id), "attachments"),
        os.path.join(root, "winlink", str(msg_id)),
        os.path.join(root, "winlink", msg_dir),
        # ► WinLink Inbox (what the /winlink/attachment endpoint typically serves)
        os.path.join(root, "winlink", "inbox", str(msg_id), "attachments"),
        os.path.join(root, "winlink", "inbox", str(msg_id)),
        os.path.join(root, "winlink", "inbox_attachments", str(msg_id)),
    ]
    seen, out = set(), []
    for p in cand:
        if p not in seen:
            seen.add(p); out.append(p)
    return out

def _glob_find_attachments(msg_id: int) -> list[tuple[str, str]]:
    """
    Fallback sweep under data/winlink/** looking for:
      …/<msg_id>/attachments/*  OR  files directly in a dir named exactly <msg_id> or msg_<msg_id>.
    Used only when the direct candidates are empty.
    """
    base = os.path.join(_data_root(), "winlink")
    if not os.path.isdir(base): return []
    hits, seen = [], set()
    # inbox-first (most common)
    for full in glob.glob(os.path.join(base, "inbox", "**", str(msg_id), "attachments", "*"), recursive=True):
        if os.path.isfile(full) and not os.path.basename(full).startswith("."):
            if full not in seen: seen.add(full); hits.append((full, os.path.basename(full)))
    for full in glob.glob(os.path.join(base, "inbox", "**", str(msg_id), "*"), recursive=True):
        if os.path.isfile(full) and not os.path.basename(full).startswith("."):
            if os.path.basename(os.path.dirname(full)) == str(msg_id) and full not in seen:
                seen.add(full); hits.append((full, os.path.basename(full)))
    # attachments/msg_<id>/** (observed host layout)
    for full in glob.glob(os.path.join(base, "attachments", f"msg_{int(msg_id)}", "**", "*"), recursive=True):
        if os.path.isfile(full) and not os.path.basename(full).startswith("."):
            if full not in seen: seen.add(full); hits.append((full, os.path.basename(full)))
    # general catch-all under winlink/** for .../<id>/attachments/*
    for full in glob.glob(os.path.join(base, "**", str(msg_id), "attachments", "*"), recursive=True):
        if os.path.isfile(full) and not os.path.basename(full).startswith("."):
            if full not in seen: seen.add(full); hits.append((full, os.path.basename(full)))
    # any directory exactly named <id> or msg_<id>
    for pat in (os.path.join(base, "**", str(msg_id), "*"),
                os.path.join(base, "**", f"msg_{int(msg_id)}", "*")):
        for full in glob.glob(pat, recursive=True):
            if os.path.isfile(full) and not os.path.basename(full).startswith("."):
                parent = os.path.basename(os.path.dirname(full))
                if parent in (str(msg_id), f"msg_{int(msg_id)}") and full not in seen:
                    seen.add(full); hits.append((full, os.path.basename(full)))
    return hits

def _list_existing_attachments(msg_id: int) -> list[tuple[str, str]]:
    """
    Return [(abs_path, basename), ...] for all files considered attachments
    for this message id. Skips dirs and dotfiles.
    """
    out, seen = [], set()
    for base in _candidate_attach_dirs_for(msg_id):
        if not os.path.isdir(base):
            continue
        try:
            for full in glob.glob(os.path.join(base, "*")):
                if not os.path.isfile(full):
                    continue
                bn = os.path.basename(full)
                if not bn or bn.startswith("."):
                    continue
                if full not in seen:
                    seen.add(full); out.append((full, bn))
        except Exception:
            # Never break the export if one path is unreadable
            pass
    if not out:
        # Scoped recursive fallback (inbox-first)
        try: out = _glob_find_attachments(msg_id)
        except Exception: pass
    return out

def _fetch_attachment_index_json(msg_id: int) -> list[str]:
    """
    Try to hit /winlink/attachment/<id>/ and parse a lightweight JSON index of files.
    Returns a list of filenames; swallows failures.
    """
    try:
        from flask import request
        base = (request.url_root or "").rstrip("/")
        url  = f"{base}/winlink/attachment/{msg_id}/"
        req  = urllib.request.Request(url, headers={"X-Requested-With":"XMLHttpRequest"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace") or "{}")
        files = data.get("files") or []
        out: list[str] = []
        for f in files:
            if isinstance(f, dict):
                name = (f.get("name") or "").strip()
            else:
                name = str(f or "").strip()
            name = os.path.basename(name)
            if name:
                out.append(name)
        return out
    except Exception:
        return []

def _try_add_http_attachment(zf: zipfile.ZipFile, msg_id: int, filename: str, arc_prefix: str) -> bool:
    """
    Last-resort: GET /winlink/attachment/<id>/<filename> and add it directly to the zip.
    Returns True if added.
    """
    try:
        from flask import request
        base = (request.url_root or "").rstrip("/")
        fn   = os.path.basename(filename.strip())
        url  = f"{base}/winlink/attachment/{msg_id}/{urllib.parse.quote(fn)}"
        req  = urllib.request.Request(url, headers={"X-Requested-With":"XMLHttpRequest"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            blob = resp.read()
        arc = f"{arc_prefix}/attachments/{fn}".replace("\\","/")
        zf.writestr(arc, blob)
        return True
    except Exception:
        return False

def _zip_add_winlink_message_folders(zf: zipfile.ZipFile) -> dict:
    """
    Build: WinLink/<SEQ>_<SubjectSafe>/{ <SEQ>_<SubjectSafe>.txt, attachments/* }
    for each inbound WinLink message found in winlink_messages.
    Returns a small summary dict for optional future use.
    """
    summary = {"messages": 0, "folders_made": 0, "bodies_written": 0, "attachments_added": 0}
    try:
        rows = dict_rows("""
            SELECT id,
                   IFNULL(timestamp,'') AS ts,
                   IFNULL(sender,'')    AS sender,
                   IFNULL(subject,'')   AS subject,
                   IFNULL(body,'')      AS body
              FROM winlink_messages
             WHERE LOWER(IFNULL(direction,'')) = 'in'
             ORDER BY id ASC
        """)
    except Exception:
        rows = []

    used_names = set()
    for r in (rows or []):
        summary["messages"] += 1
        msg_id   = int(r.get("id") or 0)
        subj_raw = r.get("subject") or ""
        body_txt = r.get("body") or ""

        seq = _seq_prefix(msg_id)
        subj_safe = _safe_fs_name(subj_raw, maxlen=80) or "untitled"
        folder = f"{seq}_{subj_safe}"
        # Avoid collisions when multiple messages share a (sanitized) subject
        if folder in used_names:
            folder = f"{folder}__{msg_id}"
        used_names.add(folder)
        base_dir = f"WinLink/{folder}".replace("\\", "/")

        # Body file named by the subject, as requested
        body_name = _safe_fs_name(subj_raw, maxlen=120) or "untitled"
        body_arc = f"{base_dir}/{seq}_{body_name}.txt".replace("\\", "/")
        try:
            zf.writestr(body_arc, body_txt)
            summary["bodies_written"] += 1
        except Exception:
            pass

        # Attachments — filesystem-first; optional HTTP fallback (env AOCT_EXPORT_WINLINK_HTTP_FALLBACK)
        files = _list_existing_attachments(msg_id)
        added_names = set()
        for abs_path, bn in files:
            arc = f"{base_dir}/attachments/{bn}".replace("\\", "/")
            try:
                zf.write(abs_path, arc)
                summary["attachments_added"] += 1
                added_names.add(bn)
            except Exception:
                pass

        # If none found (or incomplete), consult index JSON, then try FS again by name, else HTTP
        try_names = []
        if not files and HTTP_FALLBACK:
            try_names = _fetch_attachment_index_json(msg_id) or []
        for name in try_names:
            if not name or name in added_names:
                continue
            # Try mapping the name onto our candidate dirs
            found = False
            for cand in _candidate_attach_dirs_for(msg_id):
                full = os.path.join(cand, name)
                if os.path.isfile(full):
                    try:
                        arc = f"{base_dir}/attachments/{name}".replace("\\","/")
                        zf.write(full, arc)
                        summary["attachments_added"] += 1
                        added_names.add(name)
                        found = True
                        break
                    except Exception:
                        pass
            if not found and HTTP_FALLBACK:
                if _try_add_http_attachment(zf, msg_id, name, base_dir):
                    summary["attachments_added"] += 1
                    added_names.add(name)
        if files or body_txt:
            summary["folders_made"] += 1
    return summary

@bp.get('/exports/manifests.zip')
def export_manifests_only_zip():
    """Zip of all saved manifests (canonical + any legacy DB paths)."""
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        added = _zip_add_manifests(zf)
        zf.writestr('manifests/_index.json', json.dumps({"kind":"manifests","added":added}, indent=2))
    mem.seek(0)
    ts = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    return send_file(mem, mimetype='application/zip', as_attachment=True, download_name=f'manifests_{ts}.zip')


@bp.route('/export_csv')
def export_csv():
    """Back-compat alias → use the same generator as /exports/communications.csv (v2 schema)."""
    try:
        filters = parse_comm_filters(request)
    except Exception:
        filters = {"window": "all", "direction": "any", "method": "", "q": ""}
    csv_text = _generate_communications_csv_text(filters)
    buf = io.BytesIO(csv_text.encode('utf-8-sig'))  # Excel-friendly BOM
    return send_file(buf, mimetype='text/csv', as_attachment=True, download_name='communications.csv')

@bp.route('/export_all_csv')
def export_all_csv():
    """Download incoming, outgoing, and inventory logs as a ZIP."""
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        conn = sqlite3.connect(DB_FILE)

        # ► Export-All should always be ALL TIME for data files.
        filters_all = {"window": "all", "direction": "any", "method": "", "q": ""}

        # --- communications.csv (authoritative; v2 schema, ALL TIME) ---
        comm_csv = _generate_communications_csv_text(filters_all)
        zf.writestr('communications.csv', comm_csv)

        # --- flight_cargo.csv (itemized cargo per outbound flight) ---
        cargo_csv = _generate_flight_cargo_csv_text(filters_all)
        zf.writestr('flight_cargo.csv', cargo_csv)

        # --- flights.csv (canonical flight data export) ---
        flights_csv = _generate_flights_csv_text(filters_all)
        zf.writestr('flights.csv', flights_csv)

        # --- inventory_entries.csv ---
        buf = io.StringIO(); cw = csv.writer(buf)
        cw.writerow([
            'ID','CategoryID','RawName','SanitizedName',
            'WeightPerUnit','Quantity','TotalWeight',
            'Direction','Timestamp','Source'
        ])
        for row in conn.execute("""
            SELECT id, category_id, raw_name, sanitized_name,
                   weight_per_unit, quantity, total_weight,
                   direction, timestamp, source
              FROM inventory_entries
        """):
            # Guard textual columns against Excel formula interpretation
            rid, cat_id, raw_name, san_name, wpu, qty, tot_w, direction, ts, source = row
            cw.writerow([
                _csv_safe(rid), _csv_safe(cat_id),
                _csv_safe(raw_name), _csv_safe(san_name),
                _csv_safe(wpu), _csv_safe(qty), _csv_safe(tot_w),
                _csv_safe(direction), _csv_safe(ts), _csv_safe(source)
            ])
        zf.writestr('inventory_entries.csv', buf.getvalue())

        # ── Add ICS-309 (ALL TIME) as a single-file HTML into the ZIP ──
        def _ics_ctx_for_zip():
            f = {"window": "all", "direction": "any", "method": "", "q": ""}
            return _ics309_context_from_filters(f)
        ics_ctx = _ics_ctx_for_zip()
        ics_html = render_template("ics309_standalone.html", **ics_ctx)
        zf.writestr('ics309_all.html', ics_html)

        # ── Add ICS-214 (ALL TIME) as a single-file HTML using saved header prefs ──
        try:
            from modules.routes.staff import _ics214_context as _ics214_context
            ics214_ctx  = _ics214_context("all")
            ics214_html = render_template("ics214_standalone.html", **ics214_ctx)
            zf.writestr('ics214_all.html', ics214_html)
        except Exception:
            # Don’t fail the whole export if staff data isn’t present
            pass

        conn.close()

        # ── Include any persisted PDFs ───────────────────────────────
        try:
            root = os.path.join(_data_root(), "waivers")
            if os.path.isdir(root):
                for dirpath, _dirs, files in os.walk(root):
                    for fn in files:
                        if fn.lower().endswith(".pdf"):
                            full = os.path.join(dirpath, fn)
                            # keep folder structure under waivers/
                            arc = os.path.relpath(full, _data_root()).replace("\\","/")
                            zf.write(full, arc)
        except Exception:
            pass

        # ── Include all PAI PDFs under PilotAircraftInformation/ ─────
        try:
            pai_root = _pai_exports_root()
            if os.path.isdir(pai_root):
                for _dirpath, _dirs, files in os.walk(pai_root):
                    for fn in files:
                        if not fn.lower().endswith(".pdf"):
                            continue
                        full = os.path.join(pai_root, fn)
                        arc  = ("PilotAircraftInformation/" + fn).replace("\\", "/")
                        zf.write(full, arc)
        except Exception:
            pass

        # ── Include all Ramp Manifest PDFs under manifests/ ─────────
        #   - Picks up canonical data/manifests/YYYY/MM/…/*.pdf
        #   - Also sweeps any DB-stamped legacy paths to manifests/_legacy/
        try:
            added = _zip_add_manifests(zf)
            # Optional: a tiny count marker in the zip root (not required)
            try:
                zf.writestr('manifests/_COUNT.txt', str(added))
            except Exception:
                pass
        except Exception:
            pass

        # ── WinLink per-message folders (inbound): subject-named dirs + body + attachments
        try:
            _ = _zip_add_winlink_message_folders(zf)
        except Exception:
            # Never break export-all on WinLink hiccups
            pass

    mem_zip.seek(0)
    # Build filename: {default origin}_yyyymmdd-hhmmss_{mission number}_export_all.zip
    ts = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    try:
        origin = (get_preference('default_origin') or '').strip().upper()
    except Exception:
        origin = ''
    try:
        mission = (get_preference('mission_number') or '').strip().upper()
    except Exception:
        mission = ''
    def _tok(val: str, fallback: str) -> str:
        # Keep only safe token chars to avoid filesystem issues
        s = re.sub(r'[^A-Za-z0-9_-]+', '', (val or '').upper())
        return s if s else fallback
    fname = f"{_tok(origin, 'UNKNOWN')}_{ts}_{_tok(mission, 'NOMSN')}_export_all.zip"

    return send_file(
        mem_zip,
        mimetype='application/zip',
        as_attachment=True,
        download_name=fname
    )

@bp.route('/import_csv', methods=['POST'])
def import_csv():
    f = request.files.get('csv_file')
    if not f:
        flash("No file selected for import.", "error")
        return redirect(url_for('preferences.preferences'))

    text   = f.read().decode('utf-8', errors='replace')
    rdr    = csv.reader(io.StringIO(text))
    header = [h.strip().lower() for h in next(rdr, [])]
    expected = ['sender','subject','body','timestamp',
                'tail#','from','to','t/o','eta','cargo','weight','remarks']
    if header != expected:
        flash(f"Bad CSV header: {header}", "error")
        return redirect(url_for('preferences.preferences'))

    inserted = 0
    # switch to DictReader so we can refer to rec['Remarks']
    dictreader = csv.DictReader(io.StringIO(text), fieldnames=header)
    # skip the header row
    next(dictreader)

    for rec in dictreader:
        # build a parsed record
        p = parse_csv_record({
            'Sender':    rec['sender'],
            'Subject':   rec['subject'],
            'Body':      rec['body'],
            'Timestamp': rec['timestamp'],
            'Tail#':     rec['tail#'],
            'From':      rec['from'],
            'To':        rec['to'],
            'T/O':       rec['t/o'],
            'ETA':       rec['eta'],
            'Cargo':     rec['cargo'],
            'Weight':    rec['weight'],
            'Remarks':   rec['remarks']
        })

        # apply it — this writes to incoming_messages *and* updates/creates a flights row
        fid, action = apply_incoming_parsed(p)
        inserted += 1

    flash(f"Imported and applied {inserted} rows from CSV.", "import")
    # if we came from the Admin console, stay there
    ref = request.referrer or ""
    if ref.endswith(url_for('admin.admin')) or "/admin" in ref:
        return redirect(url_for('admin.admin'))
    return redirect(url_for('preferences.preferences'))

# ─────────────────────────────────────────────────────────────────────────────
# Remote Inventory CSV export
#   /exports/remote_inventory.csv?airport=AAA
# ─────────────────────────────────────────────────────────────────────────────
@bp.get('/exports/remote_inventory.csv')
def export_remote_inventory_csv():
    code = (request.args.get('airport') or '').strip().upper()
    if not code:
        flash("Missing ?airport= code.", "error")
        return redirect(url_for('preferences.preferences'))

    canon = canonical_airport_code(code)
    rows = dict_rows("""
      SELECT airport_canon, snapshot_at, csv_text
        FROM remote_inventory
       WHERE airport_canon = ?
       LIMIT 1
    """, (canon,))
    if not rows:
        flash(f"No remote snapshot for {canon}.", "error")
        return redirect(url_for('preferences.preferences'))

    csv_text = rows[0].get('csv_text') or ''
    if not csv_text.strip():
        flash(f"Snapshot for {canon} has no CSV.", "error")
        return redirect(url_for('preferences.preferences'))

    # ── Normalize to spec CSV header:
    # airport,category,sanitized_name,weight_per_unit_lb,quantity,total_lb
    # Accept legacy headers and rewrite.
    text = csv_text.strip()
    # Drop any leading "CSV" marker line if present
    first_line = (text.splitlines()[0] if text else "").strip().lower()
    if first_line in ("csv", "csv:"):
        text = "\n".join(text.splitlines()[1:])

    rdr = csv.DictReader(io.StringIO(text))
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["airport","category","sanitized_name","weight_per_unit_lb","quantity","total_lb"])

    def _to_float(x, default=0.0):
        try:
            return float(x)
        except Exception:
            return default
    def _to_int(x, default=0):
        try:
            return int(float(x))
        except Exception:
            return default

    for r in rdr:
        ap   = (r.get("airport") or canon or "").strip().upper()
        cat  = (r.get("category") or "").strip()
        name = (r.get("sanitized_name") or r.get("item") or "").strip()
        wpu  = (
            r.get("weight_per_unit_lb") or
            r.get("unit_weight_lb") or
            r.get("unit_weight_lbs") or
            ""
        )
        qty  = r.get("quantity") or ""
        tot  = r.get("total_lb") or r.get("total_weight_lb") or ""

        wpu_f = _to_float(wpu, 0.0)
        qty_i = _to_int(qty, 0)
        tot_f = _to_float(tot, 0.0)
        if not tot and (wpu_f and qty_i):
            tot_f = round(wpu_f * qty_i, 1)

        w.writerow([
            _csv_safe(ap),
            _csv_safe(cat),
            _csv_safe(name),
            _csv_safe(wpu_f),
            _csv_safe(qty_i),
            _csv_safe(round(tot_f, 1))
        ])

    out.seek(0)
    buf = io.BytesIO(out.getvalue().encode('utf-8-sig'))  # Excel-friendly BOM
    fname = f"remote_inventory_{canon}.csv"
    return send_file(buf, mimetype='text/csv', as_attachment=True, download_name=fname)

# ─────────────────────────────────────────────────────────────────────────────
# ICS-309 (HTML only)
#   GET /comms/ics309         → print view (extends base)
#   GET /comms/ics309.html    → single-file HTML download (no external assets)
# Accepts same filters as /comms: ?window=12h|24h|72h|all&method=&direction=&q=
# ─────────────────────────────────────────────────────────────────────────────

def _filters_from_request():
    # thin wrapper for templates that expect this symbol
    return parse_comm_filters(request)

def _sql_for_filters(f):
    # thin wrapper for local callers still using the old name
    return sql_for_comm_filters(f)

def _fetch_comm_rows(f, limit=5000):
    where_sql, params = sql_for_comm_filters(f)
    sql = f"""
      SELECT id, timestamp_utc, method, direction, from_party, to_party,
             subject, body, operator, metadata_json
        FROM communications
        {where_sql}
       ORDER BY timestamp_utc ASC, id ASC
       LIMIT ?
    """
    return dict_rows(sql, tuple(params) + (limit,))

def _op_period_bounds(f, rows):
    """Return (from_dt, to_dt) in UTC for header."""
    hours = COMM_WINDOWS[f["window"]]
    now = datetime.now(timezone.utc)
    if hours is not None:
        return now - timedelta(hours=hours), now
    # derive from data if 'all'
    if rows:
        try:
            fst = rows[0]["timestamp_utc"]; lst = rows[-1]["timestamp_utc"]
            fdt = datetime.fromisoformat((fst or "").replace("Z","+00:00"))
            tdt = datetime.fromisoformat((lst or "").replace("Z","+00:00"))
            return fdt, tdt
        except Exception:
            pass
    return None, None

def _ics309_context_from_filters(f):
    rows = _fetch_comm_rows(f)

    # Build table rows
    table = []
    seq = 1
    for r in rows:
        ts_raw = r.get("timestamp_utc") or ""
        try:
            hhmm = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).strftime("%H:%M")
        except Exception:
            hhmm = (ts_raw[11:16] if len(ts_raw) >= 16 else "")
        subj = (r.get("subject") or "").strip()
        body = (r.get("body") or "").strip()
        msg  = (f"{subj}: {body}" if subj and body else subj or body)
        # Red Flight: normalize/expand a single "Infrastructure: ..." slot
        try:
            meta = json.loads(r.get("metadata_json") or "{}") or {}
        except Exception:
            meta = {}
        if (meta.get("kind") == "red_flight") and meta.get("infrastructure"):
            parts = []
            for it in (meta.get("infrastructure") or []):
                nm = (it.get("name") or "").strip()
                dm = (it.get("damage") or "").strip()
                if nm or dm:
                    parts.append(f"{nm} — {dm}".strip(" —"))
            if parts:
                infra_list = "; ".join(parts)
                import re as _re
                # If message already contains an Infrastructure: fragment, replace just that fragment up to the next " | " (if any).
                if _re.search(r'Infrastructure\s*:', msg, _re.IGNORECASE):
                    msg = _re.sub(r'(Infrastructure\s*:)[^|]*', r'\1 ' + infra_list, msg, flags=_re.IGNORECASE)
                else:
                    msg = (msg + (" | " if msg else "") + "Infrastructure: " + infra_list).strip()
        table.append({
            "seq": seq,
            "time_utc": hhmm,
            "from_id": (r.get("from_party") or ""),
            "from_msg_no": "",   # left blank for manual numbering if desired
            "to_id":   (r.get("to_party") or ""),
            "to_msg_no": "",
            "message": msg,
            "method": (r.get("method") or ""),
        })
        seq += 1

    # Header fields
    op_from, op_to = _op_period_bounds(f, rows)
    def _fmt_dt(dt):
        if not dt: return {"date":"", "time":""}
        return {"date": dt.strftime("%Y-%m-%d"), "time": dt.strftime("%H:%M")}

    # Helpers to allow URL overrides but persist to preferences
    def _arg_or_pref(arg_key, pref_key, default=""):
        v = (request.args.get(arg_key) or "").strip()
        if v != "":
            return v
        try:
            return get_preference(pref_key) or default
        except Exception:
            return default

    incident_name_default = os.getenv("AOCT_INCIDENT_NAME") or ""
    incident_name = _arg_or_pref("incident_name", "incident_name", incident_name_default)
    radio_net     = _arg_or_pref("radio_network_name", "radio_network_name",
                                 (f["method"] if f.get("method") else "Mixed"))

    operator_lbl  = (
        session.get("operator_call") or
        request.cookies.get("operator_call") or
        get_preference("winlink_callsign_1") or
        ""
    )

    radio_operator = _arg_or_pref("radio_operator", "radio_operator", operator_lbl)
    prepared_by    = _arg_or_pref("prepared_by", "ics309_prepared_by", radio_operator)

    # Build display value that appends Mission Number (if available)
    mission_number_val = _arg_or_pref("mission_number", "mission_number", "").strip()
    if mission_number_val:
        suffix = f"Mission Number: {mission_number_val}"
        if suffix.lower() in incident_name.lower():
            incident_name_display = incident_name
        else:
            incident_name_display = (incident_name + (" — " if incident_name else "") + suffix).strip(" —")
    else:
        incident_name_display = incident_name

    ctx = {
        "filters": f,
        "rows": table,
        "incident_name": incident_name,
        # Display value always appends Mission Number if available
        "incident_name_display": incident_name_display,
        "op_from_date": _fmt_dt(op_from)["date"],
        "op_from_time": _fmt_dt(op_from)["time"],
        "op_to_date":   _fmt_dt(op_to)["date"],
        "op_to_time":   _fmt_dt(op_to)["time"],
        "radio_network_name": radio_net,
        "radio_operator": radio_operator,
        "prepared_by": prepared_by,
        "prepared_dt": datetime.utcnow().strftime("%Y-%m-%d %H:%MZ"),
        # Keep Airport Ops highlighted in navbar
        "active": "supervisor",
        # Auto-open the header modal if anything important is blank
        "show_header_modal": not all([incident_name, radio_net, radio_operator, prepared_by]),
    }
    return ctx

def _ics309_context():
    # Default to ALL TIME when no explicit ?window= is provided,
    # so a direct visit to /comms/ics309 also shows full history by default.
    f = parse_comm_filters(request)
    if "window" not in request.args or (request.args.get("window") or "").strip() == "":
        f["window"] = "all"
    return _ics309_context_from_filters(f)

@bp.get("/comms/ics309")
def comms_ics309():
    """ICS-309 page (harmonized with ICS-214): base layout + controls row + header modal."""
    ctx = _ics309_context()
    return render_template("ics309.html", **ctx)

@bp.get("/comms/ics309.html", endpoint="comms_ics309_download")
def comms_ics309_download():
    """
    Return a fully self-contained single-file HTML (no external CSS/JS).
    """
    ctx = _ics309_context()
    html = render_template("ics309_standalone.html", **ctx)
    return send_file(
        io.BytesIO(html.encode("utf-8")),
        mimetype="text/html; charset=utf-8",
        as_attachment=True,
        download_name="ICS-309.html",
    )

# ─────────────────────────────────────────────────────────────────────────────
# ICS-309 — save header preferences (AJAX)
# POST /comms/ics309/prefs
# Body: form or JSON with incident_name, radio_network_name, radio_operator, prepared_by
# ─────────────────────────────────────────────────────────────────────────────
@bp.post("/comms/ics309/prefs")
def comms_ics309_save_prefs():
    data = request.get_json(silent=True) or request.form
    fields = {
        "incident_name":       (data.get("incident_name") or "").strip(),
        "radio_network_name":  (data.get("radio_network_name") or "").strip(),
        "radio_operator":      (data.get("radio_operator") or "").strip(),
        "ics309_prepared_by":  (data.get("prepared_by") or "").strip(),
    }
    for k, v in fields.items():
        set_preference(k, v)
    return jsonify({"ok": True, "saved": fields})

# ─────────────────────────────────────────────────────────────────────────────
# Authoritative communications.csv (v2 — no flight fields)
#   • Source: communications table
#   • Columns: Timestamp, Direction, Contact, Subject, Body, Method, Operator, FromParty, ToParty, Metadata
#   • Route: /exports/communications.csv?window=12h|24h|72h|all&method=&direction=&q=
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_text(s: str | None) -> str:
    """Flatten CR/LF and trim surrounding whitespace."""
    if s is None:
        return ''
    return str(s).replace('\r', ' ').replace('\n', ' ').strip()

# Back-compat shim: route local calls to the shared sanitizer
def _csv_safe(s):  # keep name used in this module
    from modules.utils.common import safe_csv_cell
    return safe_csv_cell(s)

def _csv_header_comm_v2() -> list[str]:
    return [
        'Timestamp','Direction','Contact','Subject','Body',
        'Method','Operator','FromParty','ToParty','Metadata'
    ]

def _csv_header_17() -> list[str]:
    # Original 12 columns (unchanged order/names) + 5 appended
    return [
        'Timestamp','Direction','Contact','Tail#',
        'From','To','T/O','ETA','Cargo','Weight',
        'Subject','Body',
        # appended (authoritative/canonical)
        'Method','Operator','FromParty','ToParty','Metadata'
    ]

def _row_comm_v2(r: dict) -> list:
    """Map a communications row to the v2 CSV schema (no flight fields)."""
    # Timestamp: use canonical UTC timestamp string verbatim
    ts = (r.get("timestamp_utc") or "").strip()
    # Direction: keep canonical 'in'/'out'/'internal'
    direction = (r.get("direction") or "").strip().lower()
    # Contact: outbound → operator; otherwise prefer from_party → operator → to_party
    from_party = (r.get("from_party") or "").strip()
    to_party   = (r.get("to_party")   or "").strip()
    operator   = (r.get("operator")   or "").strip()
    contact = operator if direction == "out" and operator else (from_party or operator or to_party)
    # Subject/body
    subj = _csv_safe(r.get("subject"))
    body = _csv_safe(r.get("body"))
    # Appended canonical fields
    method = _csv_safe((r.get("method") or "").strip())
    # Minify metadata JSON if present
    meta_raw = r.get("metadata_json") or ""
    try:
        meta_min = json.dumps(json.loads(meta_raw), separators=(',', ':')) if meta_raw else ''
    except Exception:
        meta_min = _normalize_text(meta_raw)

    return [
        _csv_safe(ts),
        _csv_safe(direction),
        _csv_safe(contact),
        subj,
        body,
        method,
        _csv_safe(operator),
        _csv_safe(from_party),
        _csv_safe(to_party),
        _csv_safe(meta_min),
    ]

def _generate_communications_csv_text(filters: dict | None = None) -> str:
    """Build CSV text for communications.csv (v2 schema, no flight fields)."""
    f = filters or {"window": "all", "direction": "any", "method": "", "q": ""}
    rows = _fetch_comm_rows(f, limit=500000)  # generous cap for on-demand export
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(_csv_header_comm_v2())
    for r in rows:
        w.writerow(_row_comm_v2(r))
    return out.getvalue()

@bp.get('/exports/communications.csv')
def export_communications_csv():
    """Authoritative communications CSV (v2). Accepts window/method/direction/q filters."""
    try:
        filters = parse_comm_filters(request)
    except Exception:
        filters = {"window": "all", "direction": "any", "method": "", "q": ""}
    csv_text = _generate_communications_csv_text(filters)
    buf = io.BytesIO(csv_text.encode('utf-8-sig'))  # Excel-friendly BOM
    return send_file(
        buf,
        mimetype='text/csv',
        as_attachment=True,
        download_name='communications.csv'
    )

# ─────────────────────────────────────────────────────────────────────────────
# Flights CSV (new, non-legacy shape)
#   • Primary source: flights table (current canonical flight rows)
#   • Fallback: flight_history.data (JSON) if flights table missing/empty
#   • Columns: Timestamp, Direction, Tail#, From, To, T/O, ETA, Cargo, Weight,
#              Remarks, FlightCode, Operator
#   • Accepts same filters as communications: window=12h|24h|72h|all, direction=in|out|any, q=
#   • No legacy "Contact" or flight-origin/dest placeholders — this is real flight data.
# ─────────────────────────────────────────────────────────────────────────────

def _flight_ts_expr():
    """
    Build a COALESCE() expression for a best-effort flight timestamp that works
    across slightly different schemas. Uses table columns if present, else JSON.
    """
    # Introspect available columns
    cols = {r["name"] for r in dict_rows("PRAGMA table_info(flight_history)")} if dict_rows else set()
    exprs = []
    for cand in ("timestamp_utc", "timestamp", "created_at", "updated_at"):
        if cand in cols:
            exprs.append(cand)
    # Always include JSON candidates as fallbacks
    exprs.append("json_extract(data,'$.timestamp_utc')")
    exprs.append("json_extract(data,'$.timestamp')")
    return "COALESCE(" + ",".join(exprs) + ")"

def _sql_for_flight_filters(f):
    """
    Build WHERE and params for flight_history using the dynamic ts expression.
    """
    where, params = [], []
    tsx = _flight_ts_expr()
    # Normalize timestamp comparison: compare only the first 19 chars
    # (YYYY-MM-DDTHH:MM:SS) so naive vs "+00:00"/"Z" strings don't kill matches.
    tsx_norm = f"substr({tsx},1,19)"
    hours = COMM_WINDOWS[f["window"]]
    if hours is not None:
        since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
        where.append(f"{tsx_norm} >= ?")
        params.append(since)
    # Direction in flight history is 'inbound'/'outbound'; accept comms-style too.
    dir_raw = (f.get("direction") or "").lower()
    if dir_raw in ("in", "out", "inbound", "outbound"):
        dir_map = {"in": "inbound", "out": "outbound"}
        dir_val = dir_map.get(dir_raw, dir_raw)
        where.append("LOWER(IFNULL(json_extract(data,'$.direction'),'')) = ?")
        params.append(dir_val)
    # Basic free-text over a few useful JSON fields
    if f["q"]:
        like = f"%{f['q']}%"
        where.append("("
                     "IFNULL(json_extract(data,'$.tail_number'),'') LIKE ? OR "
                     "IFNULL(json_extract(data,'$.airfield_takeoff'),'') LIKE ? OR "
                     "IFNULL(json_extract(data,'$.airfield_landing'),'') LIKE ? OR "
                     "IFNULL(json_extract(data,'$.remarks'),'') LIKE ? OR "
                     "IFNULL(json_extract(data,'$.cargo_type'),'') LIKE ? OR "
                     "IFNULL(json_extract(data,'$.flight_code'),'') LIKE ?"
                     ")")
        params += [like, like, like, like, like, like]
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    return tsx, where_sql, params

def _sql_for_flights_table_filters(f):
    """
    Build WHERE and params for the flights table.
    Normalizes timestamp comparison so 'YYYY-MM-DD HH:MM:SS' and 'YYYY-MM-DDTHH:MM:SS'
    both match against the same 'since' string.
    """
    where, params = [], []
    # Normalize to 'YYYY-MM-DDTHH:MM:SS' for comparison
    tsx = "substr(REPLACE(IFNULL(timestamp,''),' ','T'),1,19)"
    hours = COMM_WINDOWS[f["window"]]
    if hours is not None:
        # Use UTC and subtract the window hours; clip to seconds (avoid lexicographic mismatches)
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        where.append(f"{tsx} >= ?")
        params.append(since)
    # Direction in flights is 'inbound'/'outbound'; accept 'in'/'out' too.
    dir_raw = (f.get("direction") or "").lower()
    if dir_raw in ("in", "out", "inbound", "outbound"):
        dir_map = {"in": "inbound", "out": "outbound"}
        dir_val = dir_map.get(dir_raw, dir_raw)
        where.append("LOWER(IFNULL(direction,'')) = ?")
        params.append(dir_val)
    # Basic free-text over tail, origin/dest, remarks, cargo_type, flight_code
    q = (f.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        where.append("("
                     "IFNULL(tail_number,'') LIKE ? OR "
                     "IFNULL(airfield_takeoff,'') LIKE ? OR "
                     "IFNULL(airfield_landing,'') LIKE ? OR "
                     "IFNULL(remarks,'') LIKE ? OR "
                     "IFNULL(cargo_type,'') LIKE ? OR "
                     "IFNULL(flight_code,'') LIKE ?"
                     ")")
        params += [like, like, like, like, like, like]
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    return where_sql, params

def _fetch_flights_table_rows(f, limit=500000):
    where_sql, params = _sql_for_flights_table_filters(f)
    sql = f"""
      SELECT id,
             IFNULL(timestamp,'')            AS ts,
             IFNULL(direction,'')            AS direction,
             IFNULL(tail_number,'')          AS tail_number,
             IFNULL(airfield_takeoff,'')     AS origin,
             IFNULL(airfield_landing,'')     AS dest,
             IFNULL(takeoff_time,'')         AS takeoff_time,
             IFNULL(eta,'')                  AS eta,
             IFNULL(cargo_type,'')           AS cargo_type,
             IFNULL(cargo_weight,'')         AS cargo_weight,
             IFNULL(remarks,'')              AS remarks,
             IFNULL(flight_code,'')          AS flight_code
        FROM flights
        {where_sql}
    ORDER BY ts ASC, id ASC
       LIMIT ?
    """
    return dict_rows(sql, tuple(params) + (limit,))

def _fetch_flight_rows(f, limit=500000):
    tsx, where_sql, params = _sql_for_flight_filters(f)
    sql = f"""
      SELECT id, {tsx} AS ts, data
        FROM flight_history
        {where_sql}
    ORDER BY ts ASC, id ASC
       LIMIT ?
    """
    return dict_rows(sql, tuple(params) + (limit,))

def _csv_header_flights():
    return [
        "Timestamp","Direction","Tail#","From","To","T/O","ETA",
        "Cargo","Weight","Remarks","FlightCode","Operator"
    ]

def _normalize_flat(s):
    if s is None: return ""
    return str(s).replace("\r", " ").replace("\n", " ").strip()

def _generate_flights_csv_text(filters: dict | None = None) -> str:
    f = filters or {"window": "all", "direction": "any", "method": "", "q": ""}
    out = io.StringIO()
    headers = _csv_header_flights()
    w = csv.DictWriter(out, fieldnames=headers, extrasaction='ignore')
    w.writeheader()

    # 1) Primary: read from flights table (covers Queue→Send-created flights)
    rows_f = []
    try:
        has_flights = dict_rows("SELECT name FROM sqlite_master WHERE type='table' AND name='flights' LIMIT 1")
        if has_flights:
            rows_f = _fetch_flights_table_rows(f, limit=500000)
    except Exception:
        rows_f = []

    wrote_any = False
    for fl in rows_f:
        fid   = fl.get("id")
        ts    = _normalize_flat(fl.get("ts") or "") or _first_history_ts(int(fid)) if fid is not None else ""
        w.writerow({
            "Timestamp":  _csv_safe(ts),
            "Direction":  _csv_safe(_normalize_flat(fl.get("direction",""))),
            "Tail#":      _csv_safe(_normalize_flat(fl.get("tail_number",""))),
            "From":       _csv_safe(_normalize_flat(fl.get("origin",""))),
            "To":         _csv_safe(_normalize_flat(fl.get("dest",""))),
            "T/O":        _csv_safe(_normalize_flat(fl.get("takeoff_time",""))),
            "ETA":        _csv_safe(_normalize_flat(fl.get("eta",""))),
            "Cargo":      _csv_safe(_normalize_flat(fl.get("cargo_type",""))),
            "Weight":     _csv_safe(_normalize_flat(fl.get("cargo_weight",""))),
            "Remarks":    _csv_safe(_normalize_flat(fl.get("remarks",""))),
            "FlightCode": _csv_safe(_normalize_flat(fl.get("flight_code",""))),
            # Operator isn't stored on flights; leave blank for now.
            "Operator":   _csv_safe(""),
        })
        wrote_any = True

    if wrote_any:
        return out.getvalue()

    # 2) Fallback: legacy path via flight_history JSON (older databases)
    try:
        has_hist = dict_rows("SELECT name FROM sqlite_master WHERE type='table' AND name='flight_history' LIMIT 1")
    except Exception:
        has_hist = []
    if not has_hist:
        return out.getvalue()  # header only, safe fallback

    rows_h = _fetch_flight_rows(f, limit=500000)
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=headers, extrasaction='ignore')
    w.writeheader()

    for r in rows_h:
        ts = _normalize_flat(r.get("ts"))
        try:
            data = json.loads(r.get("data") or "{}")
        except Exception:
            data = {}
        direction  = _csv_safe(_normalize_flat(data.get("direction", "")))
        tail       = _csv_safe(_normalize_flat(data.get("tail_number", "")))
        origin     = _csv_safe(_normalize_flat(data.get("airfield_takeoff", "")))
        dest       = _csv_safe(_normalize_flat(data.get("airfield_landing", "")))
        tko        = _csv_safe(_normalize_flat(data.get("takeoff_time", "")))
        eta        = _csv_safe(_normalize_flat(data.get("eta", "")))
        cargo      = _csv_safe(_normalize_flat(data.get("cargo_type", "")))
        weight     = _csv_safe(_normalize_flat(data.get("cargo_weight", "")))
        remarks    = _csv_safe(_normalize_flat(data.get("remarks", "")))
        flightcode = _csv_safe(_normalize_flat(data.get("flight_code", "")))
        operator   = _csv_safe(_normalize_flat(data.get("operator_call", "")))
        w.writerow({
            "Timestamp": _csv_safe(ts),
            "Direction": direction,
            "Tail#":     tail,
            "From":      origin,
            "To":        dest,
            "T/O":       tko,
            "ETA":       eta,
            "Cargo":     cargo,
            "Weight":    weight,
            "Remarks":   remarks,
            "FlightCode": flightcode,
            "Operator":   operator,
        })
    return out.getvalue()

# ─────────────────────────────────────────────────────────────────────────────
# Flight Cargo CSV
#   • Purpose: log cargo that went OUT by air, itemized.
#   • Name in ZIP: flight_cargo.csv
#   • Columns: Timestamp, Tail#, Origin, Dest, Item, Qty, Weight
#   • Sources (in priority order):
#       1) Normalized rows in flight_cargo (if table exists / rows present)
#       2) Parsed "Manifest: …" text from flights.cargo_type/remarks
#   • Window filter: same as other exports (COMM_WINDOWS), based on flights.timestamp
# ─────────────────────────────────────────────────────────────────────────────

_CARGO_HEADERS = ["Timestamp","Tail#","Origin","Dest","Item","Qty","Weight"]

def _first_history_ts(flight_id: int) -> str:
    """
    Fallback to earliest flight_history timestamp if flights.timestamp is NULL.
    Uses the same dynamic expression as _flight_ts_expr().
    """
    try:
        tsx = _flight_ts_expr()
        rows = dict_rows(
            f"SELECT MIN({tsx}) AS ts FROM flight_history WHERE flight_id=?",
            (flight_id,)
        )
        return (rows[0].get("ts") or "") if rows else ""
    except Exception:
        return ""

def _parse_manifest_items(txt: str) -> list[dict]:
    """
    Parse strings like:
      'Manifest: spaghetti 1.5 lb×3; spaghetti sauce 2 lb×6;'
    Tolerates 'x' or '×', optional unit (lb|lbs|kg). Returns list of dicts:
      {item, qty (int), weight (float, lbs)}
    """
    if not txt:
        return []
    s = txt.strip()
    # Only look at the substring after "Manifest:" if present
    m = re.search(r'manifest\s*:\s*(.*)$', s, re.IGNORECASE)
    if m:
        s = m.group(1)
    parts = [p.strip() for p in re.split(r'[;,\n]+', s) if p.strip()]
    out = []
    for part in parts:
        # Capture:  name ... <num> <unit?> [x|×] <qty>
        # name is lazy (stops before the number)
        rx = re.compile(
            r'^\s*(?P<name>.*?)(?<!\S)'
            r'(?P<wpu>\d+(?:\.\d+)?)\s*'
            r'(?P<unit>lb|lbs|kg)?\s*'
            r'[x×]\s*'
            r'(?P<qty>\d+)\s*$', re.IGNORECASE
        )
        mm = rx.match(part)
        if not mm:
            continue
        name = mm.group('name').strip()
        try:
            wpu = float(mm.group('wpu'))
        except Exception:
            continue
        unit = (mm.group('unit') or 'lb').lower()
        try:
            qty = int(mm.group('qty'))
        except Exception:
            continue
        total = wpu * qty
        # Normalize to pounds
        if unit == 'kg':
            total *= 2.20462
        out.append({"item": name, "qty": qty, "weight": round(total, 1)})
    return out

def _rows_from_flight_cargo_table(fid: int) -> list[dict]:
    """
    Try to read normalized items from flight_cargo (if present).
    Returns list of dicts with keys: item, qty, weight (lbs).
    """
    try:
        rows = dict_rows("""
          SELECT
            IFNULL(sanitized_name,'')        AS name,
            IFNULL(quantity,0)               AS qty,
            IFNULL(weight_per_unit,NULL)     AS wpu,
            COALESCE(total_weight,
                     CASE
                       WHEN weight_per_unit IS NOT NULL AND quantity IS NOT NULL
                       THEN weight_per_unit * quantity
                       ELSE NULL
                     END)                    AS total_w
            FROM flight_cargo
           WHERE flight_id=?
        """, (fid,))
    except Exception:
        return []
    out = []
    for r in rows:
        name = (r.get("name") or "").strip()
        try:
            qty = int(r.get("qty") or 0)
        except Exception:
            qty = 0
        try:
            tw = float(r.get("total_w") or 0.0)
        except Exception:
            tw = 0.0
        wpu = r.get("wpu")
        try:
            wpu_f = float(wpu) if wpu is not None else (tw/qty if qty else None)
        except Exception:
            wpu_f = None
        if name and qty > 0 and tw > 0:
            out.append({"item": name, "qty": qty, "weight": round(tw, 1), "size_lb": (round(wpu_f,2) if wpu_f else None)})
    return out

def _generate_flight_cargo_csv_text(filters: dict | None = None) -> str:
    f = filters or {"window": "all", "direction": "any", "method": "", "q": ""}
    hours = COMM_WINDOWS[f["window"]]
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat() if hours is not None else None

    # Pull outbound flights within window
    where = "WHERE LOWER(IFNULL(direction,''))='outbound'"
    params = []
    if since:
        where += " AND IFNULL(timestamp,'') >= ?"
        params.append(since)
    flights = dict_rows(f"""
      SELECT id, IFNULL(timestamp,'') AS ts,
             IFNULL(tail_number,'') AS tail_number,
             IFNULL(airfield_takeoff,'') AS origin,
             IFNULL(airfield_landing,'') AS dest,
             IFNULL(cargo_type,'') AS cargo_type,
             IFNULL(remarks,'')    AS remarks
        FROM flights
        {where}
       ORDER BY ts ASC, id ASC
    """, tuple(params))

    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=_CARGO_HEADERS)
    w.writeheader()

    for fl in flights:
        fid    = fl["id"]
        ts     = (fl.get("ts") or "") or _first_history_ts(fid)
        tail   = _csv_safe((fl.get("tail_number") or "").strip())
        origin = _csv_safe((fl.get("origin") or "").strip())
        dest   = _csv_safe((fl.get("dest") or "").strip())

        # Prefer normalized flight_cargo rows; else parse any "Manifest:" text
        items = _rows_from_flight_cargo_table(fid)
        if not items:
            manifest_txt = " ".join([
                str(fl.get("cargo_type") or ""),
                str(fl.get("remarks") or ""),
            ])
            items = _parse_manifest_items(manifest_txt)

        for it in items:
            w.writerow({
                "Timestamp": _csv_safe(ts),
                "Tail#":     tail,
                "Origin":    origin,
                "Dest":      dest,
                "Item":      _csv_safe(it["item"]),
                "Qty":       it["qty"],
                "Weight":    it["weight"],
            })
    return out.getvalue()

@bp.get('/exports/flights.csv')
def export_flights_csv():
    """
    Canonical flight-data CSV export from flight_history JSON.
    Accepts optional filters: ?window=12h|24h|72h|all&direction=&q=
    """
    try:
        filters = parse_comm_filters(request)
    except Exception:
        filters = {"window": "all", "direction": "any", "method": "", "q": ""}
    csv_text = _generate_flights_csv_text(filters)
    buf = io.BytesIO(csv_text.encode('utf-8'))
    return send_file(buf, mimetype='text/csv', as_attachment=True, download_name='flights.csv')

# ─────────────────────────────────────────────────────────────────────────────
# Waivers & Labels (HTML printables)
#   • GET  /docs/waiver/pilot        → interactive pilot waiver (prefill via args)
#   • GET  /docs/waiver/volunteer    → interactive volunteer waiver
#   • POST /docs/waiver/pilot/print  → pilot waiver, print mode, auto window.print()
#   • POST /docs/waiver/volunteer/print → volunteer waiver, print mode
#   • GET  /docs/labels/cargo?flight_id=…&scope=all|selected[&copies=N][&only=item_slug]
#       - Builds labels from normalized flight_cargo; falls back to parsed manifest.
#       - Renders templates/waivers.html with section="labels"
# ─────────────────────────────────────────────────────────────────────────────

def _ctx_waiver(section: str,
                printed_name: str = "",
                date_iso: str = "",
                initials_map: dict | None = None,
                pilot_signature_b64: str | None = None,
                witness_signature_b64: str | None = None,
                staff_id: str | int | None = None,
                print_mode: bool = False,
                auto_print: bool = False) -> dict:
    """Shared context builder for waivers.html."""
    if not date_iso:
        try:
            # default to today (local server date) for convenience
            date_iso = datetime.utcnow().strftime("%Y-%m-%d")
        except Exception:
            date_iso = ""
    return {
        "section": section,
        "printed_name": printed_name,
        "date_iso": date_iso,
        "initials_map": initials_map or {},
        "pilot_signature_b64": pilot_signature_b64,
        "witness_signature_b64": witness_signature_b64,
        "staff_id": staff_id,
        "print_mode": print_mode,
        "auto_print": auto_print,
        # keep nav highlight consistent with other docs
        "active": "supervisor",
    }


def _extract_initials_map_from_form(formlike) -> dict:
    """
    Accepts fields shaped like: initials[1]=AB, initials[2]=AB, ...
    Also tolerates a JSON field 'initials_map' when posted as JSON.
    """
    if not formlike:
        return {}
    out = {}
    # 1) bracketed fields
    for k, v in (formlike.items() if hasattr(formlike, "items") else []):
        if not isinstance(k, str):
            continue
        if k.startswith("initials[") and k.endswith("]"):
            key = k[9:-1].strip()  # grab digits between [ ]
            if key:
                out[str(key)] = (v or "").strip()
    # 2) direct JSON map
    try:
        jm = formlike.get("initials_map")
        if isinstance(jm, (dict,)):
            for kk, vv in jm.items():
                out[str(kk)] = (vv or "").strip()
    except Exception:
        pass
    return out

def _default_initials_from_name(name: str) -> str:
    """First letter of first token + first letter of last token (uppercased)."""
    words = [w for w in re.split(r'\s+', (name or '').strip()) if w]
    if not words:
        return ''
    if len(words) == 1:
        w = re.sub(r'[^A-Za-z]', '', words[0])
        return (w[:1] + (w[-1:] if len(w) > 1 else '')).upper()
    return (words[0][:1] + words[-1][:1]).upper()

def _staff_printed_name_from_id(staff_id: str | int) -> str:
    """
    Best-effort resolution using modules.utils.staff helpers if available,
    else a lightweight DB fallback against a likely 'staff' table shape.
    Never raises; returns '' if not found.
    """
    sid = str(staff_id or '').strip()
    if not sid:
        return ''
    # Try helper module first
    try:
        from modules.utils import staff as _staff  # type: ignore
        for fn_name in ('get_staff_by_id','staff_by_id','get_staff','lookup','get_staff_record'):
            fn = getattr(_staff, fn_name, None)
            if callable(fn):
                rec = fn(sid)
                if isinstance(rec, dict):
                    for key in ('printed_name','full_name','name'):
                        if rec.get(key):
                            return str(rec[key]).strip()
                    # common split fields
                    first = (rec.get('first_name') or rec.get('first') or '').strip()
                    last  = (rec.get('last_name')  or rec.get('last')  or '').strip()
                    if first or last:
                        return f"{first} {last}".strip()
                # tolerate tuple/list shapes
                if isinstance(rec, (list, tuple)) and rec:
                    return str(rec[0]).strip()
    except Exception:
        pass
    # DB fallback (best-effort)
    try:
        with sqlite3.connect(DB_FILE) as c:
            c.row_factory = sqlite3.Row
            have = c.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='staff' LIMIT 1"
            ).fetchone()
            if not have:  # no table → give up
                return ''
            cols = {r['name'] for r in c.execute("PRAGMA table_info(staff)")}
            if 'printed_name' in cols:
                row = c.execute("SELECT printed_name AS name FROM staff WHERE id=? LIMIT 1", (sid,)).fetchone()
            elif 'full_name' in cols:
                row = c.execute("SELECT full_name  AS name FROM staff WHERE id=? LIMIT 1", (sid,)).fetchone()
            elif {'first_name','last_name'} <= cols:
                row = c.execute("SELECT TRIM(first_name||' '||last_name) AS name FROM staff WHERE id=? LIMIT 1", (sid,)).fetchone()
            elif 'name' in cols:
                row = c.execute("SELECT name FROM staff WHERE id=? LIMIT 1", (sid,)).fetchone()
            else:
                row = None
            return (row['name'].strip() if row and row['name'] else '')
    except Exception:
        return ''

@bp.get("/docs/waiver/pilot")
def docs_waiver_pilot():
    printed = (request.args.get("printed") or request.args.get("printed_name") or "").strip()
    date_iso = (request.args.get("date") or "").strip()
    staff_id = (request.args.get("staff_id") or "").strip()
    if not printed and staff_id:
        printed = _staff_printed_name_from_id(staff_id) or ''
    default_initials = _default_initials_from_name(printed)
    ctx = _ctx_waiver(
        section="pilot_waiver",
        printed_name=printed,
        date_iso=date_iso,
        staff_id=staff_id,
        print_mode=False,
        auto_print=False,
    )
    ctx["default_initials"] = default_initials
    return render_template("waivers.html", **ctx)

@bp.get("/docs/waiver/volunteer")
def docs_waiver_volunteer():
    printed = (request.args.get("printed") or request.args.get("printed_name") or "").strip()
    date_iso = (request.args.get("date") or "").strip()
    staff_id = (request.args.get("staff_id") or "").strip()
    if not printed and staff_id:
        printed = _staff_printed_name_from_id(staff_id) or ''
    default_initials = _default_initials_from_name(printed)
    ctx = _ctx_waiver(
        section="volunteer_waiver",
        printed_name=printed,
        date_iso=date_iso,
        staff_id=staff_id,
        print_mode=False,
        auto_print=False,
    )
    ctx["default_initials"] = default_initials
    return render_template("waivers.html", **ctx)

@bp.post("/docs/waiver/pilot/print")
def docs_waiver_pilot_print():
    data = request.get_json(silent=True) or request.form
    printed = (data.get("printed") or data.get("printed_name") or "").strip()
    date_iso = (data.get("date") or "").strip()
    staff_id = (data.get("staff_id") or request.args.get("staff_id") or "").strip()
    if not printed and staff_id:
        printed = _staff_printed_name_from_id(staff_id) or ''
    initials_map = _extract_initials_map_from_form(data)
    sig_pilot   = data.get("pilot_signature_b64") or data.get("signature_b64")
    sig_witness = data.get("witness_signature_b64")
    ctx = _ctx_waiver(
        section="pilot_waiver",
        printed_name=printed,
        date_iso=date_iso,
        initials_map=initials_map,
        pilot_signature_b64=(sig_pilot or None),
        witness_signature_b64=(sig_witness or None),
        staff_id=staff_id,
        print_mode=True,
        auto_print=True,
    )
    # Compatibility aliases for current template partials
    ctx["pilot_signature_data_uri"] = ctx["pilot_signature_b64"]
    ctx["pilot_witness_signature_data_uri"] = ctx["witness_signature_b64"]
    ctx["pilot_printed"] = ctx["printed_name"]
    ctx["pilot_date"] = ctx["date_iso"]

    html = render_template("waivers.html", **ctx)
    # Persist to PDF (non-blocking if it fails)
    _persist_waiver_pdf("pilot", ctx, html)
    return html

@bp.post("/docs/waiver/volunteer/print")
def docs_waiver_volunteer_print():
    data = request.get_json(silent=True) or request.form
    printed = (data.get("printed") or data.get("printed_name") or "").strip()
    date_iso = (data.get("date") or "").strip()
    staff_id = (data.get("staff_id") or request.args.get("staff_id") or "").strip()
    if not printed and staff_id:
        printed = _staff_printed_name_from_id(staff_id) or ''
    initials_map = _extract_initials_map_from_form(data)
    sig_vol     = data.get("volunteer_signature_b64") or data.get("signature_b64") or data.get("pilot_signature_b64")
    sig_witness = data.get("witness_signature_b64")
    ctx = _ctx_waiver(
        section="volunteer_waiver",
        printed_name=printed,
        date_iso=date_iso,
        initials_map=initials_map,
        pilot_signature_b64=(sig_vol or None),
        witness_signature_b64=(sig_witness or None),
        staff_id=staff_id,
        print_mode=True,
        auto_print=True,
    )
    # Compatibility aliases for current template partials
    ctx["volunteer_signature_data_uri"] = ctx["pilot_signature_b64"]
    ctx["volunteer_witness_signature_data_uri"] = ctx["witness_signature_b64"]
    ctx["volunteer_printed"] = ctx["printed_name"]
    ctx["volunteer_date"] = ctx["date_iso"]

    html = render_template("waivers.html", **ctx)
    # Persist to PDF (non-blocking if it fails)
    _persist_waiver_pdf("volunteer", ctx, html)
    return html

def _data_root() -> str:
    """Root directory for persisted artifacts."""
    root = os.getenv("AOCT_DATA_DIR") or os.path.join(os.getcwd(), "data")
    os.makedirs(root, exist_ok=True)
    return root
def _pai_exports_root() -> str:
    """data/exports/pai — persisted PAI PDFs live here."""
    d = os.path.join(_data_root(), "exports", "pai")
    os.makedirs(d, exist_ok=True)
    return d

def _day_dir(kind: str) -> str:
    """data/waivers/<kind>/YYYY/MM/DD"""
    today = datetime.utcnow()
    d = os.path.join(
        _data_root(), "waivers", kind,
        f"{today:%Y}", f"{today:%m}", f"{today:%d}"
    )
    os.makedirs(d, exist_ok=True)
    return d

def _ensure_waiver_table():
    """Create lightweight log table if missing."""
    sql = """
    CREATE TABLE IF NOT EXISTS waiver_submissions (
      id INTEGER PRIMARY KEY,
      waiver_type TEXT NOT NULL,       -- 'pilot' | 'volunteer'
      staff_id TEXT,
      printed_name TEXT,
      date_iso TEXT,
      initials_json TEXT,
      pilot_signature_path TEXT,
      witness_signature_path TEXT,
      pdf_path TEXT,
      created_at TEXT
    )
    """
    conn = sqlite3.connect(DB_FILE)
    conn.execute(sql)
    # If table existed without staff_id, add it.
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(waiver_submissions)").fetchall()]
        if "staff_id" not in cols:
            conn.execute("ALTER TABLE waiver_submissions ADD COLUMN staff_id TEXT")
    except Exception:
        pass
    conn.commit()
    conn.close()

def _save_data_uri_png(data_or_uri: str | None, out_path: str | None) -> str | None:
    """
    Accepts either a full data URI (data:image/png;base64,...) or a bare base64 PNG/JPEG.
    Writes to disk and returns the path, else None.
    """
    if not data_or_uri or not out_path:
        return None
    s = (data_or_uri or "").strip()
    try:
        if s.lower().startswith("data:image"):
            m = re.match(r'^data:image/(png|jpe?g);base64,(.*)$', s, re.IGNORECASE | re.DOTALL)
            if not m:
                return None
            payload_b64 = m.group(2)
        else:
            payload_b64 = s
        with open(out_path, "wb") as f:
            f.write(base64.b64decode(payload_b64))
        return out_path
    except Exception:
        return None

def _persist_waiver_pdf(waiver_type: str, ctx: dict, html: str) -> str | None:
    """
    Render HTML to PDF via WeasyPrint, save to filesystem, then insert a row in waiver_submissions.
    Returns absolute PDF path (or None on failure). Never raises.
    """
    try:
        _ensure_waiver_table()

        # 1) HTML → PDF
        # Use filesystem base_url so WeasyPrint resolves assets without HTTP,
        # and include /static/style.css so @media print rules apply in the PDF.
        base = current_app.root_path
        stylesheets = []
        try:
            css_file = os.path.join(base, "static", "style.css")
            if os.path.exists(css_file):
                stylesheets.append(CSS(filename=css_file))
        except Exception:
            pass
        pdf_bytes = HTML(string=html, base_url=base).write_pdf(stylesheets=stylesheets)

        # 2) Filenames/paths
        stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        # _slug is declared later in this module; resolution happens at call time.
        name_slug = _slug(ctx.get("printed_name") or "unknown")[:40] or "unknown"
        daydir = _day_dir(waiver_type)
        pdf_path = os.path.join(daydir, f"{waiver_type}_waiver_{stamp}_{name_slug}.pdf")
        sig_path = os.path.join(daydir, f"{waiver_type}_signature_{stamp}_{name_slug}.png")
        wit_path = os.path.join(daydir, f"{waiver_type}_witness_{stamp}_{name_slug}.png")

        # 3) Write PDF
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)

        # 4) Save signatures if present (accept data URIs or bare base64)
        pilot_sig = ctx.get("pilot_signature_b64") or ctx.get("pilot_signature_data_uri")
        witness_sig = ctx.get("witness_signature_b64") or \
                      ctx.get("pilot_witness_signature_b64") or \
                      ctx.get("volunteer_witness_signature_data_uri")
        sig_path_written = _save_data_uri_png(pilot_sig, sig_path) if pilot_sig else None
        wit_path_written = _save_data_uri_png(witness_sig, wit_path) if witness_sig else None

        # 5) Insert DB row
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            """INSERT INTO waiver_submissions
               (waiver_type, staff_id, printed_name, date_iso, initials_json,
                pilot_signature_path, witness_signature_path, pdf_path, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                waiver_type,
                str(ctx.get("staff_id") or ""),
                ctx.get("printed_name") or "",
                ctx.get("date_iso") or "",
                json.dumps(ctx.get("initials_map") or {}),
                sig_path_written or "",
                wit_path_written or "",
                pdf_path,
                datetime.utcnow().isoformat(timespec="seconds") + "Z",
            )
        )
        conn.commit()
        conn.close()
        return pdf_path
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Cargo Labels
#   GET /docs/labels/cargo?flight_id=123&scope=all|selected[&copies=N][&only=item-slug]
#   GET /docs/labels/cargo?queued_id=45&scope=all|selected[&copies=N][&only=item-slug]
# ─────────────────────────────────────────────────────────────────────────────

def _slug(s: str) -> str:
    try:
        return re.sub(r'[^a-z0-9]+', '-', (s or '').lower()).strip('-')
    except Exception:
        return ""

def _labels_for_queued(qid: int,
                       scope: str = "all",
                       only_slug: str | None = None,
                       copies: int = 1) -> list[dict]:
    """
    Build labels from a queued (draft) flight row.
    Prefers parsable manifest data from cargo_type/remarks; if none, emits a single generic label.
    """
    if qid <= 0:
        return []
    # Best-effort: tolerate column drift in queued_flights
    rows = dict_rows("""
      SELECT *
        FROM queued_flights
       WHERE id = ?
       LIMIT 1
    """, (qid,))
    if not rows:
        return []
    q = rows[0]
    # safe getters with alias fallbacks
    def get(qobj, *names, default=""):
        for n in names:
            if n in qobj and qobj[n] is not None:
                return str(qobj[n])
        return default
    origin = get(q, "airfield_takeoff", "origin").strip()
    dest   = get(q, "airfield_landing", "destination").strip()
    tail   = get(q, "tail_number", "tail").strip()
    ts     = (get(q, "created_at", "timestamp", "ts") or "")[:10]
    cargo  = get(q, "cargo_type").strip()
    remarks= get(q, "remarks").strip()

    manifest_txt = " ".join([cargo, remarks]).strip()
    items = _parse_manifest_items(manifest_txt)

    if only_slug:
        items = [i for i in items if _slug(i.get("item","")) == only_slug]

    mission = f"Q-{qid}"
    base = []
    if items:
        for it in items:
            name = (it.get("item") or "").strip()
            qty  = int(it.get("qty") or 0)
            tot_w = it.get("weight")
            try:
                weight_lb = f"{float(tot_w):.1f}"
            except Exception:
                weight_lb = ""
            size_lb = it.get("size_lb")
            try:
                size_lb = f"{float(size_lb):.2f}" if size_lb is not None else (f"{float(tot_w)/qty:.2f}" if qty else "")
            except Exception:
                size_lb = ""
            base.append({
                "mission": mission,
                "from_org": "Walla Walla DART",
                "origin": origin,
                "destination": dest,
                "date_sealed": ts,
                "weight_lb": weight_lb,
                "contents": f"{name}" + (f" × {qty}" if qty else ""),
                "name": name, "size_lb": size_lb, "qty": qty, "dest": dest, "tail": tail,
                "flight_code": "",
            })
    else:
        generic = (cargo or remarks or "").strip()
        base.append({
            "mission": mission, "from_org": "Walla Walla DART",
            "origin": origin, "destination": dest, "date_sealed": ts,
            "weight_lb": "", "contents": generic,
        })
    try:
        copies = max(1, min(int(copies), 100))
    except Exception:
        copies = 1
    return base * copies

def _labels_for_flight(fid: int,
                       scope: str = "all",
                       only_slug: str | None = None,
                       copies: int = 1) -> list[dict]:
    """
    Build a list of label dicts:
      { mission, from_org, origin, destination, date_sealed, weight_lb, contents }
    Uses normalized flight_cargo first; falls back to parsing manifest from cargo_type/remarks.
    """
    if fid <= 0:
        return []
    fl_rows = dict_rows("""
      SELECT id,
             IFNULL(timestamp,'')        AS ts,
             IFNULL(flight_code,'')      AS flight_code,
             IFNULL(tail_number,'')      AS tail,
             IFNULL(airfield_takeoff,'') AS origin,
             IFNULL(airfield_landing,'') AS dest,
             IFNULL(cargo_type,'')       AS cargo_type,
             IFNULL(remarks,'')          AS remarks
        FROM flights
       WHERE id = ?
       LIMIT 1
    """, (fid,))
    if not fl_rows:
        return []
    fl = fl_rows[0]

    # Prefer normalized items (flight_cargo)
    items = _rows_from_flight_cargo_table(fid)

    # Fallback: try advanced manifest parser if available; else local simple parser
    if not items:
        manifest_txt = " ".join([
            str(fl.get("cargo_type") or ""),
            str(fl.get("remarks") or ""),
        ]).strip()
        try:
            # parse_adv_manifest may return [{"item":"name","qty":n,"weight":w_lbs}, ...]
            if "parse_adv_manifest" in globals() and callable(globals()["parse_adv_manifest"]):
                adv_items = globals()["parse_adv_manifest"](manifest_txt) or []
                # normalize keys just in case
                items = [{"item": i.get("item",""),
                          "qty": int(i.get("qty") or 0),
                          "weight": float(i.get("weight") or 0.0)} for i in adv_items if i]
            else:
                items = _parse_manifest_items(manifest_txt)
        except Exception:
            items = _parse_manifest_items(manifest_txt)

    # Optional filter by slug (v1.1 nicety)
    if only_slug:
        items = [i for i in items if _slug(i.get("item","")) == only_slug]

    # Selected scope hook (for future use). For now, 'selected' == 'all'.
    _ = scope  # reserved; currently unused in server route

    mission = (fl.get("flight_code") or f"FLT-{fid}").strip()
    origin  = (fl.get("origin") or "").strip()
    dest    = (fl.get("dest") or "").strip()
    tail    = (fl.get("tail") or "").strip()
    date_sealed = (fl.get("ts") or "")[:10]
    base = []
    if items:
        for it in items:
            name = (it.get("item") or "").strip()
            qty  = int(it.get("qty") or 0)
            tot_w = it.get("weight")
            try:
                weight_lb = f"{float(tot_w):.1f}"
            except Exception:
                weight_lb = ""
            size_lb = it.get("size_lb")
            try:
                size_lb = f"{float(size_lb):.2f}" if size_lb is not None else (f"{float(tot_w)/qty:.2f}" if qty else "")
            except Exception:
                size_lb = ""
            base.append({
                "mission": mission,
                "from_org": "Walla Walla DART",
                "origin": origin,
                "destination": dest,
                "date_sealed": date_sealed,
                "weight_lb": weight_lb,
                "contents": f"{name}" + (f" × {qty}" if qty else ""),
                # structured fields (for templates/exports that prefer explicit keys)
                "name": name,
                "size_lb": size_lb,
                "qty": qty,
                "dest": dest,
                "tail": tail,
                "flight_code": mission if mission.startswith("FLT-") is False else "",
            })
    else:
        # No discrete items; produce a single generic label
        generic = (fl.get("cargo_type") or fl.get("remarks") or "").strip()
        base.append({
            "mission": mission,
            "from_org": "Walla Walla DART",
            "origin": origin,
            "destination": dest,
            "date_sealed": date_sealed,
            "weight_lb": "",
            "contents": generic,
        })

    # Apply copies (cap to a sane upper bound)
    try:
        copies = max(1, min(int(copies), 100))
    except Exception:
        copies = 1
    return base * copies


@bp.get("/docs/labels/cargo")
def docs_labels_cargo():
    # Accept either persisted flight or queued draft
    fid = request.args.get("flight_id") or ""
    qid = request.args.get("queued_id") or ""
    try:
        fid_int = int(fid)
    except Exception:
        fid_int = -1
    try:
        qid_int = int(qid)
    except Exception:
        qid_int = -1
    if fid_int <= 0 and qid_int <= 0:
        abort(400, description="Missing ?flight_id or ?queued_id")

    scope = (request.args.get("scope") or "all").strip().lower()
    only  = (request.args.get("only") or "").strip().lower()
    copies = request.args.get("copies") or 1
    labels = (_labels_for_flight(fid_int, scope=scope, only_slug=only, copies=copies)
              if fid_int > 0 else _labels_for_queued(qid_int, scope=scope, only_slug=only, copies=copies))
    if not labels:
        abort(404, description="No labels could be generated for this request.")

    ctx = {
        "section": "labels",
        "labels": labels,
        "print_mode": True,
        "auto_print": True,
        "active": "supervisor",
    }
    return render_template("waivers.html", **ctx)
