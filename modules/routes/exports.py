
import sqlite3, csv, io, zipfile, json, os

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from app import DB_FILE
from flask import Blueprint, current_app, render_template
from flask import flash, redirect, request, url_for, send_file, session, Response, jsonify
from datetime import datetime, timedelta, timezone
from modules.utils.comms import parse_comm_filters, sql_for_comm_filters, COMM_WINDOWS
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

@bp.route('/export_csv')
def export_csv():
    """Back-compat alias → use the same generator as /exports/communications.csv (v2 schema)."""
    try:
        filters = parse_comm_filters(request)
    except Exception:
        filters = {"window": "24h", "direction": "any", "method": "", "q": ""}
    csv_text = _generate_communications_csv_text(filters)
    buf = io.BytesIO(csv_text.encode('utf-8-sig'))  # Excel-friendly BOM
    return send_file(buf, mimetype='text/csv', as_attachment=True, download_name='communications.csv')

@bp.route('/export_all_csv')
def export_all_csv():
    """Download incoming, outgoing, and inventory logs as a ZIP."""
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        conn = sqlite3.connect(DB_FILE)

        # --- communications.csv (authoritative; v2 schema) ---
        # Reuse the same filters used by ICS-309 endpoints if provided.
        # Defaults to last 24h when not specified (same as ICS-309 UI default).
        try:
            filters = parse_comm_filters(request)
        except Exception:
            filters = {"window": "24h", "direction": "any", "method": "", "q": ""}
        comm_csv = _generate_communications_csv_text(filters)
        zf.writestr('communications.csv', comm_csv)

        # --- flights.csv (canonical flight data export) ---
        flights_csv = _generate_flights_csv_text(filters)
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

        # ── Add ICS-309 (last 24h) as a single-file HTML into the ZIP ──
        def _ics_ctx_for_zip():
            f = {"window": "24h", "direction": "any", "method": "", "q": ""}
            return _ics309_context_from_filters(f)
        ics_ctx = _ics_ctx_for_zip()
        ics_html = render_template("ics309_standalone.html", **ics_ctx)
        zf.writestr('ics309_last24h.html', ics_html)

        # ── Add ICS-214 (last 24h) as a single-file HTML using saved header prefs ──
        try:
            from modules.routes.staff import _ics214_context as _ics214_context
            ics214_ctx  = _ics214_context("24h")
            ics214_html = render_template("ics214_standalone.html", **ics214_ctx)
            zf.writestr('ics214_last24h.html', ics214_html)
        except Exception:
            # Don’t fail the whole export if staff data isn’t present
            pass

        conn.close()

    mem_zip.seek(0)
    return send_file(
        mem_zip,
        mimetype='application/zip',
        as_attachment=True,
        download_name='export_all.zip'
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

    ctx = {
        "filters": f,
        "rows": table,
        "incident_name": incident_name,
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
    return _ics309_context_from_filters(parse_comm_filters(request))

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
    f = filters or {"window": "24h", "direction": "any", "method": "", "q": ""}
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
        filters = {"window": "24h", "direction": "any", "method": "", "q": ""}
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
#   • Source of truth: flight_history.data (JSON)
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
    hours = COMM_WINDOWS[f["window"]]
    if hours is not None:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        where.append(f"{tsx} >= ?"); params.append(since)
    # Direction is stored in JSON; accept 'in'/'out'
    if f["direction"] in ("in", "out"):
        where.append("LOWER(IFNULL(json_extract(data,'$.direction'),'')) = ?")
        params.append(f["direction"])
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
    f = filters or {"window": "24h", "direction": "any", "method": "", "q": ""}
    # If the table doesn't exist, return just the header to stay safe
    try:
        has = dict_rows("SELECT name FROM sqlite_master WHERE type='table' AND name='flight_history' LIMIT 1")
        if not has:
            out = io.StringIO(); csv.writer(out).writerow(_csv_header_flights())
            return out.getvalue()
    except Exception:
        out = io.StringIO(); csv.writer(out).writerow(_csv_header_flights())
        return out.getvalue()

    rows = _fetch_flight_rows(f, limit=500000)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(_csv_header_flights())

    for r in rows:
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
        w.writerow([
            _csv_safe(ts), direction, tail, origin, dest, tko, eta,
            cargo, weight, remarks, flightcode, operator
        ])
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
        filters = {"window": "24h", "direction": "any", "method": "", "q": ""}
    csv_text = _generate_flights_csv_text(filters)
    buf = io.BytesIO(csv_text.encode('utf-8'))
    return send_file(buf, mimetype='text/csv', as_attachment=True, download_name='flights.csv')

