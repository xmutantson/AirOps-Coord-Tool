
import sqlite3, csv, io, zipfile, json, os, re

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
        if name and qty > 0 and tw > 0:
            out.append({"item": name, "qty": qty, "weight": round(tw, 1)})
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

