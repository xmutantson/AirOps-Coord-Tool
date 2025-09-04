
import sqlite3, re, os
import time
import requests

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from modules.utils.http import _filter_headers
from app import DB_FILE
from flask import Blueprint, current_app
from flask import Response, abort, flash, jsonify, redirect, render_template, request, stream_with_context, url_for
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

@bp.app_template_filter('hide_tbd')
def hide_tbd_filter(value):
    """
    If the value is a placeholder ('TBD', '----', etc.) return an empty string so
    the table can hide it when the toggle is on. Otherwise, pass it through.
    """
    s = str(value or '').strip()
    if s.upper() in ('TBD', '—', '--', '----'):
        return ''
    return value

@bp.route('/embedded/proxy/', defaults={'path': ''})
@bp.route('/embedded/proxy/<path:path>')
def embedded_proxy(path):
    # dynamically read the admin-configured embedded_url
    upstream_base = get_preference('embedded_url') or ''
    if not upstream_base:
        abort(503, "No embedded_url configured")
    # preserve any sub‑path and query string
    upstream = f"{upstream_base.rstrip('/')}/{path}"
    resp = requests.get(
        upstream,
        params=request.args,
        headers={'User-Agent': request.headers.get('User-Agent', '')},
        stream=True,
    )
    filtered = _filter_headers(resp.raw.headers)
    return Response(
        stream_with_context(resp.raw),
        status=resp.status_code,
        headers=filtered,
    )

@bp.route('/api/lookup_tail/<tail>')
def lookup_tail(tail):
    """Return the newest flight row for a given tail number (JSON) or {}."""
    row = dict_rows(
        "SELECT * FROM flights WHERE tail_number=? ORDER BY id DESC LIMIT 1",
        (tail.upper(),)
    )
    return row[0] if row else {}

@bp.route('/')
def dashboard():
    """
    Render *only* the page skeleton.  The <div id="dashboard-table">
    will be populated via AJAX from /_dashboard_table (streaming).
    """
    # --- Query all flights and map destination status for blue-border ---
    flights_raw = dict_rows("SELECT * FROM flights")
    # convert to dict
    flights = [dict(f) for f in flights_raw]

    # fetch your airport→callsign mapping once
    raw = get_preference('airport_call_mappings') or ''
    mapping = {}
    seen_canon = {}
    for line in raw.splitlines():
        if ':' not in line: continue
        airport, addr = (x.strip().upper() for x in line.split(':', 1))
        canon = canonical_airport_code(airport)
        # conflict check
        if canon in seen_canon and seen_canon[canon] != addr:
            # Show error or refuse to load/save; handle as needed
            continue
        mapping[canon] = addr
        seen_canon[canon] = addr

    # normalize each flight’s destination via your lookup helper
    for f in flights:
        raw_dest = f['airfield_landing']
        canon = canonical_airport_code(raw_dest)
        f['dest_mapped'] = canon in mapping

    # --- Shift check-in modal gating (Step 9) --------------------------
    # Show only on the first page load *after* successful login and
    # only if the cooldown cookie isn't set.
    just_logged_in = bool(session.pop('just_logged_in', None))
    cooldown_cookie = request.cookies.get('checked_in_recently')
    show_checkin = just_logged_in and not cooldown_cookie

    # Prefill fields from prior cookies if present
    last_staff = {
        'name': request.cookies.get('last_staff_name',''),
        'role': request.cookies.get('last_staff_role',''),
        'ew':   request.cookies.get('last_staff_ew',''),
    }

    # pass tail_filter so the input box shows the right value
    tail_filter = request.args.get('tail_filter','').strip().upper()
    airport_filter = request.args.get('airport_filter','').strip().upper()
    return render_template(
        'dashboard.html',
        active='dashboard',
        tail_filter=tail_filter,
        airport_filter=airport_filter,
        mapping=mapping,
        show_checkin=show_checkin,
        last_staff=last_staff
    )

@bp.route('/dashboard/plain')
def dashboard_plain():
    #  1) only allow calls from localhost
    if request.remote_addr not in ('127.0.0.1', '::1'):
        abort(403)

    # 2) pull the top 20 by your normal priority logic
    flights = dict_rows("""
      SELECT *
        FROM flights
       ORDER BY
         CASE
           WHEN sent=0     THEN 0
           WHEN complete=0 THEN 1
           ELSE 2
         END,
         id DESC
       LIMIT 20
    """)
    return jsonify(flights)

@bp.route('/_dashboard_table')
def dashboard_table_partial():
    purge_blank_flights()
    # compute code_pref, mass_pref, hide_tbd, tail_filter, sort_seq, sql, params...

    # Pull in the user’s airport‐code preference (ICAO vs IATA)
    cookie_pref = request.cookies.get('code_format')
    airport_pref = cookie_pref or (
        dict_rows("SELECT value FROM preferences WHERE name='code_format'")
        or [{'value':'icao4'}]
    )[0]['value']

    mass_pref = request.cookies.get('mass_unit','lbs')
    hide_tbd  = request.cookies.get('hide_tbd','yes') == 'yes'

    # ── split comma-sep tail filters into exact tail_numbers list
    tail_filter = request.args.get('tail_filter','').strip().upper()
    # build exact-match list of comma-separated tails
    tail_numbers = (
        [t.strip().upper() for t in tail_filter.split(',') if t.strip()]
        if tail_filter else []
    )

    # optional airport-code filters (comma-sep, uppercased)
    airport_filter = request.args.get('airport_filter','').strip().upper()

    # resolve each comma-sep code into _all_ known aliases
    airport_idents = []
    if airport_filter:
        codes = [c.strip().upper() for c in airport_filter.split(',') if c.strip()]
        aliases = []
        for c in codes:
            aliases.extend(airport_aliases(c))
        # de-duplicate while preserving order
        airport_idents = list(dict.fromkeys(aliases))

    sort_seq = request.cookies.get('dashboard_sort_seq','no') == 'yes'

    # ── read 1090‑distances enable flag ───────────────────────────────
    rows = dict_rows(
        "SELECT value FROM preferences WHERE name='enable_1090_distances'"
    )

    # per‑browser unit preference (for the “Dist (…)" header)
    unit = request.cookies.get('distance_unit','nm')

    show_dist = bool(rows and rows[0]['value']=='yes')

    # build WHERE clauses for tail and airport filters
    sql           = "SELECT * FROM flights"
    where_clauses = []
    params         = []

    if tail_numbers:
        # exact-match tail filter (any of these)
        ph = ",".join("?" for _ in tail_numbers)
        where_clauses.append(f"tail_number IN ({ph})")
        params.extend(tail_numbers)

    if airport_idents:
        ph = ",".join("?" for _ in airport_idents)
        where_clauses.append(
            f"(airfield_takeoff IN ({ph}) OR airfield_landing IN ({ph}))"
        )
        # we need two copies: one for takeoff, one for landing
        params.extend(airport_idents)
        params.extend(airport_idents)

    if where_clauses:
        sql += " WHERE " + " AND ".join(where_clauses)

    # append ORDER BY
    if sort_seq:
        sql += " ORDER BY id DESC"
    else:
        sql += """
          ORDER BY
            CASE
              WHEN is_ramp_entry = 1 AND sent = 0 THEN 0
              WHEN complete = 0                       THEN 1
              ELSE 2
            END,
            id DESC
        """

    # --- Mapping for dest_mapped, just like dashboard ---
    raw = get_preference('airport_call_mappings') or ''
    mapping = {}
    seen_canon = {}
    for line in raw.splitlines():
        if ':' not in line: continue
        airport, addr = (x.strip().upper() for x in line.split(':', 1))
        canon = canonical_airport_code(airport)
        if canon in seen_canon and seen_canon[canon] != addr:
            continue
        mapping[canon] = addr
        seen_canon[canon] = addr

    # Open a DB cursor for streaming (explicitly configure and close later)
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        # Align ad‑hoc connection behavior with init_db() expectations
        conn.execute("PRAGMA busy_timeout=30000;")
    except Exception:
        pass
    raw_cursor = conn.execute(sql, params)


    def gen_rows():
        for r in raw_cursor:
            d = dict(r)

            # --- Add dest_mapped via canonical mapping here, with debug ---
            raw_dest = d.get('airfield_landing','')
            canon = canonical_airport_code(raw_dest)
            d['dest_mapped'] = canon in mapping

            # — airport formatting & views —
            d['origin_view'] = fmt_airport(d.get('airfield_takeoff',''), airport_pref)
            d['dest_view']   = fmt_airport(d.get('airfield_landing',''),  airport_pref)
            if d.get('direction')=='outbound' and d.get('eta') and not d.get('complete'):
                d['eta_view'] = d['eta'] + '*'
            else:
                d['eta_view'] = d.get('eta') or 'TBD'
            cw = (d.get('cargo_weight') or '').strip()
            m_lbs = re.match(r'([\d.]+)\s*lbs', cw, re.I)
            m_kg  = re.match(r'([\d.]+)\s*kg',  cw, re.I)
            if mass_pref=='kg' and m_lbs:
                d['cargo_view'] = f"{round(float(m_lbs.group(1)) / 2.20462, 1)} kg"
            elif mass_pref=='lbs' and m_kg:
                d['cargo_view'] = f"{round(float(m_kg.group(1)) * 2.20462, 1)} lbs"
            else:
                d['cargo_view'] = cw or 'TBD'
            # — distance (only if enabled) + stale‑flag for >5 min old —
            if show_dist:
                unit = request.cookies.get('distance_unit','nm')
                entry = app.extensions['distances'].get(d.get('tail_number'))
                if entry is None:
                    d['distance'] = ''
                    d['distance_stale'] = False
                else:
                    km_val, ts = entry
                    if unit=='mi':
                        val = round(km_val * 0.621371, 1)
                    elif unit=='nm':
                        val = round(km_val * 0.539957, 1)
                    else:
                        val = round(km_val, 1)
                    d['distance'] = val
                    d['distance_stale'] = (time.time() - ts) > 300
            else:
                d['distance'] = ''
                d['distance_stale'] = False

            yield d

    # Let Jinja stream the same partial, iterating over our cursor
    tmpl   = app.jinja_env.get_template('partials/_dashboard_table.html')

    stream = tmpl.stream(
        flights=gen_rows(),
        hide_tbd=hide_tbd,
        enable_1090_distances=show_dist,
        distance_unit=unit
    )

    stream.enable_buffering(5)   # flush up to 5 rows at a time

    # Wrap in stream_with_context so url_for() works, and explicitly
    # close cursor/connection when the response finishes (or client disconnects)
    resp = Response(stream_with_context(stream), mimetype='text/html')

    @resp.call_on_close
    def _close_streaming_handles():
        try:
            raw_cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

    return resp

@bp.post('/reset_db')
def reset_db():
    """Drop the SQLite file, recreate the schema and run migrations."""
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    init_db()          # recreate empty tables
    run_migrations()   # add all current columns

    # ─── rebuild & reload our airports lookup ────────────────
    ensure_airports_table()
    load_airports_from_csv()
    seed_default_categories()

    flash("Database reset and re-initialised.", "db_reset")
    # if we came from the Admin console, stay there
    ref = request.referrer or ""
    if ref.endswith(url_for('admin.admin')) or "/admin" in ref:
        return redirect(url_for('admin.admin'))
    return redirect(url_for('preferences.preferences'))

@bp.route('/embedded')
def embedded():
    # read the two prefs
    url  = dict_rows("SELECT value FROM preferences WHERE name='embedded_url'")
    name = dict_rows("SELECT value FROM preferences WHERE name='embedded_name'")
    embedded_url  = url[0]['value']  if url  else ''
    embedded_name = name[0]['value'] if name else ''

    # nothing to embed? send back home
    if not (embedded_url and embedded_name):
        return redirect(url_for('core.dashboard'))

    mode = get_preference('embedded_mode') or 'iframe'
    template = mode == 'proxy' and 'embedded.html' or 'embedded-iframe.html'

    return render_template(
        template,
        url=embedded_url,
        active='embedded',
        embedded_name=embedded_name
    )
