
from markupsafe import escape
import sqlite3

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from app import DB_FILE
from flask import Blueprint, current_app
from flask import flash, make_response, redirect, render_template, request, session, url_for
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

@bp.route('/preferences', methods=['GET', 'POST'])
def preferences():
    """Display / update local-display and ops preferences.

    * default_origin           → stored in SQLite (shared across devices)
    * code_format, mass_unit,
      operator_call(callsign),
      include_test,
      radio_show_unsent_only   → stored per-browser via cookies
    """
    ONE_YEAR = 31_536_000  # seconds

    # ── update prefs ──────────────────────────────────────────────────────
    if request.method == 'POST':

        if 'distance_unit' in request.form:
            set_preference('distance_unit', request.form.get('distance_unit','nm'))

        # ── NetOps Feeder settings (remote push) ───────────────────────
        if ('netops_enabled' in request.form or
            'netops_url' in request.form or
            'netops_station' in request.form or
            'netops_password' in request.form or
            'netops_push_interval_sec' in request.form or
            'netops_window_hours' in request.form or
            'origin_lat' in request.form or
            'origin_lon' in request.form):
            set_preference('netops_enabled', request.form.get('netops_enabled','no'))
            set_preference('netops_url',     request.form.get('netops_url','').strip())
            set_preference('netops_station', request.form.get('netops_station','').strip().upper())
            if 'netops_password' in request.form:
                set_preference('netops_password', request.form.get('netops_password',''))
            if 'netops_push_interval_sec' in request.form:
                set_preference('netops_push_interval_sec', request.form.get('netops_push_interval_sec','60').strip())
            if 'netops_window_hours' in request.form:
                set_preference('netops_window_hours', request.form.get('netops_window_hours','24').strip())
            # optional origin coordinates (from geolocation button)
            if request.form.get('origin_lat','').strip():
                set_preference('origin_lat', request.form.get('origin_lat').strip())
            if request.form.get('origin_lon','').strip():
                set_preference('origin_lon', request.form.get('origin_lon').strip())
            try:
                # refresh feeders immediately when settings change
                from modules.services.jobs import configure_netops_feeders
                configure_netops_feeders()
            except Exception:
                pass
            flash("NetOps feeder settings saved.", "success")
            return redirect(url_for('preferences.preferences'))

        # ── WinLink Airport→Callsign mappings & CC addrs ─────────
        if 'airport_codes[]' in request.form or 'winlink_cc_1' in request.form:
            # save airport→WinLink mappings
            if 'airport_codes[]' in request.form:
                codes   = request.form.getlist('airport_codes[]')
                callers = request.form.getlist('winlink_callsigns[]')
                canon_map = {}
                conflicts = []
                for c, w in zip(codes, callers):
                    if not c.strip() or not w.strip():
                        continue
                    canon = canonical_airport_code(c)
                    w = w.strip().upper()
                    if canon in canon_map and canon_map[canon] != w:
                        conflicts.append((c, canon, canon_map[canon], w))
                    canon_map[canon] = w
                if conflicts:
                    msgs = "; ".join(
                        f"‘{c}’ ({canon}) mapped to both {old} and {new}"
                        for c, canon, old, new in conflicts
                    )
                    flash(f"Conflicting mappings detected: {msgs}", "error")
                    return redirect(url_for('preferences.preferences'))
                raw = "\n".join(
                    f"{c.strip().upper()}:{canon_map[canonical_airport_code(c)]}"
                    for c in codes
                    if c.strip() and canonical_airport_code(c) in canon_map
                )
                with sqlite3.connect(DB_FILE) as c:
                    c.execute("""
                        INSERT INTO preferences(name,value)
                        VALUES('airport_call_mappings', ?)
                        ON CONFLICT(name) DO UPDATE
                          SET value=excluded.value
                    """, (raw,))

            # save up to three CC addresses
            if 'winlink_cc_1' in request.form:
                for idx in (1,2,3):
                    key = f"winlink_cc_{idx}"
                    val = request.form.get(key, "").strip()
                    with sqlite3.connect(DB_FILE) as c:
                        c.execute("""
                            INSERT INTO preferences(name,value)
                            VALUES(?, ?)
                            ON CONFLICT(name) DO UPDATE
                              SET value=excluded.value
                        """, (key, val))

            flash("WinLink mappings and CC addresses saved.", "success")
            return redirect(url_for('preferences.preferences'))

        # ── Unlock / lock admin mode ────────────────────
        if 'admin_passphrase' in request.form:
            entered = request.form['admin_passphrase'].strip()
            if entered == "I solemnly swear that I am up to no good":
                session['admin_unlocked'] = True
                flash("🔓 Admin mode unlocked.", "success")
            else:
                session.pop('admin_unlocked', None)
                flash("❌ Incorrect passphrase.", "error")
            return redirect(url_for('preferences.preferences'))

        # ----- DB-backed preference --------------------------------------
        if 'default_origin' in request.form:
            val = escape(request.form['default_origin'].strip().upper())
            with sqlite3.connect(DB_FILE) as c:
                c.execute("""
                    INSERT INTO preferences(name,value)
                    VALUES('default_origin',?)
                    ON CONFLICT(name) DO UPDATE
                    SET value = excluded.value
                """, (val,))

        # ----- cookie-backed prefs ---------------------------------------
        resp = make_response(redirect(url_for('preferences.preferences')))

        # existing cookie-backed prefs...
        if 'code_format' in request.form:
            resp.set_cookie(
                'code_format',
                request.form['code_format'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'mass_unit' in request.form:
            resp.set_cookie(
                'mass_unit',
                request.form['mass_unit'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'distance_unit' in request.form:
            resp.set_cookie(
                'distance_unit',
                request.form['distance_unit'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'operator_call' in request.form:  # protect from arbitrary text XSS
            oc = escape(request.form['operator_call'].upper())
            resp.set_cookie(
                'operator_call',
                oc,
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'include_test' in request.form:
            resp.set_cookie(
                'include_test',
                request.form['include_test'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'radio_show_unsent_only' in request.form:
            resp.set_cookie(
                'radio_show_unsent_only',
                request.form['radio_show_unsent_only'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'hide_tbd' in request.form:
            # now a yes/no dropdown → just echo the selected value
            resp.set_cookie(
                'hide_tbd',
                request.form['hide_tbd'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'show_debug_logs' in request.form:
            resp.set_cookie(
                'show_debug_logs',
                request.form['show_debug_logs'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        # Dashboard sort‐sequence pref → cookie
        if 'dashboard_sort_seq' in request.form:
            resp.set_cookie('dashboard_sort_seq',
                            request.form['dashboard_sort_seq'],
                            max_age=31_536_000, samesite='Lax')

        flash("Preferences saved", "success")
        return resp

    # ── GET: read current settings ────────────────────────────────────────
    # default_origin from DB
    row = dict_rows("SELECT value FROM preferences WHERE name='default_origin'")
    default_origin = row[0]['value'] if row else ''

    # Airport→WinLink mappings (raw + parsed)
    row2 = dict_rows(
        "SELECT value FROM preferences WHERE name='airport_call_mappings'"
    )
    raw_mappings = row2[0]['value'] if row2 else ''
    airport_mappings = []
    for line in raw_mappings.splitlines():
        if ':' in line:
            code, wl = line.split(':',1)
            airport_mappings.append((
                code.strip().upper(),
                wl.strip().upper()
            ))

    # cookie-backed settings
    current_code    = request.cookies.get('code_format',   'icao4')
    current_mass    = request.cookies.get('mass_unit',     'lbs')
    distance_unit = (get_preference('distance_unit') or request.cookies.get('distance_unit','nm'))
    operator_call   = request.cookies.get('operator_call', '')
    include_test    = request.cookies.get('include_test',  'yes')
    current_debug   = request.cookies.get('show_debug_logs','no')
    current_radio_unsent = request.cookies.get('radio_show_unsent_only','yes')
    hide_tbd        = request.cookies.get('hide_tbd','yes') == 'yes'

    winlink_cc_1 = get_preference('winlink_cc_1') or ''
    winlink_cc_2 = get_preference('winlink_cc_2') or ''
    winlink_cc_3 = get_preference('winlink_cc_3') or ''

    # NetOps feeder settings
    netops_enabled = (get_preference('netops_enabled') or 'no')
    netops_url     = (get_preference('netops_url') or '')
    netops_station = (get_preference('netops_station') or '')
    netops_push_interval_sec = (get_preference('netops_push_interval_sec') or '60')
    netops_window_hours = (get_preference('netops_window_hours') or '24')
    origin_lat = (get_preference('origin_lat') or '')
    origin_lon = (get_preference('origin_lon') or '')

    return render_template(
        'preferences.html',
        default_origin=default_origin,
        current_code=current_code,
        current_mass=current_mass,
        operator_call=operator_call,
        include_test=include_test,
        current_debug=current_debug,
        current_radio_unsent=current_radio_unsent,
        sort_seq=(request.cookies.get('dashboard_sort_seq','no')=='yes'),
        hide_tbd=hide_tbd,
        airport_mappings=airport_mappings,
        winlink_cc_1=winlink_cc_1,
        winlink_cc_2=winlink_cc_2,
        winlink_cc_3=winlink_cc_3,
        # NetOps
        netops_enabled=netops_enabled,
        netops_url=netops_url,
        netops_station=netops_station,
        netops_push_interval_sec=netops_push_interval_sec,
        netops_window_hours=netops_window_hours,
        origin_lat=origin_lat,
        origin_lon=origin_lon
    )
