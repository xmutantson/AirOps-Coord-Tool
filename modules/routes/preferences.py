
from markupsafe import escape
import sqlite3
import os

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from app import DB_FILE
from flask import Blueprint, current_app
from flask import flash, make_response, redirect, render_template, request, session, url_for
from modules.services.jobs import configure_inventory_broadcast_job
from modules.services.winlink.core import pat_config_status
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

        # ── WinLink Airport→Callsign mappings & CC addrs ─────────
        if (
            'airport_codes[]' in request.form or
            'winlink_cc_1' in request.form or
            'aoct_cc_query' in request.form or
            'aoct_cc_reply' in request.form or
            'aoct_cc_broadcast' in request.form
        ):
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

            # save AOCT CC toggles
            for key in ('aoct_cc_query','aoct_cc_reply','aoct_cc_broadcast'):
                if key in request.form:
                    val = (request.form.get(key,'no').strip().lower() == 'yes')
                    set_preference(key, 'yes' if val else 'no')

            flash("WinLink mappings and CC addresses saved.", "success")

        # ── Flight Locate & Offline Maps (DB-backed) ───────────────
        if (
            'adsb_base_url' in request.form or
            'adsb_stream_url' in request.form or
            'aoct_auto_reply_flight' in request.form or
            'adsb_poll_enabled' in request.form or
            'adsb_poll_interval_s' in request.form or
            'map_tiles_path' in request.form or
            'map_offline_seed' in request.form
        ):
            changed = False
            # ADS-B base URL (allow blank)
            if 'adsb_base_url' in request.form:
                new = (request.form.get('adsb_base_url','') or '').strip()
                if new != (get_preference('adsb_base_url') or ''):
                    set_preference('adsb_base_url', new); changed = True
            # ADS-B JSON-lines stream URL (tcp://host:port or http(s)://…)
            if 'adsb_stream_url' in request.form:
                new = (request.form.get('adsb_stream_url','') or '').strip()
                if new != (get_preference('adsb_stream_url') or ''):
                    set_preference('adsb_stream_url', new); changed = True
            # AOCT: auto-reply to *Flight Query* with latest sighting
            if 'aoct_auto_reply_flight' in request.form:
                ar = 'yes' if (request.form.get('aoct_auto_reply_flight','yes').strip().lower() == 'yes') else 'no'
                if ar != (get_preference('aoct_auto_reply_flight') or 'yes'):
                    set_preference('aoct_auto_reply_flight', ar); changed = True
            # Local ADS-B poller toggle
            if 'adsb_poll_enabled' in request.form:
                pe = 'yes' if (request.form.get('adsb_poll_enabled','no').strip().lower() == 'yes') else 'no'
                if pe != (get_preference('adsb_poll_enabled') or 'no'):
                    set_preference('adsb_poll_enabled', pe); changed = True
            # Poller interval (clamp to >=1s)
            if 'adsb_poll_interval_s' in request.form:
                raw = (request.form.get('adsb_poll_interval_s','') or '').strip()
                try:
                    n = max(1, int(float(raw)))
                except Exception:
                    n = 10
                if str(n) != (get_preference('adsb_poll_interval_s') or '10'):
                    set_preference('adsb_poll_interval_s', str(n)); changed = True
            # Map tiles path: blank ⇒ revert to derived default (delete row)
            if 'map_tiles_path' in request.form:
                mpath = (request.form.get('map_tiles_path','') or '').strip()
                cur = get_preference('map_tiles_path') or ''
                if mpath:
                    if mpath != cur:
                        set_preference('map_tiles_path', mpath); changed = True
                else:
                    if cur:
                        with sqlite3.connect(DB_FILE) as c:
                            c.execute("DELETE FROM preferences WHERE name='map_tiles_path'")
                        changed = True
             # One-time offline seed flag
            if 'map_offline_seed' in request.form:
                ovs = 'yes' if (request.form.get('map_offline_seed','yes').strip().lower() == 'yes') else 'no'
                if ovs != (get_preference('map_offline_seed') or 'yes'):
                    set_preference('map_offline_seed', ovs); changed = True
            if changed:
                flash("ADS-B & Map preferences saved.", "success")
            # DO NOT early-return; let the rest of this POST process too.

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

        if 'mission_number' in request.form:
            m = escape((request.form.get('mission_number','') or '').strip().upper())
            with sqlite3.connect(DB_FILE) as c:
                c.execute("""
                    INSERT INTO preferences(name,value)
                    VALUES('mission_number',?)
                    ON CONFLICT(name) DO UPDATE
                    SET value = excluded.value
                """, (m,))

        # ----- Remote Airports (DB-backed) --------------------------------
        if ('auto_broadcast_interval_min' in request.form or
            'auto_reply_enabled' in request.form):
            # Only act (and early-return) if something actually changed.
            curr_iv  = (get_preference('auto_broadcast_interval_min') or '0').strip()
            curr_ar  = (get_preference('auto_reply_enabled') or 'yes').strip().lower()
            changed  = False

            # Clamp to allowed values: 0/15/30/60
            if 'auto_broadcast_interval_min' in request.form:
                raw_iv  = (request.form.get('auto_broadcast_interval_min','') or '').strip()
                allowed = {'0','15','30','60'}
                val_iv  = raw_iv if raw_iv in allowed else '0'
                if val_iv != curr_iv:
                    set_preference('auto_broadcast_interval_min', val_iv)
                    changed = True
            if 'auto_reply_enabled' in request.form:
                raw_ar = (request.form.get('auto_reply_enabled','') or '').strip().lower()
                val_ar = 'yes' if raw_ar == 'yes' else 'no'
                if val_ar != curr_ar:
                    set_preference('auto_reply_enabled', val_ar)
                    changed = True

            if changed:
                # (Re)configure the minute-tick job whenever cadence changes
                try:
                    configure_inventory_broadcast_job()
                except Exception:
                    pass
                # Soft guidance: warn if inputs look incomplete
                try:
                    iv = int(float(get_preference('auto_broadcast_interval_min') or 0))
                except Exception:
                    iv = 0
                if iv > 0:
                    pat_ok, pat_path, pat_reason = pat_config_status()
                    # Compute recipients (skip our own airport & callsign)
                    raw_map = (get_preference('airport_call_mappings') or '').strip()
                    self_ap = (get_preference('default_origin') or '').strip().upper()
                    self_cs = (get_preference('winlink_callsign_1') or '').strip().upper()
                    recipients = []
                    seen = set()
                    for ln in raw_map.splitlines():
                        if ':' not in ln:
                            continue
                        ap, wl = (x.strip().upper() for x in ln.split(':', 1))
                        if not ap or not wl:
                            continue
                        if ap == self_ap or wl == self_cs:
                            continue
                        if wl not in seen:
                            seen.add(wl)
                            recipients.append(wl)
                    if not pat_ok:
                        flash("Auto-broadcast enabled, but PAT credentials are not configured.", "warning")
                    if not recipients:
                        flash("Auto-broadcast enabled, but no recipients found in airport_call_mappings.", "warning")
                flash("Remote-airport broadcast/auto-reply settings saved.", "success")

        # ----- cookie-backed prefs ---------------------------------------
        resp = make_response(redirect(url_for('preferences.preferences')))

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
        # Inbound manifest auto-scan (Ramp) -------------------------------
        if 'ramp_scan_adv_manifest' in request.form:
            resp.set_cookie(
                'ramp_scan_adv_manifest',
                request.form['ramp_scan_adv_manifest'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        flash("Preferences saved", "success")
        return resp

    # ── GET: read current settings ────────────────────────────────────────
    # default_origin / mission_number from DB
    row = dict_rows("SELECT value FROM preferences WHERE name='default_origin'")
    default_origin = row[0]['value'] if row else ''
    row_m = dict_rows("SELECT value FROM preferences WHERE name='mission_number'")
    mission_number = row_m[0]['value'] if row_m else ''

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
    scan_adv_pref   = request.cookies.get('ramp_scan_adv_manifest','yes')

    winlink_cc_1 = get_preference('winlink_cc_1') or ''
    winlink_cc_2 = get_preference('winlink_cc_2') or ''
    winlink_cc_3 = get_preference('winlink_cc_3') or ''

    # AOCT CC toggles
    aoct_cc_query     = (get_preference('aoct_cc_query') or 'no')
    aoct_cc_reply     = (get_preference('aoct_cc_reply') or 'no')
    aoct_cc_broadcast = (get_preference('aoct_cc_broadcast') or 'no')

    # Remote-Airport prefs
    auto_broadcast_interval_min = (get_preference('auto_broadcast_interval_min') or '0')
    auto_reply_enabled = (get_preference('auto_reply_enabled') or 'yes')

    # Flight Locate + Maps
    adsb_base_url           = get_preference('adsb_base_url') or ''
    adsb_stream_url         = get_preference('adsb_stream_url') or ''
    aoct_auto_reply_flight  = (get_preference('aoct_auto_reply_flight') or 'yes')
    adsb_poll_enabled       = (get_preference('adsb_poll_enabled') or 'no')
    adsb_poll_interval_s    = (get_preference('adsb_poll_interval_s') or '10')
    map_tiles_path          = (get_preference('map_tiles_path') or '')
    map_offline_seed        = (get_preference('map_offline_seed') or 'yes')
    map_tiles_default       = os.path.join(os.path.dirname(DB_FILE), 'tiles')

    return render_template(
        'preferences.html',
        active='preferences',
        default_origin=default_origin,
        mission_number=mission_number,
        current_code=current_code,
        current_mass=current_mass,
        distance_unit=distance_unit,
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
        aoct_cc_query=aoct_cc_query,
        aoct_cc_reply=aoct_cc_reply,
        aoct_cc_broadcast=aoct_cc_broadcast,
        # Remote-Airport prefs
        auto_broadcast_interval_min=auto_broadcast_interval_min,
        auto_reply_enabled=auto_reply_enabled,
        # Flight Locate + Maps
        adsb_base_url=adsb_base_url,
        adsb_stream_url=adsb_stream_url,
        aoct_auto_reply_flight=aoct_auto_reply_flight,
        adsb_poll_enabled=adsb_poll_enabled,
        adsb_poll_interval_s=adsb_poll_interval_s,
        map_tiles_path=map_tiles_path,
        map_offline_seed=map_offline_seed,
        map_tiles_default=map_tiles_default,
        # Ramp inbound auto-scan
        scan_adv_pref=scan_adv_pref
    )
