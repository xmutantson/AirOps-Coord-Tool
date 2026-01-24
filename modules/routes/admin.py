
from werkzeug.security import generate_password_hash
import uuid
from markupsafe import escape
import sqlite3, os

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from app import DB_FILE, ONE_YEAR, scheduler
from modules.services.winlink.core import _configure_pat_from_prefs_silent
# --- Wargame helpers (import or safe fallbacks) ---
from modules.services.jobs import configure_wargame_jobs, configure_internet_watch_job, configure_netops_feeders
try:
    from modules.services.wargame import (reset_wargame_state, set_wargame_epoch, seed_wargame_baseline_inventory, bump_wargame_role_epoch, get_wargame_epoch, initialize_airfield_callsigns)
except Exception:
    def reset_wargame_state(): pass
    def set_wargame_epoch(): pass
    def seed_wargame_baseline_inventory(): pass
    def configure_wargame_jobs(): pass
    def bump_wargame_role_epoch(): pass
# --- end Wargame helpers ---
from flask import Blueprint, current_app
from flask import flash, make_response, redirect, render_template, request, session, url_for
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

def _ret(endpoint, **kwargs):
    """Module-level redirect helper used across admin routes.

    Semantics:
      - Always redirect to url_for(endpoint, **kwargs)
      - On POST, persist default_origin and show_debug_logs cookie if present
    """
    from flask import make_response, redirect, url_for, request
    resp = make_response(redirect(url_for(endpoint, **kwargs)))
    try:
        if request.method == 'POST':
            if 'default_origin' in request.form:
                val = escape(request.form['default_origin'].strip().upper())
                set_preference('default_origin', val)
            if 'show_debug_logs' in request.form:
                resp.set_cookie(
                    'show_debug_logs',
                    request.form['show_debug_logs'],
                    max_age=ONE_YEAR,
                    samesite='Lax'
                )
    except Exception:
        # never let the redirect fail
        pass
    return resp



@bp.route('/admin', methods=['GET', 'POST'])
def admin():
    # only session‑backed admin
    if not session.get('admin_unlocked'):
        return _ret('preferences.preferences')
    if request.method == 'POST':

        # ── Exit Admin Mode ────────────────────────────────
        if 'exit_admin' in request.form:
            session.pop('admin_unlocked', None)
            flash("🔒 Admin mode locked.", "info")
            return _ret('preferences.preferences')

        # ── Internet detection override ─────────────────────────────
        # Only process and flash when the value actually changed AND we're not
        # in the middle of another explicit action (save_embedded, clear_embedded, etc.)
        if 'internet_force_online' in request.form:
            # Skip if this is part of another explicit action
            is_other_action = (
                'save_embedded' in request.form or
                'clear_embedded' in request.form or
                'change_password' in request.form or
                'exit_admin' in request.form or
                'invalidate_sessions' in request.form or
                'toggle_wargame' in request.form or
                'winlink_callsign_1' in request.form
            )
            if not is_other_action:
                val = (request.form.get('internet_force_online','no') or 'no').strip().lower()
                new_val = 'yes' if val == 'yes' else 'no'
                current_val = get_preference('internet_force_online') or 'no'
                if new_val != current_val:
                    set_preference('internet_force_online', new_val)
                    # Nudge the watchdog to apply the new policy promptly (safe if job not yet running)
                    try:
                        configure_internet_watch_job()
                    except Exception:
                        pass
                    flash("Internet detection override updated.", "info")
                return _ret('admin.admin')

        # ── Toggle Wargame Mode ────────────────────────────
        if 'toggle_wargame' in request.form:
            on          = (request.form.get('toggle_wargame') == 'on')
            current_on  = (get_preference('wargame_mode') == 'yes')
            if on == current_on:
                flash(f"Wargame mode already {'active' if on else 'off'}. No changes made.", "info")
                return _ret('admin.admin')
            set_preference('wargame_mode', 'yes' if on else 'no')

            # List of all tables we want to completely purge on activation/deactivation
            # NOTE: Excludes winlink tables (outgoing_messages, winlink_messages,
            # winlink_message_files) and personnel (staff, staff_shifts) per design.
            WARGAME_TABLES = [
              'flights',
              'incoming_messages',
              'flight_history',
              'wargame_emails',
              'wargame_metrics',
              'wargame_inbound_schedule',
              'wargame_radio_schedule',
              'wargame_tasks',
              'inventory_entries',
              'queued_flights',
              'cargo_requests',
              # V2 cargo system
              'cargo_requests_v2',
              'cargo_request_sources',
              'cargo_request_links',
              # Operational data
              'communications',
              'flight_locates',
              'adsb_sightings',
              'flight_cargo',
              'remote_inventory',
              'remote_inventory_rows',
            ]

            if on:
                # 1) wipe live-ops & wargame state
                with sqlite3.connect(DB_FILE) as c:
                    for tbl in WARGAME_TABLES:
                        c.execute(f"DELETE FROM {tbl}")
                # Ensure schema is current after a wipe
                run_migrations()
                # Reset sequences and seed baseline inventory so requests are satisfiable.
                try:
                    _reset_autoincrements(WARGAME_TABLES + ['wargame_inventory_batches','wargame_inventory_batch_items','wargame_ramp_requests'])
                except Exception:
                    pass

                # 2) regenerate callsigns and wire up the scheduler
                initialize_airfield_callsigns()
                reset_wargame_state()
                set_wargame_epoch()
                seed_wargame_baseline_inventory()
                configure_wargame_jobs()

                # 3) clear any stale role
                session.pop('wargame_role', None)
                resp = _ret('wgindex.wargame_index')
                # also clear the browser cookie
                resp.delete_cookie('wargame_role', path='/')

                # Invalidate all existing role cookies globally
                bump_wargame_role_epoch()

                flash("🕹️ Wargame mode activated; all live-ops & Wargame data wiped.", "success")
                return resp

            else:
                # 1) tear down scheduler
                scheduler.remove_all_jobs()

                # 2) purge wargame tables
                with sqlite3.connect(DB_FILE) as c:
                    for tbl in WARGAME_TABLES:
                        c.execute(f"DELETE FROM {tbl}")
                # Keep schema current even when turning Wargame off
                run_migrations()

                # 3) clear any stale cookies
                resp = _ret('admin.admin')
                resp.delete_cookie('wargame_emails_read', path='/')
                # Also remove the epoch-scoped read cookie for the current run
                resp.delete_cookie(f"wargame_emails_read_{get_wargame_epoch()}", path='/')
                resp.delete_cookie('wargame_role',      path='/')
                session.pop('wargame_role', None)

                # Also invalidate roles when turning Wargame off
                bump_wargame_role_epoch()

                flash("🕹️ Wargame mode deactivated; all Wargame data cleared.", "info")
                return resp

        # ── Invalidate Sessions + Clear App Password ───────
        if 'invalidate_sessions' in request.form:
            new_salt = uuid.uuid4().hex
            set_session_salt(new_salt)
            with sqlite3.connect(DB_FILE) as c:
                c.execute("DELETE FROM preferences WHERE name='app_password'")
            flash(
              "🔑 All sessions invalidated and password cleared – " +
              "please set a new password now.",
              "info"
            )
            return _ret('auth.setup')

        # ── Change App Password ─────────────────────────────
        if 'change_password' in request.form:
            new_pw     = request.form.get('new_password','')
            confirm_pw = request.form.get('confirm_password','')
            if new_pw and new_pw == confirm_pw:
                set_app_password_hash(generate_password_hash(new_pw))
                flash("Application password updated.", "success")
            else:
                flash("Passwords must match.", "error")
            return _ret('admin.admin')

        # ── Clear Embedded-Tab Settings ────────────────────
        if 'clear_embedded' in request.form:
            clear_embedded_preferences()
            flash("Embedded-tab removed.", "info")
            return _ret('admin.admin')

        # ── Toggle Embedded Mode (mode changes only) ───────────────
        # only run this when it’s *not* part of a full “save_embedded” submission
        if 'embedded_mode' in request.form and 'save_embedded' not in request.form:
            mode = request.form.get('embedded_mode', 'iframe')
            current = get_preference('embedded_mode') or 'iframe'
            if mode != current:
                set_preference('embedded_mode', mode)
                flash(f"Embedded mode set to {mode}.", "info")
            return _ret('admin.admin')

        # ── Save Embedded-Tab URL / Name / Mode / Distances Flag ──
        if 'save_embedded' in request.form:
            url   = request.form.get('embedded_url', '').strip()
            name  = request.form.get('embedded_name', '').strip()
            mode  = request.form.get('embedded_mode', 'iframe')
            dist  = 'yes' if request.form.get('enable_1090_distances')=='on' else 'no'

            if url and name:
                set_preference('embedded_url', url)
                set_preference('embedded_name', name)
                set_preference('embedded_mode', mode)
                set_preference('enable_1090_distances', dist)
                flash("Embedded-tab settings saved.", "info")
            else:
                flash("Both URL and label are required.", "error")
            return _ret('admin.admin')

        # ── Save WinLink Settings (callsigns/passwords only) ───────────
        if 'winlink_callsign_1' in request.form:
            for key in ('winlink_callsign_1','winlink_password_1',
                        'winlink_callsign_2','winlink_password_2',
                        'winlink_callsign_3','winlink_password_3'):
                set_preference(key, request.form.get(key,'').strip())
            flash("WinLink settings saved.", "success")
            return _ret('admin.admin')

        # ── NetOps test connection ────────────────────────────────────
        if request.form.get('netops_action') == 'test':
            import requests as http_requests
            base    = (request.form.get('netops_url')     or get_preference('netops_url')     or '').strip()
            station = (request.form.get('netops_station') or get_preference('netops_station') or '').strip().upper()
            pwd     = (request.form.get('netops_password') or get_preference('netops_password') or '').strip()
            if not (base and station and pwd):
                flash("Please provide NetOps URL, Station ID, and Password before testing.", "error")
                return _ret('admin.admin')
            url = f"{base.rstrip('/')}/api/v1/login"
            try:
                r = http_requests.post(url, json={"station": station, "password": pwd}, timeout=10)
                if r.ok:
                    flash(f"NetOps login succeeded ({r.status_code}).", "success")
                else:
                    flash(f"NetOps login failed: {r.status_code} – {r.text[:120]}", "error")
            except Exception as e:
                flash(f"NetOps connection error: {e}", "error")
            return _ret('admin.admin')

        # ── NetOps save settings ──────────────────────────────────────
        if 'netops_save' in request.form:
            set_preference('netops_enabled', request.form.get('netops_enabled','no'))
            set_preference('netops_url',     request.form.get('netops_url','').strip())
            set_preference('netops_station', request.form.get('netops_station','').strip().upper())
            # Only update password if a non-empty value was provided.
            _pwd = (request.form.get('netops_password','') or '').strip()
            if _pwd:
                set_preference('netops_password', _pwd)
            set_preference('netops_push_interval_sec', request.form.get('netops_push_interval_sec','60').strip())
            set_preference('netops_window_hours', request.form.get('netops_window_hours','24').strip())
            # optional origin coordinates
            if request.form.get('origin_lat','').strip():
                set_preference('origin_lat', request.form.get('origin_lat').strip())
            if request.form.get('origin_lon','').strip():
                set_preference('origin_lon', request.form.get('origin_lon').strip())
            try:
                configure_netops_feeders()
            except Exception:
                pass
            flash("NetOps feeder settings saved.", "success")
            return _ret('admin.admin')

        # ── Update Default Origin (still in both Admin & Preferences) ──
        if 'default_origin' in request.form:
            val = escape(request.form['default_origin'].strip().upper())
            set_preference('default_origin', val)

        # ── Show Debug Logs cookie ─────────────────────────
        resp = _ret('admin.admin')
        if 'show_debug_logs' in request.form:
            resp.set_cookie(
              'show_debug_logs',
              request.form['show_debug_logs'],
              max_age=ONE_YEAR,
              samesite='Lax'
            )
        flash("Admin settings saved.", "info")
        return resp


    # ── GET: fetch current settings ─────────────────────────────
    default_origin        = get_preference('default_origin') or ''
    show_debug_logs       = request.cookies.get('show_debug_logs','no')
    wargame_mode          = get_preference('wargame_mode') == 'yes'
    # Pre-fill embedded settings with tar1090 defaults if not set
    # Use 192.168.8.2 (typical Pi setup) instead of localhost so remote hosts can connect
    embedded_url          = get_preference('embedded_url') or 'http://192.168.8.2/tar1090/'
    embedded_name         = get_preference('embedded_name') or 'tar1090'
    embedded_mode         = get_preference('embedded_mode') or 'iframe'
    enable_1090_distances = get_preference('enable_1090_distances') == 'yes'
    internet_force_online = (get_preference('internet_force_online') or 'no')
    # pull WinLink prefs for template
    winlink_callsign_1     = get_preference('winlink_callsign_1')  or ''
    winlink_password_1     = get_preference('winlink_password_1')  or ''
    winlink_callsign_2     = get_preference('winlink_callsign_2')  or ''
    winlink_password_2     = get_preference('winlink_password_2')  or ''
    winlink_callsign_3     = get_preference('winlink_callsign_3')  or ''
    winlink_password_3     = get_preference('winlink_password_3')  or ''

    # NetOps feeder settings
    netops_enabled           = get_preference('netops_enabled') or 'no'
    netops_url               = get_preference('netops_url') or ''
    netops_station           = get_preference('netops_station') or ''
    netops_push_interval_sec = get_preference('netops_push_interval_sec') or '60'
    netops_window_hours      = get_preference('netops_window_hours') or '24'
    origin_lat               = get_preference('origin_lat') or ''
    origin_lon               = get_preference('origin_lon') or ''

    return render_template(
      'admin.html',
      active='admin',
      default_origin=default_origin,
      show_debug_logs=show_debug_logs,
      wargame_mode=wargame_mode,
      embedded_url=embedded_url,
      embedded_name=embedded_name,
      embedded_mode=embedded_mode,
      enable_1090_distances=enable_1090_distances,
      internet_force_online=internet_force_online,
      winlink_callsign_1=winlink_callsign_1,
      winlink_password_1=winlink_password_1,
      winlink_callsign_2=winlink_callsign_2,
      winlink_password_2=winlink_password_2,
      winlink_callsign_3=winlink_callsign_3,
      winlink_password_3=winlink_password_3,
      # NetOps
      netops_enabled=netops_enabled,
      netops_url=netops_url,
      netops_station=netops_station,
      netops_push_interval_sec=netops_push_interval_sec,
      netops_window_hours=netops_window_hours,
      origin_lat=origin_lat,
      origin_lon=origin_lon
    )

@bp.post('/configure_pat')
def configure_pat():
    """Write out ~/.config/pat/config.json using WinLink prefs."""
    try:
        ok, err = _configure_pat_from_prefs_silent()
        if ok:
            flash("PAT configured successfully.", "success")
        else:
            raise RuntimeError(err or "unknown error")
    except Exception as e:
        app.logger.exception("Failed to configure PAT")
        flash(f"Error configuring PAT: {e}", "error")
    return _ret('admin.admin')
