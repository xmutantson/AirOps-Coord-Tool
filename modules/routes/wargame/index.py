from flask import Blueprint, render_template, redirect, url_for, make_response, request, session, flash

import json
try:
    from modules.utils.common import get_preference, dict_rows
except Exception:
    get_preference = None
    dict_rows = None

def _wg_settings():
    # Try via get_preference first
    js = ''
    try:
        if get_preference:
            js = get_preference('wargame_settings') or ''
    except Exception:
        js = ''
    # Fallback: direct SELECT
    if not js and dict_rows:
        try:
            rows = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
            js = (rows[0]['value'] if rows else '') or ''
        except Exception:
            js = ''
    try:
        return json.loads(js) if js else {}
    except Exception:
        return {}

# Keep blueprint name stable for app registration
bp = Blueprint('wgindex', __name__)

# --- canonical role → endpoint map (includes inventory cue-cards) ---
ROLE_ENDPOINTS = {
    'super': 'wgsuper.wargame_super_dashboard',
    'ramp':      'wgramp.wargame_ramp_dashboard',
    'radio':     'wgradio.wargame_radio_dashboard',
    'inventory': 'wginventory.wargame_inventory_dashboard',
}

def _endpoint_for_role(role: str | None) -> str | None:
    role = (role or '').lower()
    return ROLE_ENDPOINTS.get(role)

@bp.route('/wargame')
def wargame_index():
    # Wargame must be enabled
    if get_preference('wargame_mode') != 'yes':
        return redirect(url_for('core.dashboard'))

    # If a role is already selected, send them straight to that dashboard
    role = request.cookies.get('wargame_role') or session.get('wargame_role')
    endpoint = _endpoint_for_role(role)
    if endpoint:
        return redirect(url_for(endpoint))

    # Else render the chooser
    return render_template('wargame_choose_role.html',settings=_wg_settings(),  active='wargame')

@bp.post('/wargame/choose_role')
def wargame_choose_role():
    # Wargame must be enabled
    if get_preference('wargame_mode') != 'yes':
        return redirect(url_for('core.dashboard'))

    role = (request.form.get('role') or '').lower()
    endpoint = _endpoint_for_role(role)
    if not endpoint:
        flash('Unknown role selection.', 'error')
        return redirect(url_for('wgindex.wargame_index'))

    # Persist role to both session and cookie
    session['wargame_role'] = role
    resp = make_response(redirect(url_for(endpoint)))
    resp.set_cookie('wargame_role', role, max_age=60*60*24*30, samesite='Lax')

    # Optional: apply supervisor settings on selection if available
    if role == 'super':
        try:
            from modules.services.wargame import apply_supervisor_settings
            apply_supervisor_settings()
        except Exception:
            # non-fatal; still navigate to dashboard
            pass

    return resp

@bp.route('/wargame/exit_role', methods=('GET','POST'))
def wargame_exit_role():
    # Clear role from session and cookie, return to chooser
    session.pop('wargame_role', None)
    resp = make_response(redirect(url_for('wgindex.wargame_index')))
    resp.delete_cookie('wargame_role', path='/')
    return resp
