
from werkzeug.security import generate_password_hash, check_password_hash

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from flask import Blueprint, current_app
from flask import flash, redirect, render_template, request, session, url_for
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

@bp.route('/setup', methods=['GET','POST'])
def setup():
    if get_app_password_hash():
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        pw      = request.form.get('password','')
        confirm = request.form.get('confirm','')
        if not pw or pw != confirm:
            flash("Passwords must match", "error")
            return render_template('setup.html', active='setup')
        # store hashed pw & log them in
        set_app_password_hash(generate_password_hash(pw))
        session['logged_in'] = True
        # flag first post-login page view for shift check-in modal
        session['just_logged_in'] = 1
        session['session_salt'] = get_session_salt()
        flash("Password set—you're logged in!", "success")
        return redirect(url_for('auth.setup_wizard'))

    return render_template('setup.html', active='setup')

@bp.route('/setup/wizard', methods=['GET','POST'])
def setup_wizard():
    """
    Collect initial defaults (and allow reruns):
      - Default Origin (required)
      - Mission Number (optional)
      - Operator Call Sign (optional)
      - Full Winlink mappings + CCs block
    """
    # Require a logged-in session for reruns; first-run arrives here immediately after /setup.
    if not session.get('logged_in'):
        return redirect(url_for('auth.login', next=url_for('auth.setup_wizard')))

    from modules.utils.common import (
        set_preference, canonical_airport_code, dict_rows,
        get_db_file, get_preference
    )
    def _wizard_ctx():
        # Prefill fields for reruns
        row = dict_rows("SELECT value FROM preferences WHERE name='default_origin'")
        default_origin = row[0]['value'] if row else ''
        rowm = dict_rows("SELECT value FROM preferences WHERE name='mission_number'")
        mission_number = rowm[0]['value'] if rowm else ''
        operator_call  = (get_preference('winlink_callsign_1') or '')
        # mappings
        row2 = dict_rows("SELECT value FROM preferences WHERE name='airport_call_mappings'")
        raw_mappings = row2[0]['value'] if row2 else ''
        airport_mappings = []
        for line in raw_mappings.splitlines():
            if ':' in line:
                code, wl = line.split(':',1)
                airport_mappings.append((code.strip().upper(), wl.strip().upper()))
        # CCs + toggles
        winlink_cc_1 = get_preference('winlink_cc_1') or ''
        winlink_cc_2 = get_preference('winlink_cc_2') or ''
        winlink_cc_3 = get_preference('winlink_cc_3') or ''
        aoct_cc_query     = (get_preference('aoct_cc_query') or 'no')
        aoct_cc_reply     = (get_preference('aoct_cc_reply') or 'no')
        aoct_cc_broadcast = (get_preference('aoct_cc_broadcast') or 'no')
        return dict(
            default_origin=default_origin,
            mission_number=mission_number,
            operator_call=operator_call,
            airport_mappings=airport_mappings,
            winlink_cc_1=winlink_cc_1,
            winlink_cc_2=winlink_cc_2,
            winlink_cc_3=winlink_cc_3,
            aoct_cc_query=aoct_cc_query,
            aoct_cc_reply=aoct_cc_reply,
            aoct_cc_broadcast=aoct_cc_broadcast
        )
    import sqlite3

    if request.method == 'POST':
        # 1) Required: default origin
        origin = (request.form.get('default_origin','') or '').strip().upper()
        if not origin:
            flash("Default Origin is required.", "error")
            return render_template('setup.html', active='setup', wizard=True, **_wizard_ctx())
        set_preference('default_origin', origin)

        # 2) Optional: mission number
        mission = (request.form.get('mission_number','') or '').strip().upper()
        set_preference('mission_number', mission)

        # 3) Optional: operator call sign → cookie-style in Preferences;
        #    here we store a server-side default so it’s available everywhere.
        oc = (request.form.get('operator_call','') or '').strip().upper()
        if oc:
            set_preference('winlink_callsign_1', oc)

        # 4) Full Winlink mappings + CCs (same names as Preferences form)
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
                return render_template('setup.html', active='setup', wizard=True, **_wizard_ctx())
            raw = "\n".join(
                f"{c.strip().upper()}:{canon_map[canonical_airport_code(c)]}"
                for c in codes
                if c.strip() and canonical_airport_code(c) in canon_map
            )
            with sqlite3.connect(get_db_file()) as c:
                c.execute("""
                    INSERT INTO preferences(name,value)
                    VALUES('airport_call_mappings', ?)
                    ON CONFLICT(name) DO UPDATE
                      SET value=excluded.value
                """, (raw,))

        for idx in (1,2,3):
            key = f"winlink_cc_{idx}"
            val = (request.form.get(key, "") or "").strip()
            set_preference(key, val)

        flash("Setup complete. You can adjust advanced items in Admin (unlock with the passphrase).", "success")
        return redirect(url_for('core.dashboard'))

    # GET
    return render_template('setup.html', active='setup', wizard=True, **_wizard_ctx())

@bp.route('/login', methods=['GET','POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('core.dashboard'))

    if request.method == 'POST':
        pw = request.form.get('password','')
        if (h := get_app_password_hash()) and check_password_hash(h, pw):
            session['logged_in'] = True
            # flag first post-login page view for shift check-in modal
            session['just_logged_in'] = 1
            flash("Logged in successfully.", "success")
            # stamp session salt on successful login
            session['session_salt'] = get_session_salt()
            return redirect(url_for('core.dashboard'))
        flash("Incorrect password.", "error")

    return render_template('login.html', active='login')

@bp.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('just_logged_in', None)
    flash("Logged out.", "info")
    return redirect(url_for('auth.login'))
