

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from flask import Blueprint, current_app
from flask import jsonify, redirect, render_template, request, session, url_for
from modules.services.wargame import get_wargame_epoch
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

@bp.route('/wargame/radio/email/<int:email_id>')
def fetch_wargame_email(email_id):
    """Return the subject+body for one wargame email (JSON)."""
    row = dict_rows("SELECT subject, body FROM wargame_emails WHERE id=?", (email_id,))
    if not row:
        return jsonify({}), 404
    return jsonify(subject=row[0]['subject'], body=row[0]['body'])

@bp.route('/wargame/radio')
def wargame_radio_dashboard():
    # 1) ensure wargame mode
    wm = dict_rows("SELECT value FROM preferences WHERE name='wargame_mode'")
    if not (wm and wm[0]['value']=='yes'):
        return redirect(url_for('core.dashboard'))

    # only the “radio” role may visit; everyone else bounces to /wargame
    if session.get('wargame_role') != 'radio':
        return redirect(url_for('wgindex.wargame_index'))

    # 2) fetch all generated e‑mails, newest first
    emails = dict_rows("""
      SELECT id, generated_at, message_id, size_bytes,
             source, sender, recipient, subject
        FROM wargame_emails
       ORDER BY generated_at DESC
    """)

    # 3) determine “read” state from an epoch‑namespaced cookie bitmask
    epoch = get_wargame_epoch()
    cookie_name = f"wargame_emails_read_{epoch}"
    seen = request.cookies.get(cookie_name, '')  # e.g. "1,4,7"
    _ = set(int(i) for i in seen.split(',') if i.isdigit())
    return render_template(
        'wargame_radio.html',
        emails=emails,
        epoch=epoch,                # stable across the Wargame session
        active='wargame'
    )
