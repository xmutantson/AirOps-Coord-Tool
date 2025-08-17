
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
        session['session_salt'] = get_session_salt()
        flash("Password set—you're logged in!", "success")
        return redirect(url_for('core.dashboard'))

    return render_template('setup.html', active='setup')

@bp.route('/login', methods=['GET','POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('core.dashboard'))

    if request.method == 'POST':
        pw = request.form.get('password','')
        if (h := get_app_password_hash()) and check_password_hash(h, pw):
            session['logged_in'] = True
            flash("Logged in successfully.", "success")
            # stamp session salt on successful login
            session['session_salt'] = get_session_salt()
            return redirect(request.args.get('next') or url_for('core.dashboard'))
        flash("Incorrect password.", "error")

    return render_template('login.html', active='login')

@bp.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash("Logged out.", "info")
    return redirect(url_for('auth.login'))
