import sqlite3
import os
import subprocess
import threading
from apscheduler.jobstores.base import JobLookupError
from typing import List, Tuple

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from modules.services.winlink.core import (
    generate_subject, generate_body,
    pat_config_status, pat_config_exists,
    _configure_pat_from_prefs_silent,
    send_winlink_message,
    get_send_as_callsign,
    maybe_auto_reply_flight_query,
)
from modules.services.winlink.ingest_replies import ingest_aoct_flight_reply
from modules.services.jobs import (
    configure_winlink_jobs,
    configure_winlink_auto_jobs,
    poll_winlink_job,
    process_unparsed_winlink_messages,
)
from app import DB_FILE, scheduler
from flask import Blueprint, current_app
from flask import send_file, abort
from datetime import datetime
from flask import flash, jsonify, redirect, render_template, request, session, url_for, make_response
from modules.utils.cookies import cookie_truthy

import csv as _csv
from io import StringIO as _StringIO

# --- Counterparty resolver (dest unless dest==us → origin) -------------------
def _resolve_counterparty_airport(airfield_takeoff: str, airfield_landing: str):
    self_canon = canonical_airport_code(get_preference('default_origin') or '')
    o = canonical_airport_code(airfield_takeoff or '')
    d = canonical_airport_code(airfield_landing or '')
    if self_canon and d and d == self_canon:
        return (o or None, 'origin')
    return (d or None, 'destination')

# Use explicit blueprint name and a url_prefix so endpoint names are stable:
#   endpoint:  winlink.winlink_start
#   url:       /winlink/start
bp = Blueprint("winlink", __name__, url_prefix="/winlink")
app = current_app  # legacy shim if route body references 'app'

@bp.get('/mappings.json', endpoint='winlink_mappings_json')
def winlink_mappings_json():
    """
    Return Preferences → airport_call_mappings as JSON in both directions:
      {
        "airport_to_call": {"KAAA":"CALL1", "KBBB":"CALL2", ...},
        "call_to_airport": {"CALL1":"KAAA", "CALL2":"KBBB", ...}
      }
    Lines are 'AIRPORT: CALLSIGN'. We canonicalize AIRPORT (e.g., 'BFI'→'KBFI')
    and upper-case CALLSIGN. Blank/malformed lines are skipped.
    """
    raw = (get_preference('airport_call_mappings') or '').strip()
    a2c = {}
    c2a = {}
    for ln in raw.splitlines():
        if ':' not in ln:
            continue
        ap, wl = (x.strip().upper() for x in ln.split(':', 1))
        if not ap or not wl:
            continue
        ap_canon = canonical_airport_code(ap)
        if not ap_canon:
            continue
        # prefer first occurrence; don't churn mappings mid-session
        a2c.setdefault(ap_canon, wl)
        c2a.setdefault(wl, ap_canon)
    return jsonify({'airport_to_call': a2c, 'call_to_airport': c2a})

# --- recipient counting helpers for “mass email to mapped call signs” UI ---
def _nonblank_cc_list() -> List[str]:
    """
    Return non-empty CC addresses from winlink_cc_1..3 (trimmed, uppercased).
    """
    out: List[str] = []
    for idx in (1, 2, 3):
        v = (get_preference(f"winlink_cc_{idx}") or "").strip().upper()
        if v:
            out.append(v)
    return out

def _count_mapped_callsigns(raw_map: str) -> int:
    """
    Count *lines* in Admin → WinLink 'airport_call_mappings' that have a non-blank
    callsign on the RHS. We do NOT de-duplicate; each mapping line is counted.
    Examples counted: 'KAAA: KAAA1', 'PABC:  PABC2'
    Lines ignored: blanks, comments (#...), lines without ':' or with empty RHS.
    """
    n = 0
    for ln in (raw_map or "").splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or ":" not in s:
            continue
        _, rhs = s.split(":", 1)
        if (rhs or "").strip():
            n += 1
    return n

def _recipient_counts() -> Tuple[int, int, int]:
    """
    Returns (total, mapped, cc):
      total = count of mapping lines with non-blank RHS + count of non-blank CCs.
    """
    raw_map = get_preference('airport_call_mappings') or ''
    mapped  = _count_mapped_callsigns(raw_map)
    cc_cnt  = len(_nonblank_cc_list())
    return (mapped + cc_cnt, mapped, cc_cnt)

@bp.get('/recipient_count', endpoint='winlink_recipient_count')
def winlink_recipient_count():
    """
    JSON helper for confirmation modals that say:
    “This will send a mass email to all mapped call signs (X total recipients…).”
    """
    total, mapped, cc_cnt = _recipient_counts()
    return jsonify({'total': total, 'mapped': mapped, 'cc': cc_cnt})

# --- helper: parse cookie "1-5,7,10-12" -> [(1,5),(7,7),(10,12)] ---
def _parse_read_ranges_cookie(val: str):
    """
    Cookie format: '123-150,160-170' (comma-separated inclusive ranges).
    Returns a list of (start, end) int tuples. Ignores junk gracefully.
    """
    ranges = []
    if not val:
        return ranges
    for chunk in str(val).split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '-' in chunk:
            a, b = chunk.split('-', 1)
            try:
                ranges.append((int(a), int(b)))
            except ValueError:
                continue
        else:
            try:
                x = int(chunk)
                ranges.append((x, x))
            except ValueError:
                continue
    return ranges

@bp.post('/poll_now', endpoint='winlink_poll_now')
def winlink_poll_now():
    poll_winlink_job()
    process_unparsed_winlink_messages()
    # After parsing/importing, handle any AOCT Flight Queries (auto-reply if possible)
    # Ingest any AOCT Flight Replies → adsb_sightings
    try:
        pending = dict_rows("""
            SELECT id, sender, subject, body, timestamp
              FROM winlink_messages
             WHERE direction='in' AND IFNULL(parsed,0)=0
             ORDER BY id ASC
        """)
        handled_ids = []
        for m in pending:
            if ingest_aoct_flight_reply(m):
                handled_ids.append(m['id'])
        if handled_ids:
            with sqlite3.connect(DB_FILE) as c:
                c.executemany(
                    "UPDATE winlink_messages SET parsed=1 WHERE id=?",
                    [(mid,) for mid in handled_ids]
                )
    except Exception:
        current_app.logger.exception("AOCT flight reply ingest failed")

    # After parsing/importing, handle any AOCT Flight Queries (auto-reply if possible)
    try:
        pending = dict_rows("""
            SELECT id, sender, subject, body, timestamp
              FROM winlink_messages
             WHERE direction='in' AND IFNULL(parsed,0)=0
             ORDER BY id ASC
        """)
        handled_ids = []
        for m in pending:
            handled = False
            try:
                # Step 11 — Optional Local Poller:
                # When the ADS-B poller is ON, the auto-reply should prefer table lookups.
                # When it’s OFF, do a one-shot on-demand fetch.
                # adsb_auto_lookup_tail() in modules.utils.common encapsulates that behavior.
                handled = maybe_auto_reply_flight_query(
                    m,
                    lookup_fn=adsb_auto_lookup_tail  # provided by modules.utils.common (* import)
                )  # type: ignore[arg-type]
            except TypeError:
                # Back-compat: older core without lookup_fn support
                handled = maybe_auto_reply_flight_query(m)
            if handled:
                handled_ids.append(m['id'])
        if handled_ids:
            with sqlite3.connect(DB_FILE) as c:
                c.executemany("UPDATE winlink_messages SET parsed=1 WHERE id=?",
                              [(mid,) for mid in handled_ids])
    except Exception:
        # never hard-fail the poll endpoint on handler errors
        current_app.logger.exception("AOCT flight query auto-reply sweep failed")
    return jsonify({'ok': True})

    # NOTE: the block above calls maybe_auto_reply_flight_query without any ADS-B
    # lookup hint. We now prefer table lookups when the ADS-B poller is ON.

    # (no code changes needed here because we’ll pass a lookup_fn below)

@bp.get('/inbox.json', endpoint='winlink_inbox_json')
def winlink_inbox_json():
    """Return inbound messages as JSON for AJAX refresh (supports hide_parsable via query or cookie).
       Adds attachment metadata needed by the inbox and modal."""
    def _arg_truthy(name: str):
        v = (request.args.get(name) or "").strip().lower()
        if v in ("1","true","yes","on"):  return True
        if v in ("0","false","no","off"): return False
        return None

    # precedence: explicit query arg → cookie → default False
    hp_arg = _arg_truthy("hide_parsable")
    hide_parsable = hp_arg if hp_arg is not None else cookie_truthy("hide_parsable", False, request)

    sql = """
      SELECT
             wm.id,
             wm.callsign,
             wm.sender,
             wm.subject,
             wm.body,
             wm.timestamp,
             COALESCE(wm.has_attachments,0) AS has_attachments,
             COALESCE((
               SELECT COUNT(1) FROM winlink_message_files f WHERE f.message_id = wm.id
             ), 0) AS attach_count,
             COALESCE(wm.attachment_dir, '') AS attachment_dir
        FROM winlink_messages wm
       WHERE wm.direction = 'in'
    """

    params: list[str] = []
    if hide_parsable:
        # Hide subjects starting with the parser patterns (case-insensitive)
        pats = [
            "AOCT CARGO QUERY",
            "AOCT CARGO STATUS",
            "AOCT CARGO REPLY",
            "AOCT FLIGHT QUERY",
            "AOCT FLIGHT REPLY",
            "AIR OPS:",
            "INQUIRY -",
        ]
        ors = " OR ".join(["UPPER(subject) LIKE ?"] * len(pats))
        sql += f" AND NOT ({ors})"
        params.extend([p + "%" for p in pats])
    sql += " ORDER BY timestamp DESC"

    msgs = dict_rows(sql, tuple(params))
    # Derive a basename for display/debug without exposing full paths
    for m in msgs:
        ad = (m.get("attachment_dir") or "").strip()
        m["attach_dir_basename"] = os.path.basename(ad) if ad else ""
    return jsonify(msgs)

@bp.get('/email/<int:mid>', endpoint='winlink_email')
def winlink_email(mid):
    """Fetch a single inbound message for the modal; does not toggle read."""
    rows = dict_rows("""
        SELECT id, callsign, sender, subject, body, timestamp,
               COALESCE(read,0) AS read,
               COALESCE(has_attachments,0) AS has_attachments,
               COALESCE(attachment_dir,'') AS attachment_dir
          FROM winlink_messages
         WHERE id=? AND direction='in'
    """, (mid,))
    if not rows:
        return jsonify({'ok': False}), 404
    msg = rows[0]
    # If there are attachments, include an indexed list for convenience
    files = []
    if int(msg.get('has_attachments') or 0) == 1:
        try:
            files = dict_rows("""
              SELECT filename, COALESCE(mime,'') AS mime, COALESCE(size_bytes,0) AS size_bytes,
                     COALESCE(saved_path,'') AS saved_path
                FROM winlink_message_files
               WHERE message_id=?
               ORDER BY id ASC
            """, (mid,))
        except Exception:
            files = []
    msg_out = dict(msg)
    if files:
        msg_out['files'] = files
    return jsonify(msg_out)

@bp.get('/attachment/<int:msg_id>/', endpoint='winlink_attachment_list')
def winlink_attachment_list(msg_id: int):
    """
    JSON listing for a message's attachments.
    Shape: {"files":[{"name":"WCCOL.JPG","size":12345,"mime":"image/jpeg","mtime":"..."}]}
    """
    rows = dict_rows("""
      SELECT filename, COALESCE(mime,'') AS mime, COALESCE(size_bytes,0) AS size_bytes, COALESCE(saved_path,'') AS saved_path
        FROM winlink_message_files
       WHERE message_id=?
       ORDER BY id ASC
    """, (msg_id,))
    files = []
    for r in rows:
        fp = r.get("saved_path") or ""
        try:
            st = os.stat(fp)
            mtime = datetime.utcfromtimestamp(st.st_mtime).isoformat().replace("+00:00","") + "Z"
            size = int(st.st_size)
        except Exception:
            mtime = ""
            size = int(r.get("size_bytes") or 0)
        files.append({
            "name": r.get("filename") or "",
            "size": size,
            "mime": r.get("mime") or "",
            "mtime": mtime
        })
    return jsonify({"files": files})

@bp.get('/attachment/<int:msg_id>/<path:filename>', endpoint='winlink_attachment_download')
def winlink_attachment_download(msg_id: int, filename: str):
    """
    Download a single attachment. We only serve files that are indexed for this message_id.
    """
    # Only exact matches from DB are allowed (prevents traversal)
    row = dict_rows("""
      SELECT filename, saved_path
        FROM winlink_message_files
       WHERE message_id=? AND filename=?
       LIMIT 1
    """, (msg_id, filename))
    if not row:
        abort(404)
    fp = (row[0].get("saved_path") or "").strip()
    if not fp or not os.path.isfile(fp):
        abort(404)
    # Serve directly from the indexed absolute path; force download
    return send_file(fp, as_attachment=True, download_name=row[0]["filename"])

@bp.post('/mark_read/<int:mid>', endpoint='winlink_mark_read')
def winlink_mark_read(mid):
    """Mark a message as read."""
    try:
        with sqlite3.connect(DB_FILE) as c:
            c.execute("UPDATE winlink_messages SET read=1 WHERE id=? AND direction='in'", (mid,))
        return jsonify({'ok': True})
    except Exception:
        return jsonify({'ok': False}), 500

@bp.post('/auto_start', endpoint='winlink_auto_start')
def winlink_auto_start():
    """Start AutoSend; if poll/parse aren’t running, start them too."""
    
    ok, _, reason = pat_config_status()
    if not ok:
        flash(f"Cannot start WinLink: PAT not configured (set callsign/password in Admin → WinLink, then click “Configure PAT”) ({reason}).", "error")
        return redirect(url_for('radio.radio'))

    # Ensure PAT exists (attempt silent config from prefs once).
    if not pat_config_exists():
        ok, err = _configure_pat_from_prefs_silent()
        if not ok:
            flash("PAT not configured (set callsign/password in Admin → WinLink, then click “Configure PAT”) — set WinLink creds in Admin and click Configure PAT.", "error")
            return redirect(request.referrer or url_for('radio.radio'))
    try:
        poll_job  = scheduler.get_job('winlink_poll')
        parse_job = scheduler.get_job('winlink_parse')
        if poll_job is None or parse_job is None:
            configure_winlink_jobs()  # installs both poll and parse
    except Exception:
        configure_winlink_jobs()
    ok, path, reason = pat_config_status()
    if not ok:
        flash(f"Cannot enable auto-send: PAT not configured (set callsign/password in Admin → WinLink, then click “Configure PAT”) ({reason}{' @ ' + path if path else ''}).", "error")
        return redirect(url_for('winlink.winlink_inbox'))
    configure_winlink_auto_jobs()
    flash("Auto-WinLink sending started (poll + parse running).", "success")
    return redirect(request.referrer or url_for('radio.radio'))

@bp.post('/auto_stop', endpoint='winlink_auto_stop')
def winlink_auto_stop():
    """Stop the Auto-WinLink-Send background job."""
    
    ok, _, reason = pat_config_status()
    if not ok:
        flash(f"Cannot start WinLink: PAT not configured (set callsign/password in Admin → WinLink, then click “Configure PAT”) ({reason}).", "error")
        return redirect(url_for('radio.radio'))
    try:
        scheduler.remove_job('winlink_auto_send')
        flash("Auto-WinLink sending stopped.", "info")
    except JobLookupError:
        flash("Auto-WinLink was not running.", "warning")
    return redirect(request.referrer or url_for('radio.radio'))

@bp.get('/unread_count', endpoint='winlink_unread_count')
def winlink_unread_count():
    """
    Return unread inbound WinLink count as JSON.
    Uses client cookie 'winlink_emails_read' (range-encoded ID list).
    Unread = inbound messages whose IDs are NOT in those ranges.
    """
    cookie_val = request.cookies.get('winlink_emails_read', '')
    ranges = _parse_read_ranges_cookie(cookie_val)

    where = "direction='in'"
    params = []
    if ranges:
        # build: NOT ( (id BETWEEN ? AND ?) OR (id BETWEEN ? AND ?) OR (id=? ) )
        ors = []
        for s, e in ranges:
            if s == e:
                ors.append("id=?")
                params.append(s)
            else:
                ors.append("(id BETWEEN ? AND ?)")
                params.extend([s, e])
        where = f"{where} AND NOT (" + " OR ".join(ors) + ")"

    with sqlite3.connect(DB_FILE) as c:
        count = c.execute(
            f"SELECT COUNT(*) FROM winlink_messages WHERE {where}",
            params
        ).fetchone()[0]
    return jsonify({"count": int(count)})

@bp.get('/internet_status', endpoint='internet_status')
def internet_status():
    """
    Server→internet status for UI.
    Returns: {"ok":true, "online": bool, "since":"ISO", "last_check":"ISO", "resume": "poll|auto+poll|"}
    """
    online_flag = (get_preference('internet_online') or '').strip().lower()
    return jsonify({
        'ok': True,
        'online': (online_flag == 'yes'),
        'since': get_preference('internet_since_iso') or '',
        'last_check': get_preference('internet_last_check_iso') or '',
        'resume': get_preference('winlink_resume_mask') or ''
    })

@bp.post('/send/<int:flight_id>', endpoint='winlink_send')
def winlink_send(flight_id):
    """Send the given flight via WinLink and record the outbound message."""
    # 0) ensure polling is running
    if scheduler.get_job('winlink_poll') is None:
        flash("Cannot send: WinLink polling is not active.", "error")
        return redirect(url_for('radio.radio'))

    # Ensure PAT is configured on disk
    if not pat_config_exists():
        flash('PAT not configured - set callsign/password in Admin, then click Configure PAT.', 'error')
        return redirect(url_for('radio.radio_detail', fid=flight_id))

    # 1) Fetch the flight record
    flight = dict_rows("SELECT * FROM flights WHERE id = ?", (flight_id,))[0]
    subject = generate_subject(flight)
    body    = generate_body(flight)

    # Resolve counterparty via Airport→WinLink mappings (flip to ORIGIN if dest==us)
    raw = get_preference('airport_call_mappings') or ''
    mapping = {}
    for ln in raw.splitlines():
        if ':' not in ln:
            continue
        code, wl = (x.strip().upper() for x in ln.split(':', 1))
        canon = canonical_airport_code(code)
        if canon and wl:
            mapping.setdefault(canon, wl)

    party_canon, role = _resolve_counterparty_airport(
        flight.get('airfield_takeoff',''), flight.get('airfield_landing',''))
    to_addr = mapping.get(party_canon or '')
    if not to_addr:
        missing = party_canon or '(unknown airport)'
        flash(
            f"No recipient configured for {role} {missing}. "
            "Add a mapping in Preferences → Airport→Callsign Mappings.",
            "warning"
        )
        return redirect(url_for('radio.radio_detail', fid=flight_id))

    cs = get_send_as_callsign()
    # build PAT compose cmd: flags (including CC) must come before the recipient
    cmd = ["pat", "compose", "--from", cs, "-s", subject]
    # use the same CC logic the UI count uses (non-blank only)
    ccs = _nonblank_cc_list()
    for cc in ccs:
        cmd += ["--cc", cc]
    cmd.append(to_addr)

    try:
        subprocess.run(
            cmd,
            input=body,
            text=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Record outbound and mark flight sent
        with sqlite3.connect(DB_FILE) as conn:
            ts_iso = iso8601_ceil_utc()
            conn.execute("UPDATE flights SET sent=1, sent_time=? WHERE id=?", (ts_iso, flight_id))
            conn.execute("""
                INSERT INTO winlink_messages
                  (direction, callsign, sender, subject, body, flight_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ('out', cs, to_addr, subject, body, flight_id))
            # also mirror into outgoing_messages for communications.csv
            operator = (
                request.cookies.get('operator_call', '')
                or get_preference('winlink_callsign_1')
                or 'YOURCALL'
            ).upper()
            conn.execute("""
                INSERT INTO outgoing_messages (flight_id, operator_call, timestamp, subject, body)
                VALUES (?,?,?,?,?)
            """, (flight_id, operator, ts_iso, subject, body))

        rcpt_summary = f"{to_addr}" + (f" (+{len(ccs)} CC)" if ccs else "")
        flash(f"Queued to {rcpt_summary} via PAT; flight marked sent.", "success")
        return redirect(url_for('radio.radio'))
    except subprocess.CalledProcessError as err:
        app.logger.error("PAT send failed: %s\n%s", err, err.stderr or err.stdout)
        flash("Failed to send via PAT.", "error")
        return redirect(url_for('radio.radio_detail', fid=flight_id))
    return redirect(url_for('radio.radio'))

# --- Ad-hoc AOCT reply sender for Radio page ---
@bp.post('/aoct_send', endpoint='aoct_send')
def aoct_send():
    ok, _, reason = pat_config_status()
    if not ok:
        return jsonify({'ok': False, 'message': f'PAT not configured: {reason}'}), 400
    to = (request.form.get('to') or '').strip().upper()
    subject = (request.form.get('subject') or '').strip()
    body = request.form.get('body') or ''
    if not to or not subject or not body:
        return jsonify({'ok': False, 'message': 'to, subject, and body are required'}), 400
    if scheduler.get_job('winlink_poll') is None:
        # keep parity with other senders that require poller alive
        return jsonify({'ok': False, 'message': 'WinLink polling not running'}), 400
    sent = send_winlink_message(to, subject, body)
    if not sent:
        return jsonify({'ok': False, 'message': 'PAT compose failed'}), 502
    return jsonify({'ok': True})

@bp.get('/inbox', endpoint='winlink_inbox')
def winlink_inbox():
    """Show the WinLink inbox page (with dynamic AJAX refresh)."""
    def _arg_truthy(name: str):
        v = (request.args.get(name) or "").strip().lower()
        if v in ("1","true","yes","on"):  return True
        if v in ("0","false","no","off"): return False
        return None

    hp_arg = _arg_truthy("hide_parsable")
    hide_parsable = hp_arg if hp_arg is not None else cookie_truthy("hide_parsable", False, request)

    resp = make_response(render_template(
        'winlink_inbox.html',
        active='radio',
        hide_parsable=hide_parsable
    ))
    # If user supplied an explicit query toggle, persist it in the cookie.
    if hp_arg is not None:
        resp.set_cookie('hide_parsable', 'yes' if hide_parsable else 'no', max_age=365*24*3600, samesite='Lax', path='/')
    return resp

@bp.route('/compose', methods=['GET', 'POST'], endpoint='winlink_compose')
def winlink_compose():
    """Compose and send an arbitrary Winlink message. Requires Winlink password."""
    # Auth gate: check session
    if not session.get('winlink_compose_unlocked'):
        if request.method == 'POST' and 'compose_password' in request.form:
            entered = request.form.get('compose_password', '').strip()
            valid = [get_preference(f'winlink_password_{i}') or '' for i in (1, 2, 3)]
            if entered and entered in valid:
                session['winlink_compose_unlocked'] = True
            else:
                flash('Invalid Winlink password.', 'error')
                return redirect(url_for('winlink.winlink_compose'))
        else:
            # Show password gate
            callsigns = [get_preference(f'winlink_callsign_{i}') or ''
                         for i in (1, 2, 3) if get_preference(f'winlink_callsign_{i}')]
            return render_template('winlink_compose.html',
                                   active='radio', locked=True, callsigns=callsigns)

    # Handle compose form submission (AJAX or form POST)
    if request.method == 'POST' and 'to' in request.form:
        to_raw  = request.form.get('to', '').strip().upper()
        cc_raw  = request.form.get('cc', '').strip().upper()
        subject = request.form.get('subject', '').strip()
        body    = request.form.get('body', '').strip()

        to_list = [a.strip() for a in to_raw.split(',') if a.strip()]
        cc_list = [a.strip() for a in cc_raw.split(',') if a.strip()]

        if not to_list or not subject:
            flash('To and Subject are required.', 'error')
            return redirect(url_for('winlink.winlink_compose'))

        # Record outbound messages to DB synchronously (fast) so
        # the send log is updated immediately on redirect.
        all_addrs = to_list + cc_list
        cs = get_send_as_callsign()
        try:
            with sqlite3.connect(DB_FILE, timeout=5) as conn:
                ts_iso = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                for addr in all_addrs:
                    conn.execute("""
                        INSERT INTO winlink_messages
                          (direction, callsign, sender, subject, body, timestamp)
                        VALUES ('out', ?, ?, ?, ?, ?)
                    """, (cs, addr, subject, body, ts_iso))
        except Exception:
            pass

        # Fire PAT compose in background (slow, talks to CMS)
        def _compose_bg():
            for addr in all_addrs:
                try:
                    _cmd = ["pat", "compose", "--from", cs, "-s", subject, addr]
                    subprocess.run(_cmd, input=body or "", text=True,
                                  check=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=60)
                except Exception:
                    pass
        threading.Thread(target=_compose_bg, daemon=True).start()

        all_recips = ', '.join(all_addrs)
        flash(f'Message queued to {all_recips}.', 'success')
        return redirect(url_for('winlink.winlink_compose'))

    # GET: show compose form + send log
    send_as = get_send_as_callsign()
    send_log = dict_rows("""
        SELECT timestamp, callsign, sender, subject,
               CASE WHEN timestamp IS NOT NULL THEN 1 ELSE 0 END AS sent_via_pat
          FROM winlink_messages
         WHERE direction='out'
         ORDER BY id DESC
         LIMIT 20
    """)
    return render_template('winlink_compose.html',
                           active='radio', locked=False,
                           send_as=send_as, send_log=send_log)


@bp.post('/start', endpoint='winlink_start')
def winlink_start():
    """Clear existing jobs, install our 5-min WinLink poll, and start the scheduler."""
    
    ok, _, reason = pat_config_status()
    if not ok:
        flash(f"Cannot start WinLink: PAT not configured (set callsign/password in Admin → WinLink, then click “Configure PAT”) ({reason}).", "error")
        return redirect(url_for('radio.radio'))


    # Ensure PAT config is present before enabling poll/parse.
    if not pat_config_exists():
        ok, err = _configure_pat_from_prefs_silent()
        if not ok:
            flash("PAT not configured (set callsign/password in Admin → WinLink, then click “Configure PAT”) — set WinLink creds in Admin and click Configure PAT.", "error")
            return redirect(request.referrer or url_for('radio.radio'))

    try:
        scheduler.remove_job('winlink_poll')
    except JobLookupError:
        pass
    # now add back only WinLink
    ok, path, reason = pat_config_status()
    if not ok:
        flash(f"Cannot start WinLink polling: PAT not configured (set callsign/password in Admin → WinLink, then click “Configure PAT”) ({reason}{' @ ' + path if path else ''}).", "error")
        return redirect(url_for('winlink.winlink_inbox'))
    configure_winlink_jobs()
    flash("Winlink polling started.", "success")
    return redirect(request.referrer or url_for('radio.radio'))

@bp.post('/stop', endpoint='winlink_stop')
def winlink_stop():
    """Remove poll & parse jobs; also stop AutoSend to enforce capability levels."""
    
    ok, _, reason = pat_config_status()
    if not ok:
        flash(f"Cannot start WinLink: PAT not configured (set callsign/password in Admin → WinLink, then click “Configure PAT”) ({reason}).", "error")
        return redirect(url_for('radio.radio'))
    stopped_any = False
    for job_id in ('winlink_poll', 'winlink_parse', 'winlink_auto_send'):
        try:
            scheduler.remove_job(job_id)
            stopped_any = True
        except JobLookupError:
            pass
    if stopped_any:
        flash("WinLink polling stopped (parse & AutoSend halted).", "info")
    else:
        flash("WinLink polling was not running.", "warning")
    return redirect(request.referrer or url_for('radio.radio'))

def _parse_remote_csv(csv_text: str):
    """
    Returns (rows_list, totals) from stored CSV text.
    rows_list: [{'category','sanitized_name','wpu','qty','total'}...]
    totals: {'lines':int, 'total_lb':float}
    """
    if not (csv_text or "").strip():
        return [], {'lines': 0, 'total_lb': 0.0}

    rdr = _csv.reader(_StringIO(csv_text))
    header = next(rdr, [])
    # Expect Phase 1 header: category,item,unit_weight_lb,quantity,total_weight_lb
    cols = {name: idx for idx, name in enumerate(header)}
    need = ['category', 'item', 'unit_weight_lb', 'quantity', 'total_weight_lb']
    if not all(n in cols for n in need):
        # tolerate odd input gracefully
        return [], {'lines': 0, 'total_lb': 0.0}

    rows = []
    total_lb = 0.0
    for r in rdr:
        try:
            cat   = (r[cols['category']] or '').strip()
            name  = (r[cols['item']] or '').strip()
            wpu   = float(r[cols['unit_weight_lb']] or 0.0)
            qty   = int(float(r[cols['quantity']] or 0))
            tot   = float(r[cols['total_weight_lb']] or 0.0)
        except Exception:
            # skip malformed line
            continue
        rows.append({
            'category': cat,
            'sanitized_name': name,
            'wpu': wpu,
            'qty': qty,
            'total': tot,
        })
        total_lb += tot

    return rows, {'lines': len(rows), 'total_lb': round(total_lb, 1)}

def _remote_airports_index():
    """
    Build list view: one row per airport with snapshot_at, row count, total lbs.
    """
    recs = dict_rows("""
      SELECT airport_canon, snapshot_at, received_at, csv_text
        FROM remote_inventory
       ORDER BY airport_canon
    """)
    out = []
    for r in recs:
        rows, totals = _parse_remote_csv(r.get('csv_text') or '')
        out.append({
            'airport': (r.get('airport_canon') or '').strip().upper(),
            'generated_at': r.get('snapshot_at') or '',
            'received_at': r.get('received_at') or '',
            'rows': totals['lines'],
            'total_lb': totals['total_lb'],
        })
    return out

def _remote_airport_detail(airport_code: str):
    canon = canonical_airport_code(airport_code or '')
    recs = dict_rows("""
      SELECT airport_canon, snapshot_at, csv_text
        FROM remote_inventory
       WHERE airport_canon = ?
       LIMIT 1
    """, (canon,))
    if not recs:
        return canon, None, None
    r = recs[0]
    rows, totals = _parse_remote_csv(r.get('csv_text') or '')
    return canon, {'generated_at': r.get('snapshot_at') or '',
                   'rows': rows,
                   'totals': totals}, r.get('csv_text') or ''

@bp.get('/remote_airports', endpoint='remote_airports')
def remote_airports():
    """
    Page shell for Remote Airports (entered from Inventory view).
    Optional ?airport=AAA shows the detail table under the index.
    """
    airports = _remote_airports_index()
    airport_q = (request.args.get('airport') or '').strip().upper()
    detail_rows = None
    detail_generated_at = None
    detail_airport = None
    if airport_q:
        canon, detail, _csv_text = _remote_airport_detail(airport_q)
        detail_airport = canon
        if detail:
            detail_rows = detail['rows']
            detail_generated_at = detail['generated_at']

    return render_template(
        'remote_airports.html',
        airports=airports,
        detail_rows=detail_rows,
        detail_generated_at=detail_generated_at,
        detail_airport=detail_airport,
        active='inventory'  # keep highlighting consistent with spec entry point
    )
