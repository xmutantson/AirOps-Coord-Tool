
from markupsafe import escape
import sqlite3, re, json, logging
from datetime import datetime
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for

from modules.services.winlink.core import parse_winlink, generate_subject, generate_body
from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from modules.utils.common import _start_radio_tx_once, maybe_extract_flight_code, _is_winlink_reflector_bounce  # call run-once starter from this bp

# --- IMPORTANT ---
# The star import above brings in a DB-only fallback wargame_task_finish that returns None
# and does not record metrics. Explicitly override it here with the *real* implementation.
try:
    from modules.services.wargame import (
        wargame_task_finish as _wg_finish_real,
        extract_wgid_from_text as _extract_wgid_from_text,
    )
except Exception:
    _wg_finish_real = None
    _extract_wgid_from_text = None
if _wg_finish_real:
    # Replace the fallback imported via modules.utils.common with the real one.
    wargame_task_finish = _wg_finish_real

# Give this blueprint a stable, explicit name so endpoints are always 'radio.*'
bp = Blueprint('radio', __name__)
logger = logging.getLogger(__name__)

# Start RadioTX once when this blueprint sees its first request.
# (Flask blueprints don’t have before_app_first_request; use before_request + our guard.)
#@bp.before_request
#def _radiotx_once_setup():
#    try:
#        _start_radio_tx_once()
#    except Exception:
#        # never block a request just because RadioTX couldn’t start
#        pass

@bp.route('/radio', methods=['GET','POST'], endpoint='radio')
def radio():
    if request.method == 'POST':
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        subj   = escape(request.form['subject'].strip())
        body   = escape(request.form['body'].strip())
        sender = escape(request.form.get('sender','').strip())
        ts     = datetime.utcnow().isoformat()

        # --- extract WGID (prefer services' subject+body extractor) ---
        if _extract_wgid_from_text:
            wgid = (_extract_wgid_from_text(subj, body) or '').lower() or None
        else:
            def _extract_wgid(subject, body):
                m = re.search(r'\[?WGID:([a-f0-9]{16,})\]?', str(subject), re.I)
                return m.group(1).lower() if m else None
            wgid = _extract_wgid(subj, body)

        # --- override parse_winlink tail on bare “landed” notices ---
        m_tail = re.match(r"Air Ops:\s*(?P<tail>\S+)\s*\|\s*landed", subj, re.I)
        tail_override = m_tail.group('tail').strip() if m_tail else None

        # parse
        p = parse_winlink(subj, body)
        if tail_override:
            p['tail_number'] = tail_override
        # attempt to extract flight_code from subject/body (manual Radio POST path)
        fcode = maybe_extract_flight_code(subj) or maybe_extract_flight_code(body)
        p['flight_code'] = fcode or ''

        # ── post-clean the two HHMM fields ────────────────────────────────
        def _clean(t: str) -> str:
            if not t:
                return ''
            u = t.upper().strip()
            if re.match(r'^UNK(?:N|KNOWN)?$', u):  # UNK/UNKN/UNKNOWN → blank
                return ''
            u = re.sub(r'\b(?:L|LOCAL)$', '', u).strip()  # strip trailing L/LOCAL
            return u                  # already zero-padded by parse_winlink()

        p['takeoff_time'] = _clean(p['takeoff_time'])
        p['eta']          = _clean(p['eta'])

        with sqlite3.connect(current_app.config['DB_FILE']) as c:
            c.row_factory = sqlite3.Row

            # 1) store raw incoming
            c.execute("""
              INSERT INTO incoming_messages(
                sender, subject, body, timestamp,
                tail_number, airfield_takeoff, airfield_landing,
                takeoff_time, eta, cargo_type, cargo_weight, remarks
              ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
              sender, subj, body, ts,
              p['tail_number'], p['airfield_takeoff'], p['airfield_landing'],
              p['takeoff_time'], p['eta'], p['cargo_type'], p['cargo_weight'],
              p.get('remarks','')
            ))

            # ---- end the write txn, then finish SLA BEFORE any early return ----
            c.commit()
            if wgid:
                try:
                    recorded = wargame_task_finish('radio', 'inbound', key=f"msg:{wgid}")
                    logger.debug("Radio SLA finish WGID=%s recorded=%s", wgid, recorded)
                except Exception as exc:
                    logger.debug("Could not finish Radio‑inbound SLA for WGID %s: %s", wgid, exc)
            else:
                logger.debug("No WGID in message; skipping Radio SLA finish.")

            # If this is a Winlink Test Message Reflector bounce, stop after auditing.
            if _is_winlink_reflector_bounce(subj, body):
                if is_ajax:
                    return jsonify({'action': 'ignored_reflector'})
                return redirect(url_for('radio.radio'))

            # 2) landing-report?
            lm = re.search(r'\blanded\s*(\d{1,2}:?\d{2})\b', subj, re.I)
            if lm:
                arrival = hhmm_norm(lm.group(1))
                # 1) strict tail + takeoff_time
                match = c.execute("""
                  SELECT id, remarks
                    FROM flights
                   WHERE tail_number=? AND takeoff_time=? AND complete=0
                   ORDER BY id DESC
                   LIMIT 1
                """, (p['tail_number'], p['takeoff_time'])).fetchone()
                # 2) route-based fallback
                if not match and p['airfield_takeoff'] and p['airfield_landing']:
                    match = c.execute("""
                      SELECT id, remarks
                        FROM flights
                       WHERE tail_number=?
                         AND airfield_takeoff=? AND airfield_landing=? AND complete=0
                       ORDER BY id DESC
                       LIMIT 1
                    """, (p['tail_number'], p['airfield_takeoff'], p['airfield_landing'])).fetchone()
                # 3) most-recent fallback
                if not match:
                    match = c.execute("""
                      SELECT id, remarks
                        FROM flights
                       WHERE tail_number=? AND complete=0
                       ORDER BY timestamp DESC
                       LIMIT 1
                    """, (p['tail_number'],)).fetchone()
                if match:
                    before = dict_rows("SELECT * FROM flights WHERE id=?", (match['id'],))[0]
                    c.execute("""
                      INSERT INTO flight_history(flight_id, timestamp, data)
                      VALUES (?,?,?)
                    """, (match['id'], datetime.utcnow().isoformat(), json.dumps(before)))
                    old_rem = (before.get('remarks') or '').strip()
                    new_rem = (f"{old_rem} / Arrived {arrival}" if old_rem else f"Arrived {arrival}")
                    c.execute("""
                      UPDATE flights
                         SET eta=?, complete=1, remarks=?, flight_code=COALESCE(?, flight_code)
                       WHERE id=?
                    """, (arrival, new_rem, fcode, match['id']))
                    c.commit()
                    if is_ajax:
                        row = dict_rows("SELECT * FROM flights WHERE id=?", (match['id'],))[0]
                        row['action'] = 'updated'
                        return jsonify(row)
                    # Prefer flight_code for operator feedback; fall back to id if absent
                    code_row = dict_rows(
                        "SELECT flight_code FROM flights WHERE id=?",
                        (match['id'],)
                    )
                    code_txt = (code_row[0]['flight_code'] or match['id']) if code_row else match['id']
                    flash(f"Flight {code_txt} marked as landed at {arrival}.")
                    return redirect(url_for('radio.radio'))
                # fall through to duplicate/ignore logic if still no match

                # ── no matching outbound.  Do we already have this landing? ──
                dup = c.execute("""
                   SELECT id FROM flights
                    WHERE tail_number=? AND eta=? AND complete=1
                 ORDER BY id DESC LIMIT 1
                """, (p['tail_number'], arrival)).fetchone()

                if dup:
                    if is_ajax:
                        full = dict_rows("SELECT * FROM flights WHERE id=?", (dup['id'],))
                        row = full[0] if full else {'id': dup['id']}
                        row['action'] = 'update_ignored'
                        return jsonify(row)
                    flash(f"Landed notice ignored – flight #{dup['id']} already recorded.")
                    return redirect(url_for('radio.radio'))

                # No matching outbound → ignore creating any flight.
                # We still keep incoming_messages (already inserted above) for audit.
                if is_ajax:
                    return jsonify({'action': 'ignored_landing_no_match',
                                    'tail': p['tail_number'],
                                    'arrival': arrival})
                flash("Remote landing confirmation ignored (no matching outbound leg).")
                return redirect(url_for('radio.radio'))

            # ── fallback: pure “landed” with no time given ──
            elif re.search(r'\blanded\b', subj, re.I):
                match = c.execute(
                    "SELECT id FROM flights WHERE tail_number=? AND complete=0 ORDER BY id DESC LIMIT 1",
                    (p['tail_number'],)
                ).fetchone()
                if match:
                    c.execute("UPDATE flights SET complete=1, sent=0 WHERE id=?", (match['id'],))
                    flash(f"Flight {match['id']} marked as landed (no time given).")
                return redirect(url_for('radio.radio'))

            # 3) not a landing → match by tail & takeoff_time?
            f = c.execute(
                "SELECT id FROM flights WHERE tail_number=? AND takeoff_time=?",
                (p['tail_number'], p['takeoff_time'])
            ).fetchone()

            if f:
                before = dict_rows("SELECT * FROM flights WHERE id=?", (f['id'],))[0]

                no_change = (
                    before['airfield_takeoff'] == p['airfield_takeoff'] and
                    before['airfield_landing'] == p['airfield_landing'] and
                    (p['eta'] or before['eta']) == before['eta'] and
                    (p['cargo_type']   or before['cargo_type'])   == before['cargo_type'] and
                    (p['cargo_weight'] or before['cargo_weight']) == before['cargo_weight'] and
                    (p.get('remarks','') or before['remarks'])    == before['remarks']
                )

                if no_change:
                    if is_ajax:
                        full = dict_rows("SELECT * FROM flights WHERE id=?", (f['id'],))
                        row = full[0] if full else {'id': f['id']}
                        row['action'] = 'update_ignored'
                        return jsonify(row)
                    flash(f"Duplicate Winlink ignored (flight #{f['id']}).")
                    return redirect(url_for('radio.radio'))

                c.execute("""
                  INSERT INTO flight_history(flight_id, timestamp, data)
                  VALUES (?,?,?)
                """, (f['id'], datetime.utcnow().isoformat(), json.dumps(before)))

                c.execute("""
                  UPDATE flights SET
                    airfield_takeoff = ?,
                    airfield_landing = ?,
                    eta              = CASE WHEN ?<>'' THEN ? ELSE eta END,
                    cargo_type       = CASE WHEN ?<>'' THEN ? ELSE cargo_type   END,
                    cargo_weight     = CASE WHEN ?<>'' THEN ? ELSE cargo_weight END,
                    remarks          = CASE WHEN ?<>'' THEN ? ELSE remarks      END,
                    flight_code      = COALESCE(?, flight_code)
                  WHERE id=?
                """, (
                  p['airfield_takeoff'],
                  p['airfield_landing'],
                  p['eta'], p['eta'],
                  p['cargo_type'],   p['cargo_type'],
                  p['cargo_weight'], p['cargo_weight'],
                  p.get('remarks',''), p.get('remarks',''),
                  fcode,
                  f['id']
                ))
                c.commit()

                if is_ajax:
                    rs = dict_rows("SELECT * FROM flights WHERE id=?", (f['id'],))
                    row = rs[0] if rs else {'id': f['id']}
                    row['action'] = 'updated'
                    return jsonify(row)

                flash(f"Flight {f['id']} updated from incoming message.")

            else:
                # ── NEW NON-RAMP ENTRY ────────────────────────────
                # Perfect-duplicate guard: refuse identical open leg
                dup_new = c.execute("""
                    SELECT id FROM flights
                     WHERE IFNULL(complete,0)=0
                       AND tail_number=? AND airfield_takeoff=? AND airfield_landing=?
                       AND IFNULL(takeoff_time,'')=? AND IFNULL(eta,'')=?
                       AND IFNULL(cargo_type,'')=? AND IFNULL(cargo_weight,'')=?
                       AND IFNULL(remarks,'')=?
                     ORDER BY id DESC LIMIT 1
                """, (
                  p['tail_number'], p['airfield_takeoff'], p['airfield_landing'],
                  p['takeoff_time'] or '', p['eta'] or '',
                  p['cargo_type'] or '', p['cargo_weight'] or '', p.get('remarks','') or ''
                )).fetchone()
                if dup_new:
                    if is_ajax:
                        full = dict_rows("SELECT * FROM flights WHERE id=?", (dup_new['id'],))
                        row = full[0] if full else {'id': dup_new['id']}
                        row['action'] = 'update_ignored'
                        return jsonify(row)
                    flash(f"Duplicate Winlink ignored (flight #{dup_new['id']}).")
                    return redirect(url_for('radio.radio'))

                open_prev = c.execute("""
                    SELECT id, remarks FROM flights
                     WHERE tail_number=? AND complete=0
                """, (p['tail_number'],)).fetchall()

                for prev in open_prev:
                    before = dict_rows("SELECT * FROM flights WHERE id=?", (prev['id'],))[0]
                    c.execute("""
                        INSERT INTO flight_history(flight_id,timestamp,data)
                        VALUES (?,?,?)
                    """, (prev['id'], datetime.utcnow().isoformat(), json.dumps(before)))

                    suffix  = f"Auto-closed at {p['takeoff_time'] or 'next leg'}"
                    new_rem = (prev['remarks'] + " / " if prev['remarks'] else "") + suffix

                    c.execute("""
                        UPDATE flights
                           SET complete=1, sent=0, remarks=?
                         WHERE id=?
                    """, (new_rem, prev['id']))

                fid = c.execute("""
                  INSERT INTO flights(
                    is_ramp_entry,
                    direction,
                    flight_code,
                    tail_number,
                    airfield_takeoff,
                    takeoff_time,
                    airfield_landing,
                    eta,
                    cargo_type,
                    cargo_weight,
                    remarks
                  ) VALUES (0,'inbound',?,?,?,?,?,?,?,?,?)
                """, (
                  fcode,
                  p['tail_number'],
                  p['airfield_takeoff'],
                  p['takeoff_time'],
                  p['airfield_landing'],
                  p['eta'],
                  p['cargo_type'],
                  p['cargo_weight'],
                  p.get('remarks','')
                )).lastrowid

                c.commit()

                if is_ajax:
                    row = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
                    row['action'] = 'new'
                    return jsonify(row)

                flash(f"Incoming flight logged as new entry #{fid}.")

        # normal (non-AJAX) POST → redirect back to Radio screen
        return redirect(url_for('radio.radio'))

    # ─── GET: fetch & order ramp entries ────────────────────────────────
    show_unsent_only = request.cookies.get('radio_show_unsent_only','yes') == 'yes'
    hide_tbd         = request.cookies.get('hide_tbd','yes') == 'yes'

    base_sql = """
      SELECT *
        FROM flights
       WHERE is_ramp_entry = 1
    """
    if show_unsent_only:
        base_sql += " AND sent = 0\n"
    base_sql += """
       ORDER BY
         CASE
           WHEN sent=0     THEN 0
           WHEN complete=0 THEN 1
           ELSE 2
         END,
         id DESC
    """

    flights = dict_rows(base_sql)

    pref     = dict_rows("SELECT value FROM preferences WHERE name='code_format'")
    code_fmt = request.cookies.get('code_format') or (pref[0]['value'] if pref else 'icao4')
    mass_fmt = request.cookies.get('mass_unit', 'lbs')
    hide_tbd = request.cookies.get('hide_tbd', 'yes') == 'yes'

    for f in flights:
        f['origin_view'] = fmt_airport(f.get('airfield_takeoff',''), code_fmt)
        f['dest_view']   = fmt_airport(f.get('airfield_landing',''), code_fmt)

        if f.get('direction')=='outbound' and f.get('eta') and not f.get('complete',0):
            f['eta_view'] = f['eta'] + '*'
        else:
            f['eta_view'] = f.get('eta','TBD')

        cw    = (f.get('cargo_weight') or '').strip()
        m_lbs = re.match(r'([\d.]+)\s*lbs', cw, re.I)
        m_kg  = re.match(r'([\d.]+)\s*kg',  cw, re.I)
        if mass_fmt=='kg' and m_lbs:
            v  = round(float(m_lbs.group(1)) / 2.20462, 1)
            cw = f'{v} kg'
        elif mass_fmt=='lbs' and m_kg:
            v  = round(float(m_kg.group(1)) * 2.20462, 1)
            cw = f'{v} lbs'
        f['cargo_view'] = cw or 'TBD'

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
    for f in flights:
        raw_dest = f.get('airfield_landing','')
        canon = canonical_airport_code(raw_dest)
        f['dest_mapped'] = canon in mapping

    # detect whether WinLink jobs are active
    _sch = current_app.extensions.get('scheduler')
    winlink_job_active  = bool(_sch and _sch.get_job('winlink_poll'))
    winlink_auto_active = bool(_sch and _sch.get_job('winlink_auto_send'))

    return render_template(
        'radio.html',
        flights=flights,
        active='radio',
        hide_tbd=hide_tbd,
        winlink_job_active=winlink_job_active,
        winlink_auto_active=winlink_auto_active
    )

@bp.route('/_radio_table')
def radio_table_partial():
    # read the same toggle
    show_unsent_only = request.cookies.get('radio_show_unsent_only','yes') == 'yes'

    # build matching query
    sql = """
      SELECT *
        FROM flights
       WHERE is_ramp_entry = 1
    """
    if show_unsent_only:
        sql += " AND sent = 0\n"
    sql += """
       ORDER BY
         CASE
           WHEN sent=0     THEN 0
           WHEN complete=0 THEN 1
           ELSE 2
         END,
         id DESC
    """

    flights = dict_rows(sql)

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

    # Add dest_mapped for each flight row
    for f in flights:
        raw_dest = f.get('airfield_landing','')
        canon = canonical_airport_code(raw_dest)
        f['dest_mapped'] = canon in mapping

    # same prefs + view‐field logic as in radio()
    pref     = dict_rows("SELECT value FROM preferences WHERE name='code_format'")
    code_fmt = request.cookies.get('code_format') or (pref[0]['value'] if pref else 'icao4')
    mass_fmt = request.cookies.get('mass_unit', 'lbs')
    hide_tbd = request.cookies.get('hide_tbd', 'yes') == 'yes'

    for f in flights:
        f['origin_view'] = fmt_airport(f.get('airfield_takeoff',''), code_fmt)
        f['dest_view']   = fmt_airport(f.get('airfield_landing',''), code_fmt)

        if f.get('direction')=='outbound' and f.get('eta') and not f.get('complete',0):
            f['eta_view'] = f['eta'] + '*'
        else:
            f['eta_view'] = f.get('eta','TBD')

        cw    = (f.get('cargo_weight') or '').strip()
        m_lbs = re.match(r'([\d.]+)\s*lbs', cw, re.I)
        m_kg  = re.match(r'([\d.]+)\s*kg',  cw, re.I)
        if mass_fmt=='kg' and m_lbs:
            v  = round(float(m_lbs.group(1)) / 2.20462, 1)
            cw = f'{v} kg'
        elif mass_fmt=='lbs' and m_kg:
            v  = round(float(m_kg.group(1)) * 2.20462, 1)
            cw = f'{v} lbs'
        f['cargo_view'] = cw or 'TBD'

    return render_template(
        'partials/_radio_table.html',
        flights=flights,
        hide_tbd=hide_tbd
    )

@bp.route('/radio_detail/<int:fid>')
def radio_detail(fid):
    rows = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))
    if not rows:
        return ("Not found", 404)
    flight = rows[0]

    subject, body = generate_subject(flight), generate_body(flight)

    # read CMS creds out of your preferences
    wl_callsign = get_preference('winlink_callsign_1')     or ''
    wl_pass     = get_preference('winlink_password_1')     or ''

    # fully configured?
    winlink_configured = bool(wl_callsign and wl_pass)

    # is our 5-min poll job running?
    _sch = current_app.extensions.get('scheduler')
    winlink_job_active = bool(_sch.get_job('winlink_poll')) if _sch else False

    return render_template(
        'send_flight.html',
        flight=flight,
        subject_text=subject,
        body_text=body,
        active='radio',
        winlink_configured=winlink_configured,
        winlink_job_active=winlink_job_active,
    )

@bp.route('/mark_sent/<int:fid>', methods=['POST'])
@bp.route('/mark_sent/<int:flight_id>', methods=['POST'])
def mark_sent(fid=None, flight_id=None):
    fid = fid or flight_id
    """Flag a flight as sent and snapshot its state (+ operator callsign)."""
    callsign = request.cookies.get('operator_call', 'YOURCALL').upper()
    now_ts   = datetime.utcnow().isoformat()

    with sqlite3.connect(current_app.config['DB_FILE']) as c:
        c.row_factory = sqlite3.Row
        # fetch current row (for subject/body), but gate with an atomic UPDATE below
        rows = c.execute("SELECT * FROM flights WHERE id=?", (fid,)).fetchall()
        if not rows:
            flash("Flight not found.")
            return redirect(url_for('radio.radio'))
        before  = dict(rows[0])
        code_txt = (before.get('flight_code') or 'TBD')

        # Atomically mark as sent only if not already sent (double-click safe)
        c.execute("BEGIN IMMEDIATE")
        updated = c.execute(
            "UPDATE flights SET sent=1, sent_time=? WHERE id=? AND IFNULL(sent,0)=0",
            (now_ts, fid)
        ).rowcount
        if updated == 0:
            c.execute("ROLLBACK")
            flash(f"Flight {code_txt} was already marked as sent.")
            return redirect(url_for('radio.radio'))

        # count prior messages by this operator → message number
        cnt = c.execute(
            "SELECT COUNT(*) FROM flight_history WHERE json_extract(data,'$.operator_call') = ?",
            (callsign,)
        ).fetchone()[0]

        # snapshot the state we’re sending (like manual path)
        snap = dict(before)
        snap['operator_call'] = callsign
        c.execute("""
            INSERT INTO flight_history(flight_id, timestamp, data)
            VALUES (?,?,?)
        """, (fid, now_ts, json.dumps(snap)))
        # now snapshot the outgoing Winlink message
        include_test = request.cookies.get('include_test','yes') == 'yes'
        # build body exactly as radio_detail()
        lines = []
        if include_test:
            lines.append("**** TEST MESSAGE ONLY  (if reporting on an actual flight, delete this line). ****")
        lines.append(f"{callsign} message number {cnt+1:03}.")
        lines.append("")
        lines.append(f"Aircraft {before['tail_number']}:")
        lines.append(f"  Cargo Type(s) ................. {before.get('cargo_type','none')}")
        lines.append(f"  Total Weight of the Cargo ..... {before.get('cargo_weight','none')}")
        lines.append("")
        lines.append("Additional notes/comments:")
        # Include Flight Code in the Additional notes/comments block
        if before.get('flight_code'):
            lines.append(f"  Flight Code: {before['flight_code']}")
        # Then the operator remarks, if any
        lines.append(f"  {before.get('remarks','')}")
        lines.append("")
        lines.append("{DART Aircraft Takeoff Report, rev. 2024-05-14}")
        body = "\n".join(lines)
        # build subject exactly as radio_detail()
        if before.get('direction') == 'inbound':
            subject = (
                f"Air Ops: {before['tail_number']} | "
                f"{before['airfield_takeoff']} to {before['airfield_landing']} | "
                f"Landed {before['eta'] or '----'}"
            )
        else:
            subject = (
                f"Air Ops: {before['tail_number']} | "
                f"{before['airfield_takeoff']} to {before['airfield_landing']} | "
                f"took off {before['takeoff_time'] or '----'} | "
                f"ETA {before['eta'] or '----'}"
            )
        c.execute("""
            INSERT INTO outgoing_messages(flight_id, operator_call, timestamp, subject, body)
            VALUES (?,?,?,?,?)
        """, (fid, callsign, now_ts, subject, body))

        # commit the atomic mark + snapshots
        c.commit()

    # finalize SLA — reaching here means this call performed the 0→1 transition
    try:
        row = dict_rows("SELECT direction FROM flights WHERE id=?", (fid,))
        if row and (row[0]['direction'] == 'outbound'):
            wargame_finish_radio_outbound(fid)
        else:
            # inbound: this is the landing confirmation being sent
            wargame_task_finish('radio','landing', key=f"flight:{fid}")
    except Exception:
        pass

    flash(f"Flight {code_txt} marked as sent.")
    return redirect(url_for('radio.radio'))
