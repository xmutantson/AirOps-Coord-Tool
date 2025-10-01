
import sqlite3
from datetime import datetime, timedelta
import time
import re

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from app import DB_FILE
from flask import Blueprint, current_app
from flask import render_template, request, jsonify, flash, url_for, redirect, render_template_string
from app import scheduler
from modules.services.winlink.core import (
    build_aoct_flight_query_body,
    send_winlink_message,
    pat_config_status,
)
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

@bp.route('/supervisor')
def supervisor():
    """Supervisor dashboard showing counts, recent flights, inventory, and recent locates."""
    recent_locates = dict_rows("""
        SELECT id, tail, requested_at_utc, requested_by,
               latest_sample_ts_utc, latest_from_airport, latest_from_call
          FROM flight_locates
         ORDER BY id DESC
         LIMIT 3
    """)
    return render_template('supervisor.html', active='supervisor', recent_locates=recent_locates)

@bp.route('/_supervisor_recent_locates')
def supervisor_recent_locates_partial():
    """AJAX partial: latest 3 locate requests with live status."""
    recent_locates = dict_rows("""
        SELECT id, tail, requested_at_utc, requested_by,
               latest_sample_ts_utc, latest_from_airport, latest_from_call
          FROM flight_locates
         ORDER BY id DESC
         LIMIT 3
    """)
    return render_template('partials/_supervisor_recent_locates.html', recent_locates=recent_locates)

# ─────────────────────────────────────────────────────────────────────────────
# Flight Locate (fan-out Flight Query)
# ─────────────────────────────────────────────────────────────────────────────
def _all_mapped_callsigns() -> set[str]:
    """
    Parse Admin → WinLink “airport_call_mappings” into a unique set of callsigns.
    Accepts one callsign per line (AAA: CALL) and tolerates comma/semicolon lists.
    """
    raw = get_preference('airport_call_mappings') or ''
    calls: set[str] = set()
    for ln in (raw or '').splitlines():
        if ':' not in ln:
            continue
        _, rhs = ln.split(':', 1)
        # allow comma/semicolon separated lists on RHS
        for tok in re.split(r'[,;/\s]+', rhs.strip()):
            tok = tok.strip().upper()
            if tok:
                calls.add(tok)
    # never send to ourselves
    mycall = (get_preference('winlink_callsign_1') or '').strip().upper()
    if mycall in calls:
        calls.discard(mycall)
    return calls

def _cc_calls() -> set[str]:
    """
    Collect non-empty Winlink CC callsigns from prefs (winlink_cc_1..3).
    Accepts single calls per field; tolerates accidental separators/spaces.
    Excludes our own callsign.
    """
    cc_set: set[str] = set()
    for idx in (1, 2, 3):
        raw = (get_preference(f'winlink_cc_{idx}') or '').strip().upper()
        if not raw:
            continue
        # allow accidental comma/semicolon/whitespace lists; most installs use single values
        for tok in re.split(r'[,;/\s]+', raw):
            if tok:
                cc_set.add(tok)
    mycall = (get_preference('winlink_callsign_1') or '').strip().upper()
    cc_set.discard(mycall)
    return cc_set

@bp.post('/locates/preview', endpoint='locates_preview')
def locates_preview():
    """
    Build (but do not send yet) the AOCT Flight Query for offline/manual use,
    AND create the locate record so it appears in “Recent locate requests”.
    Returns JSON: { ok, locate_id, requested_at_utc, subject, body, recipients[], mapped_count, cc_count, recipient_count }.
    - NO PAT/scheduler requirement
    - DOES insert into flight_locates (limit 3 enforced)
    """
    payload = request.get_json(silent=True) or {}
    tail = (
        request.values.get('tail') or
        request.values.get('tail_number') or
        payload.get('tail') or
        payload.get('tail_number') or
        ''
    ).strip().upper()

    if not tail:
        return jsonify({'ok': False, 'message': 'Tail is required.'}), 400

    # Enforce: at most 3 visible locates
    try:
        with sqlite3.connect(DB_FILE) as c:
            cur = c.execute("SELECT COUNT(*) FROM flight_locates")
            cur_count = int(cur.fetchone()[0] or 0)
    except Exception:
        cur_count = 0
    if cur_count >= 3:
        return jsonify({
            'ok': False,
            'code': 'locate_limit',
            'message': 'You already have 3 locate requests visible. Delete one before creating another.',
            'limit': 3,
            'count': cur_count
        }), 409

    # Build subject/body exactly as the live path would
    origin = canonical_airport_code(get_preference('default_origin') or '')
    body   = build_aoct_flight_query_body(tail, origin or '')
    subject = "AOCT flight query"

    mapped_set = _all_mapped_callsigns()
    cc_set     = _cc_calls()
    recipients = sorted(mapped_set)

    # Create the locate now so it appears in the recent list
    requested_by = (request.cookies.get('operator_call') or get_preference('winlink_callsign_1') or 'OPERATOR').upper()
    req_ts = iso8601_ceil_utc()
    with sqlite3.connect(DB_FILE) as c:
        c.execute("""
          INSERT INTO flight_locates(tail, requested_at_utc, requested_by)
          VALUES (?,?,?)
        """, (tail, req_ts, requested_by))
        locate_id = int(c.execute("SELECT last_insert_rowid()").fetchone()[0])

    return jsonify({
        'ok': True,
        'locate_id': locate_id,
        'requested_at_utc': req_ts,
        'tail': tail,
        'subject': subject,
        'body': body,
        # counts surfaced so UI can display either mapped-only or total
        'mapped_count': len(mapped_set),
        'cc_count': len(cc_set),
        'recipient_count': len(mapped_set) + len(cc_set),
        'recipients': recipients,
    })

@bp.post('/locates/start', endpoint='locates_start')
def locates_start():
    """
    Fan-out an AOCT Flight Query to all mapped Winlink callsigns.
    Input: tail (required)
    Effects:
      1) Insert into flight_locates
      2) Build Flight Query body
      3) Resolve recipients from airport_call_mappings (dedup, exclude our CS)
      4) Send N messages via PAT; mirror → communications
    """
    payload = request.get_json(silent=True) or {}
    tail = (
        request.values.get('tail') or
        request.values.get('tail_number') or
        payload.get('tail') or
        payload.get('tail_number') or
        ''
    ).strip().upper()

    if not tail:
        return jsonify({'ok': False, 'message': 'Tail is required.'}), 400

    # Enforce: at most 3 visible locates (latest three shown on Supervisor)
    try:
        with sqlite3.connect(DB_FILE) as c:
            cur = c.execute("SELECT COUNT(*) FROM flight_locates")
            cur_count = int(cur.fetchone()[0] or 0)
    except Exception:
        cur_count = 0
    if cur_count >= 3:
        return jsonify({
            'ok': False,
            'code': 'locate_limit',
            'message': 'You already have 3 locate requests visible. Delete one before sending another.',
            'limit': 3,
            'count': cur_count
        }), 409

    # Ensure PAT is configured & poller is running (parity with other senders)
    ok, _, reason = pat_config_status()
    if not ok:
        return jsonify({'ok': False, 'message': f'PAT not configured: {reason}'}), 400
    if scheduler.get_job('winlink_poll') is None:
        return jsonify({'ok': False, 'message': 'WinLink polling not running'}), 400

    mapped_set = _all_mapped_callsigns()
    cc_set     = _cc_calls()
    total_cnt  = len(mapped_set) + len(cc_set)
    recipients = sorted(mapped_set)
    if not recipients:
        # Graceful: no-op with a friendly message. Also include count fields
        # so the UI never renders "undefined recipients".
        return jsonify({
            'ok': False,
            'message': 'No mapped Winlink callsigns found (Admin → WinLink → Airport→Callsign mappings).',
            'queued': total_cnt,
            'recipient_count': total_cnt,
            'mapped_count': len(mapped_set),
            'cc_count': len(cc_set),
            'recipients': []
        }), 200

    # Record the locate request
    requested_by = (request.cookies.get('operator_call') or get_preference('winlink_callsign_1') or 'OPERATOR').upper()
    req_ts = iso8601_ceil_utc()
    with sqlite3.connect(DB_FILE) as c:
        c.execute("""
          INSERT INTO flight_locates(tail, requested_at_utc, requested_by)
          VALUES (?,?,?)
        """, (tail, req_ts, requested_by))
        locate_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Build body from default origin (best available local airport)
    origin = canonical_airport_code(get_preference('default_origin') or '')
    body   = build_aoct_flight_query_body(tail, origin or '')
    subject = "AOCT flight query"

    # Fan-out in the background so the request returns immediately.
    def _fanout_job(loc_id:int, tail:str, subj:str, body:str, rcpts:list[str]):
        done = []
        for wl in rcpts:
            try:
                if send_winlink_message(wl, subj, body):
                    done.append(wl)
            except Exception:
                # best-effort; keep going
                pass
        # (Optional) You can record dispatch stats here if desired.

    scheduler.add_job(
        id=f'locate_fanout_{int(time.time())}_{locate_id}',
        func=_fanout_job,
        args=[int(locate_id), tail, subject, body, recipients],
        replace_existing=False
    )

    rcpt_count = len(recipients)
    # NOTE: We *send* one message per mapped callsign (no CC in locate fan-out),
    # but we expose a few counts so the UI can display either mapped-only or
    # mapped+cc totals without showing "undefined".
    mapped_cnt = len(mapped_set)
    cc_cnt     = len(cc_set)
    total_cnt  = mapped_cnt + cc_cnt
    return jsonify({
        'ok': True,
        'locate_id': int(locate_id),
        'tail': tail,
        'queued': total_cnt,             # total = mapped + cc (requested behavior)
        'recipient_count': total_cnt,    # alias
        'mapped_count': mapped_cnt,      # mapped-only if UI wants that
        'cc_count': cc_cnt,              # number of non-empty CC prefs
        'recipients': recipients         # actual mapped recipients we queue
    })

@bp.post('/locates/<int:locate_id>/delete', endpoint='locates_delete')
def locates_delete(locate_id: int):
    """
    Hard-delete a locate request by id (used by Supervisor quick list).
    """
    try:
        with sqlite3.connect(DB_FILE) as c:
            c.row_factory = sqlite3.Row
            row = c.execute("SELECT id FROM flight_locates WHERE id=?", (locate_id,)).fetchone()
            if not row:
                return jsonify({'ok': False, 'message': 'Locate not found.'}), 404
            c.execute("DELETE FROM flight_locates WHERE id=?", (locate_id,))
        return jsonify({'ok': True, 'deleted_id': locate_id})
    except Exception:
        return jsonify({'ok': False, 'message': 'Failed to delete locate.'}), 500

@bp.get('/locates', endpoint='locates_index')
def locates_index():
    """
    Unified locates page.
      • If ?tail=… is present → show the map focused on that tail.
      • Otherwise → show the “all locate requests” list.
    """
    tail = (request.args.get('tail') or '').strip().upper()
    if tail:
        return render_template('locates.html', active='supervisor', view='map', tail=tail)

    q = (request.args.get('q') or '').strip().upper()
    where = ""
    params = ()
    if q:
        where = "WHERE UPPER(IFNULL(tail,'')) LIKE ?"
        params = (f"%{q}%",)

    rows = dict_rows(f"""
        SELECT id, tail, requested_at_utc, requested_by,
               latest_sample_ts_utc, latest_from_airport, latest_from_call
          FROM flight_locates
          {where}
         ORDER BY id DESC
         LIMIT 500
    """, params)
    return render_template('locates.html', active='supervisor', view='list', locates=rows, q=q)

@bp.route('/_supervisor_counts')
def supervisor_counts_partial():
    """AJAX partial: counts of inbound, outbound, other, and queued flights.

    Logic:
      - If default_origin is set, treat any flight with airfield_takeoff ∈ aliases(origin) as OUTBOUND,
        any with airfield_landing ∈ aliases(origin) as INBOUND, otherwise OTHER. (complete=0 only)
      - If default_origin is not set, fall back to the existing direction field.
    """
    origin = (get_preference('default_origin') or '').strip().upper()
    inbound_cnt = outbound_cnt = other_cnt = 0

    if origin:
        aliases = set(a.strip().upper() for a in airport_aliases(origin))
        rows = dict_rows("""
            SELECT airfield_takeoff, airfield_landing
              FROM flights
             WHERE complete = 0
        """)
        for r in rows:
            dep = (r.get('airfield_takeoff') or '').strip().upper()
            arr = (r.get('airfield_landing')   or '').strip().upper()
            if dep in aliases and arr in aliases:
                other_cnt += 1
            elif dep in aliases:
                outbound_cnt += 1
            elif arr in aliases:
                inbound_cnt += 1
            else:
                other_cnt += 1
    else:
        inbound_cnt  = dict_rows("SELECT COUNT(*) AS c FROM flights WHERE direction='inbound'  AND complete=0")[0]['c'] or 0
        outbound_cnt = dict_rows("SELECT COUNT(*) AS c FROM flights WHERE direction='outbound' AND complete=0")[0]['c'] or 0
        other_cnt    = dict_rows("SELECT COUNT(*) AS c FROM flights WHERE complete=0 AND IFNULL(direction,'') NOT IN ('inbound','outbound')")[0]['c'] or 0

    queued_cnt = dict_rows("SELECT COUNT(*) AS c FROM queued_flights")[0]['c'] or 0

    return render_template(
        'partials/_supervisor_counts.html',
        inbound=inbound_cnt, outbound=outbound_cnt, other=other_cnt, queued=queued_cnt
    )

@bp.route('/_supervisor_recent_flights')
def supervisor_recent_flights_partial():
    """AJAX partial: table of recent active flights."""
    show_dist = bool(app.extensions.get('distances')) and app.extensions.get('recv_loc') is not None
    unit = request.cookies.get('distance_unit','nm')
    rows = []
    raw_rows = dict_rows("""
        SELECT
          id,
          tail_number,
          airfield_takeoff,
          airfield_landing,
          COALESCE(takeoff_time,'----') AS departure,
          COALESCE(eta,'----') AS arrival,
          cargo_weight,
          flight_code,
          is_ramp_entry,
          sent,
          complete
        FROM flights
        WHERE complete = 0
        ORDER BY id DESC
        LIMIT 6
    """)
    for r in raw_rows:
        # Add NM distance if enabled and available, using same logic as dashboard
        if show_dist:
            entry = app.extensions['distances'].get(r['tail_number'])
            if entry is not None:
                km_val, ts = entry
                if unit=='mi':
                    val = round(km_val * 0.621371, 1)
                elif unit=='nm':
                    val = round(km_val * 0.539957, 1)
                else:
                    val = round(km_val, 1)
                r['distance'] = val
                r['distance_stale'] = (time.time() - ts) > 300
            else:
                r['distance'] = ''
                r['distance_stale'] = False
        else:
            r['distance'] = ''
            r['distance_stale'] = False
        rows.append(r)
    return render_template(
        'partials/_supervisor_recent_flights.html',
        flights=rows,
        enable_1090_distances=show_dist,
        distance_unit=unit
    )

@bp.route('/_supervisor_inventory')
def supervisor_inventory_partial():
    """AJAX partial: slim inventory overview for supervisor."""
    # replicate inventory overview logic (2h window, mass unit)
    cutoff = (datetime.utcnow() - timedelta(hours=2)).isoformat()
    inv = []
    with sqlite3.connect(DB_FILE) as c:
        cats = c.execute("SELECT id, display_name FROM inventory_categories").fetchall()
        for cid, disp in cats:
            ents = c.execute(
                "SELECT direction, total_weight, timestamp FROM inventory_entries WHERE category_id=?",
                (cid,)
            ).fetchall()
            tot_in  = sum(e[1] for e in ents if e[0]=='in')
            tot_out = sum(e[1] for e in ents if e[0]=='out')
            recent  = [e for e in ents if e[2] >= cutoff]
            in2h    = sum(e[1] for e in recent if e[0]=='in')
            out2h   = sum(e[1] for e in recent if e[0]=='out')
            inv.append({
                'category': disp,
                'net':       tot_in - tot_out,
                'rate_in':   round(in2h / 2, 1),
                'rate_out':  round(out2h / 2, 1)
            })
    mass_pref = request.cookies.get('mass_unit','lbs')
    if mass_pref == 'kg':
        for row in inv:
            row['net']      = round(row['net']    / 2.20462, 1)
            row['rate_in']  = round(row['rate_in']/ 2.20462, 1)
            row['rate_out'] = round(row['rate_out']/2.20462, 1)
    return render_template(
        'partials/_supervisor_inventory.html',
        inventory=inv,
        mass_pref=mass_pref
    )
