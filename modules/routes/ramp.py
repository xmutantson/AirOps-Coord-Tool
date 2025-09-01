
from markupsafe import escape
import sqlite3, json, uuid
from datetime import datetime, timedelta
from typing import Optional

# Wargame finish helper — soft import (no-op if unavailable)
try:
    from modules.services.wargame import wargame_finish_ramp_inbound
except Exception:
    def wargame_finish_ramp_inbound(*args, **kwargs):
        return None

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from modules.utils.common import parse_adv_manifest, guess_category_id_for_name, new_manifest_session_id, sanitize_name
from app import publish_inventory_event
from app import DB_FILE
from modules.utils.common import aggregate_manifest_net, flip_session_pending_to_committed
from flask import Blueprint, current_app
from flask import flash, jsonify, redirect, render_template, request, url_for
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

def _compute_fcode_from_form(airfield_takeoff: str, airfield_landing: str, hhmm: str) -> str | None:
    # 1) accept a valid client-provided code as-is
    raw = (request.form.get('flight_code','') or '').strip().upper()
    if raw and FLIGHT_CODE_RE.fullmatch(raw):
        return raw
    # 2) otherwise compute with frozen stamp if provided
    stamp = (request.form.get('code_stamp','') or '').strip()
    try:
        if stamp and len(stamp) == 10 and stamp.isdigit():
            mmddyy, hhmm_ = stamp[:6], stamp[6:]
        else:
            mmddyy, hhmm_ = datetime.utcnow().strftime('%m%d%y'), (hhmm or '').zfill(4)
        ooo = to_three_char_code(airfield_takeoff) or (airfield_takeoff or '')[:3].upper()
        ddd = to_three_char_code(airfield_landing) or (airfield_landing or '')[:3].upper()
        return find_unique_code_or_bump(ooo, mmddyy, ddd, hhmm_)
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────────────────────
# Advanced-Manifest: detection, parsing, and application endpoints
@bp.get('/api/adv_manifest_from_tail/<string:tail>')
def api_adv_manifest_from_tail(tail: str):
    """
    Find the most-recent flight for this tail that has remarks resembling
    Advanced-Manifest lines and return a parsed preview with category guesses.
    """
    tail = (tail or '').strip().upper()
    if not tail:
        return jsonify({'items': [], 'remarks': '', 'categories': []})
    # grab latest remarks for this tail from flights (prefer most recent non-empty)
    row = None
    rows = dict_rows("""
      SELECT remarks
        FROM flights
       WHERE tail_number = ?
         AND IFNULL(remarks,'') <> ''
       ORDER BY timestamp DESC, id DESC
       LIMIT 1
    """, (tail,))
    if rows:
        row = rows[0]
    remarks = row['remarks'] if row else ''
    items = parse_adv_manifest(remarks)
    # build category guesses
    all_cats = dict_rows("SELECT id, display_name FROM inventory_categories ORDER BY display_name")
    # for each item, sanitize name and guess a category id
    out = []
    for it in items:
        sanitized = sanitize_name(it['name'])
        guess = guess_category_id_for_name(sanitized)
        out.append({
            'raw_name': it['name'],
            'sanitized_name': sanitized,
            'size_lb': float(it['size_lb']),
            'qty': int(it['qty']),
            'category_id': guess  # may be None
        })
    return jsonify({
        'remarks': remarks,
        'items': out,
        'categories': [{'id': r['id'], 'display_name': r['display_name']} for r in all_cats]
    })

@bp.post('/api/adv_manifest_parse')
def api_adv_manifest_parse():
    """
    Parse raw remarks text posted by the browser (JSON: {remarks:string})
    and return items with category guesses + category list.
    """
    try:
        data = request.get_json(silent=True) or {}
        remarks = data.get('remarks','') or ''
    except Exception:
        remarks = ''
    items = parse_adv_manifest(remarks)
    all_cats = dict_rows("SELECT id, display_name FROM inventory_categories ORDER BY display_name")
    out = []
    for it in items:
        sanitized = sanitize_name(it['name'])
        guess = guess_category_id_for_name(sanitized)
        out.append({
            'raw_name': it['name'],
            'sanitized_name': sanitized,
            'size_lb': float(it['size_lb']),
            'qty': int(it['qty']),
            'category_id': guess
        })
    return jsonify({
        'remarks': remarks,
        'items': out,
        'categories': [{'id': r['id'], 'display_name': r['display_name']} for r in all_cats]
    })

@bp.get('/api/new_manifest_session')
def api_new_manifest_session():
    """Return a fresh manifest session id for client-side flows."""
    return jsonify({'manifest_id': new_manifest_session_id()})

@bp.post('/api/apply_adv_manifest')
def api_apply_adv_manifest():
    """
    Commit the parsed items into inventory_entries as direction='in', pending=0,
    tagged with a manifest session id (so Ramp inbound can attach them to a flight).
    Body JSON:
      {
        "manifest_id": "hex",
        "items": [
          {"sanitized_name": "beans", "raw_name":"beans", "size_lb":50, "qty":2, "category_id": 3}
        ]
      }
    """
    payload = request.get_json(silent=True) or {}
    mid = (payload.get('manifest_id') or '').strip()
    items = payload.get('items') or []
    if not mid:
        return jsonify({'error':'missing manifest_id'}), 400
    if not items:
        return jsonify({'error':'no items'}), 400
    now = datetime.utcnow().isoformat()
    inserted = 0
    with sqlite3.connect(DB_FILE) as c:
        for it in items:
            try:
                cid  = int(it['category_id'])
                name = sanitize_name(it.get('sanitized_name') or it.get('raw_name') or '')
                raw  = (it.get('raw_name') or name or '').strip()
                wpu  = float(it['size_lb'])
                qty  = int(it['qty'])
                tot  = float(wpu) * int(qty)
            except Exception:
                continue
            if not cid or not name or qty <= 0 or wpu <= 0:
                continue
            c.execute("""
              INSERT INTO inventory_entries(
                category_id, raw_name, sanitized_name,
                weight_per_unit, quantity, total_weight,
                direction, timestamp, pending, session_id, source
              ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
              cid, raw, name,
              wpu, qty, tot,
              'in', now, 0, mid, 'adv-detect'
            ))
            inserted += 1
    try:
        publish_inventory_event()
    except Exception:
        pass
    if inserted == 0:
        return jsonify({'error': 'no valid items inserted'}), 400
    return jsonify({'status':'ok', 'manifest_id': mid, 'inserted': inserted})

@bp.route('/ramp_boss', methods=['GET', 'POST'])
def ramp_boss():
    ensure_column("flights", "is_ramp_entry", "INTEGER DEFAULT 0")

    # pull default_origin from DB (for JS pre-fill)
    drow = dict_rows("SELECT value FROM preferences WHERE name='default_origin'")
    default_origin = drow[0]['value'] if drow else ''

    if request.method == 'POST':
        # ── Validate destination against airports DB ─────────────────────
        dest = request.form.get('destination','').upper().strip()
        if dest:
            rows = dict_rows(
                "SELECT 1 FROM airports "
                " WHERE ident       = ?"
                "    OR icao_code   = ?"
                "    OR iata_code   = ?"
                "    OR local_code  = ?"
                "    OR gps_code    = ?"
                " LIMIT 1",
                (dest,)*5
            )
            if not rows:
                # airport not found → flash a warning but continue
                flash(f'Destination “{dest}” is not in our airport list.', 'warning')

        direction = request.form['direction']
        unit      = request.form['weight_unit']

        # ---------- common field collection ----------
        data = {
            'direction'        : escape(direction),
            'pilot_name'       : escape(request.form.get('pilot_name','').strip()),
            'pax_count'        : escape(request.form.get('pax_count','').strip()),
            'tail_number'      : escape(request.form['tail_number'].strip().upper()),
            'airfield_takeoff' : escape(request.form['origin'].strip().upper()),
            'airfield_landing' : escape(request.form['destination'].strip().upper()),
            'cargo_type'       : escape(request.form['cargo_type'].strip()),
            'cargo_weight'     : escape(norm_weight(request.form['cargo_weight'], unit)),
            'remarks'          : escape(request.form.get('remarks','').strip())
        }

        # ---------- out-bound ----------
        if direction == 'outbound':
            # Capture previous completion state (0/1) if this is an update.
            # We do this BEFORE any UPDATE so we can detect a 0->1 transition later.
            prev_complete = 0
            try:
                fid_form = request.form.get('id')
                if fid_form:
                    row_prev = dict_rows("SELECT complete FROM flights WHERE id=?", (int(fid_form),))
                    if row_prev:
                        prev_complete = int(row_prev[0]['complete'] or 0)
            except Exception:
                # Best-effort only; default to 0 on any parse/lookup failure
                prev_complete = 0

            data['takeoff_time'] = hhmm_norm(request.form['dep_time'])
            data['eta']          = hhmm_norm(request.form['eta'])
            # compute/accept flight code (uses frozen MMDDYY+HHMM if posted)
            data['flight_code']  = _compute_fcode_from_form(
                data['airfield_takeoff'], data['airfield_landing'], data['takeoff_time']
            )

            with sqlite3.connect(DB_FILE) as c:
                c.row_factory = sqlite3.Row
                c.execute("BEGIN IMMEDIATE")
                if data.get('flight_code'):
                    ex = c.execute("SELECT id FROM flights WHERE flight_code=?",
                                   (data['flight_code'],)).fetchone()
                else:
                    ex = None
                if ex:
                    fid    = ex['id']
                    action = 'update_ignored'
                else:
                    fid = c.execute("""
                         INSERT INTO flights(
                           is_ramp_entry,direction,pilot_name,pax_count,tail_number,
                           airfield_takeoff,takeoff_time,airfield_landing,eta,
                           cargo_type,cargo_weight,remarks,flight_code)
                         VALUES (1,:direction,:pilot_name,:pax_count,:tail_number,
                                 :airfield_takeoff,:takeoff_time,:airfield_landing,:eta,
                                 :cargo_type,:cargo_weight,:remarks,:flight_code)
                    """, data).lastrowid
                    # snapshot history atomically with the insert
                    c.execute("""INSERT INTO flight_history(flight_id,timestamp,data)
                                 VALUES (?,?,?)""",
                              (fid, datetime.utcnow().isoformat(), json.dumps(data)))
                    action = 'new'
                c.commit()

                # ── 1. turn the *committed* manifest into flight_cargo rows ──
                mid = request.form.get('manifest_id','')
                if mid and action != 'update_ignored':
                    # Aggregate session rows (pending 0/1): OUT − IN
                    rows = c.execute("""
                      SELECT
                        category_id, sanitized_name, weight_per_unit,
                        SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END) AS net_qty,
                        MAX(timestamp) AS latest_ts
                        FROM inventory_entries
                       WHERE session_id=? AND pending IN (0,1)
                       GROUP BY category_id, sanitized_name, weight_per_unit
                       HAVING net_qty > 0
                    """, (mid,)).fetchall()
                    for r in rows:
                        wpu = float(r['weight_per_unit'])
                        qty = int(r['net_qty'])
                        c.execute("""
                          INSERT INTO flight_cargo(
                            flight_id, session_id, category_id, sanitized_name,
                            weight_per_unit, quantity, total_weight, direction, timestamp
                          ) VALUES (?,?,?,?,?,?,?,'out',?)
                        """, (fid, mid, int(r['category_id']), r['sanitized_name'],
                              wpu, qty, wpu*qty, r['latest_ts']))
                    c.execute("UPDATE inventory_entries SET pending=0 WHERE session_id=? AND pending=1", (mid,))

                # mark this as a NEW insert
                action = action if 'action' in locals() else 'new'

            if action != 'update_ignored':
                # WARGAME: start Radio-outbound SLA (once; until operator marks “sent”)
                wargame_start_radio_outbound(fid)
                # WARGAME: start Ramp-outbound SLA (once; creation time)
                try:
                    wargame_task_start_once('ramp', 'outbound', key=f"flight:{fid}", gen_at=datetime.utcnow().isoformat())
                except Exception:
                    pass

            # If operator just marked this outbound complete, finalize Ramp‑outbound SLA.
            # We detect a 0 -> 1 transition using the pre‑update prev_complete captured above.
            try:
                row_now = dict_rows("SELECT complete FROM flights WHERE id=?", (fid,))
                now_complete = int(row_now[0]['complete'] or 0) if row_now else 0
                if now_complete == 1 and prev_complete == 0:
                    wargame_task_finish('ramp', 'outbound', key=f"flight:{fid}")
            except Exception:
                pass

        # ---------- in-bound ----------
        else:  # direction == 'inbound'
            arrival = hhmm_norm(request.form['dep_time'])   # dep_time field = ARRIVAL HHMM
            data['eta']          = arrival      # store arrival in eta column
            data['takeoff_time'] = ''           # unknown / N/A
            # accept a code typed/pasted by operator (no recompute in inbound)
            fcode = None
            raw = (request.form.get('flight_code','') or '').strip().upper()
            if raw and FLIGHT_CODE_RE.fullmatch(raw):
                fcode = raw

            with sqlite3.connect(DB_FILE) as c:
                c.row_factory = sqlite3.Row
                c.execute("BEGIN IMMEDIATE")

                # try to find the most-recent, still-open outbound leg
                match = c.execute("""
                          SELECT id, eta FROM flights
                          WHERE tail_number=? AND complete=0
                          ORDER BY id DESC LIMIT 1
                         """, (data['tail_number'],)).fetchone()

                if match:
                    # ----- update the existing outbound row -----
                    # -- When UPDATING entries, we have to clear the sent flag
                    # -- and set the flag indicating this update came from the ramp boss
                    c.execute("""
                        UPDATE flights SET
                          eta            = ?,
                          complete       = 1,
                          sent           = 0,
                          is_ramp_entry  = 1,
                          flight_code    = COALESCE(?, flight_code),
                          remarks        = CASE
                                             WHEN LENGTH(remarks)
                                               THEN remarks || ' / Arrived ' || ?
                                             ELSE 'Arrived ' || ?
                                          END
                        WHERE id=?
                    """, (arrival, fcode, arrival, arrival, match['id']))
                    # add history snapshot
                    c.execute("""INSERT INTO flight_history(flight_id,timestamp,data)
                                 VALUES (?,?,?)""",
                              (match['id'], datetime.utcnow().isoformat(),
                               json.dumps({'arrival_update': arrival})))
                    action = 'updated'
                    fid    = match['id']

                    # ── attach any committed Advanced-Cargo manifest ──
                    mid = request.form.get('manifest_id','')
                    if mid:
                        rows = c.execute("""
                          SELECT
                            category_id, sanitized_name, weight_per_unit,
                            SUM(CASE direction WHEN ? THEN quantity ELSE -quantity END) AS net_qty,
                            MAX(timestamp) AS latest_ts
                          FROM inventory_entries
                         WHERE session_id=? AND pending IN (0,1)
                         GROUP BY category_id, sanitized_name, weight_per_unit
                         HAVING net_qty > 0
                        """, ('in', mid)).fetchall()
                        for r in rows:
                            wpu = float(r['weight_per_unit']); qty = int(r['net_qty'])
                            c.execute("""
                              INSERT INTO flight_cargo(
                                flight_id, session_id, category_id, sanitized_name,
                                weight_per_unit, quantity, total_weight,
                                direction, timestamp
                              ) VALUES (?,?,?,?,?,?,?, ?,?)
                            """, (fid, mid, int(r['category_id']), r['sanitized_name'],
                                  wpu, qty, wpu*qty, 'in', r['latest_ts']))
                        c.execute("UPDATE inventory_entries SET pending=0 WHERE session_id=? AND pending=1", (mid,))

                else:
                    # ----- no match → insert a standalone inbound row -----
                    # Duplicate-arrival guard: same tail & arrival time already logged?
                    dup = c.execute("""
                        SELECT id FROM flights
                         WHERE is_ramp_entry=1 AND direction='inbound'
                           AND tail_number=? AND IFNULL(eta,'')=?
                           AND complete=1
                         ORDER BY id DESC LIMIT 1
                    """, (data['tail_number'], arrival)).fetchone()
                    if dup:
                        fid = dup['id']
                        action = 'update_ignored'
                    else:
                        action = 'new'
                        fid = c.execute("""
                            INSERT INTO flights(
                               is_ramp_entry,direction,pilot_name,pax_count,tail_number,
                               airfield_takeoff,takeoff_time,airfield_landing,eta,
                               cargo_type,cargo_weight,remarks,complete,flight_code)
                            VALUES (1,'inbound',:pilot_name,:pax_count,:tail_number,
                                    :airfield_takeoff,'',:airfield_landing,:eta,
                                    :cargo_type,:cargo_weight,:remarks,1,:flight_code)
                        """, data | {'flight_code': fcode}).lastrowid
                        c.execute("""INSERT INTO flight_history(flight_id,timestamp,data)
                                     VALUES (?,?,?)""",
                                  (fid, datetime.utcnow().isoformat(), json.dumps(data)))

                    # ── attach any committed Advanced-Cargo manifest ──
                    mid = request.form.get('manifest_id','')
                    if mid:
                        rows = c.execute("""
                          SELECT
                            category_id, sanitized_name, weight_per_unit,
                            SUM(CASE direction WHEN ? THEN quantity ELSE -quantity END) AS net_qty,
                            MAX(timestamp) AS latest_ts
                          FROM inventory_entries
                         WHERE session_id=? AND pending IN (0,1)
                         GROUP BY category_id, sanitized_name, weight_per_unit
                         HAVING net_qty > 0
                        """, ('in', mid)).fetchall()
                        for r in rows:
                            wpu = float(r['weight_per_unit']); qty = int(r['net_qty'])
                            c.execute("""
                              INSERT INTO flight_cargo(
                                flight_id, session_id, category_id, sanitized_name,
                                weight_per_unit, quantity, total_weight,
                                direction, timestamp
                              ) VALUES (?,?,?,?,?,?,?, ?,?)
                            """, (fid, mid, int(r['category_id']), r['sanitized_name'],
                                  wpu, qty, wpu*qty, 'in', r['latest_ts']))
                        c.execute("UPDATE inventory_entries SET pending=0 WHERE session_id=? AND pending=1", (mid,))

            # Route to Radio outbox only if we actually created/updated something
            if action != 'update_ignored':
                with sqlite3.connect(DB_FILE) as c:
                    c.execute("UPDATE flights SET is_ramp_entry=1, sent=0 WHERE id=?", (fid,))

            # Start Radio "landing notice" SLA once (avoid resetting on later edits)
            pending = dict_rows(
                "SELECT 1 FROM wargame_tasks WHERE role='radio' AND kind='landing' AND key=?",
                (f"flight:{fid}",)
            )
            if action != 'update_ignored' and not pending:
                wargame_task_start(
                    role='radio',
                    kind='landing',
                    key=f"flight:{fid}",
                    gen_at=datetime.utcnow().isoformat()
                )

            # Close Ramp inbound SLA (arrival was handled)
            if action != 'update_ignored':
                wargame_finish_ramp_inbound(fid)

        # ── at this point we have `fid` of the row we inserted/updated ──
        # fetch it back in full
        row = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
        # If this outbound satisfies a Ramp Request, mark it satisfied
        if row.get('direction') == 'outbound':
            try:
                # compute numeric weight (prefer REAL column if present)
                wt = row.get('cargo_weight_real')
                if wt is None:
                    cw = (row.get('cargo_weight') or '').lower()
                    if cw.endswith('lbs'): cw = cw[:-3]
                    if cw.endswith('lb'):  cw = cw[:-2]
                    wt = float(cw.strip() or 0)
                # find oldest open request with same destination and <= weight
                req = dict_rows("""
                  SELECT id, requested_weight, created_at
                    FROM wargame_ramp_requests
                   WHERE satisfied_at IS NULL
                     AND destination = ?
                   ORDER BY created_at ASC
                   LIMIT 1
                """, (row['airfield_landing'],))
                if req and wt >= float(req[0]['requested_weight'] or 0):
                    rid     = req[0]['id']
                    now_iso = datetime.utcnow().isoformat()
                    tail    = row['tail_number']
                    with sqlite3.connect(DB_FILE) as c:
                        c.execute("""
                          UPDATE wargame_ramp_requests
                             SET satisfied_at=?, assigned_tail=?
                           WHERE id=?
                        """, (now_iso, tail, rid))
                        # record the *actual* SLA latency
                        created_dt = datetime.fromisoformat(req[0]['created_at'])
                        delta = (datetime.utcnow() - created_dt).total_seconds()
                        c.execute("""
                          INSERT INTO wargame_metrics(event_type, delta_seconds, recorded_at, key)
                          VALUES ('ramp', ?, ?, ?)
                        """, (delta, now_iso, f"rampreq:{rid}"))
            except Exception:
                pass
        row['action'] = action

        # if this was XHR (our AJAX), return JSON instead of redirect:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(row)

        # otherwise fall back to the old behavior:
        return redirect(url_for('core.dashboard'))

    # build Advanced panel data: preload ALL defined categories, then stock snapshot
    # preload *every* category (for inbound mode)
    cats = dict_rows("""
      SELECT id AS cid, display_name AS cname
        FROM inventory_categories
       ORDER BY display_name
    """)
    advanced_data = {
      "all_categories": [
        {"id": str(c["cid"]), "display_name": c["cname"]}
        for c in cats
      ],
      # will fill in only those with stock
      "stock_categories": [],
      "items": {}, "sizes": {}, "avail": {}
    }
    rows = dict_rows("""
      SELECT e.category_id AS cid,
             c.display_name AS cname,
             e.sanitized_name,
             e.weight_per_unit,
             SUM(
               CASE
                 WHEN e.direction='in'  THEN  e.quantity
                 WHEN e.direction='out' THEN -e.quantity
               END
             ) AS qty
        FROM inventory_entries e
        JOIN inventory_categories c ON c.id=e.category_id
       WHERE e.pending = 0
       GROUP BY e.category_id, e.sanitized_name, e.weight_per_unit
       HAVING qty > 0
    """)
    for r in rows:
        cid = str(r['cid'])
        # availability
        advanced_data["avail"].setdefault(cid, {})\
             .setdefault(r['sanitized_name'], {})[str(r['weight_per_unit'])] = r['qty']
        # items & sizes
        advanced_data["items"].setdefault(cid, [])
        advanced_data["sizes"].setdefault(cid, {})
        if r['sanitized_name'] not in advanced_data["items"][cid]:
            advanced_data["items"][cid].append(r['sanitized_name'])
            advanced_data["sizes"][cid][r['sanitized_name']] = []
        advanced_data["sizes"][cid][r['sanitized_name']].append(str(r['weight_per_unit']))
        # record this category for outbound (stock-only) dropdown
        if not any(c["id"] == cid for c in advanced_data["stock_categories"]):
            advanced_data["stock_categories"].append({
              "id": cid, "display_name": r["cname"]
            })

    # preference: enable/disable auto-scan for inbound arrivals
    scan_pref = get_preference('ramp_scan_adv_manifest') or 'yes'
    return render_template(
      'ramp_boss.html',
      default_origin=default_origin,
      active='ramp_boss',
      advanced_data=advanced_data,
      enable_adv_manifest_scan=(scan_pref == 'yes')
    )

@bp.route('/queue_flight', methods=['POST'])
def queue_flight():
    """Save this RampBoss form as a draft in queued_flights + record its cargo."""
    # --- Collect form inputs ---
    mid               = request.form.get('manifest_id','')
    # Ensure we have a place to persist the manifest id on the draft
    try:
        ensure_column("queued_flights", "manifest_id", "TEXT")
    except Exception:
        pass
    direction         = escape(request.form['direction'])
    pilot_name        = escape(request.form.get('pilot_name','').strip())
    pax_count         = escape(request.form.get('pax_count','').strip())
    tail_number       = escape(request.form['tail_number'].strip().upper())
    airfield_takeoff  = escape(request.form.get('origin','').strip().upper())
    # ── preferred hidden field (added by Ramp-Boss JS) ───────────
    travel_time = request.form.get('travel_time','').strip()
    # weight handling for drafts (keep typed unless manifest exists)
    unit              = request.form.get('weight_unit','lbs')
    typed_cargo_wt    = norm_weight(request.form.get('cargo_weight',''), unit)

    # fallback for older clients that still submit separate HH/MM boxes
    if not travel_time:
        hrs  = request.form.get('travel_h','').zfill(2)
        mins = request.form.get('travel_m','').zfill(2)
        travel_time = escape(f"{hrs}{mins}" if hrs or mins else '')
    airfield_landing  = escape(request.form.get('destination','').strip().upper())
    cargo_type        = escape(request.form.get('cargo_type','').strip())
    remarks           = escape(request.form.get('remarks','').strip())
    created_at        = datetime.utcnow().isoformat()

    # --- Insert into queued_flights ---
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        c.execute("BEGIN IMMEDIATE")
        # NEW: reject identical queue duplicates in a short window (double-click guard)
        try:
            cutoff = (datetime.utcnow() - timedelta(seconds=30)).isoformat()
            qdup = c.execute("""
              SELECT id FROM queued_flights
               WHERE direction=? AND tail_number=?
                 AND airfield_takeoff=? AND airfield_landing=?
                 AND COALESCE(travel_time,'')=? AND COALESCE(cargo_type,'')=?
                 AND COALESCE(remarks,'')=? AND COALESCE(cargo_weight,'')=?  -- guard weight too
                 AND created_at >= ?
               ORDER BY id DESC LIMIT 1
            """, (
              direction, tail_number,
              airfield_takeoff, airfield_landing,
              travel_time, cargo_type, remarks, typed_cargo_wt, cutoff
            )).fetchone()
        except Exception:
            qdup = None
        if qdup:
            qid = qdup['id']
            c.commit()
            flash(f"Duplicate ignored; using draft {qid}.", 'info')
            if request.headers.get('X-Requested-With')=='XMLHttpRequest':
                return jsonify({'status':'queued','qid':qid})
            return redirect(url_for('ramp.queued_flights'))

        cur = c.execute("""
          INSERT INTO queued_flights(
            direction, pilot_name, pax_count, tail_number,
            airfield_takeoff, airfield_landing, travel_time,
            cargo_weight, cargo_type, remarks, created_at
          ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
          direction, pilot_name, pax_count, tail_number,
          airfield_takeoff, airfield_landing, travel_time,
          typed_cargo_wt,
          cargo_type,        remarks,        created_at
        ))
        qid = cur.lastrowid

        # Persist manifest session on the draft for robust future edits/sends
        if mid:
            c.execute("UPDATE queued_flights SET manifest_id=? WHERE id=?", (mid, qid))

        # --- If we have a manifest, copy the net-out quantities in one go ---
        if mid:
            c.execute("DELETE FROM flight_cargo WHERE queued_id=?", (qid,))
            c.execute("""
          INSERT INTO flight_cargo(
            queued_id, session_id, category_id, sanitized_name,
            weight_per_unit, quantity, total_weight,
            direction, timestamp
          )
          SELECT
            ?,                -- queued_id
            session_id,
            category_id,
            sanitized_name,
            weight_per_unit,
            SUM(CASE direction WHEN ? THEN quantity ELSE -quantity END)                                   AS net_qty,
            weight_per_unit * SUM(CASE direction WHEN ? THEN quantity ELSE -quantity END)                 AS net_total,
            ?                       AS direction,
            MAX(timestamp)        AS latest_ts
          FROM inventory_entries
          WHERE session_id = ?
            AND pending     IN (0,1)
          GROUP BY category_id, sanitized_name, weight_per_unit
          HAVING SUM(CASE direction WHEN ? THEN quantity ELSE -quantity END) > 0
       """, (qid,
             ('in' if direction=='inbound' else 'out'),
             ('in' if direction=='inbound' else 'out'),
             ('in' if direction=='inbound' else 'out'),
             mid,
             ('in' if direction=='inbound' else 'out')))

        # IMPORTANT:
        # Stabilize this manifest session so nothing "disappears" if the operator
        # queues immediately after pressing Done. Instead of deleting any leftover
        # pendings (which makes the outs vanish in the ledger on queue), promote
        # them to committed rows. Draft delete already compensates stock, and Send
        # re-merges snapshot+new safely (see fix below).
        try:
            c.execute("""
              UPDATE inventory_entries
                 SET pending    = 0,
                     pending_ts = NULL,
                     source     = COALESCE(source,'') ||
                                  CASE WHEN source IS NULL OR source='' THEN 'queue-commit'
                                       ELSE '+queue-commit' END
               WHERE session_id = ? AND pending = 1
            """, (mid,))
        except Exception:
            pass

        # --- Overwrite draft cargo_weight ONLY if a snapshot exists ---
        nrows = c.execute(
            "SELECT COUNT(*) FROM flight_cargo WHERE queued_id=?",
            (qid,)
        ).fetchone()[0] or 0
        if nrows > 0:
            cw_total = c.execute(
                "SELECT COALESCE(SUM(total_weight),0) FROM flight_cargo WHERE queued_id=?",
                (qid,)
            ).fetchone()[0] or 0.0
            c.execute("UPDATE queued_flights SET cargo_weight=? WHERE id=?",
                      (cw_total, qid))
        # end snapshot

        # --- Canonicalize remarks + cargo_type from snapshot (only if snapshot exists) ---
        if nrows > 0:
            # Preserve operator-entered values from THIS POST unless blank
            posted_remarks = remarks
            posted_type    = cargo_type
            # Build "Manifest: NAME SIZE lbxQTY; …;" from the snapshot rows
            rows = c.execute("""
          SELECT ic.display_name AS cat,
                 fc.sanitized_name AS name,
                 fc.weight_per_unit AS wpu,
                 fc.quantity AS qty
            FROM flight_cargo fc
            JOIN inventory_categories ic ON ic.id = fc.category_id
           WHERE fc.queued_id = ?
           ORDER BY fc.id
            """, (qid,)).fetchall()
            def _fmt_wpu(w):
                try:
                    f = float(w)
                    return str(int(f)) if f.is_integer() else str(f)
                except Exception:
                    return str(w)
            remarks_txt = ("Manifest: " + "; ".join(
                f"{r['name']} {_fmt_wpu(r['wpu'])} lbx{r['qty']}" for r in rows
            ) + ";") if rows else ""
            cats = {r['cat'] for r in rows}
            new_type = (cats.pop() if len(cats) == 1 else 'Mixed') if rows else ''
            # Only overwrite if the operator didn't supply a value
            if not (posted_remarks or '').strip():
                c.execute("UPDATE queued_flights SET remarks=? WHERE id=?",
                          (remarks_txt, qid))
            if not (posted_type or '').strip():
                c.execute("UPDATE queued_flights SET cargo_type=? WHERE id=?",
                          (new_type, qid))

    flash(f"Flight draft {qid} added to queue.", 'info')
    if request.headers.get('X-Requested-With')=='XMLHttpRequest':
        return jsonify({'status':'queued','qid':qid})
    return redirect(url_for('ramp.queued_flights'))

@bp.route('/queued_flights')
def queued_flights():
    # Filters from querystring
    tail_filter = (request.args.get('tail_filter') or '').strip().upper()
    airport_filter = (request.args.get('airport_filter') or '').strip().upper()

    # Normalize comma-separated lists (dedup while preserving order)
    def _csv_list(val: str) -> list[str]:
        seen = set()
        out: list[str] = []
        for tok in (val or '').split(','):
            t = tok.strip().upper()
            if not t or t in seen:
                continue
            seen.add(t)
            out.append(t)
        return out

    tails = _csv_list(tail_filter)
    airports_input = _csv_list(airport_filter)

    # Expand airport tokens via aliases (ident, ICAO, IATA, GPS, local)
    airport_idents: list[str] = []
    if airports_input:
        acc = []
        for code in airports_input:
            try:
                acc.extend(airport_aliases(code))
            except Exception:
                acc.append(code)
        # dedupe while preserving order
        airport_idents = list(dict.fromkeys([a.strip().upper() for a in acc if a and a.strip()]))

    # Build query
    base_sql = """
      SELECT id, direction, tail_number,
             airfield_takeoff, airfield_landing,
             travel_time, cargo_type, remarks, created_at
        FROM queued_flights
       WHERE 1=1
    """
    where = []
    params: list = []
    if tails:
        ph = ",".join(["?"] * len(tails))
        where.append(f"AND tail_number IN ({ph})")
        params.extend(tails)
    if airport_idents:
        ph = ",".join(["?"] * len(airport_idents))
        where.append(f"AND airfield_landing IN ({ph})")
        params.extend(airport_idents)
    sql = " ".join([base_sql, *where, "ORDER BY created_at DESC"])
    rows = dict_rows(sql, tuple(params))

    return render_template(
        'queued_flights.html',
        queued=rows,
        active='queued_flights',
        tail_filter=tail_filter,
        airport_filter=airport_filter
    )

@bp.get('/queued_flights/_table')
def queued_flights_table_partial():
    """Partial table for AJAX refresh (same filters as /queued_flights)."""
    tail_filter = (request.args.get('tail_filter') or '').strip().upper()
    airport_filter = (request.args.get('airport_filter') or '').strip().upper()

    def _csv_list(val: str) -> list[str]:
        seen = set()
        out: list[str] = []
        for tok in (val or '').split(','):
            t = tok.strip().upper()
            if not t or t in seen:
                continue
            seen.add(t)
            out.append(t)
        return out

    tails = _csv_list(tail_filter)
    airports_input = _csv_list(airport_filter)

    airport_idents: list[str] = []
    if airports_input:
        acc = []
        for code in airports_input:
            try:
                acc.extend(airport_aliases(code))
            except Exception:
                acc.append(code)
        airport_idents = list(dict.fromkeys([a.strip().upper() for a in acc if a and a.strip()]))

    base_sql = """
      SELECT id, direction, tail_number,
             airfield_takeoff, airfield_landing,
             travel_time, cargo_type, remarks, created_at
        FROM queued_flights
       WHERE 1=1
    """
    where = []
    params: list = []
    if tails:
        ph = ",".join(["?"] * len(tails))
        where.append(f"AND tail_number IN ({ph})")
        params.extend(tails)
    if airport_idents:
        ph = ",".join(["?"] * len(airport_idents))
        where.append(f"AND airfield_landing IN ({ph})")
        params.extend(airport_idents)
    sql = " ".join([base_sql, *where, "ORDER BY created_at DESC"])
    rows = dict_rows(sql, tuple(params))

    return render_template('partials/_queued_flights_table.html', queued=rows)

@bp.route('/send_queued_flight/<int:qid>', methods=['POST','GET'])
def send_queued_flight(qid):
    # fetch draft
    q = dict_rows("SELECT * FROM queued_flights WHERE id=?", (qid,))

    if not q:
        flash(f"Queue entry {qid} not found.", 'error')
        return redirect(url_for('ramp.queued_flights'))
    q = q[0]

    # ── take-off & ETA come **from the browser** when available ─────────────
    cli_dep = request.form.get("takeoff_time","").strip()
    cli_eta = request.form.get("eta","").strip()

    takeoff = cli_dep if cli_dep else now_hhmm()                 # fall-back: server UTC
    eta     = cli_eta if cli_eta else (
                _add_hhmm(takeoff, q["travel_time"]) if q["travel_time"] else ""
              )

    data = {
      'direction'       : q['direction'],
      'pilot_name'      : q['pilot_name'] or '',
      'pax_count'       : q['pax_count'] or '',
      'tail_number'     : q['tail_number'],
      'airfield_takeoff': q['airfield_takeoff'] or '',
      'airfield_landing': q['airfield_landing'] or '',
      'takeoff_time'    : takeoff,
      'eta'             : eta,
      'cargo_type'      : q['cargo_type'] or '',
      'cargo_weight'    : '0',     # will recompute
      'remarks'         : q['remarks'] or ''
    }
    # compute/accept flight code for the actual sent flight
    flight_code = _compute_fcode_from_form(
        data['airfield_takeoff'], data['airfield_landing'], takeoff
    )

    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        # NEW: one-shot consume of the draft (prevents double-send)
        ensure_column("queued_flights", "consumed", "INTEGER DEFAULT 0")
        c.execute("BEGIN IMMEDIATE")
        touched = c.execute(
            "UPDATE queued_flights SET consumed=1 WHERE id=? AND IFNULL(consumed,0)=0",
            (qid,)
        ).rowcount
        if touched == 0:
            c.commit()
            flash(f"Queue entry {qid} was already sent.", 'info')
            return redirect(url_for('ramp.queued_flights'))
        # NEW: idempotency by flight_code (if same code already created, reuse it)
        fid = None
        if flight_code:
            ex = c.execute("SELECT id FROM flights WHERE flight_code=?",
                           (flight_code,)).fetchone()
            if ex:
                fid = ex['id']
        if not fid:
            fid = c.execute("""
              INSERT INTO flights(
                is_ramp_entry,direction,pilot_name,pax_count,tail_number,
                airfield_takeoff,takeoff_time,airfield_landing,eta,
                cargo_type,cargo_weight,remarks,flight_code
              ) VALUES (1,:direction,:pilot_name,:pax_count,:tail_number,
                        :airfield_takeoff,:takeoff_time,:airfield_landing,:eta,
                        :cargo_type,:cargo_weight,:remarks,:flight_code)
            """, data | {'flight_code': flight_code}).lastrowid

        # ── rebuild the manifest exactly like edit_queued_flight does ──
        mid = (request.form.get('manifest_id','') or '').strip()
        if not mid:
            mid = (q.get('manifest_id') or '').strip()
        if not mid:
            mrow = c.execute("SELECT session_id FROM flight_cargo WHERE queued_id=? ORDER BY id DESC, timestamp DESC LIMIT 1", (qid,)).fetchone()
            if mrow and mrow['session_id']:
                mid = mrow['session_id']
        if mid:
            # 1️⃣ pull the merged state into Python
            row_dir = 'in' if q['direction']=='inbound' else 'out'
            # Only include *newer than snapshot* inventory rows to avoid double-counting
            snap_latest = c.execute(
                "SELECT MAX(timestamp) FROM flight_cargo WHERE queued_id=?",
                (qid,)
            ).fetchone()[0]
            rows = c.execute("""
              SELECT
                category_id,
                sanitized_name,
                weight_per_unit,
                SUM(CASE direction WHEN ? THEN quantity ELSE -quantity END)        AS net_qty,
                SUM(CASE direction WHEN ? THEN total_weight ELSE -total_weight END) AS net_total,
                MAX(timestamp) AS latest_ts
              FROM (
                SELECT category_id, sanitized_name, weight_per_unit,
                       quantity, total_weight, direction, timestamp
                  FROM flight_cargo
                 WHERE queued_id = ?
                UNION ALL
                SELECT category_id, sanitized_name, weight_per_unit,
                       quantity, total_weight, direction, timestamp
                  FROM inventory_entries
                 WHERE session_id = ? AND pending IN (0,1)
                   AND ( ? IS NULL OR timestamp > ? )
              )
              GROUP BY category_id, sanitized_name, weight_per_unit
              HAVING net_qty > 0
            """, (row_dir, row_dir, qid, mid, snap_latest, snap_latest)).fetchall()

            # 2️⃣ delete the old snapshot rows
            c.execute("DELETE FROM flight_cargo WHERE queued_id = ?", (qid,))

            # 3️⃣ re-insert exactly what we just fetched
            for cat, name, wpu, qty, tot, ts in rows:
                c.execute("""
                  INSERT INTO flight_cargo(
                    queued_id, session_id, category_id, sanitized_name,
                    weight_per_unit, quantity, total_weight,
                    direction, timestamp
                  ) VALUES (?,?,?,?,?,?,?,?,?)
                """, (
                  qid, mid,
                  cat, name, wpu,
                  qty, tot,
                  row_dir, ts
                ))

        # now move all associated cargo rows onto this flight
        c.execute("""
          UPDATE flight_cargo
             SET flight_id=?, queued_id=NULL
           WHERE queued_id=?
        """, (fid, qid))

        # ── rebuild cargo_type & remarks from the actual flight_cargo ──
        rows = c.execute("""
          SELECT ic.display_name AS cat,
                 fc.sanitized_name, fc.weight_per_unit AS wpu, fc.quantity
            FROM flight_cargo fc
            JOIN inventory_categories ic
              ON ic.id = fc.category_id
           WHERE fc.flight_id = ?
        """, (fid,)).fetchall()

        # ── now re-calculate cargo_weight for this flight ───────────
        tot = c.execute(
          "SELECT COALESCE(SUM(total_weight),0) "
          "  FROM flight_cargo WHERE flight_id=?",
          (fid,)
        ).fetchone()[0] or 0.0
        # If there is no manifest content, fall back to the draft’s typed cargo weight
        # Parse typed draft weight safely (handles "1200 lbs", "1200 lb", or plain number)
        cw_raw = (q.get('cargo_weight') or '')
        try:
            cw_s = str(cw_raw).lower().strip()
            if cw_s.endswith('lbs'): cw_s = cw_s[:-3]
            if cw_s.endswith('lb'):  cw_s = cw_s[:-2]
            draft_fallback = float(cw_s.strip() or 0.0)
        except Exception:
            draft_fallback = 0.0
        effective_tot  = tot if rows else draft_fallback
        c.execute("""
          UPDATE flights
             SET cargo_weight     = printf('%.0f lbs', ?),
                 cargo_weight_real = ?
           WHERE id=?
        """, (effective_tot, effective_tot, fid))

        # Only set cargo_type / remarks from manifest when queued fields were blank.
        if rows:
            # cargo_type: single category or Mixed
            cats = {r['cat'] for r in rows}
            new_type = cats.pop() if len(cats)==1 else 'Mixed'
            # build a fresh remarks string (drop trailing “.0” on whole numbers)
            def fmt_wpu(w):
                try:
                    f = float(w)
                    return str(int(f)) if f.is_integer() else str(f)
                except:
                    return str(w)
            new_remarks = (
              "Manifest: " + '; '.join(
                f"{r['sanitized_name']} {fmt_wpu(r['wpu'])} lbx{r['quantity']}"
                for r in rows
              ) + ';'
            )
            # Preserve operator-edited values if present.
            if not (q['cargo_type'] or '').strip():
                c.execute("UPDATE flights SET cargo_type=? WHERE id=?", (new_type, fid))
            if not (q['remarks'] or '').strip():
                c.execute("UPDATE flights SET remarks=? WHERE id=?", (new_remarks, fid))

        # Commit all session pendings for this manifest (now that it's sent)
        if mid:
            c.execute("UPDATE inventory_entries SET pending=0 WHERE session_id=? AND pending=1", (mid,))

        # delete the draft record
        c.execute("DELETE FROM queued_flights WHERE id=?", (qid,))

    # Prefer flight_code in success message; fall back to 'TBD' if absent
    try:
        code_row = dict_rows("SELECT flight_code FROM flights WHERE id=?", (fid,))
        code_txt = (code_row[0]['flight_code'] or 'TBD') if code_row else 'TBD'
    except Exception:
        code_txt = 'TBD'
    flash(f"Flight {code_txt} sent.", 'success')
    # Browser fetch() → JSON; classic form-POST → normal redirect
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(
            status   ='sent',
            fid      = fid,
            redirect = url_for('ramp.queued_flights')
        )
    return redirect(url_for('ramp.queued_flights'))

@bp.route('/delete_queued_flight/<int:qid>', methods=['POST','GET'])
def delete_queued_flight(qid):
    # load draft direction
    draft = dict_rows("SELECT direction FROM queued_flights WHERE id=?", (qid,))
    direction = (draft[0]['direction'] if draft else '') or ''

    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        # read the latest snapshot inside the txn
        snap = c.execute("""
            SELECT category_id, sanitized_name, weight_per_unit,
                   quantity, direction, session_id
              FROM flight_cargo
             WHERE queued_id=?
        """, (qid,)).fetchall()

        # Only compensate for OUTBOUND drafts. Inbound drafts are snapshots of inbound
        # receipts already committed by /api/apply_adv_manifest.
        if direction == 'outbound':
            now_iso = datetime.utcnow().isoformat()

            # 1) snapshot net per key (out=+qty, in=-qty)
            base_net = {}      # (cat_id, name_lower, wpu_float) -> net_qty
            name_case = {}     # representative cased name per key
            sess_ids = set()
            for r in snap:
                try:
                    k = (int(r['category_id']),
                         (r['sanitized_name'] or '').strip().lower(),
                         float(r['weight_per_unit']))
                    sgn = 1 if r['direction'] == 'out' else -1
                    base_net[k] = base_net.get(k, 0) + sgn * int(r['quantity'] or 0)
                    if k not in name_case and r['sanitized_name']:
                        name_case[k] = r['sanitized_name']
                    if r['session_id']:
                        sess_ids.add(str(r['session_id']))
                except Exception:
                    continue

            # 2) committed session nets (pending rows intentionally ignored)
            sess_net_by_key = {}         # union-by-key across sessions
            sess_net_by_sid_key = {}     # per session id
            if sess_ids:
                ph = ",".join("?" * len(sess_ids))
                rows = c.execute(f"""
                  SELECT session_id                                   AS sid,
                         category_id                                  AS cat,
                         LOWER(sanitized_name)                         AS key_name,
                         CAST(weight_per_unit AS REAL)                 AS wpu,
                         MIN(sanitized_name)                           AS name_repr,
                         SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END) AS net_qty
                    FROM inventory_entries
                   WHERE session_id IN ({ph}) AND pending=0
                   GROUP BY session_id, category_id, LOWER(sanitized_name), CAST(weight_per_unit AS REAL)
                """, tuple(sess_ids)).fetchall()
                for r in rows:
                    k  = (int(r['cat']), (r['key_name'] or '').strip(), float(r['wpu']))
                    sk = (str(r['sid']),) + k
                    q  = int(r['net_qty'] or 0)
                    sess_net_by_key[k] = sess_net_by_key.get(k, 0) + q
                    sess_net_by_sid_key[sk] = q
                    if k not in name_case and r['name_repr']:
                        name_case[k] = (r['name_repr'] or '').strip()

            # 3) Compensate:
            #    • If a key has session commits → compensate the session net (per session).
            #    • Else (legacy typed rows)     → compensate the snapshot net.
            #    NOTE: we do NOT touch pending rows here; the reaper owns that lifecycle.

            # 3a) baseline-only keys
            for k, q in base_net.items():
                if q == 0 or k in sess_net_by_key:
                    continue
                comp_dir = 'in' if q > 0 else 'out'
                qty = abs(int(q))
                cat_id, key_name, wpu = k
                nm = name_case.get(k, key_name)
                c.execute("""
                  INSERT INTO inventory_entries(
                    category_id, raw_name, sanitized_name,
                    weight_per_unit, quantity, total_weight,
                    direction, timestamp, pending, pending_ts,
                    session_id, source
                  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                  cat_id, nm, nm,
                  wpu, qty, float(wpu) * qty,
                  comp_dir, now_iso, 0, None,
                  None, 'queue-delete/base'
                ))

            # 3b) session-backed keys (per session id)
            for sk, q in sess_net_by_sid_key.items():
                if q == 0:
                    continue
                sid, cat_id, key_name, wpu = sk
                nm = name_case.get((cat_id, key_name, wpu), key_name)
                comp_dir = 'in' if q > 0 else 'out'
                qty = abs(int(q))
                c.execute("""
                  INSERT INTO inventory_entries(
                    category_id, raw_name, sanitized_name,
                    weight_per_unit, quantity, total_weight,
                    direction, timestamp, pending, pending_ts,
                    session_id, source
                  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                  int(cat_id), nm, nm,
                  float(wpu), qty, float(wpu) * qty,
                  comp_dir, now_iso, 0, None,
                  sid, 'queue-delete/sess'
                ))

        # remove cargo and draft
        c.execute("DELETE FROM flight_cargo WHERE queued_id=?", (qid,))
        c.execute("DELETE FROM queued_flights WHERE id=?", (qid,))

    flash(f"Queue entry {qid} deleted and inventory restored.", 'info')
    return redirect(url_for('ramp.queued_flights'))

@bp.route('/api/queued_manifest/<int:qid>')
def api_queued_manifest(qid):
    # If we have a live Advanced manifest open, merge that in:
    mid = request.args.get('manifest_id','').strip()
    # NOTE: rows returned here drive the Edit-Manifest chips (snapshot view)
    if mid:
        # Cut-line: newest timestamp already captured in the queued snapshot
        snap_latest_row = dict_rows(
            "SELECT MAX(timestamp) AS t FROM flight_cargo WHERE queued_id=?",
            (qid,)
        )
        snap_latest = (snap_latest_row[0]['t'] if snap_latest_row else None)
        # Use the DRAFT direction to decide the sign when merging live commits.
        drow = dict_rows("SELECT direction FROM queued_flights WHERE id=?", (qid,))
        row_dir = 'in' if (drow and (drow[0].get('direction') == 'inbound')) else 'out'
        # Build a signed aggregate; return positives as normal and negatives as Δ (reverse) rows.
        rows = dict_rows(f"""
          WITH agg AS (
            SELECT
              x.category_id                       AS cat,
              ic.display_name                     AS category_name,
              x.sanitized_name                    AS sanitized,
              x.weight_per_unit                   AS wpu,
              SUM(x.q_signed)                     AS net_qty,
              SUM(x.t_signed)                     AS net_total
            FROM (
              SELECT category_id, sanitized_name, weight_per_unit,
                     quantity                      AS q_signed,
                     total_weight                  AS t_signed
                FROM flight_cargo
               WHERE queued_id = ?
              UNION ALL
              SELECT category_id, sanitized_name, weight_per_unit,
                     CASE direction WHEN ? THEN quantity ELSE -quantity END      AS q_signed,
                     CASE direction WHEN ? THEN total_weight ELSE -total_weight END AS t_signed
                FROM inventory_entries
               WHERE session_id = ? AND pending = 0
                 AND ( ? IS NULL OR timestamp > ? )   -- ► only newer than snapshot
              UNION ALL
              /* Include current pending edits so chips show immediately after baseline clears */
              SELECT category_id, sanitized_name, weight_per_unit,
                     CASE direction WHEN ? THEN quantity ELSE -quantity END      AS q_signed,
                     CASE direction WHEN ? THEN total_weight ELSE -total_weight END AS t_signed
                FROM inventory_entries
               WHERE session_id = ? AND pending = 1
            ) x
            JOIN inventory_categories ic ON ic.id = x.category_id
            GROUP BY x.category_id, x.sanitized_name, x.weight_per_unit
          )
          SELECT NULL AS entry_id, category_name, sanitized,
                 net_total  AS total, wpu, net_qty AS qty, 0 AS delta
            FROM agg WHERE net_qty > 0
          UNION ALL
          SELECT NULL, category_name, sanitized,
                 ABS(net_total) AS total, wpu, ABS(net_qty) AS qty, 1 AS delta
            FROM agg WHERE net_qty < 0
          ORDER BY category_name, sanitized, wpu
        """, (
          qid,
          row_dir, row_dir, mid, snap_latest, snap_latest,
          row_dir, row_dir, mid
        ))
    else:
        # no live manifest → show only the saved snapshot
        rows = dict_rows("""
          SELECT
            fc.id                  AS entry_id,
            ic.display_name        AS category_name,
            fc.sanitized_name      AS sanitized,
            fc.total_weight        AS total,
            fc.weight_per_unit     AS wpu,
            fc.quantity            AS qty,
            0                      AS delta
          FROM flight_cargo fc
          JOIN inventory_categories ic
            ON ic.id = fc.category_id
          WHERE fc.queued_id = ?
        """, (qid,))
    return jsonify(rows), 200, {'Content-Type':'application/json'}

@bp.route('/edit_queued_flight/<int:qid>', methods=['GET','POST'])
def edit_queued_flight(qid):
    row = dict_rows("SELECT * FROM queued_flights WHERE id=?", (qid,))
    if not row:
        flash("Draft not found","error"); return redirect(url_for('ramp.queued_flights'))
    draft = row[0]

    if request.method=='POST':
        # typed/posted cargo weight (used if no snapshot exists)
        unit = request.form.get('weight_unit','lbs')
        typed_cargo_wt = norm_weight(request.form.get('cargo_weight',''), unit)

        # accept either the new single field or the pair
        travel_time = request.form.get('travel_time','').strip()
        if not travel_time:
            hrs  = request.form.get('travel_h','').zfill(2)
            mins = request.form.get('travel_m','').zfill(2)
            travel_time = f"{hrs}{mins}" if hrs or mins else ''
        with sqlite3.connect(DB_FILE) as c:
            # persist column for manifest id (may be reused if form omits it)
            try:
                ensure_column("queued_flights", "manifest_id", "TEXT")
            except Exception:
                pass

            c.execute("""
              UPDATE queued_flights SET
                direction=?, pilot_name=?, pax_count=?, tail_number=?,
                airfield_takeoff=?, airfield_landing=?, travel_time=?,
                cargo_type=COALESCE(NULLIF(?,''), cargo_type),
                remarks   =COALESCE(NULLIF(?,''), remarks),
                manifest_id=COALESCE(NULLIF(?,''), manifest_id)
              WHERE id=?
            """,(
              request.form['direction'],
              request.form.get('pilot_name','').strip(),
              request.form.get('pax_count','').strip(),
              request.form['tail_number'].strip().upper(),
              request.form.get('origin','').strip().upper(),
              request.form.get('destination','').strip().upper(),
              travel_time,
              request.form.get('cargo_type','').strip(),
              request.form.get('remarks','').strip(),
              (request.form.get('manifest_id','') or '').strip(),
              qid
            ))
            # refresh the snapshot to match the **current** manifest (replace-not-append)
            # recover manifest id if the form didn't send it
            mid   = (request.form.get('manifest_id','') or '').strip()
            if not mid:
                mid = (draft.get('manifest_id') or '').strip()
            if not mid:
                mrow = c.execute("SELECT session_id FROM flight_cargo WHERE queued_id=? ORDER BY id DESC, timestamp DESC LIMIT 1", (qid,)).fetchone()
                if mrow and mrow['session_id']:
                    mid = mrow['session_id']
            rows  = []                       # ← default when no live session
            committed_now = False
            if mid:
                row_dir = 'in' if request.form['direction']=='inbound' else 'out'
                # Only treat this POST as a new commit if the manifest has newer rows
                # than our saved snapshot. This protects operator-edited remarks unless
                # they actually hit "Done" in this edit session.
                inv_latest = c.execute(
                    "SELECT MAX(timestamp) FROM inventory_entries "
                    " WHERE session_id=? AND pending=0", (mid,)
                ).fetchone()[0]
                snap_latest = c.execute(
                    "SELECT MAX(timestamp) FROM flight_cargo WHERE queued_id=?",
                    (qid,)
                ).fetchone()[0]
                committed_now = bool(inv_latest and (not snap_latest or inv_latest > snap_latest))

                # 1️⃣ collect a **combined** view (old snapshot + new edits)
                #    (We will only apply it if committed_now is True.)
                rows = c.execute("""
                  SELECT
                    category_id,
                    sanitized_name,
                    weight_per_unit,
                    SUM(CASE direction WHEN ? THEN quantity ELSE -quantity END)        AS net_qty,
                    SUM(CASE direction WHEN ? THEN total_weight ELSE -total_weight END) AS net_total,
                    MAX(timestamp)                  AS latest_ts
                  FROM (
                    /* previous snapshot rows */
                    SELECT category_id, sanitized_name, weight_per_unit,
                           quantity, total_weight, direction, timestamp
                      FROM flight_cargo
                     WHERE queued_id = ?

                    UNION ALL

                    /* newly-committed edits this session */
                    SELECT category_id, sanitized_name, weight_per_unit,
                           quantity, total_weight, direction, timestamp
                      FROM inventory_entries
                     WHERE session_id = ?
                       AND ( ? IS NULL OR timestamp > ? )   -- ► only deltas since snapshot
                  )
                  GROUP BY category_id, sanitized_name, weight_per_unit
                  HAVING net_qty > 0
                """, (row_dir, row_dir, qid, mid, snap_latest, snap_latest)).fetchall()

            # 2️⃣ Replace snapshot only if a *new* commit happened now
            if mid and committed_now:
                c.execute("DELETE FROM flight_cargo WHERE queued_id=?", (qid,))
                for cat_id, name, wpu, qty, tot, ts in rows:
                    c.execute("""
                      INSERT INTO flight_cargo(
                        queued_id, session_id, category_id, sanitized_name,
                        weight_per_unit, quantity, total_weight,
                        direction, timestamp
                      ) VALUES (?,?,?,?,?,?,?,?,?)
                    """, (
                      qid, mid,
                      cat_id, name, wpu,
                      qty,  tot,
                      row_dir, ts
                    ))
            # ──────────────────────────────────────────────────────────
            #  Re-compute the new total weight for this draft and store
            #  it, so the “Cargo Weight” input is pre-filled next time.
            # ──────────────────────────────────────────────────────────
            nrows = c.execute(
                "SELECT COUNT(*) FROM flight_cargo WHERE queued_id=?",
                (qid,)
            ).fetchone()[0] or 0
            if nrows > 0:
                cw_total = c.execute(
                    "SELECT COALESCE(SUM(total_weight),0) "
                    "  FROM flight_cargo WHERE queued_id=?",
                    (qid,)
                ).fetchone()[0] or 0.0
                c.execute(
                    "UPDATE queued_flights SET cargo_weight=? WHERE id=?",
                    (cw_total, qid)
                )
            else:
                # no snapshot rows → keep the operator's posted value if provided
                if str(typed_cargo_wt or '').strip():
                    c.execute(
                        "UPDATE queued_flights SET cargo_weight=? WHERE id=?",
                        (typed_cargo_wt, qid)
                    )

        # After snapshot refresh, also refresh remarks + cargo_type
        # IMPORTANT: Only overwrite operator-typed remarks/cargo_type if a new
        # commit occurred *this* POST (i.e., user hit "Done" now).
        if mid and committed_now:
            with sqlite3.connect(DB_FILE) as c2:
                c2.row_factory = sqlite3.Row
                rows2 = c2.execute("""
                  SELECT ic.display_name AS cat,
                         fc.sanitized_name AS name,
                         fc.weight_per_unit AS wpu,
                         fc.quantity AS qty
                    FROM flight_cargo fc
                    JOIN inventory_categories ic ON ic.id = fc.category_id
                   WHERE fc.queued_id = ?
                   ORDER BY fc.id
                """, (qid,)).fetchall()
                def _fmt_wpu(w):
                    try:
                        f = float(w);  return str(int(f)) if f.is_integer() else str(f)
                    except Exception:
                        return str(w)
                remarks_txt = ("Manifest: " + "; ".join(
                    f"{r['name']} {_fmt_wpu(r['wpu'])} lbx{r['qty']}" for r in rows2
                ) + ";") if rows2 else ""
                cats = {r['cat'] for r in rows2}
                cargo_type = (cats.pop() if len(cats) == 1 else 'Mixed') if rows2 else ''
                c2.execute(
                    "UPDATE queued_flights SET remarks=?, cargo_type=? WHERE id=?",
                    (remarks_txt, cargo_type, qid))

        else:
            # If no new commit happened but fields are blank and a snapshot exists,
            # opportunistically back-fill remarks/type from the snapshot once.
            try:
                with sqlite3.connect(DB_FILE) as c3:
                    has_rows = c3.execute(
                        "SELECT COUNT(*) FROM flight_cargo WHERE queued_id=?", (qid,)
                    ).fetchone()[0] or 0
                    if has_rows:
                        cur = c3.execute("SELECT remarks, cargo_type FROM queued_flights WHERE id=?", (qid,)).fetchone()
                        if cur and (not (cur['remarks'] or '').strip() or not (cur['cargo_type'] or '').strip()):
                            rows3 = c3.execute("""
                              SELECT ic.display_name AS cat, fc.sanitized_name AS name, fc.weight_per_unit AS wpu, fc.quantity AS qty
                                FROM flight_cargo fc JOIN inventory_categories ic ON ic.id=fc.category_id
                               WHERE fc.queued_id=? ORDER BY fc.id
                            """, (qid,)).fetchall()
                            if rows3:
                                cats = {r['cat'] for r in rows3}
                                new_type = cats.pop() if len(cats)==1 else 'Mixed'
                                def _fmt(w): 
                                    try: f=float(w); return str(int(f)) if f.is_integer() else str(f)
                                    except: return str(w)
                                new_rm = "Manifest: " + "; ".join(f"{r['name']} {_fmt(r['wpu'])} lbx{r['qty']}" for r in rows3) + ";"
                                if not (cur['cargo_type'] or '').strip():
                                    c3.execute("UPDATE queued_flights SET cargo_type=? WHERE id=?", (new_type, qid))
                                if not (cur['remarks'] or '').strip():
                                    c3.execute("UPDATE queued_flights SET remarks=? WHERE id=?", (new_rm, qid))

            except Exception:
                # Best-effort back-fill; ignore any lookup/DB hiccups here.
                pass

        flash("Draft updated","success")
        # ── XHR requests expect JSON so the front-end can redirect itself ──
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(
              status='saved',
              redirect=url_for('ramp.queued_flights')
            )
        return redirect(url_for('ramp.queued_flights'))

    # GET → render Ramp-Boss with a ‘draft’ object for pre-fill
    return render_template('ramp_boss.html',
                           draft=draft,
                           active='ramp_boss',
                           advanced_data={})   # chips fetched by JS as usual

@bp.route('/edit_flight/<int:fid>', methods=['GET','POST'])
def edit_flight(fid):
    if request.method=='POST':
        # sanitize all editable fields
        fields=['direction','pilot_name','pax_count','airfield_takeoff',
                'takeoff_time','airfield_landing','eta','cargo_type',
                'cargo_weight','remarks']
        data={f: escape(request.form.get(f,'').strip()) for f in fields}
        data['airfield_takeoff']=data['airfield_takeoff'].strip().upper()
        data['airfield_landing']=data['airfield_landing'].strip().upper()
        data['takeoff_time']=hhmm_norm(data['takeoff_time'])
        data['eta']=hhmm_norm(data['eta'])
        data['complete']=1 if request.form.get('complete')=='on' else 0
        data['id']=fid
        with sqlite3.connect(DB_FILE) as c:
            before=dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
            c.execute("INSERT INTO flight_history(flight_id,timestamp,data) VALUES (?,?,?)",
                      (fid, datetime.utcnow().isoformat(), json.dumps(before)))
            set_clause=", ".join([f"{k}=:{k}" for k in data if k!='id'])
            c.execute(f"UPDATE flights SET {set_clause} WHERE id=:id", data)
        return redirect(url_for('core.dashboard'))
    flight=dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
    return render_template('edit_flight.html', flight=flight)

@bp.post('/delete_flight/<int:fid>')
def delete_flight(fid):
    """Delete a flight *and* apply compensating inventory lines."""
    # Grab the code before deleting so our flash references the code, not the id
    try:
        code_row = dict_rows("SELECT flight_code FROM flights WHERE id=?", (fid,))
        code_txt = (code_row[0]['flight_code'] or 'TBD') if code_row else 'TBD'
    except Exception:
        code_txt = 'TBD'

    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        rows = c.execute(
          "SELECT * FROM flight_cargo WHERE flight_id=?", (fid,)
        ).fetchall()
        for r in rows:
            rev = 'in' if r['direction']=='out' else 'out'
            c.execute("""
              INSERT INTO inventory_entries(
                category_id, raw_name, sanitized_name,
                weight_per_unit, quantity, total_weight,
                direction, timestamp, source
              ) VALUES (?,?,?,?,?,?,?,?,?)
            """, (
              r['category_id'], r['sanitized_name'], r['sanitized_name'],
              r['weight_per_unit'], r['quantity'], r['total_weight'],
              rev, datetime.utcnow().isoformat(), 'flight-delete'
            ))
        c.execute("DELETE FROM flight_cargo WHERE flight_id=?", (fid,))
        c.execute("DELETE FROM flights WHERE id=?", (fid,))
    flash(f"Flight {code_txt} deleted and inventory restored.")
    return redirect(url_for('core.dashboard'))

@bp.post('/delete_flight_cargo/<int:fcid>')
def delete_flight_cargo(fcid):
    """❌-button in the queued-flight editor.
       Snapshot rows are deleted immediately so the chip disappears.
       Only create a compensator when the source row is a committed
       inventory_entries row; if the effect exists only as *pending* in
       this session, edit/delete that pending row instead. """
    # Current Adv session; if the client didn't send it, fall back to the row's session_id.
    sid = (request.form.get('manifest_id','') or '').strip()
    now = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row

        # A chip can reference either:
        #   • the saved snapshot row in flight_cargo      (legacy)
        #   • a committed inventory_entries row created   (new)
        #     during this Advanced-panel session.
        #
        r = c.execute("SELECT * FROM flight_cargo WHERE id=?", (fcid,)).fetchone()
        src_table = 'flight_cargo'

        if not r:                     # not a snapshot row → try inventory_entries
            r = c.execute("""
                  SELECT *
                    FROM inventory_entries
                   WHERE id = ? AND pending = 0
            """, (fcid,)).fetchone()
            src_table = 'inventory_entries'

        if not r:                     # nothing found anywhere → 404
            return jsonify(status='not_found'), 404

        # If no session was provided, adopt the row's session (present on both tables).
        try:
            if not sid:
                sid = (r['session_id'] or '')
        except Exception:
            sid = sid or ''

        # If this key exists in the session as *pending* in the same direction,
        # decrement/delete that pending row (availability was never reduced).
        same_dir = r['direction']
        # First preference: if effect exists only as *pending*, just reduce that.
        pen = c.execute("""
          SELECT id, quantity
            FROM inventory_entries
           WHERE session_id=? AND category_id=? AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
             AND direction=? AND pending=1
           LIMIT 1
        """, (sid, r['category_id'], r['sanitized_name'], r['weight_per_unit'], same_dir)).fetchone()

        comp_id = None
        if pen:
            new_q = max(0, int(pen['quantity']) - int(r['quantity']))
            if new_q <= 0:
                c.execute("DELETE FROM inventory_entries WHERE id=?", (pen['id'],))
            else:
                c.execute("""
                  UPDATE inventory_entries
                     SET quantity=?, total_weight=?*?, timestamp=?, source='chip-delete'
                   WHERE id=?
                """, (new_q, float(r['weight_per_unit']), new_q, now, pen['id']))

        elif src_table == 'inventory_entries':
            # No pending to undo → compensate the committed *source* row only.
            rev = 'in' if r['direction'] == 'out' else 'out'
            # Keep the original session on the compensator if the source row had one
            try:
                sid_for_comp = r['session_id'] or None
            except Exception:
                sid_for_comp = None
            cur = c.execute("""
              INSERT INTO inventory_entries(
                category_id, raw_name, sanitized_name,
                weight_per_unit, quantity, total_weight,
                direction, timestamp, pending, pending_ts,
                session_id, source
              ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
              r['category_id'], r['sanitized_name'], r['sanitized_name'],
              r['weight_per_unit'], r['quantity'],
              float(r['weight_per_unit']) * int(r['quantity']),
              rev, now,
              0,  None, sid_for_comp, 'chip-delete'
            ))
            comp_id = cur.lastrowid

        if src_table == 'flight_cargo':
            # Delete the snapshot row so the baseline disappears immediately.
            c.execute("DELETE FROM flight_cargo WHERE id=?", (fcid,))

            # Also purge any *pending* rows for this key in this session to avoid mixing.
            c.execute("""
                DELETE FROM inventory_entries
                 WHERE session_id=? AND category_id=? AND LOWER(sanitized_name)=LOWER(?)
                   AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                   AND pending=1
            """, (sid, r['category_id'], r['sanitized_name'], r['weight_per_unit']))

            # Compute the TOTAL committed session net for this key and cancel it in-session.
            row_sess_total = c.execute("""
                SELECT COALESCE(SUM(CASE direction
                                     WHEN 'out' THEN quantity
                                     ELSE -quantity END),0) AS net_qty
                  FROM inventory_entries
                 WHERE session_id=? AND category_id=? AND LOWER(sanitized_name)=LOWER(?)
                   AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                   AND pending=0
            """, (sid, r['category_id'], r['sanitized_name'], r['weight_per_unit'])).fetchone()
            sess_total = int(row_sess_total['net_qty'] or 0)
            if sess_total != 0:
                comp_dir = 'in' if sess_total > 0 else 'out'
                qty      = abs(sess_total)
                cur = c.execute("""
                  INSERT INTO inventory_entries(
                    category_id, raw_name, sanitized_name,
                    weight_per_unit, quantity, total_weight,
                    direction, timestamp, pending, pending_ts,
                    session_id, source
                  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                  r['category_id'], r['sanitized_name'], r['sanitized_name'],
                  r['weight_per_unit'], qty, float(r['weight_per_unit'])*qty,
                  comp_dir, now, 0, None, sid or None, 'chip-delete/sess-total'
                ))
                comp_id = cur.lastrowid
        else:
            # For inventory_entries source: we already inserted a compensator above.
            # Do NOT also flip the original to pending (avoids over-credit).
            pass

    return jsonify(status='ok', comp_id=comp_id)

# ──────────────────────────────────────────────────────────────────────────
# Helpers for manifest math (server-side “gate” / preview and effective qty)
# ──────────────────────────────────────────────────────────────────────────
def _row_dir_for_session(c, session_id: str, draft_id: Optional[int], flight_id: Optional[int]) -> str:
    """Return 'out' (default) or 'in' based on the snapshot tied to this session."""
    row = c.execute("""
        SELECT direction FROM flight_cargo
         WHERE (
                session_id = ? OR
                (queued_id = ? AND ? IS NOT NULL) OR
                (flight_id = ? AND ? IS NOT NULL)
               )
           AND (queued_id IS NOT NULL OR flight_id IS NOT NULL)
         ORDER BY id DESC LIMIT 1
    """, (session_id, draft_id, draft_id, flight_id, flight_id)).fetchone()
    return (row['direction'] if row and row['direction'] in ('in','out') else 'out')

def _effective_for_key(c, session_id: str, name: str, wpu: float,
                       draft_id: Optional[int], flight_id: Optional[int]) -> tuple[int,int,int,str,Optional[str]]:
    """
    Compute (effective, snap_qty, comm_net, row_dir, snap_latest_ts)
    effective = snapshot qty (queued/flight rows tied to this session) + committed deltas since that snapshot,
                signed in the snapshot's row_dir ('out' => outs positive, ins negative; inverse for inbound).
    """
    row_dir = _row_dir_for_session(c, session_id, draft_id, flight_id)
    snap_latest_row = c.execute("""
        SELECT MAX(timestamp) AS t FROM flight_cargo
         WHERE ( session_id = ? OR
                 (queued_id = ? AND ? IS NOT NULL) OR
                 (flight_id = ? AND ? IS NOT NULL) )
    """, (session_id, draft_id, draft_id, flight_id, flight_id)).fetchone()
    snap_latest = (snap_latest_row['t'] if snap_latest_row else None)

    snap_qty = c.execute("""
        SELECT COALESCE(SUM(quantity),0) AS q
          FROM flight_cargo
         WHERE LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
           AND ( session_id = ? OR
                 (queued_id = ? AND ? IS NOT NULL) OR
                 (flight_id = ? AND ? IS NOT NULL) )
    """, (name, wpu, session_id, draft_id, draft_id, flight_id, flight_id)).fetchone()['q'] or 0

    comm_net = c.execute("""
        SELECT COALESCE(SUM(CASE direction WHEN ? THEN quantity ELSE -quantity END),0) AS net_q
          FROM inventory_entries
         WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?)
           AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
           AND pending=0
           AND (? IS NULL OR timestamp > ?)
    """, (row_dir, session_id, name, wpu, snap_latest, snap_latest)).fetchone()['net_q'] or 0

    effective = int(snap_qty) + int(comm_net)
    return int(effective), int(snap_qty), int(comm_net), row_dir, snap_latest

def _stock_avail_for_key(c, name: str, wpu: float) -> int:
    """
    Return committed stock availability for (name,wpu) across the warehouse
    (pending rows do not affect stock).
    """
    row = c.execute("""
        SELECT COALESCE(SUM(CASE direction WHEN 'in' THEN quantity ELSE -quantity END),0) AS avail
          FROM inventory_entries
         WHERE pending=0
           AND LOWER(sanitized_name)=LOWER(?)
           AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
    """, (name, wpu)).fetchone()
    return int(row['avail'] or 0)

# ──────────────────────────────────────────────────────────────────────────
# NEW: Server-side scan “gate”/preview to avoid client double-counting
#      POST /api/manifest/<mid>/gate  { name, weight_per_unit, qty?:1, op?:'add'|'remove',
#                                       draft_id?:int|null, flight_id?:int|null }
# ──────────────────────────────────────────────────────────────────────────
@bp.post('/api/manifest/<manifest_id>/gate')
def api_manifest_gate(manifest_id: str):
    data = request.get_json(silent=True) or {}
    name = (data.get('sanitized_name') or data.get('name') or '').strip()
    try: wpu = float(data.get('weight_per_unit'))
    except Exception: return jsonify(error='missing weight'), 400
    qty = max(1, int(data.get('qty', 1) or 1))
    op  = (data.get('op') or 'add').strip().lower()
    draft_id  = data.get('draft_id', None)
    flight_id = data.get('flight_id', None)
    if not name or wpu <= 0:
        return jsonify(error='missing name/weight'), 400
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        eff, snap_q, comm_net, row_dir, _ = _effective_for_key(c, manifest_id, name, wpu, draft_id, flight_id)
        # Chip value shown to operator BEFORE this tick:
        before_chip = eff
        # “Add” means apply in row_dir; “remove” means apply reverse of row_dir
        sign = 1 if (op == 'add') else -1
        # In outbound (row_dir='out'), +1 add reduces stock; in inbound, +1 add increases stock.
        avail_before = _stock_avail_for_key(c, name, wpu)
        after_chip   = before_chip + (sign if row_dir=='out' else -sign)
        # Remaining stock if we were to commit this tick now.
        # Use session-pending OUTS (not committed baseline) to avoid double-subtraction.
        sess_pend_out = c.execute("""
            SELECT COALESCE(SUM(quantity),0) AS q
              FROM inventory_entries
             WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?)
               AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
               AND direction='out' AND pending=1
        """, (manifest_id, name, wpu)).fetchone()['q'] or 0
        # Apply the tick’s effect only for outbound (shipping) preview.
        tick = 0
        if row_dir == 'out':
            tick = (1 if op == 'add' else -1)
        remaining = max(0, int(avail_before) - int(sess_pend_out) - tick)
        return jsonify(
            ok=True,
            sanitized_name=name, weight_per_unit=float(wpu),
            row_dir=row_dir, op=op, qty=1,
            beforeQty=before_chip, afterQty=after_chip, delta=after_chip-before_chip,
            availSnapshot=avail_before, remaining=max(0, remaining)
        ), 200, {'Content-Type':'application/json'}

# ──────────────────────────────────────────────────────────────────────────
# NEW: Adopt a queued draft snapshot into a manifest session so that
#      nudge/remove math can "see" the baseline under that session.
#      POST /api/manifest/<mid>/adopt_snapshot  { draft_id:int }
# ──────────────────────────────────────────────────────────────────────────
@bp.post('/api/manifest/<manifest_id>/adopt_snapshot')
def api_manifest_adopt_snapshot(manifest_id: str):
    try:
        data = request.get_json(silent=True) or {}
        draft_id = int(data.get('draft_id') or 0)
    except Exception:
        return jsonify(error='invalid payload'), 400
    if not draft_id:
        return jsonify(error='missing draft_id'), 400
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        # Only adopt snapshot rows that don't already belong to some session
        c.execute("""
          UPDATE flight_cargo
             SET session_id=?
           WHERE queued_id=? AND IFNULL(session_id,'')=''
        """, (manifest_id, draft_id))
    return jsonify(ok=True)

# ──────────────────────────────────────────────────────────────────────────
# NEW: Delete-by-key for manifest session chips (scanned or manual).
#      Nukes the entire (sanitized_name, weight_per_unit) line by inserting
#      a compensator only for the *committed* portion, and deleting any
#      pending rows so we never mix "delete + compensate".
#
#  POST /api/manifest/<manifest_id>/delete_key
#   body JSON: { "sanitized_name": "...", "weight_per_unit": <number> }
#
#  Returns: { ok:true, comp_id:int|null, comp_dir:"in"|"out"|null, qty:int }
# ──────────────────────────────────────────────────────────────────────────
@bp.post('/api/manifest/<manifest_id>/delete_key')
def api_manifest_delete_key(manifest_id: str):
    try:
        data = request.get_json(silent=True) or {}
        name = (data.get('sanitized_name') or '').strip()
        wpu  = float(data.get('weight_per_unit'))
        # Optional hints so we can include baseline snapshot nets in compensation
        draft_id  = data.get('draft_id', None)    # queued draft baseline
        flight_id = data.get('flight_id', None)   # flight baseline
        prefer_comp = bool(data.get('prefer_compensate', False))
    except Exception:
        return jsonify(error='invalid payload'), 400
    if not name or wpu <= 0:
        return jsonify(error='missing name/weight'), 400

    now = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        # 1) Compute pending & committed nets for THIS session/key.
        row_p = c.execute("""
            SELECT COALESCE(SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END),0) AS net_qty
              FROM inventory_entries
             WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
               AND pending=1
        """, (manifest_id, name, wpu)).fetchone()
        net_p = int(row_p['net_qty'] or 0)

        row_c = c.execute("""
            SELECT COALESCE(SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END),0) AS net_qty
              FROM inventory_entries
             WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
               AND pending=0
        """, (manifest_id, name, wpu)).fetchone()
        net_c = int(row_c['net_qty'] or 0)

        pending_committed = 0
        if prefer_comp and net_p != 0 and not draft_id and not flight_id:
            # Only promote pendings when there is no snapshot baseline involved.
            # (i.e., live build with no queued/flight baseline). For queued edits,
            # we keep baseline and pendings separate to avoid double-comp.
            c.execute("""
                UPDATE inventory_entries
                   SET pending=0, pending_ts=NULL,
                       source=COALESCE(source,'') ||
                              CASE WHEN source IS NULL OR source='' THEN 'delete-key-commit'
                                   ELSE '+delete-key-commit' END
                 WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                   AND pending=1
            """, (manifest_id, name, wpu))
            pending_committed = abs(net_p)
            net_p = 0
            row_c = c.execute("""
                SELECT COALESCE(SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END),0) AS net_qty
                  FROM inventory_entries
                 WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                   AND pending=0
            """, (manifest_id, name, wpu)).fetchone()
            net_c = int(row_c['net_qty'] or 0)
        else:
            # Default behavior: drop pending rows (no DB-side effect on stock).
            c.execute("""
                DELETE FROM inventory_entries
                 WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                   AND pending=1
            """, (manifest_id, name, wpu))

        # 2) Determine any snapshot baselines tied to this session if ids weren't provided.
        qids, fids = [], []
        if draft_id is not None:
            qids = [int(draft_id)]
        if flight_id is not None:
            fids = [int(flight_id)]
        if not qids or not fids:
            rows_ids = c.execute("""
              SELECT DISTINCT queued_id, flight_id
                FROM flight_cargo
               WHERE session_id=? AND (queued_id IS NOT NULL OR flight_id IS NOT NULL)
            """, (manifest_id,)).fetchall()
            if not qids:
                qids = [int(r['queued_id']) for r in rows_ids if r['queued_id'] is not None]
            if not fids:
                fids = [int(r['flight_id']) for r in rows_ids if r['flight_id'] is not None]

        # ► Compute baseline net BEFORE deleting snapshot rows, so we can fall back
        #   to compensating the baseline when there is no session net yet.
        base_qty = 0
        base_dir = None
        try:
            unions = []
            args   = []
            if qids:
                phq = ",".join("?" * len(qids))
                unions.append(f"""
                  SELECT direction, SUM(quantity) AS qty
                    FROM flight_cargo
                   WHERE queued_id IN ({phq})
                     AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                """)
                args += [*qids, name, wpu]
            if fids:
                phf = ",".join("?" * len(fids))
                unions.append(f"""
                  SELECT direction, SUM(quantity) AS qty
                    FROM flight_cargo
                   WHERE flight_id IN ({phf})
                     AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                """)
                args += [*fids, name, wpu]
            if unions:
                rowb = c.execute("SELECT MAX(direction) AS dir, SUM(qty) AS qty FROM (" + " UNION ALL ".join(unions) + ")", tuple(args)).fetchone()
                base_qty = int(rowb['qty'] or 0) if rowb else 0; base_dir = (rowb['dir'] or None) if rowb else None
        except Exception:
            base_qty = 0; base_dir = None

        # 3) Physically remove the snapshot baseline rows so the line disappears in the UI.
        if qids:
            ph = ",".join("?" * len(qids))
            c.execute(f"""
                DELETE FROM flight_cargo
                 WHERE queued_id IN ({ph})
                   AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
            """, (*qids, name, wpu))
        if fids:
            ph = ",".join("?" * len(fids))
            c.execute(f"""
                DELETE FROM flight_cargo
                 WHERE flight_id IN ({ph})
                   AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
            """, (*fids, name, wpu))

        # 4) Compute the TOTAL committed net for this session/key (ignore cut-lines).
        row_sess_total = c.execute("""
            SELECT COALESCE(SUM(CASE direction
                                 WHEN 'out' THEN quantity
                                 ELSE -quantity END),0) AS net_qty
              FROM inventory_entries
             WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
               AND pending=0
        """, (manifest_id, name, wpu)).fetchone()
        sess_total = int(row_sess_total['net_qty'] or 0)

        # 5) If session net is zero, fall back to compensating the snapshot baseline (if any).
        if sess_total == 0:
            if base_qty and base_dir in ('in','out'):
                comp_dir = 'in' if base_dir == 'out' else 'out'
                # choose category_id: prefer latest session row; else any historical row; else 1
                latest = c.execute("""
                    SELECT category_id FROM inventory_entries
                     WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?)
                       AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                     ORDER BY timestamp DESC, id DESC LIMIT 1
                """, (manifest_id, name, wpu)).fetchone()
                cat_id = int(latest['category_id']) if latest and latest['category_id'] is not None else None
                if cat_id is None:
                    # Prefer category from a related snapshot (same session OR the known draft/flight),
                    # else fall back to any historical entry.
                    any_row = c.execute("""
                      SELECT category_id
                        FROM flight_cargo
                       WHERE LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                         AND (
                               session_id = ?
                            OR (? IS NOT NULL AND queued_id = ?)
                            OR (? IS NOT NULL AND flight_id = ?)
                         )
                       ORDER BY id DESC LIMIT 1
                    """, (name, wpu, manifest_id, draft_id, draft_id, flight_id, flight_id)).fetchone()
                    if any_row and any_row['category_id'] is not None:
                        cat_id = int(any_row['category_id'])
                    if cat_id is None:
                        any_hist = c.execute("""
                          SELECT category_id FROM inventory_entries
                           WHERE LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                           ORDER BY timestamp DESC, id DESC LIMIT 1
                        """, (name, wpu)).fetchone()
                        cat_id = int(any_hist['category_id']) if any_hist and any_hist['category_id'] is not None else 1
                cur = c.execute("""
                  INSERT INTO inventory_entries(category_id,raw_name,sanitized_name,weight_per_unit,quantity,total_weight,direction,timestamp,pending,pending_ts,session_id,source)
                  VALUES (?,?,?,?,?,?,?, ?,0,NULL,?, 'chip-delete/base-fallback')
                """, (cat_id, name, name, wpu, base_qty, float(wpu)*base_qty, comp_dir, now, manifest_id))
                comp_id = cur.lastrowid
                return jsonify(ok=True, comp_id=comp_id, comp_dir=comp_dir, qty=base_qty, pending_committed=pending_committed), 200, {'Content-Type':'application/json'}
            return jsonify(ok=True, comp_id=None, comp_dir=None, qty=0, pending_committed=pending_committed)

        # 6) Choose category_id: prefer most-recent session row; else any historical row; else 1.
        latest = c.execute("""
            SELECT category_id FROM inventory_entries
             WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
               AND pending=0
             ORDER BY timestamp DESC, id DESC
             LIMIT 1
        """, (manifest_id, name, wpu)).fetchone()
        cat_id = int(latest['category_id']) if latest and latest['category_id'] is not None else None
        if cat_id is None:
            # Prefer from related snapshot (session/queued/flight); else historical inventory entry
            any_row = c.execute("""
                SELECT category_id
                  FROM flight_cargo
                 WHERE LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                   AND (
                         session_id = ?
                      OR (? IS NOT NULL AND queued_id = ?)
                      OR (? IS NOT NULL AND flight_id = ?)
                   )
                 ORDER BY id DESC LIMIT 1
            """, (name, wpu, manifest_id, draft_id, draft_id, flight_id, flight_id)).fetchone()
            if any_row and any_row['category_id'] is not None:
                cat_id = int(any_row['category_id'])
            else:
                any_hist = c.execute("""
                    SELECT category_id FROM inventory_entries
                     WHERE LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                     ORDER BY timestamp DESC, id DESC
                     LIMIT 1
                """, (name, wpu)).fetchone()
                cat_id = int(any_hist['category_id']) if any_hist and any_hist['category_id'] is not None else 1

        # 7) Single compensator inside the session to zero its net and fix stock in one move.
        comp_dir = 'in' if sess_total > 0 else 'out'
        qty      = abs(sess_total)
        cur = c.execute("""
          INSERT INTO inventory_entries(
            category_id, raw_name, sanitized_name,
            weight_per_unit, quantity, total_weight,
            direction, timestamp, pending, pending_ts,
            session_id, source
          ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
          cat_id, name, name,
          wpu, qty, float(wpu) * qty,
          comp_dir, now, 0, None,
          manifest_id, 'chip-delete-all/sess-total'
        ))
        comp_id = cur.lastrowid

    # Report concise summary back to the client (session-only cancel).
    return jsonify(ok=True, comp_id=comp_id, comp_dir=comp_dir,
                   qty=qty, parts=[{'scope':'session','comp_dir':comp_dir,'qty':qty}],
                   pending_committed=pending_committed), 200, {'Content-Type':'application/json'}

@bp.post('/api/manifest/<manifest_id>/nudge')
def api_manifest_nudge(manifest_id: str):
    """
    Scanner-friendly adjuster used by the FE for 'Remove' ticks in Edit-Manifest.
    Supports going below the baseline by spawning committed reverse rows.
    Adjust the effective quantity of a (sanitized_name, weight_per_unit) key in a manifest session by ±qty.
    Behavior:
      • Remove eats PENDING rows first (no stock effect),
      • Cancel committed baseline up to the current effective,
      • Any overage (beyond baseline) creates a committed reverse row (i.e., below-baseline delta).
      JSON: { sanitized_name:str, weight_per_unit:number, qty?:int=1, op?:'remove'|'add'='remove',
              draft_id?:int|null, flight_id?:int|null }
    """
    try:
        data = request.get_json(silent=True) or {}
        # accept either sanitized_name or name
        name = (data.get('sanitized_name') or data.get('name') or '').strip()
        # weight may be absent in barcode-only payloads
        wpu_raw = data.get('weight_per_unit')
        wpu  = float(wpu_raw) if wpu_raw is not None else 0.0
        req_qty = max(1, int(data.get('qty', 1) or 1))
        # accept either 'op' or legacy 'mode'
        op   = (data.get('op') or data.get('mode') or 'remove').strip().lower()
        draft_id  = data.get('draft_id', None)
        flight_id = data.get('flight_id', None)
    except Exception:
        return jsonify(error='invalid payload'), 400

    # NEW: barcode-only bodies → resolve to (name,wpu)
    barcode = (data.get('barcode') or '').strip()
    if barcode and (not name or wpu <= 0):
        from modules.utils.common import lookup_barcode
        it = lookup_barcode(barcode)
        if not it:
            return jsonify(error='unknown_barcode', code='UNKNOWN_BARCODE'), 404
        name = it['sanitized_name']
        wpu  = float(it['weight_per_unit'])

    if not name or wpu <= 0:
        return jsonify(error='missing name/weight'), 400

    now = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row

        mid = manifest_id
        # Compute BEFORE state once (effective + availability) for the response payload
        effective, snap_qty, comm_net, row_dir, snap_latest = _effective_for_key(
            c, mid, name, wpu, draft_id, flight_id
        )
        avail_before = _stock_avail_for_key(c, name, wpu)
        effective_before = int(effective)

        baseline_purged = False
        if op == 'remove':
            # Total requested decrement this tick
            to_apply_total = req_qty

            # 1) Reduce any pending rows in the same direction first (no stock effect)
            reduced_from_pending = 0
            pen = c.execute("""
              SELECT id, quantity
                FROM inventory_entries
               WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?)
                 AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                 AND direction=? AND pending=1
               ORDER BY timestamp ASC, id ASC
               LIMIT 1
            """, (mid, name, wpu, row_dir)).fetchone()
            if pen and to_apply_total > 0:
                reduce_by = min(int(pen['quantity']), to_apply_total)
                new_q = int(pen['quantity']) - reduce_by
                reduced_from_pending = reduce_by
                to_apply_total -= reduce_by
                if new_q == 0:
                    c.execute("DELETE FROM inventory_entries WHERE id=?", (pen['id'],))
                else:
                    c.execute("""
                      UPDATE inventory_entries
                         SET quantity=?, total_weight=?*?, timestamp=?, source='scan-nudge/pending'
                       WHERE id=?
                    """, (new_q, float(wpu), new_q, now, pen['id']))

            # If there are no chips left (effective==0), do NOT spawn compensators.
            # This prevents phantom reverse rows when the UI is already clamped at 0.
            if int(effective_before) <= 0 and to_apply_total > 0:
                avail_after = _stock_avail_for_key(c, name, wpu)
                return jsonify(
                    ok=True,
                    applied=int(reduced_from_pending),
                    reduced_pending=int(reduced_from_pending),
                    applied_committed=0,
                    effective_before=int(effective_before),
                    avail_before=int(avail_before),
                    avail_after=int(avail_after),
                    effective_qty=0,
                    effective_qty_signed=0,
                    below_baseline=False,
                    remaining=0,
                    removed=True,
                    sanitized_name=name,
                    weight_per_unit=float(wpu),
                    baseline_cleared=False,
                    spawn_delta=None,
                    applied_overage=0,
                    blocked_no_chips=True
                ), 200, {'Content-Type':'application/json'}

            # 2) For any remainder, insert a committed compensator inside the session,
            #    and *also* insert overage beyond baseline so we can go below baseline.
            applied_committed = 0
            # Choose a category id (prefer latest session row, else snapshot row, else 1)
            cat_id = None
            latest = c.execute("""
                SELECT category_id FROM inventory_entries
                 WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?)
                   AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                 ORDER BY timestamp DESC, id DESC LIMIT 1
            """, (mid, name, wpu)).fetchone()
            if latest and latest['category_id'] is not None:
                cat_id = int(latest['category_id'])
            else:
                # Prefer category inferred from a related snapshot row
                any_row = c.execute("""
                    SELECT category_id
                      FROM flight_cargo
                     WHERE LOWER(sanitized_name)=LOWER(?)
                       AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                       AND (
                             session_id = ?
                          OR (? IS NOT NULL AND queued_id = ?)
                          OR (? IS NOT NULL AND flight_id = ?)
                       )
                     ORDER BY id DESC LIMIT 1
                """, (name, wpu, mid, draft_id, draft_id, flight_id, flight_id)).fetchone()
                if any_row and any_row['category_id'] is not None:
                    cat_id = int(any_row['category_id'])
                else:
                    any_hist = c.execute("""
                        SELECT category_id FROM inventory_entries
                         WHERE LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                         ORDER BY timestamp DESC, id DESC LIMIT 1
                    """, (name, wpu)).fetchone()
                    cat_id = int(any_hist['category_id']) if (any_hist and any_hist['category_id'] is not None) else 1

            # effective excludes pendings, so cap the "baseline-cancel" part by current effective
            commit_qty = min(max(0, to_apply_total), max(0, effective))
            rev_dir = 'in' if row_dir == 'out' else 'out'

            if commit_qty > 0:
                latest = c.execute("""
                    SELECT category_id FROM inventory_entries
                     WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?)
                       AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
                     ORDER BY timestamp DESC, id DESC LIMIT 1
                """, (mid, name, wpu)).fetchone()
                # Phase A: cancel down to baseline (no negative effective)
                cancel_qty = int(commit_qty)
                if cancel_qty > 0:
                    c.execute("""
                      INSERT INTO inventory_entries(
                        category_id, raw_name, sanitized_name,
                        weight_per_unit, quantity, total_weight,
                        direction, timestamp, pending, pending_ts,
                        session_id, source
                      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                      cat_id, name, name,
                      float(wpu), cancel_qty, float(wpu)*cancel_qty,
                      rev_dir, now, 0, None, mid, 'scan-nudge/remove'
                    ))
                applied_committed = cancel_qty

            # Phase B (ALWAYS): if the operator asked to remove *more* than the baseline,
            # treat the overage as a true session delta (same reverse direction).
            overage = max(0, int(to_apply_total) - int(commit_qty))
            spawn_delta = None
            if overage > 0:
                c.execute("""
                  INSERT INTO inventory_entries(
                    category_id, raw_name, sanitized_name,
                    weight_per_unit, quantity, total_weight,
                    direction, timestamp, pending, pending_ts,
                    session_id, source
                  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                  cat_id, name, name,
                  float(wpu), int(overage), float(wpu)*int(overage),
                  rev_dir, now, 0, None, mid, 'scan-nudge/over'
                ))
                spawn_delta = {
                  'sanitized_name': name,
                  'weight_per_unit': float(wpu),
                  'direction': rev_dir,
                  'qty': int(overage)
                }

            applied_total     = int(reduced_from_pending) + int(applied_committed) + int(overage)
            # Signed effective (includes overage going below baseline)
            effective_after_signed = int(effective) - (int(applied_committed) + int(overage))
            effective_after = max(0, effective_after_signed)

            # ────────────────────────────────────────────────────────────────
            # Edge case fix:
            # If we just drove the **effective** qty to 0 *and* there was a
            # non-zero snapshot (snap_qty>0), proactively purge the snapshot
            # rows for this key so there is nothing left that can repaint the
            # chip later (e.g. if a view paints from snapshot only).
            # ────────────────────────────────────────────────────────────────
            # Only purge when we landed exactly on zero (no overage).
            if int(effective_after_signed) == 0 and int(snap_qty) > 0 and int(overage) == 0:
                # discover any draft/flight baselines tied to this session
                qids, fids = [], []
                if draft_id is not None:
                    try: qids = [int(draft_id)]
                    except Exception: qids = []
                if flight_id is not None:
                    try: fids = [int(flight_id)]
                    except Exception: fids = []
                if not qids or not fids:
                    rows_ids = c.execute("""
                      SELECT DISTINCT queued_id, flight_id
                        FROM flight_cargo
                       WHERE session_id=? AND (queued_id IS NOT NULL OR flight_id IS NOT NULL)
                    """, (mid,)).fetchall()
                    if not qids:
                        qids = [int(r['queued_id']) for r in rows_ids if r['queued_id'] is not None]
                    if not fids:
                        fids = [int(r['flight_id']) for r in rows_ids if r['flight_id'] is not None]
                if qids:
                    ph = ",".join("?" * len(qids))
                    c.execute(f"DELETE FROM flight_cargo WHERE queued_id IN ({ph}) AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)", (*qids, name, wpu))
                if fids:
                    ph = ",".join("?" * len(fids))
                    c.execute(f"DELETE FROM flight_cargo WHERE flight_id IN ({ph}) AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)", (*fids, name, wpu))
                # ────────────────────────────────────────────────────────────────
                # Clean-slate session math:
                # After we purge the baseline at exactly zero (no overage), the
                # session still contains committed reverse rows (e.g., 'in') that
                # restored stock to cancel the baseline. Those rows are *correct*
                # for stock, but if they keep their session_id the session's net
                # for this key remains negative (e.g., -3). That hides the chip
                # until several subsequent 'add' scans bring it back to > 0.
                #
                # To make the UX intuitive (chip reappears immediately at 1 on
                # the next add), detach those committed reverse rows from THIS
                # manifest session by clearing their session_id. This preserves
                # stock while resetting the session chip math to zero.
                # We scope narrowly to this key and the reverse direction used
                # to cancel baseline (rev_dir).
                # ────────────────────────────────────────────────────────────────
                try:
                    c.execute(
                        """
                        UPDATE inventory_entries
                           SET session_id = NULL,
                               source = COALESCE(source,'') ||
                                        CASE WHEN source IS NULL OR source=''
                                             THEN 'baseline-purge'
                                             ELSE '+baseline-purge' END
                         WHERE session_id = ?
                           AND pending = 0
                           AND LOWER(sanitized_name) = LOWER(?)
                           AND CAST(weight_per_unit AS REAL) = CAST(? AS REAL)
                           AND direction = ?
                        """, (mid, name, wpu, rev_dir)
                    )
                except Exception:
                    pass
                baseline_purged = True

            # Recompute stock availability AFTER this tick so UI subtext stays in sync.
            avail_after = _stock_avail_for_key(c, name, wpu)

            # Tell the UI exactly what changed so it can update the chip AND the subtext.
            return jsonify(
                ok=True,
                applied=applied_total,
                reduced_pending=int(reduced_from_pending),
                applied_committed=int(applied_committed),
                # New preview fields:
                effective_before=int(effective_before),
                avail_before=int(avail_before),
                avail_after=int(avail_after),
                # Back-compat plus the new canonical field:
                effective_qty=int(effective_after),                 # legacy (clipped at 0)
                effective_qty_signed=int(effective_after_signed),   # NEW (can be negative)
                below_baseline=bool(effective_after_signed < 0),    # NEW flag for UI
                remaining=int(effective_after),
                removed=(int(effective_after) == 0),
                sanitized_name=name,
                weight_per_unit=float(wpu),
                baseline_cleared=bool(baseline_purged),
                spawn_delta=spawn_delta,
                applied_overage=int(overage)
            ), 200, {'Content-Type':'application/json'}

        # ‘add’ is already handled by your existing scan flow; keep API symmetric anyway
        if op == 'add':
            return jsonify(ok=True, applied=0, note='add path unchanged (use existing scan/out flow)'), 200, {'Content-Type':'application/json'}

    return jsonify(error='unhandled'), 400
