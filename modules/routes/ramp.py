
from markupsafe import escape
import sqlite3, json, uuid, os, base64, io
from datetime import datetime, timedelta
from typing import Optional

# Wargame finish helper — soft import (no-op if unavailable)
try:
    from modules.services.wargame import wargame_finish_ramp_inbound
except Exception:
    def wargame_finish_ramp_inbound(*args, **kwargs):
        return None

# Cargo-request reconciler — soft import (no-op if unavailable)
try:
    from modules.services.jobs import cargo_request_reconciler as _cargo_reconciler_tick
except Exception:
    def _cargo_reconciler_tick():
        return None

# Wargame STATE synchronization — soft import (to keep DB and in-memory state consistent)
try:
    from modules.routes.wargame_api import STATE as _WARGAME_STATE, LOCK as _WARGAME_LOCK
except Exception:
    _WARGAME_STATE = None
    _WARGAME_LOCK = None

# Plane pin clearing helper — soft import (to mark plane panel as complete)
try:
    from modules.routes.wargame_api import _plane_pin_clear_by_flight_ref
except Exception:
    def _plane_pin_clear_by_flight_ref(flight_ref: str) -> bool:
        return False

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from modules.services.manifest_ack import (
    acknowledgement_is_current, has_unapplied_cargo, manifest_fingerprint,
    invalidate_stale_acknowledgement, queue_manifest_id,
)


def try_satisfy_ramp_request(flight_row: dict) -> None:
    """
    Check if an outbound flight satisfies a pending ramp request.
    If so, mark the request as satisfied in both DB and STATE.

    Criteria: destination match, weight >= requested, direction=outbound
    """
    if flight_row.get('direction') != 'outbound':
        return

    try:
        # Compute numeric weight (prefer REAL column if present)
        wt = flight_row.get('cargo_weight_real')
        if wt is None:
            cw = (flight_row.get('cargo_weight') or '').lower()
            if cw.endswith('lbs'): cw = cw[:-3]
            if cw.endswith('lb'):  cw = cw[:-2]
            wt = float(cw.strip() or 0)

        # Find oldest open request with same destination and <= weight
        req = dict_rows("""
          SELECT id, requested_weight, created_at
            FROM wargame_ramp_requests
           WHERE satisfied_at IS NULL
             AND destination = ?
           ORDER BY created_at ASC
           LIMIT 1
        """, (flight_row['airfield_landing'],))

        if req and wt >= float(req[0]['requested_weight'] or 0):
            rid     = req[0]['id']
            now_iso = datetime.utcnow().isoformat()
            tail    = flight_row['tail_number']

            with sqlite3.connect(DB_FILE) as c:
                c.execute("""
                  UPDATE wargame_ramp_requests
                     SET satisfied_at=?, assigned_tail=?
                   WHERE id=?
                """, (now_iso, tail, rid))

                # Record the *actual* SLA latency
                created_dt = datetime.fromisoformat(req[0]['created_at'])
                delta = (datetime.utcnow() - created_dt).total_seconds()
                c.execute("""
                  INSERT INTO wargame_metrics(event_type, delta_seconds, recorded_at, key)
                  VALUES ('ramp', ?, ?, ?)
                """, (delta, now_iso, f"rampreq:{rid}"))

            # Also remove from wargame STATE so it doesn't reappear (STATE overrides DB)
            if _WARGAME_STATE is not None and _WARGAME_LOCK is not None:
                with _WARGAME_LOCK:
                    queues = _WARGAME_STATE.get("adapters", {}).get("queues", {})
                    reqs = queues.get("requests", [])
                    queues["requests"] = [r for r in reqs if int(r.get("id") or 0) != int(rid)]
    except Exception:
        pass


from modules.utils.common import parse_adv_manifest, guess_category_id_for_name, new_manifest_session_id, sanitize_name, \
    get_pilot_ack_for_flight, set_pilot_ack_for_flight
from app import publish_inventory_event
from app import DB_FILE
from modules.utils.common import aggregate_manifest_net, flip_session_pending_to_committed
from flask import Blueprint, current_app
from flask import flash, jsonify, redirect, render_template, request, url_for, send_file, abort
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'
from weasyprint import HTML, CSS

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
            'category_id': guess,
            'origin': it.get('origin', '')
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
            'category_id': guess,
            'origin': it.get('origin', '')
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
    from modules.services.inventory import apply_inbound_items, InventoryConflict
    try:
        with sqlite3.connect(DB_FILE) as c:
            c.execute('BEGIN IMMEDIATE')
            result = apply_inbound_items(c,mid,items,import_id=payload.get('import_id') or 'legacy',sanitize=sanitize_name)
    except InventoryConflict as exc:
        return jsonify(exc.payload()), 409
    try:
        publish_inventory_event()
    except Exception:
        pass
    if result['inserted'] == 0 and result['replayed'] == 0:
        return jsonify(error='no valid items inserted', **result), 400
    return jsonify(status='ok',manifest_id=mid,**result)

@bp.route('/ramp_boss/default_origin_status', methods=['GET'])
def ramp_boss_default_origin_status():
    """Tiny polling endpoint so the first-run setup card can auto-reveal
    the real Ramp Boss form once *anyone* sets the home-airport preference."""
    drow = dict_rows("SELECT value FROM preferences WHERE name='default_origin'")
    val = (drow[0]['value'] if drow else '') or ''
    return jsonify({'set': bool(val.strip()), 'value': val.strip()})

@bp.route('/ramp_boss', methods=['GET', 'POST'])
def ramp_boss():
    ensure_column("flights", "is_ramp_entry", "INTEGER DEFAULT 0")

    # pull default_origin from DB (for JS pre-fill)
    drow = dict_rows("SELECT value FROM preferences WHERE name='default_origin'")
    default_origin = drow[0]['value'] if drow else ''

    # First-run gate: if no default_origin is configured, the Ramp Boss form
    # asks for the home airport up front and locks out the rest until it's set.
    if request.method == 'POST' and request.form.get('action') == 'set_default_origin':
        code = request.form.get('default_origin', '').strip().upper()
        if not code:
            flash('Enter your home airport code.', 'error')
            return redirect(url_for('ramp.ramp_boss'))
        rows = dict_rows(
            "SELECT 1 FROM airports "
            " WHERE ident       = ?"
            "    OR icao_code   = ?"
            "    OR iata_code   = ?"
            "    OR local_code  = ?"
            "    OR gps_code    = ?"
            " LIMIT 1",
            (code,)*5
        )
        if not rows:
            flash(f'“{code}” is not a known airport code.', 'error')
            return redirect(url_for('ramp.ramp_boss'))
        set_preference('default_origin', code)
        flash(f'Home airport set to {code}.', 'success')
        return redirect(url_for('ramp.ramp_boss'))

    if request.method == 'POST':
        # ── Validate destination against airports DB ─────────────────────
        dest = request.form.get('destination','').upper().strip()
        # HARD GATE: destination is required to submit from Ramp Boss
        if not dest:
            msg = 'Destination is required.'
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error':'destination_required','message':msg}), 400
            flash(msg, 'error')
            # Keep UX consistent with legacy: redirect back to Ramp Boss
            return redirect(url_for('ramp.ramp_boss'))
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

        # Outbound dispatch always uses the canonical queue/sign/send workflow.
        if direction == 'outbound':
            return queue_flight()

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
                from modules.services.inventory import require_direct_session, attach_manifest_to_flight, apply_inbound_items, InventoryConflict
                from modules.services.arrivals import resolve_arrival_request, record_arrival_request
                mid = clean_mid(request.form.get('manifest_id',''))
                try:
                    arrival_key, arrival_hash, replay = resolve_arrival_request(c,
                        request.form.get('arrival_request_id'),data,mid,fcode)
                    if replay is not None:
                        replay['action'] = 'update_ignored'
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            return jsonify(replay)
                        return redirect(url_for('core.dashboard'))
                    require_direct_session(c,mid)
                except InventoryConflict as exc:
                    return jsonify(exc.payload()), 409

                allocation_mid = mid or None
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
                    if mid and action != 'update_ignored':
                        attach_manifest_to_flight(c,mid,fid,'in')

                else:
                    # ----- no match → insert a standalone inbound row -----
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
                    if mid and action != 'update_ignored':
                        attach_manifest_to_flight(c,mid,fid,'in')

                if action != 'update_ignored' and not mid and data.get('remarks'):
                    parsed = parse_adv_manifest(data['remarks'])
                    if parsed:
                        auto_mid = allocation_mid = f'arrival:{fid}'
                        items = [dict(category_id=guess_category_id_for_name(sanitize_name(it['name'])) or 1,
                            sanitized_name=sanitize_name(it['name']),raw_name=it['name'],size_lb=it['size_lb'],
                            qty=it['qty'],origin=it.get('origin','')) for it in parsed]
                        apply_inbound_items(c,auto_mid,items,import_id='arrival',sanitize=sanitize_name)
                        attach_manifest_to_flight(c,auto_mid,fid,'in')

                record_arrival_request(c,arrival_key,arrival_hash,fid,allocation_mid,action)

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

                # Fire cargo-request reconciliation immediately so matching
                # cargo_requests are satisfied right away (in addition to the
                # background minute job).
                try:
                    _cargo_reconciler_tick()
                except Exception:
                    pass

        # ── at this point we have `fid` of the row we inserted/updated ──
        # fetch it back in full
        row = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
        # If this outbound satisfies a Ramp Request, mark it satisfied
        try_satisfy_ramp_request(row)
        row['action'] = action

        # ── WebEOC activity-log summary for arrivals only ──
        # (departures are already reported when queued; no double-report)
        is_arrival = (row.get('direction') == 'inbound')
        if is_arrival and action != 'update_ignored' and get_preference('webeoc_activity_popup') == 'yes':
            mission = get_preference('mission_number') or ''
            origin_code = get_preference('default_origin') or ''
            direction_label = 'Inbound'
            verb = 'arrived'
            title = (f"Air Ops \u2013 {row['tail_number']} {verb} "
                     f"{row.get('airfield_takeoff') or origin_code or '?'}"
                     f"\u2192{row.get('airfield_landing') or '?'}")
            lines = []
            if mission:
                lines.append(f"Mission/Incident: {mission}")
            lines.append(f"Direction: {direction_label}")
            lines.append(f"Tail #: {row['tail_number']}")
            if row.get('pilot_name'):
                lines.append(f"Pilot: {row['pilot_name']}")
            if row.get('pax_count'):
                lines.append(f"PAX: {row['pax_count']}")
            lines.append(f"Origin: {row.get('airfield_takeoff') or origin_code or 'N/A'}")
            lines.append(f"Destination: {row.get('airfield_landing') or 'TBD'}")
            if row.get('eta'):
                lines.append(f"Arrival Time: {row['eta']}")
            if row.get('cargo_type'):
                lines.append(f"Cargo Type: {row['cargo_type']}")
            if row.get('cargo_weight') and str(row['cargo_weight']) != '0':
                lines.append(f"Cargo Weight: {row['cargo_weight']} lbs")
            if row.get('remarks'):
                lines.append(f"Remarks: {row['remarks']}")
            row['webeoc'] = {'title': title, 'body': '\n'.join(lines)}

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
    webeoc_popup = get_preference('webeoc_activity_popup') == 'yes'
    return render_template(
      'ramp_boss.html',
      default_origin=default_origin,
      active='ramp_boss',
      advanced_data=advanced_data,
      arrival_request_id=uuid.uuid4().hex,
      enable_adv_manifest_scan=(scan_pref == 'yes'),
      webeoc_activity_popup=webeoc_popup
    )

@bp.route('/queue_flight', methods=['POST'])
def queue_flight():
    """Save this RampBoss form as a draft in queued_flights + record its cargo."""
    # --- Collect form inputs ---
    mid               = clean_mid(request.form.get('manifest_id',''))
    # HARD GATE for Ramp-Boss-origin "Add to Queue": require a destination.
    # (Quick Add has its own minimal route that permits missing destination.)
    if not (request.form.get('destination','') or '').strip():
        msg = 'Destination is required.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error':'destination_required','message': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('ramp.ramp_boss'))
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
        from modules.services.inventory import validate_session_commit, InventoryConflict
        try:
            validate_session_commit(c, mid)
        except InventoryConflict as exc:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify(exc.payload()), 409
            flash(str(exc), 'error')
            return redirect(url_for('ramp.ramp_boss'))
        from modules.services.inventory import claim_manifest, save_ledger_cutline
        owner = claim_manifest(c, mid)
        if owner:
            if owner[2] != 'queued':
                return jsonify(error='manifest_conflict', message='This manifest has already been closed. Start a new manifest.'), 409
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify(status='queued', qid=owner[0])
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
            direction, timestamp, origin
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
            MAX(timestamp)        AS latest_ts,
            COALESCE(MAX(origin),'') AS origin
          FROM inventory_entries
          WHERE session_id = ?
            AND pending     IN (0,1)
          GROUP BY category_id, sanitized_name, weight_per_unit, origin
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
        from modules.services.inventory import commit_manifest_session
        commit_manifest_session(c,mid)

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
        if mid:
            claim_manifest(c, mid, qid)
            save_ledger_cutline(c, qid, mid)
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
                 fc.quantity AS qty,
                 COALESCE(fc.origin,'') AS origin
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
            # Origin tags are included per-item in the manifest text via [Origin]
            # (no trailing Source: line — per-item is the canonical format)
            cats = {r['cat'] for r in rows}
            new_type = (cats.pop() if len(cats) == 1 else 'Mixed') if rows else ''
            # Only overwrite if the operator didn't supply a value
            if not (posted_remarks or '').strip():
                c.execute("UPDATE queued_flights SET remarks=? WHERE id=?",
                          (remarks_txt, qid))
            if not (posted_type or '').strip():
                c.execute("UPDATE queued_flights SET cargo_type=? WHERE id=?",
                          (new_type, qid))

    # ── WebEOC activity-log summary (opt-in via global preference) ──
    webeoc = {}
    if get_preference('webeoc_activity_popup') == 'yes':
        row = dict_rows("SELECT * FROM queued_flights WHERE id=?", (qid,))
        if row:
            r = row[0]
            mission = get_preference('mission_number') or ''
            origin_code = get_preference('default_origin') or ''
            title = (f"Air Ops \u2013 {r['tail_number']} queued {r['direction']} "
                     f"{r.get('airfield_takeoff') or origin_code or '?'}"
                     f"\u2192{r.get('airfield_landing') or '?'}")
            lines = []
            if mission:
                lines.append(f"Mission/Incident: {mission}")
            lines.append(f"Direction: {(r.get('direction') or '').capitalize()}")
            lines.append(f"Tail #: {r['tail_number']}")
            if r.get('pilot_name'):
                lines.append(f"Pilot: {r['pilot_name']}")
            if r.get('pax_count'):
                lines.append(f"PAX: {r['pax_count']}")
            lines.append(f"Origin: {r.get('airfield_takeoff') or origin_code or 'N/A'}")
            lines.append(f"Destination: {r.get('airfield_landing') or 'TBD'}")
            if r.get('travel_time'):
                tt = r['travel_time']
                lines.append(f"Est. Travel Time: {tt[:2]}h {tt[2:]}m"
                             if len(tt) == 4 else f"Est. Travel Time: {tt}")
            if r.get('cargo_type'):
                lines.append(f"Cargo Type: {r['cargo_type']}")
            if r.get('cargo_weight') and str(r['cargo_weight']) != '0':
                lines.append(f"Cargo Weight: {r['cargo_weight']} lbs")
            if r.get('remarks'):
                lines.append(f"Remarks: {r['remarks']}")
            lines.append(f"Queued: {r.get('created_at', '')}")
            webeoc = {'title': title, 'body': '\n'.join(lines)}

    flash(f"Flight draft {qid} added to queue.", 'info')
    if request.headers.get('X-Requested-With')=='XMLHttpRequest':
        resp = {'status':'queued','qid':qid}
        if webeoc:
            resp['webeoc'] = webeoc
        return jsonify(resp)
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
    try:
        ensure_column("queued_flights", "pilot_ack_signed_at", "TEXT")
    except Exception:
        pass
    base_sql = """
      SELECT *
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
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        c.execute('BEGIN')
        rows = [dict(r) for r in c.execute(sql, tuple(params))]
        for draft in rows:
            draft['expected_revision'] = manifest_fingerprint(c, draft)
            if (not acknowledgement_is_current(c, draft) or
                    not os.path.isfile(draft.get('manifest_pdf_path') or '')):
                draft['pilot_ack_signed_at'] = None

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

    try:
        ensure_column("queued_flights", "pilot_ack_signed_at", "TEXT")
    except Exception:
        pass
    base_sql = """
      SELECT *
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
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        c.execute('BEGIN')
        rows = [dict(r) for r in c.execute(sql, tuple(params))]
        for draft in rows:
            draft['expected_revision'] = manifest_fingerprint(c, draft)
            if (not acknowledgement_is_current(c, draft) or
                    not os.path.isfile(draft.get('manifest_pdf_path') or '')):
                draft['pilot_ack_signed_at'] = None

    return render_template('partials/_queued_flights_table.html', queued=rows)

@bp.route('/send_queued_flight/<int:qid>', methods=['POST','GET'])
def send_queued_flight(qid):
    ensure_column("queued_flights", "consumed", "INTEGER DEFAULT 0")
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        c.execute("BEGIN IMMEDIATE")
        fresh = c.execute("SELECT * FROM queued_flights WHERE id=?", (qid,)).fetchone()
        if fresh is None or fresh['consumed']:
            flash(f"Queue entry {qid} was already sent or removed.", 'info')
            return redirect(url_for('ramp.queued_flights'))
        q = dict(fresh)
        if not (q.get('airfield_landing') or '').strip():
            msg = "Destination is required before sending."
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify(error='destination_required', message=msg), 400
            flash(msg, 'error')
            return redirect(url_for('ramp.edit_queued_flight', qid=qid))
        if not acknowledgement_is_current(c, q):
            invalidate_stale_acknowledgement(c, qid)
            msg = "Pilot acknowledgment of the current manifest is required before sending."
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify(error='pilot_ack_required', message=msg), 400
            flash(msg, 'error')
            return redirect(request.referrer or url_for('ramp.queued_flights'))

        from modules.services.inventory import require_manifest_owner, validate_allocated_stock, InventoryConflict
        mid = queue_manifest_id(c, q)
        try:
            require_manifest_owner(c, mid, qid)
            validate_allocated_stock(c, mid)
        except InventoryConflict as exc:
            return jsonify(exc.payload()), 409
        if not q.get('manifest_pdf_path') or not os.path.isfile(q['manifest_pdf_path']):
            return jsonify(error='signed_pdf_required', message='Signed PDF unavailable; acknowledge the current manifest again.'), 409

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

        touched = c.execute(
            "UPDATE queued_flights SET consumed=1 WHERE id=? AND IFNULL(consumed,0)=0",
            (qid,)
        ).rowcount
        if touched == 0:
            c.commit()
            flash(f"Queue entry {qid} was already sent.", 'info')
            return redirect(url_for('ramp.queued_flights'))
        # Never merge this signed manifest into a different existing flight.
        fid = None
        if flight_code:
            ex = c.execute("SELECT id FROM flights WHERE flight_code=?",
                           (flight_code,)).fetchone()
            if ex:
                c.rollback()
                msg = "Flight code already exists; choose a new code before sending."
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify(error='flight_code_conflict', message=msg), 409
                flash(msg, 'error')
                return redirect(url_for('ramp.queued_flights'))
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

        mid = queue_manifest_id(c, q)
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
        from modules.services.inventory import cargo_weight_lbs
        effective_tot = tot if c.execute('SELECT 1 FROM flight_cargo WHERE flight_id=? LIMIT 1', (fid,)).fetchone() else cargo_weight_lbs(q.get('cargo_weight'))
        c.execute("""
          UPDATE flights
             SET cargo_weight     = printf('%g lbs', ?),
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


        # Preserve the exact acknowledged revision and its immutable PDF.
        c.execute("""
          UPDATE flights SET pilot_ack_name=?, pilot_ack_method=?,
                 pilot_ack_signature_b64=?, pilot_ack_signed_at=?,
                 pilot_ack_manifest_hash=?, manifest_pdf_path=? WHERE id=?
        """, (q.get('pilot_ack_name'), q.get('pilot_ack_method'),
              q.get('pilot_ack_signature_b64'), q.get('pilot_ack_signed_at'),
              q.get('pilot_ack_manifest_hash'), q.get('manifest_pdf_path'), fid))

        if mid:
            c.execute("UPDATE manifest_allocations SET state='sent',flight_id=? WHERE session_id=?", (fid,mid))
        # delete the draft record
        c.execute("DELETE FROM queued_flights WHERE id=?", (qid,))

    # Check if this outbound satisfies any pending ramp requests
    row = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))
    if row:
        try_satisfy_ramp_request(row[0])
        # Mark plane panel as complete if this flight was loaded from a plane
        try:
            _plane_pin_clear_by_flight_ref(f"flight:{fid}")
        except Exception:
            pass

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
    from modules.services.inventory import delete_draft_allocation, InventoryConflict
    try:
        with sqlite3.connect(DB_FILE) as c:
            c.row_factory = sqlite3.Row
            c.execute('BEGIN IMMEDIATE')
            delete_draft_allocation(c,qid)
    except InventoryConflict as exc:
        return jsonify(exc.payload()), 409
    flash(f"Queue entry {qid} deleted and inventory restored.", 'info')
    return redirect(url_for('ramp.queued_flights'))

@bp.route('/api/queued_manifest/<int:qid>')
def api_queued_manifest(qid):
    from modules.services.inventory import manifest_rows
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        c.execute('BEGIN')
        draft = c.execute('SELECT * FROM queued_flights WHERE id=?', (qid,)).fetchone()
        if not draft:
            return jsonify([]), 404
        mid = queue_manifest_id(c, dict(draft))
        categories = dict(c.execute('SELECT id,display_name FROM inventory_categories'))
        rows = [dict(entry_id=None, category_name=categories.get(r['category_id'],''),
                     sanitized=r['sanitized_name'],total=r['total'],wpu=r['weight_per_unit'],
                     qty=r['qty'],origin=r['origin'],delta=0) for r in manifest_rows(c,mid,queued_id=qid)]
    return jsonify(rows)

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
            c.row_factory = sqlite3.Row
            c.execute("BEGIN IMMEDIATE")
            fresh = c.execute("SELECT * FROM queued_flights WHERE id=?", (qid,)).fetchone()
            if fresh is None or dict(fresh).get('consumed'):
                flash("Draft was already sent or removed.", 'error')
                return redirect(url_for('ramp.queued_flights'))
            draft = dict(fresh)

            from modules.services.inventory import (require_manifest_owner, InventoryConflict,
                manifest_rows, applied_ledger_ids, save_ledger_cutline)
            mid = queue_manifest_id(c, draft)
            posted_mid = clean_mid(request.form.get('manifest_id',''))
            if mid and posted_mid and mid != posted_mid:
                return jsonify(error='manifest_conflict', message='A saved draft cannot change manifest identity.'), 409
            mid = mid or posted_mid
            try:
                require_manifest_owner(c, mid, qid)
            except InventoryConflict as exc:
                return jsonify(exc.payload()), 409
            if request.form['direction'] != draft['direction'] and c.execute(
                    'SELECT 1 FROM flight_cargo WHERE queued_id=?', (qid,)).fetchone():
                return jsonify(error='manifest_conflict', message='Remove cargo before changing direction.'), 409
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
              clean_mid(request.form.get('manifest_id','')),
              qid
            ))
            committed_now = False
            if mid:
                applied = applied_ledger_ids(c, qid, mid)
                committed = {r[0] for r in c.execute('SELECT id FROM inventory_entries WHERE session_id=? AND COALESCE(pending,0)=0', (mid,))}
                committed_now = bool(committed - applied)
                if committed_now:
                    rows = manifest_rows(c, mid, queued_id=qid, include_pending=False)
                    c.execute('DELETE FROM flight_cargo WHERE queued_id=?', (qid,))
                    for item in rows:
                        c.execute("""INSERT INTO flight_cargo(queued_id,session_id,category_id,sanitized_name,
                            weight_per_unit,quantity,total_weight,direction,timestamp,origin)
                            VALUES (?,?,?,?,?,?,?,?,?,?)""", (qid,mid,item['category_id'],item['sanitized_name'],
                            item['weight_per_unit'],item['qty'],item['total'],item['direction'],
                            datetime.utcnow().isoformat(),item['origin']))
                save_ledger_cutline(c, qid, mid)
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
            elif committed_now:
                c.execute('UPDATE queued_flights SET cargo_weight=0 WHERE id=?', (qid,))
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
                rows2 = c.execute("""
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
                c.execute(
                    "UPDATE queued_flights SET remarks=?, cargo_type=? WHERE id=?",
                    (remarks_txt, cargo_type, qid))

            else:
                # If no new commit happened but fields are blank and a snapshot exists,
                # opportunistically back-fill remarks/type from the snapshot once.
                try:
                    has_rows = c.execute(
                        "SELECT COUNT(*) FROM flight_cargo WHERE queued_id=?", (qid,)
                    ).fetchone()[0] or 0
                    if has_rows:
                        cur = c.execute("SELECT remarks, cargo_type FROM queued_flights WHERE id=?", (qid,)).fetchone()
                        if cur and (not (cur['remarks'] or '').strip() or not (cur['cargo_type'] or '').strip()):
                            rows3 = c.execute("""
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
                                    c.execute("UPDATE queued_flights SET cargo_type=? WHERE id=?", (new_type, qid))
                                if not (cur['remarks'] or '').strip():
                                    c.execute("UPDATE queued_flights SET remarks=? WHERE id=?", (new_rm, qid))

                except Exception:
                    # Best-effort back-fill; ignore any lookup/DB hiccups here.
                    pass

            invalidate_stale_acknowledgement(c, qid)

        flash("Draft updated","success")
        # ── XHR requests expect JSON so the front-end can redirect itself ──
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(
              status='saved',
              redirect=url_for('ramp.queued_flights')
            )
        return redirect(url_for('ramp.queued_flights'))

    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        c.execute('BEGIN')
        row = c.execute('SELECT * FROM queued_flights WHERE id=?', (qid,)).fetchone()
        if row is None:
            return redirect(url_for('ramp.queued_flights'))
        draft = dict(row)
        draft['expected_revision'] = manifest_fingerprint(c, draft)
    # GET → render Ramp-Boss with a ‘draft’ object for pre-fill
    return render_template('ramp_boss.html',
                           draft=draft,
                           active='queued_flights',
                           advanced_data={})   # chips fetched by JS as usual

# Minimal aggregated view for Cargo Requests v2
@bp.get('/ramp/aggregated')
def ramp_aggregated():
    """
    Minimal 4-column aggregated view (template expected: templates/ramp_aggregated.html).
    """
    return render_template('ramp_aggregated.html')

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

    from modules.services.inventory import delete_finalized_flight, InventoryConflict
    try:
        with sqlite3.connect(DB_FILE) as c:
            c.execute('BEGIN IMMEDIATE')
            delete_finalized_flight(c,fid)
    except InventoryConflict as exc:
        return jsonify(exc.payload()), 409
    flash(f"Flight {code_txt} deleted and inventory restored.")
    return redirect(url_for('core.dashboard'))

@bp.post('/delete_flight_cargo/<int:fcid>')
def delete_flight_cargo(fcid):
    """Delete one identified manifest item with the shared reversal invariant."""
    from modules.services.inventory import reverse_manifest_entry, InventoryConflict
    try:
        with sqlite3.connect(DB_FILE) as c:
            c.row_factory = sqlite3.Row
            c.execute('BEGIN IMMEDIATE')
            result = reverse_manifest_entry(c,source_id=fcid,
                source_table=request.form.get('source_table'),
                session_id=clean_mid(request.form.get('manifest_id','')))
    except InventoryConflict as exc:
        return jsonify(exc.payload()), 409
    return jsonify(status='ok',**result)

# ──────────────────────────────────────────────────────────────────────────
# Pilot acknowledgment (typed name or drawn signature)
#   • POST /flight/<id>/ack     ← persists acknowledgment on flights.*
#   • GET  /api/flight/<id>/ack ← returns ack json for audit/export/UI
# Storage is handled via common.set_pilot_ack_for_flight (DB columns added by migrations).
# ──────────────────────────────────────────────────────────────────────────
@bp.post('/flight/<int:flight_id>/ack')
def flight_ack(flight_id):
    """
    Persist pilot acknowledgment for a flight.
    Accepts:
      - typed_name (string, optional if signature_data is present)
      - signature_data (data:image/png;base64,..., optional if typed_name present)
    Rules:
      • At least one of typed_name or signature_data must be present.
      • If signature_data is present → method='drawn', else 'typed'.
    """
    if request.content_length is None or request.content_length > 512 * 1024:
        return jsonify(ok=False, error='signature_request_size', message='Signature request must have a bounded body of at most 512 KiB.'), 413
    typed = (request.form.get('typed_name') or '').strip()
    sig   = (request.form.get('signature_data') or '').strip()
    from modules.services.manifest_images import validate_signature
    try:
        sig = validate_signature(sig)
    except ValueError as exc:
        return jsonify(ok=False, error='invalid_signature', message=str(exc)), 400
    if not typed and not sig:
        msg = 'Type name or draw a signature.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'ok': False, 'error': 'signature_required', 'message': msg}), 400
        flash(msg, 'error')
        return redirect(request.referrer or url_for('core.dashboard'))

    method = 'drawn' if sig else 'typed'
    try:
        set_pilot_ack_for_flight(
            flight_id=flight_id,
            name=typed or '',
            method=method,
            signature_b64_or_datauri=sig or None,
            signed_at_iso=None
        )
    except Exception:
        current_app.logger.exception('Failed to save pilot ack')
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'ok': False, 'error': 'signature_save_failed'}), 500
        flash('Failed to save pilot acknowledgment.', 'error')
        return redirect(request.referrer or url_for('core.dashboard'))
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'ok': True})
    flash('Pilot acknowledgment saved.', 'success')
    return redirect(request.referrer or url_for('core.dashboard'))

@bp.get('/api/flight/<int:flight_id>/ack')
def api_flight_ack(flight_id):
    """Returns: { name, method, signature_b64, signed_at } or {}"""
    try:
        data = get_pilot_ack_for_flight(flight_id) or {}
    except Exception as e:
        current_app.logger.exception('Ack fetch failed')
        return jsonify({'error': 'Failed to fetch acknowledgment', 'details': str(e)}), 500
    return jsonify(data or {})

# ──────────────────────────────────────────────────────────────────────────
# Ramp Manifest PDF (Step 8): canonical builder + storage path convention
# ──────────────────────────────────────────────────────────────────────────
def _save_manifest_path(queue_id: int, path: str) -> None:
    with sqlite3.connect(DB_FILE) as c:
        c.execute("UPDATE queued_flights SET manifest_pdf_path=? WHERE id=?", (path, int(queue_id)))

def _get_queue_row(qid: int) -> dict | None:
    rows = dict_rows("SELECT * FROM queued_flights WHERE id=?", (int(qid),))
    return rows[0] if rows else None

@bp.post('/ramp/pilot_ack/<int:queue_id>')
def ramp_pilot_ack(queue_id: int):
    """
    Persist pilot acknowledgment on a queued flight (draft).
    Accepts form or JSON:
      - typed_name (optional if signature_data present)
      - signature_data (data:image/png;base64,...; optional if typed_name present)
      - expected_revision (required, from the displayed saved manifest)
      - build_pdf retained for compatibility; signed copies are always built
    Returns JSON: { ok, pdf_url? }
    """
    if request.content_length is None or request.content_length > 512 * 1024:
        return jsonify(ok=False, error='signature_request_size', message='Signature request must have a bounded body of at most 512 KiB.'), 413
    payload = request.get_json(silent=True) or request.form
    if not hasattr(payload, 'get'):
        return jsonify(ok=False, error='invalid_signature'), 400
    typed = payload.get('typed_name') or ''
    sig = payload.get('signature_data') or ''
    if not isinstance(typed, str) or not isinstance(sig, str):
        return jsonify(ok=False, error='invalid_signature'), 400
    typed = typed.strip()
    sig = sig.strip()
    if not typed and not sig:
        return jsonify(ok=False, error='signature_required',
                       message='Type name or draw a signature.'), 400
    from modules.services.manifest_images import validate_signature
    try:
        sig = validate_signature(sig)
    except ValueError as exc:
        return jsonify(ok=False, error='invalid_signature', message=str(exc)), 400
    now_iso = datetime.utcnow().isoformat()
    build_pdf = True  # Acknowledgement requires its immutable artifact.
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT * FROM queued_flights WHERE id=?", (queue_id,)).fetchone()
        if row is None or dict(row).get('consumed'):
            return jsonify(ok=False, error='not_found'), 404
        draft = dict(row)
        if has_unapplied_cargo(c, draft):
            return jsonify(ok=False, error='manifest_changes_pending',
                           message='Save cargo changes before acknowledging the manifest.'), 409
        digest = manifest_fingerprint(c, draft)
        if payload.get('expected_revision') != digest:
            return jsonify(ok=False, error='revision_conflict', message='Manifest changed or page is stale. Reload and review before acknowledging.'), 409
        from modules.services.inventory import require_manifest_owner, InventoryConflict
        try:
            require_manifest_owner(c, queue_manifest_id(c, draft), queue_id)
        except InventoryConflict as exc:
            return jsonify(exc.payload()), 409
        draft.update(pilot_ack_name=typed, pilot_ack_method='drawn' if sig else 'typed',
                     pilot_ack_signature_b64=sig or None, pilot_ack_signed_at=now_iso,
                     pilot_ack_manifest_hash=digest)
        pdf_path = None
        if build_pdf:
            try:
                from modules.utils.manifest import build_manifest_pdf as _build_pdf
                # The reserved write lock keeps the builder's cargo read stable.
                _, pdf_path = _build_pdf(current_app, draft)
            except Exception:
                current_app.logger.exception("PDF build failed for queue %s", queue_id)
                return jsonify(ok=False, error='build_failed'), 500
        c.execute("""
          UPDATE queued_flights SET pilot_ack_name=?, pilot_ack_method=?,
                 pilot_ack_signature_b64=?, pilot_ack_signed_at=?,
                 pilot_ack_manifest_hash=?, manifest_pdf_path=? WHERE id=?
        """, (typed, draft['pilot_ack_method'], sig or None, now_iso,
              digest, pdf_path, queue_id))
    out = {'ok': True, 'pilot_ack_at': now_iso}
    if pdf_path:
        out['pdf_url'] = url_for('ramp.view_manifest_pdf', queue_id=queue_id)
    return jsonify(out)


def _queue_manifest_pdf(queue_id):
    """Return an immutable signed copy, or build an unsigned saved snapshot."""
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT * FROM queued_flights WHERE id=?", (queue_id,)).fetchone()
        if row is None:
            abort(404)
        draft = dict(row)
        pdf_path = (draft.get('manifest_pdf_path') or '').strip()
        if draft.get('pilot_ack_signed_at'):
            # Never attach an old signature to a newly rendered manifest.
            # Legacy copies without a content binding must be acknowledged again.
            if (draft.get('pilot_ack_manifest_hash') and pdf_path
                    and os.path.isfile(pdf_path)):
                return pdf_path
            abort(409, description='Signed PDF unavailable; acknowledge the current manifest again.')
        from modules.utils.manifest import build_manifest_pdf as _build_pdf
        _, pdf_path = _build_pdf(current_app, draft)
        c.execute("UPDATE queued_flights SET manifest_pdf_path=? WHERE id=?",
                  (pdf_path, queue_id))
        return pdf_path


@bp.get('/ramp/manifest/<int:queue_id>.pdf', endpoint='view_manifest_pdf')
def view_manifest_pdf(queue_id: int):
    """Stream the preserved signed PDF or a current unsigned saved snapshot."""
    pdf_path = _queue_manifest_pdf(queue_id)
    return send_file(pdf_path, mimetype='application/pdf',
                     as_attachment=False, download_name=f"manifest-{queue_id}.pdf")


@bp.post('/ramp/manifest/<int:queue_id>/build')
def force_build_manifest_pdf(queue_id: int):
    """The build button preserves an existing signed copy unchanged."""
    _queue_manifest_pdf(queue_id)
    return jsonify(ok=True, pdf_url=url_for('ramp.view_manifest_pdf', queue_id=queue_id))


@bp.post('/ramp/send_now')
def api_send_now():
    """
    JSON: { "queue_id": int }
    Enforces pilot_ack on the queued draft before allowing any send flow.
    """
    data = request.get_json(silent=True) or {}
    try:
        qid = int(data.get('queue_id'))
    except Exception:
        return jsonify({'error': 'missing queue_id'}), 400
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT * FROM queued_flights WHERE id=?", (qid,)).fetchone()
        if row is None:
            return jsonify({'error': 'not_found'}), 404
        if not acknowledgement_is_current(c, dict(row)):
            invalidate_stale_acknowledgement(c, qid)
            return jsonify(error='pilot_ack_required',
                           message='Acknowledge the current manifest before sending.'), 400
    # You can call your existing send_queued_flight(qid) logic here, or return ok:
    return jsonify({'ok': True, 'queue_id': qid}), 200

# ──────────────────────────────────────────────────────────────────────────
# Quick Add to Ramp Queue
# Tail required; pilot optional; direction defaults to outbound.
# Inserts a minimal draft so ops can fill destination/details later.
# ──────────────────────────────────────────────────────────────────────────
@bp.post('/queue_quick_add')
def queue_quick_add():
    tail   = (request.form.get('tail_number') or '').strip().upper()
    pilot  = (request.form.get('pilot_name') or '').strip()
    direct = (request.form.get('direction') or 'outbound').strip().lower()
    direction = 'inbound' if direct == 'inbound' else 'outbound'

    if not tail:
        msg = 'Tail number is required.'
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error':'tail_required','message': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('ramp.queued_flights'))

    created_at = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        c.execute("BEGIN IMMEDIATE")
        try:
            ensure_column("queued_flights", "manifest_id", "TEXT")
        except Exception:
            pass
        cur = c.execute("""
          INSERT INTO queued_flights(
            direction, pilot_name, pax_count, tail_number,
            airfield_takeoff, airfield_landing, travel_time,
            cargo_weight, cargo_type, remarks, created_at
          ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
          direction, pilot, '', tail,
          '', '', '',     # origin/destination/travel_time left blank
          '0', '', '',    # cargo weight/type/remarks defaulted
          created_at
        ))
        qid = cur.lastrowid
        c.commit()

    flash(f"Draft {qid} created for {tail}.", 'success')
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'status':'queued','qid': qid})
    return redirect(url_for('ramp.queued_flights'))

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
    from modules.services.inventory import manifest_rows
    rows = manifest_rows(c,session_id,queued_id=draft_id,flight_id=flight_id,include_pending=False)
    effective = sum(r['qty'] for r in rows if r['sanitized_name'] == name.lower().strip() and r['weight_per_unit'] == float(wpu))
    row_dir = rows[0]['direction'] if rows else _row_dir_for_session(c,session_id,draft_id,flight_id)
    column, ref = ('queued_id',draft_id) if draft_id is not None else ('flight_id',flight_id)
    if ref is not None:
        snap_qty = c.execute(f"""SELECT COALESCE(SUM(quantity),0) FROM flight_cargo
            WHERE {column}=? AND LOWER(sanitized_name)=LOWER(?) AND weight_per_unit=?""", (ref,name,wpu)).fetchone()[0]
    else:
        snap_qty = c.execute("""SELECT COALESCE(SUM(quantity),0) FROM flight_cargo
            WHERE session_id=? AND LOWER(sanitized_name)=LOWER(?) AND weight_per_unit=?""", (session_id,name,wpu)).fetchone()[0]
    return int(effective), int(snap_qty), int(effective-snap_qty), row_dir, None


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
    manifest_id = clean_mid(manifest_id)
    if not manifest_id:
        return jsonify(error='bad_manifest_id'), 400
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
    manifest_id = clean_mid(manifest_id)
    if not manifest_id:
        return jsonify(error='bad_manifest_id'), 400
    try:
        data = request.get_json(silent=True) or {}
        draft_id = int(data.get('draft_id') or 0)
    except Exception:
        return jsonify(error='invalid payload'), 400
    if not draft_id:
        return jsonify(error='missing draft_id'), 400
    from modules.services.inventory import require_manifest_owner, InventoryConflict
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        c.execute('BEGIN IMMEDIATE')
        draft = c.execute('SELECT * FROM queued_flights WHERE id=?', (draft_id,)).fetchone()
        if not draft or dict(draft).get('consumed'):
            return jsonify(error='not_found'), 404
        existing = queue_manifest_id(c, dict(draft))
        if existing and existing != manifest_id:
            return jsonify(error='manifest_conflict'), 409
        try:
            require_manifest_owner(c, manifest_id, draft_id)
        except InventoryConflict as exc:
            return jsonify(exc.payload()), 409
        c.execute("UPDATE flight_cargo SET session_id=? WHERE queued_id=? AND IFNULL(session_id,'')=''", (manifest_id,draft_id))
        c.execute('UPDATE queued_flights SET manifest_id=? WHERE id=?', (manifest_id,draft_id))
        invalidate_stale_acknowledgement(c, draft_id)
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
    manifest_id = clean_mid(manifest_id)
    if not manifest_id:
        return jsonify(error='bad_manifest_id'), 400
    try:
        return _api_manifest_delete_key_impl(manifest_id)
    except Exception:
        import traceback
        traceback.print_exc()
        logger.exception("delete_key crashed for manifest=%s body=%s", manifest_id, request.get_data(as_text=True)[:500])
        return jsonify(ok=False, error='server error'), 500

def _api_manifest_delete_key_impl(manifest_id: str):
    """Delete a selected source's line in one transaction, independent of UI totals."""
    from modules.services.inventory import remove_manifest_item, InventoryConflict
    data = request.get_json(silent=True) or {}
    try:
        name = (data.get('sanitized_name') or '').strip()
        weight = float(data.get('weight_per_unit') or 0)
        if not name or weight <= 0:
            return jsonify(error='missing_name_or_weight'), 400
        with sqlite3.connect(DB_FILE) as c:
            c.execute("BEGIN IMMEDIATE")
            result = remove_manifest_item(
                c, session_id=manifest_id, name=name, weight=weight, qty=None,
                category_id=data.get('category_id'),
                origin=data.get('origin') if 'origin' in data else None,
                queued_id=data.get('draft_id'), flight_id=data.get('flight_id'))
    except InventoryConflict as exc:
        return jsonify(exc.payload()), 409
    except (TypeError, ValueError):
        return jsonify(error='invalid_payload'), 400
    return jsonify(ok=True, comp_id=None, comp_dir=None, qty=result['applied'],
                   origin=result['origin'], pending_committed=0)

@bp.post('/api/manifest/<manifest_id>/nudge')
def api_manifest_nudge(manifest_id: str):
    """Remove cargo transactionally using its category and source identity."""
    from modules.services.inventory import remove_manifest_item, InventoryConflict
    manifest_id = clean_mid(manifest_id)
    if not manifest_id:
        return jsonify(error='bad_manifest_id'), 400
    data = request.get_json(silent=True) or {}
    op = (data.get('op') or data.get('mode') or 'remove').strip().lower()
    if op == 'add':
        return jsonify(ok=True, applied=0, note='Use the scan endpoint to add cargo')
    if op != 'remove':
        return jsonify(error='invalid_operation'), 400
    name = (data.get('sanitized_name') or data.get('name') or '').strip()
    category_id = data.get('category_id')
    try:
        weight = float(data.get('weight_per_unit') or 0)
        qty = max(1, int(data.get('qty') or 1))
        barcode = (data.get('barcode') or '').strip()
        if barcode:
            if not is_aot_barcode(barcode):
                return jsonify(error='non_aot_barcode'), 400
            item = lookup_barcode(barcode)
            if not item:
                return jsonify(error='unknown_barcode'), 404
            name, weight, category_id = item['sanitized_name'], item['weight_per_unit'], item['category_id']
        if not name or weight <= 0:
            return jsonify(error='missing_name_or_weight'), 400
        with sqlite3.connect(DB_FILE) as c:
            c.execute("BEGIN IMMEDIATE")
            result = remove_manifest_item(
                c, session_id=manifest_id, name=name, weight=weight, qty=qty,
                category_id=category_id, origin=data.get('origin') if 'origin' in data else None,
                queued_id=data.get('draft_id'), flight_id=data.get('flight_id'))
    except InventoryConflict as exc:
        return jsonify(exc.payload()), 409
    except (TypeError, ValueError):
        return jsonify(error='invalid_payload'), 400
    touch_pending_session(manifest_id)
    return jsonify(ok=True, sanitized_name=name, weight_per_unit=weight,
                   effective_qty_signed=result['effective_qty'], below_baseline=False,
                   remaining=result['effective_qty'], baseline_cleared=False,
                   spawn_delta=None, applied_overage=0, **result)
