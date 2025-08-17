
from markupsafe import escape
import sqlite3, json, uuid
from datetime import datetime

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
from flask import Blueprint, current_app
from flask import flash, jsonify, redirect, render_template, request, url_for
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

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

            with sqlite3.connect(DB_FILE) as c:
                fid = c.execute("""
                     INSERT INTO flights(
                       is_ramp_entry,direction,pilot_name,pax_count,tail_number,
                       airfield_takeoff,takeoff_time,airfield_landing,eta,
                       cargo_type,cargo_weight,remarks)
                     VALUES (1,:direction,:pilot_name,:pax_count,:tail_number,
                             :airfield_takeoff,:takeoff_time,:airfield_landing,:eta,
                             :cargo_type,:cargo_weight,:remarks)
                """, data).lastrowid

                c.execute("""INSERT INTO flight_history(flight_id,timestamp,data)
                             VALUES (?,?,?)""",
                          (fid, datetime.utcnow().isoformat(), json.dumps(data)))

                # ── 1. turn the *committed* manifest into flight_cargo rows ──
                mid = request.form.get('manifest_id','')
                if mid:
                    c.execute("""
                      INSERT INTO flight_cargo(
                        flight_id, session_id, category_id, sanitized_name,
                        weight_per_unit, quantity, total_weight, direction, timestamp
                      )
                      SELECT ?, session_id, category_id, sanitized_name,
                             weight_per_unit, quantity, total_weight,
                             direction, timestamp
                        FROM inventory_entries
                       WHERE session_id=? AND pending=0
                    """, (fid, mid))

                # mark this as a NEW insert
                action = 'new'

            # WARGAME: start Radio‑outbound SLA (once; until operator marks “sent”)
            wargame_start_radio_outbound(fid)
            # WARGAME: start Ramp‑outbound SLA (once; creation time)
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

            with sqlite3.connect(DB_FILE) as c:
                c.row_factory = sqlite3.Row

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
                          remarks        = CASE
                                             WHEN LENGTH(remarks)
                                               THEN remarks || ' / Arrived ' || ?
                                             ELSE 'Arrived ' || ?
                                          END
                        WHERE id=?
                    """, (arrival, arrival, arrival, match['id']))
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
                        c.execute("""
                          INSERT INTO flight_cargo(
                            flight_id, session_id, category_id, sanitized_name,
                            weight_per_unit, quantity, total_weight,
                            direction, timestamp
                          )
                          SELECT ?, session_id, category_id, sanitized_name,
                                 weight_per_unit, quantity, total_weight,
                                 direction, timestamp
                            FROM inventory_entries
                           WHERE session_id=? AND pending=0
                        """, (fid, mid))

                else:
                    # ----- no match → insert a standalone inbound row -----
                    action = 'new'
                    fid = c.execute("""
                        INSERT INTO flights(
                           is_ramp_entry,direction,pilot_name,pax_count,tail_number,
                           airfield_takeoff,takeoff_time,airfield_landing,eta,
                           cargo_type,cargo_weight,remarks,complete)
                        VALUES (1,'inbound',:pilot_name,:pax_count,:tail_number,
                                :airfield_takeoff,'',:airfield_landing,:eta,
                                :cargo_type,:cargo_weight,:remarks,1)
                    """, data).lastrowid
                    c.execute("""INSERT INTO flight_history(flight_id,timestamp,data)
                                 VALUES (?,?,?)""",
                              (fid, datetime.utcnow().isoformat(), json.dumps(data)))

                    # ── attach any committed Advanced-Cargo manifest ──
                    mid = request.form.get('manifest_id','')
                    if mid:
                        c.execute("""
                          INSERT INTO flight_cargo(
                            flight_id, session_id, category_id, sanitized_name,
                            weight_per_unit, quantity, total_weight,
                            direction, timestamp
                          )
                          SELECT ?, session_id, category_id, sanitized_name,
                                 weight_per_unit, quantity, total_weight,
                                 direction, timestamp
                            FROM inventory_entries
                           WHERE session_id=? AND pending=0
                        """, (fid, mid))

            # Route to Radio outbox: Ramp has now touched this record
            with sqlite3.connect(DB_FILE) as c:
                c.execute("UPDATE flights SET is_ramp_entry=1, sent=0 WHERE id=?", (fid,))

            # Start Radio "landing notice" SLA once (avoid resetting on later edits)
            pending = dict_rows(
                "SELECT 1 FROM wargame_tasks WHERE role='radio' AND kind='landing' AND key=?",
                (f"flight:{fid}",)
            )
            if not pending:
                wargame_task_start(
                    role='radio',
                    kind='landing',
                    key=f"flight:{fid}",
                    gen_at=datetime.utcnow().isoformat()
                )

            # Close Ramp inbound SLA (arrival was handled)
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
    direction         = escape(request.form['direction'])
    pilot_name        = escape(request.form.get('pilot_name','').strip())
    pax_count         = escape(request.form.get('pax_count','').strip())
    tail_number       = escape(request.form['tail_number'].strip().upper())
    airfield_takeoff  = escape(request.form.get('origin','').strip().upper())
    # ── preferred hidden field (added by Ramp-Boss JS) ───────────
    travel_time = request.form.get('travel_time','').strip()

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
        cur = c.execute("""
          INSERT INTO queued_flights(
            direction, pilot_name, pax_count, tail_number,
            airfield_takeoff, airfield_landing, travel_time,
            cargo_type, remarks, created_at
          ) VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
          direction, pilot_name, pax_count, tail_number,
          airfield_takeoff, airfield_landing, travel_time,
          cargo_type, remarks, created_at
        ))
        qid = cur.lastrowid

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
            SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END)            AS net_qty,
            weight_per_unit * SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END) AS net_total,
            'out'                 AS direction,
            MAX(timestamp)        AS latest_ts
          FROM inventory_entries
          WHERE session_id = ?
            AND pending     = 0
          GROUP BY category_id, sanitized_name, weight_per_unit
          HAVING SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END) > 0
        """, (qid, mid))

        # --- Pre-fill the draft’s cargo_weight field ----------------------
        cw_total = c.execute(
            "SELECT COALESCE(SUM(total_weight),0) FROM flight_cargo WHERE queued_id=?",
            (qid,)
        ).fetchone()[0] or 0.0
        c.execute("UPDATE queued_flights SET cargo_weight=? WHERE id=?",
                  (cw_total, qid))
        # end if(mid)

        # --- Canonicalize remarks + cargo_type for the draft ---------------
        # Build "Manifest: NAME SIZE lb×QTY; …;" from the snapshot rows
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
            f"{r['name']} {_fmt_wpu(r['wpu'])} lb×{r['qty']}" for r in rows
        ) + ";") if rows else ""
        cats = {r['cat'] for r in rows}
        cargo_type = (cats.pop() if len(cats) == 1 else 'Mixed') if rows else ''
        c.execute("UPDATE queued_flights SET remarks=?, cargo_type=? WHERE id=?",
                  (remarks_txt, cargo_type, qid))

    flash(f"Flight draft {qid} added to queue.", 'info')
    if request.headers.get('X-Requested-With')=='XMLHttpRequest':
        return jsonify({'status':'queued','qid':qid})
    return redirect(url_for('ramp.queued_flights'))

@bp.route('/queued_flights')
def queued_flights():
    rows = dict_rows("""
      SELECT id, direction, tail_number,
             airfield_takeoff, airfield_landing,   -- ▼ add landing
             travel_time, cargo_type, remarks, created_at
        FROM queued_flights
       ORDER BY created_at DESC
    """)
    return render_template('queued_flights.html',
                           queued=rows,
                           active='queued_flights')

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

    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        fid = c.execute("""
          INSERT INTO flights(
            is_ramp_entry,direction,pilot_name,pax_count,tail_number,
            airfield_takeoff,takeoff_time,airfield_landing,eta,
            cargo_type,cargo_weight,remarks
          ) VALUES (1,:direction,:pilot_name,:pax_count,:tail_number,
                    :airfield_takeoff,:takeoff_time,:airfield_landing,:eta,
                    :cargo_type,:cargo_weight,:remarks)
        """, data).lastrowid

        # ── rebuild the manifest exactly like edit_queued_flight does ──
        mid = request.form.get('manifest_id','').strip()
        if mid:
            # 1️⃣ pull the merged state into Python
            rows = c.execute("""
              SELECT
                category_id,
                sanitized_name,
                weight_per_unit,
                SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END) AS net_qty,
                SUM(CASE direction WHEN 'out' THEN total_weight ELSE -total_weight END) AS net_total,
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
                 WHERE session_id = ? AND pending = 0
              )
              GROUP BY category_id, sanitized_name, weight_per_unit
              HAVING net_qty > 0
            """, (qid, mid)).fetchall()

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
                  'out', ts
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
        c.execute("""
          UPDATE flights
             SET cargo_weight     = printf('%.0f lbs', ?),
                 cargo_weight_real = ?
           WHERE id=?
        """, (tot, tot, fid))

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
            f"{r['sanitized_name']} {fmt_wpu(r['wpu'])} lb×{r['quantity']}"
            for r in rows
          ) + ';'
        ) if rows else ''
        c.execute("""
          UPDATE flights
             SET cargo_type = ?, remarks = ?
           WHERE id = ?
        """, (new_type, new_remarks, fid))

        # delete the draft record
        c.execute("DELETE FROM queued_flights WHERE id=?", (qid,))

    flash(f"Flight {fid} sent.", 'success')
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
    # load all cargo lines
    cargo = dict_rows("""
      SELECT * FROM flight_cargo WHERE queued_id=?
    """, (qid,))

    with sqlite3.connect(DB_FILE) as c:
        # for each, insert a compensating inventory entry
        for r in cargo:
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
              rev, datetime.utcnow().isoformat(), 'queue-delete'
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
    if mid:
        rows = dict_rows("""
          SELECT
            MAX(x.id)           AS entry_id,
            ic.display_name      AS category_name,
            x.sanitized_name     AS sanitized,
            SUM(x.total_weight)  AS total,
            x.weight_per_unit    AS wpu,
            SUM(x.quantity)      AS qty
          FROM (
            -- the snapshot we saved at queue-time
            SELECT id, queued_id, category_id, sanitized_name,
                   weight_per_unit, quantity, total_weight
              FROM flight_cargo
             WHERE queued_id = ?
            UNION ALL
            -- plus any new committed lines in this manifest session
            SELECT id, NULL        AS queued_id, category_id, sanitized_name,
                   weight_per_unit,
                   CASE direction
                     WHEN 'out' THEN quantity
                     ELSE         -quantity
                   END             AS quantity,
                   CASE direction
                     WHEN 'out' THEN total_weight
                     ELSE         -total_weight
                   END             AS total_weight
              FROM inventory_entries
             WHERE session_id = ? AND pending = 0
          ) AS x
          JOIN inventory_categories ic
            ON ic.id = x.category_id
         GROUP BY x.category_id, x.sanitized_name, x.weight_per_unit
         HAVING SUM(x.quantity) > 0
        """, (qid, mid))
    else:
        # no live manifest → show only the saved snapshot
        rows = dict_rows("""
          SELECT
            fc.id                  AS entry_id,
            ic.display_name        AS category_name,
            fc.sanitized_name      AS sanitized,
            fc.total_weight        AS total,
            fc.weight_per_unit     AS wpu,
            fc.quantity            AS qty
          FROM flight_cargo fc
          JOIN inventory_categories ic
            ON ic.id = fc.category_id
          WHERE fc.queued_id = ?
        """, (qid,))
    return jsonify(rows)

@bp.route('/edit_queued_flight/<int:qid>', methods=['GET','POST'])
def edit_queued_flight(qid):
    row = dict_rows("SELECT * FROM queued_flights WHERE id=?", (qid,))
    if not row:
        flash("Draft not found","error"); return redirect(url_for('ramp.queued_flights'))
    draft = row[0]

    if request.method=='POST':
        # accept either the new single field or the pair
        travel_time = request.form.get('travel_time','').strip()
        if not travel_time:
            hrs  = request.form.get('travel_h','').zfill(2)
            mins = request.form.get('travel_m','').zfill(2)
            travel_time = f"{hrs}{mins}" if hrs or mins else ''
        with sqlite3.connect(DB_FILE) as c:
            c.execute("""
              UPDATE queued_flights SET
                direction=?, pilot_name=?, pax_count=?, tail_number=?,
                airfield_takeoff=?, airfield_landing=?, travel_time=?,
                cargo_type=?, remarks=?
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
              qid
            ))
            # refresh the snapshot to match the **current** manifest (replace-not-append)
            mid   = request.form.get('manifest_id','')
            rows  = []                       # ← default when no live session
            if mid:

                # 1️⃣ collect a **combined** view (old snapshot + new edits)
                rows = c.execute("""
                  SELECT
                    category_id,
                    sanitized_name,
                    weight_per_unit,
                    SUM(CASE direction
                          WHEN 'out' THEN quantity
                          ELSE          -quantity
                        END)                       AS net_qty,
                    SUM(CASE direction
                          WHEN 'out' THEN total_weight
                          ELSE          -total_weight
                        END)                       AS net_total,
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
                       AND pending     = 0
                  )
                  GROUP BY category_id, sanitized_name, weight_per_unit
                  HAVING net_qty > 0
                """, (qid, mid)).fetchall()

            # 2️⃣ replace the snapshot with the fresh aggregate
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
                  'out', ts
                ))
            # ──────────────────────────────────────────────────────────
            #  Re-compute the new total weight for this draft and store
            #  it, so the “Cargo Weight” input is pre-filled next time.
            # ──────────────────────────────────────────────────────────
            cw_total = c.execute(
                "SELECT COALESCE(SUM(total_weight),0) "
                "  FROM flight_cargo WHERE queued_id=?",
                (qid,)
            ).fetchone()[0] or 0.0
            c.execute(
                "UPDATE queued_flights SET cargo_weight=? WHERE id=?",
                (cw_total, qid)
            )

        # After snapshot refresh, also refresh remarks + cargo_type
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
                f"{r['name']} {_fmt_wpu(r['wpu'])} lb×{r['qty']}" for r in rows2
            ) + ";") if rows2 else ""
            cats = {r['cat'] for r in rows2}
            cargo_type = (cats.pop() if len(cats) == 1 else 'Mixed') if rows2 else ''
            c2.execute("UPDATE queued_flights SET remarks=?, cargo_type=? WHERE id=?",
                       (remarks_txt, cargo_type, qid))

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
    flash(f"Flight {fid} deleted and inventory restored.")
    return redirect(url_for('core.dashboard'))

@bp.post('/delete_flight_cargo/<int:fcid>')
def delete_flight_cargo(fcid):
    """❌-button in the queued-flight editor.
       1) add compensating inventory row (so stock is restored)
       2) delete the snapshot row from flight_cargo                """
    sid = request.form.get('manifest_id','')          # ← current Adv session, may be ''
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

        rev = 'in' if r['direction'] == 'out' else 'out'
        cur = c.execute("""
          INSERT INTO inventory_entries(
            category_id, raw_name, sanitized_name,
            weight_per_unit, quantity, total_weight,
            direction, timestamp, pending, pending_ts,
            session_id, source
          ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
          r['category_id'], r['sanitized_name'], r['sanitized_name'],
          r['weight_per_unit'], r['quantity'], r['total_weight'],
          rev, now,                     # direction, timestamp
          1,  now,  sid, 'chip-delete'  # ← marked *pending* & linked to session
        ))

        comp_id = cur.lastrowid

        if src_table == 'flight_cargo':
            # NO LONGER delete the snapshot row here—
            # defer any physical rewrite of flight_cargo until the Commit step.
            # c.execute("DELETE FROM flight_cargo WHERE id=?", (fcid,))
            pass
        else:
            # Mark the original inventory row as “rolled back” so it is ignored
            # by stock math but kept for audit-trail purposes.
            c.execute("""
              UPDATE inventory_entries
                 SET pending    = 1,
                     pending_ts = ?,
                     source     = 'chip-deleted'
               WHERE id = ?
            """, (now, fcid))

    return jsonify(status='ok', comp_id=comp_id)
