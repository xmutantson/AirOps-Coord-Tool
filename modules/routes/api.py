from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from flask import Blueprint, current_app
from flask import jsonify, make_response, session, request
import re
import sqlite3
from app import DB_FILE
import csv as _csv
from io import StringIO as _StringIO

bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

@bp.route('/api/airport_exists/<string:code>')
def airport_exists(code):
    code = code.upper()
    rows = dict_rows("""
        SELECT 1 FROM airports
         WHERE ident       = ?
            OR icao_code   = ?
            OR iata_code   = ?
            OR local_code  = ?
            OR gps_code    = ?
        LIMIT 1
    """, (code,)*5)
    return jsonify({ 'exists': bool(rows) })

@bp.get("/_ping")
def ping():
    """Return 204 immediately – used by tiny JS heartbeat."""
    # Touch the session so its expiration is refreshed on each heartbeat
    session.modified = True
    # (If using PERMANENT_SESSION_LIFETIME, this will bump the cookie expiry)

    resp = make_response(("", 204))
    # Explicit “don’t cache me” headers for any intermediate store
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp

@bp.get('/api/flight_code/convert')
def api_flight_code_convert():
    """
    Validate/parse OOOMMDDYYDDDHHMM and confirm OOO/DDD exist in airports.
    Returns {ok, origin, dest, hhmm} or {ok:false, error}.
    """
    code = (request.args.get('code') or '').strip().upper()
    info = parse_flight_code(code)
    if not info:
        return jsonify({'ok': False, 'error': 'invalid_format'}), 400
    def exists(tok: str) -> bool:
        rows = dict_rows(
            "SELECT 1 FROM airports WHERE ? IN (ident, icao_code, iata_code, gps_code, local_code) LIMIT 1",
            (tok,)
        )
        return bool(rows)
    if not exists(info['origin']) or not exists(info['dest']):
        return jsonify({'ok': False, 'error': 'unknown_airport'}), 400
    return jsonify({'ok': True, 'origin': info['origin'], 'dest': info['dest'], 'hhmm': info['hhmm']})

# --- Prev max cargo for a tail ----------------------------------------------
@bp.get('/api/aircraft/prev_max_cargo')
def api_prev_max_cargo():
    """
    Return historical max cargo weight for a given tail number using:
      1) flights.cargo_weight_real (preferred, numeric)
      2) SUM(flight_cargo.total_weight) per flight_id
      3) parsed numeric from flights.cargo_weight (e.g. '1234 lbs')
    Response: {tail, prev_max_lbs: int|None, sample_count: int}
    """
    from modules.utils.common import dict_rows, ensure_column

    tail = (request.args.get('tail') or '').strip().upper()
    if not tail:
        return jsonify({'tail': '', 'prev_max_lbs': None, 'sample_count': 0})

    # Ensure numeric column exists on older DBs
    try:
        ensure_column('flights', 'cargo_weight_real', 'REAL')
    except Exception:
        pass

    flights = dict_rows("""
        SELECT id, cargo_weight, cargo_weight_real
          FROM flights
         WHERE tail_number = ?
    """, (tail,))
    if not flights:
        return jsonify({'tail': tail, 'prev_max_lbs': None, 'sample_count': 0})

    ids = [int(r['id']) for r in flights if r.get('id') is not None]
    cargo_by_fid = {}
    if ids:
        placeholders = ",".join("?" * len(ids))
        rows = dict_rows(f"""
            SELECT flight_id, COALESCE(SUM(total_weight),0) AS tot
              FROM flight_cargo
             WHERE flight_id IN ({placeholders})
             GROUP BY flight_id
        """, tuple(ids))
        cargo_by_fid = {int(r['flight_id']): float(r['tot'] or 0.0) for r in rows}

    def parse_wt(txt: str | None) -> float:
        s = (txt or '').lower().strip()
        if not s:
            return 0.0
        s = s.replace('lbs', '').replace('lb', '')
        m = re.search(r'(-?\d+(?:\.\d+)?)', s)
        try:
            return float(m.group(1)) if m else 0.0
        except Exception:
            return 0.0

    weights: list[float] = []
    for f in flights:
        # 1) numeric canonical column
        w = f.get('cargo_weight_real') or 0.0
        try:
            w = float(w or 0.0)
        except Exception:
            w = 0.0

        # 2) manifest sum
        if not w or w <= 0:
            w = float(cargo_by_fid.get(int(f['id']), 0.0))

        # 3) legacy text field
        if not w or w <= 0:
            w = parse_wt(f.get('cargo_weight'))

        if w and w > 0:
            weights.append(float(w))

    prev_max = int(round(max(weights))) if weights else None
    return jsonify({
        'tail': tail,
        'prev_max_lbs': prev_max,
        'sample_count': len(weights)
    })

# ─────────────────────────────────────────────────────────────────────────────
# RampBoss Scan API
#   POST /api/manifest/<mid>/scan     {barcode, mode: "add"|"remove", flight_id?:int}
#   GET  /api/manifest/<mid>/items?flight_id=<id>
# ─────────────────────────────────────────────────────────────────────────────

@bp.post('/api/manifest/<string:mid>/scan')
def api_manifest_scan(mid: str):
    """
    Apply a single scan against the pending session.
       • Build (no baseline):       add → pending 'out' +1; remove → pending 'out' -1 (not below 0)
       • Edit (draft_id/flight_id): add → pending 'out' +1; remove → pending 'in' +1  (baseline-aware; can go below snapshot)
    Unknown barcode → {status:'unknown'} (client can open mapping flow).
    """
    data = request.get_json(silent=True) or {}
    barcode = (data.get('barcode') or '').strip()
    mode    = (data.get('mode') or 'add').strip().lower()
    flight_id = data.get('flight_id')
    draft_id  = data.get('draft_id')
    if not barcode:
        return jsonify({'status':'error','error':'missing_barcode'}), 400

    item = lookup_barcode(barcode)
    if not item:
        return jsonify({'status':'unknown'}), 404

    # --- Pre-check: what's the current net qty for this item? -------------
    # Enforce spec: if toggle is Remove and item isn't on the manifest, do nothing.
    pre_chips = aggregate_manifest_net(
        session_id=mid,
        flight_id=int(flight_id) if flight_id else None,
        queued_id=int(draft_id)  if draft_id  else None
    )
    def _match_item(ch):
        return (int(ch['category_id']) == int(item['category_id']) and
                ch['sanitized_name'].lower().strip() == item['sanitized_name'].lower().strip() and
                float(ch['weight_per_unit']) == float(item['weight_per_unit']))
    pre_qty = 0
    for ch in pre_chips:
        if _match_item(ch):
            pre_qty = int(ch['qty'])
            break

    # --- NOOP guard: prevent reverse rows when there are no chips left -------
    # In Edit (baseline-aware) mode, a 'remove' previously spawned reverse rows
    # even at/below zero. If the effective qty is <= 0, do nothing.
    is_edit = bool(flight_id or draft_id)
    if (mode == 'remove') and is_edit and pre_qty <= 0:
        return jsonify({
            'status': 'ok',
            'item': {
                'category_id': item['category_id'],
                'sanitized_name': item['sanitized_name'],
                'weight_per_unit': item['weight_per_unit']
            },
            'qty': 0,            # unchanged
            'removed': False,
            'noop': True,
            'reason': 'no_chips_to_remove'
        })

    # --- Baseline direction for this session (outbound vs inbound) --------
    def _row_dir_for_scan(session_id: str, qid, fid) -> str:
        with sqlite3.connect(DB_FILE) as c:
            c.row_factory = sqlite3.Row
            row = c.execute("""
                SELECT direction
                  FROM flight_cargo
                 WHERE (
                        session_id = ?
                     OR (queued_id = ? AND ? IS NOT NULL)
                     OR (flight_id = ? AND ? IS NOT NULL)
                       )
                   AND (queued_id IS NOT NULL OR flight_id IS NOT NULL)
                 ORDER BY id DESC
                 LIMIT 1
            """, (session_id, qid, qid, fid, fid)).fetchone()
        return (row['direction'] if row and row['direction'] in ('in','out') else 'out')

    baseline_dir = _row_dir_for_scan(mid, draft_id, flight_id)  # 'out' or 'in'

    # --- Stock gate: ONLY for outbound ADDs; subtract only this session's PENDING OUTS
    def _committed_avail():
        row = dict_rows("""
          SELECT COALESCE(SUM(CASE direction WHEN 'in' THEN quantity ELSE -quantity END),0) AS net
            FROM inventory_entries
           WHERE pending=0 AND category_id=? AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
        """, (item['category_id'], item['sanitized_name'], item['weight_per_unit']))[0]
        return int(row['net'] or 0)
    def _session_pending_out():
        row = dict_rows("""
          SELECT COALESCE(SUM(quantity),0) AS q
            FROM inventory_entries
           WHERE session_id=? AND category_id=? AND LOWER(sanitized_name)=LOWER(?) AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
             AND direction='out' AND pending=1
        """, (mid, item['category_id'], item['sanitized_name'], item['weight_per_unit']))[0]
        return int(row['q'] or 0)

    # Decide direction + delta per rules
    if mode not in ('add','remove'):
        mode = 'add'
    # Determine the session's baseline direction (outbound vs inbound edit)
    row_hint = dict_rows("""
        SELECT direction FROM flight_cargo
         WHERE (
                session_id = ? OR
                (queued_id = ? AND ? IS NOT NULL) OR
                (flight_id = ? AND ? IS NOT NULL)
               )
           AND (queued_id IS NOT NULL OR flight_id IS NOT NULL)
         ORDER BY id DESC LIMIT 1
    """, (mid, draft_id, draft_id, flight_id, flight_id))
    row_dir = row_hint[0]['direction'] if (row_hint and row_hint[0].get('direction') in ('in','out')) else 'out'

    if mode == 'add':
        # Apply add in the snapshot's direction:
        #  - outbound edit → 'out'
        #  - inbound edit  → 'in'
        direction = 'out' if row_dir == 'out' else 'in'
        delta = +1
        # Enforce stock cap only when we're consuming stock (outbound)
        if row_dir == 'out':
            avail = _committed_avail()
            sess  = _session_pending_out()
            if (avail - sess) < 1:
                return jsonify({'status':'out_of_stock'}), 409
    else:
        if (flight_id or draft_id):
            # Edit semantics (baseline-aware): remove applies the REVERSE of baseline
            direction = ('in' if baseline_dir == 'out' else 'out')
            delta = +1
        else:
            # Build semantics: decrement pending in the baseline direction (floored at 0 by upsert)
            direction = baseline_dir
            delta = -1

    qty = upsert_scan_pending(
        session_id=mid,
        category_id=item['category_id'],
        sanitized_name=item['sanitized_name'],
        weight_per_unit=item['weight_per_unit'],
        direction=direction,
        delta_qty=delta
    )

    # Compute net qty for the chip after this scan
    chips = aggregate_manifest_net(
        session_id=mid,
        flight_id=int(flight_id) if flight_id else None,
        queued_id=int(draft_id)  if draft_id  else None
    )
    net = 0
    for ch in chips:
        if _match_item(ch):
            net = int(ch['qty'])
            break

    # Only report "removed" when there was something to remove and it hit zero
    removed = (mode == 'remove' and not flight_id and not draft_id and pre_qty > 0 and net == 0)
    return jsonify({
        'status': 'ok',
        'item': {
            'category_id': item['category_id'],
            'sanitized_name': item['sanitized_name'],
            'weight_per_unit': item['weight_per_unit']
        },
        'qty': net,
        'removed': bool(removed)
    })

@bp.get('/api/manifest/<string:mid>/items')
def api_manifest_items(mid: str):
    """Return net chips for this session (optionally including an existing flight baseline)."""
    flight_id = request.args.get('flight_id', type=int, default=None)
    draft_id  = request.args.get('draft_id',  type=int, default=None)
    chips = aggregate_manifest_net(
        session_id=mid,
        flight_id=flight_id,
        queued_id=draft_id
    )
    return jsonify({'items': chips})


def _parse_remote_csv_for_api(csv_text: str):
    rows = []
    total = 0.0
    if not (csv_text or '').strip():
        return rows, 0, 0.0
    rdr = _csv.reader(_StringIO(csv_text))
    header = next(rdr, [])
    cols = {name: idx for idx, name in enumerate(header)}
    need = ['category','item','unit_weight_lb','quantity','total_weight_lb']
    if not all(n in cols for n in need):
        return rows, 0, 0.0
    for r in rdr:
        try:
            cat  = (r[cols['category']] or '').strip()
            name = (r[cols['item']] or '').strip()
            wpu  = float(r[cols['unit_weight_lb']] or 0.0)
            qty  = int(float(r[cols['quantity']] or 0))
            tot  = float(r[cols['total_weight_lb']] or 0.0)
        except Exception:
            continue
        rows.append({
            'category': cat,
            'item': name,
            'unit_weight_lb': wpu,
            'quantity': qty,
            'total_weight_lb': tot,
        })
        total += tot
    return rows, len(rows), round(total, 1)

@bp.get('/api/remote_inventory')
def api_remote_inventory_index():
    recs = dict_rows("""
      SELECT airport_canon, snapshot_at, received_at, csv_text
        FROM remote_inventory
       ORDER BY airport_canon
    """)
    out = []
    for r in recs:
        _, n, tot = _parse_remote_csv_for_api(r.get('csv_text') or '')
        out.append({
            'airport': (r.get('airport_canon') or '').strip().upper(),
            'generated_at': r.get('snapshot_at') or '',
            'received_at': r.get('received_at') or '',
            'rows': n,
            'total_lbs': tot,
        })
    return jsonify({'airports': out})

@bp.get('/api/remote_inventory/<string:airport>')
def api_remote_inventory_detail(airport: str):
    canon = canonical_airport_code(airport or '')
    recs = dict_rows("""
      SELECT airport_canon, snapshot_at, received_at, csv_text, summary_text
        FROM remote_inventory
       WHERE airport_canon = ?
       LIMIT 1
    """, (canon,))
    if not recs:
        return jsonify({'ok': False, 'error': 'not_found', 'airport': canon}), 404
    r = recs[0]
    rows, n, tot = _parse_remote_csv_for_api(r.get('csv_text') or '')
    return jsonify({
        'ok': True,
        'airport': canon,
        'generated_at': r.get('snapshot_at') or '',
        'received_at': r.get('received_at') or '',
        'summary_text': r.get('summary_text') or '',
        'rows': rows,
        'totals': {'lines': n, 'total_lbs': tot}
    })
