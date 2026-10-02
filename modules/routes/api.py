from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from flask import Blueprint, current_app
from flask import jsonify, make_response, session, request
import re
import sqlite3
from modules.services.inventory import InventoryConflict
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
    """Apply one source-aware scan atomically against all reservations."""
    from modules.services.inventory import adjust_pending, remove_manifest_item, manifest_rows
    mid = clean_mid(mid)
    if not mid:
        return jsonify(status='error', error='bad_manifest_id'), 400
    data = request.get_json(silent=True) or {}
    barcode = (data.get('barcode') or '').strip()
    mode = (data.get('mode') or 'add').strip().lower()
    if mode not in ('add', 'remove'):
        return jsonify(status='error', error='invalid_operation'), 400
    if not is_aot_barcode(barcode):
        return jsonify(status='error', error='non_aot_barcode', message='Not an AOT label.'), 400
    item = lookup_barcode(barcode)
    if not item:
        return jsonify(status='unknown'), 404
    try:
        qty = max(1, min(int(data.get('qty') or 1), 500))
        draft_id = int(data['draft_id']) if data.get('draft_id') else None
        flight_id = int(data['flight_id']) if data.get('flight_id') else None
        with sqlite3.connect(DB_FILE) as c:
            c.execute("BEGIN IMMEDIATE")
            if mode == 'remove':
                result = remove_manifest_item(
                    c, session_id=mid, category_id=item['category_id'],
                    name=item['sanitized_name'], weight=item['weight_per_unit'], qty=qty,
                    origin=data.get('origin') if 'origin' in data else None,
                    queued_id=draft_id, flight_id=flight_id)
                return jsonify(status='ok', item=item, qty=result['effective_qty'],
                               origin=result['origin'], removed=result['removed'])
            confirm_dup = str(data.get('confirm_dup') or '').lower() in ('1','true','yes')
            if not confirm_dup:
                dup_q = c.execute("""
                    SELECT COALESCE(SUM(quantity),0) FROM inventory_entries
                     WHERE session_id=? AND source='adv-detect' AND direction='in'
                       AND category_id=? AND LOWER(sanitized_name)=LOWER(?) AND weight_per_unit=?
                """, (mid,item['category_id'],item['sanitized_name'],item['weight_per_unit'])).fetchone()[0]
                if dup_q:
                    return jsonify(status='dup_confirm', lookup_qty=dup_q, item=item)
            direction = 'in' if str(data.get('dir') or '').lower() == 'in' else 'out'
            baseline = c.execute("""SELECT direction FROM flight_cargo
                WHERE session_id=? OR queued_id=? OR flight_id=? ORDER BY id DESC LIMIT 1""",
                (mid,draft_id,flight_id)).fetchone()
            if baseline:
                direction = baseline[0]
            _, origin = adjust_pending(
                c, session_id=mid, category_id=item['category_id'], name=item['sanitized_name'],
                weight=item['weight_per_unit'], direction=direction, delta=qty,
                origin=data.get('origin') if 'origin' in data else None)
            chips = manifest_rows(c,mid,draft_id,flight_id)
            net = next((r['qty'] for r in chips if r['category_id']==item['category_id']
                        and r['sanitized_name']==item['sanitized_name'].lower().strip()
                        and r['weight_per_unit']==item['weight_per_unit'] and r['origin']==origin),0)
    except InventoryConflict as exc:
        return jsonify(exc.payload()), 409
    except (TypeError, ValueError):
        return jsonify(status='error',error='invalid_payload'), 400
    touch_pending_session(mid)
    return jsonify(status='ok',item=item,qty=net,origin=origin,removed=False)

@bp.get('/api/manifest/<string:mid>/items')
def api_manifest_items(mid: str):
    mid = clean_mid(mid)
    if not mid:
        return jsonify({'items': []})  # poison/blank session: nothing to merge
    """Return net chips for this session (optionally including an existing flight baseline)."""
    flight_id = request.args.get('flight_id', type=int, default=None)
    draft_id  = request.args.get('draft_id',  type=int, default=None)
    # Chip refreshes count as session activity for the pending reaper
    try:
        touch_pending_session(mid)
    except Exception:
        pass
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
    header_l = [h.strip().lower() for h in header]
    cols = {name: idx for idx, name in enumerate(header_l)}
    # Try legacy header first
    legacy_need = ['category','item','unit_weight_lb','quantity','total_weight_lb']
    spec_need   = ['airport','category','sanitized_name','weight_per_unit_lb','quantity','total_lb']
    mode = None
    if all(n in cols for n in legacy_need):
        mode = 'legacy'
    elif all(n in cols for n in spec_need):
        mode = 'spec'
    else:
        return rows, 0, 0.0
    for r in rdr:
        try:
            if mode == 'legacy':
                cat  = (r[cols['category']] or '').strip()
                name = (r[cols['item']] or '').strip()
                wpu  = float(r[cols['unit_weight_lb']] or 0.0)
                qty  = int(float(r[cols['quantity']] or 0))
                tot  = float(r[cols['total_weight_lb']] or 0.0)
            else:
                # spec
                cat  = (r[cols['category']] or '').strip()
                name = (r[cols['sanitized_name']] or '').strip()
                wpu  = float(r[cols['weight_per_unit_lb']] or 0.0)
                qty  = int(float(r[cols['quantity']] or 0))
                tot  = float(r[cols['total_lb']] or 0.0)
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
