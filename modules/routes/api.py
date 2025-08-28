

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from flask import Blueprint, current_app
from flask import jsonify, make_response, session, request
import re
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
