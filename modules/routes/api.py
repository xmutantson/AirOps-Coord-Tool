

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from flask import Blueprint, current_app
from flask import jsonify, make_response, session, request
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
