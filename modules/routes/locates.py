import sqlite3
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify
from modules.utils.common import (
    get_db_file,
    adsb_latest_for_tail,
    iso8601_ceil_utc,
    age_seconds,
)

bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)

@bp.get('/api/locates/markers')
def api_locates_markers():
    """
    Returns newest sighting for the focused tail (if provided) PLUS
    newest-per-tail for all other tails seen within `window` seconds.

    Query params:
      - tail   : e.g. N12345 (optional)
      - window : seconds (default 3600)

    Response shape (Step 9 spec):
    {
      "focused": { ... } | null,
      "others":  [ ... ],
      // Back-compat for Step 8 map JS:
      "markers": [ focused + others in the older flat shape ]
    }
    """
    tail   = (request.args.get('tail') or '').strip().upper()
    window = int(request.args.get('window') or 3600)
    window = max(60, window)  # clamp to sane minimum
    cutoff = (datetime.utcnow() - timedelta(seconds=window)).isoformat()

    def _row_to_newshape(r: dict) -> dict:
        """Spec shape with nested receiver and age_s."""
        return {
            "tail": (r.get("tail") or "").strip().upper(),
            "lat": float(r["lat"]),
            "lon": float(r["lon"]),
            "track_deg": None if r.get("track_deg") is None else float(r["track_deg"]),
            "speed_kt": None if r.get("speed_kt") is None else float(r["speed_kt"]),
            "alt_ft": None if r.get("alt_ft") is None else float(r["alt_ft"]),
            "age_s": age_seconds(r.get("sample_ts_utc")),
            "receiver": {
                "airport": r.get("receiver_airport") or "",
                "call":    r.get("receiver_call") or "",
            },
            "sample_ts_utc": r.get("sample_ts_utc") or iso8601_ceil_utc(),
            "track_source": r.get("source") or r.get("track_source") or "",
            "source": r.get("source") or "",
        }

    def _row_to_oldshape(r: dict) -> dict:
        """Compat shape used by Step 8 JS (flat receiver_* keys)."""
        return {
            "tail": (r.get("tail") or "").strip().upper(),
            "lat": float(r["lat"]),
            "lon": float(r["lon"]),
            "track_deg": None if r.get("track_deg") is None else float(r["track_deg"]),
            "speed_kt": None if r.get("speed_kt") is None else float(r["speed_kt"]),
            "alt_ft": None if r.get("alt_ft") is None else float(r["alt_ft"]),
            "sample_ts_utc": r.get("sample_ts_utc") or iso8601_ceil_utc(),
            "receiver_airport": r.get("receiver_airport") or "",
            "receiver_call":   r.get("receiver_call") or "",
            "source": r.get("source") or "",
        }

    # 1) Focused (from DB newest; fallback to live snapshot if DB has none)
    focused = None
    if tail:
        try:
            with sqlite3.connect(get_db_file()) as c:
                c.row_factory = sqlite3.Row
                row = c.execute(
                    """
                    SELECT tail, sample_ts_utc, lat, lon,
                           track_deg, speed_kt, alt_ft,
                           receiver_airport, receiver_call, source
                      FROM adsb_sightings
                     WHERE UPPER(tail) = ?
                     ORDER BY sample_ts_utc DESC
                     LIMIT 1
                    """,
                    (tail,)
                ).fetchone()
            if row:
                focused = dict(row)
            else:
                # best-effort live fallback
                live = adsb_latest_for_tail(tail)
                if live and live.get("lat") is not None and live.get("lon") is not None:
                    focused = {
                        "tail": (live.get("tail") or tail).strip().upper(),
                        "lat":  float(live["lat"]),
                        "lon":  float(live["lon"]),
                        "track_deg": live.get("track_deg"),
                        "speed_kt": live.get("speed_kt"),
                        "alt_ft":   live.get("alt_ft"),
                        "sample_ts_utc": live.get("sample_ts_utc") or iso8601_ceil_utc(),
                        "receiver_airport": live.get("receiver_airport") or "",
                        "receiver_call":    live.get("receiver_call") or "",
                        "source": live.get("source") or "",
                    }
        except Exception:
            focused = None

    # 2) Others: newest-per-tail within window, excluding the focused tail
    others_rows = []
    try:
        with sqlite3.connect(get_db_file()) as c:
            c.row_factory = sqlite3.Row
            others_rows = c.execute(
                """
                SELECT s.tail, s.sample_ts_utc, s.lat, s.lon,
                       s.track_deg, s.speed_kt, s.alt_ft,
                       s.receiver_airport, s.receiver_call, s.source
                  FROM adsb_sightings s
                  JOIN (
                        SELECT tail, MAX(sample_ts_utc) AS mx
                          FROM adsb_sightings
                         WHERE sample_ts_utc >= ?
                         GROUP BY tail
                  ) m ON s.tail = m.tail AND s.sample_ts_utc = m.mx
                 WHERE (? = '' OR UPPER(s.tail) <> ?)
                   AND s.lat IS NOT NULL AND s.lon IS NOT NULL
                 ORDER BY s.sample_ts_utc DESC
                """,
                (cutoff, tail, tail)
            ).fetchall()
    except Exception:
        others_rows = []

    # Build new-shape payload
    focused_obj = _row_to_newshape(focused) if focused else None
    others_objs = [_row_to_newshape(dict(r)) for r in others_rows]

    # Back-compat flat list for existing JS
    markers = []
    if focused:
        markers.append(_row_to_oldshape(focused))
    markers.extend([_row_to_oldshape(dict(r)) for r in others_rows])
    # newest-first
    markers.sort(key=lambda m: m.get("sample_ts_utc",""), reverse=True)

    return jsonify({
        "ok": True,
        "focused": focused_obj,
        "others": others_objs,
        "markers": markers,  # compatibility with Step 8 visualizer
    })

@bp.get('/api/locates/requests')
def api_locates_requests():
    """
    JSON list of locate requests, newest first.
    Optional query params:
      - q: substring match on tail (case-insensitive)
      - limit: max rows (1..1000, default 200)
    """
    q = (request.args.get('q') or '').strip().upper()
    try:
        limit = int(request.args.get('limit') or 200)
    except Exception:
        limit = 200
    limit = max(1, min(1000, limit))

    where = ""
    params = ()
    if q:
        where = "WHERE UPPER(IFNULL(tail,'')) LIKE ?"
        params = (f"%{q}%",)

    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        rows = c.execute(f"""
            SELECT id, tail, requested_at_utc, requested_by,
                   latest_sample_ts_utc, latest_from_airport, latest_from_call
              FROM flight_locates
              {where}
             ORDER BY id DESC
             LIMIT {limit}
        """, params).fetchall()

    data = []
    for r in rows:
        d = dict(r)
        d['responded'] = bool(d.get('latest_sample_ts_utc'))
        data.append(d)
    return jsonify({'ok': True, 'locates': data})
