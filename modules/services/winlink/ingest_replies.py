import re
import json
import csv
import sqlite3
from datetime import datetime, timezone
from typing import Optional
import os
import mimetypes

from modules.utils.common import upsert_weather_product, looks_ascii_text, get_wx_keys

from modules.utils.common import (
    get_db_file,
    iso8601_ceil_utc,
    canonical_airport_code,
)

# ---- AOCT Flight Reply ingest ------------------------------------------------
_FLIGHT_REPLY_SUBJ_RE = re.compile(r'^\s*AOCT\s+FLIGHT\s+REPLY\b', re.I)
_TAIL_RE              = re.compile(r'\bN[0-9A-Z]{3,6}\b', re.I)

def _parse_number(val: str | float | int | None) -> Optional[float]:
    if val is None:
        return None
    if isinstance(val, (int, float)):
        try:
            return float(val)
        except Exception:
            return None
    m = re.search(r'[-+]?\d+(?:\.\d+)?', str(val))
    try:
        return float(m.group(0)) if m else None
    except Exception:
        return None

def _to_iso_utc(ts: str | None) -> Optional[str]:
    """Accept ISO-ish or epoch seconds; return ISO-8601 Z or None."""
    if not ts:
        return None
    t = ts.strip()
    try:
        if t.endswith('Z'):
            return (
                datetime.fromisoformat(t.replace('Z', '+00:00'))
                .astimezone(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace('+00:00', 'Z')
            )
        if 'T' in t:
            return (
                datetime.fromisoformat(t)
                .astimezone(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace('+00:00', 'Z')
            )
        if re.fullmatch(r'\d{10}', t):  # epoch seconds
            return (
                datetime.fromtimestamp(int(t), tz=timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace('+00:00', 'Z')
            )
    except Exception:
        return None
    return None

def _clamp(x: Optional[float], lo: float, hi: float) -> Optional[float]:
    if x is None:
        return None
    try:
        fx = float(x)
    except Exception:
        return None
    if fx != fx:  # NaN
        return None
    if fx < lo:
        return lo
    if fx > hi:
        return hi
    return fx

def _sanitize_tail(tail: str | None) -> str:
    return (tail or '').strip().upper()

def _parse_flight_reply_payload(subject: str, body: str, fallback_ts: str | None) -> Optional[dict]:
    """
    Returns one canonical dict or None:
      { 'tail','sample_ts_utc','lat','lon','track_deg','speed_kt','alt_ft',
        'receiver_airport','receiver_call','source' }
    Parses JSON, CSV, key:value lines, or falls back to free-text.
    """
    subj = subject or ''
    text = body or ''

    # 0) JSON (object or single-element list)
    try:
        j = json.loads(text)
        rec = j[0] if isinstance(j, list) and j else (j if isinstance(j, dict) else None)
        if isinstance(rec, dict):
            return {
                'tail'            : _sanitize_tail(rec.get('tail') or rec.get('n') or rec.get('aircraft') or ''),
                'sample_ts_utc'   : _to_iso_utc(rec.get('sample_ts_utc') or rec.get('ts') or rec.get('timestamp')),
                'lat'             : _parse_number(rec.get('lat') or rec.get('latitude')),
                'lon'             : _parse_number(rec.get('lon') or rec.get('longitude')),
                'track_deg'       : _parse_number(rec.get('track') or rec.get('trk') or rec.get('heading')),
                'speed_kt'        : _parse_number(rec.get('speed_kt') or rec.get('speed') or rec.get('kt')),
                'alt_ft'          : _parse_number(rec.get('alt_ft') or rec.get('alt') or rec.get('altitude')),
                'receiver_airport': (rec.get('receiver_airport') or rec.get('rx_airport') or rec.get('rx_ap') or '').strip().upper(),
                'receiver_call'   : (rec.get('receiver_call') or rec.get('rx_call') or rec.get('station') or '').strip().upper(),
                'source'          : (rec.get('source') or rec.get('src') or '').strip()
            }
    except Exception:
        pass

    # 1) CSV header?
    try:
        rdr = csv.DictReader(text.splitlines())
        cols = {k.lower().strip(): k for k in (rdr.fieldnames or [])}
        need = {'tail','lat','lon'}
        if need.issubset(cols.keys()):
            rec = next(rdr, None)
            if rec:
                return {
                    'tail'            : _sanitize_tail(rec.get(cols['tail'])),
                    'sample_ts_utc'   : _to_iso_utc(rec.get(cols.get('sample_ts_utc','')) or rec.get(cols.get('ts',''))),
                    'lat'             : _parse_number(rec.get(cols['lat'])),
                    'lon'             : _parse_number(rec.get(cols['lon'])),
                    'track_deg'       : _parse_number(rec.get(cols.get('track','')) or rec.get(cols.get('trk',''))),
                    'speed_kt'        : _parse_number(rec.get(cols.get('speed_kt','')) or rec.get(cols.get('kt',''))),
                    'alt_ft'          : _parse_number(rec.get(cols.get('alt_ft','')) or rec.get(cols.get('alt',''))),
                    'receiver_airport': (rec.get(cols.get('receiver_airport','')) or '').strip().upper(),
                    'receiver_call'   : (rec.get(cols.get('receiver_call','')) or '').strip().upper(),
                    'source'          : (rec.get(cols.get('source','')) or '').strip()
                }
    except Exception:
        pass

    # 2) key:value loose lines
    kv = {}
    for ln in text.splitlines():
        if ':' in ln:
            k, v = ln.split(':', 1)
            kv[k.strip().lower()] = v.strip()
    if kv:
        return {
            'tail'            : _sanitize_tail(kv.get('tail') or kv.get('aircraft') or kv.get('n')),
            'sample_ts_utc'   : _to_iso_utc(kv.get('sample_ts_utc') or kv.get('ts') or kv.get('timestamp')),
            'lat'             : _parse_number(kv.get('lat') or kv.get('latitude')),
            'lon'             : _parse_number(kv.get('lon') or kv.get('longitude')),
            'track_deg'       : _parse_number(kv.get('track') or kv.get('trk') or kv.get('heading')),
            'speed_kt'        : _parse_number(kv.get('speed_kt') or kv.get('speed') or kv.get('kt')),
            'alt_ft'          : _parse_number(kv.get('alt_ft') or kv.get('alt') or kv.get('altitude')),
            'receiver_airport': (kv.get('receiver_airport') or kv.get('rx_airport') or kv.get('rx_ap') or '').strip().upper(),
            'receiver_call'   : (kv.get('receiver_call') or kv.get('rx_call') or kv.get('station') or '').strip().upper(),
            'source'          : (kv.get('source') or kv.get('src') or '').strip()
        }

    # 3) free-text fallback
    tail = None
    m = _TAIL_RE.search(subj + ' ' + text)
    if m:
        tail = m.group(0).upper()
    lat = None
    lon = None
    mll = re.search(r'(-?\d+(?:\.\d+)?)\s*[, ]\s*(-?\d+(?:\.\d+)?)', text)
    if mll:
        lat = _parse_number(mll.group(1))
        lon = _parse_number(mll.group(2))
    ts = None
    mts = re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', text)
    if mts:
        ts = _to_iso_utc(mts.group(0))
    def _num_from(pattern: str) -> Optional[float]:
        mm = re.search(pattern, text, re.I)
        return _parse_number(mm.group(1)) if mm else None
    return {
        'tail'            : _sanitize_tail(tail or ''),
        'sample_ts_utc'   : ts or _to_iso_utc(fallback_ts),
        'lat'             : lat,
        'lon'             : lon,
        'track_deg'       : _num_from(r'\b(?:trk|track|hdg)\s*[:=]?\s*([0-9.]+)'),
        'speed_kt'        : _num_from(r'\b(?:speed|kt|knots?)\b[:=]?\s*([0-9.]+)'),
        'alt_ft'          : _num_from(r'\b(?:alt|altitude)\b[:=]?\s*([0-9.]+)'),
        'receiver_airport': '',
        'receiver_call'   : '',
        'source'          : ''
    }

def ingest_aoct_flight_reply(msg: dict) -> bool:
    """
    Ingest a single inbound AOCT FLIGHT REPLY message into adsb_sightings.
    Returns True only on successful insert (so caller can mark parsed=1).
    """
    subj = (msg.get('subject') or '')
    if not _FLIGHT_REPLY_SUBJ_RE.match(subj):
        return False

    payload = _parse_flight_reply_payload(subj, msg.get('body') or '', msg.get('timestamp'))
    if not payload:
        return False

    tail = _sanitize_tail(payload.get('tail'))
    lat  = _clamp(payload.get('lat'), -90.0, 90.0)
    lon  = _clamp(payload.get('lon'), -180.0, 180.0)
    if not tail or lat is None or lon is None:
        # ignore impossible / missing lat/lon or tail
        return False

    trk = payload.get('track_deg')
    spd = payload.get('speed_kt')
    alt = payload.get('alt_ft')

    trk = None if trk is None else (float(trk) % 360.0)
    spd = None if spd is None else _clamp(spd, 0.0, 1000.0)
    alt = None if alt is None else _clamp(alt, 0.0, 60000.0)

    rx_ap   = canonical_airport_code(payload.get('receiver_airport') or '')
    rx_call = (payload.get('receiver_call') or '').strip().upper()
    source  = (payload.get('source') or '').strip() or 'TAR1090'

    sample_ts = _to_iso_utc(payload.get('sample_ts_utc')) or _to_iso_utc(msg.get('timestamp')) or iso8601_ceil_utc()
    inserted  = iso8601_ceil_utc()

    try:
        with sqlite3.connect(get_db_file()) as c:
            c.execute(
                """
                INSERT INTO adsb_sightings(
                    tail, sample_ts_utc, lat, lon, track_deg, speed_kt, alt_ft,
                    receiver_airport, receiver_call, source, inserted_at_utc
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    tail,
                    sample_ts,
                    float(lat),
                    float(lon),
                    None if trk is None else float(trk),
                    None if spd is None else float(spd),
                    None if alt is None else float(alt),
                    rx_ap or None,
                    rx_call or None,
                    source,
                    inserted,
                ),
            )

            # Optionally update the active locate row for this tail
            c.execute(
                """
                UPDATE flight_locates
                   SET latest_sample_ts_utc = ?,
                       latest_from_airport  = COALESCE(?, latest_from_airport),
                       latest_from_call     = COALESCE(?, latest_from_call)
                 WHERE id = (
                     SELECT id FROM flight_locates
                      WHERE tail = ?
                      ORDER BY requested_at_utc DESC
                      LIMIT 1
                 )
                   AND (
                       latest_sample_ts_utc IS NULL OR latest_sample_ts_utc < ?
                   )
                """,
                (sample_ts, rx_ap or None, rx_call or None, tail, sample_ts),
            )
        return True
    except Exception:
        # never hard-fail the poll endpoint
        return False

# ─────────────────────────────────────────────────────────────────────────────
# Weather auto-ingestion (optional): call this for each Winlink attachment
# whose filename and bytes you’ve extracted from an INBOUND message.
# Slots are keyed by filename (uppercased); WA_FOR_WA is forced to text/plain.
# Returns True only if the attachment was recognized and ingested.
# ─────────────────────────────────────────────────────────────────────────────
WX_KEYS = set(k.upper() for k in get_wx_keys())

def maybe_ingest_weather_attachment(filename: str, data: bytes) -> bool:
    """
    Decide if an inbound attachment should be ingested into weather_products.
    Recognizes any configured key from get_wx_keys(), plus WA_FOR_WA* aliasing.
    """
    try:
        base = (os.path.basename(filename) or "").strip().upper()
        if not base:
            return False
        key = "WA_FOR_WA" if base.startswith("WA_FOR_WA") else base
        if key not in WX_KEYS:
            return False
        # Guess MIME; prefer text/plain when bytes look like ASCII
        mime = (mimetypes.guess_type(filename)[0]
                or ("text/plain" if looks_ascii_text(data) else "application/octet-stream"))
        if key == "WA_FOR_WA":
            mime = "text/plain"
        upsert_weather_product(key, data, mime, source="winlink")
        return True
    except Exception:
        return False

# NOTE: If/when your Winlink parser extracts attachments in the polling path,
# call maybe_ingest_weather_attachment(...) for each attachment payload.
