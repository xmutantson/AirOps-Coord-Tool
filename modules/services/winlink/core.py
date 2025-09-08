
from markupsafe import escape
import sqlite3, re, os, json, subprocess
from datetime import datetime, timezone

from typing import Tuple, Optional, List, Dict

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from modules.utils.common import _mirror_comm_winlink  # unified communications mirror helper
from modules.utils.common import adsb_auto_lookup_tail  # ADS-B on-demand (poller-aware)
from app import DB_FILE
from flask import current_app as app, has_request_context, request

# Mirror helper now imported from modules.utils.common as _mirror_comm_winlink

# --- Winlink parsing regexes (inserted by fix_all_patches.py) ---
air_ops_re = re.compile(r'''
    Air\s*Ops:\s*
    (?P<tail>[A-Z0-9-]+)\s*\|\s*
    (?P<from>[A-Z0-9]{3,4})\s*to\s*(?P<to>[A-Z0-9]{3,4})\s*\|\s*
    (?:took\s*off\s*(?P<tko>\d{1,2}:?\d{2})\s*\|\s*)?
    (?:ETA|Landed)\s*(?P<eta>\d{1,2}:?\d{2})
''', re.IGNORECASE | re.VERBOSE)

cargo_type_re   = re.compile(r"(?im)^\s*Cargo\s*Type(?:\(s\))?\s*[.:=-]+\s*(?P<ct>.+)$")
cargo_weight_re = re.compile(r"(?im)^\s*Total\s+Weight\s+of\s+the\s+Cargo\s*[.:=-]+\s*(?P<wgt>.+)$")
simple_ct_re    = re.compile(r"(?im)^\s*(?:Cargo(?:\s*Type)?|Type)\s*[:=-]\s*(?P<ct>.+)$")
#  Stop remarks before DART footer, "Attachments", a closing quote, or EOF
remarks_re      = re.compile(
    r"(?is)Additional\s+notes/comments:\s*(?P<rm>.+?)(?:\n\s*\{DART|\n\s*Attachments?:|\n\s*\"|\Z)"
)
# --- end regexes ---

def parse_winlink(subj:str, body:str):
    d = dict.fromkeys((
        'tail_number','airfield_takeoff','airfield_landing',
        'takeoff_time','eta','cargo_type','cargo_weight','remarks'
    ), '')

    # FWD/bounce handling: if outer subject isn't an "Air Ops: …", try a quoted inner Subject: from the body.
    if not air_ops_re.search(subj or ""):
        msub = re.search(r"(?im)^\s*Subject:\s*(.+)$", body or "")
        if msub:
            subj = msub.group(1).strip()

    if (m := air_ops_re.search(subj)):
        tail_raw = m.group('tail').strip().upper()
        from_raw = m.group('from').strip().upper()
        to_raw   = m.group('to').strip().upper()
        tko_raw  = m.group('tko') or ''       # None if skipped → ''
        eta_raw  = m.group('eta') or ''

        d.update(
          tail_number      = tail_raw,
          airfield_takeoff = from_raw,
          airfield_landing = to_raw,
          takeoff_time     = hhmm_norm(tko_raw),
          eta              = hhmm_norm(eta_raw)
        )

    # 1) strict dotted match first…
    if (m := cargo_type_re.search(body)):
        raw = m['ct'].strip()

    # 2) …else try the lenient fallback
    else:
        m2 = simple_ct_re.search(body)
        raw = m2['ct'].strip() if m2 else ''

    # strip any leading/trailing punctuation or whitespace
    raw = raw.strip(" .:-*")

    # 3) strip stray leading "s " (e.g. "s food" → "food")
    if raw.lower().startswith('s '):
        raw = raw[2:].lstrip()

    d['cargo_type'] = escape(raw)

    if (m := cargo_weight_re.search(body)):
        # strip punctuation
        wgt_raw = m.group('wgt').strip().strip(" .:-*")
        d['cargo_weight'] = escape(parse_weight_str(wgt_raw))

    if (m := remarks_re.search(body)):
        # collapse any run of whitespace (including newlines) into a single space
        remark_text = m.group('rm')
        remark_text = re.sub(r'\s+', ' ', remark_text).strip()
        # strip leading/trailing punctuation, colons or braces
        remark_text = remark_text.strip(" .:-*{}")
        # drop any training tags like WGID:… that slipped into the body
        remark_text = re.sub(r'\bWGID:[a-f0-9]{16,}\b', '', remark_text, flags=re.I)
        remark_text = re.sub(r'\s{2,}', ' ', remark_text).strip()
        d['remarks'] = escape(remark_text)

    return d

# ─────────────────────────────────────────────────────────────────────────────
# AOCT helpers
# ─────────────────────────────────────────────────────────────────────────────
_SUBJECT_PREFIX = re.compile(r'^(?:\s*(?:subject|subj|re|fw|fwd|ack)\s*:?\s*)+', re.I)

def classify_aoct_subject(subject: str) -> Optional[str]:
    """
    Return 'query' | 'reply' | 'status' if the subject contains those AOCT tokens
    (case/punctuation/ordering insensitive). Otherwise None.
    """
    s = _SUBJECT_PREFIX.sub('', subject or '').lower()
    toks = re.findall(r'[a-z0-9]+', s)
    st = set(toks)
    # Accept either "cargo" or "flight" families.
    if {'aoct','query'}.issubset(st)  and (('cargo' in st)  or ('flight' in st)):  return 'query'
    if {'aoct','reply'}.issubset(st)  and (('cargo' in st)  or ('flight' in st)):  return 'reply'
    if {'aoct','status'}.issubset(st) and (('cargo' in st)  or ('flight' in st)):  return 'status'
    return None

def _pat_candidate_paths():
    """All places we might find PAT's config.json inside the container."""
    return [
        os.path.expanduser("~/.wl2k/config.json"),
        os.path.expanduser("~/.config/pat/config.json"),
        "/root/.wl2k/config.json",
        "/root/.config/pat/config.json",
        "/app/.wl2k/config.json",
        "/app/.config/pat/config.json",
    ]

def pat_config_status() -> Tuple[bool, Optional[str], str]:
    """
    Returns (ok, path, reason)
      ok     : True only if config.json exists AND looks configured.
      path   : Which config.json we used (or None if not found).
      reason : If not ok, a short string explaining why.

    Heuristic for "configured":
      • mycall is non-blank
      • secure_login_password is non-blank
    """
    for p in _pat_candidate_paths():
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as e:
            return (False, p, f"unreadable JSON: {e}")

        mycall = str(data.get("mycall", "")).strip()
        pw     = str(data.get("secure_login_password", "")).strip()

        if not mycall:
            return (False, p, "mycall is blank")
        if not pw:
            return (False, p, "secure_login_password is blank")

        # Looks good enough to proceed.
        return (True, p, "")

    return (False, None, "PAT config is missing or incomplete")

def pat_config_exists() -> bool:
    """
    Back-compat shim used elsewhere. Now returns True only
    when PAT config appears *configured*, not merely present.
    """
    ok, _, _ = pat_config_status()
    return ok

def _configure_pat_from_prefs_silent():
    """
    Core writer for ~/.config/pat/config.json using DB prefs.
    Identical to /configure_pat but without flash/redirect so it can run at boot.
    Returns (ok: bool, err_str: str|None).
    """
    try:
        # primary WinLink credentials
        cs = get_preference('winlink_callsign_1') or ''
        pw = get_preference('winlink_password_1') or ''

        # determine PAT config path
        home     = os.path.expanduser('~')
        cfg_dir  = os.path.join(home, '.config', 'pat')
        cfg_file = os.path.join(cfg_dir, 'config.json')

        os.makedirs(cfg_dir, exist_ok=True)
        # load existing or start fresh
        cfg = {}
        if os.path.exists(cfg_file):
            with open(cfg_file, 'r') as f:
                cfg = json.load(f)

        # update primary credentials
        cfg['mycall']                = cs
        cfg['secure_login_password'] = pw

        # build auxiliary addresses
        aux_list = []
        for idx in (2, 3):
            call = get_preference(f'winlink_callsign_{idx}') or ''
            pwd  = get_preference(f'winlink_password_{idx}') or ''
            if call and pwd:
                aux_list.append({"address": call, "password": pwd})
        cfg['auxiliary_addresses'] = aux_list

        with open(cfg_file, 'w') as f:
            json.dump(cfg, f, indent=2)
        return True, None
    except Exception as e:
        try:
            app.logger.exception("Failed to configure PAT at boot")
        except Exception:
            pass
        return False, str(e)

def _boot_pat_and_winlink():
    from modules.utils.common import get_preference
    if get_preference('wargame_mode') == 'yes':
        # make sure Winlink jobs aren’t running
        try:
            from app import scheduler
            for jid in ('winlink_poll', 'winlink_parse', 'winlink_auto_send'):
                try:
                    scheduler.remove_job(jid)
                except Exception:
                    pass
        except Exception:
            pass
        return
    # Make this handler run only once on the very first request.
    # (Flask 3.x removed before_first_request; replicate behavior by self-removal.)
    try:
        app.before_request_funcs[None].remove(_boot_pat_and_winlink)
    except Exception:
        pass
    # Try to ensure PAT creds are present on disk (idempotent).
    _configure_pat_from_prefs_silent()
    # Auto-start polling/parsing so the UI has data without manual clicks.
    try:
        # Lazy import to avoid circulars if this ever runs
        from modules.services.jobs import configure_winlink_jobs, configure_inventory_broadcast_job
        configure_winlink_jobs()
        configure_inventory_broadcast_job()
    except Exception:
        # Don't crash startup if scheduler init fails.
        pass

def generate_body(flight, callsign=None, include_test=None):
    """Build the WinLink message body for a flight.
    If callsign/include_test are not provided, use cookie (if request context); else fallback.
    """

    # Fallback logic for callsign/include_test
    if callsign is None or include_test is None:
        if has_request_context():
            if callsign is None:
                callsign = request.cookies.get('operator_call', 'YOURCALL').upper()
            if include_test is None:
                include_test = request.cookies.get('include_test', 'yes') == 'yes'
        else:
            if callsign is None:
                callsign = "A-O-C-T"
            if include_test is None:
                include_test = False
    # Count previous messages for this callsign
    with sqlite3.connect(DB_FILE) as c:
        cnt = c.execute(
            "SELECT COUNT(*) FROM flight_history "
            "WHERE json_extract(data,'$.operator_call') = ?",
            (callsign,)
        ).fetchone()[0]
    msg_num = f"{cnt + 1:03}"

    lines = []
    if include_test:
        lines.append("**** TEST MESSAGE ONLY  (if actual flight, delete). ****")
    lines.append(f"{callsign} message number {msg_num}.")
    lines.append("")
    lines.append(f"Aircraft {flight['tail_number']}:")
    lines.append(f"  Cargo Type(s) ................. {flight.get('cargo_type','none')}")
    lines.append(f"  Total Weight of the Cargo ..... {flight.get('cargo_weight','none')}")
    lines.append("")
    lines.append("Additional notes/comments:")
    lines.append(f"  {flight.get('remarks','')}")

    # --- Ensure a Flight Code is present in the body ---
    # 1) use existing if valid; 2) otherwise compute from origin/dest + server date/time
    fc = (flight.get('flight_code') or '').strip().upper()
    info = parse_flight_code(fc) if fc else None
    if not info:
        try:
            o_raw = (flight.get('airfield_takeoff') or '').strip().upper()
            d_raw = (flight.get('airfield_landing') or '').strip().upper()
            ooo = to_three_char_code(o_raw) or (o_raw[:3] if o_raw else '')
            ddd = to_three_char_code(d_raw) or (d_raw[:3] if d_raw else '')
            if len(ooo)==3 and len(ddd)==3:
                mmddyy = datetime.utcnow().strftime('%m%d%y')   # server date
                hhmm   = datetime.utcnow().strftime('%H%M')     # server time
                fc = find_unique_code_or_bump(ooo, mmddyy, ddd, hhmm)
                info = parse_flight_code(fc)
        except Exception:
            fc = ''
    if fc and info:
        lines.append("  ")
        lines.append(f"  Flight Code: {fc}")
    lines.append("")
    lines.append("{DART Aircraft Takeoff Report, rev. 2024-05-14}")

    return "\n".join(lines)

def generate_subject(flight):
    """Build the WinLink message subject line for a flight."""
    if flight.get('direction') == 'inbound':
        return (
            f"Air Ops: {flight['tail_number']} | "
            f"{flight['airfield_takeoff']} to {flight['airfield_landing']} | "
            f"Landed {flight['eta'] or '----'}"
        )
    else:
        return (
            f"Air Ops: {flight['tail_number']} | "
            f"{flight['airfield_takeoff']} to {flight['airfield_landing']} | "
            f"took off {flight['takeoff_time'] or '----'} | "
            f"ETA {flight['eta'] or '----'}"
        )

# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: AOCT cargo query parser + send helper
# ─────────────────────────────────────────────────────────────────────────────
_q_airport_re   = re.compile(r"(?im)^\s*AIRPORT\s*:\s*([A-Z0-9\-]+)\s*$")
_q_cats_re      = re.compile(r"(?im)^\s*CATEGORIES?\s*:\s*(.+)$")
_q_csv_re       = re.compile(r"(?im)^\s*CSV\s*:\s*(yes|no)\s*$")
_tok_norm_re    = re.compile(r"[^a-z0-9]+")

def _tok_norm(s: str) -> str:
    return _tok_norm_re.sub("-", (s or "").strip().lower()).strip("-")

def parse_aoct_cargo_query(body: str) -> Dict:
    """
    Parse AOCT cargo query body.
      • AIRPORT: <token>  (or first non-empty line)
      • CATEGORIES: a, b, c  (optional)
      • CSV: yes/no          (optional; default yes)
    """
    body = body or ""
    airport = None
    m = _q_airport_re.search(body)
    if m:
        airport = m.group(1).strip().upper()
    else:
        # Fallback: first non-empty line's first token
        for ln in body.splitlines():
            ln = (ln or "").strip()
            if not ln:
                continue
            airport = ln.split()[0].strip().upper()
            break
    airport = canonical_airport_code(airport or "")

    cats: List[str] = []
    m = _q_cats_re.search(body)
    if m:
        raw = m.group(1)
        # accept separators: comma, semicolon, slash, pipe, or multi-space
        parts = re.split(r"[,\;/\|]+|\s{2,}", raw)
        cats = [_tok_norm(x) for x in parts if (x or "").strip()]

    wants_csv = True
    m = _q_csv_re.search(body)
    if m:
        wants_csv = (m.group(1).strip().lower() != "no")

    return {"airport": airport, "categories": cats, "wants_csv": wants_csv}

# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: AOCT Flight Query/Reply — parsing & builders
# ─────────────────────────────────────────────────────────────────────────────
_fq_tail_re   = re.compile(r"(?im)^\s*TAIL\s*:\s*([A-Z0-9-]+)\s*$")
_fq_from_re   = re.compile(r"(?im)^\s*FROM[_\s-]*AIRPORT\s*:\s*([A-Z0-9]{3,4})\s*$")
_fq_csv_re    = re.compile(r"(?im)^\s*CSV\s*:\s*(yes|no)\s*$")
_fq_note_re   = re.compile(r"(?im)^\s*NOTE\s*:\s*(.+)$")

_fr_tail_re   = _fq_tail_re
_fr_pos_re    = re.compile(r"(?im)^\s*POSITION\s*:\s*([+-]?\d+(?:\.\d+)?)\s*,\s*([+-]?\d+(?:\.\d+)?)\s*$")
_fr_track_re  = re.compile(r"(?im)^\s*TRACK[_\s-]*DEG\s*:\s*([\d.]+)\s*$")
_fr_gs_re     = re.compile(r"(?im)^\s*GROUND[_\s-]*SPEED[_\s-]*KT\s*:\s*([\d.]+)\s*$")
_fr_alt_re    = re.compile(r"(?im)^\s*ALTITUDE[_\s-]*FT\s*:\s*([\d.]+)\s*$")
_fr_ts_re     = re.compile(r"(?im)^\s*SAMPLE[_\s-]*TS\s*:\s*([0-9T:\-+.Zz]+)\s*$")
_fr_recv_ap   = re.compile(r"(?im)^\s*RECEIVER[_\s-]*AIRPORT\s*:\s*([A-Z0-9]{3,4})\s*$")
_fr_recv_call = re.compile(r"(?im)^\s*RECEIVER[_\s-]*CALL\s*:\s*([A-Z0-9-]+)\s*$")
_fr_source_re = re.compile(r"(?im)^\s*SOURCE\s*:\s*([A-Z0-9_-]+)\s*$")

def _iso_to_utc_z(ts_raw: str) -> tuple[str, bool]:
    """
    Normalize an ISO-8601 timestamp string to 'YYYY-MM-DDTHH:MM:SSZ'.
    If input has an offset, convert to UTC. If naive (no tzinfo), treat as UTC
    and return tz_guess=True. If parsing fails, fall back to current UTC and
    log a warning (tz_guess=True).
    """
    try:
        s = (ts_raw or "").strip()
        # Make Python happy with 'Z'
        s = s.replace("z", "Z")
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z"), False
        # Try general ISO parser (may be naive or offset-aware)
        dt = datetime.fromisoformat(s)
        tz_guess = False
        if dt.tzinfo is None:
            # Treat as UTC per spec (log tz_guess=true)
            tz_guess = True
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.replace(microsecond=0).isoformat().replace("+00:00","Z"), tz_guess
    except Exception:
        # Defensive: never crash on malformed inputs
        try:
            app.logger.warning("AOCT timestamp parse failed; using current UTC. raw=%r", ts_raw)
        except Exception:
            pass
        from modules.utils.common import iso8601_ceil_utc  # local import to avoid cycles
        return iso8601_ceil_utc(), True

def parse_aoct_flight_query(body: str) -> Dict:
    """
    Parse AOCT Flight Query.
      Required: TAIL, FROM_AIRPORT
      Optional: CSV (YES/NO, default NO), NOTE
    Returns dict: {'tail','from_airport','wants_csv','note'}
    """
    text = body or ""
    m = _fq_tail_re.search(text)
    tail = (m.group(1).strip().upper() if m else "")
    m = _fq_from_re.search(text)
    from_ap = canonical_airport_code(m.group(1).strip().upper() if m else "")
    wants_csv = False  # default for flight queries (spec example shows "CSV: NO")
    m = _fq_csv_re.search(text)
    if m:
        wants_csv = (m.group(1).strip().lower() == 'yes')
    note = ""
    m = _fq_note_re.search(text)
    if m:
        note = m.group(1).strip()
    return {
        "tail": tail,
        "from_airport": from_ap,
        "wants_csv": wants_csv,
        "note": note,
    }

def parse_aoct_flight_reply(body: str) -> Dict:
    """
    Parse AOCT Flight Reply.
    Returns fields (strings or numbers where appropriate) and a normalized
    SAMPLE_TS in UTC '...Z'. Adds 'tz_guess': bool when input timestamp lacked tz.
    """
    text = body or ""
    out: Dict[str, object] = {
        "tail": "",
        "position": None,  # (lat, lon)
        "track_deg": None,
        "ground_speed_kt": None,
        "altitude_ft": None,
        "sample_ts": "",
        "receiver_airport": "",
        "receiver_call": "",
        "source": "",
        "tz_guess": False,
    }
    if (m := _fr_tail_re.search(text)):
        out["tail"] = m.group(1).strip().upper()
    if (m := _fr_pos_re.search(text)):
        try:
            lat = float(m.group(1))
            lon = float(m.group(2))
            # Defensive: ignore malformed lat/lon
            if -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0:
                out["position"] = (lat, lon)
        except Exception:
            pass
    if (m := _fr_track_re.search(text)):
        try:
            val = float(m.group(1))
            out["track_deg"] = float(val % 360.0)
        except Exception: pass
    if (m := _fr_gs_re.search(text)):
        try:
            from modules.utils.common import clamp_range  # lazy to avoid cycles
            out["ground_speed_kt"] = clamp_range(float(m.group(1)), 0.0, 800.0)
        except Exception:
            pass
    if (m := _fr_alt_re.search(text)):
        try:
            from modules.utils.common import clamp_range
            out["altitude_ft"] = clamp_range(float(m.group(1)), -1000.0, 60000.0)
        except Exception: pass
    if (m := _fr_ts_re.search(text)):
        iso_raw = m.group(1).strip()
        ts_norm, tz_guess = _iso_to_utc_z(iso_raw)
        out["sample_ts"] = ts_norm
        out["tz_guess"] = tz_guess
        if tz_guess:
            try: app.logger.info("AOCT flight reply SAMPLE_TS treated as UTC (tz_guess=true): %s", iso_raw)
            except Exception: pass
    if (m := _fr_recv_ap.search(text)):
        out["receiver_airport"] = canonical_airport_code(m.group(1).strip().upper())
    if (m := _fr_recv_call.search(text)):
        out["receiver_call"] = m.group(1).strip().upper()
    if (m := _fr_source_re.search(text)):
        out["source"] = m.group(1).strip().upper()
    return out

def build_aoct_flight_query_body(tail: str, from_airport: str, csv: str = 'NO', note: str = 'Reply with your last known ADS-B sighting if any.') -> str:
    """
    Build body for AOCT flight query (subject handled by caller).
    """
    tail = (tail or '').strip().upper()
    ap = canonical_airport_code((from_airport or '').strip().upper())
    csv = (csv or 'NO').strip().upper()
    note = (note or '').strip()
    lines = [
        f"TAIL: {tail}",
        f"FROM_AIRPORT: {ap}",
        f"CSV: {csv}",
    ]
    if note:
        lines.append(f"NOTE: {note}")
    lines.append("{AOCT flight query, rev. 2025-09-01}")
    return "\n".join(lines)

def build_aoct_flight_reply_body(sample: Dict) -> str:
    """
    Build body for AOCT flight reply from a sample dict.
    Expected keys: tail, lat, lon (or position tuple), track_deg, ground_speed_kt,
                   altitude_ft, sample_ts (ISO), receiver_airport, receiver_call, source.
    """
    tail = (sample.get('tail') or '').strip().upper()
    # Accept either a (lat, lon) tuple or discrete lat/lon fields; be defensive if absent.
    lat = lon = None
    if 'position' in sample and isinstance(sample.get('position'), (tuple, list)) and len(sample.get('position')) == 2:
        lat, lon = sample['position']
    else:
        lat = sample.get('lat')
        lon = sample.get('lon')
    has_pos = (lat is not None) and (lon is not None)
    track = sample.get('track_deg')
    # accept either alias
    gs = sample.get('ground_speed_kt')
    if gs is None: gs = sample.get('speed_kt')
    alt = sample.get('altitude_ft')
    if alt is None: alt = sample.get('alt_ft')
    ts_norm, tz_guess = _iso_to_utc_z(str(sample.get('sample_ts') or sample.get('sample_ts_utc') or ''))
    if tz_guess:
        try: app.logger.info("AOCT flight reply SAMPLE_TS treated as UTC (tz_guess=true): %s", sample.get('sample_ts'))
        except Exception: pass
    recv_ap = canonical_airport_code((sample.get('receiver_airport') or '').strip().upper())
    recv_cs = (sample.get('receiver_call') or '').strip().upper()
    src = (sample.get('source') or '').strip().upper()
    pos_line = f"POSITION: {float(lat):.4f},{float(lon):.4f}" if has_pos else "POSITION: "
    lines = [
        f"TAIL: {tail}",
        pos_line,
        f"TRACK_DEG: {int(round(float(track)))}" if track is not None else "TRACK_DEG: ",
        f"GROUND_SPEED_KT: {int(round(float(gs)))}" if gs is not None else "GROUND_SPEED_KT: ",
        f"ALTITUDE_FT: {int(round(float(alt)))}" if alt is not None else "ALTITUDE_FT: ",
        f"SAMPLE_TS: {ts_norm}",
        f"RECEIVER_AIRPORT: {recv_ap}",
        f"RECEIVER_CALL: {recv_cs}",
        f"SOURCE: {src}",
        "{AOCT flight reply, rev. 2025-09-01}",
    ]
    return "\n".join(lines)

def _normalize_comm_metadata(md: Optional[Dict]) -> Optional[Dict]:
    """
    Ensure AOCT comms metadata uses canonical keys required by /comms.
    Aliases supported:
      - 'tail' -> 'tail_number'
    """
    if not isinstance(md, dict):
        return md
    out = dict(md)  # shallow copy
    if 'tail' in out and 'tail_number' not in out:
        out['tail_number'] = out.pop('tail')
    # Ensure keys exist (helpful for UI filters even when empty)
    for k in ('tail_number', 'sample_ts', 'receiver_call', 'receiver_airport', 'source'):
        out.setdefault(k, "")
    return out

def send_winlink_message(to_addr: str, subject: str, body: str, metadata: Optional[Dict] = None) -> bool:
    """
    Minimal helper to send a text Winlink message via PAT.
    Records in winlink_messages and outgoing_messages on success.
    """
    to_addr = (to_addr or "").strip()
    if not to_addr:
        return False
    cs = get_preference('winlink_callsign_1') or ""
    if not cs:
        return False
    cmd = ["pat", "compose", "--from", cs, "-s", subject, to_addr]
    try:
        subprocess.run(
            cmd,
            input=body or "",
            text=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as err:
        try: app.logger.error("PAT send failed (AOCT reply): %s\n%s", err, err.stderr or err.stdout)
        except Exception: pass
        return False

    # Mirror to DB on success
    try:
        # Best-guess operator (local side): cookie if present, else station callsign
        operator = (
            request.cookies.get('operator_call', cs)
            if has_request_context() else cs
        ).upper()

        with sqlite3.connect(DB_FILE) as conn:
            ts_iso = iso8601_ceil_utc()
            conn.execute("""
                INSERT INTO winlink_messages
                  (direction, callsign, sender, subject, body)
                VALUES ('out', ?, ?, ?, ?)
            """, (cs, to_addr, subject, body))
            conn.execute("""
                INSERT INTO outgoing_messages (flight_id, operator_call, timestamp, subject, body)
                VALUES (?,?,?,?,?)
            """, (
                0,  # flight_id may be NOT NULL on some DBs; use 0 when unknown
                operator, ts_iso, subject, body))
            # ---- communications mirror (outbound) ----
            try:

                # If metadata not supplied, try to auto-build it for AOCT Flight Replies,
                # otherwise fall back to Air Ops subject parsing for tail number.
                meta_final: Optional[Dict] = None
                if metadata is not None:
                    meta_final = _normalize_comm_metadata(metadata)
                else:
                    # Is this an AOCT Flight Reply we're sending?
                    fam = classify_aoct_subject(subject or "")
                    stoks = set(re.findall(r'[a-z0-9]+', (subject or '').lower()))
                    if fam == 'reply' and 'flight' in stoks:
                        try:
                            parsed = parse_aoct_flight_reply(body or "")
                            # Build canonical metadata doc
                            ts_norm, _ = _iso_to_utc_z(str(parsed.get('sample_ts') or ''))
                            meta_final = {
                                "tail_number": parsed.get('tail') or "",
                                "sample_ts": ts_norm,
                                "receiver_call": parsed.get('receiver_call') or "",
                                "receiver_airport": parsed.get('receiver_airport') or "",
                                "source": (parsed.get('source') or '').strip().upper() or "TAR1090",
                            }
                        except Exception:
                            meta_final = None
                    else:
                        # Try to pull a tail# if this was an “Air Ops” message
                        tail = ''
                        try:
                            tail = (parse_winlink(subject, body) or {}).get('tail_number', '')  # type: ignore
                        except Exception:
                            pass
                        if tail:
                            meta_final = {"tail_number": tail}
                _mirror_comm_winlink(
                    ts_iso, "out",
                    from_party=cs,
                    to_party=to_addr,
                    subject=subject,
                    body=body,
                    operator=operator,
                    metadata=meta_final
                )
            except Exception:
                pass
    except Exception:
        pass
    return True

# ─────────────────────────────────────────────────────────────────────────────
# Inbound AOCT Flight Query → optional auto-reply with latest local sighting
# ─────────────────────────────────────────────────────────────────────────────
def _subject_tokens(s: str) -> set[str]:
    s = _SUBJECT_PREFIX.sub('', s or '').lower()
    return set(re.findall(r'[a-z0-9]+', s))

def _latest_local_adsb_sample(tail: str, lookup_fn=None) -> Optional[Dict]:
    """
    Return a dict compatible with build_aoct_flight_reply_body(), or None.
    Prefers the local poller DB when enabled; else uses an on-demand lookup.
    If lookup_fn is provided, it will be used for the on-demand fetch; otherwise
    defaults to modules.utils.common.adsb_auto_lookup_tail.
    """
    tail = (tail or '').strip().upper()
    if not tail:
        return None
    # Prefer the background poller’s DB if enabled
    if (get_preference('adsb_poll_enabled') or '').strip().lower() == 'yes':
        rows = dict_rows("""
            SELECT tail, sample_ts_utc, lat, lon, track_deg, speed_kt, alt_ft,
                   receiver_airport, receiver_call, source
              FROM adsb_sightings
             WHERE tail = ?
             ORDER BY sample_ts_utc DESC
             LIMIT 1
        """, (tail,))
        if rows:
            r = rows[0]
            return {
                "tail": tail,
                "position": (float(r['lat']), float(r['lon'])),
                "track_deg": r.get('track_deg'),
                "ground_speed_kt": r.get('speed_kt'),
                "altitude_ft": r.get('alt_ft'),
                "sample_ts": r.get('sample_ts_utc'),
                "receiver_airport": canonical_airport_code(r.get('receiver_airport') or ''),
                "receiver_call": (r.get('receiver_call') or '').strip().upper(),
                "source": (r.get('source') or 'TAR1090').strip().upper() or 'TAR1090',
            }

    # Fallback: on-demand (poller-aware) lookup
    stub = (lookup_fn or adsb_auto_lookup_tail)(tail)
    if stub:
        # Normalize stub keys to what the builder expects
        lat = stub.get('lat'); lon = stub.get('lon')
        if lat is None or lon is None:
            return None
        return {
            "tail": tail,
            "position": (float(lat), float(lon)),
            "track_deg": stub.get('track_deg'),
            "ground_speed_kt": stub.get('speed_kt'),
            "altitude_ft": stub.get('alt_ft'),
            "sample_ts": stub.get('sample_ts_utc') or stub.get('sample_ts'),
            "receiver_airport": canonical_airport_code(stub.get('receiver_airport') or ''),
            "receiver_call": (stub.get('receiver_call') or '').strip().upper(),
            "source": (stub.get('source') or 'TAR1090').strip().upper() or 'TAR1090',
        }
    return None

def maybe_auto_reply_flight_query(msg_row: Dict, lookup_fn=None) -> bool:
    """
    Decide whether to auto-reply to an inbound AOCT Flight Query row and do so.
    Returns True if message was recognized/handled as a Flight Query (reply may
    or may not have been sent depending on local sighting availability).
    """
    try:
        subject = msg_row.get('subject') or ''
        body    = msg_row.get('body') or ''
        sender  = (msg_row.get('sender') or '').strip().upper()
        ts_in   = msg_row.get('timestamp') or iso8601_ceil_utc()

        fam = classify_aoct_subject(subject or "")
        toks = _subject_tokens(subject or "")
        if fam != 'query' or ('flight' not in toks):
            return False  # not an AOCT Flight Query

        q = parse_aoct_flight_query(body or "")
        tail = (q.get('tail') or '').strip().upper()
        if not tail:
            return False  # malformed query; let other handlers consider it

        # Mirror the inbound query to communications (best-effort)
        try:
            _mirror_comm_winlink(
                ts_in, "in",
                from_party=sender,
                to_party=(get_preference('winlink_callsign_1') or 'OPERATOR'),
                subject=subject, body=body,
                operator=None,
                metadata={"tail_number": tail, "sample_ts": "", "receiver_call": "", "receiver_airport": "", "source": ""}
            )
        except Exception:
            pass

        # Respect site preference
        if (get_preference('aoct_auto_reply_flight') or '').strip().lower() != 'yes':
            return True  # handled (recognized and mirrored), but no auto-reply

        # Look up latest local ADS-B sample (prefer poller DB; otherwise provided lookup_fn)
        sample = _latest_local_adsb_sample(tail, lookup_fn=lookup_fn)
        if not sample:
            return True  # handled (no reply if no sighting)

        # Ensure timestamp normalized for metadata
        ts_norm, _tz_guess = _iso_to_utc_z(str(sample.get('sample_ts') or ''))

        # Build and send reply
        reply_body = build_aoct_flight_reply_body(sample)
        reply_subj = f"AOCT Flight Reply: {tail}"
        meta = {
            "tail_number": tail,
            "sample_ts": ts_norm,
            "receiver_call": sample.get('receiver_call') or '',
            "receiver_airport": sample.get('receiver_airport') or '',
            "source": sample.get('source') or 'TAR1090',
        }
        if sender:
            send_winlink_message(sender, reply_subj, reply_body, metadata=meta)
        return True
    except Exception:
        try: app.logger.exception("maybe_auto_reply_flight_query failed")
        except Exception: pass
        return False
