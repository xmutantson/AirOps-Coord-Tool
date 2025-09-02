
from markupsafe import escape
import sqlite3, re, os, json, subprocess
from datetime import datetime

from typing import Tuple, Optional, List, Dict

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from app import DB_FILE
from flask import current_app, has_request_context, request
app = current_app  # legacy shim for helpers

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
        cats = [ _tok_norm(x) for x in raw.split(",") if (x or "").strip() ]

    wants_csv = True
    m = _q_csv_re.search(body)
    if m:
        wants_csv = (m.group(1).strip().lower() != "no")

    return {"airport": airport, "categories": cats, "wants_csv": wants_csv}

def send_winlink_message(to_addr: str, subject: str, body: str) -> bool:
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
            """, (None, "A-O-C-T", ts_iso, subject, body))
    except Exception:
        pass
    return True
