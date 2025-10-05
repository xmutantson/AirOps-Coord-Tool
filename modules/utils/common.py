# ---- compat shims for app-level globals (avoid circular imports) ----
import sys as _sys, logging as _logging, re as _re, random as _random
from functools import lru_cache
from typing import List, Iterable, Optional

# Safe fallbacks so static analysis and runtime don’t crash if app globals aren’t ready yet.
SQL_TRACE = False
SQL_TRACE_EXPANDED = False
_sql_logger = _logging.getLogger("sql")
TraceConn = None
# sql logger exists even if not configured; WARNINGs will still show

_zeroconf = None
MDNS_NAME = ""
HOST_IP = ""
MDNS_REASON = ""

HARDCODED_AIRFIELDS = []
WARGAME_ITEMS = {}
AIRFIELD_CALLSIGNS = {}

# one-time init flags for background workers
_wg_scheduler_inited = False
_distance_thread_started = False
_radio_started = False

DASHY_RE = _re.compile(r'^[\s\-_‒–—―]+$')
logger = _logging.getLogger(__name__)
ENGLISH_ADJECTIVES = set()
# Throttle guard for background-y DB tidy
_pending_cleanup_last = 0.0

# stray alias used in a few helpers
_r = _random

# Safe defaults so import-time references don't crash (overridden by _hydrate_from_app).
get_wargame_role_epoch       = lambda: ""
configure_wargame_jobs       = lambda *a, **k: None
wargame_start_radio_outbound = lambda *a, **k: None
wargame_finish_radio_outbound= lambda *a, **k: None
wargame_start_ramp_inbound   = lambda *a, **k: None

# --- DB-backed fallbacks so generator caps work even if app doesn’t inject helpers ---
def _wg_task_db_start(role, kind, key, *, gen_at=None, sched_for=None):
    try:
        from datetime import datetime as _dt
        import sqlite3
        ts_now = _dt.utcnow().isoformat()
        gen_at = gen_at or ts_now
        from modules.utils.common import get_db_file  # self-import safe at runtime
        with sqlite3.connect(get_db_file()) as c:
            c.execute("""
                INSERT OR IGNORE INTO wargame_tasks(role, kind, key, gen_at, sched_for, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (role, kind, key, gen_at, sched_for, ts_now))
    except Exception:
        logger.debug("wargame_task_start fallback failed", exc_info=True)

def _wg_task_db_finish(role, kind, key):
    try:
        import sqlite3
        from modules.utils.common import get_db_file
        with sqlite3.connect(get_db_file()) as c:
            c.execute("DELETE FROM wargame_tasks WHERE role=? AND kind=? AND key=?", (role, kind, key))
    except Exception:
        logger.debug("wargame_task_finish fallback failed", exc_info=True)

def _wg_task_db_start_once(role, kind, key, *, gen_at=None, sched_for=None):
    try:
        from modules.utils.common import dict_rows
        rows = dict_rows("SELECT 1 FROM wargame_tasks WHERE role=? AND kind=? AND key=? LIMIT 1",
                         (role, kind, key))
        if rows:
            return False
    except Exception:
        # best-effort: if lookup failed, still attempt start to avoid duplicates later
        pass
    _wg_task_db_start(role, kind, key, gen_at=gen_at, sched_for=sched_for)
    return True

# Defaults; _hydrate_from_app() will overwrite with app-provided versions if present.
wargame_task_start      = _wg_task_db_start
wargame_task_finish     = _wg_task_db_finish
wargame_task_start_once = _wg_task_db_start_once

def _hydrate_from_app():
    """Copy known globals from the running app module, if available."""
    mod = _sys.modules.get("app")
    if not mod:
        return
    for name in (
        "SQL_TRACE", "SQL_TRACE_EXPANDED", "_sql_logger", "TraceConn",
        "_zeroconf", "MDNS_NAME", "HOST_IP",
        "HARDCODED_AIRFIELDS", "WARGAME_ITEMS",
        "DASHY_RE", "logger", "ENGLISH_ADJECTIVES",
    ):
        if hasattr(mod, name):
            globals()[name] = getattr(mod, name)

    # Optional callables; default to no-ops if app doesn’t provide them
    globals()["get_wargame_role_epoch"]       = getattr(mod, "get_wargame_role_epoch",       get_wargame_role_epoch)
    globals()["configure_wargame_jobs"]       = getattr(mod, "configure_wargame_jobs",       configure_wargame_jobs)
    globals()["wargame_task_start"]           = getattr(mod, "wargame_task_start",           wargame_task_start)
    globals()["wargame_task_finish"]          = getattr(mod, "wargame_task_finish",          wargame_task_finish)
    globals()["wargame_task_start_once"]      = getattr(mod, "wargame_task_start_once",      wargame_task_start_once)
    globals()["wargame_start_radio_outbound"] = getattr(mod, "wargame_start_radio_outbound", wargame_start_radio_outbound)
    globals()["wargame_finish_radio_outbound"]= getattr(mod, "wargame_finish_radio_outbound",wargame_finish_radio_outbound)
    globals()["wargame_start_ramp_inbound"]   = getattr(mod, "wargame_start_ramp_inbound",   wargame_start_ramp_inbound)

# Try once at import time; it’s fine if many values aren’t there yet.
_hydrate_from_app()

import random, string

import uuid
from markupsafe import escape
import sqlite3, csv, re, os, json, base64, mimetypes
from datetime import datetime, timedelta, timezone
import threading, time, socket, math
from urllib.request import urlopen
from zeroconf import ServiceInfo, NonUniqueNameException
import fcntl
import struct
from flask_wtf.csrf import generate_csrf
from radio_tx import start_radio_tx
try:
    from radio_tx import start_radio_tx
except Exception:
    # Optional dependency: keep import-time failures from crashing the app.
    # _start_radio_tx_once() already wraps usage in try/except.
    def start_radio_tx(*args, **kwargs):  # type: ignore
        raise RuntimeError("radio_tx.start_radio_tx unavailable")

from flask import current_app
from flask import flash, jsonify, make_response, redirect, render_template, request, session, url_for
app = current_app  # legacy shim for helpers

# ---- SQL diagnostics toggles (env-driven) -------------------------------
#  AOCT_SQL_SLOW_MS   : float, default 50 (log queries >= threshold)
#  AOCT_SQL_LOG       : 1/true to log ALL queries executed via dict_rows()
#  AOCT_SQL_EXPLAIN   : 1/true to log EXPLAIN QUERY PLAN for slow SELECTs
#  AOCT_SQL_TRACE     : 1/true to force SQL_TRACE (sqlite trace hook)
#  AOCT_SQL_TRACE_EXPANDED : 1/true to include expanded SQL in trace
_AOCT_SQL_LOG      = (os.getenv("AOCT_SQL_LOG", "0").lower() in ("1","true","yes"))
try:
    _AOCT_SQL_SLOW_MS = float(os.getenv("AOCT_SQL_SLOW_MS", "50") or 50)
except Exception:
    _AOCT_SQL_SLOW_MS = 50.0
_AOCT_SQL_EXPLAIN  = (os.getenv("AOCT_SQL_EXPLAIN", "0").lower() in ("1","true","yes"))

def _apply_sql_env_overrides():
    v = os.getenv("AOCT_SQL_TRACE")
    if v is not None and v != "": globals()["SQL_TRACE"] = (v.lower() in ("1","true","yes"))
    v = os.getenv("AOCT_SQL_TRACE_EXPANDED")
    if v is not None and v != "": globals()["SQL_TRACE_EXPANDED"] = (v.lower() in ("1","true","yes"))
_apply_sql_env_overrides()

# ---- Network/ADS-B guardrails (env-driven) -------------------------------
#  AOCT_DISABLE_ONDEMAND_ADSB : 1/true to forbid live ADS-B fetches (DB-only)
#  AOCT_ADSB_BUDGET_MS        : overall budget per locate call (default 1200 ms)
_AOCT_DISABLE_ONDEMAND_ADSB = (os.getenv("AOCT_DISABLE_ONDEMAND_ADSB","0").lower() in ("1","true","yes"))
try:
    _AOCT_ADSB_BUDGET_MS = float(os.getenv("AOCT_ADSB_BUDGET_MS","1200") or 1200.0)
except Exception:
    _AOCT_ADSB_BUDGET_MS = 1200.0

# ───── Flight Code helpers/spec ─────────────────────────────────────────────
# Format: OOOMMDDYYDDDHHMM  (OOO/IATA pref, DDD/IATA pref, local date mmddyy)
FLIGHT_CODE_RE      = re.compile(r'^[A-Z0-9]{3}\d{6}[A-Z0-9]{3}\d{4}$')
FLIGHT_CODE_ANY_RE  = re.compile(r'(?<![A-Z0-9])([A-Z0-9]{3}\d{6}[A-Z0-9]{3}\d{4})(?![A-Z0-9])')

@lru_cache(maxsize=8192)
def to_three_char_code(raw_code: str) -> str | None:
    """
    Map any airport token to a 3-char ops code, *preferring IATA*.
    If no IATA exists, return None (caller decides whether to accept raw).
    """
    code = (raw_code or '').strip().upper()
    if not code:
        return None
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        row = c.execute(
            """
            SELECT iata_code, icao_code, ident, local_code, gps_code
              FROM airports
             WHERE icao_code  = ?
                OR iata_code  = ?
                OR gps_code   = ?
                OR ident      = ?
                OR local_code = ?
             LIMIT 1
            """,
            (code, code, code, code, code)
        ).fetchone()
    if row and (row['iata_code'] and len(row['iata_code'].strip()) == 3):
        return row['iata_code'].strip().upper()
    # Already a plausible 3-char ops code (A–Z/0–9)? accept upstream can prompt if needed
    if re.fullmatch(r'[A-Z0-9]{3}', code):
        return code
    return None

def _norm_hhmm(hhmm: str) -> str:
    s = (hhmm or '').strip()
    # allow '930' → '0930'
    if not s.isdigit(): raise ValueError("HHMM must be numeric")
    if len(s) not in (3,4): raise ValueError("HHMM must be 3–4 digits")
    s = s.zfill(4)
    h, m = int(s[:2]), int(s[2:])
    if h>23 or m>59: raise ValueError("HHMM out of range")
    return f"{h:02}{m:02}"

def compute_flight_code(origin_code: str, date_dt, dest_code: str, hhmm_str: str) -> str:
    """
    Build OOOMMDDYYDDDHHMM using IATA-preferred 3-char codes.
    `date_dt` is treated as *local date* by caller (UI freezes locally).
    """
    ooo = to_three_char_code(origin_code)
    ddd = to_three_char_code(dest_code)
    if not ooo or not ddd:
        raise ValueError("origin/destination must map to a 3-char ops code")
    hhmm   = _norm_hhmm(hhmm_str)
    mmddyy = date_dt.strftime("%m%d%y")
    return f"{ooo}{mmddyy}{ddd}{hhmm}"

def parse_flight_code(code: str) -> dict | None:
    c = (code or '').strip().upper()
    if not FLIGHT_CODE_RE.fullmatch(c):
        return None
    return {
        'origin'     : c[0:3],
        'date_mmddyy': c[3:9],
        'dest'       : c[9:12],
        'hhmm'       : c[12:16],
    }

def maybe_extract_flight_code(text: str | None) -> str | None:
    if not text: return None
    m = FLIGHT_CODE_ANY_RE.search(text.upper())
    return m.group(1) if m else None

def find_unique_code_or_bump(ooo: str, mmddyy: str, ddd: str, hhmm: str) -> str:
    """
    If OOOMMDDYYDDDHHMM collides, bump HHMM by +1 minute (up to +59), keeping OOO/DDD/date fixed.
    """
    def build(hhmm_): return f"{ooo}{mmddyy}{ddd}{hhmm_}"
    cur = _norm_hhmm(hhmm)
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        for _ in range(60):
            code = build(cur)
            hit  = c.execute("SELECT 1 FROM flights WHERE flight_code=? LIMIT 1", (code,)).fetchone()
            if not hit:
                return code
            # +1 minute (wrap within day; date stays frozen per spec)
            h, m = int(cur[:2]), int(cur[2:])
            total = (h*60 + m + 1) % 1440
            cur = f"{total//60:02}{total%60:02}"
    raise RuntimeError("Could not find unique flight code within +59 minutes")

def connect(db, timeout=30, **kwargs):
    # Only add the tracing connection factory when requested
    if SQL_TRACE:
        kwargs.setdefault("factory", TraceConn)

    # create the connection first (fall back if _original_connect not present)
    base_connect = getattr(sqlite3, "_original_connect", sqlite3.connect)
    conn = base_connect(db, timeout=timeout, **kwargs)

    try:
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.execute("PRAGMA journal_mode=WAL;")
        # Expanded SQL is VERY noisy — only when explicitly enabled
        if SQL_TRACE and SQL_TRACE_EXPANDED:
            conn.set_trace_callback(lambda s: _sql_logger.debug("SQL EXPANDED | %s", s))
    except Exception:
        pass

    return conn

def _ip_for_iface(iface: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack('256s', iface.encode()[:15])
        addr = fcntl.ioctl(s.fileno(), 0x8915, packed)[20:24]  # SIOCGIFADDR
        return socket.inet_ntoa(addr)
    finally:
        try:
            s.close()
        except Exception:
            pass

def get_lan_ip() -> str:
    # 0) explicit IP override:
    if ip := os.environ.get('HOST_LAN_IP'):
        return ip

    # 1) explicit interface override:
    if iface := os.environ.get('HOST_LAN_IFACE'):
        try:
            return _ip_for_iface(iface)
        except Exception:
            pass

    # 2) default‐route interface (skip tun*, docker*, br-*, lo):
    try:
        with open('/proc/net/route') as f:
            for line in f.readlines()[1:]:
                iface, dest, flags = line.split()[:3]
                if dest=='00000000' and int(flags,16)&2:
                    if not iface.startswith(('tun','tap','wg','docker','br-','lo')):
                        return _ip_for_iface(iface)
    except Exception:
        pass

    # 3) last-ditch UDP trick:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # Final fallback: loopback (still lets Flask run)
        return "127.0.0.1"

def register_mdns(name: str, port: int):
    """
    Try to announce the service via Bonjour.  On success returns
    (mdns_name, host_ip).  On any failure returns ("", host_ip) and
    stores an explanatory message in MDNS_REASON so the UI can tell
    users why mDNS is absent.
    """
    global MDNS_REASON

    # --- honour opt‑out via env ---------------------------------
    if os.environ.get("DISABLE_MDNS") == "1":
        MDNS_REASON = "mDNS disabled via DISABLE_MDNS=1"
        ip = get_lan_ip()
        globals()['MDNS_NAME'] = ""
        globals()['HOST_IP'] = ip
        return "", ip

    host_ip = get_lan_ip()

    # --- verify zeroconf is available -------------------------------
    if _zeroconf is None:
        MDNS_REASON = "mDNS unavailable (zeroconf not initialized)"
        globals()['MDNS_NAME'] = ""
        globals()['HOST_IP'] = host_ip
        return "", host_ip

    # --- attempt to claim a unique Bonjour name -----------------
    base   = name
    trial  = base
    for i in range(1, 10):                  # rampops, rampops-1, … rampops-9
        info = ServiceInfo(
            type_      = "_http._tcp.local.",
            name       = f"{trial}._http._tcp.local.",
            addresses  = [socket.inet_aton(host_ip)],
            port       = port,
            server     = f"{trial}.local.",
            properties = {}
        )
        try:
            _zeroconf.register_service(info)
            globals()['MDNS_NAME'] = f"{trial}.local"
            globals()['HOST_IP'] = host_ip
            return f"{trial}.local", host_ip
        except NonUniqueNameException:
            trial = f"{base}-{i}"           # try a new suffix
        except Exception as exc:
            MDNS_REASON = f"mDNS error: {exc}"
            globals()['MDNS_NAME'] = ""
            globals()['HOST_IP'] = host_ip
            return "", host_ip

    # exhausted all variants
    MDNS_REASON = "mdns failed: Too many servers!"
    globals()['MDNS_NAME'] = ""
    globals()['HOST_IP'] = host_ip
    return "", host_ip

def _mmss(value):
    try:
        total = int(float(value))
    except Exception:
        return "0:00"
    m, s = divmod(max(total, 0), 60)
    return f"{m}:{s:02d}"

def _strip_hop_by_hop(resp):
    for h in ("Connection","Keep-Alive","Proxy-Authenticate","Proxy-Authorization",
              "TE","Trailer","Transfer-Encoding","Upgrade"):
        if h in resp.headers:
            try:
                del resp.headers[h]
            except Exception:
                pass
    return resp

def generate_random_callsign():
    """
    Generate a US‑FCC style callsign:
      • Prefix: 'K', 'N', or 'W', optionally followed by one letter A–Z
      • Number: always '7'
      • Suffix: 1–3 letters A–Z
      • Total length: 4–6 characters
    """
    # 1) Decide prefix length (1 or 2)
    first = random.choice(['K', 'N', 'W'])
    if random.choice([True, False]):
        prefix = first
        p_len = 1
    else:
        prefix = first + random.choice(string.ascii_uppercase)
        p_len = 2

    # 2) Compute valid suffix length range so total length ∈ [4,6]:
    #    prefix_len + 1 (for '7') + suffix_len between 4 and 6
    min_suf = max(1, 4 - (p_len + 1))
    max_suf = min(3, 6 - (p_len + 1))
    suffix_len = random.randint(min_suf, max_suf)

    # 3) Generate suffix
    suffix = ''.join(random.choices(string.ascii_uppercase, k=suffix_len))

    return f"{prefix}7{suffix}"

def generate_tail_number():
    """US N-number: 'N' + 4–5 digits (first digit non‑zero)."""
    length = random.choice([4, 5])
    first  = random.choice('123456789')
    rest   = ''.join(random.choices('0123456789', k=length-1))
    return f"N{first}{rest}"

def initialize_airfield_callsigns():
    """On Wargame start, assign each HARDCODED_AIRFIELD a random callsign."""
    global AIRFIELD_CALLSIGNS
    AIRFIELD_CALLSIGNS = {
        af: generate_random_callsign()
        for af in HARDCODED_AIRFIELDS
    }

def inject_globals():
    # batch‑fetch all needed prefs in one go
    prefs = dict_rows("""
      SELECT name, value
        FROM preferences
       WHERE name IN (
         'wargame_mode',
         'embedded_url',
         'embedded_name',
         'embedded_mode',
         'enable_1090_distances',
         'code_format',
         'session_salt'
       )
    """)
    prefs = {p['name']: p['value'] for p in prefs}

    return {
      'wargame_mode': prefs.get('wargame_mode') == 'yes',
      'wargame_role': session.get('wargame_role') or request.cookies.get('wargame_role',''),
      'embedded_url': prefs.get('embedded_url',''),
      'embedded_name': prefs.get('embedded_name',''),
      'embedded_mode': prefs.get('embedded_mode','iframe'),
      'enable_1090_distances': prefs.get('enable_1090_distances')=='yes',
      'mdns_name': MDNS_NAME,
      'mdns_reason': globals().get('MDNS_REASON', ''),
      'host_ip': (HOST_IP or get_lan_ip()),
      'now': datetime.utcnow,
      'current_year': datetime.utcnow().year,
      'hide_tbd': request.cookies.get('hide_tbd','yes')=='yes',
      'show_debug': request.cookies.get('show_debug_logs','no')=='yes',
      'admin_unlocked': session.get('admin_unlocked', False),
      'distance_unit': (get_preference('distance_unit') or request.cookies.get('distance_unit','nm')),
      'generate_callsign': generate_random_callsign,
      # Jinja: {{ csrf_token() }} for plain HTML forms
      'csrf_token': generate_csrf,
      'get_preference': get_preference,
      # Current Wargame role-epoch (used to invalidate stale role cookies)
      'wargame_role_epoch': lambda: get_wargame_role_epoch()
    }

def get_session_salt():
    rows = dict_rows("SELECT value FROM preferences WHERE name='session_salt'")
    if rows:
        return rows[0]['value']
    # initialize on first run
    salt = uuid.uuid4().hex
    set_session_salt(salt)
    return salt

def get_db_file():
    from app import DB_FILE
    return DB_FILE

def get_data_dir() -> str:
    """
    Return the *persisted* data directory (sibling of the DB file).
    Example: if DB is /app/data/aoct.sqlite → /app/data
    """
    return os.path.dirname(get_db_file())

def winlink_attachments_root() -> str:
    """
    Canonical base folder for extracted Winlink attachments.
    Created by entrypoint; callers should still os.makedirs(..., exist_ok=True) when needed.
    """
    return os.path.join(get_data_dir(), "winlink", "attachments")

def expand_text_macros(text: str) -> str:
    """
    Lightweight rewrite helper:
      {MISSION}, {{MISSION}}, ${MISSION} → mission_number preference
      (No-ops if unset.)
    """
    t = str(text or '')
    m = (get_preference('mission_number') or '').strip()
    if not m:
        return t
    return (t
        .replace('{MISSION}', m)
        .replace('{{MISSION}}', m)
        .replace('${MISSION}', m))

def emit_inventory_event(event):
    from app import publish_inventory_event
    return publish_inventory_event(event)

def set_session_salt(salt: str):
    with sqlite3.connect(get_db_file()) as c:
        c.execute("""
            INSERT INTO preferences(name,value)
            VALUES('session_salt',?)
            ON CONFLICT(name) DO UPDATE
              SET value=excluded.value
        """, (salt,))

def _ensure_wargame_scheduler_once():
    """Flask 3.x: run Wargame scheduler init once on the first actual request."""
    global _wg_scheduler_inited
    if _wg_scheduler_inited:
        return
    try:
        if get_preference('wargame_mode') == 'yes':
            initialize_airfield_callsigns()
            configure_wargame_jobs()
    except Exception:
        # don't block the app if scheduler init fails
        pass
    finally:
        # Mark checked either way; Admin toggle will (re)configure explicitly.
        _wg_scheduler_inited = True

def maybe_start_distances():
    global _distance_thread_started
    if _distance_thread_started:
        return
    # check user preference
    rows = dict_rows(
      "SELECT value FROM preferences WHERE name='enable_1090_distances'"
    )
    if not (rows and rows[0]['value']=='yes'):
        return

    # Ensure the background thread uses a REAL Flask app object, not the LocalProxy.
    # Without this, `app.extensions[...]` inside the thread raises outside request ctx
    # and gets swallowed by broad excepts, leaving the distances map empty.
    try:
        from flask import current_app as _current_app
        globals()['app'] = _current_app._get_current_object()
    except Exception:
        pass

    # grab receiver location once
    fetch_recv_loc()
    # spin up the background worker
    t = threading.Thread(target=distances_worker, daemon=True)
    t.start()
    _distance_thread_started = True

def blankish_to_none(v: str | None):
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    u = s.upper()
    if DASHY_RE.match(s) or u in {"N/A","NONE","UNK","UNKNOWN","TBD"}:
        return None
    return s

def require_login():
    """
    Gate everything behind auth except:
      • static files
      • auth.setup / auth.login / auth.logout
      • localhost-only utilities: /_ping, /__routes__, /dashboard/plain
    Also avoid redirect loops by not redirecting when we’re already on the
    login/setup endpoints.
    """
    ep = request.endpoint or ""                 # e.g. 'auth.login'
    _ = request.blueprint or ""                # e.g. 'auth'

    # --- public read-only Aggregate API: always exempt from auth -----------
    # Served strictly from read-only SQLite connections; safe to expose without auth.
    if request.blueprint == "aggregate":
        return

    # --- localhost-only open endpoints (by PATH) -----------------------
    if request.remote_addr in ("127.0.0.1", "::1"):
        if request.path in ("/_ping", "/__routes__", "/dashboard/plain"):
            return

    # --- unconditional endpoint exemptions -----------------------------
    exempt_eps = {
        "auth.login",
        "auth.logout",
        "auth.setup",
    }
    if ep.startswith("static") or ep in exempt_eps:
        return

    # --- onboarding: no password set → force setup ---------------------
    if not get_app_password_hash():
        if ep != "auth.setup":
            nxt = request.full_path if request.query_string else request.path
            return redirect(url_for("auth.setup", next=nxt))
        return

    # --- require logged-in session -------------------------------------
    if not session.get("logged_in"):
        if ep != "auth.login":
            nxt = request.full_path if request.query_string else request.path
            return redirect(url_for("auth.login", next=nxt))
        return

    # --- global invalidation via session salt --------------------------
    if session.get("session_salt") != get_session_salt():
        session.clear()
        if ep != "auth.login":
            nxt = request.full_path if request.query_string else request.path
            return redirect(url_for("auth.login", next=nxt))
        return

def get_app_password_hash():
    """Fetch the hashed app password from preferences table (or None)."""
    rows = dict_rows(
        "SELECT value FROM preferences WHERE name='app_password'"
    )
    return rows[0]['value'] if rows else None

def set_app_password_hash(hashval):
    """Upsert the hashed app password into preferences."""
    with sqlite3.connect(get_db_file()) as c:
        c.execute("""
            INSERT INTO preferences(name,value)
            VALUES('app_password',?)
            ON CONFLICT(name) DO UPDATE
              SET value=excluded.value
        """, (hashval,))

def _rate_limit_exceeded(e):
    # return a realistic-looking 500 page
    html = """<!DOCTYPE html>
<html lang="en"><head>
<meta http-equiv="content-type" content="text/html; charset=UTF-8"><title>500 Internal Server Error</title>
</head><body><h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete 
your request. Either the server is overloaded or there is an error in 
the application.</p>
</body></html>"""
    resp = make_response(html, 500)
    resp.headers["Content-Type"] = "text/html; charset=UTF-8"
    return resp

def handle_csrf_error(e):
    """
    Catch any CSRF failures:
      - For AJAX (X-Requested-With), return 401+JSON so client JS can detect expiry.
      - For normal form posts, flash a message and redirect to the same path (forces reload).
    """
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        resp = jsonify({
            'csrf_expired': True,
            'message': e.description or 'Session expired; please reload.'
        })
        resp.status_code = 401
        return resp

    flash('Your session has expired. Please reload this page.', 'error')
    return redirect(request.path)

def init_db():
    print("🔧 initializing DB…")

    with sqlite3.connect(get_db_file(), timeout=30) as c:
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("PRAGMA busy_timeout=30000;")

    with sqlite3.connect(get_db_file()) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS preferences(
                       id INTEGER PRIMARY KEY,
                       name TEXT UNIQUE,
                       value TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS incoming_messages(
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       sender TEXT, subject TEXT, body TEXT, timestamp TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS flights(
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       tail_number TEXT)""")            # minimal; columns added below
        c.execute("""CREATE TABLE IF NOT EXISTS flight_history(
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       flight_id INTEGER, timestamp TEXT, data TEXT)""")
        # ─── Inventory tables ────────────────────────────────────────
        c.execute("""
          CREATE TABLE IF NOT EXISTS inventory_categories (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT    UNIQUE NOT NULL,
            display_name  TEXT    NOT NULL
          )
        """)
        c.execute("""
          CREATE TABLE IF NOT EXISTS inventory_entries (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            category_id      INTEGER NOT NULL,
            raw_name         TEXT,
            sanitized_name   TEXT,
            weight_per_unit  REAL,
            quantity         INTEGER,
            total_weight     REAL,
            direction        TEXT    CHECK(direction IN ('in','out')),
            timestamp        TEXT    NOT NULL,
            source           TEXT    NOT NULL DEFAULT 'inventory',
            FOREIGN KEY(category_id) REFERENCES inventory_categories(id)
          )
        """)
        # Barcode → item dictionary (event log remains the source of truth for counts)
        c.execute("""
          CREATE TABLE IF NOT EXISTS inventory_barcodes (
            barcode         TEXT    PRIMARY KEY,
            category_id     INTEGER NOT NULL,
            sanitized_name  TEXT    NOT NULL,
            raw_name        TEXT,
            weight_per_unit REAL    NOT NULL,   -- stored in lbs to match inventory_entries
            created_at      TEXT    DEFAULT (datetime('now')),
            updated_at      TEXT
          )
        """)
        c.execute("""
          CREATE INDEX IF NOT EXISTS idx_inv_barcodes_item
            ON inventory_barcodes(category_id, sanitized_name, weight_per_unit)
        """)
        c.execute("""
          CREATE TABLE IF NOT EXISTS outgoing_messages (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            flight_id      INTEGER NOT NULL,
            operator_call  TEXT    NOT NULL,
            timestamp      TEXT    NOT NULL,
            subject        TEXT    NOT NULL,
            body           TEXT    NOT NULL
          )
        """)
        # ───────────────────── Wargame Mode schema ─────────────────────
        c.execute("""
          CREATE TABLE IF NOT EXISTS wargame_emails (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            generated_at  TEXT    NOT NULL,
            message_id    TEXT    NOT NULL,
            size_bytes    INTEGER NOT NULL,
            source        TEXT    NOT NULL,
            sender        TEXT    NOT NULL,
            recipient     TEXT    NOT NULL,
            subject       TEXT    NOT NULL,
            body          TEXT    NOT NULL
          )
        """)
        c.execute("""
          CREATE TABLE IF NOT EXISTS wargame_metrics (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type     TEXT    NOT NULL,
            delta_seconds  REAL    NOT NULL,
            recorded_at    TEXT    NOT NULL,
            key            TEXT
          )
        """)
        # ── inbound scheduling for ramp arrivals ────────────────────
        c.execute("""
          CREATE TABLE IF NOT EXISTS wargame_inbound_schedule (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            tail_number      TEXT    NOT NULL,
            airfield_takeoff TEXT    NOT NULL,
            airfield_landing TEXT    NOT NULL,
            scheduled_at     TEXT    NOT NULL,
            eta              TEXT    NOT NULL,
            cargo_type       TEXT    NOT NULL,
            cargo_weight     REAL    NOT NULL
          )
        """)
        c.execute("""
          CREATE TABLE IF NOT EXISTS wargame_radio_schedule (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            generated_at   TEXT    NOT NULL,   -- original ts
            scheduled_for  TEXT    NOT NULL,   -- when to show to Radio
            message_id     TEXT    NOT NULL,
            size_bytes     INTEGER NOT NULL,
            source         TEXT    NOT NULL,
            sender         TEXT    NOT NULL,
            recipient      TEXT    NOT NULL,
            subject        TEXT    NOT NULL,
            body           TEXT    NOT NULL
          )
        """)
        # ── Flights cargo items ──────────────────────────────────────────
        c.execute("""
          CREATE TABLE IF NOT EXISTS flight_cargo (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            flight_id        INTEGER,
            queued_id        INTEGER,
            session_id       TEXT    NOT NULL,
            category_id      INTEGER NOT NULL,
            sanitized_name   TEXT    NOT NULL,
            weight_per_unit  REAL    NOT NULL,
            quantity         INTEGER NOT NULL,
            total_weight     REAL    NOT NULL,
            direction        TEXT    NOT NULL CHECK(direction IN ('in','out')),
            timestamp        TEXT    NOT NULL,
            FOREIGN KEY(flight_id)   REFERENCES flights(id),
            FOREIGN KEY(queued_id)   REFERENCES queued_flights(id),
            FOREIGN KEY(category_id) REFERENCES inventory_categories(id)
          )
        """)
        # ── Queued flights (draft Ramp entries) ─────────────────────────────
        c.execute("""
          CREATE TABLE IF NOT EXISTS queued_flights (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            direction          TEXT    NOT NULL,
            airfield_landing   TEXT,
            pilot_name         TEXT,
            pax_count          TEXT,
            tail_number        TEXT    NOT NULL,
            airfield_takeoff   TEXT,
            cargo_weight       REAL    DEFAULT 0,
            travel_time        TEXT,
            cargo_type         TEXT,
            remarks            TEXT,
            created_at         TEXT    NOT NULL
          )
        """)
        # default preferences for Wargame Mode
        c.execute("""
          INSERT OR IGNORE INTO preferences(name,value)
          VALUES
            ('wargame_mode',     'no'),
            ('wargame_settings', '{}')
        """)

    # ─── Flight Locate: ADS-B sightings & locate logs ────────────────────────
    with sqlite3.connect(get_db_file()) as c:
        c.execute("""
          CREATE TABLE IF NOT EXISTS adsb_sightings (
            id               INTEGER PRIMARY KEY,
            tail             TEXT,
            sample_ts_utc    TEXT,   -- ISO-8601 UTC from source station
            lat              REAL,
            lon              REAL,
            track_deg        REAL,   -- nullable
            speed_kt         REAL,   -- nullable
            alt_ft           REAL,   -- nullable
            receiver_airport TEXT,
            receiver_call    TEXT,
            source           TEXT,   -- e.g., TAR1090, readsb
            inserted_at_utc  TEXT    -- server UTC at ingest
          )
        """)
        c.execute("""
          CREATE INDEX IF NOT EXISTS idx_adsb_sightings_tail_time
            ON adsb_sightings(tail, sample_ts_utc DESC)
        """)
        c.execute("""
          CREATE INDEX IF NOT EXISTS idx_adsb_sightings_inserted
            ON adsb_sightings(inserted_at_utc DESC)
        """)
        c.execute("""
          CREATE TABLE IF NOT EXISTS flight_locates (
            id                   INTEGER PRIMARY KEY,
            tail                 TEXT,
            requested_at_utc     TEXT,
            requested_by         TEXT,   -- operator cookie
            latest_sample_ts_utc TEXT,
            latest_from_airport  TEXT,
            latest_from_call     TEXT
          )
        """)

        c.execute("""
          CREATE TABLE IF NOT EXISTS wargame_tasks (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            role       TEXT    NOT NULL CHECK(role IN ('radio','ramp','inventory')),
            kind       TEXT    NOT NULL,                         -- e.g. inbound/outbound
            key        TEXT    NOT NULL,                         -- e.g. 'msg:<id>' or 'flight:<id>'
            gen_at     TEXT    NOT NULL,                         -- generation timestamp
            sched_for  TEXT,                                     -- optional (radio batch anchor)
            created_at TEXT    NOT NULL,
            UNIQUE(role, kind, key)
          )
        """)
        # ── Wargame Inventory batches (truck-like) ─────────────────────
        c.execute("""
          CREATE TABLE IF NOT EXISTS wargame_inventory_batches (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            direction    TEXT    NOT NULL CHECK(direction IN ('in','out')),
            created_at   TEXT    NOT NULL,
            manifest     TEXT    NOT NULL,
            satisfied_at TEXT
          )
        """)
        c.execute("""
          CREATE TABLE IF NOT EXISTS wargame_inventory_batch_items (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id      INTEGER NOT NULL,
            name          TEXT    NOT NULL,
            size_lb       REAL    NOT NULL,
            qty_required  INTEGER NOT NULL,
            qty_done      INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(batch_id) REFERENCES wargame_inventory_batches(id)
          )
        """)
        # ── Wargame: cargo requests shown on Ramp dashboard ─────────────
        c.execute("""
          CREATE TABLE IF NOT EXISTS wargame_ramp_requests (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at       TEXT    NOT NULL,
            destination      TEXT    NOT NULL,
            requested_weight REAL    NOT NULL,
            manifest         TEXT,
            satisfied_at     TEXT,
            assigned_tail    TEXT
          )
        """)
        # ── Cargo Requests (aggregated, production feature) ────────────────
        _create_tables_cargo_requests(c)
        # ── winlink messages table ───────────────────────────
        c.execute("""
            CREATE TABLE IF NOT EXISTS winlink_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                direction TEXT   NOT NULL,
                sender    TEXT,
                parsed    INTEGER NOT NULL DEFAULT 0,
                callsign  TEXT   NOT NULL,
                subject   TEXT,
                body      TEXT,
                flight_id INTEGER,
                timestamp TEXT   NOT NULL DEFAULT (datetime('now')),
                UNIQUE(direction, callsign, subject, timestamp)
          )
        """)

        # ── Remote Airports: last snapshot per remote airport ──────────
        # Retains only the most recent snapshot per airport (one row per airport).
        c.execute("""
          CREATE TABLE IF NOT EXISTS remote_inventory (
            airport_canon TEXT PRIMARY KEY,
            snapshot_at   TEXT NOT NULL,   -- timestamp embedded in snapshot (if known)
            received_at   TEXT NOT NULL,   -- when we stored this snapshot locally
            summary_text  TEXT NOT NULL,   -- human-readable summary body
            csv_text      TEXT NOT NULL    -- CSV (plain text) for parsing
          )
        """)

        # ── Weather Tab storage (latest-per-key) ────────────────────────────
        c.execute("""
          CREATE TABLE IF NOT EXISTS weather_products (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            key             TEXT NOT NULL UNIQUE,   -- e.g., 'WCCOL.JPG', 'WA_FOR_WA'
            display_name    TEXT NOT NULL,          -- UI label; fallback = key
            mime            TEXT NOT NULL,          -- 'image/jpeg', 'image/gif', 'text/plain'
            content         BLOB NOT NULL,          -- raw bytes (latest only)
            content_hash    TEXT NOT NULL,          -- sha256 for dedupe
            source          TEXT NOT NULL,          -- 'winlink' | 'manual'
            received_at_utc TEXT NOT NULL,          -- when we ingested it
            updated_at_utc  TEXT NOT NULL           -- last time this row changed
          )
        """)
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS weather_products_key_uq ON weather_products(key)")

        # Defaults for Remote-Airport feature flags
        c.execute("""
          INSERT OR IGNORE INTO preferences(name,value)
          VALUES
            ('auto_broadcast_interval_min','0'),
            ('auto_reply_enabled','yes')
        """)

        # Defaults for Flight Locate & Offline Maps
        c.execute("""
          INSERT OR IGNORE INTO preferences(name,value)
          VALUES
            ('adsb_base_url',''),
            ('aoct_auto_reply_flight','yes'),
            ('adsb_poll_enabled','no'),
            ('adsb_poll_interval_s','10'),
            ('map_tiles_path', ?),
            ('map_offline_seed','yes')
        """, (os.path.join(os.path.dirname(get_db_file()), 'tiles'),))

        # ── Weather Tab defaults (public; no admin required) ────────────────
        c.execute("""
          INSERT OR IGNORE INTO preferences(name,value) VALUES
            ('wx_catalog_body', 'WCCOL.JPG\nWCIR.JPG\nWCVS.JPG\nUSWXRAD.GIF\nWA_FOR_WA')
        """)
        c.execute("""
          INSERT OR IGNORE INTO preferences(name,value) VALUES
            ('wx_display_names',
             'WCCOL.JPG=West Coast (Color)\nWCIR.JPG=West Coast (Infrared)\nWCVS.JPG=West Coast (Visible)\nUSWXRAD.GIF=US Radar Mosaic\nWA_FOR_WA=WA Area Forecast (Text)')
        """)

    # ── Staff tables (idempotent; separated util owns schema) ────────────────
    try:
        from modules.utils.staff import ensure_staff_tables  # type: ignore
        ensure_staff_tables()
    except Exception:
        # never hard-fail app init if optional module isn’t available yet
        pass

    # ── Pilot & Aircraft Information (PAI) tables
    try:
        from modules.utils.aircraft import ensure_aircraft_tables  # type: ignore
        ensure_aircraft_tables()
    except Exception:
        pass

    # ── Help system (ensure + always reseed from YAML) ───────────────────────
    try:
        # Always ensure help schema, migrate legacy, then reseed from YAML
        ensure_help_tables()
        seed_help_from_yaml(only_if_empty=False)
    except Exception as e:
        logger.warning("Help DB init skipped: %s", e)

def run_migrations():
    print("🔧 running DB migrations…")
    # flights table
    for col, typ in [
        ("is_ramp_entry",    "INTEGER DEFAULT 0"),
        ("sent",             "INTEGER DEFAULT 0"),
        ("complete",         "INTEGER DEFAULT 0"),
        ("direction",        "TEXT"),
        ("pilot_name",       "TEXT"),
        ("pax_count",        "TEXT"),
        ("airfield_takeoff", "TEXT"),
        ("takeoff_time",     "TEXT"),
        ("airfield_landing", "TEXT"),
        ("eta",              "TEXT"),
        ("cargo_type",       "TEXT"),
        ("cargo_weight",     "TEXT"),
        ("remarks",          "TEXT"),
        ("sent_time",        "TEXT")
    ]:
        ensure_column("flights", col, typ)

    # incoming_messages table
    for col, typ in [
        ("tail_number",      "TEXT"),
        ("airfield_takeoff", "TEXT"),
        ("airfield_landing", "TEXT"),
        ("takeoff_time",     "TEXT"),
        ("eta",              "TEXT"),
        ("cargo_type",       "TEXT"),
        ("cargo_weight",     "TEXT"),
        ("remarks",          "TEXT")
    ]:
        ensure_column("incoming_messages", col, typ)

    # ─── Inventory: add pending‐line support ───────────────
    ensure_column("inventory_entries", "pending",    "INTEGER DEFAULT 0")
    ensure_column("inventory_entries", "pending_ts", "TEXT")
    ensure_column("inventory_entries", "session_id", "TEXT")
    ensure_column("inventory_entries", "source",     "TEXT DEFAULT 'inventory'")

    # wargame_metrics.key for linking metrics to entities (e.g., flight:<id>)
    ensure_column("wargame_metrics", "key", "TEXT")
    ensure_column("flights", "cargo_weight_real", "REAL")
    # Ensure the canonical timestamp column exists on flights
    ensure_column("flights", "timestamp", "TEXT")
    # Flight Code storage (no DB uniqueness; app handles deconflict)
    ensure_column("flights", "flight_code", "TEXT")

    with sqlite3.connect(get_db_file()) as c:
        # backfill any missing timestamps on existing rows
        c.execute("""
          UPDATE flights
             SET timestamp = strftime('%Y-%m-%dT%H:%M:%f','now')
           WHERE IFNULL(timestamp,'') = ''
        """)
        # idempotent trigger to auto-stamp timestamp on inserts that omit it
        c.execute("""
          CREATE TRIGGER IF NOT EXISTS flights_set_timestamp
          AFTER INSERT ON flights
          WHEN NEW.timestamp IS NULL OR NEW.timestamp = ''
          BEGIN
            UPDATE flights
               SET timestamp = strftime('%Y-%m-%dT%H:%M:%f','now')
             WHERE id = NEW.id;
          END;
        """)
        # index for fast lookups by code
        c.execute("CREATE INDEX IF NOT EXISTS idx_flights_code ON flights(flight_code)")

    # Wargame: hold cargo manifest on inbound schedule so it becomes flight.remarks
    ensure_column("wargame_inbound_schedule", "manifest", "TEXT")

    # Wargame: record which tail was assigned to a ramp request
    ensure_column("wargame_ramp_requests", "assigned_tail",   "TEXT")

    with sqlite3.connect(get_db_file()) as c:
        # flight_cargo -------------------------------------------------
        c.execute("""
          CREATE TABLE IF NOT EXISTS flight_cargo (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            flight_id        INTEGER,
            queued_id        INTEGER,
            session_id       TEXT    NOT NULL DEFAULT '',
            category_id      INTEGER NOT NULL,
            sanitized_name   TEXT    NOT NULL,
            weight_per_unit  REAL    NOT NULL,
            quantity         INTEGER NOT NULL,
            total_weight     REAL    NOT NULL,
            direction        TEXT    NOT NULL CHECK(direction IN ('in','out')),
            timestamp        TEXT    NOT NULL
          )
        """)

        # queued_flights ----------------------------------------------
        c.execute("""
          CREATE TABLE IF NOT EXISTS queued_flights (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            direction        TEXT    NOT NULL,
            airfield_landing TEXT,
            pilot_name       TEXT,
            pax_count        TEXT,
            tail_number      TEXT    NOT NULL,
            airfield_takeoff TEXT,
            travel_time      TEXT,
            cargo_weight     REAL    DEFAULT 0,
            cargo_type       TEXT,
            remarks          TEXT,
            created_at       TEXT    NOT NULL
          )
        """)
        # Ensure Cargo Requests tables/indexes exist on upgraded DBs
        _create_tables_cargo_requests(c)

    # flight_cargo gained a NOT-NULL session_id
    ensure_column("flight_cargo", "session_id", "TEXT NOT NULL DEFAULT ''")
    # queued_flights gained dest + travel_time (if DB predates them)
    ensure_column("queued_flights", "airfield_landing", "TEXT")
    ensure_column("queued_flights", "travel_time",      "TEXT")
    ensure_column("queued_flights", "cargo_weight",     "REAL DEFAULT 0")
    ensure_column("winlink_messages", "sender",         "TEXT")

    # Winlink attachments: minimal DB pointers (files live on disk under /app/data/winlink/attachments)
    ensure_column("winlink_messages", "has_attachments", "INTEGER NOT NULL DEFAULT 0")
    ensure_column("winlink_messages", "attachment_dir",  "TEXT")

    with sqlite3.connect(get_db_file()) as c:
        c.execute("""
          CREATE TABLE IF NOT EXISTS winlink_message_files (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id   INTEGER NOT NULL,
            filename     TEXT    NOT NULL,   -- e.g., 'WCCOL.JPG'
            mime         TEXT,               -- best-effort (e.g., 'image/jpeg')
            size_bytes   INTEGER,            -- best-effort size on disk
            saved_path   TEXT    NOT NULL,   -- full path under /app/data/winlink/attachments/...
            created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            UNIQUE(message_id, filename),
            FOREIGN KEY(message_id) REFERENCES winlink_messages(id)
          )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_wl_files_msg ON winlink_message_files(message_id)")

    # ─── Pilot acknowledgment (signatures) ───────────────────────────────
    # Store both on flights (final record) and queued_flights (drafts).
    ensure_column("flights", "pilot_ack_name",        "TEXT")
    ensure_column("flights", "pilot_ack_method",      "TEXT")   # 'typed' | 'drawn'
    ensure_column("flights", "pilot_ack_signature_b64","TEXT")  # base64 PNG (no data: prefix)
    ensure_column("flights", "pilot_ack_signed_at",   "TEXT")
    # Optional metadata for gating/audit + manifest storage
    ensure_column("flights", "pilot_ack_boot_id",     "TEXT")
    ensure_column("flights", "manifest_pdf_path",     "TEXT")
    ensure_column("queued_flights", "pilot_ack_name",         "TEXT")
    ensure_column("queued_flights", "pilot_ack_method",       "TEXT")
    ensure_column("queued_flights", "pilot_ack_signature_b64","TEXT")
    ensure_column("queued_flights", "pilot_ack_signed_at",    "TEXT")
    ensure_column("queued_flights", "pilot_ack_boot_id",      "TEXT")
    ensure_column("queued_flights", "manifest_pdf_path",      "TEXT")

    # Helpful index for inventory reconciliation lookups
    with sqlite3.connect(get_db_file()) as c:
        c.execute("CREATE INDEX IF NOT EXISTS idx_wg_items_lookup ON wargame_inventory_batch_items(lower(name), size_lb)")
        # ---- Hot-path indexes to speed dashboard/radio/ramp flows ----
        # flights: common filters & sorts
        c.execute("CREATE INDEX IF NOT EXISTS idx_flights_tail_time    ON flights(tail_number, takeoff_time)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_flights_tail_open    ON flights(tail_number, complete, id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_flights_route_open   ON flights(tail_number, airfield_takeoff, airfield_landing, complete, id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_flights_ramp_unsent  ON flights(is_ramp_entry, sent, id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_flights_complete_id  ON flights(complete, id)")
        # airports: ensure per-column probes are indexed even on older DBs
        c.execute("CREATE INDEX IF NOT EXISTS idx_airports_ident       ON airports(ident)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_airports_icao        ON airports(icao_code)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_airports_iata        ON airports(iata_code)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_airports_gps         ON airports(gps_code)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_airports_local       ON airports(local_code)")
        # inventory & batches
        c.execute("CREATE INDEX IF NOT EXISTS idx_inv_entries_sku      ON inventory_entries(sanitized_name, weight_per_unit)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_inv_entries_commit   ON inventory_entries(pending, direction, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_wg_batches_open_out  ON wargame_inventory_batches(direction, satisfied_at, created_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_wg_items_by_batch    ON wargame_inventory_batch_items(batch_id)")
        # wargame flows
        c.execute("CREATE INDEX IF NOT EXISTS idx_wg_tasks_role_kind   ON wargame_tasks(role, kind)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_wg_inbound_eta       ON wargame_inbound_schedule(eta)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_wg_ramp_open         ON wargame_ramp_requests(satisfied_at)")

        # Remote-Airports table for existing DBs (idempotent)
        c.execute("""
          CREATE TABLE IF NOT EXISTS remote_inventory (
            airport_canon TEXT PRIMARY KEY,
            snapshot_at   TEXT NOT NULL,
            received_at   TEXT NOT NULL,
            summary_text  TEXT NOT NULL,
            csv_text      TEXT NOT NULL
          )
        """)
        # Ensure preference defaults exist on upgraded DBs
        c.execute("""
          INSERT OR IGNORE INTO preferences(name,value)
          VALUES
            ('auto_broadcast_interval_min','0'),
            ('auto_reply_enabled','yes')
        """)
        # New prefs for Flight Locate & Offline Maps (ensure on upgrade)
        c.execute("""
          INSERT OR IGNORE INTO preferences(name,value)
          VALUES
            ('adsb_base_url',''),
            ('aoct_auto_reply_flight','yes'),
            ('adsb_poll_enabled','no'),
            ('adsb_poll_interval_s','10'),
            ('map_tiles_path', ?),
            ('map_offline_seed','yes')
        """, (os.path.join(os.path.dirname(get_db_file()), 'tiles'),))

    # ── Staff tables (again during migrations for upgraded DBs) ───────────────
    try:
        from modules.utils.staff import ensure_staff_tables  # type: ignore
        ensure_staff_tables()
    except Exception:
        pass

    # ── PAI tables (upgrade path)
    try:
        from modules.utils.aircraft import ensure_aircraft_tables  # type: ignore
        ensure_aircraft_tables()
    except Exception:
        pass

    # Ensure help table exists after upgrades and reseed from YAML
    try:
        ensure_help_tables()
        seed_help_from_yaml(only_if_empty=False)
    except Exception as e:
        logger.warning("Help DB migration hook skipped: %s", e)

    # Keep cache tidy after structural changes
    try:
        clear_airport_cache()
    except Exception:
        pass

def cleanup_pending():
    """Purge any pending inventory‐entries older than 15 minutes.
       Run at most once per 60s and never 500 the request."""
    import sqlite3 as _sqlite3
    from time import monotonic
    global _pending_cleanup_last
    # throttle on hot pages to reduce write contention
    now = monotonic()
    if (now - _pending_cleanup_last) < 60.0:
        return
    _pending_cleanup_last = now
    try:
        cutoff = (datetime.utcnow() - timedelta(minutes=15)).isoformat()
        with connect(get_db_file(), timeout=30) as c:
            c.execute("DELETE FROM inventory_entries WHERE pending=1 AND pending_ts<=?", (cutoff,))
    except _sqlite3.OperationalError as e:
        # benign under load; try later rather than crashing the request
        if "locked" in str(e).lower():
            logger.debug("cleanup_pending: skipped (database is locked)")
            return
        raise
    except Exception:
        logger.debug("cleanup_pending: best-effort failed", exc_info=True)

def _cleanup_before_view():
    # Fire on inventory-like views (Inventory pages, RampBoss, and API endpoints used by scanning)
    # So the pending layer is tidied up whenever someone visits related pages.
    if request.blueprint in ('inventory', 'ramp', 'api'):
        cleanup_pending()

def _start_radio_tx_once():
    global _radio_started
    if _radio_started:
        return
    try:
        # reuse existing DB helper
        start_radio_tx(lambda sql, params=(): dict_rows(sql, params))
        _radio_started = True
        logger.info("Radio TX thread started.")
    except Exception as e:
        logger.exception("Failed to start Radio TX thread: %s", e)

def ensure_airports_table():
    with sqlite3.connect(get_db_file()) as c:
        c.execute("""
          CREATE TABLE IF NOT EXISTS airports (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ident      TEXT UNIQUE,
            name       TEXT,
            icao_code  TEXT UNIQUE,
            iata_code  TEXT UNIQUE,
            gps_code   TEXT,
            local_code TEXT
          )
        """)

        # Per-column indexes let SQLite OR-optimizer hit each probe efficiently.
        c.execute("CREATE INDEX IF NOT EXISTS idx_airports_ident      ON airports(ident)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_airports_icao       ON airports(icao_code)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_airports_iata       ON airports(iata_code)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_airports_gps        ON airports(gps_code)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_airports_local      ON airports(local_code)")
        # Keep the old composite for legacy queries; harmless if unused.
        c.execute("CREATE INDEX IF NOT EXISTS idx_airports_search     ON airports(ident, icao_code, iata_code, gps_code, local_code)")

def _airports_csv_candidates() -> list[str]:
    """
    Ordered search paths for airports.csv:
      1) AOCT_AIRPORTS_CSV env override
      2) /app/airports.csv (Docker image convention; next to app.py)
      3) folder of the loaded app module (if available) + 'airports.csv'
      4) legacy: same folder as this common.py
    """
    cand: list[str] = []
    # 1) explicit override
    envp = os.getenv("AOCT_AIRPORTS_CSV")
    if envp:
        cand.append(envp)
    # 2) container default
    cand.append("/app/airports.csv")
    # 3) alongside app.py if we can find it
    try:
        mod = _sys.modules.get("app")
        if mod and getattr(mod, "__file__", None):
            cand.append(os.path.join(os.path.dirname(mod.__file__), "airports.csv"))
    except Exception:
        pass
    # 4) legacy: next to this module
    cand.append(os.path.join(os.path.dirname(__file__), "airports.csv"))
    # de-dupe preserving order
    seen, out = set(), []
    for p in cand:
        if p and p not in seen:
            out.append(p); seen.add(p)
    return out

def load_airports_from_csv():
    """One-time load/refresh of airports.csv into airports table."""
    # Make sure the schema is there (idempotent)
    ensure_airports_table()

    candidates = _airports_csv_candidates()
    csv_path = next((p for p in candidates if os.path.exists(p)), None)
    if not csv_path:
        logger.warning("airports.csv not found; looked in: %s", ", ".join(candidates))
        return

    with sqlite3.connect(get_db_file()) as c, open(csv_path, newline='', encoding='utf-8') as f:
        rdr = csv.DictReader(f)
        # tolerate different schemas; pull with .get(...)
        for r in rdr:
            ident = (r.get('ident') or '').strip()
            if not ident:
                continue  # skip rows without a canonical key
            name  = (r.get('name') or '').strip()
            icao  = (r.get('icao_code') or r.get('gps_code') or r.get('ident') or '').strip() or None
            iata  = (r.get('iata_code') or '').strip() or None
            gps   = (r.get('gps_code') or '').strip() or None
            local = (r.get('local_code') or '').strip() or None
            try:
                c.execute("""
                  INSERT INTO airports
                    (ident,name,icao_code,iata_code,gps_code,local_code)
                  VALUES (?,?,?,?,?,?)
                  ON CONFLICT(ident) DO UPDATE SET
                    name       = excluded.name,
                    icao_code  = excluded.icao_code,
                    iata_code  = excluded.iata_code,
                    gps_code   = excluded.gps_code,
                    local_code = excluded.local_code
                """, (ident, name, icao, iata, gps, local))
            except sqlite3.IntegrityError as e:
                # If a uniqueness clash on iata/icao occurs, just skip that row.
                # logger.debug("airports.csv upsert skipped for ident=%s (%s)", ident, e) #this is LOUD
                continue

    # Any refresh invalidates cached lookups.
    try:
        clear_airport_cache()
    except Exception:
        pass

# ── Help system tables + seeding (centralized here; single source of truth) ──
def _project_root_dir() -> str:
    """Return repository root assuming DB lives under a data/ sibling."""
    data_dir = os.path.dirname(get_db_file())
    return os.path.dirname(data_dir)

def _help_seed_path() -> str:
    return os.path.join(_project_root_dir(), "helpdocs", "help_seed.yaml")

def _normalize_route_prefix(p: str) -> str:
    p = (p or "/").strip()
    p = re.sub(r'//+', '/', p)
    if not p.startswith("/"):
        p = "/" + p
    if p != "/" and p.endswith("/"):
        p = p[:-1]
    return p

def _migrate_legacy_help_docs_if_needed(c):
    """
    If an older DB has help_docs (slug/title/body_md/…)
    and help_articles is empty, copy rows across.
    """
    have_docs = c.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='help_docs'"
    ).fetchone()
    if not have_docs:
        return
    empty_articles = (c.execute("SELECT COUNT(*) FROM help_articles").fetchone()[0] == 0)
    if not empty_articles:
        return
    rows = c.execute("""
        SELECT slug, title, body_md, updated_at
          FROM help_docs
    """).fetchall()
    for r in rows or []:
        rp   = _normalize_route_prefix(r[0] or "/")
        ttl  = (r[1] or "Help").strip()
        body = r[2] or ""
        upd  = (r[3] or datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00","Z"))
        c.execute("""
          INSERT OR IGNORE INTO help_articles
            (route_prefix,title,body_md,is_active,seeded,version,updated_by,updated_at_utc)
          VALUES (?,?,?,?,1,1,NULL,?)
        """, (rp, ttl, body, 1, upd))

def ensure_help_tables():
    """
    Create/upgrade the help_articles table used by the site-wide Help system.
    Also migrate legacy help_docs data once, if present.
    """
    with sqlite3.connect(get_db_file()) as c:
        c.execute("""
        CREATE TABLE IF NOT EXISTS help_articles (
          id               INTEGER PRIMARY KEY AUTOINCREMENT,
          route_prefix     TEXT NOT NULL UNIQUE,
          title            TEXT NOT NULL,
          body_md          TEXT NOT NULL,
          is_active        INTEGER NOT NULL DEFAULT 1,
          seeded           INTEGER NOT NULL DEFAULT 0,
          version          INTEGER NOT NULL DEFAULT 1,
          updated_by       TEXT,
          updated_at_utc   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_help_prefix ON help_articles(route_prefix)")
        # One-time legacy migration (help_docs → help_articles)
        _migrate_legacy_help_docs_if_needed(c)

def seed_help_from_yaml(only_if_empty: bool = True) -> int:
    """
    Load helpdocs/help_seed.yaml and upsert into help_articles.
    Accepts either:
      • a list of {route_prefix,title,body_md}
      • a dict with key "docs": [{slug|path,title,md|body|content}]
    Returns number of rows inserted (updates are not counted).
    """
    path = _help_seed_path()
    if not os.path.exists(path):
        logger.info("Help seed not found at %s; skipping.", path)
        return 0

    with sqlite3.connect(get_db_file()) as c:
        if only_if_empty:
            n = c.execute("SELECT COUNT(*) FROM help_articles").fetchone()[0]
            if n > 0:
                return 0

    try:
        import yaml  # type: ignore
    except Exception:
        logger.warning("PyYAML not available; help seeding skipped.")
        return 0

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or []

    # Normalize both shapes into a single list of items
    items = []
    if isinstance(raw, dict) and isinstance(raw.get("docs"), list):
        for d in raw["docs"]:
            if not isinstance(d, dict):
                continue
            items.append({
                "route_prefix": d.get("route_prefix") or d.get("path") or d.get("slug"),
                "title": d.get("title"),
                "body_md": d.get("body_md") or d.get("md") or d.get("body") or d.get("content"),
            })
    elif isinstance(raw, list):
        items = raw
    else:
        items = []

    inserts = 0
    nowz = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00","Z")
    with sqlite3.connect(get_db_file()) as c:
        for it in items:
            rp   = _normalize_route_prefix(it.get("route_prefix") or "/")
            ttl  = (it.get("title") or "Help").strip()
            body = it.get("body_md") or ""
            # Insert if missing
            cur = c.execute(
                """
                INSERT INTO help_articles(route_prefix,title,body_md,is_active,seeded,version,updated_at_utc)
                SELECT ?,?,?,1,1,1,?
                 WHERE NOT EXISTS (SELECT 1 FROM help_articles WHERE route_prefix=?)
                """,
                (rp, ttl, body, nowz, rp)
            )
            inserts += cur.rowcount or 0

            # Refresh existing rows from YAML if content changed
            # (bump version so optimistic concurrency notices the change)
            c.execute(
                """
                UPDATE help_articles
                   SET title          = ?,
                       body_md        = ?,
                       seeded         = 1,
                       version        = version + 1,
                       updated_at_utc = ?
                 WHERE route_prefix   = ?
                   AND (title <> ? OR body_md <> ?)
                """,
                (ttl, body, nowz, rp, ttl, body)
            )
    return inserts

def iso8601_ceil_utc(dt: datetime | None = None) -> str:
    """
    Return an ISO-8601 string with 'Z' timezone, rounded UP to the nearest second.
    If dt is None, use current UTC time.
    """
    if dt is None:
        dt = datetime.now(timezone.utc)
    else:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
    if dt.microsecond > 0:
        dt = dt + timedelta(seconds=1)
    dt = dt.replace(microsecond=0)
    return dt.isoformat().replace("+00:00", "Z")

# ─────────────────────────────────────────────────────────────────────────────
# Weather Tab helpers (schema utils + upsert)
# ─────────────────────────────────────────────────────────────────────────────

# Built-in catalog (used when prefs are absent/missing)
WX_DEFAULT_KEYS = [
    "WCCOL.JPG",     # West Coast (Color)
    "WCIR.JPG",      # West Coast (Infrared)
    "WCVS.JPG",      # West Coast (Visible)
    "USWXRAD.GIF",   # US Radar Mosaic
    "WA_FOR_WA",     # WA Area Forecast (Text)
]

def get_wx_display_names() -> dict[str, str]:
    """
    Built-in labels with preference overrides applied.
    """
    base = {
        "WCCOL.JPG":   "West Coast (Color)",
        "WCIR.JPG":    "West Coast (Infrared)",
        "WCVS.JPG":    "West Coast (Visible)",
        "USWXRAD.GIF": "US Radar Mosaic",
        "WA_FOR_WA":   "WA Area Forecast (Text)",
    }
    # Preference map wins over built-ins
    try:
        base.update(_wx_display_map())
    except Exception:
        pass
    return base

def wx_normalize_key(raw: str) -> str:
    """
    Normalize a product key:
      • Upper-case
      • Special-case WA_FOR_WA: strip a trailing .TXT/.TEXT if present
    """
    k = (raw or "").strip().upper()
    if not k:
        return ""
    if k.startswith("WA_FOR_WA"):
        # Accept WA_FOR_WA, WA_FOR_WA.TXT, WA_FOR_WA.TEXT → WA_FOR_WA
        if k in ("WA_FOR_WA.TXT", "WA_FOR_WA.TEXT"):
            return "WA_FOR_WA"
    return k

def get_wx_keys() -> list[str]:
    """
    Keys that the Weather tab should track, in configured order.
    Public install defaults to 5 Winlink products.
    """
    body = (get_preference("wx_catalog_body") or "").splitlines()
    keys = [wx_normalize_key(x) for x in body if wx_normalize_key(x)]
    # De-dupe while preserving order
    out, seen = [], set()
    for k in keys:
        if k not in seen:
            out.append(k); seen.add(k)
    # Fallback to built-in catalog when pref is empty/missing
    return out if out else WX_DEFAULT_KEYS[:]

def _wx_display_map() -> dict[str, str]:
    """
    Parse wx_display_names preference into {KEY: 'Label'}.
    """
    raw = get_preference("wx_display_names") or ""
    out: dict[str, str] = {}
    for line in raw.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = wx_normalize_key(k)
        v = (v or "").strip()
        if k and v:
            out[k] = v
    return out

def get_wx_display_name(key: str) -> str:
    k = wx_normalize_key(key)
    return get_wx_display_names().get(k, k)

def wx_guess_mime(filename: str, data: bytes | None = None) -> str:
    """
    Light-touch mime inference. Most products are images; WA_FOR_WA is text.
    """
    name = (filename or "").lower()
    if name.endswith((".jpg", ".jpeg")): return "image/jpeg"
    if name.endswith(".gif"):            return "image/gif"
    if name.endswith(".png"):            return "image/png"
    # WA_FOR_WA (no extension) → prefer text/plain
    if wx_normalize_key(filename) == "WA_FOR_WA":
        return "text/plain"
    # Fallback: sniff ASCII → text/plain
    try:
        if data is not None:
            bs = bytes(data[:1024])
            if all((32 <= b <= 126) or b in (9, 10, 13) for b in bs):
                return "text/plain"
    except Exception:
        pass
    return "application/octet-stream"

def upsert_weather_product(key: str, data: bytes, mime: str | None, source: str) -> dict:
    """
    Insert/update a product row. De-dupe by sha256(content).
    Returns {'changed': bool, 'etag': sha, 'received_at_utc': iso, 'updated_at_utc'?: iso}
    """
    import hashlib, sqlite3
    k    = wx_normalize_key(key)
    if not k:
        return {"changed": False, "etag": "", "received_at_utc": iso8601_ceil_utc()}
    sha  = hashlib.sha256(data or b"").hexdigest()
    now  = iso8601_ceil_utc()
    mime = (mime or wx_guess_mime(k, data)).strip().lower()
    disp = get_wx_display_name(k)

    with sqlite3.connect(get_db_file(), timeout=30) as c:
        c.row_factory = sqlite3.Row
        row = c.execute("SELECT content_hash FROM weather_products WHERE key=?", (k,)).fetchone()
        if row and (row["content_hash"] or "") == sha:
            c.execute("UPDATE weather_products SET received_at_utc=? WHERE key=?", (now, k))
            return {"changed": False, "etag": sha, "received_at_utc": now}
        if row:
            c.execute("""
              UPDATE weather_products
                 SET display_name=?, mime=?, content=?, content_hash=?, source=?,
                     received_at_utc=?, updated_at_utc=?
               WHERE key=?""",
              (disp, mime, sqlite3.Binary(data), sha, (source or "manual"), now, now, k)
            )
        else:
            c.execute("""
              INSERT INTO weather_products
                (key, display_name, mime, content, content_hash, source, received_at_utc, updated_at_utc)
              VALUES (?,?,?,?,?,?,?,?)""",
              (k, disp, mime, sqlite3.Binary(data), sha, (source or "manual"), now, now)
            )
    return {"changed": True, "etag": sha, "received_at_utc": now, "updated_at_utc": now}

# ── Light MIME/text helpers (generic) ────────────────────────────────────────
def looks_ascii_text(b: bytes) -> bool:
    """
    Best-effort check: decodes as UTF-8 → treat as text.
    """
    try:
        b.decode("utf-8")
        return True
    except Exception:
        return False

def infer_mime_for_upload(filename: str, data: bytes) -> str:
    """
    Try extension first, then sniff ASCII vs binary.
    """
    mt = (mimetypes.guess_type(filename or "")[0] or "").lower()
    return mt if mt else ("text/plain" if looks_ascii_text(data) else "application/octet-stream")

def _parse_iso_utc(ts: str | None) -> datetime | None:
    """
    Parse ISO-8601 (optionally with 'Z') into an aware UTC datetime.
    Returns None if parsing fails.
    """
    if not ts:
        return None
    try:
        s = ts.strip()
        # Handle trailing 'Z'
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return None

def age_seconds(ts_iso: str | None, *, now: datetime | None = None) -> int:
    """
    Non-negative age in whole seconds between `now` (UTC) and `ts_iso`.
    Unparseable timestamps return 0.
    """
    now = now or datetime.now(timezone.utc)
    dt  = _parse_iso_utc(ts_iso)
    return max(0, int((now - dt).total_seconds())) if dt else 0

# ── shared helper: mirror Winlink traffic into communications ────────────────
def _mirror_comm_winlink(timestamp_utc, direction, from_party, to_party,
                         subject, body, operator=None, metadata=None):
    """
    Centralized, best-effort mirror. Uses modules.utils.comms.insert_comm if
    available, else falls back to a direct INSERT. Never raises upstream.
    """
    meta_json = json.dumps(metadata or {}, ensure_ascii=False)
    # Try the shared helper first to keep logic/schema in one place.
    try:
        from modules.utils.comms import insert_comm as _insert_comm  # type: ignore
        _insert_comm(timestamp_utc, "Winlink", direction, from_party, to_party,
                     subject, body, operator=operator, metadata_json=meta_json)
        return
    except Exception:
        pass
    # Fallback: direct insert (kept deliberately simple).
    try:
        with sqlite3.connect(get_db_file()) as _c:
            _c.execute("""
              INSERT INTO communications(
                timestamp_utc, method, direction,
                from_party, to_party, subject, body, operator, metadata_json
              ) VALUES (?, 'Winlink', ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp_utc, direction, from_party, to_party,
                  subject, body, operator or '', meta_json))
    except Exception:
        pass

def sanitize_name(raw: str) -> str:
    cleaned = re.sub(r'[^\w\s]', ' ', raw or '')
    words   = cleaned.lower().split()
    # strip out any “English adjectives” but preserve all remaining words
    nouns = [w for w in words if w not in ENGLISH_ADJECTIVES]
    if nouns:
        # join them back into a multi-word phrase
        return " ".join(nouns)
    # if everything was filtered, fall back to last token
    return words[-1] if words else ''

def ensure_column(table, col, ctype="TEXT"):
    with sqlite3.connect(get_db_file()) as c:
        # If the table doesn't exist yet, don't try to ALTER it.
        exists = c.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,)
        ).fetchone()
        if not exists:
            return
        have = {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
        if col not in have:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ctype}")

def haversine(lat1, lon1, lat2, lon2):
    # all args in decimal degrees → km
    R = 6371.0
    φ1, φ2 = map(math.radians, (lat1, lat2))
    Δφ = math.radians(lat2 - lat1)
    Δλ = math.radians(lon2 - lon1)
    a = math.sin(Δφ/2)**2 + math.cos(φ1)*math.cos(φ2)*math.sin(Δλ/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

def fetch_recv_loc():
    """Grab <pre>LAT, LON</pre> from localhost:/info once."""
    try:
        # ensure extension bucket exists
        app.extensions.setdefault('recv_loc', {'lat': None, 'lon': None})
        html = urlopen("http://localhost/info/").read().decode('utf-8')
        m = re.search(r'<pre>\s*([0-9.+-]+),\s*([0-9.+-]+)\s*</pre>', html)
        if m:
            app.extensions['recv_loc']['lat'] = float(m.group(1))
            app.extensions['recv_loc']['lon'] = float(m.group(2))
    except:
        pass

def distances_worker():
    """Continuously read JSON lines from 30154 and compute distances."""
    while True:
        try:
            sock = socket.create_connection(('127.0.0.1', 30154), timeout=5)
            f = sock.makefile('r')
            for line in f:
                try:
                    rec = json.loads(line)
                    call = rec.get('flight','').strip()
                    lat2 = rec.get('lat')
                    lon2 = rec.get('lon')
                    # ensure extension buckets exist
                    loc = app.extensions.setdefault('recv_loc', {'lat': None, 'lon': None})
                    dmap = app.extensions.setdefault('distances', {})
                    lat1 = loc.get('lat')
                    lon1 = loc.get('lon')
                    if call and (lat1 is not None) and (lat2 is not None) and (lon2 is not None):
                        km_val = haversine(float(lat1), float(lon1), float(lat2), float(lon2))
                        # store both the latest distance *and* when we saw it
                        dmap[call] = (round(km_val,1), time.time())
                except:
                    continue
        except:
            time.sleep(5)

def seed_default_categories():
    defaults = ['emergency supplies','food','medical supplies','water','other']
    with sqlite3.connect(get_db_file()) as c:
        for nm in defaults:
            c.execute("""
              INSERT OR IGNORE INTO inventory_categories(name, display_name)
              VALUES(?,?)
            """, (nm, nm.title()))

def now_hhmm():
    return datetime.utcnow().strftime('%H%M')

def _add_hhmm(start, delta):
    """start,delta = 'HHMM' strings → return (start+delta) % 24h as HHMM"""
    try:
        sh,sm = int(start[:2]), int(start[2:])
        dh,dm = int(delta[:2]), int(delta[2:])
        total = (sh*60+sm) + (dh*60+dm)
        total%= 1440
        return f"{total//60:02}{total%60:02}"
    except Exception:
        return ''

def round_half_kg(val):
    return round(val * 2) / 2

def _create_tables_wargame_ramp_requests(c):
    # Air‑cargo requests that appear on Wargame → Ramp dashboard
    c.execute("""
      CREATE TABLE IF NOT EXISTS wargame_ramp_requests (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at       TEXT    NOT NULL,
        destination      TEXT    NOT NULL,
        requested_weight REAL    NOT NULL,
        manifest         TEXT,
        satisfied_at     TEXT
      )""")

def _create_tables_cargo_requests(c):
    """
    Schema for Cargo Requests (aggregated per-airport, per-sanitized item).
    - One row per (airport_canon, sanitized_name).
    - requested_lb grows as new requests are manually parsed/added.
    - fulfilled_lb grows as landed flight manifests are applied.
    - If fulfilled_lb >= requested_lb, the line is deleted (auto-close).
    """
    c.execute("""
      CREATE TABLE IF NOT EXISTS cargo_requests (
        airport_canon   TEXT NOT NULL,
        sanitized_name  TEXT NOT NULL,
        requested_lb    REAL NOT NULL DEFAULT 0,
        fulfilled_lb    REAL NOT NULL DEFAULT 0,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL,
        last_source_id  TEXT,
        PRIMARY KEY (airport_canon, sanitized_name)
      )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_cargo_req_airport ON cargo_requests(airport_canon)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_cargo_req_remaining ON cargo_requests(airport_canon, requested_lb, fulfilled_lb)")


def get_preference(name: str) -> str | None:
    """Fetch a single preference value (or sensible default if not set)."""
    rows = dict_rows("SELECT value FROM preferences WHERE name=?", (name,))
    val = rows[0]['value'] if rows else None
    # Provide opinionated defaults for new feature flags
    key = (name or '').strip()
    if key == 'map_tiles_path':
        v = blankish_to_none(val)
        return v if v is not None else os.path.join(os.path.dirname(get_db_file()), 'tiles')
    if key == 'adsb_poll_interval_s':
        v = blankish_to_none(val)
        return v if v is not None else '10'
    if key == 'adsb_poll_enabled':
        v = blankish_to_none(val)
        return v if v is not None else 'no'
    if key == 'map_offline_seed':
        v = blankish_to_none(val)
        return v if v is not None else 'yes'
    if key == 'aoct_auto_reply_flight':
        v = blankish_to_none(val)
        return v if v is not None else 'yes'
    if key == 'adsb_base_url':
        # default empty string
        return (val or '')
    if key == 'adsb_stream_url':
        # JSON-lines stream for readsb/tar1090 (:30154). Accepts:
        #   • tcp://host:port   (recommended)
        #   • http://host:port/ (if your setup serves JSONL over HTTP)
        v = blankish_to_none(val)
        return v if v is not None else 'tcp://127.0.0.1:30154'
    if key == 'adsb_retention_hours':
        # retention window for ADS-B table purge (in hours); default 24h
        v = blankish_to_none(val)
        return v if v is not None else '24'
    return val

    if key == 'wx_catalog_body':
        # default 5 weather products
        v = blankish_to_none(val)
        return v if v is not None else 'WCCOL.JPG\nWCIR.JPG\nWCVS.JPG\nUSWXRAD.GIF\nWA_FOR_WA'
    if key == 'wx_display_names':
        v = val or ''
        return v

# ── ADS-B Adapter (Step 6) ──────────────────────────────────────────────────
def _epoch_to_iso_utc(val) -> str:
    """Convert seconds (int/float/str) since epoch → ISO-8601 Z. Fallback to now."""
    try:
        sec = float(val)
        dt  = datetime.fromtimestamp(sec, tz=timezone.utc)
        return iso8601_ceil_utc(dt)
    except Exception:
        return iso8601_ceil_utc()

def _as_float(x):
    try:
        if x is None or (isinstance(x, float) and x != x):  # NaN check
            return None
        return float(x)
    except Exception:
        try:
            m = re.search(r'[-+]?\d+(?:\.\d+)?', str(x))
            return float(m.group(0)) if m else None
        except Exception:
            return None

def _sanitize_tail(t: str | None) -> str:
    return (t or '').strip().upper()

def _receiver_station_defaults() -> tuple[str, str]:
    """Resolve preferred receiver airport/call from preferences (or blanks)."""
    ap   = canonical_airport_code(get_preference('default_origin') or '') or ''
    call = (get_preference('winlink_callsign_1') or '').strip().upper()
    return ap, call

def _normalize_adsb_dict(obj: dict, *, sample_ts_iso: str, source: str) -> Optional[dict]:
    """
    Map raw readsb/tar1090 keys → canonical dict:
      tail, lat, lon, track_deg?, speed_kt?, alt_ft?, sample_ts_utc, receiver_airport, receiver_call, source
    Returns None if lat/lon missing.
    """
    # Validate bounds for coordinates and clamp speed/alt to sane ranges
    lat = clamp_range(_as_float(obj.get('lat')),  -90.0,  90.0)
    lon = clamp_range(_as_float(obj.get('lon')), -180.0, 180.0)
    if lat is None or lon is None:
        return None
    track = _as_float(obj.get('track') or obj.get('trk') or obj.get('heading'))
    # Prefer geometric altitude, then baro
    alt = _as_float(obj.get('alt_geom') if obj.get('alt_geom') not in (None, 'ground') else None)
    if alt is None:
        alt = _as_float(obj.get('alt_baro'))
    alt = clamp_range(alt, -1000.0, 60000.0)
    gs  = _as_float(obj.get('gs') or obj.get('speed') or obj.get('speed_kt'))
    gs  = clamp_range(gs, 0.0, 800.0)
    # Tail / registration:
    #   • Prefer readsb/tar1090 'r' (registration)
    #   • Fall back to 'registration' if present
    #   • Many GA aircraft only populate 'flight' with the N-number → accept that
    tail = _sanitize_tail(obj.get('r') or obj.get('registration') or '')
    if not tail:
        f = (obj.get('flight') or obj.get('callsign') or '').strip()
        # keep only A–Z, 0–9, and '-' then upper
        f = re.sub(r'[^A-Za-z0-9-]', '', f).upper()
        # basic sanity: at least 3 chars (e.g., "N12", "C-GABC"), max 8
        if 3 <= len(f) <= 8:
            tail = f
    rx_ap, rx_call = _receiver_station_defaults()
    return {
        'tail': tail,
        'lat': float(lat),
        'lon': float(lon),
        'track_deg': None if track is None else float(track % 360.0),
        'speed_kt': None if gs is None else float(gs),
        'alt_ft': None if alt is None else float(alt),
        'sample_ts_utc': sample_ts_iso,
        'receiver_airport': rx_ap,
        'receiver_call': rx_call,
        'source': source
    }

def adsb_fetch_snapshot(*, _budget_s: float | None = None) -> List[dict]:
    """
    Try to read {base}/data/aircraft.json (tar1090/readsb).
    Returns a list of normalized dicts (see _normalize_adsb_dict), possibly empty.
    """
    # Build candidate base URLs (preference first, then common localhost fallbacks)
    base = (get_preference('adsb_base_url') or '').strip()
    candidates = []
    if base:
        candidates.append(base)
    # Common local defaults
    candidates.extend([
        "http://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1/tar1090",
        "http://localhost/tar1090",
    ])

    last_err = None
    for b in candidates:
        try:
            url = b.rstrip('/') + "/data/aircraft.json"
            # respect remaining budget if provided (min 0.3s)
            to = 3
            if _budget_s is not None:
                to = max(0.3, min(3.0, _budget_s))
            with urlopen(url, timeout=to) as resp:
                raw = resp.read()
            doc = json.loads(raw.decode('utf-8', errors='ignore'))
            # tar1090/readsb top-level 'now' is seconds since epoch
            ts_iso = _epoch_to_iso_utc(doc.get('now')) if isinstance(doc, dict) else iso8601_ceil_utc()
            source = "TAR1090" if ('tar1090' in b.lower()) else "readsb"
            out: List[dict] = []
            ac_list = (doc.get('aircraft') if isinstance(doc, dict) else None) or []
            for rec in ac_list:
                if not isinstance(rec, dict):
                    continue
                norm = _normalize_adsb_dict(rec, sample_ts_iso=ts_iso, source=source)
                if norm:
                    out.append(norm)
            return out
        except Exception as e:
            last_err = e
            continue
    # No candidates worked
    if last_err:
        logger.debug("adsb_fetch_snapshot failed: %s", last_err, exc_info=True)
    return []

def adsb_bulk_upsert(rows: List[dict]) -> int:
    """
    Insert a batch of normalized ADS-B rows into adsb_sightings.
    De-dupe by (tail, sample_ts_utc, lat, lon) and skip blank tails.
    Returns number of rows inserted.
    """
    if not rows:
        return 0
    n = 0
    with sqlite3.connect(get_db_file()) as c:
        cur = c.cursor()
        for r in rows:
            tail = (r.get('tail') or '').strip().upper()
            if not tail:
                continue
            sample = r.get('sample_ts_utc') or ''
            lat = r.get('lat'); lon = r.get('lon')
            if lat is None or lon is None:
                continue
            cur.execute("""
              INSERT INTO adsb_sightings
                (tail, sample_ts_utc, lat, lon, track_deg, speed_kt, alt_ft,
                 receiver_airport, receiver_call, source, inserted_at_utc)
              SELECT ?,?,?,?,?,?,?,?,?,?,?
               WHERE NOT EXISTS (
                 SELECT 1 FROM adsb_sightings
                  WHERE tail=? AND sample_ts_utc=?
                    AND ABS(IFNULL(lat,0)-?) < 1e-7
                    AND ABS(IFNULL(lon,0)-?) < 1e-7
               )
            """, (
                tail, sample, r.get('lat'), r.get('lon'),
                r.get('track_deg'), r.get('speed_kt'), r.get('alt_ft'),
                r.get('receiver_airport'), r.get('receiver_call'),
                r.get('source'), iso8601_ceil_utc(),
                # EXISTS args
                tail, sample, r.get('lat'), r.get('lon')
            ))
            if cur.rowcount > 0:
                n += 1
    return n

def adsb_latest_from_table(tail: str) -> dict | None:
    t = _sanitize_tail(tail)
    if not t:
        return None
    try:
        rows = dict_rows("""
            SELECT tail, sample_ts_utc, lat, lon, track_deg, speed_kt, alt_ft,
                   receiver_airport, receiver_call, source
              FROM adsb_sightings
             WHERE UPPER(tail) = ?
             ORDER BY sample_ts_utc DESC
             LIMIT 1
        """, (t,))
        return rows[0] if rows else None
    except Exception:
        return None

def adsb_parse_socket_lines(lines: Iterable[str]) -> List[dict]:
    """
    Parse JSON lines coming from the :30154 feed (readsb/TAR1090 JSONL).
    Returns normalized dicts; empty list on failure.
    """
    ts_default = iso8601_ceil_utc()
    out: List[dict] = []
    for ln in lines:
        try:
            rec = json.loads(ln.strip())
            if not isinstance(rec, dict):
                continue
            ts_iso = _epoch_to_iso_utc(rec.get('now')) if 'now' in rec else ts_default
            norm = _normalize_adsb_dict(rec, sample_ts_iso=ts_iso, source="readsb")
            if norm:
                out.append(norm)
        except Exception:
            continue
    return out

def adsb_latest_for_tail(tail: str) -> dict | None:
    """
    Return the latest sighting dict for a given tail using either:
      1) adsb_sightings table (preferred when populated), or
      2) on-demand snapshot (aircraft.json) or socket (:30154) feed.
    Normalized keys:
      tail, lat, lon, track_deg?, speed_kt?, alt_ft?, sample_ts_utc,
      receiver_airport, receiver_call, source
    """
    t = _sanitize_tail(tail)
    if not t:
        return None

    # 1) Try DB first (cheap and already normalized)
    try:
        rows = dict_rows("""
            SELECT tail, sample_ts_utc, lat, lon, track_deg, speed_kt, alt_ft,
                   receiver_airport, receiver_call, source
              FROM adsb_sightings
             WHERE UPPER(tail) = ?
             ORDER BY sample_ts_utc DESC
             LIMIT 1
        """, (t,))
        if rows:
            return rows[0]
    except Exception:
        # best-effort only
        pass

    # 2) On-demand HTTP snapshot (tar1090/readsb)
    if _AOCT_DISABLE_ONDEMAND_ADSB:
        return None
    try:
        # overall wall-clock budget across all branches
        start = time.perf_counter()
        budget = _AOCT_ADSB_BUDGET_MS / 1000.0
        for rec in adsb_fetch_snapshot(_budget_s=budget - (time.perf_counter() - start)):
            # after normalization 'tail' is set; still be tolerant
            rt = _sanitize_tail(rec.get('tail') or rec.get('registration') or '')
            if rt == t and rec.get('lat') is not None:
                return rec
    except Exception:
        pass

    # 3) Live socket feed (:30154 JSON lines)
    if _AOCT_DISABLE_ONDEMAND_ADSB:
        return None
    try:
        # keep socket dial within remaining budget
        start = time.perf_counter()
        budget = _AOCT_ADSB_BUDGET_MS / 1000.0
        remain = max(0.3, budget - (start - start))  # ≈ budget (avoid 0)
        sock = socket.create_connection(('127.0.0.1', 30154), timeout=min(2, remain))
        f = sock.makefile('r')
        lines = []
        # cap read loop by remaining budget too
        deadline = time.time() + min(1.5, max(0.3, budget - (time.perf_counter() - start)))
        while time.time() < deadline:
            ln = f.readline()
            if not ln:
                break
            lines.append(ln)
            if len(lines) >= 1000:
                break
        try:
            sock.close()
        except Exception:
            pass
        for rec in adsb_parse_socket_lines(lines):
            if _sanitize_tail(rec.get('tail')) == t and rec.get('lat') is not None:
                return rec
    except Exception:
        pass

    return None

def adsb_auto_lookup_tail(tail: str) -> dict | None:
    """
    Helper for auto-replies:
      • If the ADS-B poller is ON → prefer table lookup only (no live HTTP).
      • If OFF → perform a one-shot on-demand fetch (DB fallback still OK).
    """
    # Prefer table when the poller is ON, or when live lookups are disabled.
    try:
        poll_on = (get_preference('adsb_poll_enabled') or 'no').strip().lower() == 'yes'
    except Exception:
        poll_on = False
    if poll_on or _AOCT_DISABLE_ONDEMAND_ADSB:
        return adsb_latest_from_table(tail)
    return adsb_latest_for_tail(tail)

def adsb_fetch_stream_snapshot(max_lines: int = 1000, timeout_s: float = 1.8) -> List[dict]:
    """
    Read a short burst from the configured JSON-lines stream and return
    normalized sighting dicts suitable for adsb_bulk_upsert(...).
    Supports:
      • tcp://host:port    (recommended; readsb/tar1090 :30154)
      • http://host:port/  (if your setup proxies JSON-lines over HTTP)
    Falls back to [] on any error.
    """
    try:
        url = (get_preference('adsb_stream_url') or 'tcp://127.0.0.1:30154').strip()
    except Exception:
        url = 'tcp://127.0.0.1:30154'

    # Parse scheme without adding a top-level import
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        scheme = (parsed.scheme or 'tcp').lower()
    except Exception:
        parsed = None
        scheme = 'tcp'

    # TCP JSON-lines (readsb)
    if scheme in ('tcp', ''):
        try:
            host = parsed.hostname or '127.0.0.1'
            port = parsed.port or 30154
            sock = socket.create_connection((host, port), timeout=timeout_s)
            f = sock.makefile('r', encoding='utf-8', errors='ignore')
            lines: List[str] = []
            deadline = time.time() + timeout_s
            while time.time() < deadline and len(lines) < max_lines:
                ln = f.readline()
                if not ln:
                    break
                lines.append(ln)
            try:
                sock.close()
            except Exception:
                pass
            return adsb_parse_socket_lines(lines)
        except Exception:
            return []

    # HTTP(S) JSON-lines
    if scheme in ('http', 'https'):
        try:
            # Read a bounded chunk to avoid hanging on infinite streams
            with urlopen(url, timeout=timeout_s) as resp:
                raw = resp.read(128 * 1024)  # up to 128 KiB
            text = raw.decode('utf-8', errors='ignore')
            # Primary: treat as JSON-lines
            if '\n' in text:
                return adsb_parse_socket_lines(text.splitlines())
            # Fallback: if a single JSON object/array slipped through, try to normalize it
            try:
                doc = json.loads(text)
            except Exception:
                return []
            # If it looks like aircraft.json, reuse that path’s normalizer quickly
            if isinstance(doc, dict) and isinstance(doc.get('aircraft'), list):
                ts_iso = _epoch_to_iso_utc(doc.get('now'))
                out: List[dict] = []
                for rec in doc.get('aircraft') or []:
                    if not isinstance(rec, dict):
                        continue
                    norm = _normalize_adsb_dict(rec, sample_ts_iso=ts_iso, source="readsb")
                    if norm:
                        out.append(norm)
                return out
            # Otherwise: nothing usable
            return []
        except Exception:
            return []

    # Unknown scheme
    return []


# ── Validation / clamping helpers (defensive parsing) ───────────────────────
def clamp_range(val: float | int | None, lo: float, hi: float) -> float | None:
    """
    Clamp numeric input into [lo, hi]. Returns None if input is None or unparseable.
    """
    if val is None:
        return None
    try:
        x = float(val)
        if x < lo: return lo
        if x > hi: return hi
        return x
    except Exception:
        return None

def set_preference(name: str, value: str) -> None:
    """Upsert a preference."""
    with sqlite3.connect(get_db_file()) as c:
        c.execute("""
            INSERT INTO preferences(name,value)
            VALUES(?,?)
            ON CONFLICT(name) DO UPDATE
              SET value = excluded.value
        """, (name, value))

    # Side effects for Wargame toggles/settings: install/refresh jobs immediately
    try:
        if name == 'wargame_settings':
            # Rebuild generator jobs (radio/ramp/inv) from new rates
            from modules.services.jobs import apply_supervisor_settings
            apply_supervisor_settings()
        elif name == 'wargame_mode':
            # Turning Wargame on should (re)install all jobs in one go
            if str(value).strip().lower() == 'yes':
                from modules.services.jobs import configure_wargame_jobs, apply_supervisor_settings
                configure_wargame_jobs()
                apply_supervisor_settings()
            else:
                # Best-effort: tear down generator jobs when Wargame is disabled
                from app import scheduler
                for jid in ('job_radio','job_inventory_out','job_inventory_in','job_ramp_requests',
                            'job_radio_dispatch','job_inbound_schedule','job_remote_confirm'):
                    try:
                        scheduler.remove_job(jid)
                    except Exception:
                        pass

        # NetOps feeder settings should (re)configure the job immediately
        if name.startswith('netops_') or name in ('origin_lat','origin_lon'):
            try:
                from modules.services.jobs import configure_netops_feeders
                configure_netops_feeders()
            except Exception:
                pass

    except Exception:
        # Never hard-fail a preference write if scheduling errors occur
        pass

    # Keep retention job configured and refreshed when its pref changes.
    try:
        if name == 'adsb_retention_hours':
            from modules.services.jobs import configure_retention_jobs
            configure_retention_jobs()
        # Turning the local ADS-B poller on/off or changing its cadence
        # should immediately (re)configure the scheduler job.
        if name in ('adsb_poll_enabled', 'adsb_poll_interval_s'):
            try:
                from modules.services.jobs import configure_adsb_poller_job
                configure_adsb_poller_job()
            except Exception:
                # best-effort only; never block preference writes
                pass
    except Exception:
        # Best-effort: don't block preference writes on scheduling errors.
        pass

def clear_embedded_preferences() -> None:
    """Remove any embedded‑tab prefs and reset distances off."""
    with sqlite3.connect(get_db_file()) as c:
        c.execute("DELETE FROM preferences WHERE name IN ('embedded_url','embedded_name')")
        # ensure the distances flag is off
        c.execute("""
            INSERT INTO preferences(name,value)
            VALUES('enable_1090_distances','no')
            ON CONFLICT(name) DO UPDATE
              SET value = excluded.value
        """)

def hhmm_from_iso(iso_str: str) -> str:
    """Convert an ISO8601 string to HHMM, fallback to 'TBD' if parse fails."""
    try:
        return datetime.fromisoformat(iso_str).strftime('%H%M')
    except Exception:
        return 'TBD'

def safe_csv_cell(s) -> str:
    """
    Guard against Excel CSV formula injection.
    If the cell begins with TAB or CR, or the first *non-space* character is
    one of = + - @, prefix a single quote. Otherwise return the value as-is.
    Always returns a str; None becomes ''.
    """
    if s is None:
        return ''
    t = str(s)
    if not t:
        return ''
    if t[0] in ('\t', '\r'):
        return "'" + t
    lead = t.lstrip()
    if lead and lead[0] in ('=', '+', '-', '@'):
        return "'" + t
    return t

def choose_ramp_direction_with_balance() -> str:
    """
    Steer the ramp generator toward a 50/50 inbound/outbound mix within
    ±balance_pct, considering expected inbound that hasn't appeared yet.
    """
    # settings
    srow = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
    settings = json.loads(srow[0]['value'] or '{}') if srow else {}
    band_pct = float(settings.get('balance_pct', 20))  # e.g., 20 => ±20%
    band = max(0.0, min(0.5, band_pct / 100.0))       # clamp to [0, 50%]
    target = 0.5

    # window (optional; defaults to last 60 minutes if not present)
    window_min = int(settings.get('balance_window_min', 60))
    since = (datetime.utcnow() - timedelta(minutes=window_min)).isoformat()
    now_iso = datetime.utcnow().isoformat()

    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row

        # 1) Current visible ramp flights by direction
        cur = c.execute("""
            SELECT direction, COUNT(*) AS cnt
              FROM flights
             WHERE is_ramp_entry=1
               AND timestamp >= ?
             GROUP BY direction
        """, (since,))
        counts = {r['direction']: r['cnt'] for r in cur.fetchall()}
        inbound_current  = counts.get('inbound', 0)
        outbound_current = counts.get('outbound', 0)

        # 2) Future inbound already scheduled (radio or confirmations already queued)
        inbound_scheduled = c.execute("""
            SELECT COUNT(*) AS n
              FROM wargame_inbound_schedule
             WHERE eta > ?
        """, (now_iso,)).fetchone()['n']

        # 3) Outbounds sent but not yet turned into inbound schedule (confirmation pending)
        pending_confirms = c.execute("""
            SELECT COUNT(*) AS n
              FROM flights f
             WHERE f.is_ramp_entry=1
               AND f.direction='outbound'
               AND f.sent=1
               AND f.complete=0
               AND NOT EXISTS (
                     SELECT 1
                       FROM wargame_inbound_schedule s
                      WHERE s.tail_number      = f.tail_number
                        AND s.airfield_takeoff = f.airfield_landing
                        AND s.airfield_landing = f.airfield_takeoff
                   )
        """).fetchone()['n']

    inbound_expected = inbound_current + inbound_scheduled + pending_confirms
    total_expected   = inbound_expected + outbound_current
    frac_inbound = (inbound_expected / total_expected) if total_expected > 0 else target

    lower = target - band
    upper = target + band

    if frac_inbound > upper:
        return 'outbound'  # too inbound-heavy → push outbound
    if frac_inbound < lower:
        return 'inbound'   # too outbound-heavy → push inbound

    # Inside the band: mild bias toward the center to avoid drift/oscillation
    # Probability of choosing inbound pulls toward target.
    d = (target - frac_inbound)
    p_inbound = max(0.1, min(0.9, 0.5 + d))  # clamp a bit for randomness
    return 'inbound' if random.random() < p_inbound else 'outbound'

def dict_rows(sql, params=()):
    """SELECT helper → list[dict]; logs slow queries if enabled."""
    t0 = time.perf_counter()
    with connect(get_db_file(), timeout=30) as c:
        c.row_factory = sqlite3.Row
        if SQL_TRACE and SQL_TRACE_EXPANDED:
            try:
                c.set_trace_callback(lambda s: _sql_logger.debug("SQL EXPANDED | %s", s))
            except Exception:
                pass
        cur = c.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
    dt_ms = (time.perf_counter() - t0) * 1000.0
    try:
        if _AOCT_SQL_LOG or dt_ms >= _AOCT_SQL_SLOW_MS:
            one = " ".join((sql or "").strip().split())
            _sql_logger.warning("[SQL %s %.1f ms] %s | params=%s",
                               "SLOW" if dt_ms >= _AOCT_SQL_SLOW_MS else "OK", dt_ms, one, params)
            if _AOCT_SQL_EXPLAIN and one.lstrip().upper().startswith("SELECT"):
                with connect(get_db_file(), timeout=30) as c2:
                    plan = c2.execute("EXPLAIN QUERY PLAN " + one, params).fetchall()
                _sql_logger.warning("[SQL PLAN] %s", "; ".join(str(tuple(r)) for r in plan))
    except Exception:
        pass
    return rows

def hhmm_norm(t:str)->str: return t.strip().zfill(4) if t.strip() else ''

def to_icao(code:str)->str:
    code=code.strip().upper()
    return 'K'+code if len(code)==3 and not code.startswith(('K','C')) else code

def kg_to_lbs(kg:float)->float: return round(kg*2.20462,1)

def norm_weight(w:str, unit:str)->str:
    w=w.strip();  # blank allowed
    if not w: return ''
    try: num=float(w)
    except ValueError: return w
    if unit=='kg': num=kg_to_lbs(num)
    return f"{num} lbs"

def hide_tbd_filter(value):
    """
    Jinja filter: blank out any of '', None, 'TBD' or '—'.
      In templates: {{ some_field|hide_tbd }}
    """
    return '' if value in (None, '', 'TBD', '—') else value

@lru_cache(maxsize=8192)
def canonical_airport_code(code: str) -> str:
    """
    Given any airport code, return the best canonical code for mapping.
    Prefers ICAO4, then IATA, then local_code. Falls back to uppercase input.
    """
    code = (code or '').strip().upper()
    if not code:
        return ''
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        row = c.execute(
            """
            SELECT icao_code, iata_code, local_code
              FROM airports
             WHERE icao_code  = ?
                OR iata_code  = ?
                OR gps_code   = ?
                OR ident      = ?
                OR local_code = ?
             LIMIT 1
            """,
            (code, code, code, code, code)
        ).fetchone()
    if not row:
        return code
    for k in ['icao_code', 'iata_code', 'local_code']:
        val = row[k]
        if val and val.strip():
            return val.strip().upper()
    return code

def format_airport(raw_code: str, pref: str) -> str:
    """
    Given any user input code, look up the airport and return the preferred format.
    Match priority: ICAO > IATA > GPS > ident > local.
    Falls back to raw_code if not found.
    """

    # Normalize preference
    p = str(pref or '').strip().lower()
    if p.startswith('icao'):
        pref = 'icao4'
    elif p.startswith('iata'):
        pref = 'iata'
    elif p.startswith('local'):
        pref = 'local'
    else:
        pref = 'icao4'

    code = (raw_code or '').strip().upper()
    if not code:
        return 'TBD'

    # List fields in match priority order
    priority_fields = [
        'icao_code',
        'iata_code',
        'gps_code',
        'ident',
        'local_code',
    ]

    # Query all possible matches in one go
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        matches = c.execute(
            """
            SELECT *
              FROM airports
             WHERE icao_code  = ?
                OR iata_code  = ?
                OR gps_code   = ?
                OR ident      = ?
                OR local_code = ?""", (code, code, code, code, code)).fetchall()

    if not matches:
        return raw_code

    # Now find the *best* row per the priority order
    best_row = None
    best_rank = len(priority_fields)  # Higher is worse
    for row in matches:
        for rank, field in enumerate(priority_fields):
            if row[field] and row[field].upper() == code:
                if rank < best_rank:
                    best_row = row
                    best_rank = rank
                break  # Stop searching this row: matched on this field

    if not best_row:
        return raw_code

    # Return the requested format, fallback to sensible alternatives
    if pref == 'icao4':
        return best_row['icao_code'] or raw_code
    if pref == 'iata':
        return best_row['iata_code'] or raw_code
    if pref == 'local':
        return (best_row['gps_code'] or best_row['local_code'] or best_row['ident'] or raw_code)

    # Fallback
    return raw_code

@lru_cache(maxsize=4096)
def airport_aliases(code: str) -> list:
    """Return every recorded airport code (ident, ICAO, IATA, GPS, local) for the given input."""
    c = code.strip().upper()
    # must match all five columns against our single input
    rows = dict_rows(
        "SELECT ident, icao_code, iata_code, gps_code, local_code "
        "FROM airports "
        "WHERE ident = ? OR icao_code = ? OR iata_code = ? OR gps_code = ? OR local_code = ? ",
        (c, c, c, c, c)
    )
    if not rows:
        return [c]
    aliases = set()
    for row in rows:
        aliases |= {
            row.get('ident'),
            row.get('icao_code'),
            row.get('iata_code'),
            row.get('gps_code'),
            row.get('local_code'),
        }
    return [a.upper() for a in aliases if a]

def parse_weight_str(w):
    w = (w or '').strip()
    if not w:
        return ''
    # Convert any 'kg' flavor to lbs when a number is present; otherwise fall back unchanged.
    if 'kg' in w.lower():
        m = re.search(r"[\d.]+", w)
        if m:
            try:
                num = float(m.group(0))
                return f"{kg_to_lbs(num)} lbs"
            except Exception:
                return w
        return w
    return w

def _is_winlink_reflector_bounce(subj: str, body: str) -> bool:
    """
    Detect Winlink *test message reflector* bounces so we can ignore them
    for flight creation/updates. We still store the raw mail in
    incoming_messages for audit.
    """
    s = (subj or '').lower()
    b = (body or '').lower()
    if 'winlink test message reflector' in s or 'winlink test message reflector' in b:
        return True
    s = (subj or '')
    b = (body or '').lower()
    # Quoted headers in the bounce often include “To: TEST”
    if re.search(r'(?im)^\s*To:\s*TEST\b', body or ''):
        return True
    # Additional light-touch heuristics that are common on reflector bounces
    if re.search(r'(?i)\bauto(?:mated)?[ -]?reply|automated response\b', s):
        return True
    if re.search(r'(?im)^\s*From:.*\bno-?reply\b', body or ''):
        return True
    if re.search(r'(?im)^\s*(To|From):.*\btest@winlink\.org\b', body or ''):
        return True
    if 'do not reply' in b or 'do-not-reply' in b:
        return True
    return False

def parse_csv_record(rec: dict) -> dict:
    # normalize & escape every field coming from the CSV
    tail       = escape(rec['Tail#'].strip().upper())
    frm        = escape(rec['From'].strip().upper())
    to_        = escape(rec['To'].strip().upper())
    tko        = hhmm_norm(rec['T/O'].replace(':','').strip())
    eta        = hhmm_norm(rec['ETA'].replace(':','').strip())
    cargo      = escape(rec['Cargo'].strip())
    weight_raw = rec['Weight'].strip()
    weight     = escape(parse_weight_str(weight_raw))
    remarks    = escape(rec.get('Remarks','').strip())

    return {
      'sender'           : escape(rec['Sender'].strip()),
      'subject'          : escape(rec['Subject'].strip()),
      'body'             : escape(rec['Body'].strip()),
      'timestamp'        : escape(rec['Timestamp'].strip()),
      'tail_number'      : tail,
      'airfield_takeoff' : frm,
      'airfield_landing' : to_,
      'takeoff_time'     : tko,
      'eta'              : eta,
      'cargo_type'       : cargo,
      'cargo_weight'     : weight,
      'remarks'          : remarks
    }

def apply_incoming_parsed(p: dict) -> tuple[int,str]:
    """
    Given a parsed record `p` (with keys sender,subject,body,timestamp,
    tail_number,airfield_takeoff,…,remarks),
    insert into incoming_messages, then update or insert flights.
    Returns (flight_id, action) where action is 'landed','updated', or 'new'.
    """
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row

        # 1) raw store
        c.execute("""
          INSERT INTO incoming_messages(
            sender, subject, body, timestamp,
            tail_number, airfield_takeoff, airfield_landing,
            takeoff_time, eta, cargo_type, cargo_weight, remarks
          ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
          p['sender'], p['subject'], p['body'], p['timestamp'],
          p['tail_number'], p['airfield_takeoff'], p['airfield_landing'],
          p['takeoff_time'], p['eta'], p['cargo_type'], p['cargo_weight'],
          p.get('remarks','')
        ))

        # 1a) communications mirror (inbound)
        try:
            _mirror_comm_winlink(
                p.get('timestamp') or iso8601_ceil_utc(),
                "in",
                from_party=p.get('sender') or '',
                to_party=(get_preference('winlink_callsign_1') or 'OPERATOR'),
                subject=p.get('subject', ''),
                body=p.get('body', ''),
                operator=None,  # inbound: no definitive human operator yet
                metadata={
                    "tail_number": p.get('tail_number') or '',
                    "flight_code": (maybe_extract_flight_code(p.get('subject','')) or
                                    maybe_extract_flight_code(p.get('body','')) or '')
                }
            )
        except Exception:
            pass

        # Ignore Winlink *test message reflector* bounces beyond raw store.
        if _is_winlink_reflector_bounce(p.get('subject',''), p.get('body','')):
            return 0, 'ignored_reflector'

        # 2) attempt flight-code extraction from subject/body
        fcode = maybe_extract_flight_code(p.get('subject','')) or \
                maybe_extract_flight_code(p.get('body',''))

        # 2a) landed by explicit code match (preferred new step)
        if fcode:
            match = c.execute("""
              SELECT id, remarks FROM flights
               WHERE flight_code=? AND complete=0
               ORDER BY id DESC LIMIT 1
            """, (fcode,)).fetchone()
            if match:
                arrival = hhmm_norm(p.get('eta') or now_hhmm())
                before = dict_rows("SELECT * FROM flights WHERE id=?", (match['id'],))[0]
                c.execute("INSERT INTO flight_history(flight_id, timestamp, data) VALUES (?,?,?)",
                          (match['id'], datetime.utcnow().isoformat(), json.dumps(before)))
                old_rem = match['remarks'] or ''
                new_rem = (f"{old_rem} / Arrived {arrival}" if old_rem else f"Arrived {arrival}")
                c.execute("""
                  UPDATE flights
                     SET eta=?, complete=1, sent=0, remarks=?, flight_code=?
                   WHERE id=?
                """, (arrival, new_rem, fcode, match['id']))
                return match['id'], 'landed'

        # 2b) landing? (legacy heuristics)
        # detect “landed HHMM” too (e.g. “landed 09:53” or “landed 0953”)
        lm = re.search(r'\blanded\s*(\d{1,2}:?\d{2})\b', p['subject'], re.I)
        if lm:
            arrival = hhmm_norm(lm.group(1))
            # 1) strict tail + latest open
            match = c.execute("""
              SELECT id, remarks
                FROM flights
               WHERE tail_number=? AND complete=0
               ORDER BY id DESC
               LIMIT 1
            """, (p['tail_number'],)).fetchone()
            # 2) route-based fallback
            if not match and p['airfield_takeoff'] and p['airfield_landing']:
                match = c.execute("""
                  SELECT id, remarks
                    FROM flights
                   WHERE tail_number=?
                     AND airfield_takeoff=? AND airfield_landing=? AND complete=0
                   ORDER BY id DESC
                   LIMIT 1
                """, (p['tail_number'], p['airfield_takeoff'], p['airfield_landing'])).fetchone()
            # 3) most-recent fallback
            if not match:
                match = c.execute("""
                  SELECT id, remarks
                    FROM flights
                   WHERE tail_number=? AND complete=0
                   ORDER BY timestamp DESC
                   LIMIT 1
                """, (p['tail_number'],)).fetchone()
            if match:
                before = dict_rows(
                    "SELECT * FROM flights WHERE id=?",
                    (match['id'],)
                )[0]
                c.execute("""
                  INSERT INTO flight_history(flight_id, timestamp, data)
                  VALUES (?,?,?)
                """, (
                  match['id'],
                  datetime.utcnow().isoformat(),
                  json.dumps(before)
                ))
                old_rem = match['remarks'] or ''
                new_rem = (
                    f"{old_rem} / Arrived {arrival}"
                    if old_rem else
                    f"Arrived {arrival}"
                )
                c.execute("""
                  UPDATE flights
                     SET eta=?, complete=1, sent=0, remarks=?, flight_code=COALESCE(?, flight_code)
                   WHERE id=?
                """, (arrival, new_rem, fcode, match['id']))
                return match['id'], 'landed'

        # 3) not a landing → match by tail & takeoff_time
        f = c.execute(
            "SELECT id FROM flights WHERE tail_number=? AND takeoff_time=?",
            (p['tail_number'], p['takeoff_time'])
        ).fetchone()

        # fallback: same tail + same origin, still-open
        if not f and p['airfield_takeoff']:
            f = c.execute("""
                SELECT id
                  FROM flights
                 WHERE tail_number=?
                   AND airfield_takeoff=?
                   AND complete=0
                 ORDER BY id DESC
                 LIMIT 1
            """, (
                p['tail_number'],
                p['airfield_takeoff']
            )).fetchone()

        if f:
            before = dict_rows(
                "SELECT * FROM flights WHERE id=?", 
                (f['id'],)
            )[0]
            c.execute("""
              INSERT INTO flight_history(flight_id, timestamp, data)
              VALUES (?,?,?)
            """, (
              f['id'],
              datetime.utcnow().isoformat(),
              json.dumps(before)
            ))

            # Only overwrite when parser actually returned non-empty values
            # Use code to backfill origin/dest/takeoff if parser didn't find them
            if fcode:
                info = parse_flight_code(fcode)
                if info:
                    if not p['airfield_takeoff']: p['airfield_takeoff'] = info['origin']
                    if not p['airfield_landing']: p['airfield_landing'] = info['dest']
                    if not p['takeoff_time']:     p['takeoff_time']     = info['hhmm']

            c.execute("""
              UPDATE flights SET
                airfield_takeoff = ?,
                airfield_landing = ?,
                eta              = CASE WHEN ?<>'' THEN ? ELSE eta END,
                cargo_type       = CASE WHEN ?<>'' THEN ? ELSE cargo_type   END,
                cargo_weight     = CASE WHEN ?<>'' THEN ? ELSE cargo_weight END,
                remarks          = CASE WHEN ?<>'' THEN ? ELSE remarks      END,
                flight_code      = COALESCE(?, flight_code)
              WHERE id=?
            """, (
              p['airfield_takeoff'],
              p['airfield_landing'],
              p['eta'],            p['eta'],
              p['cargo_type'],     p['cargo_type'],
              p['cargo_weight'],   p['cargo_weight'],
              p.get('remarks',''), p.get('remarks',''),
              fcode,
              f['id']
            ))
            return f['id'], 'updated'

        # 4) new entry (mark pure Winlink imports as inbound)
        # Backfill fields from code for brand-new entries
        if fcode:
            info = parse_flight_code(fcode)
            if info:
                p['airfield_takeoff'] = p['airfield_takeoff'] or info['origin']
                p['airfield_landing'] = p['airfield_landing'] or info['dest']
                p['takeoff_time']     = p['takeoff_time']     or info['hhmm']

        fid = c.execute("""
          INSERT INTO flights(
            is_ramp_entry, direction, flight_code,
            tail_number, airfield_takeoff, takeoff_time,
            airfield_landing, eta, cargo_type, cargo_weight, remarks
          ) VALUES (0,'inbound',?,?,?,?,?,?,?,?,?)
        """, (
          fcode,
          p['tail_number'],
          p['airfield_takeoff'],
          p['takeoff_time'],
          p['airfield_landing'],
          p['eta'],
          p['cargo_type'],
          p['cargo_weight'],
          p.get('remarks','')
        )).lastrowid
        return fid, 'new'

def refresh_user_cookies(response):
    # only replay prefs on GET responses so POST-set cookies aren't stomped
    if request.method != 'GET':
        return response

    ONE_YEAR = 31_536_000  # seconds
    pref_cookies = [
        'code_format', 'mass_unit', 'operator_call',
        'include_test', 'radio_show_unsent_only', 'show_debug_logs',
        'hide_tbd', 'distance_unit', 'scanner_mode']
    for name in pref_cookies:
        val = request.cookies.get(name)
        if val is not None:
            response.set_cookie(
                name,
                val,
                max_age=ONE_YEAR,
                samesite='Lax'
            )
    return response

def purge_blank_flights() -> None:
    """Remove flights where *every* user-facing field is blank or “TBD”."""
    with sqlite3.connect(get_db_file()) as c:
        c.execute(
            """
            DELETE FROM flights
             WHERE (IFNULL(tail_number      ,'') IN ('','TBD'))
               AND (IFNULL(airfield_takeoff ,'') IN ('','TBD'))
               AND (IFNULL(airfield_landing ,'') IN ('','TBD'))
               AND (IFNULL(takeoff_time     ,'') IN ('','TBD'))
               AND (IFNULL(eta              ,'') IN ('','TBD'))
               AND (IFNULL(cargo_type       ,'') IN ('','TBD'))
               AND (IFNULL(cargo_weight     ,'') IN ('','TBD'))
               AND (IFNULL(remarks          ,'') =  '')
            """
        )
        _create_tables_wargame_ramp_requests(c)

def get_airfield_callsign(af):
    """Map an airfield to a persistent random callsign."""
    if af not in AIRFIELD_CALLSIGNS:
        AIRFIELD_CALLSIGNS[af] = generate_random_callsign()
    return AIRFIELD_CALLSIGNS[af]

def _reset_autoincrements(names: list[str]) -> None:
    """Best‑effort reset of AUTOINCREMENT counters (SQLite keeps them after DELETE)."""
    try:
        with sqlite3.connect(get_db_file()) as c:
            for n in names:
                c.execute("DELETE FROM sqlite_sequence WHERE name=?", (n,))
    except Exception:
        # Ignore on engines without sqlite_sequence or non‑AUTOINCREMENT tables.
        pass

def seed_wargame_baseline_inventory():
    """
    Seed some shelf stock so outbound requests and Ramp can be fulfilled from the start.
    Quantities are modest and use the canonical nouns/sizes from WARGAME_ITEMS.
    """
    stock = [
        ('emergency supplies', 'batteries', 10,  12),
        ('emergency supplies', 'batteries', 25,   8),
        ('food',               'beans',     25,  10),
        ('food',               'rice',      20,  10),
        ('medical supplies',   'bandages',   5,  20),
        ('water',              'water',     20,  20),
    ]
    with sqlite3.connect(get_db_file()) as c:
        # lookup category IDs by display_name (seed_default_categories already ran)
        rows = dict_rows("SELECT id, display_name FROM inventory_categories")
        name_to_id = {r['display_name'].lower(): r['id'] for r in rows}
        ts = datetime.utcnow().isoformat()
        for cat_name, noun, size_lb, qty in stock:
            cid = name_to_id.get(cat_name.lower())
            if not cid: 
                continue
            c.execute("""
              INSERT INTO inventory_entries(
                category_id,raw_name,sanitized_name,
                weight_per_unit,quantity,total_weight,
                direction,timestamp,pending
              ) VALUES (?,?,?,?,?,?, 'in', ?, 0)
            """, (
              cid, noun, noun,
              float(size_lb), int(qty), float(size_lb)*int(qty),
              ts
            ))

def generate_radio_message():
    _hydrate_from_app()
    if not HARDCODED_AIRFIELDS:
        logger.warning("Wargame: no airfields available; skipping radio message.")
        return
    if not WARGAME_ITEMS:
        logger.warning("Wargame: no items catalog; skipping radio message.")
        return
    """Enqueue a synthetic radio email into the schedule (batch or immediate)."""
    now   = datetime.utcnow()
    ts    = now.isoformat()
    msg_id = uuid.uuid4().hex

    # pick a non‑origin airfield for the sender; choose a plausible destination
    pref   = dict_rows("SELECT value FROM preferences WHERE name='default_origin'")
    origin = (pref[0]['value'].strip().upper() if pref and pref[0]['value'] else None)
    choices = [af for af in HARDCODED_AIRFIELDS if af != origin]
    if not choices and not HARDCODED_AIRFIELDS:
        return
    af = random.choice(choices) if choices else random.choice(HARDCODED_AIRFIELDS)
    callsign = get_airfield_callsign(af)
    tail     = generate_tail_number()
    dest = origin or random.choice([x for x in HARDCODED_AIRFIELDS if x != af])

    # Respect Radio max-pending (only tasks that are visible to the operator)
    settings_row = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
    settings  = json.loads(settings_row[0]['value'] or '{}') if settings_row else {}
    # exit without completing generation if not in correct modes
    flow = settings.get('cargo_flow', 'hybrid')
    if flow not in ('air_air', 'air_ground', 'hybrid'):
        return

    max_radio = int(settings.get('max_radio', 3) or 3)
    # Count ALL open radio inbound tasks across the pipeline (visible and future-scheduled)
    pipeline_cnt = dict_rows("""
      SELECT COUNT(*) AS c
        FROM wargame_tasks
       WHERE role='radio' AND kind='inbound'
    """)[0]['c'] or 0
    if pipeline_cnt >= max_radio:
        return

    # build realistic times & Air Ops subject with a hidden WG tag
    tko_hhmm = now.strftime('%H%M')
    eta_hhmm = (now + timedelta(minutes=random.randint(12, 45))).strftime('%H%M')

    # Compute a Flight Code for the email body (freeze today's date + this leg's HHMM)
    try:
        frozen_mmddyy = now.strftime('%m%d%y')
        ooo = to_three_char_code(af)  or (af  or '')[:3].upper()
        ddd = to_three_char_code(dest) or (dest or '')[:3].upper()
        fcode = find_unique_code_or_bump(ooo, frozen_mmddyy, ddd, tko_hhmm)
    except Exception:
        fcode = None

    size    = random.randint(500, 2000)
    manifest, total_wt, cargo_type = generate_cargo_manifest()
    subject = (
        f"Air Ops: {tail} | {af} to {dest} | "
        f"took off {tko_hhmm} | ETA {eta_hhmm} [WGID:{msg_id}]"
    )

    notes = ["Auto-generated Wargame traffic."]
    if fcode:
        notes.append(f"Flight Code: {fcode}")
    if manifest:
        notes.append(f"Manifest: {manifest}")
    body = "\n".join([
        f"Cargo Type: {cargo_type}",
        (f"Total Weight of the Cargo: {int(total_wt)} lbs"
         if total_wt else "Total Weight of the Cargo: none"),
        "",
        "Additional notes/comments:",
        *[f"  {line}" for line in notes],
        "",
        "{DART Aircraft Takeoff Report, rev. 2024-05-14}"
    ])

    # read Supervisor’s settings
    settings_row = dict_rows(
        "SELECT value FROM preferences WHERE name='wargame_settings'"
    )
    settings    = json.loads(settings_row[0]['value'] or '{}') if settings_row else {}
    use_batch   = settings.get('radio_use_batch',   'no')  == 'yes'
    batch_delay_s = 300 if use_batch else 0
    scheduled_for = (now + timedelta(seconds=batch_delay_s)).isoformat()

    # start a pending Radio-inbound task now; sched_for is used for batch semantics
    wargame_task_start(
        role='radio',
        kind='inbound',
        key=f"msg:{msg_id}",
        gen_at=ts,
        sched_for=scheduled_for
    )

    with sqlite3.connect(get_db_file()) as c:
        # 1) enqueue for the Radio dashboard
        c.execute("""
          INSERT INTO wargame_radio_schedule
            (generated_at, scheduled_for,
             message_id, size_bytes,
             source, sender, recipient, subject, body)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
          ts, scheduled_for,
          msg_id, size,
          af, callsign, 'OPERATOR', subject, body
        ))

def extract_wgid_from_subject(subject: str) -> str | None:
    """
    Return WGID hex if present in the *subject* line, else None.
    Matches both “WGID:…” or “[WGID:…]”.
    """
    m = re.search(r'\[?WGID:([a-f0-9]{16,})\]?', subject, re.I)
    return m.group(1) if m else None

def extract_wgid_from_text(subject: str | None, body: str | None) -> str | None:
    """
    Find a Wargame ID anywhere in the subject or body.
    Accepts both “WGID:deadbeef…” and “[WGID:deadbeef…]”, case-insensitive.
    Returns the first hex ID found, else None.
    """
    pat = re.compile(r'\[?WGID:([a-f0-9]{16,})\]?', re.I)
    for chunk in (subject, body):
        if not chunk:
            continue
        m = pat.search(chunk)
        if m:
            return m.group(1)
    return None

def generate_cargo_manifest():
    """
    Returns: (manifest_str, total_weight_lbs, cargo_type)
      • 70% chance to include cargo
      • manifest lines are deduped by (name,size), summed quantities
      • lines sorted alphabetically by item name, then size asc
      • cargo_type is 'Mixed' when present, else 'none'
    """
    if random.random() >= 0.70:
        return ("", 0.0, "none")

    # choose 1..5 unique (name,size) pairs across the full catalog
    pairs = [(n, s) for n, sizes in WARGAME_ITEMS.items() for s in sizes]
    picks = random.sample(pairs, k=random.randint(1, 5))

    # aggregate quantities per (name,size)
    agg = {}
    for name, size in picks:
        qty = random.randint(1, 12)
        agg[(name, size)] = agg.get((name, size), 0) + qty

    total = 0.0
    lines = []
    for (name, size) in sorted(agg.keys(), key=lambda t: (t[0], t[1])):
        qty = agg[(name, size)]
        lines.append(f"{name} {size} lbx{qty}")
        total += size * qty

    manifest = "; ".join(lines)
    manifest = ensure_trailing_semicolon(manifest) if lines else ""
    return (manifest, float(total), "Mixed")

def generate_ramp_request():
    """
    Generate a cargo *request* destined to a remote airport (appears on
    Wargame → Ramp as a cue card). Enforces max_ramp cap and guarantees
    a non-empty manifest.
    """
    _hydrate_from_app()
    if not HARDCODED_AIRFIELDS:
        logger.warning("Wargame: no airfields; skipping ramp request.")
        return

    # enforce cap
    settings_row = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
    settings  = json.loads(settings_row[0]['value'] or '{}') if settings_row else {}
    # Cargo-flow gating: only generate ramp cargo requests in these modes
    flow = settings.get('cargo_flow', 'hybrid')
    if flow not in ('air_air', 'ground_air', 'hybrid'):
        return

    max_ramp  = int(settings.get('max_ramp', 3) or 3)
    open_cnt  = int(dict_rows("""
        SELECT COUNT(*) AS c
          FROM wargame_ramp_requests
         WHERE satisfied_at IS NULL
    """)[0]['c'] or 0)
    if open_cnt >= max_ramp:
        return

    ts = datetime.utcnow().isoformat()
    # choose destination ≠ our origin (if set)
    pref   = dict_rows("SELECT value FROM preferences WHERE name='default_origin'")
    origin = (pref[0]['value'].strip().upper() if pref and pref[0]['value'] else None)
    choices = [af for af in HARDCODED_AIRFIELDS if af != origin] or HARDCODED_AIRFIELDS[:]
    if not choices:
        return
    destination = random.choice(choices)

    # Build availability from committed shelf stock (only items we can actually load).
    avail = dict_rows("""
      SELECT e.sanitized_name AS noun,
             e.weight_per_unit AS size_lb,
             SUM(CASE WHEN e.direction='in' THEN e.quantity
                      WHEN e.direction='out' THEN -e.quantity END) AS qty
        FROM inventory_entries e
       WHERE e.pending=0
       GROUP BY e.sanitized_name, e.weight_per_unit
       HAVING qty > 0
    """)
    if not avail:
        return  # nothing to request yet

    picks = _r.sample(avail, k=min(len(avail), _r.randint(2,5)))
    lines, total_wt = [], 0.0
    for r in picks:
        have = int(r['qty'])
        ask  = _r.randint(1, min(4, have))
        lines.append(f"{r['noun']} {int(r['size_lb'])} lbx{ask}")
        total_wt += r['size_lb'] * ask
    manifest = ensure_trailing_semicolon('; '.join(lines)) if lines else ''

    with sqlite3.connect(get_db_file()) as c:
        cur = c.execute("""
          INSERT INTO wargame_ramp_requests(created_at, destination, requested_weight, manifest)
          VALUES (?,?,?,?)
        """, (ts, destination, float(total_wt), manifest))
        rid = cur.lastrowid
        # generate and persist a one‐off “proposed tail” for this request
        proposed = generate_tail_number()
        c.execute("""
          UPDATE wargame_ramp_requests
             SET assigned_tail = ?
           WHERE id = ?
        """, (proposed, rid))

def ensure_trailing_semicolon(s: str) -> str:
    """
    Ensure the string ends with exactly one ';' and no trailing space.
    Blank input returns blank.
    """
    t = (s or '').strip()
    if not t:
        return t
    # Collapse any trailing spaces/semicolons to a single ';'
    return re.sub(r'[;\s]+$', '', t) + ';'

# ─────────────────────────────────────────────────────────────────────────────
# Pilot acknowledgment (typed/drawn signature) helpers
# ─────────────────────────────────────────────────────────────────────────────
def _sig_now_iso() -> str:
    try:
        return iso8601_ceil_utc()
    except Exception:
        return datetime.utcnow().replace(microsecond=0).isoformat()

def _sig_strip_data_uri(b64_or_datauri: str | None) -> str:
    """
    Accepts either a bare base64 PNG or a data URI like 'data:image/png;base64,....'
    Returns the base64 payload only ('' on falsy input).
    """
    if not b64_or_datauri:
        return ""
    s = str(b64_or_datauri).strip()
    if s.startswith("data:image/png;base64,"):
        s = s.split(",", 1)[1]
    # Light sanity check
    try:
        # don’t keep it if it’s not valid base64
        base64.b64decode(s, validate=True)
    except Exception:
        return ""
    return s

def set_pilot_ack_for_flight(
    flight_id: int,
    *, name: str,
    method: str,                 # 'typed' | 'drawn'
    signature_b64_or_datauri: str | None = None,
    signed_at_iso: str | None = None
) -> None:
    """
    Attach pilot acknowledgment to a flight:
      - name (required)
      - method: 'typed' or 'drawn'
      - signature_b64_or_datauri: required for 'drawn', optional for 'typed'
      - signed_at_iso: optional (defaults to now, ISO-8601)
    Safe to call repeatedly (overwrites).
    """
    if not flight_id:
        return
    m = (method or "").strip().lower()
    m = "drawn" if m == "drawn" else "typed"
    sig_b64 = _sig_strip_data_uri(signature_b64_or_datauri) if m == "drawn" else ""
    ts = signed_at_iso or _sig_now_iso()
    with sqlite3.connect(get_db_file()) as c:
        c.execute("""
          UPDATE flights
             SET pilot_ack_name         = ?,
                 pilot_ack_method       = ?,
                 pilot_ack_signature_b64= ?,
                 pilot_ack_signed_at    = ?,
                 pilot_ack_boot_id      = COALESCE(pilot_ack_boot_id, ?)
           WHERE id=?
        """, (name.strip(), m, sig_b64, ts, get_boot_id(), int(flight_id)))

def set_pilot_ack_for_queue(
    qid: int,
    *, name: str,
    method: str,
    signature_b64_or_datauri: str | None = None,
    signed_at_iso: str | None = None
) -> None:
    """
    Same as set_pilot_ack_for_flight, but stores on queued_flights.
    Useful if you capture signature before a draft is sent.
    """
    if not qid:
        return
    m = (method or "").strip().lower()
    m = "drawn" if m == "drawn" else "typed"
    sig_b64 = _sig_strip_data_uri(signature_b64_or_datauri) if m == "drawn" else ""
    ts = signed_at_iso or _sig_now_iso()
    with sqlite3.connect(get_db_file()) as c:
        c.execute("""
          UPDATE queued_flights
             SET pilot_ack_name          = ?,
                 pilot_ack_method        = ?,
                 pilot_ack_signature_b64 = ?,
                 pilot_ack_signed_at     = ?,
                 pilot_ack_boot_id       = COALESCE(pilot_ack_boot_id, ?)
           WHERE id=?
        """, (name.strip(), m, sig_b64, ts, get_boot_id(), int(qid)))

def copy_pilot_ack_from_queue(qid: int, flight_id: int) -> None:
    """
    When a queued flight becomes a real flight, copy any existing signature
    fields across. No-ops if either record is missing.
    """
    if not (qid and flight_id):
        return
    with sqlite3.connect(get_db_file()) as c:
        row = c.execute("""
          SELECT pilot_ack_name, pilot_ack_method, pilot_ack_signature_b64, pilot_ack_signed_at
            FROM queued_flights WHERE id=? LIMIT 1
        """, (int(qid),)).fetchone()
        if not row:
            return
        c.execute("""
          UPDATE flights
             SET pilot_ack_name         = COALESCE(?, pilot_ack_name),
                 pilot_ack_method       = COALESCE(?, pilot_ack_method),
                 pilot_ack_signature_b64= COALESCE(?, pilot_ack_signature_b64),
                 pilot_ack_signed_at    = COALESCE(?, pilot_ack_signed_at),
                 pilot_ack_boot_id      = COALESCE(pilot_ack_boot_id, ?)
           WHERE id=?
        """, (row[0], row[1], row[2], row[3], get_boot_id(), int(flight_id)))

def get_pilot_ack_for_flight(flight_id: int) -> dict:
    """
    Fetch acknowledgment metadata (and signature base64) for export/audit.
    Returns {} if not present.
    """
    if not flight_id:
        return {}
    rows = dict_rows("""
      SELECT pilot_ack_name AS name,
             pilot_ack_method AS method,
             pilot_ack_signature_b64 AS signature_b64,
             pilot_ack_signed_at AS signed_at,
             pilot_ack_boot_id   AS boot_id
        FROM flights WHERE id=? LIMIT 1
    """, (int(flight_id),))
    return rows[0] if rows else {}

def get_boot_id() -> str:
    """
    Return the current process BOOT_ID (fresh each container/process start),
    or '' if unavailable. Used to stamp pilot-ack provenance.
    """
    try:
        return (current_app.config.get("BOOT_ID") or "").strip()
    except Exception:
        try:
            from app import app as _app  # best-effort fallback during early import
            return (_app.config.get("BOOT_ID") or "").strip()
        except Exception:
            return ""

def _parse_manifest(manifest: str):
    """
    Return list of dicts: [{'name':str,'size_lb':float,'qty':int}, ...]
    Accepts 'tarps 10 lbx3; water 20 lbx2' and minor variants (x, lbs, spaces).
    """
    items = []
    for part in (manifest or '').split(';'):
        t = part.strip()
        if not t: continue
        # If this chunk starts with a human label like "Manifest: ...",
        # drop everything up to and including that label (only if it
        # occurs before the first digit, which begins the size).
        m = re.search(r'(?i)\bmanifest\b\s*[:\-–—]\s*', t)
        if m:
            first_digit = re.search(r'\d', t)
            if not first_digit or m.start() <= first_digit.start():
                t = t[m.end():].strip()

        # greedy name, then number + 'lb'/'lbs', then 'x' or '×' qty
        m = re.search(r'^(?P<name>.+?)\s+(?P<size>\d+(?:\.\d+)?)\s*lb[s]?\s*[×x]\s*(?P<qty>\d+)\s*$', t, re.I)
        if not m:
            # fallback: just a weight → treat as one line with qty=1 and name=t
            m2 = re.search(r'^(?P<name>.+?)\s+(?P<size>\d+(?:\.\d+)?)\s*lb[s]?\s*$', t, re.I)
            if m2:
                items.append({'name': m2.group('name').strip(), 'size_lb': float(m2.group('size')), 'qty': 1})
            continue
        items.append({
            'name': m.group('name').strip(),
            'size_lb': float(m.group('size')),
            'qty': int(m.group('qty'))
        })
    return items

# ─────────────────────────────────────────────────────────────────────────────
# Cargo Requests — Core Helpers (aggregated per airport)
# ─────────────────────────────────────────────────────────────────────────────
def ensure_cargo_request_tables() -> None:
    """Public idempotent creator for Cargo Requests tables."""
    with sqlite3.connect(get_db_file()) as c:
        _create_tables_cargo_requests(c)

def _now_iso_z() -> str:
    try:
        return iso8601_ceil_utc()
    except Exception:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")

def cr_sanitize_item(name: str) -> str:
    """Normalize an item name for request aggregation (uses sanitize_name)."""
    return (sanitize_name(name) or "").strip().lower()

def cr_upsert_requests(airport: str, items: list[dict], *, source_email_id: str | None = None) -> int:
    """
    Merge a batch of requests into cargo_requests for an airport.
    `items` = [{'name': 'spaghetti', 'weight_lb': 120.0}, ...]
    Returns number of rows inserted or updated.
    """
    ensure_cargo_request_tables()
    ap = canonical_airport_code(airport or "")
    if not ap or not items:
        return 0
    # fold duplicates by sanitized name
    agg: dict[str, float] = {}
    for it in items:
        nm = cr_sanitize_item(it.get("name", ""))
        if not nm:
            continue
        try:
            w = float(it.get("weight_lb") or 0.0)
        except Exception:
            w = 0.0
        if w <= 0:
            continue
        agg[nm] = round(agg.get(nm, 0.0) + w, 1)
    if not agg:
        return 0

    ts = _now_iso_z()
    n = 0
    with sqlite3.connect(get_db_file()) as c:
        for nm, w in agg.items():
            cur = c.execute("""
              INSERT INTO cargo_requests(airport_canon, sanitized_name, requested_lb, fulfilled_lb, created_at, updated_at, last_source_id)
              VALUES (?,?,?,?,?,?,?)
              ON CONFLICT(airport_canon, sanitized_name) DO UPDATE SET
                requested_lb = cargo_requests.requested_lb + excluded.requested_lb,
                updated_at   = excluded.updated_at,
                last_source_id = COALESCE(excluded.last_source_id, cargo_requests.last_source_id)
            """, (ap, nm, w, 0.0, ts, ts, source_email_id)).rowcount
            n += 1 if (cur or 0) >= 0 else 0
        # Auto-prune lines that are already fully satisfied (edge case)
        c.execute("""
          DELETE FROM cargo_requests
           WHERE airport_canon=? AND fulfilled_lb >= requested_lb
        """, (ap,))
    return n

def cr_get_overview() -> list[dict]:
    """
    Overview for the RampBoss FAB badge and drawer list.
    Returns: [{'airport': 'ABC', 'open_items': 7, 'remaining_lb': 1234.5}, ...]
    """
    ensure_cargo_request_tables()
    rows = dict_rows("""
      SELECT airport_canon AS airport,
             COUNT(*) AS open_items,
             ROUND(SUM(MAX(requested_lb - fulfilled_lb, 0.0)), 1) AS remaining_lb
        FROM cargo_requests
       WHERE requested_lb > fulfilled_lb
       GROUP BY airport_canon
       ORDER BY remaining_lb DESC, airport
    """)
    # SQLite MAX() over scalar literal needs CASE; re-compute in Python for safety
    out = []
    for r in rows:
        rem = float(r.get("remaining_lb") or 0.0)
        if rem <= 0:
            # Defensive: filter any non-open aggregates
            continue
        out.append({
            "airport": r.get("airport") or "",
            "open_items": int(r.get("open_items") or 0),
            "remaining_lb": round(rem, 1),
        })
    return out

def cr_get_airport_items(airport: str) -> list[dict]:
    """
    Detailed list for a single airport:
    [{'name': 'spaghetti', 'requested_lb': 200.0, 'fulfilled_lb': 150.0, 'remaining_lb': 50.0}, ...]
    """
    ensure_cargo_request_tables()
    ap = canonical_airport_code(airport or "")
    if not ap:
        return []
    rows = dict_rows("""
      SELECT sanitized_name, requested_lb, fulfilled_lb
        FROM cargo_requests
       WHERE airport_canon=?
       ORDER BY sanitized_name
    """, (ap,))
    out = []
    for r in rows:
        req = float(r.get("requested_lb") or 0.0)
        ful = float(r.get("fulfilled_lb") or 0.0)
        out.append({
            "name": r.get("sanitized_name") or "",
            "requested_lb": round(req, 1),
            "fulfilled_lb": round(ful, 1),
            "remaining_lb": round(max(req - ful, 0.0), 1)
        })
    return out

def cr_delete_item(airport: str, name: str) -> None:
    """Manual delete of a single line item for an airport (spec: with confirmation in UI)."""
    ensure_cargo_request_tables()
    ap = canonical_airport_code(airport or "")
    nm = cr_sanitize_item(name or "")
    if not ap or not nm:
        return
    with sqlite3.connect(get_db_file()) as c:
        c.execute("DELETE FROM cargo_requests WHERE airport_canon=? AND sanitized_name=?", (ap, nm))

def cr_delete_airport(airport: str) -> None:
    """Manual delete of all requests for an airport (spec: with confirmation in UI)."""
    ensure_cargo_request_tables()
    ap = canonical_airport_code(airport or "")
    if not ap:
        return
    with sqlite3.connect(get_db_file()) as c:
        c.execute("DELETE FROM cargo_requests WHERE airport_canon=?", (ap,))

def _cr_apply_weights(ap: str, weights_by_name: dict[str, float]) -> dict:
    """
    Core: apply delivered weights to open requests at airport `ap`.
    Returns summary: {'credited_lb': float, 'closed_items': int, 'remaining_items': int}
    """
    if not weights_by_name:
        return {"credited_lb": 0.0, "closed_items": 0, "remaining_items": 0}
    credited = 0.0
    closed = 0
    with sqlite3.connect(get_db_file()) as c:
        for nm, delivered in weights_by_name.items():
            if delivered <= 0:
                continue
            # Fetch current line
            row = c.execute("""
              SELECT requested_lb, fulfilled_lb
                FROM cargo_requests
               WHERE airport_canon=? AND sanitized_name=?
               LIMIT 1
            """, (ap, nm)).fetchone()
            if not row:
                continue  # no open request for this item
            req, ful = float(row[0] or 0.0), float(row[1] or 0.0)
            remain = max(req - ful, 0.0)
            if remain <= 0:
                # already satisfied; clean just in case
                c.execute("DELETE FROM cargo_requests WHERE airport_canon=? AND sanitized_name=?", (ap, nm))
                closed += 1
                continue
            add = min(delivered, remain)
            credited += add
            new_ful = round(ful + add, 1)
            ts = _now_iso_z()
            c.execute("""
              UPDATE cargo_requests
                 SET fulfilled_lb = ?,
                     updated_at   = ?
               WHERE airport_canon=? AND sanitized_name=?
            """, (new_ful, ts, ap, nm))
            # Fully satisfied? delete the row
            if new_ful >= req:
                c.execute("DELETE FROM cargo_requests WHERE airport_canon=? AND sanitized_name=?", (ap, nm))
                closed += 1
        # After line deletes, count remaining
        rem = c.execute("SELECT COUNT(*) FROM cargo_requests WHERE airport_canon=?", (ap,)).fetchone()[0]
    return {"credited_lb": round(credited, 1), "closed_items": int(closed), "remaining_items": int(rem)}

def cr_apply_manifest_to_requests(airport: str, *, manifest_text: str | None = None, manifest_rows: list[dict] | None = None) -> dict:
    """
    Apply a landed flight's cargo against open requests for an airport.
    - If `manifest_rows` provided, expect [{'name':str,'size_lb':float,'qty':int}, ...]
    - Else, if `manifest_text` provided, parse via _parse_manifest(...).
    Returns summary dict from _cr_apply_weights(...).
    """
    ensure_cargo_request_tables()
    ap = canonical_airport_code(airport or "")
    if not ap:
        return {"credited_lb": 0.0, "closed_items": 0, "remaining_items": 0}
    rows = manifest_rows or []
    if not rows and manifest_text:
        try:
            rows = _parse_manifest(manifest_text) or []
        except Exception:
            rows = []
    weights: dict[str, float] = {}
    for r in rows:
        nm = cr_sanitize_item(r.get("name", ""))
        if not nm:
            continue
        try:
            size = float(r.get("size_lb") or 0.0)
            qty = int(r.get("qty") or 0)
            w = round(size * qty, 1)
        except Exception:
            w = 0.0
        if w <= 0:
            continue
        weights[nm] = round(weights.get(nm, 0.0) + w, 1)
    return _cr_apply_weights(ap, weights)

def cr_apply_flight_id(flight_id: int) -> dict:
    """
    Convenience: look up a flight's destination + manifest and credit requests.
    Prefers `flight_cargo` rows (direction='out') when present; falls back to
    parsing `flights.remarks` via _parse_manifest. No-ops if destination missing.
    """
    ensure_cargo_request_tables()
    if not flight_id:
        return {"credited_lb": 0.0, "closed_items": 0, "remaining_items": 0}
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        f = c.execute("""
          SELECT airfield_landing AS dest, remarks
            FROM flights WHERE id=? LIMIT 1
        """, (flight_id,)).fetchone()
        if not f:
            return {"credited_lb": 0.0, "closed_items": 0, "remaining_items": 0}
        dest = (f["dest"] or "").strip().upper()
        if not dest:
            return {"credited_lb": 0.0, "closed_items": 0, "remaining_items": 0}
        # Prefer explicit flight_cargo rows if any exist
        cargo = c.execute("""
          SELECT sanitized_name AS name, weight_per_unit AS size_lb, quantity AS qty
            FROM flight_cargo
           WHERE flight_id=? AND direction='out'
        """, (flight_id,)).fetchall()
        rows = [dict(r) for r in cargo] if cargo else None
        text = None if rows else (f["remarks"] or "")
    return cr_apply_manifest_to_requests(dest, manifest_text=text, manifest_rows=rows or [])

def _create_inventory_batch(direction: str, manifest: str, created_at: str | None = None):
    """Insert a batch + items; return batch_id."""
    created_at = created_at or datetime.utcnow().isoformat()
    # Normalize for storage/UI: exactly one trailing ';'
    manifest = ensure_trailing_semicolon(manifest)
    items = _parse_manifest(manifest)
    if not items:
        return None
    with sqlite3.connect(get_db_file()) as c:
        cur = c.execute("""
          INSERT INTO wargame_inventory_batches(direction, created_at, manifest)
          VALUES(?,?,?)
        """, (direction, created_at, manifest))
        bid = cur.lastrowid
        for it in items:
            c.execute("""
              INSERT INTO wargame_inventory_batch_items
                (batch_id, name, size_lb, qty_required, qty_done)
              VALUES (?,?,?,?,0)
            """, (bid, it['name'], it['size_lb'], it['qty']))
    return bid

def _mark_batch_done_if_complete(c, batch_id: int):
    """
    If every line in a batch has qty_done >= qty_required, stamp satisfied_at.
    """
    row = c.execute("""
        SELECT 1
          FROM wargame_inventory_batch_items
         WHERE batch_id=? AND qty_done < qty_required
         LIMIT 1
    """, (batch_id,)).fetchone()
    if not row:
        c.execute(
            "UPDATE wargame_inventory_batches SET satisfied_at=? WHERE id=?",
            (datetime.utcnow().isoformat(), batch_id)
        )

def apply_inventory_entry_to_batches(direction: str, sanitized_name: str, size_lb: float, qty: int):
    """
    Reconcile a *committed* inventory entry against open batch items.
    Decrements qty_required→qty_done oldest-first and emits a UI event.
    """
    try:
        qty = int(qty)
        if qty <= 0:
            return
    except Exception:
        return

    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        items = c.execute("""
          SELECT bi.id AS item_id, bi.batch_id, bi.qty_required, bi.qty_done
            FROM wargame_inventory_batch_items bi
            JOIN wargame_inventory_batches b ON b.id = bi.batch_id
           WHERE b.direction = ?
             AND b.satisfied_at IS NULL
             AND LOWER(bi.name) = LOWER(?)
             AND CAST(bi.size_lb AS REAL) = CAST(? AS REAL)
             AND bi.qty_done < bi.qty_required
           ORDER BY b.created_at ASC, bi.id ASC
        """, (direction, sanitized_name, float(size_lb))).fetchall()

        remaining = qty
        for it in items:
            if remaining <= 0:
                break
            needed = int(it['qty_required']) - int(it['qty_done'])
            take   = min(needed, remaining)
            if take <= 0:
                continue
            c.execute(
                "UPDATE wargame_inventory_batch_items SET qty_done = qty_done + ? WHERE id=?",
                (take, it['item_id'])
            )
            remaining -= take
            _mark_batch_done_if_complete(c, it['batch_id'])
            try:
                emit_inventory_event({"kind": direction, "batch_id": int(it['batch_id']), "item_id": int(it['item_id'])})
            except Exception:
                pass

def insert_inventory_entry_and_reconcile(
    *, category_id: int, sanitized_name: str, size_lb: float, qty: int,
    direction: str, raw_name: str = "", total_weight: float | None = None,
    session_id: str = "", source: str = "inventory", timestamp_iso: str | None = None,
):
    """
    Convenience wrapper used by routes: insert the entry and immediately
    apply it to any open batches so cue cards tick down live.
    """
    ts = timestamp_iso or datetime.utcnow().isoformat()
    tw = float(total_weight) if total_weight is not None else float(size_lb) * int(qty)
    with sqlite3.connect(get_db_file()) as c:
        c.execute("""
          INSERT INTO inventory_entries(
            category_id, raw_name, sanitized_name,
            weight_per_unit, quantity, total_weight,
            direction, timestamp, session_id, pending, source
          ) VALUES (?,?,?,?,?,?, ?,?,?, 0,?)
        """, (int(category_id), raw_name or sanitized_name, sanitized_name,
              float(size_lb), int(qty), tw, direction, ts, session_id or "", source))
    try:
        apply_inventory_entry_to_batches(direction, sanitized_name, float(size_lb), int(qty))
    except Exception:
        pass

def parse_adv_manifest(remarks: str) -> list[dict]:
    """
    Lightweight public wrapper around _parse_manifest so routes don’t import
    a private helper. Returns list of dicts:
      [{'name': str, 'size_lb': float, 'qty': int}, ...]
    """
    return _parse_manifest(remarks or "")

def guess_category_id_for_name(sanitized: str) -> int | None:
    """
    Pick the most-frequently-used category for a given sanitized_name,
    or None if we’ve never seen it.
    """
    rows = dict_rows("""
      SELECT category_id, COUNT(*) AS n
        FROM inventory_entries
       WHERE sanitized_name = ?
       GROUP BY category_id
       ORDER BY n DESC
       LIMIT 1
    """, (sanitized.strip().lower(),))
    return int(rows[0]['category_id']) if rows else None

def new_manifest_session_id() -> str:
    """Generate a fresh session id for Advanced Manifest edits."""
    return uuid.uuid4().hex

def generate_inventory_outbound_request():
    """Generate a multi-line outbound request batch (to be fulfilled by Inventory)."""
    ts = datetime.utcnow().isoformat()
    settings_row = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
    settings  = json.loads(settings_row[0]['value'] or '{}') if settings_row else {}
    # Cargo-flow gating: only run outbound inventory in these modes
    flow = settings.get('cargo_flow', 'hybrid')
    if flow not in ('ground_ground', 'air_ground'):
        return

    max_inv   = int(settings.get('max_inventory', 3) or 3)
    # only count UNSATISFIED outbound batches as 'pending'
    pending = dict_rows("""
      SELECT COUNT(*) AS c FROM wargame_inventory_batches
       WHERE direction='out' AND satisfied_at IS NULL
    """)[0]['c'] or 0
    if pending >= max_inv:
        return
    # Build availability from committed entries only.
    avail = dict_rows("""
      SELECT c.id    AS cid,
             e.sanitized_name AS noun,
             e.weight_per_unit AS size_lb,
             SUM(CASE WHEN e.direction='in'  THEN e.quantity
                      WHEN e.direction='out' THEN -e.quantity END) AS qty
        FROM inventory_entries e
        JOIN inventory_categories c ON c.id=e.category_id
       WHERE e.pending=0
       GROUP BY c.id, e.sanitized_name, e.weight_per_unit
       HAVING qty > 0
    """)
    if not avail:
        return  # nothing on shelves → don't ask for outbound
    # Choose 2..6 distinct (noun,size) with available qty > 0

    picks = _r.sample(avail, k=min(len(avail), _r.randint(2,6)))
    lines = []
    for r in picks:
        have = int(r['qty'] or 0)
        if have <= 0: 
            continue
        ask = _r.randint(1, have)  # do not exceed stock
        lines.append(f"{r['noun']} {int(r['size_lb'])} lbx{ask}")
    if not lines:
        return
    # _create_inventory_batch normalizes trailing ';'
    bid = _create_inventory_batch('out', '; '.join(lines), ts)
    # Notify any open Inventory dashboards
    try:
        emit_inventory_event({"kind":"out","batch_id": bid})
    except Exception:
        pass

def generate_inventory_inbound_delivery():
    """Generate a multi-line inbound delivery batch (stuff 'arrived' that must be logged)."""
    _hydrate_from_app()
    if not WARGAME_ITEMS:
        logger.warning("Wargame: no items catalog; skipping inbound delivery.")
        return
    ts = datetime.utcnow().isoformat()
    settings_row = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
    settings  = json.loads(settings_row[0]['value'] or '{}') if settings_row else {}
    # Cargo-flow gating: only run inbound inventory deliveries in these modes
    flow = settings.get('cargo_flow', 'hybrid')
    if flow not in ('ground_ground', 'ground_air', 'hybrid'):
        return

    max_inv   = int(settings.get('max_inventory', 3) or 3)
    pending = dict_rows("""
      SELECT COUNT(*) AS c FROM wargame_inventory_batches
       WHERE direction='in' AND satisfied_at IS NULL
    """)[0]['c'] or 0
    if pending >= max_inv:
        return
    pairs = [(n, s) for n, szs in WARGAME_ITEMS.items() for s in szs]
    if not pairs:
        return
    k = min(random.randint(2, 6), len(pairs))
    if k <= 0:
        return
    combos = random.sample(pairs, k=k)
    lines = []
    for name, size in combos:
        qty = random.randint(1,5)
        lines.append(f"{name} {size} lbx{qty}")
    manifest = '; '.join(lines)
    # _create_inventory_batch normalizes trailing ';'
    bid = _create_inventory_batch('in', manifest, ts)
    # Notify any open Inventory dashboards
    try:
        emit_inventory_event({"kind":"in","batch_id": bid})
    except Exception:
        pass

def generate_ramp_flight():
    """Generate a ramp flight with detailed cargo line items (no metrics here).
       If outbound, start the Radio‑outbound timer so SLA runs until operator marks 'sent'."""
    ts         = datetime.utcnow().isoformat()          # ISO for metrics
    direction  = choose_ramp_direction_with_balance()
    tail       = generate_tail_number()
    dep, arr   = random.sample(HARDCODED_AIRFIELDS, 2)
    tko_hhmm   = datetime.utcnow().strftime('%H%M')     # HHMM for dashboard fields
    eta_hhmm   = (datetime.utcnow() + timedelta(minutes=random.randint(15,90))).strftime('%H%M')

    combos = random.sample([(n,s) for n,szs in WARGAME_ITEMS.items() for s in szs],
                           k=random.randint(1,9))
    lines, total_wt = [], 0
    for name, size in combos:
        qty = random.randint(1,9)
        lines.append(f"{name} {size} lbx{qty}")
        total_wt += size * qty
    remarks = ensure_trailing_semicolon('; '.join(lines)) if lines else ''

    # Build flight code (freeze *now* date + planned HHMM)
    try:
        frozen_mmddyy = datetime.utcnow().strftime('%m%d%y')
        # Prefer 3-char mapping; fall back to first 3
        ooo = to_three_char_code(dep) or (dep or '')[:3].upper()
        ddd = to_three_char_code(arr) or (arr or '')[:3].upper()
        fcode = find_unique_code_or_bump(ooo, frozen_mmddyy, ddd, tko_hhmm)
    except Exception:
        fcode = None

    with sqlite3.connect(get_db_file()) as c:
        cur = c.execute("""
          INSERT INTO flights
            (tail_number, airfield_takeoff, airfield_landing,
             takeoff_time, eta, cargo_type, cargo_weight, cargo_weight_real,
             is_ramp_entry, direction, complete, remarks, flight_code)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 0, ?, ?)
        """, (tail, dep, arr, tko_hhmm, eta_hhmm, 'Mixed', total_wt, float(total_wt), direction, remarks, fcode))

        fid = cur.lastrowid

    # If this is an outbound request, start the Radio‑outbound timer now.
    if direction == 'outbound' and get_preference('wargame_mode') == 'yes':
        wargame_start_radio_outbound(fid)
        # Also start Ramp outbound SLA (runs until ramp marks complete)
        try:
            wargame_task_start('ramp', 'outbound', key=f"flight:{fid}", gen_at=ts)
        except Exception: pass

def too_large(e):
    return (
        render_template(
            '413.html',
            max_mb=app.config['MAX_CONTENT_LENGTH'] // (1024*1024)
        ),
        413
    )

# LRU-cached front door used by routes/templates. Normalize args for cache hits.
@lru_cache(maxsize=4096)
def fmt_airport(code: str, pref: str) -> str:
    """
    Cached airport formatter:
      - Normalizes inputs for maximal cache locality.
      - Delegates to format_airport(...) for the actual DB-backed lookup.
    """
    c = (code or '').strip().upper()
    p = str(pref or '').strip().lower()
    return format_airport(c, p)


# Back-compat for modules that still call _fmt_airport(...)
_fmt_airport = fmt_airport

def clear_airport_cache() -> None:
    """
    Clear all airport-related LRU caches (use after CSV reloads or admin edits).
    """
    for fn in (fmt_airport, canonical_airport_code, to_three_char_code, airport_aliases):
        try:
            fn.cache_clear()            # only those wrapped by lru_cache have it
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# Scanner helpers for RampBoss (pending inventory as live scan layer)
#   • Keep ONE pending row per (session_id, category_id, sanitized_name, wpu, direction)
#   • “Add” in Build/Edit → direction='out' (scan out)
#   • “Remove” in Edit     → direction='in'  (put back on shelf)
#   • “Remove” in Build    → decrement the 'out' row; delete at qty=0
#   • Always bump pending_ts so the reaper won’t purge active work
# ─────────────────────────────────────────────────────────────────────────────
def lookup_barcode(barcode: str) -> dict | None:
    """Return {category_id, sanitized_name, weight_per_unit} for a known barcode."""
    bc = (barcode or '').strip()
    if not bc:
        return None
    rows = dict_rows("""
      SELECT category_id, sanitized_name, weight_per_unit
        FROM inventory_barcodes
       WHERE barcode = ?
       LIMIT 1
    """, (bc,))
    if not rows:
        return None
    r = rows[0]
    return {
        'category_id': int(r['category_id']),
        'sanitized_name': r['sanitized_name'],
        'weight_per_unit': float(r['weight_per_unit']),
    }

def _pending_row_get(c, session_id: str, cat_id: int, name: str, wpu: float, direction: str):
    return c.execute("""
      SELECT id, quantity
        FROM inventory_entries
       WHERE pending=1 AND session_id=?
         AND category_id=? AND LOWER(sanitized_name)=LOWER(?)
         AND CAST(weight_per_unit AS REAL)=CAST(? AS REAL)
         AND direction=?
       LIMIT 1
    """, (session_id, int(cat_id), name, float(wpu), direction)).fetchone()

def upsert_scan_pending(*, session_id: str, category_id: int, sanitized_name: str,
                        weight_per_unit: float, direction: str, delta_qty: int) -> int:
    """
    Apply a ±delta_qty to the single pending row for this item+direction.
    Returns the resulting pending quantity for that row (0 ⇒ deleted).
    """
    from datetime import datetime
    ts = datetime.utcnow().isoformat()
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        c.execute("BEGIN IMMEDIATE")
        row = _pending_row_get(c, session_id, category_id, sanitized_name, weight_per_unit, direction)
        if row:
            new_q = max(0, int(row['quantity']) + int(delta_qty))
            if new_q <= 0:
                c.execute("DELETE FROM inventory_entries WHERE id=?", (row['id'],))
                c.commit()
                return 0
            c.execute("""
              UPDATE inventory_entries
                 SET quantity=?, total_weight=?*?,
                     pending_ts=?, timestamp=?, source='scanner'
               WHERE id=?
            """, (new_q, float(weight_per_unit), new_q, ts, ts, row['id']))
            c.commit()
            return new_q
        # create new when delta > 0
        if int(delta_qty) > 0:
            c.execute("""
              INSERT INTO inventory_entries(
                category_id, raw_name, sanitized_name,
                weight_per_unit, quantity, total_weight,
                direction, timestamp, pending, pending_ts, session_id, source
              ) VALUES (?,?,?,?,?,?, ?, ?,1, ?, ?, 'scanner')
            """, (
              int(category_id), sanitized_name, sanitized_name,
              float(weight_per_unit), int(delta_qty), float(weight_per_unit)*int(delta_qty),
              direction, ts, ts, session_id
            ))
            c.commit()
            return int(delta_qty)
        # delta <= 0 with no row → effectively 0
        c.commit()
        return 0

def aggregate_manifest_net(
    session_id: str,
    flight_id: int | None = None,
    queued_id: int | None = None
) -> list[dict]:
    """
    Return net chips for UI/exports:
      • Start with existing baseline rows:
          - flight_cargo.flight_id (when editing a sent flight), OR
          - flight_cargo.queued_id (when editing a queued draft)
      • Add session inventory_entries (pending 0/1): OUT − IN
    Output rows: [{category_id, sanitized_name, weight_per_unit, qty, total, direction:'out'}...]
    Only positive net qty are returned.
    """
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        base = {}
        if flight_id is not None:
            for r in c.execute("""
                SELECT category_id, sanitized_name, weight_per_unit, quantity
                  FROM flight_cargo
                 WHERE flight_id=?
            """, (int(flight_id),)):
                key = (int(r['category_id']), r['sanitized_name'].lower().strip(), float(r['weight_per_unit']))
                base[key] = base.get(key, 0) + int(r['quantity'])
        elif queued_id is not None:
            for r in c.execute("""
                SELECT category_id, sanitized_name, weight_per_unit, quantity
                  FROM flight_cargo
                 WHERE queued_id=?
            """, (int(queued_id),)):
                key = (int(r['category_id']), r['sanitized_name'].lower().strip(), float(r['weight_per_unit']))
                base[key] = base.get(key, 0) + int(r['quantity'])
        for r in c.execute("""
          SELECT category_id, sanitized_name, weight_per_unit,
                 SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END) AS net_qty
            FROM inventory_entries
           WHERE session_id=? AND pending IN (0,1)
           GROUP BY category_id, sanitized_name, weight_per_unit
        """, (session_id,)):
            key = (int(r['category_id']), r['sanitized_name'].lower().strip(), float(r['weight_per_unit']))
            base[key] = base.get(key, 0) + int(r['net_qty'] or 0)

        out = []
        for (cid, name, wpu), qty in base.items():
            if qty and qty > 0:
                out.append({
                    'category_id': cid,
                    'sanitized_name': name,
                    'weight_per_unit': wpu,
                    'qty': int(qty),
                    'total': float(wpu) * int(qty),
                    'direction': 'out'
                })
        return sorted(out, key=lambda d: (d['sanitized_name'], d['weight_per_unit']))

def flip_session_pending_to_committed(session_id: str):
    """After a send/commit, turn session pendings into committed rows (pending=0)."""
    with sqlite3.connect(get_db_file()) as c:
        c.execute("""
          UPDATE inventory_entries
             SET pending=0
           WHERE session_id=? AND pending=1
        """, (session_id,))

def lookup_callsign_for_airport(code: str) -> str:
    """
    Return mapped Winlink callsign for an airport code (ICAO/IATA/FAA).
    Uses the 'airport_call_mappings' preference and canonical_airport_code().
    """
    try:
        raw = (get_preference('airport_call_mappings') or '').strip()
    except Exception:
        raw = ''
    canon = canonical_airport_code((code or '').strip())
    if not canon:
        return ''
    for line in raw.splitlines():
        if ':' not in line:
            continue
        ap, wl = (x.strip().upper() for x in line.split(':', 1))
        if canonical_airport_code(ap) == canon and wl:
            return wl
    return ''
