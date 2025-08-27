# ---- compat shims for app-level globals (avoid circular imports) ----
import sys as _sys, logging as _logging, re as _re, random as _random
from functools import lru_cache

# Safe fallbacks so static analysis and runtime don’t crash if app globals aren’t ready yet.
SQL_TRACE = False
SQL_TRACE_EXPANDED = False
_sql_logger = _logging.getLogger("sql")
TraceConn = None

_zeroconf = None
MDNS_NAME = ""
HOST_IP = ""
MDNS_REASON = ""

HARDCODED_AIRFIELDS = []
WARGAME_ITEMS = {}

# one-time init flags for background workers
_wg_scheduler_inited = False
_distance_thread_started = False
_radio_started = False

DASHY_RE = _re.compile(r'^[\s\-_‒–—―]+$')
logger = _logging.getLogger(__name__)
ENGLISH_ADJECTIVES = set()

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
from flask_wtf.csrf import generate_csrf
from markupsafe import escape
import sqlite3, csv, re, os, json
from datetime import datetime, timedelta, timezone
import threading, time, socket, math
from urllib.request import urlopen
from zeroconf import ServiceInfo, NonUniqueNameException
import fcntl
import struct
from radio_tx import start_radio_tx

from flask import current_app
from flask import flash, jsonify, make_response, redirect, render_template, request, session, url_for
app = current_app  # legacy shim for helpers

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
    packed = struct.pack('256s', iface.encode()[:15])
    addr = fcntl.ioctl(s.fileno(), 0x8915, packed)[20:24]  # SIOCGIFADDR
    return socket.inet_ntoa(addr)

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
    
    # flight_cargo gained a NOT-NULL session_id
    ensure_column("flight_cargo", "session_id", "TEXT NOT NULL DEFAULT ''")
    # queued_flights gained dest + travel_time (if DB predates them)
    ensure_column("queued_flights", "airfield_landing", "TEXT")
    ensure_column("queued_flights", "travel_time",      "TEXT")
    ensure_column("queued_flights", "cargo_weight",     "REAL DEFAULT 0")
    ensure_column("winlink_messages", "sender",         "TEXT")

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

    # Keep cache tidy after structural changes
    try:
        clear_airport_cache()
    except Exception:
        pass

def cleanup_pending():
    """Purge any pending inventory‐entries older than 15 minutes."""
    cutoff = (datetime.utcnow() - timedelta(minutes=15)).isoformat()
    with sqlite3.connect(get_db_file()) as c:
        c.execute("DELETE FROM inventory_entries WHERE pending=1 AND pending_ts<=?",
                  (cutoff,))

def _cleanup_before_view():
    # fire only on inventory blueprint routes
    if request.blueprint == 'inventory':
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

def load_airports_from_csv():
    """One-time load/refresh of airports.csv into airports table."""
    csv_path = os.path.join(os.path.dirname(__file__), 'airports.csv')
    if not os.path.exists(csv_path):
        return
    with sqlite3.connect(get_db_file()) as c, open(csv_path, newline='', encoding='utf-8') as f:
        rdr = csv.DictReader(f)
        for r in rdr:
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
            """, (
                r['ident'], r['name'],
                r['icao_code'] or None,
                r['iata_code'] or None,
                r['gps_code']  or None,
                r['local_code'] or None
            ))

    # Any refresh invalidates cached lookups.
    try:
        clear_airport_cache()
    except Exception:
        pass

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

def get_preference(name: str) -> str | None:
    """Fetch a single preference value (or None if not set)."""
    rows = dict_rows("SELECT value FROM preferences WHERE name=?", (name,))
    return rows[0]['value'] if rows else None

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
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        return [dict(r) for r in c.execute(sql, params)]

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
    w=w.strip()
    if 'kg' in w.lower():
        num=float(re.findall(r"[\d.]+",w)[0])
        return f"{kg_to_lbs(num)} lbs"
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
    for chunk in (subject or "", body or ""):
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
              float(size_lb), int(qty), tw, direction, ts, session_id or "", "inventory"))
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
