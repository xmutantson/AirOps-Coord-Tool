# app.py — Aircraft Ops Coordination Tool
# =======================================
#  • Ramp-Boss: mandatory Inbound / Outbound, kg→lbs, ICAO storage
#  • Dashboard honours per-browser 3- vs 4-letter preference via cookie
#  • flight_history JSON-safe; CSV export; DB auto-migrate
#  • LAN-only Flask server on :5150

import flask
from markupsafe import Markup as _Markup

# restore flask.Markup so Flask-WTF’s recaptcha.widgets can import it
flask.Markup = _Markup

# restore werkzeug.urls.url_encode for Flask-WTF recaptcha.widgets
import werkzeug.urls
werkzeug.urls.url_encode = werkzeug.urls.urlencode

import random, string
import atexit

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flask import (
    Flask, render_template, request, redirect,
    url_for, send_file, flash, make_response,
    jsonify, Response, stream_with_context,
    session, Blueprint, abort
)

inventory_bp = Blueprint('inventory', __name__, url_prefix='/inventory')

from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter.errors import RateLimitExceeded
import uuid

from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf, CSRFError
from markupsafe import escape

import sqlite3, csv, io, re, os, json
from datetime import datetime, timedelta
import threading, time, socket, math
from urllib.request import urlopen
import queue
import requests

from functools import lru_cache

from zeroconf import Zeroconf, ServiceInfo, NonUniqueNameException
import fcntl
import struct

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import STATE_RUNNING

import logging, sys

# convenience logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Cookie lifetime convenience (shared across routes)
ONE_YEAR = 31_536_000  # seconds

SQL_TRACE           = os.getenv("SQL_TRACE", "0") == "1"          # enable tracer
SQL_TRACE_ALL       = os.getenv("SQL_TRACE_ALL", "0") == "1"      # log every stmt
SQL_TRACE_EXPANDED  = os.getenv("SQL_TRACE_EXPANDED", "0") == "1" # include expanded SQL
SLOW_MS             = float(os.getenv("SQL_SLOW_MS", "50"))       # threshold (ms)
LOG_LEVEL           = os.getenv("LOG_LEVEL", "INFO").upper()
_SKIP_RE_S          = os.getenv("SQL_TRACE_SKIP_RE", "")
_SKIP_RE            = re.compile(_SKIP_RE_S) if _SKIP_RE_S else None

## ── Patch sqlite3.connect (guarded) + optional SQL tracing ─────────────────
# Capture the real connect exactly once on the module object to avoid recursion.
if not hasattr(sqlite3, "_original_connect"):
    sqlite3._original_connect = sqlite3.connect

_sql_logger = logging.getLogger("sql")
_sql_logger.setLevel(logging.DEBUG if SQL_TRACE else logging.WARNING)
_sql_logger.propagate = True
_sql_logger.debug("SQL tracing %s (SLOW_MS=%s)", "ENABLED" if SQL_TRACE else "disabled", SLOW_MS)

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
        stream=sys.stdout,
    )
# Dedicated handler for 'sql' so DEBUG always prints when SQL_TRACE=1
if not _sql_logger.handlers:
    _sql_logger.setLevel(logging.DEBUG if SQL_TRACE else getattr(logging, LOG_LEVEL, logging.INFO))
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s:%(name)s: %(message)s"))
    _h.setLevel(logging.DEBUG if SQL_TRACE else getattr(logging, LOG_LEVEL, logging.INFO))
    _sql_logger.addHandler(_h)
    _sql_logger.propagate = False

class TraceCursor(sqlite3.Cursor):
    def execute(self, sql, params=()):
        t0 = time.perf_counter()
        try:
            return super().execute(sql, params)
        finally:
            if SQL_TRACE:
                dt = (time.perf_counter() - t0) * 1000.0
                should_log = SQL_TRACE_ALL or (dt >= SLOW_MS)
                if should_log and not (_SKIP_RE and _SKIP_RE.search(sql)):
                    _sql_logger.debug("SQL %6.1f ms | %s | %s", dt, sql.strip(), params)
                if dt >= SLOW_MS:
                    try:
                        plan = super().execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
                        _sql_logger.debug("PLAN        | %s", plan)
                    except Exception:
                        pass

class TraceConn(sqlite3.Connection):
    def cursor(self, *args, **kwargs):
        kwargs.setdefault("factory", TraceCursor)
        return super().cursor(*args, **kwargs)
    def execute(self, sql, params=()):
        t0 = time.perf_counter()
        try:
            return super().execute(sql, params)
        finally:
            if SQL_TRACE:
                dt = (time.perf_counter() - t0) * 1000.0
                should_log = SQL_TRACE_ALL or (dt >= SLOW_MS)
                if should_log and not (_SKIP_RE and _SKIP_RE.search(sql)):
                    _sql_logger.debug("SQL %6.1f ms | %s | %s", dt, sql.strip(), params)
                if dt >= SLOW_MS:
                    try:
                        plan = super().execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
                        _sql_logger.debug("PLAN        | %s", plan)
                    except Exception:
                        pass

def connect(db, timeout=30, **kwargs):
    # Only add the tracing connection factory when requested
    if SQL_TRACE:
        kwargs.setdefault("factory", TraceConn)

    # create the connection first
    conn = sqlite3._original_connect(db, timeout=timeout, **kwargs)

    try:
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.execute("PRAGMA journal_mode=WAL;")
        # Expanded SQL is VERY noisy — only when explicitly enabled
        if SQL_TRACE and SQL_TRACE_EXPANDED:
            conn.set_trace_callback(lambda s: _sql_logger.debug("SQL EXPANDED | %s", s))
    except Exception:
        pass

    return conn

# Publish the wrapper on the sqlite3 module (idempotent if re-imported)
sqlite3.connect = connect

#-----------mDNS section--------------
# ─── low-level: ask the kernel for an iface’s IPv4 ─────────────────
def _ip_for_iface(iface: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packed = struct.pack('256s', iface.encode()[:15])
    addr = fcntl.ioctl(s.fileno(), 0x8915, packed)[20:24]  # SIOCGIFADDR
    return socket.inet_ntoa(addr)

# ─── pick your LAN IP ────────────────────────────────────────────
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

# ─── mDNS registration & context injection ──────────────────────

_zeroconf   = Zeroconf()
MDNS_REASON = ""                 # becomes a human‑readable tooltip on failure

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
        return "", get_lan_ip()

    host_ip = get_lan_ip()

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
            return f"{trial}.local", host_ip
        except NonUniqueNameException:
            trial = f"{base}-{i}"           # try a new suffix
        except Exception as exc:
            MDNS_REASON = f"mDNS error: {exc}"
            return "", host_ip

    # exhausted all variants
    MDNS_REASON = "mdns failed: Too many servers!"
    return "", host_ip


# 1) Try Docker secret file (if you mount one)
secret = None
secret_file = '/run/secrets/flask_secret'
if os.path.exists(secret_file):
    with open(secret_file) as f:
        secret = f.read().strip()

# 2) Fallback to env var
if not secret:
    secret = os.environ.get('FLASK_SECRET')

# 3) Final fallback for local dev only
if not secret:
    secret = 'dev-secret-please-change'

app = Flask(__name__)
app.config['DEBUG'] = False
app.config['ENV']   = 'production'
app.secret_key = secret
CSRFProtect(app)
DB_FILE = os.path.join(os.path.dirname(__file__), "data", "aircraft_ops.db")
# Ensure DB directory exists (first-run safety)
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)

# ---- Jinja filter: seconds -> mm:ss (used by Wargame Super template) ----
def _mmss(value):
    try:
        total = int(float(value))
    except Exception:
        return "0:00"
    m, s = divmod(max(total, 0), 60)
    return f"{m}:{s:02d}"
app.jinja_env.filters['mmss'] = _mmss

# Remove hop‑by‑hop headers from all responses (PEP 3333)
@app.after_request
def _strip_hop_by_hop(resp):
    for h in ("Connection","Keep-Alive","Proxy-Authenticate","Proxy-Authorization",
              "TE","Trailer","Transfer-Encoding","Upgrade"):
        if h in resp.headers:
            try:
                del resp.headers[h]
            except Exception:
                pass
    return resp

# Constants: Only these ICAO4 codes will be used in Wargame Mode
HARDCODED_AIRFIELDS = [
    "0W7","0S9","13W","1RL","CYNJ","KALW","KBDN","KBFI",
    "KBLI","KBVS","KCLM","KHQM","KOKH","KSHN","KUAO",
    "S60","W10","WN08"
]

# Wargame cargo catalog (weights in pounds)
WARGAME_ITEMS = {
    'ammo': [100, 200],
    'antennas': [5, 10],
    'bandages': [2, 5, 10],
    'batteries': [10, 25, 50],
    'beans': [10, 25, 50, 60],
    'bleach': [10, 20],
    'boots': [5, 10],
    'camp stoves': [10, 25],
    'canned food': [15, 30],
    'chainsaws': [12, 20],
    'chargers': [5, 10],
    'clothing': [10, 20],
    'diapers': [10, 20],
    'diesel': [40, 55],
    'flour': [5, 20],
    'formula': [5, 10],
    'gauze': [2, 5, 10],
    'gasoline': [40, 55],
    'generators': [45, 80],
    'gloves': [1, 5],
    'heaters': [25, 50],
    'hygiene kits': [5, 10],
    'lumber': [20, 40, 60],
    'masks': [1, 2, 5],
    'medkits': [2, 5],
    'mres': [10, 20],
    'nails': [5, 10, 25],
    'oats': [5, 20],
    'ppe kits': [5, 10],
    'propane': [20, 40],
    'rice': [5, 20, 60],
    'rope': [5, 10, 20],
    'salt': [5, 20],
    'saline': [10, 20],
    'sanitizer': [5, 10],
    'sat phones': [5, 8],
    'soap': [5, 10],
    'solar panels': [20, 40],
    'sugar': [5, 20],
    'tarps': [5, 10, 20],
    'tents': [15, 30],
    'tool kits': [10, 20],
    'vhf radios': [5, 10],
    'water': [10, 20, 50],
    'ham': [20, 40],
}

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

# ── PREFLIGHT: pregenerate mapping AF→callsign ─────────────────
AIRFIELD_CALLSIGNS: dict[str,str] = {}

def initialize_airfield_callsigns():
    """On Wargame start, assign each HARDCODED_AIRFIELD a random callsign."""
    global AIRFIELD_CALLSIGNS
    AIRFIELD_CALLSIGNS = {
        af: generate_random_callsign()
        for af in HARDCODED_AIRFIELDS
    }

# advertise our webapp on mDNS:
MDNS_NAME, HOST_IP = register_mdns("rampops", 5150)

@app.context_processor
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
      'host_ip': HOST_IP,
      'now': datetime.utcnow,
      'current_year': datetime.utcnow().year,
      'hide_tbd': request.cookies.get('hide_tbd','yes')=='yes',
      'show_debug': request.cookies.get('show_debug_logs','no')=='yes',
      'admin_unlocked': session.get('admin_unlocked', False),
      'distance_unit': request.cookies.get('distance_unit','nm'),
      'generate_callsign': generate_random_callsign,
      # Jinja: {{ csrf_token() }} for plain HTML forms
      'csrf_token': generate_csrf,
      # Current Wargame role-epoch (used to invalidate stale role cookies)
      'wargame_role_epoch': lambda: get_wargame_role_epoch()
    }

# ─── Wargame role-epoch helpers ──────────────────────────────────────────────
def get_wargame_role_epoch() -> str:
    """Return the current epoch; create one if missing."""
    row = dict_rows("SELECT value FROM preferences WHERE name='wargame_role_epoch'")
    if row:
        return row[0]['value']
    ep = uuid.uuid4().hex
    set_preference('wargame_role_epoch', ep)
    return ep

def bump_wargame_role_epoch() -> None:
    """Rotate epoch so all existing role cookies become stale."""
    set_preference('wargame_role_epoch', uuid.uuid4().hex)

# ─── Session-Salt Helpers ───────────────────────────────────────────
def get_session_salt():
    rows = dict_rows("SELECT value FROM preferences WHERE name='session_salt'")
    if rows:
        return rows[0]['value']
    # initialize on first run
    salt = uuid.uuid4().hex
    set_session_salt(salt)
    return salt

def set_session_salt(salt: str):
    with sqlite3.connect(DB_FILE) as c:
        c.execute("""
            INSERT INTO preferences(name,value)
            VALUES('session_salt',?)
            ON CONFLICT(name) DO UPDATE
              SET value=excluded.value
        """, (salt,))

### thread-once guard
_distance_thread_started = False

_wg_scheduler_inited = False
@app.before_request
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

@app.before_request
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
    # grab receiver location once
    fetch_recv_loc()
    # spin up the background worker
    t = threading.Thread(target=distances_worker, daemon=True)
    t.start()
    _distance_thread_started = True

# Normalize values that are visually blank (em/en dashes, hyphens, UNDERSCORE lines),
# or common sentinels to actual None/"" so gating logic is correct.
DASHY_RE = re.compile(r'^[\s\-_‒–—―]+$')  # hyphen, en/em/horz bars, underscores
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

# ───────────────── Login Flows ──────────────────

@app.before_request
def require_login():
    # allow static, setup/login/logout without auth
    exempt = ('static','setup','login','logout')
    # guard against endpoint==None (e.g. favicon) and skip any "static" blueprint
    ep = request.endpoint or ''
    # allow unauthenticated access to /dashboard/plain *only* from localhost
    if ep == 'dashboard_plain' and request.remote_addr in ('127.0.0.1', '::1'):
        return
    if ep in exempt or ep.startswith('static'):
        return
    # if no password set yet → force setup
    if not get_app_password_hash():
        if request.endpoint != 'setup':
            return redirect(url_for('setup'))
        return
    # password set but not logged in → force login
    if not session.get('logged_in'):
        return redirect(url_for('login', next=request.path))

    # global‐invalidation: check the session salt
    if session.get('session_salt') != get_session_salt():
        session.clear()
        return redirect(url_for('login', next=request.path))

def get_app_password_hash():
    """Fetch the hashed app password from preferences table (or None)."""
    rows = dict_rows(
        "SELECT value FROM preferences WHERE name='app_password'"
    )
    return rows[0]['value'] if rows else None

def set_app_password_hash(hashval):
    """Upsert the hashed app password into preferences."""
    with sqlite3.connect(DB_FILE) as c:
        c.execute("""
            INSERT INTO preferences(name,value)
            VALUES('app_password',?)
            ON CONFLICT(name) DO UPDATE
              SET value=excluded.value
        """, (hashval,))

# pretend RateLimitExceeded is a 500, to confuse bots
@app.errorhandler(RateLimitExceeded)
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

@app.errorhandler(CSRFError)
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

# ───────────────── DB init & migrations ──────────────────
def init_db():
    print("🔧 initializing DB…")

    with sqlite3.connect(DB_FILE, timeout=30) as c:
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("PRAGMA busy_timeout=30000;")

    with sqlite3.connect(DB_FILE) as c:
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

# ───────────────────────────────────────────────────────────
#  schema migrations – run on every start or after DB reset
# ───────────────────────────────────────────────────────────
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

    with sqlite3.connect(DB_FILE) as c:
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

    # Wargame: hold cargo manifest on inbound schedule so it becomes flight.remarks
    ensure_column("wargame_inbound_schedule", "manifest", "TEXT")

    # Wargame: record which tail was assigned to a ramp request
    ensure_column("wargame_ramp_requests", "assigned_tail",   "TEXT")

    with sqlite3.connect(DB_FILE) as c:
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
    print("  → ensuring queued_flights.cargo_weight")
    ensure_column("queued_flights", "cargo_weight",     "REAL DEFAULT 0")

def cleanup_pending():
    """Purge any pending inventory‐entries older than 15 minutes."""
    cutoff = (datetime.utcnow() - timedelta(minutes=15)).isoformat()
    with sqlite3.connect(DB_FILE) as c:
        c.execute("DELETE FROM inventory_entries WHERE pending=1 AND pending_ts<=?",
                  (cutoff,))

# ─── Run pending‐cleanup before any inventory view ─────────
@inventory_bp.before_app_request
def _cleanup_before_view():
    # fire only on inventory blueprint routes
    if request.blueprint == 'inventory':
        cleanup_pending()



@inventory_bp.route('/_advance_data')
def inventory_advance_data():
    """JSON stock snapshot for Advanced panel (re-polled every 15s)."""
    # same build logic as in ramp_boss()
    rows = dict_rows("""
      SELECT e.category_id AS cid,
             c.display_name AS cname,
             e.sanitized_name,
             e.weight_per_unit,
             /*   in  −  out   → available   */
             SUM(
               CASE
                 WHEN e.direction = 'in'  THEN  e.quantity
                 WHEN e.direction = 'out' THEN -e.quantity
               END
             ) AS qty
        FROM inventory_entries e
        JOIN inventory_categories c ON c.id=e.category_id
        GROUP BY e.category_id, e.sanitized_name, e.weight_per_unit
        HAVING qty > 0
    """)
    data = {"categories":[], "items":{}, "sizes":{}, "avail":{}}
    for r in rows:
        cid = str(r['cid'])
        # availability
        data["avail"].setdefault(cid, {})\
             .setdefault(r['sanitized_name'], {})[str(r['weight_per_unit'])] = r['qty']
        # categories
        if not any(c["id"]==cid for c in data["categories"]):
            data["categories"].append({"id":cid,"display_name":r['cname']})
        # items & sizes
        data["items"].setdefault(cid, [])
        data["sizes"].setdefault(cid, {})
        if r['sanitized_name'] not in data["items"][cid]:
            data["items"][cid].append(r['sanitized_name'])
            data["sizes"][cid][r['sanitized_name']] = []
        data["sizes"][cid][r['sanitized_name']].append(str(r['weight_per_unit']))
    # ─── maintain legacy key so Ramp-Boss JS keeps working ───
    data["all_categories"] = data["categories"]
    return jsonify(data)

def ensure_airports_table():
    with sqlite3.connect(DB_FILE) as c:
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
        c.execute("""
          CREATE INDEX IF NOT EXISTS idx_airports_search
            ON airports(ident, icao_code, iata_code, gps_code, local_code)
        """)

def load_airports_from_csv():
    """One-time load/refresh of airports.csv into airports table."""
    csv_path = os.path.join(os.path.dirname(__file__), 'airports.csv')
    if not os.path.exists(csv_path):
        return
    with sqlite3.connect(DB_FILE) as c, open(csv_path, newline='', encoding='utf-8') as f:
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

# ───────────────────────────────────────────────────────────────────────────
# Inventory Name‑Sanitization (strip punctuation, lowercase, drop adjectives)
ADJECTIVES_FILE = os.path.join(os.path.dirname(__file__), 'english_adjectives.txt')
with open(ADJECTIVES_FILE, encoding='utf-8') as f:
    ENGLISH_ADJECTIVES = {
        line.strip().lower()
        for line in f
        if line.strip() and not line.startswith('#')
    }

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
    with sqlite3.connect(DB_FILE) as c:
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

init_db()
run_migrations()
ensure_airports_table()
load_airports_from_csv()


  # ── init 1090-distance globals ───────────────────────────────────────
app.extensions.setdefault('distances', {})   # hex/flight→km
app.extensions.setdefault('recv_loc', {'lat':None,'lon':None})

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
                    lat1 = app.extensions['recv_loc']['lat']
                    lon1 = app.extensions['recv_loc']['lon']
                    if call and lat1 is not None:
                        km_val = haversine(lat1, lon1, lat2, lon2)
                        # store both the latest distance *and* when we saw it
                        app.extensions['distances'][call] = (round(km_val,1), time.time())
                except:
                    continue
        except:
            time.sleep(5)

# ────────────────────────────────────────────────────────────────
# Seed default inventory categories
def seed_default_categories():
    defaults = ['emergency supplies','food','medical supplies','water','other']
    with sqlite3.connect(DB_FILE) as c:
        for nm in defaults:
            c.execute("""
              INSERT OR IGNORE INTO inventory_categories(name, display_name)
              VALUES(?,?)
            """, (nm, nm.title()))

seed_default_categories()

# ───────────────── helper funcs ──────────────────────────

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

# Ensure clean shutdown (useful in dev / reloader)
def _shutdown_scheduler():
    try:
        if scheduler.state == STATE_RUNNING: scheduler.shutdown(wait=False)
    except Exception: pass
atexit.register(_shutdown_scheduler)

def get_preference(name: str) -> str | None:
    """Fetch a single preference value (or None if not set)."""
    rows = dict_rows("SELECT value FROM preferences WHERE name=?", (name,))
    return rows[0]['value'] if rows else None

def set_preference(name: str, value: str) -> None:
    """Upsert a preference."""
    with sqlite3.connect(DB_FILE) as c:
        c.execute("""
            INSERT INTO preferences(name,value)
            VALUES(?,?)
            ON CONFLICT(name) DO UPDATE
              SET value = excluded.value
        """, (name, value))

def clear_embedded_preferences() -> None:
    """Remove any embedded‑tab prefs and reset distances off."""
    with sqlite3.connect(DB_FILE) as c:
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

@app.route('/wargame/radio/email/<int:email_id>')
def fetch_wargame_email(email_id):
    """Return the subject+body for one wargame email (JSON)."""
    row = dict_rows("SELECT subject, body FROM wargame_emails WHERE id=?", (email_id,))
    if not row:
        return jsonify({}), 404
    return jsonify(subject=row[0]['subject'], body=row[0]['body'])

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

    with sqlite3.connect(DB_FILE) as c:
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
    with sqlite3.connect(DB_FILE) as c:
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

@app.template_filter('hide_tbd')
def hide_tbd_filter(value):
    """
    Jinja filter: blank out any of '', None, 'TBD' or '—'.
      In templates: {{ some_field|hide_tbd }}
    """
    return '' if value in (None, '', 'TBD', '—') else value

def format_airport(raw_code: str, pref: str) -> str:
    """
    Given any code (ICAO, IATA, or local), look it up in airports
    and return the user-preferred format. Falls back to raw_code.
    """
    code = (raw_code or '').upper()
    if not code:
        return 'TBD'

    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        row = c.execute("""
          SELECT *
            FROM airports
           WHERE ? IN (icao_code, iata_code, gps_code, local_code, ident)
           /* prefer real ICAO / IATA over stray local_code hits like AYBM=BLI */
           ORDER BY (icao_code = ? OR iata_code = ?) DESC
           LIMIT 1
        """, (code, code, code)).fetchone()

    if not row:
        return raw_code

    if pref == 'icao4':
        return row['icao_code'] or raw_code
    if pref == 'iata':
        return row['iata_code'] or raw_code
    if pref == 'local':
        return row['gps_code'] or row['local_code'] or row['ident'] or raw_code

    # fallback
    return raw_code

# Cache airport lookups (up to 250 entries)
_fmt_airport = lru_cache(maxsize=250)(format_airport)

# ── Winlink parser with conversions ──────────────────────
# allow either “ETA” or “landed” before the time, so that
# subjects like “| landed 1840” still parse tail/from/to/tko
# allow the “took off … | ” segment to be skipped for pure-landed notices
# ── Winlink parser with conversions ──────────────────────
# allow subjects with or without “took off … | ”,
# and with “ETA”, “ETA hhmm”, “landed hhmm”, or no time
air_ops_re = re.compile(r"""
    Air\ Ops:\s*
    (?P<tail>[^|]+?)\s*\|\s*
    (?P<from>[^|]+?)\s*to\s*(?P<to>[^|]+?)\s*\|\s*
    (?:                                    # optional “took off HHMM”
       (?:took\ off|takeoff\s+estimate)\s*(?P<tko>\d{1,2}:?\d{2})
       (?:\s*\|\s*|\s+)                   # allow “|” *or* just space before next
    )?
    (?:                                    # optional ETA or landed segment
       (?:ETA(?:\s*(?P<eta>\d{1,2}:?\d{2}))?)?   # “ETA” or “ETA hhmm” or bare “ETA”
       |
       (?:landed\s*(?P<landed>\d{1,2}:?\d{2}))?  # “landed hhmm”
    )
""", re.IGNORECASE | re.VERBOSE)


# more permissive parsing for Cargo Type, Cargo Weight and Remarks
cargo_type_re = re.compile(
    r"Cargo\s*Type(?:\(\s*s\)|s)?\s*[:\.\s-]*?(?P<ct>[^\r\n]+)",
    re.I
)

# ── fall‐back “any Cargo Type” matcher ──────────────────────────────
simple_ct_re = re.compile(
    r"Cargo\s*Type(?:\(s\))?\s*[^\S\r\n]*(?P<ct>[^\r\n]+)",
    re.IGNORECASE
)

cargo_weight_re = re.compile(
    r"Total\s*Weight(?:\s*of\s*the\s*Cargo)?\s*[:\.\s-]*?(?P<wgt>[^\r\n]+)",
    re.I
)
# capture anything after “Additional notes/comments” (or variants) up to “DART”
remarks_re = re.compile(
    r"Additional\s*notes(?:/comments| comments)?\s*[:\.\s]*?(?P<rm>.*?)(?=\bDART|\Z)",
    re.I | re.S
)

def parse_weight_str(w):
    w=w.strip()
    if 'kg' in w.lower():
        num=float(re.findall(r"[\d.]+",w)[0])
        return f"{kg_to_lbs(num)} lbs"
    return w

def parse_winlink(subj:str, body:str):
    d = dict.fromkeys((
        'tail_number','airfield_takeoff','airfield_landing',
        'takeoff_time','eta','cargo_type','cargo_weight','remarks'
    ), '')

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

    # 3) strip stray leading “s ” (e.g. “s food” → “food”)
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
    with sqlite3.connect(DB_FILE) as c:
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

        # 2) landing?
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
                     SET eta=?, complete=1, sent=0, remarks=?
                   WHERE id=?
                """, (arrival, new_rem, match['id']))
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
            c.execute(f"""
              UPDATE flights SET
                airfield_takeoff = ?,
                airfield_landing = ?,
                eta              = CASE WHEN ?<>'' THEN ? ELSE eta END,
                cargo_type       = CASE WHEN ?<>'' THEN ? ELSE cargo_type   END,
                cargo_weight     = CASE WHEN ?<>'' THEN ? ELSE cargo_weight END,
                remarks          = CASE WHEN ?<>'' THEN ? ELSE remarks      END
              WHERE id=?
            """, (
              p['airfield_takeoff'],
              p['airfield_landing'],
              p['eta'],            p['eta'],
              p['cargo_type'],     p['cargo_type'],
              p['cargo_weight'],   p['cargo_weight'],
              p.get('remarks',''), p.get('remarks',''),
              f['id']
            ))
            return f['id'], 'updated'

        # 4) new entry (mark pure Winlink imports as inbound)
        fid = c.execute("""
          INSERT INTO flights(
            is_ramp_entry, direction,
            tail_number, airfield_takeoff, takeoff_time,
            airfield_landing, eta, cargo_type, cargo_weight, remarks
          ) VALUES (0,'inbound',?,?,?,?,?,?,?,?)
        """, (
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

@app.after_request
def refresh_user_cookies(response):
    # only replay prefs on GET responses so POST-set cookies aren't stomped
    if request.method != 'GET':
        return response

    ONE_YEAR = 31_536_000  # seconds
    pref_cookies = [
        'code_format', 'mass_unit', 'operator_call',
        'include_test', 'radio_show_unsent_only', 'show_debug_logs',
        'hide_tbd'
    ]
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

# ──────────────────────────────────────────────────────────
#  Purge rows with **no meaningful data**
# ──────────────────────────────────────────────────────────
def purge_blank_flights() -> None:
    """Remove flights where *every* user-facing field is blank or “TBD”."""
    with sqlite3.connect(DB_FILE) as c:
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

# ── CORE WARGAME SCHEDULER & JOBS ──────────────────────────
scheduler = BackgroundScheduler()
_CONFIGURE_WG_LOCK = threading.Lock()

# ── Helpers for radio callsigns ───────────────────────────
def get_airfield_callsign(af):
    """Map an airfield to a persistent random callsign."""
    if af not in AIRFIELD_CALLSIGNS:
        AIRFIELD_CALLSIGNS[af] = generate_random_callsign()
    return AIRFIELD_CALLSIGNS[af]

# Insert a pending task only if it does not already exist
def wargame_task_start_once(role: str, kind: str, key: str, gen_at: str, sched_for: str | None = None) -> None:
    rows = dict_rows(
        "SELECT 1 FROM wargame_tasks WHERE role=? AND kind=? AND key=?",
        (role, kind, key)
    )
    if rows:
        return
    wargame_task_start(role=role, kind=kind, key=key, gen_at=gen_at, sched_for=sched_for)

def _reset_autoincrements(names: list[str]) -> None:
    """Best‑effort reset of AUTOINCREMENT counters (SQLite keeps them after DELETE)."""
    try:
        with sqlite3.connect(DB_FILE) as c:
            for n in names:
                c.execute("DELETE FROM sqlite_sequence WHERE name=?", (n,))
    except Exception:
        # Ignore on engines without sqlite_sequence or non‑AUTOINCREMENT tables.
        pass


def set_wargame_epoch(epoch=None) -> int:
    """
    Persist a stable epoch for the current Wargame run.
    This namespaces client cookies (e.g., read/unread) so they reset only
    when Wargame is (re)started, not on every page render.
    """
    if epoch is None:
        epoch = int(time.time())
    with sqlite3.connect(DB_FILE) as c:
        c.execute(
            "INSERT OR REPLACE INTO preferences(name, value) VALUES(?, ?)",
            ('wargame_epoch', str(epoch))
        )
        c.commit()
    return epoch

def get_wargame_epoch() -> int:
    """Return current Wargame epoch (0 if not set)."""
    row = dict_rows("SELECT value FROM preferences WHERE name='wargame_epoch'")
    try:
        return int(row[0]['value'])
    except Exception:
        return 0


def reset_wargame_state():
    """
    Wipe transient Wargame queues so a fresh run starts clean.
    Note: delete child rows before parent rows.
    """
    with sqlite3.connect(DB_FILE) as c:
        cur = c.cursor()
        # Radio
        cur.execute("DELETE FROM wargame_emails")
        cur.execute("DELETE FROM wargame_radio_schedule")
        # Ramp
        cur.execute("DELETE FROM wargame_ramp_requests")
        cur.execute("DELETE FROM wargame_inbound_schedule")
        # Inventory (batch items, then batches)
        cur.execute("DELETE FROM wargame_inventory_batch_items")
        cur.execute("DELETE FROM wargame_inventory_batches")
        c.commit()
    # Reset AUTOINCREMENT counters so new runs start from 1 again.
    _reset_autoincrements([
        'wargame_emails',
        'wargame_radio_schedule',
        'wargame_ramp_requests',
        'wargame_inbound_schedule',
        'wargame_inventory_batches',
        'wargame_inventory_batch_items',
        'wargame_tasks'
    ])

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
    with sqlite3.connect(DB_FILE) as c:
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
    """Enqueue a synthetic radio email into the schedule (batch or immediate)."""
    now   = datetime.utcnow()
    ts    = now.isoformat()
    msg_id = uuid.uuid4().hex

    # pick a non‑origin airfield for the sender; choose a plausible destination
    pref   = dict_rows("SELECT value FROM preferences WHERE name='default_origin'")
    origin = (pref[0]['value'].strip().upper() if pref and pref[0]['value'] else None)
    choices = [af for af in HARDCODED_AIRFIELDS if af != origin]
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
    now_iso   = now.isoformat()
    due_cnt = dict_rows("""
      SELECT COUNT(*) AS c
        FROM wargame_tasks
       WHERE role='radio' AND kind='inbound'
         AND (sched_for IS NULL OR sched_for <= ?)
    """, (now_iso,))[0]['c'] or 0
    if due_cnt >= max_radio:
        return

    # build realistic times & Air Ops subject with a hidden WG tag
    tko_hhmm = now.strftime('%H%M')
    eta_hhmm = (now + timedelta(minutes=random.randint(12, 45))).strftime('%H%M')

    size    = random.randint(500, 2000)
    manifest, total_wt, cargo_type = generate_cargo_manifest()
    subject = (
        f"Air Ops: {tail} | {af} to {dest} | "
        f"took off {tko_hhmm} | ETA {eta_hhmm} [WGID:{msg_id}]"
    )

    notes = ["Auto-generated Wargame traffic."]
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

    with sqlite3.connect(DB_FILE) as c:
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

def wargame_finish_radio_inbound_if_tagged(subject: str, body: str) -> None:
    """If message carries a WGID and Wargame is on, finish the radio-inbound task."""
    if get_preference('wargame_mode') != 'yes':
        return
    wgid = extract_wgid_from_text(subject, body)
    if wgid:
        try:
            wargame_task_finish('radio', 'inbound', f"msg:{wgid}")
        except Exception:
            pass  # be defensive; this should never break operator flow

def wargame_finish_radio_outbound(fid: int) -> None:
    """Finish radio‑outbound metric when the operator marks the flight as sent."""
    if get_preference('wargame_mode') == 'yes':
        try:
            wargame_task_finish('radio', 'outbound', key=f"flight:{fid}")
        except Exception:
            pass

def wargame_start_radio_outbound(fid: int) -> None:
    """Start radio‑outbound metric for a new outbound ramp flight."""
    if get_preference('wargame_mode') == 'yes':
        try:
            wargame_task_start_once('radio', 'outbound', key=f"flight:{fid}", gen_at=datetime.utcnow().isoformat())
        except Exception:
            pass

def wargame_finish_ramp_inbound(fid: int) -> None:
    """Finish ramp‑inbound metric when an arrival is logged/updated."""
    if get_preference('wargame_mode') == 'yes':
        try:
            wargame_task_finish('ramp', 'inbound', key=f"flight:{fid}")
        except Exception:
            pass

def wargame_start_ramp_inbound(fid: int, started_at: str | None = None) -> None:
    """Start ramp‑inbound timer when an inbound cue appears for this flight."""
    if get_preference('wargame_mode') == 'yes':
        wargame_task_start_once(
            role='ramp',
            kind='inbound',
            key=f"flight:{fid}",
            gen_at=(started_at or datetime.utcnow().isoformat())
        )

def process_radio_schedule():
    """
    Every minute: move due messages into wargame_emails.
    (Metrics are finalized when the operator actually submits to the parser.)
    """
    now_iso = datetime.utcnow().isoformat()
    settings_row = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
    settings  = json.loads(settings_row[0]['value'] or '{}') if settings_row else {}
    max_radio = int(settings.get('max_radio', 3) or 3)
    visible = dict_rows("""
      SELECT COUNT(*) AS c
        FROM wargame_tasks
       WHERE role='radio' AND kind='inbound'
         AND (sched_for IS NULL OR sched_for <= ?)
    """, (now_iso,))[0]['c'] or 0
    allow = max(0, max_radio - visible)
    if allow <= 0:
        return

    due = dict_rows(
        "SELECT * FROM wargame_radio_schedule WHERE scheduled_for <= ? ORDER BY scheduled_for ASC LIMIT ?",
        (now_iso, allow)
    )

    for r in due:
        with sqlite3.connect(DB_FILE) as c:
            c.execute("""
              INSERT INTO wargame_emails
                (generated_at, message_id, size_bytes,
                 source, sender, recipient, subject, body)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
              r['generated_at'], r['message_id'], r['size_bytes'],
              r['source'],       r['sender'],     r['recipient'],
              r['subject'],      r['body']
            ))
            c.execute("DELETE FROM wargame_radio_schedule WHERE id=?", (r['id'],))

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
        lines.append(f"{name} {size} lb×{qty}")
        total += size * qty

    return ("; ".join(lines), float(total), "Mixed")

def generate_ramp_request():
    """
    Generate a cargo *request* destined to a remote airport (appears on
    Wargame → Ramp as a cue card). Enforces max_ramp cap and guarantees
    a non-empty manifest.
    """
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
    import random as _r
    picks = _r.sample(avail, k=min(len(avail), _r.randint(2,5)))
    lines, total_wt = [], 0.0
    for r in picks:
        have = int(r['qty'])
        ask  = _r.randint(1, min(4, have))
        lines.append(f"{r['noun']} {int(r['size_lb'])} lb×{ask}")
        total_wt += r['size_lb'] * ask
    manifest = '; '.join(lines)

    with sqlite3.connect(DB_FILE) as c:
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

def _parse_manifest(manifest: str):
    """
    Return list of dicts: [{'name':str,'size_lb':float,'qty':int}, ...]
    Accepts 'tarps 10 lb×3; water 20 lb×2' and minor variants (x, lbs, spaces).
    """
    items = []
    for part in (manifest or '').split(';'):
        t = part.strip()
        if not t: continue
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
    items = _parse_manifest(manifest)
    if not items:
        return None
    with sqlite3.connect(DB_FILE) as c:
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

def reconcile_inventory_batches(session_id: str) -> None:
    """
    For the just-committed /inventory session:
      • Match **only** by exact item (sanitized name) **and** exact size.
      • Use either parsed lines from raw_name (e.g., "beans 25 lb×3"), or the
        structured columns (sanitized_name, weight_per_unit, quantity).
      • There is **no weight-based fallback**; any remainder stays unapplied
        until exact stock lines are logged.
      • When a batch completes, set satisfied_at and write one inventory SLA metric.
    """
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        entries = c.execute("""
            SELECT
              id,
              direction,             -- 'in' | 'out'
              quantity,
              total_weight,
              weight_per_unit,
              sanitized_name,
              COALESCE(NULLIF(raw_name,''), '') AS raw_name
            FROM inventory_entries
            WHERE session_id=? AND pending=0
              AND source='inventory'
        """, (session_id,)).fetchall()
        if not entries:
            return
        now_ts = datetime.utcnow().isoformat()

        def load_batches(direction: str):
            bs = c.execute("""
                SELECT id, created_at
                  FROM wargame_inventory_batches
                 WHERE direction=? AND satisfied_at IS NULL
            """, (direction,)).fetchall()
            out = []
            for b in bs:
                items = c.execute("""
                    SELECT id, name, size_lb, qty_required, qty_done
                      FROM wargame_inventory_batch_items
                     WHERE batch_id=?
                """, (b['id'],)).fetchall()
                remain = sum(1 for it in items if it['qty_done'] < it['qty_required'])
                out.append({'b': b, 'items': items, 'remain': remain})
            return out

        def pick_most_complete(cands):
            if not cands:
                return None
            cands.sort(key=lambda r: (r['remain'], r['b']['created_at']))
            return cands[0]

        def close_if_complete(batch_id: int, created_at: str):
            items_now = c.execute("""
                SELECT qty_required, qty_done
                  FROM wargame_inventory_batch_items
                 WHERE batch_id=?
            """, (batch_id,)).fetchall()
            if all(x['qty_done'] >= x['qty_required'] for x in items_now):
                c.execute("UPDATE wargame_inventory_batches SET satisfied_at=? WHERE id=?",
                          (now_ts, batch_id))
                delta = (datetime.fromisoformat(now_ts) - datetime.fromisoformat(created_at)).total_seconds()
                c.execute("""
                  INSERT INTO wargame_metrics(event_type, delta_seconds, recorded_at, key)
                  VALUES ('inventory', ?, ?, ?)
                """, (delta, now_ts, f"invbatch:{batch_id}"))

        def apply_item(direction: str, name_raw: str, size_lb: float, qty: int) -> int:
            """
            Allocate `qty` units of (sanitized(name_raw), size_lb) across batches that still need them.
            Returns the number of units actually applied.
            """
            if qty <= 0 or size_lb <= 0:
                return 0
            applied = 0
            san = sanitize_name(name_raw)
            while qty > 0:
                cands = []
                for r in load_batches(direction):
                    need_here = any(
                        sanitize_name(it['name']) == san and abs(it['size_lb'] - size_lb) < 1e-6 and
                        it['qty_done'] < it['qty_required']
                        for it in r['items']
                    )
                    if need_here:
                        cands.append(r)
                pick = pick_most_complete(cands)
                if not pick:
                    break
                for it in pick['items']:
                    if sanitize_name(it['name']) == san and abs(it['size_lb'] - size_lb) < 1e-6:
                        remaining = it['qty_required'] - it['qty_done']
                        inc = min(qty, remaining)
                        if inc > 0:
                            c.execute(
                              "UPDATE wargame_inventory_batch_items SET qty_done=qty_done+? WHERE id=?",
                              (inc, it['id'])
                            )
                            applied += inc
                            qty     -= inc
                        break
                close_if_complete(pick['b']['id'], pick['b']['created_at'])
            return applied

        for e in entries:
            # 1) Try parsing raw_name ("beans 25 lb×3" etc.)
            parsed = _parse_manifest(e['raw_name'])
            if parsed:
                for it in parsed:
                    q = int(e['quantity'] or it['qty'] or 1)
                    size = float(it['size_lb'])
                    used = apply_item(e['direction'], it['name'], size, q)

                continue  # next entry

            # 2) No parse → use structured columns (typical for outbound entries)
            qty  = int(e['quantity'] or 0)
            size = float(e['weight_per_unit'] or 0.0)
            name = e['sanitized_name'] or e['raw_name']
            used = 0
            if qty > 0 and size > 0 and name:
                used = apply_item(e['direction'], name, size, qty)

def reconcile_inventory_entry(entry_id: int) -> None:
    """
    Reconcile a single committed Inventory entry (used by Inventory Detail form).
    Mirrors batch reconciliation:
      • Require exact (sanitized name + size) match using parsed raw_name or
        the structured columns.
    """
    row = dict_rows("""
      SELECT id, direction, quantity, total_weight, weight_per_unit, sanitized_name,
             COALESCE(NULLIF(raw_name,''), '') AS raw_name
        FROM inventory_entries
       WHERE id=? AND pending=0
         AND source='inventory'
    """, (entry_id,))
    if not row:
        return
    e = row[0]

    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        now_ts = datetime.utcnow().isoformat()

        def load_batches(direction: str):
            bs = c.execute("""
                SELECT id, created_at FROM wargame_inventory_batches
                 WHERE direction=? AND satisfied_at IS NULL
            """, (direction,)).fetchall()
            out = []
            for b in bs:
                items = c.execute("""
                    SELECT id, name, size_lb, qty_required, qty_done
                      FROM wargame_inventory_batch_items
                     WHERE batch_id=?
                """, (b['id'],)).fetchall()
                remain = sum(1 for it in items if it['qty_done'] < it['qty_required'])
                out.append({'b': b, 'items': items, 'remain': remain})
            return out

        def pick_most_complete(cands):
            if not cands: return None
            cands.sort(key=lambda r: (r['remain'], r['b']['created_at']))
            return cands[0]

        def close_if_complete(batch_id: int, created_at: str):
            items_now = c.execute("""
                SELECT qty_required, qty_done
                  FROM wargame_inventory_batch_items
                 WHERE batch_id=?
            """, (batch_id,)).fetchall()
            if all(x['qty_done'] >= x['qty_required'] for x in items_now):
                c.execute("UPDATE wargame_inventory_batches SET satisfied_at=? WHERE id=?",
                          (now_ts, batch_id))
                delta = (datetime.fromisoformat(now_ts) - datetime.fromisoformat(created_at)).total_seconds()
                c.execute("""
                  INSERT INTO wargame_metrics(event_type, delta_seconds, recorded_at, key)
                  VALUES ('inventory', ?, ?, ?)
                """, (delta, now_ts, f"invbatch:{batch_id}"))

        def apply_item(direction: str, name_raw: str, size_lb: float, qty: int) -> int:
            if qty <= 0 or size_lb <= 0: return 0
            applied = 0
            san = sanitize_name(name_raw)
            while qty > 0:
                cands = []
                for r in load_batches(direction):
                    need_here = any(
                        sanitize_name(it['name']) == san and abs(it['size_lb'] - size_lb) < 1e-6 and
                        it['qty_done'] < it['qty_required']
                        for it in r['items']
                    )
                    if need_here: cands.append(r)
                pick = pick_most_complete(cands)
                if not pick: break
                for it in pick['items']:
                    if sanitize_name(it['name']) == san and abs(it['size_lb'] - size_lb) < 1e-6:
                        remaining = it['qty_required'] - it['qty_done']
                        inc = min(qty, remaining)
                        if inc > 0:
                            c.execute("UPDATE wargame_inventory_batch_items SET qty_done=qty_done+? WHERE id=?",
                                      (inc, it['id']))
                            applied += inc
                            qty     -= inc
                        break
                close_if_complete(pick['b']['id'], pick['b']['created_at'])
            return applied

        # Prefer parsed raw_name if present, else the structured columns
        parsed = _parse_manifest(e['raw_name'])
        if parsed:
            for it in parsed:
                q = int(e['quantity'] or it['qty'] or 1)
                size = float(it['size_lb'])
                used = apply_item(e['direction'], it['name'], size, q)
        else:
            qty  = int(e['quantity'] or 0)
            size = float(e['weight_per_unit'] or 0.0)
            name = e['sanitized_name'] or e['raw_name']
            used = 0
            if qty > 0 and size > 0 and name:
                used = apply_item(e['direction'], name, size, qty)

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
    import random as _r
    picks = _r.sample(avail, k=min(len(avail), _r.randint(2,6)))
    lines = []
    for r in picks:
        have = int(r['qty'] or 0)
        if have <= 0: 
            continue
        ask = _r.randint(1, have)  # do not exceed stock
        lines.append(f"{r['noun']} {int(r['size_lb'])} lb×{ask}")
    if not lines:
        return
    bid = _create_inventory_batch('out', '; '.join(lines), ts)
    # Notify any open Inventory dashboards
    try:
        publish_inventory_event({"kind":"out","batch_id": bid})
    except Exception:
        pass

def generate_inventory_inbound_delivery():
    """Generate a multi-line inbound delivery batch (stuff 'arrived' that must be logged)."""
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
    combos = random.sample([(n,s) for n,szs in WARGAME_ITEMS.items() for s in szs],
                           k=random.randint(2,6))
    lines = []
    for name, size in combos:
        qty = random.randint(1,5)
        lines.append(f"{name} {size} lb×{qty}")
    manifest = '; '.join(lines)
    bid = _create_inventory_batch('in', manifest, ts)
    # Notify any open Inventory dashboards
    try:
        publish_inventory_event({"kind":"in","batch_id": bid})
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
        lines.append(f"{name} {size} lb×{qty}")
        total_wt += size * qty
    remarks = '; '.join(lines)

    with sqlite3.connect(DB_FILE) as c:
        cur = c.execute("""
          INSERT INTO flights
            (tail_number, airfield_takeoff, airfield_landing,
             takeoff_time, eta, cargo_type, cargo_weight, cargo_weight_real,
             is_ramp_entry, direction, complete, remarks)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 0, ?)
        """, (tail, dep, arr, tko_hhmm, eta_hhmm, 'Mixed', total_wt, float(total_wt), direction, remarks))

        fid = cur.lastrowid

    # If this is an outbound request, start the Radio‑outbound timer now.
    if direction == 'outbound' and get_preference('wargame_mode') == 'yes':
        wargame_start_radio_outbound(fid)
        # Also start Ramp outbound SLA (runs until ramp marks complete)
        try:
            wargame_task_start('ramp', 'outbound', key=f"flight:{fid}", gen_at=ts)
        except Exception: pass

def process_inbound_schedule():
    """
    Every minute:
      (a) publish due entries from wargame_inbound_schedule → flights and start a Ramp inbound timer immediately;
      (b) promote radio‑parsed inbound flights (already in flights) to Ramp after they’ve existed ≥ 5 minutes
          and are destined for the configured default origin.
    """
    now_dt  = datetime.utcnow()
    now_iso = now_dt.isoformat()
    settings_row = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
    settings  = json.loads(settings_row[0]['value'] or '{}') if settings_row else {}
    # Cargo-flow gating: only schedule inbound flights for ramp boss in these modes
    flow = settings.get('cargo_flow', 'hybrid')
    if flow not in ('air_air', 'air_ground', 'hybrid'):
        return

    max_ramp  = int(settings.get('max_ramp', 3) or 3)
    pend = dict_rows("""
      SELECT COUNT(*) AS c FROM wargame_tasks
       WHERE role='ramp' AND kind='inbound'
    """)[0]['c'] or 0
    allow = max(0, max_ramp - pend)
    if allow <= 0:
        return
    due = dict_rows("""
      SELECT * FROM wargame_inbound_schedule
       WHERE eta <= ?
       ORDER BY eta ASC
       LIMIT ?
    """, (now_iso, allow))

    for r in due:
        tko_hhmm = hhmm_from_iso(r['scheduled_at'])
        eta_hhmm = hhmm_from_iso(r['eta'])
        # Dedup: prefer updating any existing open leg with same identity
        existing = dict_rows("""
          SELECT id, remarks FROM flights
           WHERE complete=0
             AND tail_number=? AND airfield_takeoff=? AND airfield_landing=? AND takeoff_time=?
           ORDER BY id DESC LIMIT 1
        """, (r['tail_number'], r['airfield_takeoff'], r['airfield_landing'], tko_hhmm))
        if existing:
            fid = existing[0]['id']
            with sqlite3.connect(DB_FILE) as c:
                c.execute("""
                  UPDATE flights
                     SET eta=?, cargo_type=?, cargo_weight=?, cargo_weight_real=?,
                         direction='inbound'
                   WHERE id=?
                """, (eta_hhmm, r['cargo_type'], r['cargo_weight'],
                      float(r['cargo_weight'] or 0.0), fid))
            if r['manifest'] and not (existing[0]['remarks'] or '').strip():
                with sqlite3.connect(DB_FILE) as c:
                    c.execute("UPDATE flights SET remarks=? WHERE id=?", (r['manifest'], fid))
        else:
            with sqlite3.connect(DB_FILE) as c:
                cur = c.execute("""
                  INSERT INTO flights
                    (tail_number, airfield_takeoff, airfield_landing,
                     takeoff_time, eta, cargo_type, cargo_weight, cargo_weight_real,
                     is_ramp_entry, direction, complete, remarks)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 'inbound', 0, ?)
                """, (
                  r['tail_number'], r['airfield_takeoff'], r['airfield_landing'],
                  tko_hhmm, eta_hhmm, r['cargo_type'], r['cargo_weight'],
                  float(r['cargo_weight'] or 0.0),
                  r.get('manifest','') or ''
                ))
                fid = cur.lastrowid
        # start ramp inbound SLA when the cue card becomes visible
        wargame_start_ramp_inbound(fid, started_at=now_iso)

        with sqlite3.connect(DB_FILE) as c:
            c.execute("DELETE FROM wargame_inbound_schedule WHERE id=?", (r['id'],))

    # ── (b) Promote radio‑parsed inbound flights after 5 minutes, within remaining headroom ──
    # Recompute remaining capacity after scheduling the due items above.
    pend2 = dict_rows("""
      SELECT COUNT(*) AS c FROM wargame_tasks
       WHERE role='ramp' AND kind='inbound'
    """)[0]['c'] or 0
    remaining = max(0, max_ramp - pend2)
    if remaining <= 0:
        return

    default_dest = (get_preference('default_origin') or '').strip().upper()
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        candidates = c.execute("""
          SELECT id, timestamp, airfield_landing
            FROM flights
           WHERE direction='inbound'
             AND IFNULL(complete,0)=0
             AND IFNULL(is_ramp_entry,0)=0
        """).fetchall()

    created = 0
    for f in candidates:
        # Filter to default origin when configured
        if default_dest and (f['airfield_landing'] or '').strip().upper() != default_dest:
            continue
        # Must be ≥ 5 minutes old
        try:
            born = datetime.fromisoformat(f['timestamp'])
        except Exception:
            continue
        if (now_dt - born).total_seconds() < 600:
            continue
        # Start Ramp inbound SLA once (anchor at the time it becomes visible)
        wargame_task_start_once('ramp', 'inbound', key=f"flight:{f['id']}", gen_at=now_iso)
        created += 1
        if created >= remaining:
            break


def process_remote_confirmations():
    """
    Every minute: for outbound flights we sent >5 min ago (and still not complete),
    enqueue a *radio email* that confirms landing at the remote airport.
    No auto‑creating inbound flights; Radio parses & updates the dashboard.
    """
    now       = datetime.utcnow()
    cutoff    = (now - timedelta(minutes=5)).isoformat()
    delivery  = now.isoformat()  # visible to Radio immediately

    pending = dict_rows("""
      SELECT id, tail_number, airfield_takeoff, airfield_landing, sent_time
        FROM flights
       WHERE is_ramp_entry=1
         AND direction='outbound'
         AND sent=1
         AND complete=0
         AND sent_time <= ?
         AND NOT EXISTS (
               SELECT 1
                 FROM wargame_tasks t
                WHERE t.role='radio' AND t.kind='confirm_gen'
                  AND t.key = 'flight:' || flights.id
            )
    """, (cutoff,))

    for f in pending:
        msg_id         = uuid.uuid4().hex
        landed_hhmm    = datetime.utcnow().strftime('%H%M')
        takeoff_hhmm   = (f.get('takeoff_time') or '').strip() or '----'
        # Build subject with take-off AND landed times, Winlink-style
        subject = (
            f"Air Ops: {f['tail_number']} | "
            f"{f['airfield_takeoff']} to {f['airfield_landing']} | "
            f"took off {takeoff_hhmm} | landed {landed_hhmm} [WGID:{msg_id}]"
        )

        # Build a Winlink-style body matching our Ramp-Boss outbound format
        # so parse_winlink (Cargo Type, Total Weight, etc) still works if needed.
        sender_call = get_airfield_callsign(f['airfield_landing'])
        body_lines = [
            f"{sender_call} message number AUTO.",
            "",
            f"Aircraft {f['tail_number']}:",
            f"  Cargo Type(s) ................. {f.get('cargo_type','none')}",
            f"  Total Weight of the Cargo ..... {f.get('cargo_weight','none')}",
            "",
            "Additional notes/comments:",
            f"  Arrived {landed_hhmm}",
            "",
            "{DART Aircraft Takeoff Report, rev. 2024-05-14}"
        ]
        body = "\n".join(body_lines)
        with sqlite3.connect(DB_FILE) as c:
            # Start radio inbound SLA for this message (batch semantics handled by dispatcher)
            wargame_task_start('radio','inbound', key=f"msg:{msg_id}",
                               gen_at=datetime.utcnow().isoformat(), sched_for=delivery)
            # Guard to avoid re‑generating this confirm again
            wargame_task_start('radio','confirm_gen', key=f"flight:{f['id']}",
                               gen_at=datetime.utcnow().isoformat())
            # Schedule into the radio inbox
            c.execute("""
              INSERT INTO wargame_radio_schedule
                (generated_at, scheduled_for, message_id, size_bytes,
                 source, sender, recipient, subject, body)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
              datetime.utcnow().isoformat(), delivery, msg_id,
              random.randint(400,1200),
              f['airfield_landing'],  # source
              get_airfield_callsign(f['airfield_landing']),  # sender callsign at remote
              'OPERATOR',
              subject, body
            ))

def wargame_task_start(role: str, kind: str, key: str, gen_at: str, sched_for: str | None = None) -> None:
    """Create or refresh a pending Wargame task anchor."""
    with sqlite3.connect(DB_FILE) as c:
        c.execute("""
          INSERT INTO wargame_tasks(role,kind,key,gen_at,sched_for,created_at)
          VALUES(?,?,?,?,?,?)
          ON CONFLICT(role,kind,key) DO UPDATE SET
            gen_at     = excluded.gen_at,
            sched_for  = excluded.sched_for,
            created_at = excluded.created_at
        """, (role, kind, key, gen_at, sched_for, datetime.utcnow().isoformat()))

def wargame_task_finish(role: str, kind: str, key: str) -> bool:
    """
    Resolve a pending Wargame task into a finalized metric.
    Returns True if a task was found & recorded; False if no pending task existed.
    """
    rows = dict_rows(
        "SELECT gen_at, sched_for FROM wargame_tasks WHERE role=? AND kind=? AND key=?",
        (role, kind, key)
    )
    if not rows:
        return False

    now       = datetime.utcnow()
    now_iso   = now.isoformat()
    gen_dt    = datetime.fromisoformat(rows[0]['gen_at'])
    sched_for = rows[0]['sched_for']

    # Radio inbound uses batch semantics; others are simple now - gen_at.
    if role == 'radio' and kind == 'inbound':
        srow = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
        settings    = json.loads(srow[0]['value'] or '{}') if srow else {}
        use_batch   = (settings.get('radio_use_batch','no')   == 'yes')
        count_batch = (settings.get('radio_count_batch','yes') == 'yes')
        anchor_dt   = (datetime.fromisoformat(sched_for)
                       if (use_batch and not count_batch and sched_for)
                       else gen_dt)
    else:
        anchor_dt = gen_dt

    delta = (now - anchor_dt).total_seconds()

    with sqlite3.connect(DB_FILE) as c:
        c.execute("""
          INSERT INTO wargame_metrics(event_type, delta_seconds, recorded_at, key)
          VALUES (?, ?, ?, ?)
        """, (role, delta, now_iso, key))
        c.execute("DELETE FROM wargame_tasks WHERE role=? AND kind=? AND key=?",
                  (role, kind, key))
    return True

def configure_wargame_jobs():
    # clear out any existing jobs
    scheduler.remove_all_jobs()

    # always dispatch due radio messages every minute
    scheduler.add_job(
        func=process_radio_schedule,
        trigger='interval',
        seconds=60,
        id='job_radio_dispatch',
        replace_existing=True
    )

    # publish due inbound schedule entries + promote radio-parsed inbounds every minute
    scheduler.add_job(
        func=process_inbound_schedule,
        trigger='interval',
        seconds=60,
        id='job_inbound_schedule',
        replace_existing=True
    )

    # load supervisor settings
    settings_row = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
    settings = json.loads(settings_row[0]['value'] or '{}') if settings_row else {}

    #rates have been moved out to a different function, to allow super settings to affect
    #includes radio_rate, inv_out_rate, inv_in_rate, and ramp_rate


    scheduler.add_job(
        func=process_remote_confirmations,
        trigger='interval',
        seconds=60,
        id='job_remote_confirm',
        replace_existing=True
    )

    if scheduler.state != STATE_RUNNING:
        scheduler.start()

def apply_supervisor_settings():
    # clear out any existing rate‐based jobs
    for job_id in ('job_radio','job_inventory_out','job_inventory_in','job_ramp_requests'):
        try:
            scheduler.remove_job(job_id)
        except Exception:
            pass

    # re‐read settings
    srow     = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
    settings = json.loads(srow[0]['value'] or '{}')
    radio_rate   = float(settings.get('radio_rate', 0)    or 0)
    inv_out_rate = float(settings.get('inv_out_rate', settings.get('inv_rate', 0)) or 0)
    inv_in_rate  = float(settings.get('inv_in_rate', settings.get('inv_rate', 0)) or 0)
    ramp_rate    = float(settings.get('ramp_rate', 0)     or 0)

    if radio_rate  > 0:
      scheduler.add_job(
        func=generate_radio_message,
        trigger='interval',
        seconds=max(5, 3600.0 / radio_rate),
        id='job_radio',
        replace_existing=True
      )
    if inv_out_rate> 0:
      scheduler.add_job(
        func=generate_inventory_outbound_request,
        trigger='interval',
        seconds=max(5, 3600.0 / inv_out_rate),
        id='job_inventory_out',
        replace_existing=True
      )
    if inv_in_rate > 0:
      scheduler.add_job(
        func=generate_inventory_inbound_delivery,
        trigger='interval',
        seconds=max(5, 3600.0 / inv_in_rate),
        id='job_inventory_in',
        replace_existing=True
      )
    if ramp_rate   > 0:
      scheduler.add_job(
        func=generate_ramp_request,
        trigger='interval',
        seconds=max(5, 3600.0 / ramp_rate),
        id='job_ramp_requests',
        replace_existing=True
      )

# ————— Proxy for embedded site ——————————————————————————————————————
def _filter_headers(headers):
    # strip hop-by-hop headers
    block = {
        'connection', 'keep-alive', 'proxy-authenticate',
        'proxy-authorization', 'te', 'trailers',
        'transfer-encoding', 'upgrade'
    }
    return [(k, v) for k, v in headers.items() if k.lower() not in block]

# ───────────────── routes ─────────────────────────────────

@app.route('/trigger-500')
def trigger_500():
    # this will always throw, producing a 500
    raise RuntimeError("💥 Test internal server error")

@app.errorhandler(413)
def too_large(e):
    return (
        render_template(
            '413.html',
            max_mb=app.config['MAX_CONTENT_LENGTH'] // (1024*1024)
        ),
        413
    )

# ── Airport code existence check ─────────────────────────────────────────
@app.route('/api/airport_exists/<string:code>')
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

@app.route('/embedded/proxy/', defaults={'path': ''})
@app.route('/embedded/proxy/<path:path>')
@limiter.exempt
def embedded_proxy(path):
    # dynamically read the admin-configured embedded_url
    upstream_base = get_preference('embedded_url') or ''
    if not upstream_base:
        abort(503, "No embedded_url configured")
    # preserve any sub‑path and query string
    upstream = f"{upstream_base.rstrip('/')}/{path}"
    resp = requests.get(
        upstream,
        params=request.args,
        headers={'User-Agent': request.headers.get('User-Agent', '')},
        stream=True,
    )
    filtered = _filter_headers(resp.raw.headers)
    return Response(
        stream_with_context(resp.raw),
        status=resp.status_code,
        headers=filtered,
    )

# ───────────────────────────────────────────────────────────
#  ultra-light heartbeat so browsers can detect connectivity
# ───────────────────────────────────────────────────────────
@app.get("/_ping")
def ping():
    """Return 204 immediately – used by tiny JS heartbeat."""
    resp = make_response(("", 204))
    # Explicit “don’t cache me” headers for any intermediate store
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp

@app.route('/api/lookup_tail/<tail>')
def lookup_tail(tail):
    """Return the newest flight row for a given tail number (JSON) or {}."""
    row = dict_rows(
        "SELECT * FROM flights WHERE tail_number=? ORDER BY id DESC LIMIT 1",
        (tail.upper(),)
    )
    return row[0] if row else {}

# --- dashboard route --------------------------------------
@app.route('/')
def dashboard():
    """
    Render *only* the page skeleton.  The <div id="dashboard-table">
    will be populated via AJAX from /_dashboard_table (streaming).
    """
    # pass tail_filter so the input box shows the right value
    tail_filter = request.args.get('tail_filter','').strip().upper()
    return render_template(
        'dashboard.html',
        active='dashboard',
        tail_filter=tail_filter
    )

# --- Stripped-down dashboard, allows transmission over an AX.25 link or similar ----
@app.route('/dashboard/plain')
def dashboard_plain():
    #  1) only allow calls from localhost
    if request.remote_addr not in ('127.0.0.1', '::1'):
        abort(403)

    # 2) pull the top 20 by your normal priority logic
    flights = dict_rows("""
      SELECT *
        FROM flights
       ORDER BY
         CASE
           WHEN sent=0     THEN 0
           WHEN complete=0 THEN 1
           ELSE 2
         END,
         id DESC
       LIMIT 20
    """)
    return jsonify(flights)

# ─── Radio Operator out-box (sortable, clickable table) ───
@app.route('/radio', methods=['GET','POST'])
def radio():
    if request.method == 'POST':
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        subj   = escape(request.form['subject'].strip())
        body   = escape(request.form['body'].strip())
        sender = escape(request.form.get('sender','').strip())
        ts     = datetime.utcnow().isoformat()

        # --- extract WGID once (subject only) ---
        def _extract_wgid(subject, body):
            m = re.search(r'\[?WGID:([a-f0-9]{16,})\]?', str(subject), re.I)
            return m.group(1).lower() if m else None
        wgid = _extract_wgid(subj, body)

        # --- override parse_winlink tail on bare “landed” notices ---
        m_tail = re.match(r"Air Ops:\s*(?P<tail>\S+)\s*\|\s*landed", subj, re.I)
        tail_override = m_tail.group('tail').strip() if m_tail else None

        # parse
        p = parse_winlink(subj, body)
        if tail_override:
            p['tail_number'] = tail_override

        # ── post-clean the two HHMM fields ────────────────────────────────
        def _clean(t: str) -> str:
            if not t:
                return ''
            u = t.upper().strip()
            if re.match(r'^UNK(?:N|KNOWN)?$', u):  # UNK/UNKN/UNKNOWN → blank
                return ''
            u = re.sub(r'\b(?:L|LOCAL)$', '', u).strip()  # strip trailing L/LOCAL
            return u                  # already zero-padded by parse_winlink()

        p['takeoff_time'] = _clean(p['takeoff_time'])
        p['eta']          = _clean(p['eta'])

        with sqlite3.connect(DB_FILE) as c:
            c.row_factory = sqlite3.Row

            # 1) store raw incoming
            c.execute("""
              INSERT INTO incoming_messages(
                sender, subject, body, timestamp,
                tail_number, airfield_takeoff, airfield_landing,
                takeoff_time, eta, cargo_type, cargo_weight, remarks
              ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
              sender, subj, body, ts,
              p['tail_number'], p['airfield_takeoff'], p['airfield_landing'],
              p['takeoff_time'], p['eta'], p['cargo_type'], p['cargo_weight'],
              p.get('remarks','')
            ))

            # ---- end the write txn, then finish SLA BEFORE any early return ----
            c.commit()
            if wgid:
                try:
                    recorded = wargame_task_finish('radio', 'inbound', key=f"msg:{wgid}")
                    logger.debug("Radio SLA finish WGID=%s recorded=%s", wgid, recorded)
                except Exception as exc:
                    logger.debug("Could not finish Radio‑inbound SLA for WGID %s: %s", wgid, exc)
            else:
                logger.debug("No WGID in message; skipping Radio SLA finish.")

            # 2) landing-report?
            lm = re.search(r'\blanded\s*(\d{1,2}:?\d{2})\b', subj, re.I)
            if lm:
                arrival = hhmm_norm(lm.group(1))
                # 1) strict tail + takeoff_time
                match = c.execute("""
                  SELECT id, remarks
                    FROM flights
                   WHERE tail_number=? AND takeoff_time=? AND complete=0
                   ORDER BY id DESC
                   LIMIT 1
                """, (p['tail_number'], p['takeoff_time'])).fetchone()
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
                    before = dict_rows("SELECT * FROM flights WHERE id=?", (match['id'],))[0]
                    c.execute("""
                      INSERT INTO flight_history(flight_id, timestamp, data)
                      VALUES (?,?,?)
                    """, (match['id'], datetime.utcnow().isoformat(), json.dumps(before)))
                    old_rem = (before.get('remarks') or '').strip()
                    new_rem = (f"{old_rem} / Arrived {arrival}" if old_rem else f"Arrived {arrival}")
                    c.execute("""
                      UPDATE flights
                         SET eta=?, complete=1, remarks=?
                       WHERE id=?
                    """, (arrival, new_rem, match['id']))
                    c.commit()
                    if is_ajax:
                        row = dict_rows("SELECT * FROM flights WHERE id=?", (match['id'],))[0]
                        row['action'] = 'updated'
                        return jsonify(row)
                    flash(f"Flight {match['id']} marked as landed at {arrival}.")
                    return redirect(url_for('radio'))
                # fall through to duplicate/ignore logic if still no match

                # ── no matching outbound.  Do we already have this landing? ──
                dup = c.execute("""
                   SELECT id FROM flights
                    WHERE tail_number=? AND eta=? AND complete=1
                 ORDER BY id DESC LIMIT 1
                """, (p['tail_number'], arrival)).fetchone()

                if dup:
                    if is_ajax:
                        full = dict_rows("SELECT * FROM flights WHERE id=?", (dup['id'],))
                        row = full[0] if full else {'id': dup['id']}
                        row['action'] = 'update_ignored'
                        return jsonify(row)
                    flash(f"Landed notice ignored – flight #{dup['id']} already recorded.")
                    return redirect(url_for('radio'))

                # No matching outbound → ignore creating any flight.
                # We still keep incoming_messages (already inserted above) for audit.
                if is_ajax:
                    return jsonify({'action': 'ignored_landing_no_match',
                                    'tail': p['tail_number'],
                                    'arrival': arrival})
                flash("Remote landing confirmation ignored (no matching outbound leg).")
                return redirect(url_for('radio'))

            # ── fallback: pure “landed” with no time given ──
            elif re.search(r'\blanded\b', subj, re.I):
                match = c.execute(
                    "SELECT id FROM flights WHERE tail_number=? AND complete=0 ORDER BY id DESC LIMIT 1",
                    (p['tail_number'],)
                ).fetchone()
                if match:
                    c.execute("UPDATE flights SET complete=1, sent=0 WHERE id=?", (match['id'],))
                    flash(f"Flight {match['id']} marked as landed (no time given).")
                return redirect(url_for('radio'))

            # 3) not a landing → match by tail & takeoff_time?
            f = c.execute(
                "SELECT id FROM flights WHERE tail_number=? AND takeoff_time=?",
                (p['tail_number'], p['takeoff_time'])
            ).fetchone()

            if f:
                before = dict_rows("SELECT * FROM flights WHERE id=?", (f['id'],))[0]

                no_change = (
                    before['airfield_takeoff'] == p['airfield_takeoff'] and
                    before['airfield_landing'] == p['airfield_landing'] and
                    (p['eta'] or before['eta']) == before['eta'] and
                    (p['cargo_type']   or before['cargo_type'])   == before['cargo_type'] and
                    (p['cargo_weight'] or before['cargo_weight']) == before['cargo_weight'] and
                    (p.get('remarks','') or before['remarks'])    == before['remarks']
                )

                if no_change:
                    if is_ajax:
                        full = dict_rows("SELECT * FROM flights WHERE id=?", (f['id'],))
                        row = full[0] if full else {'id': f['id']}
                        row['action'] = 'update_ignored'
                        return jsonify(row)
                    flash(f"Duplicate Winlink ignored (flight #{f['id']}).")
                    return redirect(url_for('radio'))

                c.execute("""
                  INSERT INTO flight_history(flight_id, timestamp, data)
                  VALUES (?,?,?)
                """, (f['id'], datetime.utcnow().isoformat(), json.dumps(before)))

                c.execute(f"""
                  UPDATE flights SET
                    airfield_takeoff = ?,
                    airfield_landing = ?,
                    eta              = CASE WHEN ?<>'' THEN ? ELSE eta END,
                    cargo_type       = CASE WHEN ?<>'' THEN ? ELSE cargo_type   END,
                    cargo_weight     = CASE WHEN ?<>'' THEN ? ELSE cargo_weight END,
                    remarks          = CASE WHEN ?<>'' THEN ? ELSE remarks      END
                  WHERE id=?
                """, (
                  p['airfield_takeoff'],
                  p['airfield_landing'],
                  p['eta'], p['eta'],
                  p['cargo_type'],   p['cargo_type'],
                  p['cargo_weight'], p['cargo_weight'],
                  p.get('remarks',''), p.get('remarks',''),
                  f['id']
                ))
                c.commit()

                if is_ajax:
                    rs = dict_rows("SELECT * FROM flights WHERE id=?", (f['id'],))
                    row = rs[0] if rs else {'id': f['id']}
                    row['action'] = 'updated'
                    return jsonify(row)

                flash(f"Flight {f['id']} updated from incoming message.")

            else:
                # ── NEW NON-RAMP ENTRY ────────────────────────────
                open_prev = c.execute("""
                    SELECT id, remarks FROM flights
                     WHERE tail_number=? AND complete=0
                """, (p['tail_number'],)).fetchall()

                for prev in open_prev:
                    before = dict_rows("SELECT * FROM flights WHERE id=?", (prev['id'],))[0]
                    c.execute("""
                        INSERT INTO flight_history(flight_id,timestamp,data)
                        VALUES (?,?,?)
                    """, (prev['id'], datetime.utcnow().isoformat(), json.dumps(before)))

                    suffix  = f"Auto-closed at {p['takeoff_time'] or 'next leg'}"
                    new_rem = (prev['remarks'] + " / " if prev['remarks'] else "") + suffix

                    c.execute("""
                        UPDATE flights
                           SET complete=1, sent=0, remarks=?
                         WHERE id=?
                    """, (new_rem, prev['id']))

                fid = c.execute("""
                  INSERT INTO flights(
                    is_ramp_entry,
                    direction,
                    tail_number,
                    airfield_takeoff,
                    takeoff_time,
                    airfield_landing,
                    eta,
                    cargo_type,
                    cargo_weight,
                    remarks
                  ) VALUES (0,'inbound',?,?,?,?,?,?,?,?)
                """, (
                  p['tail_number'],
                  p['airfield_takeoff'],
                  p['takeoff_time'],
                  p['airfield_landing'],
                  p['eta'],
                  p['cargo_type'],
                  p['cargo_weight'],
                  p.get('remarks','')
                )).lastrowid

                c.commit()

                if is_ajax:
                    row = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
                    row['action'] = 'new'
                    return jsonify(row)

                flash(f"Incoming flight logged as new entry #{fid}.")

        # normal (non-AJAX) POST → redirect back to Radio screen
        return redirect(url_for('radio'))

    # ─── GET: fetch & order ramp entries ────────────────────────────────
    show_unsent_only = request.cookies.get('radio_show_unsent_only','yes') == 'yes'
    hide_tbd         = request.cookies.get('hide_tbd','yes') == 'yes'

    base_sql = """
      SELECT *
        FROM flights
       WHERE is_ramp_entry = 1
    """
    if show_unsent_only:
        base_sql += " AND sent = 0\n"
    base_sql += """
       ORDER BY
         CASE
           WHEN sent=0     THEN 0
           WHEN complete=0 THEN 1
           ELSE 2
         END,
         id DESC
    """

    flights = dict_rows(base_sql)

    pref     = dict_rows("SELECT value FROM preferences WHERE name='code_format'")
    code_fmt = request.cookies.get('code_format') or (pref[0]['value'] if pref else 'icao4')
    mass_fmt = request.cookies.get('mass_unit', 'lbs')
    hide_tbd = request.cookies.get('hide_tbd', 'yes') == 'yes'

    for f in flights:
        f['origin_view'] = format_airport(f.get('airfield_takeoff',''), code_fmt)
        f['dest_view']   = format_airport(f.get('airfield_landing',''), code_fmt)

        if f.get('direction')=='outbound' and f.get('eta') and not f.get('complete',0):
            f['eta_view'] = f['eta'] + '*'
        else:
            f['eta_view'] = f.get('eta','TBD')

        cw    = (f.get('cargo_weight') or '').strip()
        m_lbs = re.match(r'([\d.]+)\s*lbs', cw, re.I)
        m_kg  = re.match(r'([\d.]+)\s*kg',  cw, re.I)
        if mass_fmt=='kg' and m_lbs:
            v  = round(float(m_lbs.group(1)) / 2.20462, 1)
            cw = f'{v} kg'
        elif mass_fmt=='lbs' and m_kg:
            v  = round(float(m_kg.group(1)) * 2.20462, 1)
            cw = f'{v} lbs'
        f['cargo_view'] = cw or 'TBD'

    return render_template(
        'radio.html',
        flights=flights,
        active='radio',
        hide_tbd=hide_tbd
    )

# ───────────────────────────────────────────────────────────
#  AJAX PARTIALS for Dashboard & Radio
# ───────────────────────────────────────────────────────────

@app.route('/_dashboard_table')
def dashboard_table_partial():
    purge_blank_flights()
    # compute code_pref, mass_pref, hide_tbd, tail_filter, sort_seq, sql, params...
    cookie_code = request.cookies.get('code_format')
    code_pref   = cookie_code or (
        dict_rows("SELECT value FROM preferences WHERE name='code_format'")
        or [{'value':'icao4'}]
    )[0]['value']
    mass_pref = request.cookies.get('mass_unit','lbs')
    hide_tbd  = request.cookies.get('hide_tbd','yes') == 'yes'

    tail_filter = request.args.get('tail_filter','').strip().upper()
    sort_seq    = request.cookies.get('dashboard_sort_seq','no') == 'yes'

    # ── read 1090‑distances enable flag ───────────────────────────────
    rows = dict_rows(
        "SELECT value FROM preferences WHERE name='enable_1090_distances'"
    )

    # per‑browser unit preference (for the “Dist (…)" header)
    unit = request.cookies.get('distance_unit','nm')

    show_dist = bool(rows and rows[0]['value']=='yes')

    sql = "SELECT * FROM flights"
    params = ()
    if tail_filter:
        sql += " WHERE tail_number LIKE ?"
        params = (f"%{tail_filter}%",)
    if sort_seq:
        sql += " ORDER BY id DESC"
    else:
        sql += """
          ORDER BY
            CASE
              WHEN is_ramp_entry = 1 AND sent = 0 THEN 0
              WHEN complete = 0                       THEN 1
              ELSE 2
            END,
            id DESC
        """

    # Open a DB cursor for streaming (explicitly configure and close later)
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        # Align ad‑hoc connection behavior with init_db() expectations
        conn.execute("PRAGMA busy_timeout=30000;")
    except Exception:
        pass
    raw_cursor = conn.execute(sql, params)


    def gen_rows():
        for r in raw_cursor:
            d = dict(r)

            # — airport formatting & views —
            d['origin_view'] = _fmt_airport(d.get('airfield_takeoff',''), code_pref)
            d['dest_view']   = _fmt_airport(d.get('airfield_landing',''), code_pref)
            if d.get('direction')=='outbound' and d.get('eta') and not d.get('complete'):
                d['eta_view'] = d['eta'] + '*'
            else:
                d['eta_view'] = d.get('eta') or 'TBD'
            cw = (d.get('cargo_weight') or '').strip()
            m_lbs = re.match(r'([\d.]+)\s*lbs', cw, re.I)
            m_kg  = re.match(r'([\d.]+)\s*kg',  cw, re.I)
            if mass_pref=='kg' and m_lbs:
                d['cargo_view'] = f"{round(float(m_lbs.group(1)) / 2.20462, 1)} kg"
            elif mass_pref=='lbs' and m_kg:
                d['cargo_view'] = f"{round(float(m_kg.group(1)) * 2.20462, 1)} lbs"
            else:
                d['cargo_view'] = cw or 'TBD'

            # — distance (only if enabled) + stale‑flag for >5 min old —
            if show_dist:
                unit = request.cookies.get('distance_unit','nm')
                entry = app.extensions['distances'].get(d.get('tail_number'))
                if entry is None:
                    d['distance'] = ''
                    d['distance_stale'] = False
                else:
                    km_val, ts = entry
                    # convert
                    if unit=='mi':
                        val = round(km_val * 0.621371, 1)
                    elif unit=='nm':
                        val = round(km_val * 0.539957, 1)
                    else:
                        val = round(km_val, 1)
                    d['distance'] = val
                    # stale if more than 5 minutes old
                    d['distance_stale'] = (time.time() - ts) > 300
            else:
                d['distance'] = ''
                d['distance_stale'] = False

            yield d

    # Let Jinja stream the same partial, iterating over our cursor
    tmpl   = app.jinja_env.get_template('partials/_dashboard_table.html')

    stream = tmpl.stream(
        flights=gen_rows(),
        hide_tbd=hide_tbd,
        enable_1090_distances=show_dist,
        distance_unit=unit
    )

    stream.enable_buffering(5)   # flush up to 5 rows at a time

    # Wrap in stream_with_context so url_for() works, and explicitly
    # close cursor/connection when the response finishes (or client disconnects)
    resp = Response(stream_with_context(stream), mimetype='text/html')

    @resp.call_on_close
    def _close_streaming_handles():
        try:
            raw_cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

    return resp

@app.route('/_radio_table')
def radio_table_partial():
    # read the same toggle
    show_unsent_only = request.cookies.get('radio_show_unsent_only','yes') == 'yes'

    # build matching query
    sql = """
      SELECT *
        FROM flights
       WHERE is_ramp_entry = 1
    """
    if show_unsent_only:
        sql += " AND sent = 0\n"
    sql += """
       ORDER BY
         CASE
           WHEN sent=0     THEN 0
           WHEN complete=0 THEN 1
           ELSE 2
         END,
         id DESC
    """

    flights = dict_rows(sql)

    # same prefs + view‐field logic as in radio()
    pref     = dict_rows("SELECT value FROM preferences WHERE name='code_format'")
    code_fmt = request.cookies.get('code_format') or (pref[0]['value'] if pref else 'icao4')
    mass_fmt = request.cookies.get('mass_unit', 'lbs')
    hide_tbd = request.cookies.get('hide_tbd', 'yes') == 'yes'

    for f in flights:
        f['origin_view'] = format_airport(f.get('airfield_takeoff',''), code_fmt)
        f['dest_view']   = format_airport(f.get('airfield_landing',''), code_fmt)

        if f.get('direction')=='outbound' and f.get('eta') and not f.get('complete',0):
            f['eta_view'] = f['eta'] + '*'
        else:
            f['eta_view'] = f.get('eta','TBD')

        cw    = (f.get('cargo_weight') or '').strip()
        m_lbs = re.match(r'([\d.]+)\s*lbs', cw, re.I)
        m_kg  = re.match(r'([\d.]+)\s*kg',  cw, re.I)
        if mass_fmt=='kg' and m_lbs:
            v  = round(float(m_lbs.group(1)) / 2.20462, 1)
            cw = f'{v} kg'
        elif mass_fmt=='lbs' and m_kg:
            v  = round(float(m_kg.group(1)) * 2.20462, 1)
            cw = f'{v} lbs'
        f['cargo_view'] = cw or 'TBD'

    return render_template(
        'partials/_radio_table.html',
        flights=flights,
        hide_tbd=hide_tbd
    )

# --- Radio message detail / copy-paste helper ---------------------------
@app.route('/radio_detail/<int:fid>')
def radio_detail(fid):
    rows = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))
    if not rows:
        return ("Not found", 404)
    flight = rows[0]
    callsign   = request.cookies.get('operator_call', 'YOURCALL').upper()
    include_test = request.cookies.get('include_test','yes') == 'yes'

    # build the body lines dynamically
    # ---- figure out the next sequential message number for THIS callsign ---
    with sqlite3.connect(DB_FILE) as c:
        # how many previous history rows were sent by this operator?
        cnt = c.execute("""
            SELECT COUNT(*) FROM flight_history
            WHERE json_extract(data, '$.operator_call') = ?
        """, (callsign,)).fetchone()[0]

    msg_num = f"{cnt + 1:03}"           # 001, 002, …

    # ---- build the Winlink body -------------------------------------------
    lines = []
    if include_test:
        lines.append("**** TEST MESSAGE ONLY  (if reporting on an actual flight, delete this line). ****")
    lines.append(f"{callsign} message number {msg_num}.")
    lines.append("")
    lines.append(f"Aircraft {flight['tail_number']}:")
    lines.append(f"  Cargo Type(s) ................. {flight.get('cargo_type','none')}")
    lines.append(f"  Total Weight of the Cargo ..... {flight.get('cargo_weight','none')}")
    lines.append("")
    lines.append("Additional notes/comments:")
    lines.append(f"  {flight.get('remarks','')}")
    lines.append("")
    lines.append("{DART Aircraft Takeoff Report, rev. 2024-05-14}")

    body = "\n".join(lines)

    # For inbound flights, use “Landed” instead of “ETA”
    if flight.get('direction') == 'inbound':
        subject = (
            f"Air Ops: {flight['tail_number']} | "
            f"{flight['airfield_takeoff']} to {flight['airfield_landing']} | "
            f"Landed {flight['eta'] or '----'}"
        )
    else:
        subject = (
            f"Air Ops: {flight['tail_number']} | "
            f"{flight['airfield_takeoff']} to {flight['airfield_landing']} | "
            f"took off {flight['takeoff_time'] or '----'} | "
            f"ETA {flight['eta'] or '----'}"
        )

    return render_template(
        'send_flight.html',
        flight=flight,
        subject_text=subject,
        body_text=body,
        active='radio'
    )

@app.route('/mark_sent/<int:fid>', methods=['POST'])
@app.route('/mark_sent/<int:flight_id>', methods=['POST'])  # temporary compat
def mark_sent(fid=None, flight_id=None):
    fid = fid or flight_id
    """Flag a flight as sent and snapshot its state (+ operator callsign)."""
    callsign = request.cookies.get('operator_call', 'YOURCALL').upper()
    now_ts   = datetime.utcnow().isoformat()

    with sqlite3.connect(DB_FILE) as c:
        before = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
        prev_sent = int(before.get('sent') or 0)
        before['operator_call'] = callsign

        c.execute("""
            INSERT INTO flight_history(flight_id, timestamp, data)
            VALUES (?,?,?)
        """, (fid, now_ts, json.dumps(before)))

        # also stamp the time so background acks can key off it
        c.execute("UPDATE flights SET sent = 1, sent_time = ? WHERE id = ?", (now_ts, fid))

    # finalize SLA on the first transition 0 -> 1
    if prev_sent == 0:
        # if this is an outbound flight, finish Radio‑outbound SLA
        try:
            row = dict_rows("SELECT direction FROM flights WHERE id=?", (fid,))
            if row and (row[0]['direction'] == 'outbound'):
                wargame_finish_radio_outbound(fid)
            else:
                # inbound: this is the landing confirmation being sent
                wargame_task_finish('radio','landing', key=f"flight:{fid}")
        except Exception:
            pass

    flash(f"Flight {fid} marked as sent.")
    return redirect(url_for('radio'))

# ──────────────────────────────────────────────────────────
#  Ramp-Boss intake (now pre-fills Origin for outbound)
# ──────────────────────────────────────────────────────────
@app.route('/ramp_boss', methods=['GET', 'POST'])
def ramp_boss():
    ensure_column("flights", "is_ramp_entry", "INTEGER DEFAULT 0")

    # pull default_origin from DB (for JS pre-fill)
    drow = dict_rows("SELECT value FROM preferences WHERE name='default_origin'")
    default_origin = drow[0]['value'] if drow else ''

    if request.method == 'POST':
        # ── Validate destination against airports DB ─────────────────────
        dest = request.form.get('destination','').upper().strip()
        if dest:
            rows = dict_rows(
                "SELECT 1 FROM airports "
                " WHERE ident       = ?"
                "    OR icao_code   = ?"
                "    OR iata_code   = ?"
                "    OR local_code  = ?"
                "    OR gps_code    = ?"
                " LIMIT 1",
                (dest,)*5
            )
            if not rows:
                # airport not found → flash a warning but continue
                flash(f'Destination “{dest}” is not in our airport list.', 'warning')

        direction = request.form['direction']
        unit      = request.form['weight_unit']

        # ---------- common field collection ----------
        data = {
            'direction'        : escape(direction),
            'pilot_name'       : escape(request.form.get('pilot_name','').strip()),
            'pax_count'        : escape(request.form.get('pax_count','').strip()),
            'tail_number'      : escape(request.form['tail_number'].strip().upper()),
            'airfield_takeoff' : escape(request.form['origin'].strip().upper()),
            'airfield_landing' : escape(request.form['destination'].strip().upper()),
            'cargo_type'       : escape(request.form['cargo_type'].strip()),
            'cargo_weight'     : escape(norm_weight(request.form['cargo_weight'], unit)),
            'remarks'          : escape(request.form.get('remarks','').strip())
        }

        # ---------- out-bound ----------
        if direction == 'outbound':
            # Capture previous completion state (0/1) if this is an update.
            # We do this BEFORE any UPDATE so we can detect a 0->1 transition later.
            prev_complete = 0
            try:
                fid_form = request.form.get('id')
                if fid_form:
                    row_prev = dict_rows("SELECT complete FROM flights WHERE id=?", (int(fid_form),))
                    if row_prev:
                        prev_complete = int(row_prev[0]['complete'] or 0)
            except Exception:
                # Best-effort only; default to 0 on any parse/lookup failure
                prev_complete = 0

            data['takeoff_time'] = hhmm_norm(request.form['dep_time'])
            data['eta']          = hhmm_norm(request.form['eta'])

            with sqlite3.connect(DB_FILE) as c:
                fid = c.execute("""
                     INSERT INTO flights(
                       is_ramp_entry,direction,pilot_name,pax_count,tail_number,
                       airfield_takeoff,takeoff_time,airfield_landing,eta,
                       cargo_type,cargo_weight,remarks)
                     VALUES (1,:direction,:pilot_name,:pax_count,:tail_number,
                             :airfield_takeoff,:takeoff_time,:airfield_landing,:eta,
                             :cargo_type,:cargo_weight,:remarks)
                """, data).lastrowid

                c.execute("""INSERT INTO flight_history(flight_id,timestamp,data)
                             VALUES (?,?,?)""",
                          (fid, datetime.utcnow().isoformat(), json.dumps(data)))

                # ── 1. turn the *committed* manifest into flight_cargo rows ──
                mid = request.form.get('manifest_id','')
                if mid:
                    c.execute("""
                      INSERT INTO flight_cargo(
                        flight_id, session_id, category_id, sanitized_name,
                        weight_per_unit, quantity, total_weight, direction, timestamp
                      )
                      SELECT ?, session_id, category_id, sanitized_name,
                             weight_per_unit, quantity, total_weight,
                             direction, timestamp
                        FROM inventory_entries
                       WHERE session_id=? AND pending=0
                    """, (fid, mid))

                # mark this as a NEW insert
                action = 'new'

            # WARGAME: start Radio‑outbound SLA (once; until operator marks “sent”)
            wargame_start_radio_outbound(fid)
            # WARGAME: start Ramp‑outbound SLA (once; creation time)
            try:
                wargame_task_start_once('ramp', 'outbound', key=f"flight:{fid}", gen_at=datetime.utcnow().isoformat())
            except Exception:
                pass

            # If operator just marked this outbound complete, finalize Ramp‑outbound SLA.
            # We detect a 0 -> 1 transition using the pre‑update prev_complete captured above.
            try:
                row_now = dict_rows("SELECT complete FROM flights WHERE id=?", (fid,))
                now_complete = int(row_now[0]['complete'] or 0) if row_now else 0
                if now_complete == 1 and prev_complete == 0:
                    wargame_task_finish('ramp', 'outbound', key=f"flight:{fid}")
            except Exception:
                pass

        # ---------- in-bound ----------
        else:  # direction == 'inbound'
            arrival = hhmm_norm(request.form['dep_time'])   # dep_time field = ARRIVAL HHMM
            data['eta']          = arrival      # store arrival in eta column
            data['takeoff_time'] = ''           # unknown / N/A

            with sqlite3.connect(DB_FILE) as c:
                c.row_factory = sqlite3.Row

                # try to find the most-recent, still-open outbound leg
                match = c.execute("""
                          SELECT id, eta FROM flights
                          WHERE tail_number=? AND complete=0
                          ORDER BY id DESC LIMIT 1
                         """, (data['tail_number'],)).fetchone()

                if match:
                    # ----- update the existing outbound row -----
                    # -- When UPDATING entries, we have to clear the sent flag
                    # -- and set the flag indicating this update came from the ramp boss
                    c.execute("""
                        UPDATE flights SET
                          eta            = ?,
                          complete       = 1,
                          sent           = 0,
                          is_ramp_entry  = 1,
                          remarks        = CASE
                                             WHEN LENGTH(remarks)
                                               THEN remarks || ' / Arrived ' || ?
                                             ELSE 'Arrived ' || ?
                                          END
                        WHERE id=?
                    """, (arrival, arrival, arrival, match['id']))
                    # add history snapshot
                    c.execute("""INSERT INTO flight_history(flight_id,timestamp,data)
                                 VALUES (?,?,?)""",
                              (match['id'], datetime.utcnow().isoformat(),
                               json.dumps({'arrival_update': arrival})))
                    action = 'updated'
                    fid    = match['id']

                    # ── attach any committed Advanced-Cargo manifest ──
                    mid = request.form.get('manifest_id','')
                    if mid:
                        c.execute("""
                          INSERT INTO flight_cargo(
                            flight_id, session_id, category_id, sanitized_name,
                            weight_per_unit, quantity, total_weight,
                            direction, timestamp
                          )
                          SELECT ?, session_id, category_id, sanitized_name,
                                 weight_per_unit, quantity, total_weight,
                                 direction, timestamp
                            FROM inventory_entries
                           WHERE session_id=? AND pending=0
                        """, (fid, mid))

                else:
                    # ----- no match → insert a standalone inbound row -----
                    action = 'new'
                    fid = c.execute("""
                        INSERT INTO flights(
                           is_ramp_entry,direction,pilot_name,pax_count,tail_number,
                           airfield_takeoff,takeoff_time,airfield_landing,eta,
                           cargo_type,cargo_weight,remarks,complete)
                        VALUES (1,'inbound',:pilot_name,:pax_count,:tail_number,
                                :airfield_takeoff,'',:airfield_landing,:eta,
                                :cargo_type,:cargo_weight,:remarks,1)
                    """, data).lastrowid
                    c.execute("""INSERT INTO flight_history(flight_id,timestamp,data)
                                 VALUES (?,?,?)""",
                              (fid, datetime.utcnow().isoformat(), json.dumps(data)))

                    # ── attach any committed Advanced-Cargo manifest ──
                    mid = request.form.get('manifest_id','')
                    if mid:
                        c.execute("""
                          INSERT INTO flight_cargo(
                            flight_id, session_id, category_id, sanitized_name,
                            weight_per_unit, quantity, total_weight,
                            direction, timestamp
                          )
                          SELECT ?, session_id, category_id, sanitized_name,
                                 weight_per_unit, quantity, total_weight,
                                 direction, timestamp
                            FROM inventory_entries
                           WHERE session_id=? AND pending=0
                        """, (fid, mid))

            # Route to Radio outbox: Ramp has now touched this record
            with sqlite3.connect(DB_FILE) as c:
                c.execute("UPDATE flights SET is_ramp_entry=1, sent=0 WHERE id=?", (fid,))

            # Start Radio "landing notice" SLA once (avoid resetting on later edits)
            pending = dict_rows(
                "SELECT 1 FROM wargame_tasks WHERE role='radio' AND kind='landing' AND key=?",
                (f"flight:{fid}",)
            )
            if not pending:
                wargame_task_start(
                    role='radio',
                    kind='landing',
                    key=f"flight:{fid}",
                    gen_at=datetime.utcnow().isoformat()
                )

            # Close Ramp inbound SLA (arrival was handled)
            wargame_finish_ramp_inbound(fid)

        # ── at this point we have `fid` of the row we inserted/updated ──
        # fetch it back in full
        row = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
        # If this outbound satisfies a Ramp Request, mark it satisfied
        if row.get('direction') == 'outbound':
            try:
                # compute numeric weight (prefer REAL column if present)
                wt = row.get('cargo_weight_real')
                if wt is None:
                    cw = (row.get('cargo_weight') or '').lower()
                    if cw.endswith('lbs'): cw = cw[:-3]
                    if cw.endswith('lb'):  cw = cw[:-2]
                    wt = float(cw.strip() or 0)
                # find oldest open request with same destination and <= weight
                req = dict_rows("""
                  SELECT id, requested_weight, created_at
                    FROM wargame_ramp_requests
                   WHERE satisfied_at IS NULL
                     AND destination = ?
                   ORDER BY created_at ASC
                   LIMIT 1
                """, (row['airfield_landing'],))
                if req and wt >= float(req[0]['requested_weight'] or 0):
                    rid     = req[0]['id']
                    now_iso = datetime.utcnow().isoformat()
                    tail    = row['tail_number']
                    with sqlite3.connect(DB_FILE) as c:
                        c.execute("""
                          UPDATE wargame_ramp_requests
                             SET satisfied_at=?, assigned_tail=?
                           WHERE id=?
                        """, (now_iso, tail, rid))
                        # record the *actual* SLA latency
                        created_dt = datetime.fromisoformat(req[0]['created_at'])
                        delta = (datetime.utcnow() - created_dt).total_seconds()
                        c.execute("""
                          INSERT INTO wargame_metrics(event_type, delta_seconds, recorded_at, key)
                          VALUES ('ramp', ?, ?, ?)
                        """, (delta, now_iso, f"rampreq:{rid}"))
            except Exception:
                pass
        row['action'] = action

        # if this was XHR (our AJAX), return JSON instead of redirect:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(row)

        # otherwise fall back to the old behavior:
        return redirect(url_for('dashboard'))

    # build Advanced panel data: preload ALL defined categories, then stock snapshot
    # preload *every* category (for inbound mode)
    cats = dict_rows("""
      SELECT id AS cid, display_name AS cname
        FROM inventory_categories
       ORDER BY display_name
    """)
    advanced_data = {
      "all_categories": [
        {"id": str(c["cid"]), "display_name": c["cname"]}
        for c in cats
      ],
      # will fill in only those with stock
      "stock_categories": [],
      "items": {}, "sizes": {}, "avail": {}
    }
    rows = dict_rows("""
      SELECT e.category_id AS cid,
             c.display_name AS cname,
             e.sanitized_name,
             e.weight_per_unit,
             SUM(
               CASE
                 WHEN e.direction='in'  THEN  e.quantity
                 WHEN e.direction='out' THEN -e.quantity
               END
             ) AS qty
        FROM inventory_entries e
        JOIN inventory_categories c ON c.id=e.category_id
       WHERE e.pending = 0
       GROUP BY e.category_id, e.sanitized_name, e.weight_per_unit
       HAVING qty > 0
    """)
    for r in rows:
        cid = str(r['cid'])
        # availability
        advanced_data["avail"].setdefault(cid, {})\
             .setdefault(r['sanitized_name'], {})[str(r['weight_per_unit'])] = r['qty']
        # items & sizes
        advanced_data["items"].setdefault(cid, [])
        advanced_data["sizes"].setdefault(cid, {})
        if r['sanitized_name'] not in advanced_data["items"][cid]:
            advanced_data["items"][cid].append(r['sanitized_name'])
            advanced_data["sizes"][cid][r['sanitized_name']] = []
        advanced_data["sizes"][cid][r['sanitized_name']].append(str(r['weight_per_unit']))
        # record this category for outbound (stock-only) dropdown
        if not any(c["id"] == cid for c in advanced_data["stock_categories"]):
            advanced_data["stock_categories"].append({
              "id": cid, "display_name": r["cname"]
            })

    return render_template(
      'ramp_boss.html',
      default_origin=default_origin,
      active='ramp_boss',
      advanced_data=advanced_data
    )

# ───────────── Add RampBoss entry to “queued_flights” ─────────────
@app.route('/queue_flight', methods=['POST'])
def queue_flight():
    """Save this RampBoss form as a draft in queued_flights + record its cargo."""
    # --- Collect form inputs ---
    mid               = request.form.get('manifest_id','')
    direction         = escape(request.form['direction'])
    pilot_name        = escape(request.form.get('pilot_name','').strip())
    pax_count         = escape(request.form.get('pax_count','').strip())
    tail_number       = escape(request.form['tail_number'].strip().upper())
    airfield_takeoff  = escape(request.form.get('origin','').strip().upper())
    # ── preferred hidden field (added by Ramp-Boss JS) ───────────
    travel_time = request.form.get('travel_time','').strip()

    # fallback for older clients that still submit separate HH/MM boxes
    if not travel_time:
        hrs  = request.form.get('travel_h','').zfill(2)
        mins = request.form.get('travel_m','').zfill(2)
        travel_time = escape(f"{hrs}{mins}" if hrs or mins else '')
    airfield_landing  = escape(request.form.get('destination','').strip().upper())
    cargo_type        = escape(request.form.get('cargo_type','').strip())
    remarks           = escape(request.form.get('remarks','').strip())
    created_at        = datetime.utcnow().isoformat()

    # --- Insert into queued_flights ---
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        cur = c.execute("""
          INSERT INTO queued_flights(
            direction, pilot_name, pax_count, tail_number,
            airfield_takeoff, airfield_landing, travel_time,
            cargo_type, remarks, created_at
          ) VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
          direction, pilot_name, pax_count, tail_number,
          airfield_takeoff, airfield_landing, travel_time,
          cargo_type, remarks, created_at
        ))
        qid = cur.lastrowid

        # --- If we have a manifest, copy the net-out quantities in one go ---
        if mid:
            c.execute("DELETE FROM flight_cargo WHERE queued_id=?", (qid,))
            c.execute("""
          INSERT INTO flight_cargo(
            queued_id, session_id, category_id, sanitized_name,
            weight_per_unit, quantity, total_weight,
            direction, timestamp
          )
          SELECT
            ?,                -- queued_id
            session_id,
            category_id,
            sanitized_name,
            weight_per_unit,
            SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END)            AS net_qty,
            weight_per_unit * SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END) AS net_total,
            'out'                 AS direction,
            MAX(timestamp)        AS latest_ts
          FROM inventory_entries
          WHERE session_id = ?
            AND pending     = 0
          GROUP BY category_id, sanitized_name, weight_per_unit
          HAVING SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END) > 0
        """, (qid, mid))

        # --- Pre-fill the draft’s cargo_weight field ----------------------
        cw_total = c.execute(
            "SELECT COALESCE(SUM(total_weight),0) FROM flight_cargo WHERE queued_id=?",
            (qid,)
        ).fetchone()[0] or 0.0
        c.execute("UPDATE queued_flights SET cargo_weight=? WHERE id=?",
                  (cw_total, qid))
        # end if(mid)

    flash(f"Flight draft {qid} added to queue.", 'info')
    if request.headers.get('X-Requested-With')=='XMLHttpRequest':
        return jsonify({'status':'queued','qid':qid})
    return redirect(url_for('queued_flights'))

# ─────────────── List all queued flights ───────────────────────────
@app.route('/queued_flights')
def queued_flights():
    rows = dict_rows("""
      SELECT id, direction, tail_number,
             airfield_takeoff, airfield_landing,   -- ▼ add landing
             travel_time, cargo_type, remarks, created_at
        FROM queued_flights
       ORDER BY created_at DESC
    """)
    return render_template('queued_flights.html',
                           queued=rows,
                           active='queued_flights')

# ────────────── Send a queued flight “Now” ──────────────────────────
@app.route('/send_queued_flight/<int:qid>', methods=['POST','GET'])
def send_queued_flight(qid):
    # fetch draft
    q = dict_rows("SELECT * FROM queued_flights WHERE id=?", (qid,))
    if not q:
        flash(f"Queue entry {qid} not found.", 'error')
        return redirect(url_for('queued_flights'))
    q = q[0]

    # ── take-off & ETA come **from the browser** when available ─────────────
    cli_dep = request.form.get("takeoff_time","").strip()
    cli_eta = request.form.get("eta","").strip()

    takeoff = cli_dep if cli_dep else now_hhmm()                 # fall-back: server UTC
    eta     = cli_eta if cli_eta else (
                _add_hhmm(takeoff, q["travel_time"]) if q["travel_time"] else ""
              )

    data = {
      'direction'       : q['direction'],
      'pilot_name'      : q['pilot_name'] or '',
      'pax_count'       : q['pax_count'] or '',
      'tail_number'     : q['tail_number'],
      'airfield_takeoff': q['airfield_takeoff'] or '',
      'airfield_landing': q['airfield_landing'] or '',
      'takeoff_time'    : takeoff,
      'eta'             : eta,
      'cargo_type'      : q['cargo_type'] or '',
      'cargo_weight'    : '0',     # will recompute
      'remarks'         : q['remarks'] or ''
    }

    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        fid = c.execute("""
          INSERT INTO flights(
            is_ramp_entry,direction,pilot_name,pax_count,tail_number,
            airfield_takeoff,takeoff_time,airfield_landing,eta,
            cargo_type,cargo_weight,remarks
          ) VALUES (1,:direction,:pilot_name,:pax_count,:tail_number,
                    :airfield_takeoff,:takeoff_time,:airfield_landing,:eta,
                    :cargo_type,:cargo_weight,:remarks)
        """, data).lastrowid

        # ── rebuild the manifest exactly like edit_queued_flight does ──
        mid = request.form.get('manifest_id','').strip()
        if mid:
            # 1️⃣ pull the merged state into Python
            rows = c.execute("""
              SELECT
                category_id,
                sanitized_name,
                weight_per_unit,
                SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END) AS net_qty,
                SUM(CASE direction WHEN 'out' THEN total_weight ELSE -total_weight END) AS net_total,
                MAX(timestamp) AS latest_ts
              FROM (
                SELECT category_id, sanitized_name, weight_per_unit,
                       quantity, total_weight, direction, timestamp
                  FROM flight_cargo
                 WHERE queued_id = ?
                UNION ALL
                SELECT category_id, sanitized_name, weight_per_unit,
                       quantity, total_weight, direction, timestamp
                  FROM inventory_entries
                 WHERE session_id = ? AND pending = 0
              )
              GROUP BY category_id, sanitized_name, weight_per_unit
              HAVING net_qty > 0
            """, (qid, mid)).fetchall()

            # 2️⃣ delete the old snapshot rows
            c.execute("DELETE FROM flight_cargo WHERE queued_id = ?", (qid,))

            # 3️⃣ re-insert exactly what we just fetched
            for cat, name, wpu, qty, tot, ts in rows:
                c.execute("""
                  INSERT INTO flight_cargo(
                    queued_id, session_id, category_id, sanitized_name,
                    weight_per_unit, quantity, total_weight,
                    direction, timestamp
                  ) VALUES (?,?,?,?,?,?,?,?,?)
                """, (
                  qid, mid,
                  cat, name, wpu,
                  qty, tot,
                  'out', ts
                ))

        # now move all associated cargo rows onto this flight
        c.execute("""
          UPDATE flight_cargo
             SET flight_id=?, queued_id=NULL
           WHERE queued_id=?
        """, (fid, qid))

        # ── rebuild cargo_type & remarks from the actual flight_cargo ──
        rows = c.execute("""
          SELECT ic.display_name AS cat,
                 fc.sanitized_name, fc.weight_per_unit AS wpu, fc.quantity
            FROM flight_cargo fc
            JOIN inventory_categories ic
              ON ic.id = fc.category_id
           WHERE fc.flight_id = ?
        """, (fid,)).fetchall()

        # ── now re-calculate cargo_weight for this flight ───────────
        tot = c.execute(
          "SELECT COALESCE(SUM(total_weight),0) "
          "  FROM flight_cargo WHERE flight_id=?",
          (fid,)
        ).fetchone()[0] or 0.0
        c.execute("""
          UPDATE flights
             SET cargo_weight     = printf('%.0f lbs', ?),
                 cargo_weight_real = ?
           WHERE id=?
        """, (tot, tot, fid))

        # cargo_type: single category or Mixed
        cats = {r['cat'] for r in rows}
        new_type = cats.pop() if len(cats)==1 else 'Mixed'
        # build a fresh remarks string (drop trailing “.0” on whole numbers)
        def fmt_wpu(w):
            try:
                f = float(w)
                return str(int(f)) if f.is_integer() else str(f)
            except:
                return str(w)

        new_remarks = '; '.join(
          f"{r['sanitized_name']} {fmt_wpu(r['wpu'])} lb×{r['quantity']}"
          for r in rows
        ) + (';' if rows else '')
        c.execute("""
          UPDATE flights
             SET cargo_type = ?, remarks = ?
           WHERE id = ?
        """, (new_type, new_remarks, fid))

        # delete the draft record
        c.execute("DELETE FROM queued_flights WHERE id=?", (qid,))

    flash(f"Flight {fid} sent.", 'success')
    # Browser fetch() → JSON; classic form-POST → normal redirect
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(
            status   ='sent',
            fid      = fid,
            redirect = url_for('queued_flights')
        )
    return redirect(url_for('queued_flights'))

# ───────────── Delete a queued flight & roll back inventory ─────────
@app.route('/delete_queued_flight/<int:qid>', methods=['POST','GET'])
def delete_queued_flight(qid):
    # load all cargo lines
    cargo = dict_rows("""
      SELECT * FROM flight_cargo WHERE queued_id=?
    """, (qid,))

    with sqlite3.connect(DB_FILE) as c:
        # for each, insert a compensating inventory entry
        for r in cargo:
            rev = 'in' if r['direction']=='out' else 'out'
            c.execute("""
              INSERT INTO inventory_entries(
                category_id, raw_name, sanitized_name,
                weight_per_unit, quantity, total_weight,
                direction, timestamp, source
              ) VALUES (?,?,?,?,?,?,?,?,?)
            """, (
              r['category_id'], r['sanitized_name'], r['sanitized_name'],
              r['weight_per_unit'], r['quantity'], r['total_weight'],
              rev, datetime.utcnow().isoformat(), 'queue-delete'
            ))
        # remove cargo and draft
        c.execute("DELETE FROM flight_cargo WHERE queued_id=?", (qid,))
        c.execute("DELETE FROM queued_flights WHERE id=?", (qid,))

    flash(f"Queue entry {qid} deleted and inventory restored.", 'info')
    return redirect(url_for('queued_flights'))

# ──────────────────────────────────────────────────────────────
#  API: return all cargo rows for a queued-flight draft
# ──────────────────────────────────────────────────────────────

@app.route('/api/queued_manifest/<int:qid>')
def api_queued_manifest(qid):
    # If we have a live Advanced manifest open, merge that in:
    mid = request.args.get('manifest_id','').strip()
    if mid:
        rows = dict_rows("""
          SELECT
            MAX(x.id)           AS entry_id,
            ic.display_name      AS category_name,
            x.sanitized_name     AS sanitized,
            SUM(x.total_weight)  AS total,
            x.weight_per_unit    AS wpu,
            SUM(x.quantity)      AS qty
          FROM (
            -- the snapshot we saved at queue-time
            SELECT id, queued_id, category_id, sanitized_name,
                   weight_per_unit, quantity, total_weight
              FROM flight_cargo
             WHERE queued_id = ?
            UNION ALL
            -- plus any new committed lines in this manifest session
            SELECT id, NULL        AS queued_id, category_id, sanitized_name,
                   weight_per_unit,
                   CASE direction
                     WHEN 'out' THEN quantity
                     ELSE         -quantity
                   END             AS quantity,
                   CASE direction
                     WHEN 'out' THEN total_weight
                     ELSE         -total_weight
                   END             AS total_weight
              FROM inventory_entries
             WHERE session_id = ? AND pending = 0
          ) AS x
          JOIN inventory_categories ic
            ON ic.id = x.category_id
         GROUP BY x.category_id, x.sanitized_name, x.weight_per_unit
         HAVING SUM(x.quantity) > 0
        """, (qid, mid))
    else:
        # no live manifest → show only the saved snapshot
        rows = dict_rows("""
          SELECT
            fc.id                  AS entry_id,
            ic.display_name        AS category_name,
            fc.sanitized_name      AS sanitized,
            fc.total_weight        AS total,
            fc.weight_per_unit     AS wpu,
            fc.quantity            AS qty
          FROM flight_cargo fc
          JOIN inventory_categories ic
            ON ic.id = fc.category_id
          WHERE fc.queued_id = ?
        """, (qid,))
    return jsonify(rows)

# ───────────── Edit a queued draft ───────────────────────────────
@app.route('/edit_queued_flight/<int:qid>', methods=['GET','POST'])
def edit_queued_flight(qid):
    row = dict_rows("SELECT * FROM queued_flights WHERE id=?", (qid,))
    if not row:
        flash("Draft not found","error"); return redirect(url_for('queued_flights'))
    draft = row[0]

    if request.method=='POST':
        # accept either the new single field or the pair
        travel_time = request.form.get('travel_time','').strip()
        if not travel_time:
            hrs  = request.form.get('travel_h','').zfill(2)
            mins = request.form.get('travel_m','').zfill(2)
            travel_time = f"{hrs}{mins}" if hrs or mins else ''
        with sqlite3.connect(DB_FILE) as c:
            c.execute("""
              UPDATE queued_flights SET
                direction=?, pilot_name=?, pax_count=?, tail_number=?,
                airfield_takeoff=?, airfield_landing=?, travel_time=?,
                cargo_type=?, remarks=?
              WHERE id=?
            """,(
              request.form['direction'],
              request.form.get('pilot_name','').strip(),
              request.form.get('pax_count','').strip(),
              request.form['tail_number'].strip().upper(),
              request.form.get('origin','').strip().upper(),
              request.form.get('destination','').strip().upper(),
              travel_time,
              request.form.get('cargo_type','').strip(),
              request.form.get('remarks','').strip(),
              qid
            ))
            # refresh the snapshot to match the **current** manifest (replace-not-append)
            mid   = request.form.get('manifest_id','')
            rows  = []                       # ← default when no live session
            if mid:

                # 1️⃣ collect a **combined** view (old snapshot + new edits)
                rows = c.execute("""
                  SELECT
                    category_id,
                    sanitized_name,
                    weight_per_unit,
                    SUM(CASE direction
                          WHEN 'out' THEN quantity
                          ELSE          -quantity
                        END)                       AS net_qty,
                    SUM(CASE direction
                          WHEN 'out' THEN total_weight
                          ELSE          -total_weight
                        END)                       AS net_total,
                    MAX(timestamp)                  AS latest_ts
                  FROM (
                    /* previous snapshot rows */
                    SELECT category_id, sanitized_name, weight_per_unit,
                           quantity, total_weight, direction, timestamp
                      FROM flight_cargo
                     WHERE queued_id = ?

                    UNION ALL

                    /* newly-committed edits this session */
                    SELECT category_id, sanitized_name, weight_per_unit,
                           quantity, total_weight, direction, timestamp
                      FROM inventory_entries
                     WHERE session_id = ?
                       AND pending     = 0
                  )
                  GROUP BY category_id, sanitized_name, weight_per_unit
                  HAVING net_qty > 0
                """, (qid, mid)).fetchall()

            # 2️⃣ replace the snapshot with the fresh aggregate
            c.execute("DELETE FROM flight_cargo WHERE queued_id=?", (qid,))
            for cat_id, name, wpu, qty, tot, ts in rows:
                c.execute("""
                  INSERT INTO flight_cargo(
                    queued_id, session_id, category_id, sanitized_name,
                    weight_per_unit, quantity, total_weight,
                    direction, timestamp
                  ) VALUES (?,?,?,?,?,?,?,?,?)
                """, (
                  qid, mid,
                  cat_id, name, wpu,
                  qty,  tot,
                  'out', ts
                ))
            # ──────────────────────────────────────────────────────────
            #  Re-compute the new total weight for this draft and store
            #  it, so the “Cargo Weight” input is pre-filled next time.
            # ──────────────────────────────────────────────────────────
            cw_total = c.execute(
                "SELECT COALESCE(SUM(total_weight),0) "
                "  FROM flight_cargo WHERE queued_id=?",
                (qid,)
            ).fetchone()[0] or 0.0
            c.execute(
                "UPDATE queued_flights SET cargo_weight=? WHERE id=?",
                (cw_total, qid)
            )

        flash("Draft updated","success")
        # ── XHR requests expect JSON so the front-end can redirect itself ──
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(
              status='saved',
              redirect=url_for('queued_flights')
            )
        return redirect(url_for('queued_flights'))

    # GET → render Ramp-Boss with a ‘draft’ object for pre-fill
    return render_template('ramp_boss.html',
                           draft=draft,
                           active='ramp_boss',
                           advanced_data={})   # chips fetched by JS as usual

# ─────────── Consolidated Advanced endpoint ─────────────
@inventory_bp.route('/_advance_line', methods=['POST'])
def inventory_advance_line():
    """Single endpoint: add / delete / commit pending lines by `action`."""
    action = request.form.get('action')
    mid     = request.form['manifest_id']

    if action == 'add':
        cleanup_pending()
        direction = request.form['direction']
        cat_id    = int(request.form['category'])

        if direction == 'outbound':
            name = request.form['item']
            wpu  = float(request.form['size'])
            qty  = int(request.form['qty'])

            # check stock availability
            in_qty  = dict_rows(
              "SELECT COALESCE(SUM(quantity),0) AS v FROM inventory_entries "
              "WHERE category_id=? AND sanitized_name=? AND weight_per_unit=? "
              "  AND direction='in' AND pending=0",
              (cat_id,name,wpu)
            )[0]['v']
            out_qty = dict_rows(
              "SELECT COALESCE(SUM(quantity),0) AS v FROM inventory_entries "
              "WHERE category_id=? AND sanitized_name=? AND weight_per_unit=? "
              "  AND direction='out'",
              (cat_id,name,wpu)
            )[0]['v']
            avail = in_qty - out_qty
            if qty > avail:
                return jsonify(success=False,
                               message=f"Only {avail} available"), 400

            raw       = name
            sanitized = name
        else:
            raw       = request.form['name']
            sanitized = sanitize_name(raw)
            wpu       = float(request.form['weight'])
            qty       = int(request.form['qty'])

        total = wpu * qty
        ts    = datetime.utcnow().isoformat()

        # decide source: ramp-panel vs. inventory-detail
        src = 'ramp'
        with sqlite3.connect(DB_FILE) as c:
            cur = c.execute("""
              INSERT INTO inventory_entries(
                category_id, raw_name, sanitized_name,
                weight_per_unit, quantity, total_weight,
                direction, timestamp, pending, pending_ts, session_id, source
              ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
              cat_id, raw, sanitized,
              wpu, qty, total,
              ('in' if direction.startswith('in') else 'out'),
              ts, 1, ts, mid, src
            ))
            eid = cur.lastrowid
            # current running total for this manifest/session (pending only)
            tot = c.execute(
              "SELECT COALESCE(SUM(total_weight),0) FROM inventory_entries "
              "WHERE pending=1 AND session_id=?",
              (mid,)
            ).fetchone()[0] or 0.0

        return jsonify(success=True,
                       entry_id=eid,
                       raw=raw,
                       sanitized=sanitized,
                       wpu=wpu,
                       qty=qty,
                       total=total,
                       direction=direction,
                       ts=ts,
                       manifest_total=float(tot))

    # ─── DELETE branch ────────────────────────────────────────────────
    elif action == 'delete':
        eid   = int(request.form['entry_id'])
        purge = request.form.get('purge') == '1'
        comp_id = None                    # ← ensure it’s always defined
        ts    = datetime.utcnow().isoformat()

        with sqlite3.connect(DB_FILE) as c:
            c.row_factory = sqlite3.Row

            # allow both *pending* rows (still editable) **and** rows that were
            # already committed earlier in this manifest
            row = c.execute(
              "SELECT * FROM inventory_entries WHERE id=? AND session_id=?",
              (eid, mid)
            ).fetchone()

            if not row:
                return jsonify(success=False, message='Row not found'), 404

            is_committed = (row['pending'] == 0)

            # HARD-PURGE  (Back-button or ❌ on a *pending* chip)
            if purge:
                if is_committed:
                    return jsonify(success=False,
                                   message='Cannot purge committed row'), 400
                c.execute("DELETE FROM inventory_entries WHERE id=?", (eid,))

            # SOFT-DELETE  (❌ on a *committed* snapshot chip)
            else:
                # insert an equal-and-opposite *pending* row to cancel it out
                rev = 'in' if row['direction'] == 'out' else 'out'
                cur = c.execute("""
                  INSERT INTO inventory_entries(
                    category_id, raw_name, sanitized_name,
                    weight_per_unit, quantity, total_weight,
                    direction, timestamp, pending, pending_ts,
                    session_id, source
                  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                  row['category_id'], row['raw_name'], row['sanitized_name'],
                  row['weight_per_unit'], row['quantity'], row['total_weight'],
                  rev, ts, 1, ts, mid, 'adv-delete'
                ))
                comp_id = cur.lastrowid

                # we keep the original committed row for audit;
                # if it was still pending we already deleted it via purge

            # fresh pending total for this manifest (only pending rows count)
            tot = c.execute(
              "SELECT COALESCE(SUM(total_weight),0) FROM inventory_entries "
              "WHERE pending=1 AND session_id=?", (mid,)
            ).fetchone()[0] or 0.0

        return jsonify(success=True,
                       manifest_total=float(tot),
                       comp_id=(comp_id if not purge else None))

    elif action == 'commit':
        # mark all session rows committed
        with sqlite3.connect(DB_FILE) as c:
            c.row_factory = sqlite3.Row
            # preserve any explicit source such as 'chip-delete'
            c.execute("""
              UPDATE inventory_entries
                 SET source = COALESCE(NULLIF(source,''),'ramp')
               WHERE session_id=? AND pending=1
            """, (mid,))
            rows = c.execute("""
              SELECT id, timestamp
                FROM inventory_entries
               WHERE session_id=? AND pending=1
            """, (mid,)).fetchall()
            c.execute("UPDATE inventory_entries SET pending=0 WHERE session_id=?", (mid,))

        # Wargame: batch‑level SLA via reconciliation; Legacy: per‑entry timers
        if get_preference('wargame_mode') == 'yes':
            reconcile_inventory_batches(mid)
        else:
            now_ts = datetime.utcnow().isoformat()
            with sqlite3.connect(DB_FILE) as c:
                for r in rows:
                    created_dt = datetime.fromisoformat(r['timestamp'])
                    delta = (datetime.utcnow() - created_dt).total_seconds()
                    c.execute("""
                      INSERT INTO wargame_metrics(event_type, delta_seconds, recorded_at)
                      VALUES ('inventory', ?, ?)
                    """, (delta, now_ts))

        # After commit/reconciliation, notify dashboards (SSE)
        try:
            publish_inventory_event()
        except Exception:
            pass
        # after commit, nothing remains pending for this manifest
        return jsonify(success=True, manifest_total=0.0)

    # ──────────────────────────────────────────────────────────
    #  PURGE  – silent rollback used by the Back button
    # ──────────────────────────────────────────────────────────

    elif action == 'purge':
        eid = int(request.form['entry_id'])
        with sqlite3.connect(DB_FILE) as c:
            c.execute(
              "DELETE FROM inventory_entries "
              " WHERE id=? AND pending=1 AND session_id=?",
              (eid, mid)
            )
        return jsonify(success=True)

    return jsonify(success=False), 400

@app.route('/edit_flight/<int:fid>', methods=['GET','POST'])
def edit_flight(fid):
    if request.method=='POST':
        # sanitize all editable fields
        fields=['direction','pilot_name','pax_count','airfield_takeoff',
                'takeoff_time','airfield_landing','eta','cargo_type',
                'cargo_weight','remarks']
        data={f: escape(request.form.get(f,'').strip()) for f in fields}
        data['airfield_takeoff']=data['airfield_takeoff'].strip().upper()
        data['airfield_landing']=data['airfield_landing'].strip().upper()
        data['takeoff_time']=hhmm_norm(data['takeoff_time'])
        data['eta']=hhmm_norm(data['eta'])
        data['complete']=1 if request.form.get('complete')=='on' else 0
        data['id']=fid
        with sqlite3.connect(DB_FILE) as c:
            before=dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
            c.execute("INSERT INTO flight_history(flight_id,timestamp,data) VALUES (?,?,?)",
                      (fid, datetime.utcnow().isoformat(), json.dumps(before)))
            set_clause=", ".join([f"{k}=:{k}" for k in data if k!='id'])
            c.execute(f"UPDATE flights SET {set_clause} WHERE id=:id", data)
        return redirect(url_for('dashboard'))
    flight=dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
    return render_template('edit_flight.html', flight=flight)

@app.post('/delete_flight/<int:fid>')
def delete_flight(fid):
    """Delete a flight *and* apply compensating inventory lines."""
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        rows = c.execute(
          "SELECT * FROM flight_cargo WHERE flight_id=?", (fid,)
        ).fetchall()
        for r in rows:
            rev = 'in' if r['direction']=='out' else 'out'
            c.execute("""
              INSERT INTO inventory_entries(
                category_id, raw_name, sanitized_name,
                weight_per_unit, quantity, total_weight,
                direction, timestamp, source
              ) VALUES (?,?,?,?,?,?,?,?,?)
            """, (
              r['category_id'], r['sanitized_name'], r['sanitized_name'],
              r['weight_per_unit'], r['quantity'], r['total_weight'],
              rev, datetime.utcnow().isoformat(), 'flight-delete'
            ))
        c.execute("DELETE FROM flight_cargo WHERE flight_id=?", (fid,))
        c.execute("DELETE FROM flights WHERE id=?", (fid,))
    flash(f"Flight {fid} deleted and inventory restored.")
    return redirect(url_for('dashboard'))

@app.post('/delete_flight_cargo/<int:fcid>')
def delete_flight_cargo(fcid):
    """❌-button in the queued-flight editor.
       1) add compensating inventory row (so stock is restored)
       2) delete the snapshot row from flight_cargo                """
    sid = request.form.get('manifest_id','')          # ← current Adv session, may be ''
    now = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row

        # A chip can reference either:
        #   • the saved snapshot row in flight_cargo      (legacy)
        #   • a committed inventory_entries row created   (new)
        #     during this Advanced-panel session.
        #
        r = c.execute("SELECT * FROM flight_cargo WHERE id=?", (fcid,)).fetchone()
        src_table = 'flight_cargo'

        if not r:                     # not a snapshot row → try inventory_entries
            r = c.execute("""
                  SELECT *
                    FROM inventory_entries
                   WHERE id = ? AND pending = 0
            """, (fcid,)).fetchone()
            src_table = 'inventory_entries'

        if not r:                     # nothing found anywhere → 404
            return jsonify(status='not_found'), 404

        rev = 'in' if r['direction'] == 'out' else 'out'
        cur = c.execute("""
          INSERT INTO inventory_entries(
            category_id, raw_name, sanitized_name,
            weight_per_unit, quantity, total_weight,
            direction, timestamp, pending, pending_ts,
            session_id, source
          ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
          r['category_id'], r['sanitized_name'], r['sanitized_name'],
          r['weight_per_unit'], r['quantity'], r['total_weight'],
          rev, now,                     # direction, timestamp
          1,  now,  sid, 'chip-delete'  # ← marked *pending* & linked to session
        ))

        comp_id = cur.lastrowid

        if src_table == 'flight_cargo':
            # NO LONGER delete the snapshot row here—
            # defer any physical rewrite of flight_cargo until the Commit step.
            # c.execute("DELETE FROM flight_cargo WHERE id=?", (fcid,))
            pass
        else:
            # Mark the original inventory row as “rolled back” so it is ignored
            # by stock math but kept for audit-trail purposes.
            c.execute("""
              UPDATE inventory_entries
                 SET pending    = 1,
                     pending_ts = ?,
                     source     = 'chip-deleted'
               WHERE id = ?
            """, (now, fcid))

    return jsonify(status='ok', comp_id=comp_id)

# ─────────────── CSV EXPORT (incoming-messages log) ────────────────
@app.route('/export_csv')
def export_csv():
    """Download all raw Winlink traffic as a CSV file, including remarks."""
    buf   = io.StringIO()
    csv_w = csv.writer(buf)

    # 1) Header now has 12 columns
    csv_w.writerow([
        'Sender','Subject','Body','Timestamp',
        'Tail#','From','To','T/O','ETA','Cargo','Weight','Remarks'
    ])

    with sqlite3.connect(DB_FILE) as c:
        # 2) Pull the remarks column as the final field
        rows = c.execute("""
            SELECT
              sender, subject, body, timestamp,
              tail_number, airfield_takeoff, airfield_landing,
              takeoff_time, eta, cargo_type, cargo_weight,
              remarks
            FROM incoming_messages
        """)
        for row in rows:
            # row is a tuple of 12 items, so s for s in row works
            csv_w.writerow([
                # flatten any internal line breaks
                s.replace('\r',' ').replace('\n',' ')
                if isinstance(s, str) else s
                for s in row
            ])

    # 3) Stream it back as before
    buf.seek(0)
    return send_file(
        io.BytesIO(buf.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='incoming_messages.csv'
    )

@app.route('/import_csv', methods=['POST'])
def import_csv():
    f = request.files.get('csv_file')
    if not f:
        flash("No file selected for import.", "error")
        return redirect(url_for('preferences'))

    text   = f.read().decode('utf-8', errors='replace')
    rdr    = csv.reader(io.StringIO(text))
    header = [h.strip().lower() for h in next(rdr, [])]
    expected = ['sender','subject','body','timestamp',
                'tail#','from','to','t/o','eta','cargo','weight','remarks']
    if header != expected:
        flash(f"Bad CSV header: {header}", "error")
        return redirect(url_for('preferences'))

    inserted = 0
    # switch to DictReader so we can refer to rec['Remarks']
    dictreader = csv.DictReader(io.StringIO(text), fieldnames=header)
    # skip the header row
    next(dictreader)

    for rec in dictreader:
        # build a parsed record
        p = parse_csv_record({
            'Sender':    rec['sender'],
            'Subject':   rec['subject'],
            'Body':      rec['body'],
            'Timestamp': rec['timestamp'],
            'Tail#':     rec['tail#'],
            'From':      rec['from'],
            'To':        rec['to'],
            'T/O':       rec['t/o'],
            'ETA':       rec['eta'],
            'Cargo':     rec['cargo'],
            'Weight':    rec['weight'],
            'Remarks':   rec['remarks']
        })

        # apply it — this writes to incoming_messages *and* updates/creates a flights row
        fid, action = apply_incoming_parsed(p)
        inserted += 1

    flash(f"Imported and applied {inserted} rows from CSV.", "import")
    # if we came from the Admin console, stay there
    ref = request.referrer or ""
    if ref.endswith(url_for('admin')) or "/admin" in ref:
        return redirect(url_for('admin'))
    return redirect(url_for('preferences'))

# ─────────────── DB RESET (danger - wipes everything) ────────────────
@app.post('/reset_db')
def reset_db():
    """Drop the SQLite file, recreate the schema and run migrations."""
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    init_db()          # recreate empty tables
    run_migrations()   # add all current columns

    # ─── rebuild & reload our airports lookup ────────────────
    ensure_airports_table()
    load_airports_from_csv()
    seed_default_categories()

    flash("Database reset and re-initialised.", "db_reset")
    # if we came from the Admin console, stay there
    ref = request.referrer or ""
    if ref.endswith(url_for('admin')) or "/admin" in ref:
        return redirect(url_for('admin'))
    return redirect(url_for('preferences'))


# ───────────────────────────────────────────────────────────
# First-run setup: pick a password if none exists
@app.route('/setup', methods=['GET','POST'])
@limiter.limit("20 per minute")
def setup():
    if get_app_password_hash():
        return redirect(url_for('login'))

    if request.method == 'POST':
        pw      = request.form.get('password','')
        confirm = request.form.get('confirm','')
        if not pw or pw != confirm:
            flash("Passwords must match", "error")
            return render_template('setup.html', active='setup')
        # store hashed pw & log them in
        set_app_password_hash(generate_password_hash(pw))
        session['logged_in'] = True
        session['session_salt'] = get_session_salt()
        flash("Password set—you're logged in!", "success")
        return redirect(url_for('dashboard'))

    return render_template('setup.html', active='setup')

# ───────────────────────────────────────────────────────────
# Login / logout
@app.route('/login', methods=['GET','POST'])
@limiter.limit("5 per minute")
def login():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        pw = request.form.get('password','')
        if (h := get_app_password_hash()) and check_password_hash(h, pw):
            session['logged_in'] = True
            flash("Logged in successfully.", "success")
            # stamp session salt on successful login
            session['session_salt'] = get_session_salt()
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash("Incorrect password.", "error")

    return render_template('login.html', active='login')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash("Logged out.", "info")
    return redirect(url_for('login'))

# --- preferences route (DB-stored default_origin + cookie prefs) ----------
@app.route('/preferences', methods=['GET', 'POST'])
def preferences():
    """Display / update local-display and ops preferences.

    * default_origin           → stored in SQLite (shared across devices)
    * code_format, mass_unit,
      operator_call(callsign),
      include_test,
      radio_show_unsent_only   → stored per-browser via cookies
    """
    ONE_YEAR = 31_536_000  # seconds

    # ── update prefs ──────────────────────────────────────────────────────
    if request.method == 'POST':

        # ── Unlock / lock admin mode ────────────────────
        if 'admin_passphrase' in request.form:
            entered = request.form['admin_passphrase'].strip()
            if entered == "I solemnly swear that I am up to no good":
                session['admin_unlocked'] = True
                flash("🔓 Admin mode unlocked.", "success")
            else:
                session.pop('admin_unlocked', None)
                flash("❌ Incorrect passphrase.", "error")
            return redirect(url_for('preferences'))

        # ----- DB-backed preference --------------------------------------
        if 'default_origin' in request.form:
            val = escape(request.form['default_origin'].strip().upper())
            with sqlite3.connect(DB_FILE) as c:
                c.execute("""
                    INSERT INTO preferences(name,value)
                    VALUES('default_origin',?)
                    ON CONFLICT(name) DO UPDATE
                    SET value = excluded.value
                """, (val,))

        # ----- cookie-backed prefs ---------------------------------------
        resp = make_response(redirect(url_for('preferences')))

        # existing cookie-backed prefs...
        if 'code_format' in request.form:
            resp.set_cookie(
                'code_format',
                request.form['code_format'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'mass_unit' in request.form:
            resp.set_cookie(
                'mass_unit',
                request.form['mass_unit'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'distance_unit' in request.form:
            resp.set_cookie(
                'distance_unit',
                request.form['distance_unit'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'operator_call' in request.form:  # protect from arbitrary text XSS
            oc = escape(request.form['operator_call'].upper())
            resp.set_cookie(
                'operator_call',
                oc,
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'include_test' in request.form:
            resp.set_cookie(
                'include_test',
                request.form['include_test'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'radio_show_unsent_only' in request.form:
            resp.set_cookie(
                'radio_show_unsent_only',
                request.form['radio_show_unsent_only'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'hide_tbd' in request.form:
            # now a yes/no dropdown → just echo the selected value
            resp.set_cookie(
                'hide_tbd',
                request.form['hide_tbd'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        if 'show_debug_logs' in request.form:
            resp.set_cookie(
                'show_debug_logs',
                request.form['show_debug_logs'],
                max_age=ONE_YEAR,
                samesite='Lax'
            )

        # Dashboard sort‐sequence pref → cookie
        if 'dashboard_sort_seq' in request.form:
            resp.set_cookie('dashboard_sort_seq',
                            request.form['dashboard_sort_seq'],
                            max_age=31_536_000, samesite='Lax')

        flash("Preferences saved", "success")
        return resp

    # ── GET: read current settings ────────────────────────────────────────
    # default_origin from DB
    row = dict_rows("SELECT value FROM preferences WHERE name='default_origin'")
    default_origin = row[0]['value'] if row else ''

    # cookie-backed settings
    current_code    = request.cookies.get('code_format',   'icao4')
    current_mass    = request.cookies.get('mass_unit',     'lbs')
    operator_call   = request.cookies.get('operator_call', '')
    include_test    = request.cookies.get('include_test',  'yes')
    current_debug   = request.cookies.get('show_debug_logs','no')
    current_radio_unsent = request.cookies.get('radio_show_unsent_only','yes')
    hide_tbd        = request.cookies.get('hide_tbd','yes') == 'yes'

    return render_template(
        'preferences.html',
        default_origin=default_origin,
        current_code=current_code,
        current_mass=current_mass,
        operator_call=operator_call,
        include_test=include_test,
        current_debug=current_debug,
        current_radio_unsent=current_radio_unsent,
        sort_seq=request.cookies.get('dashboard_sort_seq','no')=='yes',
        hide_tbd=hide_tbd
    )

# ───────────────────────────────────────────────────────────
#  Admin dashboard - only when unlocked (plus Wargame mode)
# ───────────────────────────────────────────────────────────
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # only session‑backed admin
    if not session.get('admin_unlocked'):
        return redirect(url_for('preferences'))

    if request.method == 'POST':
        # ── Exit Admin Mode ────────────────────────────────
        if 'exit_admin' in request.form:
            session.pop('admin_unlocked', None)
            flash("🔒 Admin mode locked.", "info")
            return redirect(url_for('preferences'))

        # ── Toggle Wargame Mode ────────────────────────────
        if 'toggle_wargame' in request.form:
            on          = (request.form.get('toggle_wargame') == 'on')
            current_on  = (get_preference('wargame_mode') == 'yes')
            if on == current_on:
                flash(f"Wargame mode already {'active' if on else 'off'}. No changes made.", "info")
                return redirect(url_for('admin'))
            set_preference('wargame_mode', 'yes' if on else 'no')

            # List of all tables we want to completely purge on activation/deactivation
            WARGAME_TABLES = [
              'flights',
              'incoming_messages',
              'flight_history',
              'wargame_emails',
              'wargame_metrics',
              'wargame_inbound_schedule',
              'wargame_radio_schedule',
              'wargame_tasks',
              'inventory_entries'
            ]

            if on:
                # 1) wipe live‑ops & wargame state
                with sqlite3.connect(DB_FILE) as c:
                    for tbl in WARGAME_TABLES:
                        c.execute(f"DELETE FROM {tbl}")
                # Ensure schema is current after a wipe
                run_migrations()
                # Reset sequences and seed baseline inventory so requests are satisfiable.
                _reset_autoincrements(WARGAME_TABLES + ['wargame_inventory_batches','wargame_inventory_batch_items','wargame_ramp_requests'])

                # 2) regenerate callsigns and wire up the scheduler
                initialize_airfield_callsigns()
                reset_wargame_state()
                set_wargame_epoch()
                seed_wargame_baseline_inventory()
                configure_wargame_jobs()

                # 3) clear any stale role
                session.pop('wargame_role', None)
                resp = redirect(url_for('wargame_index'))
                # also clear the browser cookie
                resp.delete_cookie('wargame_role', path='/')

                # Invalidate all existing role cookies globally
                bump_wargame_role_epoch()

                flash("🕹️ Wargame mode activated; all live‑ops & Wargame data wiped.", "success")
                return resp

            else:
                # 1) tear down scheduler
                scheduler.remove_all_jobs()

                # 2) purge wargame tables
                with sqlite3.connect(DB_FILE) as c:
                    for tbl in WARGAME_TABLES:
                        c.execute(f"DELETE FROM {tbl}")
                # Keep schema current even when turning Wargame off
                run_migrations()

                # 3) clear any stale cookies
                resp = redirect(url_for('admin'))
                resp.delete_cookie('wargame_emails_read', path='/')
                # Also remove the epoch‑scoped read cookie for the current run
                resp.delete_cookie(f"wargame_emails_read_{get_wargame_epoch()}", path='/')
                resp.delete_cookie('wargame_role',      path='/')
                session.pop('wargame_role', None)

                # Also invalidate roles when turning Wargame off
                bump_wargame_role_epoch()

                flash("🕹️ Wargame mode deactivated; all Wargame data cleared.", "info")
                return resp

        # ── Invalidate Sessions + Clear App Password ───────
        if 'invalidate_sessions' in request.form:
            new_salt = uuid.uuid4().hex
            set_session_salt(new_salt)
            with sqlite3.connect(DB_FILE) as c:
                c.execute("DELETE FROM preferences WHERE name='app_password'")
            flash(
              "🔑 All sessions invalidated and password cleared – " +
              "please set a new password now.",
              "info"
            )
            return redirect(url_for('setup'))

        # ── Change App Password ─────────────────────────────
        if 'change_password' in request.form:
            new_pw     = request.form.get('new_password','')
            confirm_pw = request.form.get('confirm_password','')
            if new_pw and new_pw == confirm_pw:
                set_app_password_hash(generate_password_hash(new_pw))
                flash("Application password updated.", "success")
            else:
                flash("Passwords must match.", "error")
            return redirect(url_for('admin'))

        # ── Clear Embedded‑Tab Settings ────────────────────
        if 'clear_embedded' in request.form:
            clear_embedded_preferences()
            flash("Embedded‑tab removed.", "info")
            return redirect(url_for('admin'))

        # ── Toggle Embedded Mode ─────────────────────────────
        if 'embedded_mode' in request.form:
            mode = request.form.get('embedded_mode')
            set_preference('embedded_mode', mode)
            flash(f"Embedded mode set to {mode}.", "info")
            return redirect(url_for('admin'))

        # ── Save Embedded‑Tab URL / Name / Distances Flag ──
        if any(k in request.form for k in ('embedded_url','embedded_name','embedded_mode','enable_1090_distances')):
            url  = request.form.get('embedded_url','').strip()
            name = request.form.get('embedded_name','').strip()
            if url and name:
                # persist mode
                set_preference('embedded_mode', request.form.get('embedded_mode','iframe'))
                set_preference('embedded_url', url)
                set_preference('embedded_name', name)
                set_preference(
                  'enable_1090_distances',
                   'yes' if request.form.get('enable_1090_distances')=='on' else 'no'
                )
                flash("Embedded‑tab settings saved.", "info")
            else:
                flash("Both URL and label are required.", "error")
            return redirect(url_for('admin'))

        # ── Update Default Origin (still in both Admin & Preferences) ──
        if 'default_origin' in request.form:
            val = escape(request.form['default_origin'].strip().upper())
            set_preference('default_origin', val)

        # ── Show Debug Logs cookie ─────────────────────────
        resp = make_response(redirect(url_for('admin')))
        if 'show_debug_logs' in request.form:
            resp.set_cookie(
              'show_debug_logs',
              request.form['show_debug_logs'],
              max_age=ONE_YEAR,
              samesite='Lax'
            )
        flash("Admin settings saved.", "info")
        return resp

    # ── GET: fetch current settings ─────────────────────────────
    default_origin        = get_preference('default_origin') or ''
    show_debug_logs       = request.cookies.get('show_debug_logs','no')
    wargame_mode          = get_preference('wargame_mode') == 'yes'
    embedded_url          = get_preference('embedded_url') or ''
    embedded_name         = get_preference('embedded_name') or ''
    embedded_mode         = get_preference('embedded_mode') or 'iframe'
    enable_1090_distances = get_preference('enable_1090_distances') == 'yes'

    return render_template(
      'admin.html',
      active='admin',
      default_origin=default_origin,
      show_debug_logs=show_debug_logs,
      wargame_mode=wargame_mode,
      embedded_url=embedded_url,
      embedded_name=embedded_name,
      embedded_mode=embedded_mode,
      enable_1090_distances=enable_1090_distances
    )

@app.route('/wargame')
def wargame_index():
    # 1) ensure wargame mode is active
    wm = dict_rows("SELECT value FROM preferences WHERE name='wargame_mode'")
    if not (wm and wm[0]['value'] == 'yes'):
        return redirect(url_for('dashboard'))

    # 2) have they already chosen a role?
    server_epoch = get_wargame_role_epoch()
    role         = request.cookies.get('wargame_role')
    role_epoch   = request.cookies.get('wargame_role_epoch')
    if (not role) or (role_epoch != server_epoch):
        # fetch supervisor’s last‐saved settings
        row = dict_rows(
            "SELECT value FROM preferences WHERE name='wargame_settings'"
        )
        settings = json.loads(row[0]['value'] or '{}') if row else {}
        # clear any stale role for this client
        session.pop('wargame_role', None)
        resp = make_response(render_template('wargame_choose_role.html', settings=settings))
        resp.delete_cookie('wargame_role', path='/')
        return resp

    # 3) if they have a role, send them to their dashboard
    return redirect(url_for(f"wargame_{role}_dashboard"))

@app.route('/wargame/choose_role', methods=['POST'])
def wargame_choose_role():
    """Handle the initial Wargame Role selection (and, if Supervisor, save settings)."""
    role = request.form.get('role')
    allowed = ['radio', 'ramp', 'inventory', 'super']
    if role not in allowed:
        flash("Invalid Wargame role selected.", "error")
        return redirect(url_for('wargame'))

    # If the Exercise Supervisor picked this role, capture all extra settings
    if role == 'super':
        settings = {k: v for k, v in request.form.items() if k != 'role'}
        # Normalize toggles: if absent, treat as 'no'
        for k in ('radio_use_batch', 'radio_count_batch'):
            settings[k] = 'yes' if settings.get(k) == 'yes' else 'no'
        with sqlite3.connect(DB_FILE) as c:
            c.execute("""
              INSERT INTO preferences(name, value)
              VALUES('wargame_settings', ?)
              ON CONFLICT(name) DO UPDATE SET value=excluded.value
            """, (json.dumps(settings),))
        # now tear down & rebuild *all* rate-based jobs with the new settings
        apply_supervisor_settings()

    session['wargame_role'] = role
    resp = make_response(redirect(url_for(f"wargame_{role}_dashboard")))
    resp.set_cookie('wargame_role', role, max_age=ONE_YEAR, samesite='Lax')
    # carry the current epoch so we can invalidate on the next recycle
    resp.set_cookie('wargame_role_epoch', get_wargame_role_epoch(), max_age=ONE_YEAR, samesite='Lax')
    return resp

@app.post('/wargame/exit_role')
def wargame_exit_role():
    """Clear this client’s role cookie/session and send them to the chooser."""
    session.pop('wargame_role', None)
    resp = make_response(redirect(url_for('wargame_index')))
    resp.delete_cookie('wargame_role', path='/')
    # do not touch the epoch cookie; it’s used for global invalidation
    flash("You’ve exited your Wargame role. Please choose a new role.", "info")
    return resp

# ───────────────────────────────────────────────────────────
#  WARGAME: Radio Operator Inbox
# ───────────────────────────────────────────────────────────
@app.route('/wargame/radio')
def wargame_radio_dashboard():
    # 1) ensure wargame mode
    wm = dict_rows("SELECT value FROM preferences WHERE name='wargame_mode'")
    if not (wm and wm[0]['value']=='yes'):
        return redirect(url_for('dashboard'))

    # only the “radio” role may visit; everyone else bounces to /wargame
    if session.get('wargame_role') != 'radio':
        return redirect(url_for('wargame_index'))

    # 2) fetch all generated e‑mails, newest first
    emails = dict_rows("""
      SELECT id, generated_at, message_id, size_bytes,
             source, sender, recipient, subject
        FROM wargame_emails
       ORDER BY generated_at DESC
    """)

    # 3) determine “read” state from an epoch‑namespaced cookie bitmask
    epoch = get_wargame_epoch()
    cookie_name = f"wargame_emails_read_{epoch}"
    seen = request.cookies.get(f"wargame_emails_read_{epoch}", '')  # e.g. "1,4,7"
    seen_ids = set(int(i) for i in seen.split(',') if i.isdigit())
    for e in emails:
        e['read'] = (e['id'] in seen_ids)

    return render_template(
        'wargame_radio.html',
        emails=emails,
        epoch=epoch,                # stable across the Wargame session
        active='wargame'
    )

# ───────────────────────────────────────────────────────────
#  WARGAME: Ramp Boss “Cue Cards”
# ───────────────────────────────────────────────────────────
@app.route('/wargame/ramp')
def wargame_ramp_dashboard():
    wm = dict_rows("SELECT value FROM preferences WHERE name='wargame_mode'")
    if not (wm and wm[0]['value']=='yes'):
        return redirect(url_for('dashboard'))

    # only the “ramp” role may visit; everyone else bounces to /wargame
    if session.get('wargame_role') != 'ramp':
        return redirect(url_for('wargame_index'))

    # Arrivals cue cards: only flights that have been promoted to Ramp (pending task)
    dest = (get_preference('default_origin') or '').strip().upper()
    base_sql = """
      SELECT f.id, f.timestamp, f.tail_number,
             f.airfield_takeoff, f.airfield_landing,
             f.takeoff_time, f.eta, f.cargo_type,
             COALESCE(f.cargo_weight_real,
                      CASE
                        WHEN f.cargo_weight LIKE '%lb%' THEN CAST(REPLACE(REPLACE(f.cargo_weight,' lbs',''),' lb','') AS REAL)
                        ELSE CAST(f.cargo_weight AS REAL)
                      END) AS cargo_weight,
             f.remarks
        FROM flights f
        JOIN wargame_tasks t
          ON t.role='ramp' AND t.kind='inbound' AND t.key='flight:' || f.id
       WHERE f.direction='inbound'
         AND IFNULL(f.is_ramp_entry,0)=0
         AND IFNULL(f.complete,0)=0
    """
    params = ()
    if dest:
        base_sql += " AND UPPER(f.airfield_landing)=?\n"
        params += (dest,)
    base_sql += " ORDER BY t.gen_at ASC, f.id DESC"
    arrivals = dict_rows(base_sql, params)

    # Cargo requests waiting to be satisfied by creating an outbound flight
    raw_reqs = dict_rows("""
      SELECT id, created_at, destination, requested_weight, manifest, assigned_tail
        FROM wargame_ramp_requests
       WHERE satisfied_at IS NULL
       ORDER BY created_at ASC
    """)
    # Shape to match the existing template (field names),
    # coercing any dash‑only placeholders into None and
    # falling back to a new random tail when empty
    requests = []
    for r in raw_reqs:
        tail = blankish_to_none(r.get('assigned_tail')) or generate_tail_number()
        requests.append({
            'timestamp':        r['created_at'],
            'airfield_landing': r['destination'],
            'cargo_weight':     r['requested_weight'],
            'cargo_type':       'Mixed',
            'proposed_tail':    tail,
            'remarks':          r['manifest'] or '—'
        })

    return render_template(
      'wargame_ramp.html',
      arrivals=arrivals,
      requests=requests,
      active='wargame'
    )


# ───────────────────────────────────────────────────────────
#  WARGAME: Inventory Specialist “Cue Cards”
# ───────────────────────────────────────────────────────────
@app.route('/wargame/inventory')
def wargame_inventory_dashboard():
    wm = dict_rows("SELECT value FROM preferences WHERE name='wargame_mode'")
    if not (wm and wm[0]['value']=='yes'):
        return redirect(url_for('dashboard'))

    # only the “inventory” role may visit; everyone else bounces to /wargame
    if session.get('wargame_role') != 'inventory':
        return redirect(url_for('wargame_index'))

    # Pending batches (in/out)
    incoming_deliveries = dict_rows("""
      SELECT id, created_at, manifest
        FROM wargame_inventory_batches
       WHERE direction='in' AND satisfied_at IS NULL
       ORDER BY created_at ASC
    """)
    outgoing_requests = dict_rows("""
      SELECT id, created_at, manifest
        FROM wargame_inventory_batches
       WHERE direction='out' AND satisfied_at IS NULL
       ORDER BY created_at ASC
    """)
    def lines_for(bid):
        return dict_rows("""
          SELECT name, size_lb, qty_required, qty_done
            FROM wargame_inventory_batch_items
           WHERE batch_id=?
        """, (bid,))

    return render_template(
      'wargame_inventory.html',
      incoming_deliveries=[{**b, 'lines': lines_for(b['id'])} for b in incoming_deliveries],
      outgoing_requests=[{**b, 'lines': lines_for(b['id'])} for b in outgoing_requests],
      last_inventory_timestamp=last_inventory_update or datetime.utcnow().isoformat(),
      active='wargame'
    )

# ───────────────────────────────────────────────────────────
#  WARGAME: Exercise Supervisor Dashboard
# ───────────────────────────────────────────────────────────
@app.route('/wargame/super')
def wargame_super_dashboard():
    wm = dict_rows("SELECT value FROM preferences WHERE name='wargame_mode'")
    if not (wm and wm[0]['value']=='yes'):
        return redirect(url_for('dashboard'))

    # only the “super” role may visit; everyone else bounces to /wargame
    if session.get('wargame_role') != 'super':
        return redirect(url_for('wargame_index'))

    # 1) per‑role delay metrics
    metrics = {}
    for role in ('radio','ramp','inventory'):
        row = dict_rows(f"""
            SELECT
              AVG(delta_seconds) AS avg,
              MIN(delta_seconds) AS min,
              MAX(delta_seconds) AS max
            FROM wargame_metrics
           WHERE event_type=?
        """, (role,))[0]
        metrics[role] = {
          'avg': round(row['avg'] or 0,2),
          'min': row['min'] or 0,
          'max': row['max'] or 0
        }

    # 2) throughput over the past hour
    cutoff = (datetime.utcnow() - timedelta(hours=1)).isoformat()

    # 2a) ramp boss entries in the last hour (all inbound & outbound)
    frow = dict_rows("""
      SELECT COUNT(*) AS cnt
        FROM flights
       WHERE is_ramp_entry=1
         AND timestamp >= ?
    """, (cutoff,))[0]
    aircraft_entries_per_hour = frow['cnt'] or 0

    # 2b) total cargo weight entered by ramp boss in the last hour
    crow = dict_rows("""
      SELECT SUM(
               COALESCE(cargo_weight_real,
                        CASE
                          WHEN cargo_weight LIKE '%lb%' THEN CAST(REPLACE(REPLACE(cargo_weight,' lbs',''),' lb','') AS REAL)
                          ELSE CAST(cargo_weight AS REAL)
                        END)
             ) AS sum_wt
        FROM flights
       WHERE is_ramp_entry=1
         AND timestamp >= ?
    """, (cutoff,))[0]
    air_cargo_entries_per_hour = round(crow['sum_wt'] or 0, 1)

    stats = {
      'aircraft_entries_per_hour': aircraft_entries_per_hour,
      'air_cargo_entries_per_hour': air_cargo_entries_per_hour
    }

    # 3) read‑only difficulty settings
    js = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
    settings = json.loads(js[0]['value']) if js else {}

    return render_template(
      'wargame_super.html',
      metrics=metrics,
      stats=stats,
      settings=settings,
      active='wargame'
    )

# ───────────────────────────────────────────────────────────
# WARGAME: Inventory “last update” poll endpoint
@app.route('/wargame/inventory/last_update')
def wargame_inventory_last_update():
    """Return the ISO timestamp of the last inventory change for Wargame clients."""
    ts = last_inventory_update or datetime.utcnow().isoformat()
    return jsonify(timestamp=ts)

@app.route('/embedded')
@limiter.exempt
def embedded():
    # read the two prefs
    url  = dict_rows("SELECT value FROM preferences WHERE name='embedded_url'")
    name = dict_rows("SELECT value FROM preferences WHERE name='embedded_name'")
    embedded_url  = url[0]['value']  if url  else ''
    embedded_name = name[0]['value'] if name else ''

    # nothing to embed? send back home
    if not (embedded_url and embedded_name):
        return redirect(url_for('dashboard'))

    mode = get_preference('embedded_mode') or 'iframe'
    template = mode == 'proxy' and 'embedded.html' or 'embedded-iframe.html'

    return render_template(
        template,
        url=embedded_url,
        active='embedded',
        embedded_name=embedded_name
    )

@inventory_bp.route('/')
def inventory_overview():
    cutoff = (datetime.utcnow() - timedelta(hours=2)).isoformat()
    overview = []
    for c in dict_rows("SELECT id,display_name FROM inventory_categories"):
        ents = dict_rows(
            "SELECT direction,total_weight,timestamp FROM inventory_entries WHERE category_id=?",
            (c['id'],)
        )
        tot_in  = sum(e['total_weight'] for e in ents if e['direction']=='in')
        tot_out = sum(e['total_weight'] for e in ents if e['direction']=='out')
        recent  = [e for e in ents if e['timestamp'] >= cutoff]
        in2h    = sum(e['total_weight'] for e in recent if e['direction']=='in')
        out2h   = sum(e['total_weight'] for e in recent if e['direction']=='out')
        overview.append({
            'category':  c['display_name'],
            'total_in':  tot_in,
            'total_out': tot_out,
            'net':       tot_in - tot_out,
            'rate_in':   in2h  / 2,
            'rate_out':  out2h / 2
        })
    # apply user’s mass‐unit preference (cookie from /preferences)
    mass_pref = request.cookies.get('mass_unit','lbs')
    if mass_pref == 'kg':
        for item in overview:
            # stored totals are in pounds → convert to kg
            item['total_in']  = round(item['total_in']  / 2.20462, 1)
            item['total_out'] = round(item['total_out'] / 2.20462, 1)
            item['net']       = round(item['net']       / 2.20462, 1)
            item['rate_in']   = round(item['rate_in']   / 2.20462, 1)
            item['rate_out']  = round(item['rate_out']  / 2.20462, 1)
    # pass skeleton page only; table will come from AJAX
    return render_template(
        'inventory_overview.html',
        active='inventory'
    )

# ─────────── Manage Inventory Categories ───────────
@inventory_bp.route('/categories', methods=('GET','POST'))
def inventory_categories():
    """List existing categories and let you add new ones (use sparingly!)."""
    if request.method == 'POST':
        # pull and normalize inputs
        name    = request.form['name'].strip().lower()
        display = request.form['display_name'].strip()
        with sqlite3.connect(DB_FILE) as c:
            c.execute("""
              INSERT INTO inventory_categories(name, display_name)
              VALUES(?,?)
            """, (name, display))
        flash("Category added.", "success")
        return redirect(url_for('inventory.inventory_categories'))

    cats = dict_rows("""
      SELECT id, name, display_name
        FROM inventory_categories
       ORDER BY display_name
    """)
    return render_template(
        'inventory_categories.html',
        categories=cats,
        active='inventory'
    )

@inventory_bp.route('/_overview_table')
def inventory_overview_table():
    """AJAX partial: just the <table> for overview."""
    cutoff = (datetime.utcnow() - timedelta(hours=2)).isoformat()
    overview = []
    for c in dict_rows("SELECT id,display_name FROM inventory_categories"):
        ents = dict_rows(
            "SELECT direction,total_weight,timestamp FROM inventory_entries WHERE category_id=?",
            (c['id'],)
        )
        tot_in  = sum(e['total_weight'] for e in ents if e['direction']=='in')
        tot_out = sum(e['total_weight'] for e in ents if e['direction']=='out')
        recent  = [e for e in ents if e['timestamp'] >= cutoff]
        in2h    = sum(e['total_weight'] for e in recent if e['direction']=='in')
        out2h   = sum(e['total_weight'] for e in recent if e['direction']=='out')
        overview.append({
            'category':  c['display_name'],
            'total_in':  tot_in,
            'total_out': tot_out,
            'net':       tot_in - tot_out,
            'rate_in':   in2h  / 2,
            'rate_out':  out2h / 2
        })
    # apply user’s mass‐unit preference
    mass_pref = request.cookies.get('mass_unit','lbs')
    if mass_pref == 'kg':
        for row in overview:
            for key in ('total_in','total_out','net','rate_in','rate_out'):
                row[key] = round(row[key] / 2.20462, 1)

    return render_template(
        'partials/_inventory_overview_table.html',
        inventory=overview,
        mass_pref=mass_pref
    )

@inventory_bp.route('/detail', methods=('GET','POST'))
def inventory_detail():
    if request.method=='POST':

        cat_id = int(request.form['category'])
        raw = request.form['name']
        noun = sanitize_name(raw)
        weight_val = float(request.form['weight'] or 0)
        weight_unit = request.form.get('weight_unit', 'lbs')
        session['inv_weight_unit'] = weight_unit
        if weight_unit == 'kg':
            wpu_lbs = kg_to_lbs(weight_val)
        else:
            wpu_lbs = weight_val
        qty = int(request.form['qty'] or 0)
        total_lbs = wpu_lbs * qty
        dirn = request.form['direction']
        session['inv_direction'] = dirn
        ts = datetime.utcnow().isoformat()

        # ── enforce no‐overdraw on OUTBOUND ─────────────────────────────────
        if dirn == 'out':
            # re‐compute on‐hand in DB
            row = dict_rows("""
              SELECT
                COALESCE(SUM(
                  CASE WHEN direction='in'  THEN  quantity
                       WHEN direction='out' THEN -quantity
                  END
                ), 0) AS avail
              FROM inventory_entries
             WHERE (pending IS NULL OR pending=0)
               AND category_id=?
               AND sanitized_name=?
               AND ABS(weight_per_unit - ?) < 0.001
            """, (cat_id, noun, wpu_lbs))[0]
            on_hand = row['avail']

            # reject if they asked for more than exists
            if qty > on_hand:
                msg = f'Cannot exceed available qty ({on_hand})'
                # AJAX path
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'message': msg}), 400

                # full‐page path: flash + re‐render
                flash(msg, 'error')
                # rebuild form context & advanced_data for the template
                categories = dict_rows("SELECT id, display_name FROM inventory_categories")
                # ── build advanced_data exactly as the template expects ──
                cats = dict_rows("""
                  SELECT id AS cid, display_name AS cname
                    FROM inventory_categories
                   ORDER BY display_name
                """)
                advanced_data = {
                  "all_categories": [
                    {"id": str(c["cid"]), "display_name": c["cname"]} for c in cats
                  ],
                  "stock_categories": [],
                  "items": {}, "sizes": {}, "avail": {}
                }
                rows = dict_rows("""
                  SELECT category_id AS cid,
                         sanitized_name,
                         weight_per_unit,
                         SUM(
                           CASE WHEN direction='in'  THEN quantity
                                WHEN direction='out' THEN -quantity
                           END
                         ) AS qty
                    FROM inventory_entries
                   WHERE pending=0
                   GROUP BY category_id, sanitized_name, weight_per_unit
                   HAVING qty>0
                """)
                for r in rows:
                    cid = str(r["cid"])
                    # availability
                    advanced_data["avail"].setdefault(cid, {})\
                         .setdefault(r["sanitized_name"], {})[str(r["weight_per_unit"])] = r["qty"]
                    # set up items & sizes
                    advanced_data["items"].setdefault(cid, []).append(r["sanitized_name"])
                    advanced_data["sizes"].setdefault(cid, {})\
                         .setdefault(r["sanitized_name"], []).append(str(r["weight_per_unit"]))
                    # record stock-only categories
                    if not any(c["id"] == cid for c in advanced_data["stock_categories"]):
                        name = next((c["cname"] for c in cats if str(c["cid"]) == cid), "")
                        advanced_data["stock_categories"].append({
                          "id": cid, "display_name": name
                        })
                return render_template(
                    'inventory_detail.html',
                    initial_direction=session.get('inv_direction','inbound'),
                    categories=categories,
                    inv_weight_unit=session.get('inv_weight_unit', request.cookies.get('mass_unit','lbs')),
                    active='inventory',
                    advanced_data=advanced_data,
                    form_data=request.form  # you can use these to pre-fill your template
                )

        with sqlite3.connect(DB_FILE) as c:
            cur = c.execute("""
              INSERT INTO inventory_entries(
                category_id,raw_name,sanitized_name,
                weight_per_unit,quantity,total_weight,
                direction,timestamp
              ) VALUES (?,?,?,?,?,?,?,?)
            """, (cat_id, raw, noun, wpu_lbs, qty, total_lbs, dirn, ts))
            eid = cur.lastrowid

        # If Wargame is active, immediately reconcile this single entry
        # so Wargame Inventory cue cards reflect progress (strikethroughs).
        try:
            if get_preference('wargame_mode') == 'yes':
                reconcile_inventory_entry(int(eid))
        except Exception:
            # never block the operator’s flow on reconciliation issues
            pass

        # Notify live Wargame Inventory dashboards to refresh (SSE)
        try:
            publish_inventory_event()
        except Exception:
            pass

        return redirect(url_for('inventory.inventory_detail'))

    # build categories + advanced_data for the initial GET render
    categories = dict_rows("SELECT id, display_name FROM inventory_categories")
    cats = dict_rows("""
      SELECT id AS cid, display_name AS cname
        FROM inventory_categories
       ORDER BY display_name
    """)
    advanced_data = {
      "all_categories": [
        {"id": str(c["cid"]), "display_name": c["cname"]} for c in cats
      ],
      "stock_categories": [],
      "items": {}, "sizes": {}, "avail": {}
    }
    rows = dict_rows("""
      SELECT category_id AS cid,
             sanitized_name,
             weight_per_unit,
             SUM(
               CASE WHEN direction='in'  THEN quantity
                    WHEN direction='out' THEN -quantity
               END
             ) AS qty
        FROM inventory_entries
       WHERE pending=0
       GROUP BY category_id, sanitized_name, weight_per_unit
       HAVING qty>0
    """)
    for r in rows:
        cid = str(r["cid"])
        advanced_data["avail"].setdefault(cid, {})\
             .setdefault(r["sanitized_name"], {})[str(r["weight_per_unit"])] = r["qty"]
        advanced_data["items"].setdefault(cid, []).append(r["sanitized_name"])
        advanced_data["sizes"].setdefault(cid, {})\
             .setdefault(r["sanitized_name"], []).append(str(r["weight_per_unit"]))
        if not any(c["id"] == cid for c in advanced_data["stock_categories"]):
            name = next((c["cname"] for c in cats if str(c["cid"]) == cid), "")
            advanced_data["stock_categories"].append({
              "id": cid, "display_name": name
            })

    # Fetch everything for display
    entries    = dict_rows("""
      SELECT e.id,c.display_name AS category,
             e.raw_name,e.sanitized_name,
             e.weight_per_unit,e.quantity,
             e.total_weight,e.direction,e.timestamp
        FROM inventory_entries e
        JOIN inventory_categories c ON c.id=e.category_id
       ORDER BY e.timestamp DESC
    """)

    # apply mass-unit preference and prepare view-fields
    mass_pref = request.cookies.get('mass_unit','lbs')
    inv_unit  = session.get('inv_weight_unit', mass_pref)

    for e in entries:
        if mass_pref == 'kg':
            e['weight_view'] = round_half_kg(e['weight_per_unit'] / 2.20462)
            e['total_view']  = round_half_kg(e['total_weight']    / 2.20462)
        else:
            e['weight_view'] = e['weight_per_unit']
            e['total_view']  = e['total_weight']

    # render skeleton; entries come from AJAX
    return render_template(
        'inventory_detail.html',
        categories=categories,
        inv_weight_unit=session.get('inv_weight_unit',
                                    request.cookies.get('mass_unit','lbs')),
        active='inventory',
        advanced_data=advanced_data
    )

# ───────────────────────── STOCK (collapsed summary) ─────────────────────────
@inventory_bp.route('/stock')
def inventory_stock():
    """
    “What’s on the shelf right now” view – grouped by category, collapsed by
    default.  Inside each category the rows are already ordered by
    sanitized name then package size (small→large).
    """
    rows = dict_rows("""
      SELECT c.display_name AS category,
             e.sanitized_name      AS noun,
             e.weight_per_unit     AS wpu,
             SUM(CASE
                   WHEN e.direction='in'  THEN  e.quantity
                   WHEN e.direction='out' THEN -e.quantity
                 END)               AS qty
        FROM inventory_entries e
        JOIN inventory_categories c ON c.id = e.category_id
       WHERE e.pending = 0
       GROUP BY e.category_id, e.sanitized_name, e.weight_per_unit
       HAVING qty > 0
       ORDER BY c.display_name, e.sanitized_name, e.weight_per_unit
    """)

    stock = {}
    for r in rows:
        cat = r['category']
        entry = {
          'noun' : r['noun'],
          'size' : r['wpu'],
          'qty'  : r['qty'],
          'total': r['wpu'] * r['qty']
        }
        stock.setdefault(cat, []).append(entry)

    # honour kg / lbs preference
    mass_pref = request.cookies.get('mass_unit','lbs')
    if mass_pref == 'kg':
        for items in stock.values():
            for ent in items:
                ent['size']  = round(ent['size']  / 2.20462, 1)
                ent['total'] = round(ent['total'] / 2.20462, 1)

    return render_template(
        'inventory_stock.html',
        stock     = stock,
        mass_pref = mass_pref,
        active    = 'inventory'
    )

@inventory_bp.route('/_detail_table')
def inventory_detail_table():
    """AJAX partial: table of recent inventory entries."""
    entries = dict_rows("""
      SELECT e.id, c.display_name AS category,
             e.raw_name, e.sanitized_name,
             e.weight_per_unit, e.quantity,
             e.total_weight, e.direction, e.timestamp
        FROM inventory_entries e
        JOIN inventory_categories c ON c.id=e.category_id
       ORDER BY e.timestamp DESC
    """)
    mass_pref = request.cookies.get('mass_unit','lbs')
    if mass_pref=='kg':
        for e in entries:
            e['weight_per_unit'] = round(e['weight_per_unit']/2.20462, 1)
            e['total_weight']    = round(e['total_weight']/2.20462,    1)

    return render_template(
        'partials/_inventory_detail_table.html',
        entries=entries,
        mass_pref=mass_pref
    )

# ──────────── Edit Inventory Entry ────────────
@inventory_bp.route('/edit/<int:entry_id>', methods=('GET','POST'))
def inventory_edit(entry_id):
    # load categories & the entry
    categories = dict_rows("SELECT id,display_name FROM inventory_categories")
    rows = dict_rows("SELECT * FROM inventory_entries WHERE id=?", (entry_id,))
    if not rows:
        flash("Entry not found.", "error")
        return redirect(url_for('inventory.inventory_detail'))
    entry = rows[0]

    if request.method=='POST':
        raw         = request.form['name']
        noun        = sanitize_name(raw)
        weight_val  = float(request.form['weight'] or 0)
        weight_unit = request.form['weight_unit']
        # normalize to lbs
        wpu = kg_to_lbs(weight_val) if weight_unit=='kg' else weight_val
        qty         = int(request.form['qty'] or 0)
        total       = wpu * qty
        dirn        = request.form['direction']
        # persist
        with sqlite3.connect(DB_FILE) as c:
            c.execute("""
              UPDATE inventory_entries
                 SET category_id=?,
                     raw_name=?, sanitized_name=?,
                     weight_per_unit=?, quantity=?, total_weight=?, direction=?
               WHERE id=?
            """, (
              int(request.form['category']),
              raw, noun,
              wpu, qty, total,
              dirn,
              entry_id
            ))
        return redirect(url_for('inventory.inventory_detail'))

    return render_template(
        'inventory_edit.html',
        entry=entry,
        categories=categories,
        inv_weight_unit=session.get(
           'inv_weight_unit',
           request.cookies.get('mass_unit','lbs')
        ),
        active='inventory'
    )

# ───────────── Delete Inventory Entry ─────────────
@inventory_bp.route('/delete/<int:entry_id>', methods=('POST',))
def inventory_delete(entry_id):
    """Delete a single inventory entry and return to detail page."""
    with sqlite3.connect(DB_FILE) as c:
        c.execute("DELETE FROM inventory_entries WHERE id = ?", (entry_id,))
    return redirect(url_for('inventory.inventory_detail'))

# register the inventory blueprint
app.register_blueprint(inventory_bp)

last_inventory_update: str | None = None

def publish_inventory_event(data=None):
    """
    Record the time of the last inventory change for polling clients.
    """
    global last_inventory_update
    last_inventory_update = datetime.utcnow().isoformat()

# ───────────────────────────────────────────────────────────
if __name__=="__main__":
    app.run(host='0.0.0.0', port=5150)
