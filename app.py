# app.py — Aircraft Ops Coordination Tool
# =======================================
#  • Ramp-Boss: mandatory Inbound / Outbound, kg→lbs, ICAO storage
#  • Dashboard honours per-browser 3- vs 4-letter preference via cookie
#  • flight_history JSON-safe; CSV export; DB auto-migrate
#  • LAN-only Flask server on :5150

import os, sys, re, sqlite3, threading, time, logging, traceback, importlib, subprocess, json, secrets
from pathlib import Path
from datetime import datetime, timezone, timedelta
import socket, select  # for GPSD client
from functools import lru_cache
from flask import Blueprint, Flask, jsonify, redirect, render_template, session, url_for, current_app, request, g

import flask
from markupsafe import Markup as _Markup
import werkzeug.urls
try:
    # Needed by the url_for compatibility shim
    from werkzeug.routing import BuildError
except Exception:  # ultra-defensive fallback
    class BuildError(Exception): pass
# Compatibility shims must be applied BEFORE anything imports flask_wtf or extensions
if not hasattr(flask, "Markup"):
    Markup = _Markup
if not hasattr(werkzeug.urls, "url_encode"):
    werkzeug.urls.url_encode = werkzeug.urls.urlencode
from flask_wtf.csrf import CSRFProtect, CSRFError
# Rate limiting removed - all devices behind NAT share one IP bucket
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
from zeroconf import Zeroconf
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import STATE_RUNNING

# ──────────────────────────────────────────────────────────────────────────────
# Path safety: ensure /app (this file’s dir) is importable as a top-level package
_here = os.path.dirname(__file__)
if _here and _here not in sys.path:
    sys.path.insert(0, _here)

# ──────────────────────────────────────────────────────────────────────────────
# Early constants & globals that submodules may reference during import

# Define DB_FILE *before* importing modules that might pull it in
DB_FILE = os.path.join(os.path.dirname(__file__), "data", "aircraft_ops.db")
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)

# Cookie lifetime convenience (shared across routes) — define EARLY to avoid circulars
ONE_YEAR = 31_536_000  # seconds

# Inventory change ticker used by wargame clients polling
last_inventory_update: str | None = None
def publish_inventory_event(data=None):
    global last_inventory_update
    last_inventory_update = datetime.utcnow().isoformat()

# Scheduler/locks used by routes/services on import
scheduler = BackgroundScheduler()
_CONFIGURE_WG_LOCK = threading.Lock()

# This blueprint exists before inventory subroutes import and attach to it
inventory_bp = Blueprint('inventory', __name__, url_prefix='/inventory')

# ──────────────────────────────────────────────────────────────────────────────
# Logging & SQL trace plumbing
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

SQL_TRACE           = os.getenv("SQL_TRACE", "0") == "1"
SQL_TRACE_ALL       = os.getenv("SQL_TRACE_ALL", "0") == "1"
SQL_TRACE_EXPANDED  = os.getenv("SQL_TRACE_EXPANDED", "0") == "1"
SLOW_MS             = float(os.getenv("SQL_SLOW_MS", "50"))
LOG_LEVEL           = os.getenv("LOG_LEVEL", "INFO").upper()
_SKIP_RE_S          = os.getenv("SQL_TRACE_SKIP_RE", "")
_SKIP_RE            = re.compile(_SKIP_RE_S) if _SKIP_RE_S else None

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
        stream=sys.stdout,
    )

def tame_third_party_logs() -> None:
    """
    Reduce noise from third-party libraries used during PDF generation and scheduling,
    without altering the application's own logger level.
    """
    # WeasyPrint "Ignored ..." CSS warnings → keep only errors
    logging.getLogger('weasyprint').setLevel(logging.ERROR)

    # FontTools chatty DEBUG/INFO during subsetting → raise to WARNING
    logging.getLogger('fontTools').setLevel(logging.WARNING)
    logging.getLogger('fontTools.ttLib').setLevel(logging.WARNING)
    logging.getLogger('fontTools.subset').setLevel(logging.WARNING)

    # APScheduler “job executed successfully” every minute → raise to WARNING
    logging.getLogger('apscheduler').setLevel(logging.WARNING)
    logging.getLogger('apscheduler.executors.default').setLevel(logging.WARNING)

    # Optional if you want less werkzeug noise in production:
    # logging.getLogger('werkzeug').setLevel(logging.WARNING)

# Quiet noisy third-party libraries without changing your app log level.
try:
    tame_third_party_logs()
except Exception as _e:
    logging.getLogger(__name__).debug("logging tamer failed: %s", _e)

_sql_logger = logging.getLogger("sql")
if not _sql_logger.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s:%(name)s: %(message)s"))
    _h.setLevel(logging.DEBUG if SQL_TRACE else getattr(logging, LOG_LEVEL, logging.INFO))
    _sql_logger.addHandler(_h)
    _sql_logger.propagate = False
_sql_logger.setLevel(logging.DEBUG if SQL_TRACE else logging.WARNING)
_sql_logger.debug("SQL tracing %s (SLOW_MS=%s)", "ENABLED" if SQL_TRACE else "disabled", SLOW_MS)

# Guarded capture of original sqlite3.connect
if not hasattr(sqlite3, "_original_connect"):
    sqlite3._original_connect = sqlite3.connect

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

# ──────────────────────────────────────────────────────────────────────────────
# Import module utilities (after DB_FILE is defined)
from modules.utils.common import (
    connect,
    _mmss,
    register_mdns,
    dict_rows,
    init_db,
    run_migrations,
    ensure_airports_table,
    load_airports_from_csv,
    seed_default_categories,
    format_airport,
    fmt_airport,
    clear_airport_cache,
    get_preference,
    # request-cycle helpers (live in modules/utils/common.py)
    require_login,
    refresh_user_cookies,
    _cleanup_before_view,
    _ensure_wargame_scheduler_once,
    _start_radio_tx_once,
    maybe_start_distances,
)

from modules.utils.comms import ensure_comms_tables
from modules.utils.staff import ensure_staff_tables

# Replace sqlite3.connect with the wrapped/traced one exported by modules.utils.common
sqlite3.connect = connect

# ──────────────────────────────────────────────────────────────────────────────
# Flask app + CSRF + Rate limits
app = Flask(__name__)

# Generate a fresh BOOT_ID each time the process/container starts (or honor an override)
app.config["BOOT_ID"] = os.getenv("AOCT_BOOT_ID") or secrets.token_hex(8)

# Server-side once-per-boot sentinel directory
SENTINEL_DIR = Path("/tmp/aoct-sentinels")
SENTINEL_DIR.mkdir(parents=True, exist_ok=True)

# Expose BOOT_ID to all templates
@app.context_processor
def _inject_boot_id():
    return {"BOOT_ID": current_app.config.get("BOOT_ID")}

# Install the Delivery-Truck spawner job at startup (safe to call multiple times)
try:
    from modules.services.jobs import configure_wargame_truck_spawner_job
    configure_wargame_truck_spawner_job(app)
except Exception as _e:
    logging.getLogger(__name__).debug("truck spawner configure failed: %s", _e)

# ──────────────────────────────────────────────────────────────────────────────
# Time probe / auto-set controls (OFF by default; safe logging only)
AOCT_SET_HOST_TIME       = os.getenv("AOCT_SET_HOST_TIME","0").lower() in ("1","true","yes")
try:
    AOCT_TIME_DRIFT_MS   = int(float(os.getenv("AOCT_TIME_DRIFT_MS","30000")))
except Exception:
    AOCT_TIME_DRIFT_MS   = 30000
try:
    AOCT_TIME_MAX_ADJ_S  = int(float(os.getenv("AOCT_TIME_MAX_ADJUST_SEC","900")))
except Exception:
    AOCT_TIME_MAX_ADJ_S  = 900

# ──────────────────────────────────────────────────────────────────────────────
# GPS time (via gpsd) — prefer GPS when healthy
AOCT_GPS_TIME_ENABLE   = os.getenv("AOCT_GPS_TIME_ENABLE","1").lower() in ("1","true","yes")
AOCT_GPSD_HOST         = os.getenv("AOCT_GPSD_HOST","127.0.0.1")
AOCT_GPSD_PORT         = int(os.getenv("AOCT_GPSD_PORT","2947"))
AOCT_GPS_MIN_MODE      = int(os.getenv("AOCT_GPS_MIN_MODE","2"))   # 2D=2, 3D=3
AOCT_GPS_POLL_SEC      = float(os.getenv("AOCT_GPS_POLL_SEC","1.0"))
AOCT_GPS_CONF_SECS     = float(os.getenv("AOCT_GPS_CONF_SECS","3.0"))  # require this many consecutive good TPV seconds
AOCT_GPS_EPT_MAX_S     = float(os.getenv("AOCT_GPS_EPT_MAX_S","0.50"))
AOCT_GPS_REQUIRE_MODE  = os.getenv("AOCT_GPS_REQUIRE_MODE","0").lower() in ("1","true","yes")

# Shared GPS state
_gps_state = {
    "confident": False,          # true when we’ve seen sustained valid TPV (mode>=min) recently
    "last_good_iso": None,       # str ISO 8601 (Z) from TPV.time
    "last_good_dt":  None,       # datetime(UTC)
    "last_seen":     0.0,        # monotonic seconds
    "good_streak":   0.0,        # consecutive seconds of good TPV
    "last_fix_mode": 0,          # 0/1/2/3
}

_GPS_THREAD_STARTED = False
_GPS_LOCK = threading.Lock()

def _now_monotonic():
    try:
        return time.monotonic()
    except Exception:
        return time.time()

def _parse_gpsd_json_line(line: str):
    try:
        obj = json.loads(line)
    except Exception:
        return None, None
    # We only care about TPV reports for time+mode
    if obj.get("class") == "TPV":
        tpv_time = obj.get("time")
        mode     = int(obj.get("mode") or 0)
        ept      = obj.get("ept")  # seconds (float)
        try:
            ept = float(ept) if ept is not None else None
        except Exception:
            ept = None
        return (tpv_time, mode, ept), "TPV"
    return (None, None, None), None

def _set_host_time_if_needed(target_dt_utc: datetime, reason: str) -> tuple[bool,str]:
    """
    Compare host UTC to target UTC and set if drift exceeds AOCT_TIME_DRIFT_MS and within cap.
    Returns (adjusted, message).
    """
    server_utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
    target_dt_utc = target_dt_utc.replace(tzinfo=timezone.utc, microsecond=0)
    delta_ms = int((target_dt_utc - server_utc_dt).total_seconds() * 1000)

    if abs(delta_ms) < AOCT_TIME_DRIFT_MS:
        return False, f"drift {delta_ms}ms < threshold {int(AOCT_TIME_DRIFT_MS)}ms"
    if AOCT_TIME_MAX_ADJ_S > 0 and abs(delta_ms) > AOCT_TIME_MAX_ADJ_S * 1000:
        return False, f"drift {delta_ms}ms exceeds cap AOCT_TIME_MAX_ADJUST_SEC={AOCT_TIME_MAX_ADJ_S}"

    stamp = target_dt_utc.strftime("%Y-%m-%d %H:%M:%S")
    rc = subprocess.run(["date","-u","-s", stamp], capture_output=True, text=True)
    ok = (rc.returncode == 0)
    msg = rc.stdout.strip() or rc.stderr.strip() or "(no message)"
    level = logging.INFO if ok else logging.WARNING
    logger.log(level, "GPS_TIME: set host UTC to %s (rc=%s) via %s; %s",
               target_dt_utc.isoformat().replace("+00:00","Z"), rc.returncode, reason, msg)
    return ok, msg

def _gps_time_thread():
    """
    Minimal gpsd JSON client:
      - connects to gpsd at AOCT_GPSD_HOST:AOCT_GPSD_PORT
      - WATCH enable
      - reads TPV; when mode>=AOCT_GPS_MIN_MODE, treats TPV.time as authoritative UTC
      - after AOCT_GPS_CONF_SECS of consecutive good TPV, marks confident and (optionally) sets host time
    """
    backoff = 1.0
    WATCH = '?WATCH={"enable":true,"json":true}\n'
    while True:
        try:
            with socket.create_connection((AOCT_GPSD_HOST, AOCT_GPSD_PORT), timeout=5.0) as s:
                s.setblocking(False)
                try:
                    s.sendall(WATCH.encode("ascii"))
                except Exception:
                    pass
                backoff = 1.0
                last_tick = _now_monotonic()
                while True:
                    r, _, _ = select.select([s], [], [], AOCT_GPS_POLL_SEC)
                    if not r:
                        # periodic “no data” tick to age confidence
                        now = _now_monotonic()
                        dt = now - last_tick
                        last_tick = now
                        with _GPS_LOCK:
                            _gps_state["good_streak"] = max(0.0, _gps_state["good_streak"] - dt)
                            _gps_state["confident"] = (_gps_state["good_streak"] >= AOCT_GPS_CONF_SECS)
                        continue
                    chunk = s.recv(8192)
                    if not chunk:
                        raise ConnectionError("gpsd closed")
                    for line in chunk.splitlines():
                        try:
                            line_s = line.decode("utf-8","ignore").strip()
                        except Exception:
                            continue
                        (tpv_time, mode, ept), cls = _parse_gpsd_json_line(line_s)
                        now = _now_monotonic()
                        with _GPS_LOCK:
                            _gps_state["last_seen"] = now
                            if mode is not None:
                                _gps_state["last_fix_mode"] = int(mode or 0)
                        # Decide if this TPV conveys trustworthy time:
                        has_time = bool(tpv_time)
                        ept_ok   = (ept is not None and ept <= AOCT_GPS_EPT_MAX_S)
                        mode_ok  = ((mode or 0) >= AOCT_GPS_MIN_MODE) if AOCT_GPS_REQUIRE_MODE else True
                        good_time = has_time and ept_ok and mode_ok

                        if not good_time:
                            # degrade streak
                            with _GPS_LOCK:
                                _gps_state["good_streak"] = max(0.0, _gps_state["good_streak"] - AOCT_GPS_POLL_SEC)
                                _gps_state["confident"] = (_gps_state["good_streak"] >= AOCT_GPS_CONF_SECS)
                            continue
                        # Good TPV with acceptable time accuracy
                        try:
                            # gpsd TPV time is ISO8601 with Z
                            dt_utc = datetime.fromisoformat(tpv_time.replace("Z","+00:00")).astimezone(timezone.utc)
                        except Exception:
                            continue
                        with _GPS_LOCK:
                            _gps_state["last_good_dt"]  = dt_utc
                            _gps_state["last_good_iso"] = dt_utc.isoformat().replace("+00:00","Z")
                            _gps_state["good_streak"]   = min(AOCT_GPS_CONF_SECS + 5.0, _gps_state["good_streak"] + AOCT_GPS_POLL_SEC)
                            became_conf = (not _gps_state["confident"]) and (_gps_state["good_streak"] >= AOCT_GPS_CONF_SECS)
                            _gps_state["confident"] = (_gps_state["good_streak"] >= AOCT_GPS_CONF_SECS)
                            confident = _gps_state["confident"]
                            last_iso  = _gps_state["last_good_iso"]

                        if confident and AOCT_SET_HOST_TIME and dt_utc:
                            _set_host_time_if_needed(dt_utc, reason="GPS")
                        #if became_conf:
                            #logger.info("GPS_TIME: confidence achieved (mode=%s, time=%s)", mode, last_iso)
        except Exception as e:
            logger.warning("GPS_TIME: gpsd stream error: %s (reconnecting in %.1fs)", e, backoff)
            time.sleep(backoff)
            backoff = min(10.0, backoff * 1.5)

def _start_gps_time_once():
    global _GPS_THREAD_STARTED
    if not AOCT_GPS_TIME_ENABLE:
        logger.info("GPS_TIME: disabled via AOCT_GPS_TIME_ENABLE=0")
        return
    if _GPS_THREAD_STARTED:
        return
    t = threading.Thread(target=_gps_time_thread, name="gps-time", daemon=True)
    t.start()
    _GPS_THREAD_STARTED = True
    logger.info("GPS_TIME: background thread started (gpsd %s:%s, min_mode=%s)",
                AOCT_GPSD_HOST, AOCT_GPSD_PORT, AOCT_GPS_MIN_MODE)

# ──────────────────────────────────────────────────────────────────────────────
# On-demand per-request profiler (profiles only when ?__profile=1 is present)
# Writes /tmp/aoct-profiles/req-<path>-<utc>.pstats and logs the filename.
class _ProfileThisRequest:
    def __init__(self, app, outdir="/tmp/aoct-profiles"):
        self.app = app
        self.outdir = outdir
        try:
            os.makedirs(outdir, exist_ok=True)
        except Exception:
            pass

    def __call__(self, environ, start_response):
        qs = environ.get("QUERY_STRING", "")
        want = ("__profile=1" in qs) or (environ.get("HTTP_X_PROFILE", "") == "1")
        if not want:
            return self.app(environ, start_response)

        from datetime import datetime as _dt
        import cProfile, pstats, io, threading

        pr = cProfile.Profile()
        pr.enable()
        app_iter = self.app(environ, start_response)
        chunks = []
        try:
            for chunk in app_iter:
                chunks.append(chunk)
        finally:
            if hasattr(app_iter, "close"):
                try: app_iter.close()
                except Exception: pass
            pr.disable()
            ts = _dt.utcnow().strftime("%Y%m%d-%H%M%S")
            path = (environ.get("PATH_INFO","/").strip("/") or "root").replace("/", "_")
            fname = f"{self.outdir}/req-{path}-{ts}-{threading.get_ident()}.pstats"
            try:
                pr.dump_stats(fname)
                logger.info("PROFILE wrote %s", fname)
            except Exception:
                logger.exception("PROFILE failed to write stats")
        return iter(chunks)

@app.route('/favicon.ico')
def _favicon_redirect():
    # simple redirect so the automatic /favicon.ico request finds your PNG
    return redirect(url_for('static', filename='favicon.png'), code=302)

# --- ensure PAT/WinLink autoconfig on first request ---
try:
    from modules.services.winlink.core import _boot_pat_and_winlink
    if not any(getattr(f, '__name__', '') == '_boot_pat_and_winlink'
               for f in (app.before_request_funcs.get(None) or [])):
        app.before_request(_boot_pat_and_winlink)
except Exception as _e:
    try:
        app.logger.warning("PAT bootstrap not installed: %s", _e)
    except Exception:
        pass

# Always installed; zero overhead unless ?__profile=1 (or header X-Profile: 1)
app.wsgi_app = _ProfileThisRequest(app.wsgi_app)

# Make `import app` resolve to this module before any submodules import it
sys.modules.setdefault('app', sys.modules[__name__])

# Secrets (docker secret → env → dev fallback)
secret = None
secret_file = '/run/secrets/flask_secret'
if os.path.exists(secret_file):
    with open(secret_file) as f:
        secret = f.read().strip()
if not secret:
    secret = os.environ.get('FLASK_SECRET')
if not secret:
    secret = 'dev-secret-please-change'

app.config.update(
    DEBUG=False,
    ENV='production',
    SECRET_KEY=secret,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
    DB_FILE=DB_FILE,
    WTF_CSRF_TIME_LIMIT=10800,  # 3 hours in seconds
)

CSRFProtect(app)
# Rate limiting removed - see field test postmortem
# limiter = Limiter(app, key_func=get_remote_address, default_limits=["1000 per hour"])

# ──────────────────────────────────────────────────────────────────────────────
# CSRF failures → standardize responses for global client handler
@app.errorhandler(CSRFError)
def _handle_csrf_error(e):
    """
    Return a consistent signal for CSRF failures:
      - For XHR/JSON callers: 400 JSON + header X-CSRF-Error: 1
      - For normal form posts / full-page: render session_expired.html (400) + same header
    The client JS in base.html watches for this header and forces a reload.
    """
    try:
        desc = getattr(e, "description", None) or "CSRF token missing or expired."
    except Exception:
        desc = "CSRF token missing or expired."

    wants_json = (
        (request.headers.get("X-Requested-With") == "XMLHttpRequest")
        or ("application/json" in (request.headers.get("Accept") or ""))
    )
    if wants_json:
        resp = jsonify({"ok": False, "error": "csrf", "message": desc})
        resp.status_code = 400
        resp.headers["X-CSRF-Error"] = "1"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # Full-page fallback
    body = render_template("session_expired.html", message=desc)
    headers = {"X-CSRF-Error": "1", "Cache-Control": "no-store"}
    return body, 400, headers

# Jinja filter: seconds -> mm:ss
app.jinja_env.filters['mmss'] = _mmss

# Zeroconf / mDNS
_zeroconf   = Zeroconf()
import modules.utils.common as _common
_common._hydrate_from_app()                 # <-- make zeroconf visible before registering
MDNS_REASON = ""
MDNS_NAME, HOST_IP = register_mdns("rampops", 5150)

# Expose discovered mDNS name + a concrete host:port fallback to templates.
# Keeps your UX: show '---' when the label is truly unknown.
app.config['MDNS_LABEL'] = (MDNS_NAME or "").strip()
app.extensions['mdns_label'] = app.config['MDNS_LABEL']

# ──────────────────────────────────────────────────────────────────────────────
# Template helpers: expose stable mDNS / host labels to every render
@app.context_processor
def _inject_mdns_labels():
    """
    mdns_host_label:     prefer mDNS (name.local:port); fall back to IP:port
    mdns_fallback_label: always IP:port (or ---:port)
    """
    port = 5150

    # Also peek at the values that modules.utils.common might be holding
    try:
        import modules.utils.common as _common
        common_name = (getattr(_common, "MDNS_NAME", "") or "").strip()
        common_ip   = (getattr(_common, "HOST_IP", "") or "").strip()
    except Exception:
        common_name = common_ip = ""

    # Use whichever source actually has a name first.
    raw_name = (MDNS_NAME or common_name or "").strip()

    # Optional override for a *cosmetic* label when registration fails:
    # export AOCT_MDNS_LABEL=rampops (or your desired name) if you want a name to show
    if not raw_name:
        raw_name = (os.getenv("AOCT_MDNS_LABEL", "") or "").strip()

    # Avoid double ".local"
    base = raw_name[:-6] if raw_name.endswith(".local") else raw_name

    # Pick the best IP we know
    ip = (HOST_IP or common_ip or "").strip()

    # Build the two labels
    if base:
        primary = f"{base}.local:{port}"
    elif ip:
        primary = f"{ip}:{port}"
    else:
        primary = f"---:{port}"

    fallback = f"{ip or '---'}:{port}"

    return {
        "mdns_host_label": primary,
        "mdns_fallback_label": fallback,
    }

@app.context_processor
def _inject_preferences_helpers():
    """
    Make get_preference() available inside templates (e.g. preferences.html),
    so tags like {{ get_preference('ramp_scan_adv_manifest') }} work.
    """
    return {"get_preference": get_preference}

@app.context_processor
def _inject_mission_number():
    """
    Expose the current Mission Number (from Preferences) to all templates
    as {{ mission_number }}. Falls back to empty string if unavailable.
    """
    try:
        mn = (get_preference('mission_number') or '').strip()
    except Exception:
        mn = ''
    return {'mission_number': mn}

# Make scheduler available via app.extensions to avoid importing from app in routes
app.extensions['scheduler'] = scheduler

# ──────────────────────────────────────────────────────────────────────────────
# Safe imports + blueprint registration with unique names and clear diagnostics

# Global guards & background starters (implemented in modules.utils.common)
from modules.utils.common import (
    require_login as _require_login,
    maybe_start_distances as _maybe_start_distances,
)

# Fast-lane helper for high-frequency Wargame API endpoints (JSON only)
def _is_wg_fastlane_path(path: str) -> bool:
    try:
        p = (path or "").lower()
    except Exception:
        p = ""
    # Only the chatty JSON endpoints — do NOT include /wargame pages like /wargame/play
    return (
        p.startswith("/api/wargame/")
        or p.startswith("/wargame/pos")
        or p.startswith("/wargame/state")
        or p.startswith("/wargame/players")
        or p.startswith("/wargame/claim")
        or p.startswith("/wargame/cart/")
    )

@app.before_request
def _global_before_request():
    # run one-time initializers BEFORE we might return on auth
    _ensure_wargame_scheduler_once()
    _maybe_start_distances()

    # Fast-lane: skip heavy auth/DB work for Wargame JSON endpoints
    if _is_wg_fastlane_path(request.path):
        g.AUTH_CHECKED = True
        return

    # auth gate (may return a redirect)
    rv = _require_login()
    if rv:
        return rv

    _cleanup_before_view()
    g.AUTH_CHECKED = True

def _safe_import(modpath: str):
    try:
        m = importlib.import_module(modpath)
        logger.info("Imported %s", modpath)
        return m
    except Exception:
        logger.error("FAILED importing %s\n%s", modpath, traceback.format_exc().rstrip())
        return None

def _get_bp(modpath: str, attr: str = "bp"):
    m = _safe_import(modpath)
    return getattr(m, attr, None) if m else None

def _reg(bp, *, name: str):
    # Note: name is the *blueprint name* used internally by Flask's app
    if not bp:
        logger.warning("Skipping blueprint '%s' (missing or failed import)", name)
        return
    app.register_blueprint(bp, name=name)
    logger.info("Registered blueprint name=%s url_prefix=%s", name, getattr(bp, "url_prefix", None))

# ──────────────────────────────────────────────────────────────────────────────
# Global template context for navbar + flags (admin/embedded/wargame/debug/etc.)
@app.context_processor
def _inject_global_nav_flags():
    try:
        embedded_url  = get_preference('embedded_url')  or ''
        embedded_name = get_preference('embedded_name') or ''
        embedded_mode = get_preference('embedded_mode') or 'iframe'
        wargame_mode  = (get_preference('wargame_mode') == 'yes')
        show_debug    = (get_preference('show_debug_logs') == 'yes')
        enable_1090   = (get_preference('enable_1090_distances') == 'yes')
    except Exception:
        embedded_url = embedded_name = ''
        embedded_mode = 'iframe'
        wargame_mode = show_debug = enable_1090 = False

    # Be liberal in what we accept for the session flag name
    admin_unlocked = bool(
        flask.session.get('admin_unlocked')
        or flask.session.get('is_admin')
        or flask.session.get('admin')
    )

    return {
        'embedded_url': embedded_url,
        'embedded_name': embedded_name,
        'embedded_mode': embedded_mode,
        'wargame_mode': wargame_mode,
        'show_debug': show_debug,
        'enable_1090_distances': enable_1090,
        'admin_unlocked': admin_unlocked,
        'current_year': datetime.utcnow().year,
    }

# Inventory subroutes attach to the shared inventory_bp on import
for _mod in (
    "modules.routes_inventory.overview",
    "modules.routes_inventory.categories",
    "modules.routes_inventory.detail",
    "modules.routes_inventory.stock",
    "modules.routes_inventory.barcodes",
    "modules.routes_inventory.scan",
    "modules.routes_inventory.propagate",
    "modules.routes_inventory.requests",
):
    _safe_import(_mod)

# Blueprints that export a `bp`
radio_bp       = _get_bp("modules.routes.radio")
wgradio_bp     = _get_bp("modules.routes.wargame.radio")
help_bp        = _get_bp("modules.routes.help")
wgapi_bp       = _get_bp("modules.routes.wargame_api")
winlink_bp     = _get_bp("modules.routes.winlink")
errors_bp      = _get_bp("modules.routes.errors")
api_bp         = _get_bp("modules.routes.api")
core_bp        = _get_bp("modules.routes.core")
ramp_bp        = _get_bp("modules.routes.ramp")
exports_bp     = _get_bp("modules.routes.exports")
auth_bp        = _get_bp("modules.routes.auth")
preferences_bp = _get_bp("modules.routes.preferences")
admin_bp       = _get_bp("modules.routes.admin")
index_bp       = _get_bp("modules.routes.wargame.index")
wgramp_bp      = _get_bp("modules.routes.wargame.ramp")
super_bp       = _get_bp("modules.routes.wargame.super")
supervisor_bp  = _get_bp("modules.routes.supervisor")
wginventory_bp  = _get_bp("modules.routes.wargame.inventory")
staff_bp       = _get_bp("modules.routes.staff")
comms_bp       = _get_bp("modules.routes.comms")
aircraft_bp    = _get_bp("modules.utils.aircraft")   # ← merged utils+routes
webeoc_bp      = _get_bp("modules.routes.webeoc")    # /webeoc/*
locates_bp     = _get_bp("modules.routes.locates")   # /api/locates/*
training_bp    = _get_bp("modules.routes.training")  # /training (PDF hub + help directory)
wgclient_bp    = _get_bp("modules.routes.wgclient")  # /wargame/play host page
captive_bp     = _get_bp("modules.routes.captive")   # captive portal detection responses

# Register blueprints with unique names to avoid collisions
tiles_bp       = _get_bp("modules.services.tiles")   # /tiles/{z}/{x}/{y}.png
# Weather (page + API)
weather_page_bp = _get_bp("modules.routes.weather", "bp_page")
weather_api_bp = _get_bp("modules.routes.weather", "bp_api")
aggregate_api_bp = _get_bp("modules.api_aggregate", "aggregate_bp")
app.register_blueprint(inventory_bp, name="inventory")
_reg(wginventory_bp,  name="wginventory")
_reg(radio_bp,       name="radio")
_reg(wgradio_bp,     name="wgradio")
_reg(wgclient_bp,    name="wgclient")
_reg(help_bp,        name="help")
_reg(winlink_bp,     name="winlink")
_reg(errors_bp,      name="errors")
_reg(api_bp,         name="api")
_reg(wgapi_bp,       name="wgapi")
_reg(core_bp,        name="core")
_reg(ramp_bp,        name="ramp")
_reg(wgramp_bp,      name="wgramp")
_reg(exports_bp,     name="exports")
_reg(auth_bp,        name="auth")
_reg(preferences_bp, name="preferences")
_reg(admin_bp,       name="admin")
_reg(index_bp,       name="wgindex")
_reg(super_bp,       name="wgsuper")
_reg(supervisor_bp,  name="supervisor")
_reg(tiles_bp,       name="tiles")
_reg(locates_bp,     name="locates")
_reg(staff_bp,       name="staff")
_reg(webeoc_bp,      name="webeoc")
_reg(comms_bp,       name="comms")
_reg(aircraft_bp,    name="aircraft")   # /aircraft routes
_reg(training_bp,    name="training")   # /training routes
_reg(captive_bp,     name="captive")    # captive portal detection
_reg(weather_page_bp, name="weather_page")  # /weather
_reg(weather_api_bp,  name="weather_api")   # /api/weather/*
if aggregate_api_bp:
    # Register at /aggregate (auth-exempt via require_login() check for blueprint 'aggregate')
    app.register_blueprint(aggregate_api_bp, name="aggregate", url_prefix="/aggregate")
    logger.info("Registered blueprint name=aggregate url_prefix=/aggregate")
else:
    logger.warning("Skipping blueprint 'aggregate' (missing or failed import)")

# Shutdown hook from services
_jobs = _safe_import("modules.services.jobs")
_shutdown_scheduler = getattr(_jobs, "_shutdown_scheduler", lambda: None)

# Export WG hooks so modules.utils.common can pick them up via _hydrate_from_app()
import sys as _sys
for _name in (
    "configure_wargame_jobs",
    "wargame_task_start",
    "wargame_task_finish",
    "wargame_task_start_once",
    "wargame_start_radio_outbound",
    "wargame_finish_radio_outbound",
    "wargame_start_ramp_inbound",
    "get_wargame_role_epoch",
    "configure_netops_feeders",
    "configure_cargo_reconciler_job",
):
    if hasattr(_jobs, _name):
        setattr(_sys.modules[__name__], _name, getattr(_jobs, _name))

import atexit
atexit.register(_shutdown_scheduler)

# Configure NetOps feeder on startup (best-effort; no-op if disabled)
try:
    if hasattr(_jobs, "configure_netops_feeders"):
        _jobs.configure_netops_feeders()
except Exception as e:
    try:
        logger.warning("NetOps feeder not configured: %s", e)
    except Exception:
        pass

# Configure the cargo-request reconciler on startup (idempotent).
try:
    if hasattr(_jobs, "configure_cargo_reconciler_job"):
        _jobs.configure_cargo_reconciler_job()
except Exception as e:
    try:
        logger.warning("Cargo reconciler not configured: %s", e)
    except Exception:
        pass

# Ensure the APScheduler is running (safe if already started).
try:
    if getattr(scheduler, "state", None) != STATE_RUNNING:
        scheduler.start()
        logger.info("BackgroundScheduler started.")
except Exception as e:
    try:
        logger.warning("Scheduler start skipped: %s", e)
    except Exception:
        pass

# Start GPS time watcher after scheduler init (daemon thread, non-blocking)
try:
    _start_gps_time_once()
except Exception as e:
    try:
        logger.warning("GPS_TIME: start failed: %s", e)
    except Exception:
        pass

# ──────────────────────────────────────────────────────────────────────────────
# App state & constants

HARDCODED_AIRFIELDS = [
    "0W7","0S9","13W","1RL","CYNJ","KALW","KBDN","KBFI",
    "KBLI","KBVS","KCLM","KHQM","KOKH","KSHN","KUAO",
    "S60","W10","WN08"
]

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

# Now that app-level constants exist, push them into modules.utils.common
try:
    import modules.utils.common as _common
    _common._hydrate_from_app()
    logger.info("Hydrated common with Wargame constants (airfields/items).")
except Exception as e:
    logger.warning("Post-constants hydrate failed: %s", e)

# Flask extensions / app.locals
app.extensions.setdefault('distances', {})   # hex/flight→km
app.extensions.setdefault('recv_loc', {'lat':None,'lon':None})

# Use the shared cached formatter from modules.utils.common
_fmt_airport = fmt_airport

# ──────────────────────────────────────────────────────────────────────────────
# DB init / migrations / data seeds
init_db()
ensure_airports_table()
run_migrations()
ensure_staff_tables()        # staff schema first (owned by modules/utils/staff.py)
ensure_comms_tables()        # then communications (may be mirrored to by staff routes)
load_airports_from_csv()
seed_default_categories()
clear_airport_cache()

# ──────────────────────────────────────────────────────────────────────────────
# Helpful route dump + dev diagnostics

# First-boot offline tiles bootstrap (non-blocking; best-effort)
try:
    import modules.services.tiles as _tiles
    # Creates directory/MBTiles if missing and kicks off a tiny z0–7 seed,
    # guarded by a sentinel file and the 'map_offline_seed' preference.
    _tiles.bootstrap_offline_tiles(app)
except Exception as e:
    logger.warning("Tiles bootstrap skipped: %s", e)

try:
    for r in app.url_map.iter_rules():
        logger.info("ROUTE %-35s -> %s", r.rule, r.endpoint)
except Exception as e:
    logger.warning("Could not list routes: %s", e)

@app.get("/__routes__")
def __routes__():
    return jsonify([
        {"rule": r.rule,
         "endpoint": r.endpoint,
         "methods": sorted(m for m in r.methods if m not in ("HEAD", "OPTIONS"))}
        for r in app.url_map.iter_rules()
    ])

@app.get("/__ping__")
def __ping__():
    return jsonify(ok=True, now=datetime.utcnow().isoformat()+"Z")

# ──────────────────────────────────────────────────────────────────────────────
# Browser time probe → verbose log (+ optional host set)
#  - Server-side once-per-BOOT_ID gating (normal app rate limits apply)
@app.post("/__time_probe__")
def __time_probe_post():
    try:
        payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}

    client_epoch_ms = payload.get("client_epoch_ms")
    tz_offset_min   = payload.get("tz_offset_min")  # for logs only
    iana_tz         = (payload.get("iana_tz") or "").strip()

    ok_nums = True
    try:
        client_epoch_ms = float(client_epoch_ms)
    except Exception:
        ok_nums = False

    server_utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
    server_utc_ms = int(server_utc_dt.timestamp() * 1000)

    # Compute client UTC from local time + offset if numbers are good
    if ok_nums:
        # Date.now() is already UTC epoch ms
        client_utc_ms = int(client_epoch_ms)
        client_utc_dt = datetime.fromtimestamp(client_utc_ms/1000.0, tz=timezone.utc)
        delta_ms      = client_utc_ms - server_utc_ms
    else:
        client_utc_dt = None
        delta_ms      = 0

    # Verbose dev log to terminal
    try:
        app.logger.info(
            "TIME_PROBE: client_local_ms=%s iana_tz=%s tz_offset_min=%s | "
            "client_utc=%s server_utc=%s | delta_ms=%+d",
            payload.get("client_epoch_ms"),
            iana_tz or "(unknown)",
            payload.get("tz_offset_min"),
            client_utc_dt.isoformat().replace("+00:00","Z") if client_utc_dt else "(bad-input)",
            server_utc_dt.isoformat().replace("+00:00","Z"),
            int(delta_ms)
        )
    except Exception:
        pass

    # Mark this session as probed
    try:
        session["time_probe_done"] = True
        # Also record which server boot this session has probed for
        session["time_probe_boot_id"] = current_app.config.get("BOOT_ID")
    except Exception:
        pass

    # Optional: set host time (requires SYS_TIME and explicit env opt-in)
    adjusted = False
    adjust_reason = ""
    gps_preempted = False
    # If GPS time is confident, we **preempt** client time corrections entirely.
    gps_conf = False
    gps_dt   = None
    with _GPS_LOCK:
        gps_conf = bool(_gps_state["confident"])
        gps_dt   = _gps_state["last_good_dt"]

    if gps_conf and gps_dt:
        gps_preempted = True
        if AOCT_SET_HOST_TIME:
            _set_host_time_if_needed(gps_dt, reason="GPS(preempt-client)")
        # return without using client time to adjust; still log/probe as usual below
    elif AOCT_SET_HOST_TIME and ok_nums and abs(delta_ms) >= AOCT_TIME_DRIFT_MS:
        # Once-per-boot sentinel (atomic create)
        boot_id = current_app.config.get("BOOT_ID")
        sentinel = SENTINEL_DIR / f"time_set_{boot_id}"
        can_attempt = True
        created_line = f"created={datetime.utcnow().isoformat()}Z delta_ms={int(delta_ms)} " \
                       f"server_utc={server_utc_dt.isoformat().replace('+00:00','Z')} " \
                       f"client_utc={(client_utc_dt.isoformat().replace('+00:00','Z') if client_utc_dt else 'None')}\n"
        try:
            fd = os.open(str(sentinel), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            with os.fdopen(fd, "w") as fh:
                fh.write(created_line)
        except FileExistsError:
            can_attempt = False
            app.logger.info("TIME_PROBE: time-set already completed this boot (sentinel %s)", sentinel)
        except Exception as e:
            # If we can't ensure atomicity, still try once and log.
            app.logger.warning("TIME_PROBE: sentinel create failed (%s): %s", sentinel, e)

        if can_attempt:
            # Enforce max adjust cap if configured (>0)
            cap_ok = (AOCT_TIME_MAX_ADJ_S <= 0 or abs(delta_ms) <= AOCT_TIME_MAX_ADJ_S * 1000)
            if not cap_ok:
                app.logger.warning(
                    "TIME_PROBE: drift (%+d ms) exceeds AOCT_TIME_MAX_ADJUST_SEC=%s → not adjusting",
                    int(delta_ms), AOCT_TIME_MAX_ADJ_S
                )
            else:
                target_dt = client_utc_dt.replace(microsecond=0)
                iso_for_log = target_dt.isoformat().replace("+00:00","Z")
                stamp = target_dt.strftime("%Y-%m-%d %H:%M:%S")
                try:
                    rc = subprocess.run(["date","-u","-s", stamp], capture_output=True, text=True)
                    adjusted = (rc.returncode == 0)
                    adjust_reason = rc.stdout.strip() or rc.stderr.strip()
                    level = logging.INFO if adjusted else logging.WARNING
                    app.logger.log(level, "TIME_PROBE: set host UTC to %s (rc=%s) msg=%s",
                                   iso_for_log, rc.returncode, adjust_reason or "(none)")
                    # Append outcome to sentinel; DO NOT delete the sentinel — gate strictly once per BOOT_ID.
                    try:
                        with open(sentinel, "a") as fh:
                            fh.write(
                                f"rc={getattr(rc,'returncode','NA')} adjusted={int(bool(adjusted))} "
                                f"reason={adjust_reason}\n"
                            )
                    except Exception:
                        pass
                except Exception as e:
                    app.logger.warning("TIME_PROBE: set host UTC failed: %s", e)
                    try:
                        with open(sentinel, "a") as fh:
                            fh.write(f"exception={e}\n")
                    except Exception:
                        pass

    return jsonify({
        "ok": True,
        "probed": True,
        "server_utc": server_utc_dt.isoformat().replace("+00:00","Z"),
        "client_utc": (client_utc_dt.isoformat().replace("+00:00","Z") if client_utc_dt else None),
        "delta_ms": int(delta_ms),
        "adjusted": bool(adjusted),
        "gps_preempted": bool(gps_preempted),
        "gps_confident": bool(gps_conf),
        "gps_time": (_gps_state["last_good_iso"] if gps_conf else None),
        "gps_fix_mode": int(_gps_state["last_fix_mode"]),
    })

@app.get("/__gps_status__")
def __gps_status__():
    with _GPS_LOCK:
        s = dict(_gps_state)
    # Make datetimes JSON-friendly
    iso = s.get("last_good_iso")
    return jsonify({
        "confident": bool(s.get("confident")),
        "last_good_iso": iso,
        "last_fix_mode": int(s.get("last_fix_mode") or 0),
        "good_streak_sec": float(s.get("good_streak") or 0.0),
    })

# Fallback landing: redirect to a common home if present, else show routes
@app.route("/")
def _root():
    rules = {r.rule for r in app.url_map.iter_rules()}
    for candidate in ("/dashboard", "/wargame", "/ramp", "/inventory"):
        if candidate in rules:
            return redirect(candidate, code=302)
    return (
        "AOCT is running, but no landing page was found. "
        "Known routes include: " + ", ".join(sorted(rules))
    ), 200

# ──────────────────────────────────────────────────────────────────────────────
# Core request hooks (thin delegators → keep app.py small)
@app.before_request
def _core_before_request():
    # Skip duplicate work on WG fast-lane or when auth already ran
    if _is_wg_fastlane_path(request.path) or getattr(g, "AUTH_CHECKED", False):
        return
    # 1) auth gate; may return a redirect/response
    r = require_login()
    if r:
        return r
    # 2) per-blueprint cleanup (inventory pending rows)
    _cleanup_before_view()
    # 3) one-time initializers that should start on first real request
    _ensure_wargame_scheduler_once()
    _start_radio_tx_once()
    maybe_start_distances()
    g.AUTH_CHECKED = True

@app.after_request
def _core_after_request(resp):
    # Tag fast-lane responses to aid diagnostics and any upstream caches
    try:
        if _is_wg_fastlane_path(request.path):
            resp.headers["X-WG-Fastlane"] = "1"
    except Exception:
        pass
    # replay preference cookies on GETs
    return refresh_user_cookies(resp)

# ──────────────────────────────────────────────────────────────────────────────
# Wargame inventory views (local to this file)
# ──────────────────────────────────────────────────────────────────────────────
# Dev server
if __name__=="__main__":
    app.run(host='0.0.0.0', port=5150)
