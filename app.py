# app.py — Aircraft Ops Coordination Tool
# =======================================
#  • Ramp-Boss: mandatory Inbound / Outbound, kg→lbs, ICAO storage
#  • Dashboard honours per-browser 3- vs 4-letter preference via cookie
#  • flight_history JSON-safe; CSV export; DB auto-migrate
#  • LAN-only Flask server on :5150

import os, sys, re, sqlite3, threading, time, logging, traceback, importlib
from datetime import datetime
from functools import lru_cache
from flask import Blueprint, Flask, jsonify, redirect, render_template, session, url_for

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
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from zeroconf import Zeroconf
from apscheduler.schedulers.background import BackgroundScheduler

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

# Replace sqlite3.connect with the wrapped/traced one exported by modules.utils.common
sqlite3.connect = connect

# ──────────────────────────────────────────────────────────────────────────────
# Flask app + CSRF + Rate limits
app = Flask(__name__)

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
)

CSRFProtect(app)
limiter = Limiter(app, key_func=get_remote_address, default_limits=["1000 per hour"])

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

# Make scheduler available via app.extensions to avoid importing from app in routes
app.extensions['scheduler'] = scheduler

# ──────────────────────────────────────────────────────────────────────────────
# Safe imports + blueprint registration with unique names and clear diagnostics

# Global guards & background starters (implemented in modules.utils.common)
from modules.utils.common import (
    require_login as _require_login,
    maybe_start_distances as _maybe_start_distances,
)

@app.before_request
def _global_before_request():
    # run one-time initializers BEFORE we might return on auth
    _ensure_wargame_scheduler_once()
    _maybe_start_distances()

    # auth gate (may return a redirect)
    rv = _require_login()
    if rv:
        return rv

    _cleanup_before_view()

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
):
    _safe_import(_mod)

# Blueprints that export a `bp`
radio_bp       = _get_bp("modules.routes.radio")
wgradio_bp     = _get_bp("modules.routes.wargame.radio")
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

# Register blueprints with unique names to avoid collisions
app.register_blueprint(inventory_bp, name="inventory")
_reg(wginventory_bp,  name="wginventory")
_reg(radio_bp,       name="radio")
_reg(wgradio_bp,     name="wgradio")
_reg(winlink_bp,     name="winlink")
_reg(errors_bp,      name="errors")
_reg(api_bp,         name="api")
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
    "get_wargame_role_epoch",   # if defined in your services
):
    if hasattr(_jobs, _name):
        setattr(_sys.modules[__name__], _name, getattr(_jobs, _name))

import atexit
atexit.register(_shutdown_scheduler)

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
run_migrations()
ensure_airports_table()
load_airports_from_csv()
seed_default_categories()
clear_airport_cache()

# ──────────────────────────────────────────────────────────────────────────────
# Helpful route dump + dev diagnostics

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

@app.after_request
def _core_after_request(resp):
    # replay preference cookies on GETs
    return refresh_user_cookies(resp)

# ──────────────────────────────────────────────────────────────────────────────
# Wargame inventory views (local to this file)
# ──────────────────────────────────────────────────────────────────────────────
# Dev server
if __name__=="__main__":
    app.run(host='0.0.0.0', port=5150)
