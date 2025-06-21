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

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flask import (
    Flask, render_template, request, redirect,
    url_for, send_file, flash, make_response,
    jsonify
)

from flask_wtf import CSRFProtect
from markupsafe import escape

import sqlite3, csv, io, re, os, json
from datetime import datetime

from zeroconf import Zeroconf, ServiceInfo
import fcntl
import struct
import socket

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
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

# ─── mDNS registration & context injection ──────────────────────
_zeroconf = Zeroconf()

def register_mdns(name: str, port: int):
    host_ip   = get_lan_ip()
    mdns_name = f"{name}.local"

    info = ServiceInfo(
      type_     = "_http._tcp.local.",
      name      = f"{name}._http._tcp.local.",
      addresses = [socket.inet_aton(host_ip)],
      port      = port,
      server    = f"{name}.local.",
      properties= {}
    )
    _zeroconf.register_service(info)
    return mdns_name, host_ip

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
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)

# advertise our webapp on mDNS:
MDNS_NAME, HOST_IP = register_mdns("rampops", 5150)

@app.context_processor
def inject_debug_pref():
    # expose as `show_debug` in **all** Jinja templates
    return {
        'show_debug': request.cookies.get('show_debug_logs','no')
    }

@app.context_processor
def inject_now():
    from datetime import datetime
    return {'now': datetime.utcnow}

@app.context_processor
def inject_network_info():
    return {
        'mdns_name': MDNS_NAME,
        'host_ip'  : HOST_IP,
    }

# ───────────────── DB init & migrations ──────────────────
def init_db():
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

# ───────────────────────────────────────────────────────────
#  schema migrations – run on every start or after DB reset
# ───────────────────────────────────────────────────────────
def run_migrations():
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
        ("remarks",          "TEXT")
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

def ensure_column(table, col, ctype="TEXT"):
    with sqlite3.connect(DB_FILE) as c:
        have={r[1] for r in c.execute(f"PRAGMA table_info({table})")}
        if col not in have:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ctype}")

init_db()
run_migrations()
ensure_airports_table()
load_airports_from_csv()

# ───────────────── helper funcs ──────────────────────────
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
           WHERE ? IN (icao_code, iata_code, local_code, gps_code, ident)
           LIMIT 1
        """, (code,)).fetchone()

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
       took\ off\s*(?P<tko>\d{1,2}:?\d{2})
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
            match = c.execute("""
              SELECT id, remarks
                FROM flights
               WHERE tail_number=? AND complete=0
            ORDER BY id DESC
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

        # 4) new entry
        fid = c.execute("""
          INSERT INTO flights(
            is_ramp_entry, tail_number, airfield_takeoff, takeoff_time,
            airfield_landing, eta, cargo_type, cargo_weight, remarks
          ) VALUES (0,?,?,?,?,?,?,?,?)
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
        'include_test', 'radio_show_unsent_only', 'show_debug_logs'
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
    # per-browser preferences
    cookie_code = request.cookies.get('code_format')
    if cookie_code:
        code_pref = cookie_code
    else:
        row = dict_rows("SELECT value FROM preferences WHERE name='code_format'")
        code_pref = row[0]['value'] if row else 'icao4'

    mass_pref = request.cookies.get('mass_unit', 'lbs')

    # --- 1) Tail‐filter from queryparam
    tail_filter = request.args.get('tail_filter','').strip().upper()

    # --- 2) Sorting preference from cookie
    sort_seq = request.cookies.get('dashboard_sort_seq','no') == 'yes'

    # --- 3) Build SQL
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
    flights = dict_rows(sql, params)

    # --- 4) Auto‐remove completely blank/TBD rows
    def is_blank_row(f):
        keys = ['tail_number','origin_view','dest_view',
                'takeoff_time','eta','cargo_type','cargo_weight','remarks']
        return all((not f.get(k) or f.get(k)=='TBD') for k in keys)
    flights = [f for f in flights if not is_blank_row(f)]

    for f in flights:
        # 3- vs 4-letter code
        f['origin_view'] = format_airport(f.get('airfield_takeoff',''), code_pref)
        f['dest_view']   = format_airport(f.get('airfield_landing',''), code_pref)

        # ETA / Arrival view  – add “*” **only** for OPEN outbound legs
        if (
            f.get('direction') == 'outbound'       # outbound leg
            and f.get('eta')                       # ETA present
            and not f.get('complete', 0)           # leg not yet completed
        ):
            f['eta_view'] = f['eta'] + '*'
        else:
            f['eta_view'] = f.get('eta', 'TBD')

        # mass-unit view
        cw = (f.get('cargo_weight') or '').strip()
        if cw:
            m_lbs = re.match(r'([\d.]+)\s*lbs', cw, re.I)
            m_kg  = re.match(r'([\d.]+)\s*kg',  cw, re.I)

            if mass_pref == 'kg' and m_lbs:
                v = round(float(m_lbs.group(1)) / 2.20462, 1)
                cw = f'{v} kg'
            elif mass_pref == 'lbs' and m_kg:
                v = round(float(m_kg.group(1)) * 2.20462, 1)
                cw = f'{v} lbs'

        f['cargo_view'] = cw or 'TBD'


    return render_template(
        'dashboard.html',
        flights=flights,
        active='dashboard',
        tail_filter=tail_filter,
        sort_seq=sort_seq
    )
# ─── Radio Operator out-box (sortable, clickable table) ───
@app.route('/radio', methods=['GET','POST'])
def radio():
    if request.method == 'POST':
        subj   = escape(request.form['subject'].strip())
        body   = escape(request.form['body'].strip())
        sender = escape(request.form.get('sender','').strip())
        ts     = datetime.utcnow().isoformat()

        # --- override parse_winlink tail on bare “landed” notices ---
        m_tail = re.match(r"Air Ops:\s*(?P<tail>\S+)\s*\|\s*landed", subj, re.I)
        tail_override = m_tail.group('tail').strip() if m_tail else None

        # parse
        p = parse_winlink(subj, body)
        if tail_override:
            p['tail_number'] = tail_override

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

            # 2) landing-report?
            # look for “landed HHMM” (allow “09:53” or “0953”)
            lm = re.search(r'\blanded\s*(\d{1,2}:?\d{2})\b', subj, re.I)
            if lm:
                arrival = hhmm_norm(lm.group(1))

                # try updating the matching “in-flight” entry (by tail & takeoff_time)
                # don't self-limit to outbound ramp boss flights, update regardless
                match = c.execute("""
                  SELECT id, remarks
                    FROM flights
                   WHERE tail_number=? AND takeoff_time=? AND complete=0
                ORDER BY id DESC
                   LIMIT 1
                """, (p['tail_number'], p['takeoff_time'])).fetchone()

                if match:
                    # snapshot & update it
                    before = dict_rows("SELECT * FROM flights WHERE id=?", (match['id'],))[0]
                    c.execute("""
                      INSERT INTO flight_history(flight_id, timestamp, data)
                      VALUES (?,?,?)
                    """, (match['id'], datetime.utcnow().isoformat(), json.dumps(before)))

                    old_rem = match['remarks'] or ''
                    new_rem = f"{old_rem} / Arrived {arrival}" if old_rem else f"Arrived {arrival}"
                    c.execute("""
                      UPDATE flights
                         SET eta=?, complete=1, sent=0, remarks=?
                       WHERE id=?
                    """, (arrival, new_rem, match['id']))

                    flash(f"Flight {match['id']} marked as landed at {arrival}.")
                    return redirect(url_for('radio'))

                # ── no existing outbound → insert standalone inbound row ──
                fid = c.execute("""
                  INSERT INTO flights(
                    is_ramp_entry, direction, tail_number,
                    airfield_takeoff, takeoff_time,
                    airfield_landing, eta,
                    cargo_type, cargo_weight, remarks,
                    complete, sent
                  ) VALUES (0,'inbound',?,?,?,?,?,?,?,?,1,0)
                """, (
                  p['tail_number'],
                  p['airfield_takeoff'],
                  '',                # takeoff_time empty for inbound
                  p['airfield_landing'],
                  arrival,           # eta = arrival
                  p['cargo_type'],
                  p['cargo_weight'],
                  p.get('remarks','')
                )).lastrowid

                # record history
                c.execute("""
                  INSERT INTO flight_history(flight_id, timestamp, data)
                  VALUES (?,?,?)
                """, (fid, datetime.utcnow().isoformat(), json.dumps({
                  'inbound_landing': arrival
                })))

                flash(f"Landed notice logged as new inbound entry #{fid}.")
                return redirect(url_for('radio'))

            # ── fallback: pure “landed” with no time given ──
            elif re.search(r'\blanded\b', subj, re.I):
                # find the most‐recent open flight
                match = c.execute(
                    "SELECT id FROM flights WHERE tail_number=? AND complete=0 ORDER BY id DESC LIMIT 1",
                    (p['tail_number'],)
                ).fetchone()
                if match:
                    c.execute(
                        "UPDATE flights SET complete=1, sent=0 WHERE id=?",
                        (match['id'],)
                    )
                    flash(f"Flight {match['id']} marked as landed (no time given).")
                return redirect(url_for('radio'))

            # 3) not a landing → match by tail & takeoff_time?
            f = c.execute(
                "SELECT id FROM flights WHERE tail_number=? AND takeoff_time=?",
                (p['tail_number'], p['takeoff_time'])
            ).fetchone()

            if f:
                # snapshot & update existing flight
                before = dict_rows("SELECT * FROM flights WHERE id=?", (f['id'],))[0]
                c.execute("""
                  INSERT INTO flight_history(flight_id, timestamp, data)
                  VALUES (?,?,?)
                """, (f['id'], datetime.utcnow().isoformat(), json.dumps(before)))

                # conditional-field update so blanks don’t overwrite
                # only overwrite ETA if we actually parsed one
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

                flash(f"Flight {f['id']} updated from incoming message.")
            else:
                # ── NEW NON-RAMP ENTRY ────────────────────────────
                fid = c.execute("""
                  INSERT INTO flights(
                    is_ramp_entry,
                    tail_number,
                    airfield_takeoff,
                    takeoff_time,
                    airfield_landing,
                    eta,
                    cargo_type,
                    cargo_weight,
                    remarks
                  ) VALUES (0,?,?,?,?,?,?,?,?)
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

                flash(f"Incoming flight logged as new entry #{fid}.")

        return redirect(url_for('radio'))

    # ─── GET: fetch & order ramp entries ────────────────────────────────
    # read new preference toggle
    show_unsent_only = request.cookies.get('radio_show_unsent_only','no') == 'yes'

    # build your query
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

    # ─── display prefs & compute view fields ────────────────────────────
    pref     = dict_rows("SELECT value FROM preferences WHERE name='code_format'")
    code_fmt = request.cookies.get('code_format') or (pref[0]['value'] if pref else 'icao4')
    mass_fmt = request.cookies.get('mass_unit', 'lbs')

    for f in flights:
        f['origin_view'] = format_airport(f.get('airfield_takeoff',''), code_fmt)
        f['dest_view']   = format_airport(f.get('airfield_landing',''), code_fmt)

        if f.get('direction')=='outbound' and f.get('eta') and not f.get('complete',0):
            f['eta_view'] = f['eta'] + '*'
        else:
            f['eta_view'] = f.get('eta','TBD')

        # mass-unit conversion
        cw    = (f.get('cargo_weight') or '').strip()
        m_lbs = re.match(r'([\d.]+)\s*lbs', cw, re.I)
        m_kg  = re.match(r'([\d.]+)\s*kg',  cw, re.I)
        if mass_fmt=='kg' and m_lbs:
            v  = round(float(m_lbs.group(1)) / 2.20462, 1)
            cw = f'{v} kg'
        elif mass_fmt=='lbs' and m_kg:
            v = round(float(m_kg.group(1)) * 2.20462, 1)
            cw = f'{v} lbs'
        f['cargo_view'] = cw or 'TBD'

    return render_template('radio.html', flights=flights, active='radio')

# ───────────────────────────────────────────────────────────
#  AJAX PARTIALS for Dashboard & Radio
# ───────────────────────────────────────────────────────────

@app.route('/_dashboard_table')
def dashboard_table_partial():
    # 1) figure out code_pref & mass_pref exactly as in dashboard()
    cookie_code = request.cookies.get('code_format')
    if cookie_code:
        code_pref = cookie_code
    else:
        row = dict_rows("SELECT value FROM preferences WHERE name='code_format'")
        code_pref = row[0]['value'] if row else 'icao4'
    mass_pref = request.cookies.get('mass_unit', 'lbs')

    # Tail-filter & sort-order prefs
    tail_filter = request.args.get('tail_filter','').strip().upper()
    sort_seq    = request.cookies.get('dashboard_sort_seq','no') == 'yes'

    # 2) run the same SQL you use in dashboard()
    # Build SQL (partial match & your sort sequence)
    sql    = "SELECT * FROM flights"
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
    flights = dict_rows(sql, params)

    # 3) post-process each flight exactly as in dashboard()
    for f in flights:
        f['origin_view'] = format_airport(f.get('airfield_takeoff',''), code_pref)
        f['dest_view']   = format_airport(f.get('airfield_landing',''), code_pref)
        if (f.get('direction')=='outbound'
            and f.get('eta')
            and not f.get('complete',0)):
            f['eta_view'] = f['eta'] + '*'
        else:
            f['eta_view'] = f.get('eta','TBD')

        # mass conversion
        cw = (f.get('cargo_weight') or '').strip()
        m_lbs = re.match(r'([\d.]+)\s*lbs', cw, re.I)
        m_kg  = re.match(r'([\d.]+)\s*kg',  cw, re.I)
        if mass_pref=='kg' and m_lbs:
            v  = round(float(m_lbs.group(1)) / 2.20462, 1)
            cw = f'{v} kg'
        elif mass_pref=='lbs' and m_kg:
            v  = round(float(m_kg.group(1)) * 2.20462, 1)
            cw = f'{v} lbs'
        f['cargo_view'] = cw or 'TBD'

    # 4) render only the table partial
    return render_template('partials/_dashboard_table.html', flights=flights)

@app.route('/_radio_table')
def radio_table_partial():
    # read the same toggle
    show_unsent_only = request.cookies.get('radio_show_unsent_only','no') == 'yes'

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

    return render_template('partials/_radio_table.html', flights=flights)

# --- Radio message detail / copy-paste helper ---------------------------
@app.route('/radio_detail/<int:fid>')
def radio_detail(fid):
    flight     = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
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

@app.post('/mark_sent/<int:fid>')
def mark_sent(fid):
    """Flag a flight as sent and snapshot its state (+ operator callsign)."""
    callsign = request.cookies.get('operator_call', 'YOURCALL').upper()

    with sqlite3.connect(DB_FILE) as c:
        before = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
        before['operator_call'] = callsign          # ← add to history blob

        c.execute("""
            INSERT INTO flight_history(flight_id, timestamp, data)
            VALUES (?,?,?)
        """, (fid, datetime.utcnow().isoformat(), json.dumps(before)))

        c.execute("UPDATE flights SET sent = 1 WHERE id = ?", (fid,))

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
                    fid = match['id']

                else:
                    # ----- no match → insert a standalone inbound row -----
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

        # ── at this point we have `fid` of the row we inserted/updated ──
        # fetch it back in full
        row = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]

        # if this was XHR (our AJAX), return JSON instead of redirect:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(row)

        # otherwise fall back to the old behavior:
        return redirect(url_for('dashboard'))

    return render_template('ramp_boss.html', default_origin=default_origin, active='ramp_boss')

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
    """Delete a flight record and return to dashboard."""
    with sqlite3.connect(DB_FILE) as c:
        c.execute("DELETE FROM flights WHERE id = ?", (fid,))
    flash(f"Flight {fid} deleted.")
    return redirect(url_for('dashboard'))

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

    flash("Database reset and re-initialised.", "db_reset")
    return redirect(url_for('preferences'))

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
    current_radio_unsent = request.cookies.get('radio_show_unsent_only','no')

    return render_template(
        'preferences.html',
        default_origin=default_origin,
        current_code=current_code,
        current_mass=current_mass,
        operator_call=operator_call,
        include_test=include_test,
        current_debug=current_debug,
        current_radio_unsent=current_radio_unsent,
        sort_seq=request.cookies.get('dashboard_sort_seq','no')=='yes'
    )

# ───────────────────────────────────────────────────────────
if __name__=="__main__":
    app.run(host='0.0.0.0', port=5150)
