
from markupsafe import escape
import sqlite3, re, json, logging
from datetime import datetime, timezone
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from app import scheduler

from modules.services.winlink.core import (
    parse_winlink, generate_subject, generate_body,
    parse_aoct_cargo_query, pat_config_status, send_winlink_message,
    build_aoct_flight_reply_body,   # ← for AOCT flight query preview
)
from modules.services.webeoc.ingest_rr import ingest_saved_data
from modules.utils.comms import insert_comm
from modules.utils.remote_inventory import (
    parse_remote_snapshot,
    upsert_remote_inventory,
    ensure_remote_inventory_tables,
    build_inventory_snapshot,
)
from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from modules.utils.common import adsb_bulk_upsert
from modules.utils.common import _start_radio_tx_once, maybe_extract_flight_code, _is_winlink_reflector_bounce, _mirror_comm_winlink  # call run-once starter from this bp
from modules.utils.common import canonical_airport_code
from modules.utils.comms import insert_comm
from modules.services.jobs import _parse_aoct_flight_reply
from modules.routes.ramp import try_satisfy_ramp_request
from modules.routes.wargame_api import _plane_pin_clear_by_flight_ref

# --- IMPORTANT ---
# The star import above brings in a DB-only fallback wargame_task_finish that returns None
# and does not record metrics. Explicitly override it here with the *real* implementation.
try:
    from modules.services.wargame import (
        wargame_task_finish as _wg_finish_real,
        extract_wgid_from_text as _extract_wgid_from_text,
    )
except Exception:
    _wg_finish_real = None
    _extract_wgid_from_text = None
if _wg_finish_real:
    # Replace the fallback imported via modules.utils.common with the real one.
    wargame_task_finish = _wg_finish_real

# Give this blueprint a stable, explicit name so endpoints are always 'radio.*'
bp = Blueprint('radio', __name__)
logger = logging.getLogger(__name__)

# Mirror helper now imported from modules.utils.common as _mirror_comm_winlink

# --- AOCT subject/body normalization + mapping helpers -----------------------
_SUBJECT_PREFIX = re.compile(r'^(?:\s*(?:subject|subj|re|fw|fwd|ack)\s*:?\s*)+', re.I)
_AOCT_PHRASE   = re.compile(r'\baoct\s+cargo\s+(reply|status|query)\b', re.I)
_AOCT_FLIGHT   = re.compile(r'\baoct\s+flight\s+(reply|query)\b', re.I)
_AIRPORT_LINE  = re.compile(r'^\s*AIRPORT\s*:\s*([A-Z0-9]{3,4})\b', re.I | re.M)

def _build_aoct_query(airport: str, categories=None, wants_csv: bool=True):
    """Return (subject, body) for a standards-compliant AOCT cargo query."""
    ap = (airport or '').strip().upper()
    cats = [c.strip().upper() for c in (categories or []) if c and c.strip()]
    subject = "AOCT cargo query"
    lines = [subject, "", f"AIRPORT: {ap}"]
    # Always include CATEGORIES:, even if blank (spec permits an empty list)
    lines.append("CATEGORIES: " + (", ".join(cats) if cats else ""))
    # Be explicit about CSV preference
    lines.append("CSV: " + ("YES" if wants_csv else "NO"))
    # Update spec revision to current
    lines += ["", "{AOCT cargo query, rev. 2025-09-01}"]
    return subject, "\n".join(lines)

def _parse_categories(form):
    """Accept 'categories[]' multi or 'categories' csv/space; return list[str]."""
    if 'categories[]' in form:
        return form.getlist('categories[]')
    raw = (form.get('categories') or '').strip()
    if not raw:
        return []
    return re.split(r'[,\s]+', raw)

def _normalize_subject(s: str) -> str:
    """Strip leading 'Subject:/Re:/Fw:/Ack:' prefixes (any count)."""
    return _SUBJECT_PREFIX.sub('', s or '').strip()

def _airport_from_body(body: str) -> str:
    """Best-effort pull of 'AIRPORT: KXXX' from the body text."""
    m = _AIRPORT_LINE.search(body or '')
    return (m.group(1).upper() if m else '')

def _lookup_callsign_for_airport(code: str) -> str:
    """Resolve airport → Winlink callsign from preferences mapping."""
    try:
        raw = get_preference('airport_call_mappings') or ''
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

def _split_recipients(raw: str) -> list[str]:
    """Split a 'to' field into callsigns; accept comma/space/semicolon/newline separated."""
    if not raw:
        return []
    parts = re.split(r'[,\s;]+', raw.upper().strip())
    seen, out = set(), []
    for p in parts:
        if not p:
            continue
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out

def _get_winlink_ccs():
    """Return list[str] of configured CC addresses (uppercased, non-empty)."""
    addrs = []
    try:
        for i in (1,2,3):
            v = (get_preference(f'winlink_cc_{i}') or '').strip().upper()
            if v:
                addrs.append(v)
    except Exception:
        pass
    return addrs

@bp.post("/import_rr")
def import_rr():
    """
    Accepts a pasted WebEOC 'Save data' JSON blob and ingests into v2 aggregates.
    Returns {'added': N}.
    """
    text = (request.form.get("payload") or "").strip()
    if not text:
        return jsonify({"error": "missing payload"}), 400
    try:
        user_airport_entry = (request.form.get("icao4") or
                              request.form.get("airport") or
                              request.form.get("airport_override") or "").strip()
        comm_id = insert_comm(
            timestamp_utc=None,
            method="Resource Request (WebEOC)",
            direction="in",
            from_party=None,
            to_party=None,
            subject="RR — WebEOC import",
            body="Imported WebEOC saved-data payload.",
            operator=None,
            notes=None,
            metadata={"kind":"resource_request"}
        )
        added = ingest_saved_data(
            text,
            source_comm_id=comm_id,
            airport_override=(user_airport_entry or None),
            allow_raw_airport=True
        )
        hint_icao = canonical_airport_code(user_airport_entry) if user_airport_entry else None
        return jsonify({
            "added": int(added),
            "comm_id": comm_id,
            "airport_hint": {
                "input": user_airport_entry,
                "icao4": hint_icao,
                "normalized": bool(hint_icao),
                "label_used": (hint_icao or user_airport_entry or "").upper() if (user_airport_entry or hint_icao) else None
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def _send_with_optional_cc(to_addr: str, subject: str, body: str, include_cc: bool=False) -> bool:
    """Try to send with cc list if requested; gracefully degrade if core API lacks cc."""
    cc_list = _get_winlink_ccs() if include_cc else []
    try:
        if cc_list:
            # Attempt kwarg form first (preferred if core supports it)
            ok = send_winlink_message(to_addr, subject, body, cc=cc_list)  # type: ignore
        else:
            ok = send_winlink_message(to_addr, subject, body)
        return bool(ok)
    except TypeError:
        # Core doesn't support cc kwarg — send primary + best-effort copies
        primary_ok = False
        try:
            primary_ok = bool(send_winlink_message(to_addr, subject, body))
        except Exception:
            primary_ok = False
        # Best effort CC fan-out (ignore individual failures)
        if cc_list and primary_ok:
            for cc in cc_list:
                try:
                    send_winlink_message(cc, subject, body)
                except Exception:
                    pass
        return primary_ok

# --- WinLink poller countdown helpers / endpoints ----------------------------
def _winlink_poller_status():
    """
    Return (running: bool, seconds_remaining: int|None, next_run_iso: str|None)
    based on APScheduler job 'winlink_poll'.
    """
    try:
        job = scheduler.get_job('winlink_poll')
    except Exception:
        job = None
    running = bool(job)
    seconds = None
    next_iso = None
    if job and getattr(job, "next_run_time", None):
        nxt = job.next_run_time
        # APS may return aware or naive; normalize to aware UTC
        if nxt.tzinfo is None:
            nxt = nxt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = (nxt - now).total_seconds()
        seconds = max(0, int(delta + 0.999))  # ceil
        next_iso = nxt.isoformat()
    return running, seconds, next_iso

@bp.app_context_processor
def _inject_winlink_status():
    """
    Make these available to templates (used by radio.html):
      winlink_job_active, winlink_auto_active, winlink_poll_seconds, winlink_poll_next_iso
    """
    try:
        running, seconds, next_iso = _winlink_poller_status()
        auto = bool(scheduler.get_job('winlink_auto_send'))
    except Exception:
        running, seconds, next_iso, auto = False, None, None, False
    return dict(
        winlink_job_active=running,
        winlink_auto_active=auto,
        winlink_poll_seconds=seconds,
        winlink_poll_next_iso=next_iso
    )

@bp.get('/winlink/poller_status')
def winlink_poller_status():
    running, seconds, next_iso = _winlink_poller_status()
    return jsonify({"running": running, "seconds": seconds, "next_run": next_iso})

# --- Counterparty resolver ---------------------------------------------------
def _resolve_counterparty_airport(airfield_takeoff: str, airfield_landing: str):
    """
    Return (canon_code, role) for the airport we should notify / map against.
    If the destination is our own station (default_origin), flip to ORIGIN.
    Otherwise use DESTINATION. Role is 'origin' or 'destination'.
    """
    self_canon = canonical_airport_code(get_preference('default_origin') or '')
    o = canonical_airport_code(airfield_takeoff or '')
    d = canonical_airport_code(airfield_landing or '')
    if self_canon and d and d == self_canon:
        return (o or None, 'origin')
    return (d or None, 'destination')

# --- AOCT flight-query sighting resolver -------------------------------------
def _latest_sighting_for_tail_db_first(tail: str) -> dict | None:
    """
    Best-effort resolver used by AOCT flight query preview:
      1) newest row in adsb_sightings for this tail
      2) fallback to adsb_latest_for_tail(tail)
      3) fallback to scanning adsb_fetch_snapshot()
    Always back-fills receiver metadata from preferences if blank.
    Returns a dict with keys compatible with build_aoct_flight_reply_body(), or None.
    """
    t = (tail or '').strip().upper()
    if not t:
        return None
    row = None
    try:
        with sqlite3.connect(current_app.config['DB_FILE']) as c:
            c.row_factory = sqlite3.Row
            row = c.execute("""
                SELECT tail, sample_ts_utc, lat, lon, track_deg, speed_kt, alt_ft,
                       receiver_airport, receiver_call, source
                  FROM adsb_sightings
                 WHERE UPPER(tail)=?
                 ORDER BY sample_ts_utc DESC
                 LIMIT 1
            """, (t,)).fetchone()
    except Exception:
        row = None

    d: dict | None = dict(row) if row else None
    if not d:
        try:
            logger.debug("AOCT flight: no DB/live sample for tail=%s; scanning snapshot…", t)
        except Exception:
            pass
        # Try the lightweight live helper
        try:
            live = adsb_latest_for_tail(t)
        except Exception:
            live = None
        if live and (live.get('lat') is not None) and (live.get('lon') is not None):
            d = {
                "tail": (live.get("tail") or t).strip().upper(),
                "lat": float(live["lat"]),
                "lon": float(live["lon"]),
                "track_deg": live.get("track_deg"),
                "speed_kt": live.get("speed_kt"),
                "alt_ft": live.get("alt_ft"),
                "sample_ts_utc": live.get("sample_ts_utc") or iso8601_ceil_utc(),
                "receiver_airport": (live.get("receiver_airport") or "").strip().upper(),
                "receiver_call":    (live.get("receiver_call") or "").strip().upper(),
                "source": (live.get("source") or ""),
            }
        else:
            # Last-ditch: scan the current snapshot for a matching tail
            try:
                snap = adsb_fetch_snapshot() or []
            except Exception:
                snap = []
            for r in snap:
                rt = (r.get("tail") or r.get("reg") or "").strip().upper()
                if rt == t and r.get("lat") is not None and r.get("lon") is not None:
                    d = {
                        "tail": t,
                        "lat": float(r["lat"]),
                        "lon": float(r["lon"]),
                        "track_deg": r.get("track_deg"),
                        "speed_kt": r.get("speed_kt"),
                        "alt_ft": r.get("alt_ft"),
                        "sample_ts_utc": r.get("sample_ts_utc") or iso8601_ceil_utc(),
                        "receiver_airport": (r.get("receiver_airport") or "").strip().upper(),
                        "receiver_call":    (r.get("receiver_call") or "").strip().upper(),
                        "source": (r.get("source") or ""),
                    }
                    break

    if not d:
        return None
    # Fill metadata defaults if missing (we are the receiver)
    d.setdefault("sample_ts_utc", iso8601_ceil_utc())
    if not (d.get("receiver_airport") or "").strip():
        d["receiver_airport"] = (get_preference('default_origin') or '').strip().upper()
    if not (d.get("receiver_call") or "").strip():
        d["receiver_call"] = (get_preference('winlink_callsign_1') or '').strip().upper()
    if not (d.get("source") or "").strip():
        d["source"] = "adsb"
    return d

# Start RadioTX once when this blueprint sees its first request.
# (Flask blueprints don’t have before_app_first_request; use before_request + our guard.)
#@bp.before_request
#def _radiotx_once_setup():
#    try:
#        _start_radio_tx_once()
#    except Exception:
#        # never block a request just because RadioTX couldn’t start
#        pass

@bp.route('/radio', methods=['GET','POST'], endpoint='radio')
def radio():
    if request.method == 'POST':
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        subj   = escape(request.form['subject'].strip())
        body   = escape(request.form['body'].strip())
        sender = escape(request.form.get('sender','').strip())
        ts     = datetime.utcnow().isoformat()
        subj_norm = _normalize_subject(subj)

        # --- AOCT FLIGHT REPLY (manual paste) --------------------------------
        # Accept variations like "AOCT Flight Reply: QHD811" or with extra text after.
        # Using a case-insensitive prefix match keeps behavior aligned with real-world emails.
        if re.match(r'(?i)^\s*aoct\s+flight\s+reply\b', subj_norm):
            # audit row
            with sqlite3.connect(current_app.config['DB_FILE']) as c:
                c.execute("""
                  INSERT INTO incoming_messages(
                    sender, subject, body, timestamp,
                    tail_number, airfield_takeoff, airfield_landing,
                    takeoff_time, eta, cargo_type, cargo_weight, remarks
                  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (sender, subj, body, ts, '', '', '', '', '', '', '', ''))
                c.commit()
            # parse + persist
            try:
                d = _parse_aoct_flight_reply(body)
            except Exception as exc:
                logger.exception("AOCT flight reply parse failed (manual): %s", exc)
                if is_ajax:
                    return jsonify({'action':'aoct_flight_failed', 'error':'parse_error'}), 200
                flash("AOCT flight reply could not be parsed.", "error")
                return redirect(url_for('radio.radio'))

            # --- NEW: ingest parsed flight reply + update locate + respond ---
            try:
                # Basic sanity: must have tail + lat/lon
                if (not d) or (not d.get('tail')) or (d.get('lat') is None) or (d.get('lon') is None):
                    if is_ajax:
                        return jsonify({'action':'aoct_flight_failed', 'error':'missing_fields'}), 200
                    flash("AOCT flight reply lacked tail/lat/lon; not ingested.", "error")
                    return redirect(url_for('radio.radio'))

                # Defaults & normalization
                d['sample_ts_utc']    = d.get('sample_ts_utc') or iso8601_ceil_utc()
                d['receiver_airport'] = canonical_airport_code(
                    d.get('receiver_airport') or (get_preference('default_origin') or '')
                ) or ''
                d['receiver_call']    = (d.get('receiver_call') or (get_preference('winlink_callsign_1') or '')).strip().upper()
                d['source']           = d.get('source') or 'readsb'

                # De-duped insert into adsb_sightings
                adsb_bulk_upsert([{
                    'tail': d['tail'],
                    'sample_ts_utc': d['sample_ts_utc'],
                    'lat': d['lat'],
                    'lon': d['lon'],
                    'track_deg': d.get('track_deg'),
                    'speed_kt': d.get('speed_kt'),
                    'alt_ft': d.get('alt_ft'),
                    'receiver_airport': d.get('receiver_airport') or None,
                    'receiver_call': d.get('receiver_call') or None,
                    'source': d.get('source') or 'readsb',
                }])

                # Flip most recent locate row for this tail to "responded"
                with sqlite3.connect(current_app.config['DB_FILE']) as c:
                    row = c.execute("""
                        SELECT id FROM flight_locates
                         WHERE UPPER(tail)=?
                         ORDER BY requested_at_utc DESC
                         LIMIT 1
                    """, (d['tail'],)).fetchone()
                    if row:
                        c.execute("""
                          UPDATE flight_locates
                             SET latest_sample_ts_utc=?,
                                 latest_from_airport=?,
                                 latest_from_call=?
                           WHERE id=?
                        """, (d['sample_ts_utc'], d.get('receiver_airport') or None,
                              d.get('receiver_call') or None, row[0]))
                        c.commit()

                # Success response
                if is_ajax:
                    return jsonify({'action':'aoct_flight_ingested',
                                    'tail': d['tail'],
                                    'airport': d.get('receiver_airport') or '',
                                    'ts': d['sample_ts_utc']}), 200
                flash(f"AOCT flight reply ingested for {d['tail']} from {d.get('receiver_airport','')} at {d['sample_ts_utc']}.", "success")
                return redirect(url_for('radio.radio'))
            except Exception as exc:
                logger.exception("AOCT flight reply ingest failed (manual): %s", exc)
                if is_ajax:
                    return jsonify({'action':'aoct_flight_failed', 'error':'server_error'}), 200
                flash("AOCT flight reply ingest failed.", "error")
                return redirect(url_for('radio.radio'))


        # --- AOCT FLIGHT QUERY (manual preview) ------------------------------
        # Behaves like the cargo-query path: compose a reply and show the modal.
        m_flt = _AOCT_FLIGHT.search(subj_norm)
        if subj_norm.lower() == 'aoct flight query' or (m_flt and m_flt.group(1).lower() == 'query'):
            ts = datetime.utcnow().isoformat()
            # Audit trail: store raw inbound (empty flight fields)
            with sqlite3.connect(current_app.config['DB_FILE']) as c:
                c.execute("""
                  INSERT INTO incoming_messages(
                    sender, subject, body, timestamp,
                    tail_number, airfield_takeoff, airfield_landing,
                    takeoff_time, eta, cargo_type, cargo_weight, remarks
                  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (sender, subj, body, ts, '', '', '', '', '', '', '', ''))
                c.commit()
            # Mirror to communications (inbound AOCT flight query)
            try:
                _mirror_comm_winlink(
                    ts, "in",
                    from_party=(sender or ''),
                    to_party=(get_preference('winlink_callsign_1') or 'OPERATOR'),
                    subject=subj, body=body,
                    operator=(request.cookies.get('operator_call') or None),
                    metadata={"kind": "AOCT flight query"}
                )
            except Exception:
                pass

            # Parse minimal fields from body
            m_tail = re.search(r'^\s*TAIL\s*:\s*([A-Z0-9\-]+)\b', body or '', re.I | re.M)
            tail   = (m_tail.group(1).upper() if m_tail else '').strip()
            m_from = re.search(r'^\s*FROM_AIRPORT\s*:\s*([A-Z0-9]{3,4})\b', body or '', re.I | re.M)
            from_ap = (m_from.group(1).upper() if m_from else '').strip()

            # Build reply body from newest ADS-B sample (DB first, then live/snapshot)
            reply_subject = "AOCT flight reply"
            reply_body    = ""
            sample        = _latest_sighting_for_tail_db_first(tail) if tail else None
            if sample and (sample.get('lat') is not None) and (sample.get('lon') is not None):
                try:
                    reply_body = build_aoct_flight_reply_body(sample)
                except Exception:
                    # fallback: inline compose if builder isn’t available
                    lines = [
                        "AOCT flight reply", "",
                        f"TAIL: {sample['tail']}",
                        f"POSITION: {sample['lat']},{sample['lon']}",
                        f"TRACK_DEG: {'' if sample.get('track_deg') is None else sample['track_deg']}",
                        f"GROUND_SPEED_KT: {'' if sample.get('speed_kt') is None else sample['speed_kt']}",
                        f"ALTITUDE_FT: {'' if sample.get('alt_ft') is None else sample['alt_ft']}",
                        f"SAMPLE_TS: {sample['sample_ts_utc']}",
                        f"RECEIVER_AIRPORT: {sample.get('receiver_airport','')}",
                        f"RECEIVER_CALL: {sample.get('receiver_call','')}",
                        f"SOURCE: {sample.get('source','')}",
                        "{AOCT flight reply, rev. 2025-09-01}",
                    ]
                    reply_body = "\n".join(lines)
            else:
                # No sighting available → produce a polite, standards-shaped notice
                # (Operator may still send manually, or try again later.)
                tail_txt = tail or "UNKNOWN"
                reply_body = (
                    "AOCT flight reply\n\n"
                    f"TAIL: {tail_txt}\n"
                    "POSITION: \n"
                    "TRACK_DEG: \n"
                    "GROUND_SPEED_KT: \n"
                    "ALTITUDE_FT: \n"
                    f"SAMPLE_TS: {iso8601_ceil_utc()}\n"
                    f"RECEIVER_AIRPORT: {(get_preference('default_origin') or '').strip().upper()}\n"
                    f"RECEIVER_CALL: {(get_preference('winlink_callsign_1') or '').strip().upper()}\n"
                    "SOURCE: adsb\n"
                    "{AOCT flight reply, rev. 2025-09-01}"
                )

            # Determine destination callsign hint from FROM_AIRPORT mapping
            to_hint = _lookup_callsign_for_airport(from_ap) or (sender or "").strip().upper()
            pat_ok, _, _ = pat_config_status()
            if is_ajax:
                return jsonify({
                    'action': 'aoct_query_reply',
                    'airport': from_ap,
                    'categories': [],  # shape parity with cargo path
                    'subject': reply_subject,
                    'body': reply_body,
                    'can_send': bool(pat_ok),
                    'to_hint': to_hint
                })
            flash("AOCT flight query parsed; reply preview available (AJAX).")
            return redirect(url_for('radio.radio'))

        # ── AOCT SNAPSHOT MESSAGES (handled before Air Ops parsing) ─────────────
        # Accept subjects: "AOCT cargo reply" or "AOCT cargo status" (ignore queries)
        # Detect the phrase ANYWHERE in subject (after normalizing prefixes like "Subject:" / "RE:")
        m_aoct = _AOCT_PHRASE.search(subj_norm)
        if m_aoct:
            kind = m_aoct.group(1).lower()
            # Audit trail: store raw inbound (empty flight fields)
            with sqlite3.connect(current_app.config['DB_FILE']) as c:
                c.execute("""
                  INSERT INTO incoming_messages(
                    sender, subject, body, timestamp,
                    tail_number, airfield_takeoff, airfield_landing,
                    takeoff_time, eta, cargo_type, cargo_weight, remarks
                  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (sender, subj, body, ts, '', '', '', '', '', '', '', ''))
                c.commit()
            # Mirror to communications (inbound AOCT)
            try:
                _mirror_comm_winlink(
                    ts, "in",
                    from_party=(sender or ''),
                    to_party=(get_preference('winlink_callsign_1') or 'OPERATOR'),
                    subject=subj, body=body,
                    operator=(request.cookies.get('operator_call') or None),
                    metadata={"kind": f"AOCT {kind}"}
                )
            except Exception:
                pass

            # --- AOCT QUERY → compose a reply preview for operator ---
            if kind == 'query':
                try:
                    q = parse_aoct_cargo_query(body or "")
                    # Determine target airport from query/body (fallback to default)
                    ap_code = (q.get('airport') or _airport_from_body(body) or (get_preference('default_origin') or '')).strip().upper()
                    # ── Self-target guard (canonical compare): don’t surface manual reply ──
                    self_ap  = canonical_airport_code(get_preference('default_origin') or '')
                    if self_ap and canonical_airport_code(ap_code) == self_ap:
                        note = (f"This AOCT query targets our own airport ({self_ap}). "
                                "No action is required — we don’t reply to ourselves.")
                        if is_ajax:
                            return jsonify({'action':'aoct_self_target','airport':self_ap,'message':note})
                        flash(note, "info")
                        return redirect(url_for('radio.radio'))

                    # Build snapshot using requested categories (our own airport)
                    # Sanitize category tokens: allow blank, and drop stray CSV YES/NO artifacts
                    cats_raw = q.get('categories') or []
                    def _canon_tok(s: str) -> str:
                        return re.sub(r"[^a-z0-9]+", "-", (s or "").strip().lower()).strip("-")
                    _DROP = {"csv", "yes", "no", "csv-yes", "csv-no"}
                    cats = []
                    for t in cats_raw:
                        ct = _canon_tok(t)
                        if not ct or ct in _DROP:
                            continue
                        cats.append(ct)
                    snap, human, csv_text = build_inventory_snapshot(cats)
                    # Unknown-category banner (DB-driven), same as jobs.py
                    def _tok_norm_local(s: str) -> str:
                        return re.sub(r"[^a-z0-9]+", "-", (s or "").strip().lower()).strip("-")
                    rows = dict_rows("SELECT display_name FROM inventory_categories ORDER BY display_name ASC")
                    known = {_tok_norm_local(r.get('display_name') or '') for r in rows}
                    unknown = [t for t in cats if t not in known]
                    if unknown:
                        available_names = [r['display_name'] for r in rows]
                        banner = [
                          "Unknown category token(s): " + ", ".join(sorted(set(unknown))),
                          "Categories available at this site are: " + ", ".join(available_names),
                        ]
                        human = ("\n".join(banner) + ("\n\n" + (human or "")).rstrip()).strip()
                    wants_csv = q.get('wants_csv', True)
                    reply_subject = "AOCT cargo reply"
                    reply_body = (human or "")
                    if wants_csv and csv_text:
                        reply_body = (reply_body + "\n\n" + csv_text).strip()

                    # Determine airport → callsign for autofill (prefer explicit airport in body/query)
                    to_hint_map = _lookup_callsign_for_airport(ap_code)

                    # Can we send via PAT right away?
                    pat_ok, _, _ = pat_config_status()
                    can_send = bool(pat_ok)
                    # Prefer mapping-derived callsign; fall back to any Sender header that was pasted.
                    to_hint = to_hint_map or (sender or "").strip().upper()

                    if is_ajax:
                        return jsonify({
                            'action': 'aoct_query_reply',
                            'airport': (snap.get('airport') or ap_code or ''),
                            'categories': cats,
                            'subject': reply_subject,
                            'body': reply_body,
                            'can_send': can_send,
                            'to_hint': to_hint
                        })
                    # Non-AJAX fallback: just flash and stay on page
                    flash("AOCT query parsed; reply preview available (use the AJAX path).")
                    return redirect(url_for('radio.radio'))
                except Exception as exc:
                    logger.exception("AOCT query compose failed: %s", exc)
                    if is_ajax:
                        return jsonify({'action': 'aoct_ingest_failed', 'error': 'query_compose_failed'})
                    flash("Could not compose AOCT reply from query.", "error")
                    return redirect(url_for('radio.radio'))

            # Parse & upsert snapshot for reply/status
            try:
                ensure_remote_inventory_tables()
                # Pass normalized subject so snapshots that were prefixed with "Subject:" etc. still ingest.
                canon, snap, summary_text, csv_text = parse_remote_snapshot(subj_norm, body, sender or None)
                rows = (snap.get('rows') or [])
                mode = ('status' if kind == 'status' else 'reply')
                is_full = (kind == 'status')
                # ── Guard: do NOT ingest snapshots that target our own station (alias-aware) ──
                try:
                    self_alias_canons = set()
                    self_raw = (get_preference('default_origin') or '').strip().upper()
                    if self_raw:
                        # include all aliases (ICAO/IATA/FAA/GPS/local) → canonical
                        aliases = set(airport_aliases(self_raw) or [])
                        aliases.add(self_raw)
                        for a in aliases:
                            c = canonical_airport_code(a)
                            if c:
                                self_alias_canons.add(c)
                except Exception:
                    self_alias_canons = set()

                if canon and (canon in self_alias_canons):
                    logger.info("AOCT ingest skipped: snapshot for our own station (%s)", canon)
                    if is_ajax:
                        return jsonify({'action': 'aoct_ingest_skipped_self', 'airport': canon})
                    flash("AOCT snapshot targets our own station; ignored.", "info")
                    return redirect(url_for('radio.radio'))
                try:
                    logger.debug(
                        "AOCT ingest candidate: subj_kind=%s airport=%s canon=%s rows=%d",
                        kind, (snap.get('airport') or ''), canon, len(rows)
                    )
                except Exception:
                    pass
                if canon and rows:
                    # Only overwrite when we have valid rows; do layered updates per category.
                    cov = sorted({ (r.get('category') or '').strip().upper() for r in rows if (r.get('category') or '').strip() })
                    upsert_remote_inventory(
                        canon,
                        snap,
                        iso8601_ceil_utc(datetime.utcnow()),
                        summary_text,
                        csv_text,
                        sender or None,
                        mode=mode,
                        coverage_categories=cov,
                        is_full=is_full,
                    )
                    if is_ajax:
                        return jsonify({
                            'action': 'aoct_ingested',
                            'airport': canon,
                            'rows': len(snap.get('rows') or []),
                            'total_lb': float((snap.get('totals') or {}).get('total_weight_lb') or 0.0),
                            'generated_at': (snap.get('generated_at') or '')
                        })
                    flash(f"AOCT snapshot ingested for {canon}.")
                    return redirect(url_for('radio.radio'))
                else:
                    try:
                        logger.debug(
                            "AOCT ingest rejected: airport=%s canon=%s rows=%d",
                            (snap.get('airport') or ''), canon, len(rows)
                        )
                    except Exception:
                        pass
                    if is_ajax:
                        return jsonify({'action': 'aoct_ingest_failed', 'error': 'no_airport'})
                    flash("AOCT snapshot lacked a recognizable airport code; not ingested.", "error")
                    return redirect(url_for('radio.radio'))
            except Exception as exc:
                logger.exception("AOCT ingest failed: %s", exc)
                if is_ajax:
                    return jsonify({'action': 'aoct_ingest_failed', 'error': 'server_error'})
                flash("AOCT snapshot ingest failed.", "error")
                return redirect(url_for('radio.radio'))

        # --- extract WGID (prefer services' subject+body extractor) ---
        if _extract_wgid_from_text:
            wgid = (_extract_wgid_from_text(subj, body) or '').lower() or None
        else:
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
        # attempt to extract flight_code from subject/body (manual Radio POST path)
        fcode = maybe_extract_flight_code(subj) or maybe_extract_flight_code(body)
        p['flight_code'] = fcode or ''

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

        with sqlite3.connect(current_app.config['DB_FILE']) as c:
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
            # Mirror to communications (generic inbound)
            try:
                _mirror_comm_winlink(
                    ts, "in",
                    from_party=(sender or ''),
                    to_party=(get_preference('winlink_callsign_1') or 'OPERATOR'),
                    subject=subj, body=body,
                    operator=(request.cookies.get('operator_call') or None),
                    metadata={
                        "tail_number": p.get('tail_number') or '',
                        "flight_code": (p.get('flight_code') or ''),
                        "wgid": (wgid or '')
                    }
                )
            except Exception:
                pass
            if wgid:
                try:
                    recorded = wargame_task_finish('radio', 'inbound', key=f"msg:{wgid}")
                    logger.debug("Radio SLA finish WGID=%s recorded=%s", wgid, recorded)
                except Exception as exc:
                    logger.debug("Could not finish Radio‑inbound SLA for WGID %s: %s", wgid, exc)
            else:
                logger.debug("No WGID in message; skipping Radio SLA finish.")

            # If this is a Winlink Test Message Reflector bounce, stop after auditing.
            if _is_winlink_reflector_bounce(subj, body):
                if is_ajax:
                    return jsonify({'action': 'ignored_reflector'})
                return redirect(url_for('radio.radio'))

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
                         SET eta=?, complete=1, remarks=?, flight_code=COALESCE(?, flight_code)
                       WHERE id=?
                    """, (arrival, new_rem, fcode, match['id']))
                    c.commit()
                    if is_ajax:
                        row = dict_rows("SELECT * FROM flights WHERE id=?", (match['id'],))[0]
                        row['action'] = 'updated'
                        return jsonify(row)
                    # Prefer flight_code for operator feedback; fall back to id if absent
                    code_row = dict_rows(
                        "SELECT flight_code FROM flights WHERE id=?",
                        (match['id'],)
                    )
                    code_txt = (code_row[0]['flight_code'] or match['id']) if code_row else match['id']
                    flash(f"Flight {code_txt} marked as landed at {arrival}.")
                    return redirect(url_for('radio.radio'))
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
                    return redirect(url_for('radio.radio'))

                # No matching outbound → ignore creating any flight.
                # We still keep incoming_messages (already inserted above) for audit.
                if is_ajax:
                    return jsonify({'action': 'ignored_landing_no_match',
                                    'tail': p['tail_number'],
                                    'arrival': arrival})
                flash("Remote landing confirmation ignored (no matching outbound leg).")
                return redirect(url_for('radio.radio'))

            # ── fallback: pure “landed” with no time given ──
            elif re.search(r'\blanded\b', subj, re.I):
                match = c.execute(
                    "SELECT id FROM flights WHERE tail_number=? AND complete=0 ORDER BY id DESC LIMIT 1",
                    (p['tail_number'],)
                ).fetchone()
                if match:
                    c.execute("UPDATE flights SET complete=1, sent=0 WHERE id=?", (match['id'],))
                    flash(f"Flight {match['id']} marked as landed (no time given).")
                return redirect(url_for('radio.radio'))

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
                    return redirect(url_for('radio.radio'))

                c.execute("""
                  INSERT INTO flight_history(flight_id, timestamp, data)
                  VALUES (?,?,?)
                """, (f['id'], datetime.utcnow().isoformat(), json.dumps(before)))

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
                  p['eta'], p['eta'],
                  p['cargo_type'],   p['cargo_type'],
                  p['cargo_weight'], p['cargo_weight'],
                  p.get('remarks',''), p.get('remarks',''),
                  fcode,
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
                # Perfect-duplicate guard: refuse identical open leg
                dup_new = c.execute("""
                    SELECT id FROM flights
                     WHERE IFNULL(complete,0)=0
                       AND tail_number=? AND airfield_takeoff=? AND airfield_landing=?
                       AND IFNULL(takeoff_time,'')=? AND IFNULL(eta,'')=?
                       AND IFNULL(cargo_type,'')=? AND IFNULL(cargo_weight,'')=?
                       AND IFNULL(remarks,'')=?
                     ORDER BY id DESC LIMIT 1
                """, (
                  p['tail_number'], p['airfield_takeoff'], p['airfield_landing'],
                  p['takeoff_time'] or '', p['eta'] or '',
                  p['cargo_type'] or '', p['cargo_weight'] or '', p.get('remarks','') or ''
                )).fetchone()
                if dup_new:
                    if is_ajax:
                        full = dict_rows("SELECT * FROM flights WHERE id=?", (dup_new['id'],))
                        row = full[0] if full else {'id': dup_new['id']}
                        row['action'] = 'update_ignored'
                        return jsonify(row)
                    flash(f"Duplicate Winlink ignored (flight #{dup_new['id']}).")
                    return redirect(url_for('radio.radio'))

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
                    flight_code,
                    tail_number,
                    airfield_takeoff,
                    takeoff_time,
                    airfield_landing,
                    eta,
                    cargo_type,
                    cargo_weight,
                    remarks
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

                c.commit()

                if is_ajax:
                    row = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))[0]
                    row['action'] = 'new'
                    return jsonify(row)

                flash(f"Incoming flight logged as new entry #{fid}.")

        # normal (non-AJAX) POST → redirect back to Radio screen
        return redirect(url_for('radio.radio'))

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
        f['origin_view'] = fmt_airport(f.get('airfield_takeoff',''), code_fmt)
        f['dest_view']   = fmt_airport(f.get('airfield_landing',''), code_fmt)

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

    # --- Mapping for (counterparty) mapped, with "we-are-destination" flip ---
    raw = get_preference('airport_call_mappings') or ''
    mapping = {}
    seen_canon = {}
    for line in raw.splitlines():
        if ':' not in line: continue
        airport, addr = (x.strip().upper() for x in line.split(':', 1))
        canon = canonical_airport_code(airport)
        if canon in seen_canon and seen_canon[canon] != addr:
            continue
        mapping[canon] = addr
        seen_canon[canon] = addr
    for f in flights:
        party_canon, role = _resolve_counterparty_airport(
            f.get('airfield_takeoff',''), f.get('airfield_landing',''))
        f['dest_mapped'] = bool(party_canon and party_canon in mapping)
        # optional: expose for templates/macros if you want to message which side is missing
        f['mapped_party_canon'] = party_canon or ''
        f['mapped_party_role']  = role

    # detect whether WinLink jobs are active
    _sch = current_app.extensions.get('scheduler')
    winlink_job_active  = bool(_sch and _sch.get_job('winlink_poll'))
    winlink_auto_active = bool(_sch and _sch.get_job('winlink_auto_send'))

    return render_template(
        'radio.html',
        flights=flights,
        active='radio',
        hide_tbd=hide_tbd,
        winlink_job_active=winlink_job_active,
        winlink_auto_active=winlink_auto_active
    )

@bp.route('/_radio_table')
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

    # --- Mapping for (counterparty) mapped, with "we-are-destination" flip ---
    raw = get_preference('airport_call_mappings') or ''
    mapping = {}
    seen_canon = {}
    for line in raw.splitlines():
        if ':' not in line: continue
        airport, addr = (x.strip().upper() for x in line.split(':', 1))
        canon = canonical_airport_code(airport)
        if canon in seen_canon and seen_canon[canon] != addr:
            continue
        mapping[canon] = addr
        seen_canon[canon] = addr

    # Add (counterparty) mapped flag for each flight row
    for f in flights:
        party_canon, role = _resolve_counterparty_airport(
            f.get('airfield_takeoff',''), f.get('airfield_landing',''))
        f['dest_mapped'] = bool(party_canon and party_canon in mapping)
        f['mapped_party_canon'] = party_canon or ''
        f['mapped_party_role']  = role

    # same prefs + view‐field logic as in radio()
    pref     = dict_rows("SELECT value FROM preferences WHERE name='code_format'")
    code_fmt = request.cookies.get('code_format') or (pref[0]['value'] if pref else 'icao4')
    mass_fmt = request.cookies.get('mass_unit', 'lbs')
    hide_tbd = request.cookies.get('hide_tbd', 'yes') == 'yes'

    for f in flights:
        f['origin_view'] = fmt_airport(f.get('airfield_takeoff',''), code_fmt)
        f['dest_view']   = fmt_airport(f.get('airfield_landing',''), code_fmt)

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

@bp.route('/radio_detail/<int:fid>')
def radio_detail(fid):
    rows = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))
    if not rows:
        return ("Not found", 404)
    flight = rows[0]

    subject, body = generate_subject(flight), generate_body(flight)

    # read CMS creds out of your preferences
    wl_callsign = get_preference('winlink_callsign_1')     or ''
    wl_pass     = get_preference('winlink_password_1')     or ''

    # fully configured?
    winlink_configured = bool(wl_callsign and wl_pass)

    # is our 5-min poll job running?
    _sch = current_app.extensions.get('scheduler')
    winlink_job_active = bool(_sch.get_job('winlink_poll')) if _sch else False

    # Prefill a smart "To" hint: flip to ORIGIN if the destination is us.
    party_canon, _role = _resolve_counterparty_airport(
        flight.get('airfield_takeoff',''), flight.get('airfield_landing',''))
    to_hint = _lookup_callsign_for_airport(party_canon or flight.get('airfield_landing',''))

    return render_template(
        'send_flight.html',
        flight=flight,
        subject_text=subject,
        body_text=body,
        active='radio',
        winlink_configured=winlink_configured,
        winlink_job_active=winlink_job_active,
        to_hint=to_hint,
    )

@bp.route('/mark_sent/<int:fid>', methods=['POST'])
@bp.route('/mark_sent/<int:flight_id>', methods=['POST'])
def mark_sent(fid=None, flight_id=None):
    fid = fid or flight_id
    """Flag a flight as sent and snapshot its state (+ operator callsign)."""
    callsign = request.cookies.get('operator_call', 'YOURCALL').upper()
    now_ts   = datetime.utcnow().isoformat()

    with sqlite3.connect(current_app.config['DB_FILE']) as c:
        c.row_factory = sqlite3.Row
        # fetch current row (for subject/body), but gate with an atomic UPDATE below
        rows = c.execute("SELECT * FROM flights WHERE id=?", (fid,)).fetchall()
        if not rows:
            flash("Flight not found.")
            return redirect(url_for('radio.radio'))
        before  = dict(rows[0])
        code_txt = (before.get('flight_code') or 'TBD')

        # Atomically mark as sent only if not already sent (double-click safe)
        c.execute("BEGIN IMMEDIATE")
        updated = c.execute(
            "UPDATE flights SET sent=1, sent_time=? WHERE id=? AND IFNULL(sent,0)=0",
            (now_ts, fid)
        ).rowcount
        if updated == 0:
            c.execute("ROLLBACK")
            flash(f"Flight {code_txt} was already marked as sent.")
            return redirect(url_for('radio.radio'))

        # count prior messages by this operator → message number
        cnt = c.execute(
            "SELECT COUNT(*) FROM flight_history WHERE json_extract(data,'$.operator_call') = ?",
            (callsign,)
        ).fetchone()[0]

        # Upsert operator into the *earliest* history snapshot for this flight
        # (avoid creating a second history row that would duplicate in flights.csv)
        row_hist = c.execute(
            "SELECT id, data FROM flight_history "
            " WHERE flight_id=? ORDER BY timestamp ASC, id ASC LIMIT 1",
            (fid,)
        ).fetchone()
        if row_hist:
            try:
                # Prefer in-DB JSON patch (SQLite JSON1)
                c.execute(
                    "UPDATE flight_history "
                    "   SET data = json_set(COALESCE(data,'{}'), '$.operator_call', ?) "
                    " WHERE id=?",
                    (callsign, row_hist["id"])
                )
            except Exception:
                # Fallback: read/modify/write if json_set isn't available
                try:
                    d = json.loads(row_hist["data"] or "{}")
                except Exception:
                    d = {}
                d["operator_call"] = callsign
                c.execute(
                    "UPDATE flight_history SET data=? WHERE id=?",
                    (json.dumps(d), row_hist["id"])
                )
        else:
            # No prior snapshot (e.g., queued send) → create a single canonical row
            snap = dict(before)
            snap["operator_call"] = callsign
            c.execute(
                "INSERT INTO flight_history(flight_id, timestamp, data) "
                "VALUES (?,?,?)",
                (fid, now_ts, json.dumps(snap))
            )

        # now snapshot the outgoing Winlink message
        include_test = request.cookies.get('include_test','yes') == 'yes'
        # build body exactly as radio_detail()
        lines = []
        if include_test:
            lines.append("**** TEST MESSAGE ONLY  (if reporting on an actual flight, delete this line). ****")
        lines.append(f"{callsign} message number {cnt+1:03}.")
        lines.append("")
        lines.append(f"Aircraft {before['tail_number']}:")
        lines.append(f"  Cargo Type(s) ................. {before.get('cargo_type','none')}")
        lines.append(f"  Total Weight of the Cargo ..... {before.get('cargo_weight','none')}")
        lines.append("")
        lines.append("Additional notes/comments:")
        # Include Flight Code in the Additional notes/comments block
        if before.get('flight_code'):
            lines.append(f"  Flight Code: {before['flight_code']}")
        # Then the operator remarks, if any
        lines.append(f"  {before.get('remarks','')}")
        lines.append("")
        lines.append("{DART Aircraft Takeoff Report, rev. 2024-05-14}")
        body = "\n".join(lines)
        # build subject exactly as radio_detail()
        if before.get('direction') == 'inbound':
            subject = (
                f"Air Ops: {before['tail_number']} | "
                f"{before['airfield_takeoff']} to {before['airfield_landing']} | "
                f"Landed {before['eta'] or '----'}"
            )
        else:
            subject = (
                f"Air Ops: {before['tail_number']} | "
                f"{before['airfield_takeoff']} to {before['airfield_landing']} | "
                f"took off {before['takeoff_time'] or '----'} | "
                f"ETA {before['eta'] or '----'}"
            )
        c.execute("""
            INSERT INTO outgoing_messages(flight_id, operator_call, timestamp, subject, body)
            VALUES (?,?,?,?,?)
        """, (fid, callsign, now_ts, subject, body))

        # commit the atomic mark + snapshots
        c.commit()

    # --- Log to communications as an OUTBOUND "radio" message -------------
    try:
        # Best-effort counterparty (flip to ORIGIN if the destination is us)
        party_canon, _role = _resolve_counterparty_airport(
            before.get('airfield_takeoff',''), before.get('airfield_landing',''))
        to_party = _lookup_callsign_for_airport(party_canon or before.get('airfield_landing',''))
        insert_comm(
            timestamp_utc=now_ts,
            method="radio",            # manual radio (not Winlink)
            direction="out",
            from_party=callsign,
            to_party=(to_party or None),
            subject=subject,
            body=body,
            related_flight_id=fid,
            operator=callsign,
            metadata={
                "tail_number": (before.get("tail_number") or ""),
                "flight_code": (before.get("flight_code") or ""),
                "source": "radio_mark_sent"
            },
        )
    except Exception as e:
        logger.debug("communications insert (mark_sent fid=%s) failed: %s", fid, e)

    # finalize SLA — reaching here means this call performed the 0→1 transition
    try:
        row = dict_rows("SELECT * FROM flights WHERE id=?", (fid,))
        if row and (row[0]['direction'] == 'outbound'):
            wargame_finish_radio_outbound(fid)
            # Check if this outbound satisfies any pending ramp requests
            try_satisfy_ramp_request(row[0])
            # Mark plane panel as complete if this flight was loaded from a plane
            try:
                _plane_pin_clear_by_flight_ref(f"flight:{fid}")
            except Exception:
                pass
        else:
            # inbound: this is the landing confirmation being sent
            wargame_task_finish('radio','landing', key=f"flight:{fid}")
    except Exception:
        pass

    flash(f"Flight {code_txt} marked as sent.")
    return redirect(url_for('radio.radio'))

# ─────────────────────────────────────────────────────────────────────────────
# AOCT: ad-hoc sender used by the Radio UI’s “Send via PAT” button
# POST body: to, subject, body  → JSON {ok:bool, message?:str}
# ─────────────────────────────────────────────────────────────────────────────
@bp.route('/aoct_send', methods=['POST'])
def aoct_send():
    to_field = (request.form.get('to') or '')
    to_list  = _split_recipients(to_field)
    subject = (request.form.get('subject') or '').strip() or 'AOCT cargo reply'
    body    = (request.form.get('body') or '')

    pat_ok, _, reason = pat_config_status()
    if not pat_ok:
        return jsonify(ok=False, message=f"PAT not configured: {reason or 'unknown'}"), 400
    if not to_list:
        return jsonify(ok=False, message="Missing destination callsign(s)"), 400

    # Include CCs for AOCT reply if enabled in prefs
    include_cc = (get_preference('aoct_cc_reply') or 'no').strip().lower() == 'yes'
    try:
        ok_any = False
        for addr in to_list:
            ok_any = _send_with_optional_cc(addr, subject, body, include_cc=include_cc) or ok_any
        ok = ok_any
    except Exception as exc:
        logger.exception("AOCT PAT send failed: %s", exc)
        ok = False
    if not ok:
        return jsonify(ok=False, message="PAT send failed."), 502
    return jsonify(ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# AOCT: compose & (optionally) send a cargo QUERY
# POST form:
#   to=CALLSIGN  (optional when dry_run=1)
#   airport=KXXX (defaults to default_origin)
#   categories   (csv string) or categories[]=a&categories[]=b
#   wants_csv=yes|no (default yes)
#   dry_run=1 to only return subject/body JSON (no send)
# ─────────────────────────────────────────────────────────────────────────────
@bp.route('/aoct_query', methods=['POST'])
def aoct_query():
    """
    Preview and/or send AOCT queries via PAT.
    If AIRPORT targets our own default_origin, do NOT send; return a user-facing note.
    """

    ap = (request.form.get('airport') or (get_preference('default_origin') or '')).strip().upper()
    cats = _parse_categories(request.form)
    wants_csv = (request.form.get('wants_csv','yes').strip().lower() != 'no')
    subject, body = _build_aoct_query(ap, cats, wants_csv)

    # Preview-only?
    if request.form.get('dry_run'):
        return jsonify(ok=True, subject=subject, body=body, airport=ap, categories=cats, wants_csv=wants_csv)

    # ── Self-target guard for sends (canonical compare) ──
    self_ap = canonical_airport_code(get_preference('default_origin') or '')
    if self_ap and canonical_airport_code(ap) == self_ap:
        msg = (f"This query targets our own airport ({self_ap}). "
               "No action is required; we do not send AOCT queries to ourselves.")
        return jsonify(ok=False, code='self_target', message=msg, airport=self_ap), 200

    # Send via PAT
    to_field = (request.form.get('to') or '')
    to_list  = _split_recipients(to_field)
    if not to_list:
        return jsonify(ok=False, message="Missing destination callsign(s)"), 400
    pat_ok, _, reason = pat_config_status()
    if not pat_ok:
        return jsonify(ok=False, message=f"PAT not configured: {reason or 'unknown'}"), 400
    # include CC? explicit form override → otherwise use pref default
    inc_param = request.form.get('include_cc')
    include_cc = ((inc_param is not None and inc_param not in ('0','no','false','off'))
                  or (inc_param is None and (get_preference('aoct_cc_query') or 'no').strip().lower() == 'yes'))
    try:
        sent_any = False
        for addr in to_list:
            sent_any = _send_with_optional_cc(addr, subject, body, include_cc=include_cc) or sent_any
        sent = sent_any
    except Exception as exc:
        logger.exception("AOCT query PAT send failed: %s", exc)
        sent = False
    if not sent:
        return jsonify(ok=False, message="PAT send failed."), 502
    return jsonify(ok=True)
