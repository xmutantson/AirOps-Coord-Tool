import random
import re
import logging

import uuid
import time
import sqlite3, os, json
from datetime import datetime, timedelta, timezone
import subprocess
import glob
from apscheduler.schedulers.base import STATE_RUNNING
from apscheduler.jobstores.base import JobLookupError
from modules.utils.http import http_post_json

from modules.services.winlink.core import (
    pat_config_exists,
    pat_config_status,
    parse_winlink,          # used in process_unparsed_winlink_messages
    generate_subject,       # used in auto_winlink_send_job
    generate_body,          # used in auto_winlink_send_job
    parse_aoct_cargo_query,
    maybe_auto_reply_flight_query,
    send_winlink_message,
)
from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from modules.utils.common import _is_winlink_reflector_bounce
from modules.utils.remote_inventory import (
    build_inventory_snapshot,
    parse_remote_snapshot,
    upsert_remote_inventory,
)
from modules.utils.common import adsb_fetch_stream_snapshot, adsb_bulk_upsert, get_preference
from app import DB_FILE, scheduler
from flask import current_app
app = current_app  # legacy shim for helpers
# ── Logging bootstrap: prefer Flask's app.logger; fall back to a stdout handler ──
def _get_logger():
    try:
        return app.logger  # inherits Flask/Waitress handlers/level
    except Exception:
        l = logging.getLogger("aoct.jobs")
        if not l.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            l.addHandler(h)
        if l.level == logging.NOTSET:
            l.setLevel(logging.INFO)
        return l
LOG = _get_logger()

# ─────────────────────────────────────────────────────────────────────────────
# Alias helpers
# ─────────────────────────────────────────────────────────────────────────────
def _self_alias_canons() -> set:
    """
    Return the set of canonical airport codes (ICAO-preferred) that represent
    our own station's airport, including all known aliases (ICAO/IATA/FAA/GPS/local).
    """
    raw = (get_preference('default_origin') or '').strip().upper()
    if not raw:
        return set()
    try:
        aliases = set(airport_aliases(raw) or [])
    except Exception:
        aliases = set()
    aliases.add(raw)
    out = set()
    for a in aliases:
        try:
            c = canonical_airport_code(a)
        except Exception:
            c = None
        if c:
            out.add(c)
    return out

# ─────────────────────────────────────────────────────────────────────────────
# Winlink helpers (CC fan-out compatible with older core)
# ─────────────────────────────────────────────────────────────────────────────
def _winlink_ccs() -> list[str]:
    out = []
    try:
        for i in (1, 2, 3):
            v = (get_preference(f"winlink_cc_{i}") or "").strip().upper()
            if v:
                out.append(v)
    except Exception:
        pass
    return out

# ─────────────────────────────────────────────────────────────────────────────
# ADS-B Local Poller (optional)
# Prefs:
#   • adsb_poll_enabled    : 'yes' | 'no'
#   • adsb_poll_interval_s : seconds (str/number; default 10s; min 3s)
# Uses the Step-6 adapter: adsb_fetch_snapshot() → normalized dicts.
# Inserts into adsb_sightings with receiver metadata and light de-duplication.
# ─────────────────────────────────────────────────────────────────────────────
def adsb_poller_tick():
    """
    One polling tick: fetch snapshot from TAR1090/readsb and upsert rows.
    Skips work entirely when 'adsb_poll_enabled' is not 'yes'.
    """
    try:
        enabled = (get_preference('adsb_poll_enabled') or 'no').strip().lower() == 'yes'
    except Exception:
        enabled = False
    if not enabled:
        return
    try:
        rows = adsb_fetch_stream_snapshot()
        if not rows:
            return
        # Best-effort bulk insert; helper handles dedupe and blanks
        adsb_bulk_upsert(rows)
    except Exception as e:
        try:
            LOG.debug("adsb_poller_tick failed: %s", e)
        except Exception:
            pass

def configure_adsb_poller_job():
    """
    (Re)install or remove the ADS-B poller based on preferences.
    Safe to call repeatedly.
    """
    try:
        scheduler.remove_job('adsb_poller')
    except Exception:
        pass

    try:
        enabled = (get_preference('adsb_poll_enabled') or 'no').strip().lower() == 'yes'
    except Exception:
        enabled = False
    if not enabled:
        return
    try:
        raw = get_preference('adsb_poll_interval_s') or '10'
        interval = max(3, int(float(raw)))
    except Exception:
        interval = 10

    scheduler.add_job(
        id='adsb_poller',
        func=adsb_poller_tick,
        trigger='interval',
        seconds=interval,
        replace_existing=True
    )
    if scheduler.state != STATE_RUNNING:
        scheduler.start()

def _send_with_optional_cc(to_addr: str, subject: str, body: str, include_cc: bool=False) -> bool:
    """
    Try to use send_winlink_message(..., cc=[...]) if available; otherwise
    send primary then best-effort fan-out to CC recipients. Mirrors radio.py behavior.
    """
    cc_list = _winlink_ccs() if include_cc else []
    try:
        if cc_list:
            ok = send_winlink_message(to_addr, subject, body, cc=cc_list)  # type: ignore
        else:
            ok = send_winlink_message(to_addr, subject, body)
        return bool(ok)
    except TypeError:
        # Core lacks cc kwarg → send primary + fan-out
        primary_ok = False
        try:
            primary_ok = bool(send_winlink_message(to_addr, subject, body))
        except Exception:
            primary_ok = False
        if primary_ok and cc_list:
            for cc in cc_list:
                try:
                    send_winlink_message(cc, subject, body)
                except Exception:
                    pass
        return primary_ok

# Only for Winlink email bodies: make human-readable sections ASCII-safe.
def _wl_ascii(s):
    if not s:
        return s
    # Narrow replacements: keep CSV untouched elsewhere.
    return (
        s.replace('•', '*')
         .replace('—', '-')
         .replace('–', '-')
         .replace('×', 'x')
    )

# --- AOCT flight reply (key:value) parser ------------------------------------
def _parse_aoct_flight_reply(body: str) -> dict:
    """
    Parse the AOCT flight reply per spec:
      TAIL, POSITION(lat,lon), TRACK_DEG, GROUND_SPEED_KT, ALTITUDE_FT,
      SAMPLE_TS (ISO 8601, Z), RECEIVER_AIRPORT, RECEIVER_CALL, SOURCE
    Returns a dict with normalized keys or raises ValueError on bad input.
    """
    if not body:
        raise ValueError("empty body")

    kv = {}
    for raw in (body or "").splitlines():
        if ":" not in raw:
            continue
        k, v = raw.split(":", 1)
        kv[k.strip().upper()] = v.strip()

    tail = (kv.get("TAIL") or "").upper()
    if not tail:
        raise ValueError("missing TAIL")

    pos = kv.get("POSITION") or ""
    if "," not in pos:
        raise ValueError("POSITION must be 'lat,lon'")
    lat_s, lon_s = [p.strip() for p in pos.split(",", 1)]
    lat, lon = float(lat_s), float(lon_s)
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        raise ValueError("POSITION out of range")

    def _num(name, cast=float):
        s = kv.get(name)
        if s is None or s == "":
            return None
        try:
            return cast(s)
        except Exception:
            return None

    track = _num("TRACK_DEG", float)
    spd   = _num("GROUND_SPEED_KT", float)
    alt   = _num("ALTITUDE_FT", float)

    ts = kv.get("SAMPLE_TS") or ""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None
    except Exception:
        dt = None
    sample_ts = iso8601_ceil_utc(dt)  # uses now if dt is None

    return {
        "tail": tail,
        "lat": lat, "lon": lon,
        "track_deg": track, "speed_kt": spd, "alt_ft": alt,
        "sample_ts_utc": sample_ts,
        "receiver_airport": (kv.get("RECEIVER_AIRPORT") or "").upper(),
        "receiver_call":    (kv.get("RECEIVER_CALL") or "").upper(),
        "source": (kv.get("SOURCE") or "")
    }

def _shutdown_scheduler():
    try:
        if scheduler.state == STATE_RUNNING: scheduler.shutdown(wait=False)
    except Exception: pass

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

    self_alias_canons = _self_alias_canons()
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
        # Filter to default origin when configured — match ANY alias (canonicalized)
        if self_alias_canons:
            dest_canon = canonical_airport_code(f.get('airfield_landing') or '')
            if not dest_canon or dest_canon not in self_alias_canons:
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
      SELECT id, tail_number, airfield_takeoff, airfield_landing, sent_time, flight_code
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

        # Reuse the original flight's code; do NOT generate a new one here.
        fcode = (f.get('flight_code') or '').strip().upper() or None

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
        # Insert Flight Code into the notes block (body only), if present
        if fcode:
            insert_at = len(body_lines) - 2  # before the blank line + DART footer
            body_lines.insert(insert_at, "  ")
            body_lines.insert(insert_at + 1, f"  Flight Code: {fcode}")
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

def configure_wargame_jobs():
    print(">>> Wargame jobs configured!")
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
    _ = json.loads(settings_row[0]['value'] or '{}') if settings_row else {}
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

    # Also install the rate-based generator jobs according to Supervisor settings
    try:
        apply_supervisor_settings()
    except Exception as e:
        try:
            app.logger.warning("Wargame generators not applied: %s", e)
        except Exception:
            pass
    # Ensure nightly retention job is (re)installed alongside wargame jobs.
    try:
        configure_retention_jobs()
    except Exception:
        pass

    # Also ensure the inventory auto-broadcast minute ticker is installed.
    # (Safe to call repeatedly; job is replace_existing=True.)
    try:
        configure_inventory_broadcast_job()
    except Exception:
        pass

def configure_winlink_jobs():
    # ── clear any existing jobs ───────────────────
    for job_id in ('winlink_poll', 'winlink_parse'):
        try:
            scheduler.remove_job(job_id)
        except JobLookupError:
            pass

    # Gate startup on PAT being actually configured (not just installed)
    ok, path, reason = pat_config_status()
    if not ok:
        try:
            app.logger.warning("Winlink polling disabled: PAT not configured (%s%s%s)",
                               reason, " @ " if path else "", path or "")
        except Exception:
            pass
        # Do not schedule polling/parsing if PAT is unconfigured.
        return

    # ── polling job: fetch new .b2f files every 5min ──
    scheduler.add_job(
        id='winlink_poll',
        func=poll_winlink_job,
        trigger='interval',
        minutes=5
    )

    # ── parsing job: process any unparsed messages ───
    scheduler.add_job(
        id='winlink_parse',
        func=process_unparsed_winlink_messages,
        trigger='interval',
        minutes=5
    )


    if scheduler.state != STATE_RUNNING:
        scheduler.start()

# ─────────────────────────────────────────────────────────────────────────────
# Retention & Purge (ADS-B)
# ─────────────────────────────────────────────────────────────────────────────
def purge_adsb_sightings_job():
    """
    Nightly retention: purge ADS-B sightings older than N hours (default 24h).
    Retains flight_locates indefinitely.
    """
    try:
        hours_raw = get_preference('adsb_retention_hours') or '24'
        retention_hours = max(1.0, float(hours_raw))
    except Exception:
        retention_hours = 24.0

    cutoff_dt  = datetime.utcnow() - timedelta(hours=retention_hours)
    cutoff_iso = iso8601_ceil_utc(cutoff_dt)

    try:
        with sqlite3.connect(DB_FILE) as c:
            c.execute(
                "DELETE FROM adsb_sightings WHERE IFNULL(sample_ts_utc,'') <> '' AND sample_ts_utc < ?",
                (cutoff_iso,)
            )
        try:
            LOG.info("ADS-B purge ran: cutoff=%s (%.1f h retention)", cutoff_iso, retention_hours)
        except Exception:
            pass
    except Exception as e:
        try:
            LOG.warning("ADS-B purge failed: %s", e)
        except Exception:
            pass

def configure_retention_jobs():
    """Install/refresh nightly purge of ADS-B sightings at 02:30 UTC."""
    try:
        scheduler.remove_job('purge_adsb_sightings')
    except Exception:
        pass
    scheduler.add_job(
        id='purge_adsb_sightings',
        func=purge_adsb_sightings_job,
        trigger='cron',
        hour=2,
        minute=30,
        timezone=timezone.utc,
        replace_existing=True
    )
    if scheduler.state != STATE_RUNNING:
        scheduler.start()

def configure_winlink_auto_jobs():
    """Schedule the auto-send job (every 1m)."""
    # Do not attempt auto-send unless PAT config is usable
    ok, path, reason = pat_config_status()
    if not ok:
        try:
            app.logger.warning("Winlink auto-send disabled: PAT not configured (%s%s%s)",
                               reason, " @ " if path else "", path or "")
        except Exception:
            pass
        return
    try:
        scheduler.remove_job('winlink_auto_send')
    except JobLookupError:
        pass
    scheduler.add_job(
        id='winlink_auto_send',
        func=auto_winlink_send_job,
        trigger='interval',
        minutes=1
    )
    if scheduler.state != STATE_RUNNING:
        scheduler.start()

def auto_winlink_send_job():
    """Scan unsent outbound flights and dispatch them via PAT automatically."""
    if not pat_config_exists():
        try:
            ok, path, reason = pat_config_status()
            app.logger.error("PAT unconfigured (%s%s%s). Auto-send skipped.",
                             reason, " @ " if path else "", path or "")
        except Exception:
            pass
        return
    # load CC addresses
    cc_list = [
        get_preference(f'winlink_cc_{i}') or ''
        for i in (1,2,3)
    ]
    # pull all unsent outbound flights
    flights = dict_rows("""
        SELECT * FROM flights
         WHERE direction='outbound' AND sent=0
    """)
    for f in flights:
        dest = (f.get('airfield_landing') or '').strip().upper()
        dest_canon = canonical_airport_code(dest)

        # load mappings
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

        to_addr = mapping.get(dest_canon)
        if not to_addr:
            continue

        subject = generate_subject(f)
        op_call = "A-O-C-T"
        body    = generate_body(f, callsign=op_call, include_test=False)
        cs      = get_preference('winlink_callsign_1') or ''

        # build PAT compose cmd: flags (including CC) must come before the recipient
        cmd = ["pat", "compose", "--from", cs, "-s", subject]
        for cc in cc_list:
            if cc:
                cmd += ["--cc", cc]
        cmd.append(to_addr)

        try:
            subprocess.run(cmd, input=body, text=True, check=True)
            # mark flight sent & record
            with sqlite3.connect(DB_FILE) as conn:
                ts_iso = iso8601_ceil_utc()
                # --- Snapshot state into flight_history so the AOCT counter advances ---
                try:
                    before_rows = dict_rows("SELECT * FROM flights WHERE id=?", (f['id'],))
                    if before_rows:
                        before = before_rows[0]
                        # match manual path: stash operator_call in the snapshot payload
                        before['operator_call'] = op_call
                        conn.execute(
                            "INSERT INTO flight_history(flight_id, timestamp, data) VALUES (?,?,?)",
                            (f['id'], ts_iso, json.dumps(before))
                        )
                except Exception:
                    # don't block auto-send if history snapshot fails
                    pass

                conn.execute("UPDATE flights SET sent=1, sent_time=? WHERE id=?", (ts_iso, f['id']))
                conn.execute("""
                    INSERT INTO winlink_messages
                      (direction,callsign,sender,subject,body,flight_id)
                    VALUES(?,?,?,?,?,?)
                """, ('out', cs, cs, subject, body, f['id']))
                # also mirror into outgoing_messages for communications.csv
                conn.execute("""
                    INSERT INTO outgoing_messages (flight_id, operator_call, timestamp, subject, body)
                    VALUES (?,?,?,?,?)
                """, (f['id'], op_call, ts_iso, subject, body))

        except subprocess.CalledProcessError as e:
            app.logger.error("Auto-send failed for flight %s: %s", f['id'], e)
            continue

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

def poll_winlink_job():
    """APScheduler job: every 5min, pull inbound for each configured callsign."""
    # Safety: if PAT isn’t configured, don’t try to poll
    if not pat_config_exists():
        try:
            ok, path, reason = pat_config_status()
            app.logger.error("Skipping Winlink poll: PAT unconfigured (%s%s%s)", reason, " @ " if path else "", path or "")
        except Exception:
            pass
        return
    # For each configured callsign/password, call PAT and pull any .b2f files
    for idx in (1, 2, 3):
        cs = get_preference(f'winlink_callsign_{idx}') or ""
        pw = get_preference(f'winlink_password_{idx}') or ""
        if not all([cs, pw]):
            continue

        # 1) connect to CMS via PAT
        try:
            subprocess.run(
                ["pat", "connect", "telnet"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        except subprocess.CalledProcessError:
            # skip this callsign if we can't connect
            continue

        # 2) find all inbound .b2f files for this callsign
        inbox_dir = os.path.expanduser(f"~/.local/share/pat/mailbox/{cs}/in")
        for b2f in glob.glob(os.path.join(inbox_dir, "*.b2f")):
            try:
                # feed "0\n0\nq\n" to choose mailbox 0, message 0, then quit
                p = subprocess.run(
                    ["pat", "read", b2f],
                    input="0\n0\nq\n",
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            except subprocess.CalledProcessError:
                continue

            # 3) parse Subject and body
            raw = p.stdout.splitlines()
            subject = ""
            sender  = ""
            body_lines = []
            in_body = False

            for line in raw:
                if line.startswith("Subject:"):
                    subject = line.split(":", 1)[1].strip()
                elif line.startswith("From:"):
                    sender = line.split(":", 1)[1].strip()
                if in_body:
                    if line.startswith("==="):
                        break
                    body_lines.append(line)
                # once we’ve captured the Subject header, an empty line signals body start
                if subject and line.strip() == "":
                    in_body = True

            body = "\n".join(body_lines).strip()

            # Use RECEIVE time (now), not the b2f Date header
            ts_iso = iso8601_ceil_utc()

            # 4) insert into SQLite
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO winlink_messages "
                    "(direction, callsign, sender, subject, body, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                    ("in", cs, sender, subject, body, ts_iso)
                )
                # remove the .b2f so we don’t re-read it next time
                try:
                    os.remove(b2f)
                except OSError:
                    # if deletion fails, ignore and move on
                    pass

def process_unparsed_winlink_messages():
    """APScheduler job: parse any new inbound WinLink messages."""
    # fetch all un‐parsed inbound messages
    msgs = dict_rows("""
      SELECT id, callsign, sender, subject, body, timestamp
        FROM winlink_messages
       WHERE direction='in' AND parsed=0
    """)

    # Always emit a heartbeat at INFO so you can see it's running
    try:
        LOG.info("Winlink parse tick: %d unparsed inbound message(s)", len(msgs))
        if not msgs:
            LOG.info("Winlink parser: nothing to do this tick.")
    except Exception:
        pass

    for m in msgs:
        try:
            LOG.info("WL inbound[%s]: subj=%r from=%r ts=%r",
                     m.get('id'),
                     m.get('subject'),
                     (m.get('sender') or m.get('callsign') or ''),
                     m.get('timestamp'))
        except Exception:
            pass
        # normalize receive time once
        raw_ts = m.get('timestamp')
        try:
            if raw_ts:
                dt = datetime.fromisoformat(raw_ts.replace('Z', '+00:00'))
            else:
                dt = None
        except Exception:
            dt = None
        ts_iso = iso8601_ceil_utc(dt)

        # Reflector bounce? Mirror to incoming_messages for audit, mark parsed, and skip flights.
        if _is_winlink_reflector_bounce(m.get('subject',''), m.get('body','')):
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("""
                    INSERT INTO incoming_messages(
                        sender, subject, body, timestamp,
                        tail_number, airfield_takeoff, airfield_landing,
                        takeoff_time, eta, cargo_type, cargo_weight, remarks
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    (m.get('sender') or ''), (m.get('subject') or ''), (m.get('body') or ''), ts_iso,
                    '', '', '', '', '', '', '', ''
                ))
                conn.execute("UPDATE winlink_messages SET parsed=1 WHERE id=?", (m['id'],))
            continue

        # normalize subject once for routing
        subj_norm = (m.get('subject') or '').strip().lower()

        # ── AOCT flight query (auto-reply from background path) ───────────────
        if subj_norm == 'aoct flight query':
            try:
                # Mirror raw mail for audit (like other AOCT branches)
                with sqlite3.connect(DB_FILE) as conn:
                    conn.execute("""
                        INSERT INTO incoming_messages(
                            sender, subject, body, timestamp,
                            tail_number, airfield_takeoff, airfield_landing,
                            takeoff_time, eta, cargo_type, cargo_weight, remarks
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        (m.get('sender') or ''), (m.get('subject') or ''), (m.get('body') or ''), ts_iso,
                        '', '', '', '', '', '', '', ''
                    ))
                handled = maybe_auto_reply_flight_query(m)
                with sqlite3.connect(DB_FILE) as conn:
                    conn.execute("UPDATE winlink_messages SET parsed=1 WHERE id=?", (m['id'],))
                try:
                    LOG.info("AOCT flight query handled=%s from=%r", bool(handled), (m.get('sender') or m.get('callsign') or ''))
                except Exception:
                    pass
                continue
            except Exception:
                # fall through to generic handling on any error
                pass

        # ── AOCT flight reply → insert sighting + update locate status ───────
        if subj_norm == 'aoct flight reply':
            try:
                # Mirror raw mail for audit
                with sqlite3.connect(DB_FILE) as conn:
                    conn.execute("""
                        INSERT INTO incoming_messages(
                            sender, subject, body, timestamp,
                            tail_number, airfield_takeoff, airfield_landing,
                            takeoff_time, eta, cargo_type, cargo_weight, remarks
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        (m.get('sender') or ''), (m.get('subject') or ''), (m.get('body') or ''), ts_iso,
                        '', '', '', '', '', '', '', ''
                    ))

                d = _parse_aoct_flight_reply(m.get('body') or '')

                # 1) record into adsb_sightings (map reads this) — de-duped
                adsb_bulk_upsert([{
                    'tail': d['tail'],
                    'sample_ts_utc': d['sample_ts_utc'],
                    'lat': d['lat'],
                    'lon': d['lon'],
                    'track_deg': d['track_deg'],
                    'speed_kt': d['speed_kt'],
                    'alt_ft': d['alt_ft'],
                    'receiver_airport': d['receiver_airport'],
                    'receiver_call': d['receiver_call'],
                    'source': d['source'],
                }])

                # 2) update the newest locate request for this tail (if any)
                with sqlite3.connect(DB_FILE) as conn:
                    row = conn.execute("""
                        SELECT id FROM flight_locates
                         WHERE UPPER(tail)=?
                         ORDER BY id DESC LIMIT 1
                    """, (d["tail"],)).fetchone()
                    if row:
                        conn.execute("""
                            UPDATE flight_locates
                               SET latest_sample_ts_utc=?,
                                   latest_from_airport=?,
                                   latest_from_call=?
                             WHERE id=?
                        """, (d["sample_ts_utc"], d["receiver_airport"], d["receiver_call"], row[0]))

                with sqlite3.connect(DB_FILE) as conn:
                    conn.execute("UPDATE winlink_messages SET parsed=1 WHERE id=?", (m['id'],))

                try:
                    LOG.info("AOCT flight reply ingested: tail=%s ts=%s lat=%.5f lon=%.5f src=%s",
                             d["tail"], d["sample_ts_utc"], d["lat"], d["lon"], d["receiver_airport"])
                except Exception:
                    pass
                continue
            except Exception as e:
                try:
                    LOG.exception("AOCT flight reply parse failed: %s", e)
                except Exception:
                    pass
                # fall through to generic handling

        # ── Phase 3: Remote inventory replies/status ───────────────────────────
        if subj_norm in ('aoct cargo reply', 'aoct cargo status'):
            try:
                LOG.info("AOCT snapshot ingest path: subject=%r", m.get('subject'))
            except Exception:
                pass
            # NOTE: broadcasts are treated as "full" snapshots; replies as "partial"
            # Mirror raw mail for audit
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("""
                    INSERT INTO incoming_messages(
                        sender, subject, body, timestamp,
                        tail_number, airfield_takeoff, airfield_landing,
                        takeoff_time, eta, cargo_type, cargo_weight, remarks
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    (m.get('sender') or ''), (m.get('subject') or ''), (m.get('body') or ''), ts_iso,
                    '', '', '', '', '', '', '', ''
                ))

            # Parse snapshot (CSV preferred; human fallback)
            ap_canon, snapshot, summary_text, csv_text = parse_remote_snapshot(
                m.get('subject') or '', m.get('body') or '', m.get('sender') or ''
            )

            # ── Guard: do NOT ingest snapshots that target our own station (alias-aware) ──
            try:
                self_alias_canons = _self_alias_canons()
            except Exception:
                self_alias_canons = set()
            if ap_canon and (ap_canon in self_alias_canons):
                try: app.logger.info("AOCT ingest skipped for our own station: %s", ap_canon)
                except Exception: pass
                with sqlite3.connect(DB_FILE) as conn:
                    conn.execute("UPDATE winlink_messages SET parsed=1 WHERE id=?", (m['id'],))
                continue

            has_rows = bool(snapshot.get('rows'))
            # Tighten: only overwrite when we have valid CSV rows
            if ap_canon and has_rows:
                # Derive coverage + mode for layered updates
                mode = ('status' if subj_norm == 'aoct cargo status' else 'reply')
                coverage_categories = sorted({
                    (r.get('category') or '').strip().upper()
                    for r in (snapshot.get('rows') or [])
                    if (r.get('category') or '').strip()
                })
                is_full = (mode == 'status')

                try:
                    LOG.info("AOCT ingest: airport=%s rows=%d mode=%s",
                             ap_canon, len(snapshot.get('rows') or []), mode)
                except Exception:
                    pass
                # New args (backward compatible if util ignores extras)
                upsert_remote_inventory(
                    ap_canon,
                    snapshot,
                    received_at_iso=ts_iso,
                    summary_text=summary_text,
                    csv_text=csv_text,
                    source_callsign=(m.get('sender') or None),
                    # ─ layered ingest hints ─
                    mode=mode,
                    coverage_categories=coverage_categories,
                    is_full=is_full,
                )

            # Mark parsed either way (we already mirrored the inbound)
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("UPDATE winlink_messages SET parsed=1 WHERE id=?", (m['id'],))
            continue

        # ── Phase 1: AOCT cargo query ─────────────────────────────────────────
        if subj_norm == 'aoct cargo query':
            try:
                LOG.info("AOCT query received: id=%s from=%r", m.get('id'), (m.get('sender') or m.get('callsign') or ''))
            except Exception:
                pass
            # Mirror inbound query to incoming_messages for audit
            with sqlite3.connect(DB_FILE) as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO incoming_messages(
                        sender, subject, body, timestamp,
                        tail_number, airfield_takeoff, airfield_landing,
                        takeoff_time, eta, cargo_type, cargo_weight, remarks
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    (m.get('sender') or ''), (m.get('subject') or ''), (m.get('body') or ''), ts_iso,
                    '', '', '', '', '', '', '', ''
                ))
                incoming_id = cur.lastrowid
            # Parse the query body
            q = parse_aoct_cargo_query(m.get('body') or '')
            try: LOG.info("AOCT query parsed: %s", q)
            except Exception: pass
            # ── Guard: reply-to airport purports to be our own station (alias-aware) ──
            self_alias_canons = _self_alias_canons()
            reply_ap = (q.get('airport') or '')
            if self_alias_canons and reply_ap in self_alias_canons:
                # Surface a clear operator note and skip auto-reply.
                note = (
                    "AOCT: parsing aborted — reply address airport matches our own station "
                    f"({reply_ap}). No auto-reply sent."
                )
                try:
                    with sqlite3.connect(DB_FILE) as conn:
                        conn.execute("UPDATE incoming_messages SET remarks=? WHERE id=?", (note, incoming_id))
                        conn.execute("UPDATE winlink_messages SET parsed=1 WHERE id=?", (m['id'],))
                except Exception:
                    with sqlite3.connect(DB_FILE) as conn:
                        conn.execute("UPDATE winlink_messages SET parsed=1 WHERE id=?", (m['id'],))
                continue
            # If airport token did not canonicalize → politely error out
            if not (q.get('airport') or ''):
                reply_subject = "AOCT cargo reply"
                reply_body = "airport not recognized"
                auto_reply = (get_preference('auto_reply_enabled') or 'yes').strip().lower() == 'yes'
                to_addr = (m.get('sender') or '').strip() or (m.get('callsign') or '').strip()
                if auto_reply and pat_config_exists() and to_addr:
                    send_winlink_message(to_addr, reply_subject, reply_body)
                with sqlite3.connect(DB_FILE) as conn:
                    conn.execute("UPDATE winlink_messages SET parsed=1 WHERE id=?", (m['id'],))
                continue
            # Build the snapshot (filter by categories if provided)
            # Sanitize category tokens so blank CATEGORIES: doesn't create "csv-yes"
            raw_tokens = q.get('categories') or []
            def _canon_tok(s: str) -> str:
                return re.sub(r"[^a-z0-9]+", "-", (s or "").strip().lower()).strip("-")
            _DROP = {"csv", "yes", "no", "csv-yes", "csv-no"}
            requested_tokens = []
            for t in raw_tokens:
                ct = _canon_tok(t)
                if not ct or ct in _DROP:
                    continue
                requested_tokens.append(ct)
            try:
                logger.debug("AOCT query tokens: raw=%r → requested=%r", raw_tokens, requested_tokens)
            except Exception:
                pass
            snapshot, human, csv_text = build_inventory_snapshot(requested_tokens)
            # Human-only notice for unknown category tokens; list live categories from DB
            def _tok_norm_local(s: str) -> str:
                return re.sub(r"[^a-z0-9]+", "-", (s or "").strip().lower()).strip("-")
            rows = dict_rows("SELECT id, display_name FROM inventory_categories ORDER BY display_name ASC")
            known_tokens = {_tok_norm_local(r.get('display_name') or '') for r in rows}
            unknown = [t for t in requested_tokens if t not in known_tokens]
            if unknown:
                try: LOG.info("AOCT query unknown category token(s): %s", ", ".join(sorted(set(unknown))))
                except Exception: pass
                available_names = [r['display_name'] for r in rows]
                notice_lines = [
                    "Unknown category token(s): " + ", ".join(sorted(set(unknown))),
                    "Categories available at this site are: " + ", ".join(available_names),
                ]
                human = ("\n".join(notice_lines) + ("\n\n" + (human or "")).rstrip()).strip()
            airport = q.get('airport') or (get_preference('default_origin') or '').strip().upper() or 'UNKNOWN'
            # Subjects/bodies per spec
            reply_subject = "AOCT cargo reply"
            wants_csv = bool(q.get('wants_csv', True))
            # ASCII-normalize only the human-readable portion for Winlink delivery.
            send_human = _wl_ascii(human)
            reply_body_to_send = send_human + (("\n\n" + csv_text) if (wants_csv and csv_text) else "")
            # Honor auto-reply preference (spec §6.1, §9)
            auto_reply = (get_preference('auto_reply_enabled') or 'yes').strip().lower() == 'yes'
            # Choose a reply-to (prefer real From:; fall back to callsign bucket)
            to_addr = (m.get('sender') or '').strip() or (m.get('callsign') or '').strip()
            include_cc = (get_preference('aoct_cc_reply') or 'no').strip().lower() == 'yes'
            try:
                LOG.info("AOCT auto-reply decision: auto_reply=%s pat_ok=%s to=%r cc=%s wants_csv=%s airport=%s",
                         auto_reply, pat_config_exists(), to_addr, include_cc, wants_csv, airport)
            except Exception:
                pass
            ok = False
            if auto_reply and pat_config_exists() and to_addr:
                ok = _send_with_optional_cc(to_addr, reply_subject, reply_body_to_send, include_cc=include_cc)
                try: LOG.info("AOCT auto-reply send: ok=%s to=%r subject=%r", ok, to_addr, reply_subject)
                except Exception: pass
                if ok:
                    # Mirror into winlink_messages for observability
                    try:
                        cs = (get_preference('winlink_callsign_1') or '').strip().upper()
                        with sqlite3.connect(DB_FILE) as conn:
                            conn.execute("""
                                INSERT INTO winlink_messages(direction, callsign, sender, subject, body, timestamp)
                                VALUES('out', ?, ?, ?, ?, ?)
                            """, (cs, cs, reply_subject, reply_body_to_send, iso8601_ceil_utc()))
                    except Exception as e:
                        try: LOG.debug("AOCT auto-reply mirror failed: %s", e)
                        except Exception: pass
            elif not auto_reply:
                try: LOG.info("AOCT auto-reply suppressed by preference (auto_reply_enabled=no).")
                except Exception: pass
            else:
                # Either PAT not configured or no destination
                try:
                    LOG.warning("AOCT auto-reply skipped: pat_ok=%s to_addr=%r",
                                   pat_config_exists(), to_addr)
                except Exception:
                    pass
            # Mark parsed regardless; we’ve recorded the inbound either way
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("UPDATE winlink_messages SET parsed=1 WHERE id=?", (m['id'],))
            # done with this message
            continue

        # run your existing parser
        parsed_data = parse_winlink(m['subject'], m['body'])
        try: LOG.info("Inbound id=%s parsed as flight update (tail=%s)", m.get('id'), parsed_data.get('tail_number'))
        except Exception: pass

        # ── upsert flight record and record history ─────────────────────
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Mirror into incoming_messages so exports see it
            sender_for_log = (m.get('sender') or '')
            cur.execute("""
                INSERT INTO incoming_messages(
                    sender, subject, body, timestamp,
                    tail_number, airfield_takeoff, airfield_landing,
                    takeoff_time, eta, cargo_type, cargo_weight, remarks
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                sender_for_log,
                (m.get('subject')  or ''),
                (m.get('body')     or ''),
                ts_iso,
                parsed_data['tail_number'],
                parsed_data['airfield_takeoff'],
                parsed_data['airfield_landing'],
                parsed_data['takeoff_time'],
                parsed_data['eta'],
                parsed_data['cargo_type'],
                parsed_data['cargo_weight'],
                parsed_data.get('remarks','')
            ))

            # 1) try to find an existing inbound flight for this tail + route
            row = cur.execute("""
                SELECT id FROM flights
                 WHERE tail_number=? AND airfield_takeoff=? AND airfield_landing=?
            """, (
                parsed_data['tail_number'],
                parsed_data['airfield_takeoff'],
                parsed_data['airfield_landing']
            )).fetchone()

            if row:
                # 2a) update existing flight only if there are material changes
                flight_id = row[0]
                existing = cur.execute("SELECT * FROM flights WHERE id=?", (flight_id,)).fetchone()
                no_change = (
                    (existing['takeoff_time'] or '') == (parsed_data['takeoff_time'] or '') and
                    (existing['eta'] or '')          == (parsed_data['eta'] or '')          and
                    (existing['cargo_type'] or '')   == (parsed_data['cargo_type'] or '')   and
                    (existing['cargo_weight'] or '') == (parsed_data['cargo_weight'] or '') and
                    (existing['remarks'] or '')      == (parsed_data.get('remarks','') or '')
                )
                if not no_change:
                    cur.execute("""
                        UPDATE flights
                           SET takeoff_time=?,
                               eta=?,
                               cargo_type=?,
                               cargo_weight=?,
                               remarks=?
                         WHERE id=?
                    """, (
                        parsed_data['takeoff_time'],
                        parsed_data['eta'],
                        parsed_data['cargo_type'],
                        parsed_data['cargo_weight'],
                        parsed_data.get('remarks',''),
                        flight_id
                    ))
                    # append history only when something changed
                    cur.execute("""
                        INSERT INTO flight_history (flight_id, timestamp, data)
                        VALUES (?, datetime('now'), ?)
                    """, (flight_id, json.dumps(parsed_data)))
            else:
                # 2b) insert a new inbound flight — but guard against perfect duplicates
                dup = cur.execute("""
                    SELECT id FROM flights
                     WHERE IFNULL(complete,0)=0
                       AND tail_number=? AND airfield_takeoff=? AND airfield_landing=?
                       AND IFNULL(takeoff_time,'')=? AND IFNULL(eta,'')=?
                       AND IFNULL(cargo_type,'')=? AND IFNULL(cargo_weight,'')=?
                       AND IFNULL(remarks,'')=?
                     ORDER BY id DESC LIMIT 1
                """, (
                    parsed_data['tail_number'],
                    parsed_data['airfield_takeoff'],
                    parsed_data['airfield_landing'],
                    parsed_data['takeoff_time'] or '',
                    parsed_data['eta'] or '',
                    parsed_data['cargo_type'] or '',
                    parsed_data['cargo_weight'] or '',
                    parsed_data.get('remarks','') or ''
                )).fetchone()
                if dup:
                    flight_id = dup[0]
                else:
                    cur.execute("""
                        INSERT INTO flights
                            (tail_number,
                             direction,
                             airfield_takeoff,
                             airfield_landing,
                             takeoff_time,
                             eta,
                             cargo_type,
                             cargo_weight,
                             remarks)
                        VALUES (?, 'inbound', ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        parsed_data['tail_number'],
                        parsed_data['airfield_takeoff'],
                        parsed_data['airfield_landing'],
                        parsed_data['takeoff_time'],
                        parsed_data['eta'],
                        parsed_data['cargo_type'],
                        parsed_data['cargo_weight'],
                        parsed_data.get('remarks','')
                    ))
                    flight_id = cur.lastrowid
                    cur.execute("""
                        INSERT INTO flight_history (flight_id, timestamp, data)
                        VALUES (?, datetime('now'), ?)
                    """, (flight_id, json.dumps(parsed_data)))

            conn.commit()

        # ── finally mark this WinLink message as parsed ────────────────
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "UPDATE winlink_messages SET parsed=1 WHERE id=?",
                (m['id'],)
            )

# ───────────────────────────── NetOps Feeder (login + periodic push) ─────────────────────────────
_NETOPS_TOKEN = None
_NETOPS_TOKEN_TS = None

def _netops_enabled_cfg():
    base = (get_preference('netops_url') or '').strip()
    enabled = (get_preference('netops_enabled') or 'no').strip().lower() == 'yes'
    station = (get_preference('netops_station') or '').strip().upper()
    pwd  = (get_preference('netops_password') or '').strip()
    try:
        interval = int(float(get_preference('netops_push_interval_sec') or 60))
    except Exception:
        interval = 60
    try:
        hours = int(float(get_preference('netops_window_hours') or 24))
    except Exception:
        hours = 24
    return enabled and bool(base and station and pwd), base, station, pwd, max(30, interval), max(1, hours)

def _netops_login(base, station, pwd):
    global _NETOPS_TOKEN, _NETOPS_TOKEN_TS
    url = f"{base.rstrip('/')}/api/login"
    code, body = http_post_json(url, {"station": station, "password": pwd})
    if code == 200 and isinstance(body, dict) and body.get("token"):
        _NETOPS_TOKEN = str(body["token"])
        _NETOPS_TOKEN_TS = time.time()
        return True
    _NETOPS_TOKEN = None
    return False

def _ensure_token(base, station, pwd):
    # refresh roughly every 50 minutes
    if _NETOPS_TOKEN and _NETOPS_TOKEN_TS and (time.time() - _NETOPS_TOKEN_TS < 3000):
        return True
    return _netops_login(base, station, pwd)

def _parse_lbs(row):
    try:
        val = float(row.get('cargo_weight_real') or 0.0)
        if val > 0:
            return val
    except Exception:
        pass
    w = (row.get('cargo_weight') or '').strip()
    if not w:
        return 0.0
    s = w.lower()
    import re as _re
    nums = _re.findall(r"[\d.]+", s)
    if not nums:
        return 0.0
    num = float(nums[0])
    if 'kg' in s:
        return num * 2.20462
    return num

def _collect_flows(window_hours: int):
    since_iso = (datetime.utcnow() - timedelta(hours=window_hours)).isoformat()
    rows = dict_rows("""
        SELECT id, tail_number, direction, airfield_takeoff, airfield_landing,
               cargo_type, cargo_weight, cargo_weight_real, remarks, timestamp, eta, takeoff_time
          FROM flights
         WHERE timestamp >= ?
    """, (since_iso,))
    flows = {}
    for r in rows:
        o = (r.get('airfield_takeoff') or '').strip().upper()
        d = (r.get('airfield_landing') or '').strip().upper()
        dirn = (r.get('direction') or '').strip().lower() or 'inbound'
        key = (o, d, dirn)
        node = flows.setdefault(key, {"origin": o, "dest": d, "direction": dirn, "legs": 0, "weight_lbs": 0.0})
        node["legs"] += 1
        node["weight_lbs"] += _parse_lbs(r)
    for v in flows.values():
        v["weight_lbs"] = round(v["weight_lbs"], 1)
    return sorted(flows.values(), key=lambda x: (x["origin"], x["dest"], x["direction"]))

def _collect_manifests(window_hours: int):
    since_iso = (datetime.utcnow() - timedelta(hours=window_hours)).isoformat()
    rows = dict_rows("""
        SELECT id, tail_number, direction, airfield_takeoff, airfield_landing,
               cargo_type, cargo_weight, cargo_weight_real, remarks, timestamp, eta, takeoff_time, is_ramp_entry, complete
          FROM flights
         WHERE timestamp >= ?
         ORDER BY id DESC
    """, (since_iso,))
    out = []
    for r in rows:
        out.append({
            "flight_id": r["id"],
            "tail": (r.get("tail_number") or "").strip().upper(),
            "direction": (r.get("direction") or "").strip().lower() or "inbound",
            "origin": (r.get("airfield_takeoff") or "").strip().upper(),
            "dest": (r.get("airfield_landing") or "").strip().upper(),
            "cargo_type": (r.get("cargo_type") or "").strip(),
            "cargo_weight_lbs": round(_parse_lbs(r), 1),
            "remarks": (r.get("remarks") or "").strip(),
            "takeoff_hhmm": (r.get("takeoff_time") or "").strip(),
            "eta_hhmm": (r.get("eta") or "").strip(),
            "is_ramp_entry": int(r.get("is_ramp_entry") or 0),
            "complete": int(r.get("complete") or 0),
            "updated_at": (r.get("timestamp") or ""),
        })
    return out

def _collect_station_meta():
    default_origin = (get_preference('default_origin') or '').strip().upper()
    try:
        lat = float(get_preference('origin_lat') or '')
        lon = float(get_preference('origin_lon') or '')
        coords = {"lat": lat, "lon": lon}
    except Exception:
        coords = None
    try:
        from app import last_inventory_update
        inv_tick = last_inventory_update
    except Exception:
        inv_tick = None
    return default_origin, coords, inv_tick

def _collect_inventory():
    """
    Current stock-on-hand summary using the same roll-up as UI:
      group by (category_id, sanitized_name, weight_per_unit),
      qty = Σ(in) − Σ(out), keep only qty > 0,
      weight_lbs = qty * weight_per_unit,
      updated_at = MAX(timestamp).
    """
    rows = dict_rows("""
      SELECT c.display_name     AS category,
             e.sanitized_name   AS item,
             e.weight_per_unit  AS unit_weight_lbs,
             SUM(
               CASE
                 WHEN e.direction = 'in'  THEN  e.quantity
                 WHEN e.direction = 'out' THEN -e.quantity
               END
             )                   AS qty,
             MAX(e.timestamp)    AS updated_at
        FROM inventory_entries e
        JOIN inventory_categories c ON c.id = e.category_id
       WHERE e.pending = 0
       GROUP BY e.category_id, e.sanitized_name, e.weight_per_unit
       HAVING qty > 0
       ORDER BY c.display_name, e.sanitized_name, e.weight_per_unit
    """)
    out = []
    for r in rows:
        qty = int(r.get("qty") or 0)
        wpu = float(r.get("unit_weight_lbs") or 0.0)
        total = round(qty * wpu, 1)
        ts = r.get("updated_at")
        try:
            upd = iso8601_ceil_utc(datetime.fromisoformat(ts)) if ts else None
        except Exception:
            upd = iso8601_ceil_utc()
        out.append({
            "category": r.get("category") or "",
            "item": r.get("item") or "",
            "unit_weight_lbs": wpu,
            "qty": qty,
            "weight_lbs": total,
            "updated_at": upd,
        })
    return out

def netops_push_job():
    ok, base, station, pwd, interval, hours = _netops_enabled_cfg()
    if not ok:
        return
    if not _ensure_token(base, station, pwd):
        try: app.logger.warning("NetOps: login failed for station %s", station)
        except Exception: pass
        return
    default_origin, coords, inv_tick = _collect_station_meta()
    inventory = _collect_inventory()
    # derive a fallback ticker from item timestamps if app-level tick is missing
    if not inv_tick and inventory:
        inv_times = [i.get("updated_at") for i in inventory if i.get("updated_at")]
        inv_tick = max(inv_times) if inv_times else None
    payload = {
        "station": station,
        "generated_at": iso8601_ceil_utc(),
        "default_origin": default_origin,
        "origin_coords": coords,
        "inventory_last_update": inv_tick,
        "window_hours": hours,
        "flows": _collect_flows(hours),
        "manifests": _collect_manifests(hours),
        "inventory": inventory,
    }
    import requests  # ensure available at top of file; safe to keep here too
    url = f"{base.rstrip('/')}/api/ingest"
    headers = {"Accept": "application/json"}
    if _NETOPS_TOKEN:
        headers["Authorization"] = f"Bearer {_NETOPS_TOKEN}"

    # First attempt
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        code = r.status_code
        body = r.json() if r.headers.get("content-type","").startswith("application/json") else r.text
    except Exception as e:
        log_exception("netops_push_job POST error (first attempt)", e)
        return
    if code == 401:
        if _netops_login(base, station, pwd):
            headers = {"Accept": "application/json", "Authorization": f"Bearer {_NETOPS_TOKEN}"}
            r = requests.post(url, json=payload, headers=headers, timeout=10)
            code = r.status_code
            body = r.json() if r.headers.get("content-type","").startswith("application/json") else r.text
    if code and code >= 400:
        try: app.logger.warning("NetOps ingest error %s: %s", code, body)
        except Exception: pass

def configure_netops_feeders():
    """Install/refresh the periodic push job based on preferences."""
    enabled, base, station, pwd, interval, hours = _netops_enabled_cfg()
    try:
        scheduler.remove_job('netops_push')
    except Exception:
        pass
    if not enabled:
        return
    scheduler.add_job(
        id='netops_push',
        func=netops_push_job,
        trigger='interval',
        seconds=interval,
        replace_existing=True
    )
    if scheduler.state != STATE_RUNNING:
        scheduler.start()

# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: Inventory auto-broadcast (every minute; gated by preference)
# Prefs used:
#   • auto_broadcast_interval_min : int (0=off; else 15/30/60)
#   • airport_call_mappings       : lines "AAA: CALL1"
#   • default_origin              : our airport code (for subject/self-skip)
#   • winlink_callsign_1          : our WL callsign (self-skip)
#   • last_auto_broadcast_tick    : internal minute tick we last fired
# ─────────────────────────────────────────────────────────────────────────────
def _minute_tick(dt=None) -> str:
    if dt is None:
        dt = datetime.utcnow()
    dt = dt.replace(second=0, microsecond=0)
    return dt.isoformat() + "Z"

def _should_fire_broadcast_now() -> tuple[bool, str]:
    try:
        interval = int(float(get_preference('auto_broadcast_interval_min') or 0))
    except Exception:
        interval = 0
    if interval <= 0:
        return (False, "")
    now = datetime.utcnow()
    if (now.minute % interval) != 0:
        return (False, "")
    tick = _minute_tick(now)
    return ((get_preference('last_auto_broadcast_tick') or '') != tick, tick)

def inventory_auto_broadcast_job():
    try:
        should, tick = _should_fire_broadcast_now()
        if not should:
            return
        if not pat_config_exists():
            return
        # Build all-non-empty snapshot (no category filter)
        snapshot, human, csv_text = build_inventory_snapshot([])
        if not snapshot.get('rows'):
            set_preference('last_auto_broadcast_tick', tick)
            return
        # Recipients
        raw_map = (get_preference('airport_call_mappings') or '').strip()
        self_cs = (get_preference('winlink_callsign_1') or '').strip().upper()
        self_alias_canons = _self_alias_canons()
        mapping = {}
        for ln in raw_map.splitlines():
            if ':' not in ln:
                continue
            k, v = ln.split(':', 1)
            k = (k or '').strip().upper()
            v = (v or '').strip().upper()
            if k and v:
                mapping[k] = v
        recipients = []
        for ap, wl in mapping.items():
            ap_canon = canonical_airport_code(ap)
            # Skip our own airport by ANY alias (canonicalized), and skip our own callsign
            if (ap_canon and ap_canon in self_alias_canons) or wl == self_cs:
                continue
            recipients.append(wl)
        seen = set()
        recipients = [r for r in recipients if not (r in seen or seen.add(r))]
        if not recipients:
            set_preference('last_auto_broadcast_tick', tick)
            return
        subject = "AOCT cargo status"
        # csv_text already begins with "CSV\n"
        # ASCII-normalize only the human-readable portion for Winlink delivery.
        body_human_ascii = _wl_ascii(human)
        body = body_human_ascii + (("\n\n" + csv_text) if csv_text else "")
        # Honor Broadcast CC toggle: fan-out to CC addrs once total (not per recipient)
        cc_enabled = (get_preference('aoct_cc_broadcast') or 'no').strip().lower() == 'yes'
        targets = list(recipients)
        if cc_enabled:
            self_cs = (get_preference('winlink_callsign_1') or '').strip().upper()
            cc_raw = [
                (get_preference('winlink_cc_1') or '').strip().upper(),
                (get_preference('winlink_cc_2') or '').strip().upper(),
                (get_preference('winlink_cc_3') or '').strip().upper(),
            ]
            for cc in cc_raw:
                if not cc:
                    continue
                if cc == self_cs:
                    continue
                if cc not in seen:
                    seen.add(cc)
                    targets.append(cc)

        for to in targets:
            send_winlink_message(to, subject, body)
        set_preference('last_auto_broadcast_tick', tick)
    except Exception as e:
        try: app.logger.exception("inventory_auto_broadcast_job: %s", e)
        except Exception: pass

def configure_inventory_broadcast_job():
    try:
        scheduler.remove_job('inv_auto_broadcast')
    except JobLookupError:
        pass
    scheduler.add_job(
        id='inv_auto_broadcast',
        func=inventory_auto_broadcast_job,
        trigger='interval',
        minutes=1,
        replace_existing=True
    )
    if scheduler.state != STATE_RUNNING:
        scheduler.start()
