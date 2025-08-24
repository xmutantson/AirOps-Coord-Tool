import random

import uuid
import sqlite3, os, json
from datetime import datetime, timedelta
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
)
from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from modules.utils.common import _is_winlink_reflector_bounce
from app import DB_FILE, scheduler
from flask import current_app
app = current_app  # legacy shim for helpers

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
        dest = f['airfield_landing'].upper()
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

        to_addr = mapping.get(dest)
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
      SELECT id, callsign, subject, body, timestamp
        FROM winlink_messages
       WHERE direction='in' AND parsed=0
    """)

    for m in msgs:
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

        # run your existing parser
        parsed_data = parse_winlink(m['subject'], m['body'])

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

def netops_push_job():
    ok, base, station, pwd, interval, hours = _netops_enabled_cfg()
    if not ok:
        return
    if not _ensure_token(base, station, pwd):
        try: app.logger.warning("NetOps: login failed for station %s", station)
        except Exception: pass
        return
    default_origin, coords, inv_tick = _collect_station_meta()
    payload = {
        "station": station,
        "generated_at": iso8601_ceil_utc(),
        "default_origin": default_origin,
        "origin_coords": coords,
        "inventory_last_update": inv_tick,
        "window_hours": hours,
        "flows": _collect_flows(hours),
        "manifests": _collect_manifests(hours),
    }
    url = f"{base.rstrip('/')}/api/ingest"
    headers = {"Authorization": f"Bearer {_NETOPS_TOKEN}"} if _NETOPS_TOKEN else {}
    code, body = http_post_json(url, payload, headers=headers)
    if code == 401:
        if _netops_login(base, station, pwd):
            headers = {"Authorization": f"Bearer {_NETOPS_TOKEN}"}
            code, body = http_post_json(url, payload, headers=headers)
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
