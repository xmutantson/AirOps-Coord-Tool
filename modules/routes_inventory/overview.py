
import sqlite3
import json
from datetime import datetime, timedelta, timezone
import logging

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from app import DB_FILE, publish_inventory_event, scheduler
from flask import jsonify, render_template, request, redirect, url_for, flash
from app import inventory_bp as bp  # reuse existing blueprint
from modules.utils.remote_inventory import ensure_remote_inventory_tables, build_inventory_snapshot
from modules.utils.remote_inventory import (
    ensure_remote_inventory_tables,
    build_inventory_snapshot,
    get_layered_remote_rows,
)
from modules.services.jobs import configure_inventory_broadcast_job
from modules.services.winlink.core import pat_config_status, send_winlink_message

# Logger for this module
logger = logging.getLogger(__name__)

# --- local helper: round overview rows to one decimal everywhere ----------
def _round_overview_rows(rows: list[dict]) -> list[dict]:
    for r in rows:
        for k in ("total_in", "total_out", "net", "rate_in", "rate_out"):
            try:
                r[k] = round(float(r.get(k, 0) or 0.0), 1)
            except Exception:
                r[k] = 0.0
    return rows

# Optional Wargame reconciler: import with a no-op fallback so
# /inventory commits never 500 if the service isn't available.
try:
    from modules.services.wargame import reconcile_inventory_batches  # type: ignore
except Exception:
    def reconcile_inventory_batches(*_args, **_kwargs):
        return None

@bp.route('/_advance_data')
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

@bp.route('/_advance_line', methods=['POST'])
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
            try:
                reconcile_inventory_batches(mid)
            except Exception as exc:
                # Never block operator flow on a scoring hook
                logger.debug(
                    "reconcile_inventory_batches failed for session %s: %s",
                    mid, exc
                )
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

@bp.route('/')
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

    mass_pref = request.cookies.get('mass_unit','lbs')
    if mass_pref == 'kg':
        for item in overview:
            # stored totals are in pounds → convert to kg
            item['total_in']  = item['total_in']  / 2.20462
            item['total_out'] = item['total_out'] / 2.20462
            item['net']       = item['net']       / 2.20462
            item['rate_in']   = item['rate_in']   / 2.20462
            item['rate_out']  = item['rate_out']  / 2.20462
    # enforce one-decimal everywhere (lbs or kg)
    overview = _round_overview_rows(overview)
    # pass skeleton page only; table will come from AJAX
    return render_template(
        'inventory_overview.html',
        active='inventory'
    )

@bp.route('/_overview_table')
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
            row['total_in']  = row['total_in']  / 2.20462
            row['total_out'] = row['total_out'] / 2.20462
            row['net']       = row['net']       / 2.20462
            row['rate_in']   = row['rate_in']   / 2.20462
            row['rate_out']  = row['rate_out']  / 2.20462
    # enforce one-decimal everywhere (lbs or kg)
    overview = _round_overview_rows(overview)

    return render_template(
        'partials/_inventory_overview_table.html',
        inventory=overview,
        mass_pref=mass_pref
    )

@bp.route('/_detail_table')
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

    # Preserve raw lbs for client-side propagation UI *before* any unit conversion
    for e in entries:
        try:
            e['wpu_lbs'] = float(e.get('weight_per_unit') or 0.0)
        except Exception:
            e['wpu_lbs'] = 0.0

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

# ──────────────────────────────────────────────────────────────
# Remote Airports viewer + Broadcast (scaffold routes)
# Base path: /inventory (blueprint mount) → /inventory/remote, /inventory/broadcast
# ──────────────────────────────────────────────────────────────

@bp.route('/remote')
def remote_airports():
    """List remote airports with latest snapshot summary."""
    ensure_remote_inventory_tables()
    rows = dict_rows("""
      WITH latest AS (
        SELECT airport, MAX(generated_at) AS g
          FROM remote_inventory_rows
         GROUP BY airport
      )
      SELECT r.airport,
             r.generated_at,
             COUNT(*) AS rows,
             COALESCE(SUM(r.total_weight_lb),0) AS total_lb
        FROM remote_inventory_rows r
        JOIN latest l
          ON l.airport = r.airport AND l.g = r.generated_at
       GROUP BY r.airport, r.generated_at
       ORDER BY r.airport
    """)
    return render_template(
        'remote_airports.html',
        airports=rows,
        active='inventory'
    )

@bp.route('/remote/<string:airport>/clear', methods=['POST'])
def remote_airport_clear(airport):
    """Delete stored snapshot for a remote airport (rows + last-snapshot meta), then return to overview."""
    ensure_remote_inventory_tables()
    a = canonical_airport_code(airport)
    if not a:
        return jsonify(success=False, message="Invalid airport code"), 400
    with sqlite3.connect(DB_FILE) as c:
        c.execute("DELETE FROM remote_inventory_rows WHERE airport=?", (a,))
        c.execute("DELETE FROM remote_inventory WHERE airport_canon=?", (a,))
        c.commit()
    try:
        flash(f"Cleared remote snapshot for {a}.")
    except Exception:
        pass
    return redirect(url_for('inventory.remote_airports'))

@bp.route('/remote/<string:airport>')
def remote_airport_detail(airport):
    """Detail view for a single remote airport's latest snapshot."""
    ensure_remote_inventory_tables()
    a = canonical_airport_code(airport)
    # Also load airports for dropdown
    airports = dict_rows("""
      WITH latest AS (
        SELECT airport, MAX(generated_at) AS g
          FROM remote_inventory_rows
         GROUP BY airport
      )
      SELECT r.airport, r.generated_at
        FROM remote_inventory_rows r
        JOIN latest l ON l.airport=r.airport AND l.g=r.generated_at
       GROUP BY r.airport
       ORDER BY r.airport
    """)
    # Layered rows: per-category latest (prevents partial replies from wiping other cats)
    rows, meta = get_layered_remote_rows(a)
    # Prefer the most recent "full" time; else fall back to newest per-category time we have.
    gen = (meta.get('last_full_at') or '') if isinstance(meta, dict) else ''
    if not gen and rows:
        try:
            gen = max((r.get('updated_at') or r.get('generated_at') or '') for r in rows)
        except Exception:
            gen = rows[0].get('updated_at') or rows[0].get('generated_at') or ''
    # Age text (for last full update): floor minutes, XhYm
    age_txt = ''
    if gen:
        # Parse to a UTC-aware datetime, accepting common variants.
        txt = (gen or '').strip()
        gdt = None
        try:
            # Normalize “Z”/“ UTC” → +00:00 for fromisoformat()
            iso = txt.replace(' UTC', '')
            if iso.endswith('Z'):
                iso = iso[:-1] + '+00:00'
            # Accept both " " and "T" between date/time.
            gdt = datetime.fromisoformat(iso)
        except Exception:
            # Fallbacks without tz → assume UTC
            for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M'):
                try:
                    gdt = datetime.strptime(txt.replace(' UTC','').replace('Z',''), fmt)
                    break
                except Exception:
                    continue
        if gdt:
            # Ensure timezone awareness (UTC)
            if gdt.tzinfo is None:
                gdt = gdt.replace(tzinfo=timezone.utc)
            else:
                gdt = gdt.astimezone(timezone.utc)
            delta = datetime.now(timezone.utc) - gdt
            mins = int(max(0, delta.total_seconds() // 60))
            hrs, rem = divmod(mins, 60)
            age_txt = (f"{hrs}h{rem:02d}m" if hrs else f"{rem}m")
    return render_template(
        'remote_airports.html',
        airports=airports,
        detail_rows=rows,
        detail_airport=a,
        detail_generated_at=gen,          # last full or newest per-cat
        detail_last_full_at=gen,          # alias for templates
        detail_meta=meta,                 # may include per-category times
        detail_age_text=age_txt,
        active='inventory'
    )

@bp.route('/_remote_dropdown')
def remote_dropdown():
    """HTML <select> of airports that have a latest snapshot (latest only)."""
    ensure_remote_inventory_tables()
    airports = dict_rows("""
      SELECT airport, MAX(generated_at) AS generated_at
        FROM remote_inventory_rows
       GROUP BY airport
       ORDER BY airport
    """)
    return render_template(
        'partials/_remote_dropdown.html',
        airports=airports
    )

@bp.route('/_remote_table')
def remote_table():
    """
    Render the latest snapshot table for a given airport.
    Query param: ?airport=KELN
    """
    ensure_remote_inventory_tables()
    a = canonical_airport_code(request.args.get('airport','') or '')
    rows = []
    if a:
        rows, meta = get_layered_remote_rows(a)
        gen = (meta.get('last_full_at') or '') if isinstance(meta, dict) else ''
        if not gen and rows:
            try:
                gen = max((r.get('updated_at') or r.get('generated_at') or '') for r in rows)
            except Exception:
                gen = rows[0].get('updated_at') or rows[0].get('generated_at') or ''
    return render_template(
        'partials/_remote_table.html',
        rows=rows,
        airport=a,
        generated_at=(gen if a else '')
    )

@bp.route('/broadcast')
def inventory_broadcast():
    """Broadcast page with previews and soft warnings."""
    try:
        cur = int(float(get_preference('auto_broadcast_interval_min') or 0))
    except Exception:
        cur = 0
    # Soft warnings
    warnings = []
    pat_ok, pat_path, pat_reason = pat_config_status()
    if not pat_ok:
        warnings.append("PAT is not configured; auto-broadcast will be skipped.")
    raw_map = (get_preference('airport_call_mappings') or '').strip()
    self_ap = (get_preference('default_origin') or '').strip().upper()
    self_cs = (get_preference('winlink_callsign_1') or '').strip().upper()
    recipients = []
    seen = set()
    for ln in raw_map.splitlines():
        if ':' not in ln:
            continue
        ap, wl = (x.strip().upper() for x in ln.split(':', 1))
        if not ap or not wl:
            continue
        if ap == self_ap or wl == self_cs:
            continue
        if wl not in seen:
            seen.add(wl)
            recipients.append(wl)
    if not recipients:
        warnings.append("No recipients found in Preferences → airport_call_mappings.")
    return render_template('inventory_broadcast.html',
                           current_interval=cur,
                           broadcast_warnings=warnings,
                           recipient_count=len(recipients),
                           recipients=recipients,
                           active='inventory')

@bp.route('/broadcast/preview', methods=['POST'])
def broadcast_preview():
    """
    Return current inventory snapshot previews.
    Body: kind = human|csv|both  (optional; returns all fields regardless)
    """
    # Build "all non-empty" snapshot (no category filter)
    snapshot, human, csv_text = build_inventory_snapshot([])
    # Ensure CSV block is present as spec ("CSV\\n..." already included)
    return jsonify({
        "human": human or "",
        "csv":   (csv_text or "").strip(),
        "both":  ((human or "") + ("\n\n" + (csv_text or "") if csv_text else "")).strip()
    })

@bp.route('/broadcast/schedule', methods=['POST'])
def broadcast_schedule():
    """
    Update auto-broadcast cadence and re-arm job.
    Body: interval = 0|15|30|60
    """
    iv = request.form.get('interval', '0').strip()
    try:
        iv_int = int(float(iv))
    except Exception:
        iv_int = 0
    if iv_int not in (0, 15, 30, 60):
        return jsonify(success=False, message="Invalid interval"), 400
    set_preference('auto_broadcast_interval_min', str(iv_int))
    try:
        configure_inventory_broadcast_job()
    except Exception as e:
        # Save succeeded even if scheduler refresh fails; report soft error.
        try: logger.warning("configure_inventory_broadcast_job failed: %s", e)
        except Exception: pass
    return jsonify(success=True, interval=iv_int)

@bp.route('/broadcast/test', methods=['POST'])
def broadcast_test_send():
    """
    Send a one-off AOCT cargo status to our own callsign for testing.
    Guards:
      • PAT must be configured
      • WinLink polling job must be running (so outbox/inbox flow is alive)
    """
    # 1) PAT config
    pat_ok, pat_path, pat_reason = pat_config_status()
    if not pat_ok:
        return jsonify(success=False, message=f"PAT is not configured: {pat_reason or 'unknown'}"), 400
    # 2) Polling job guard
    try:
        wl_job = scheduler.get_job('winlink_poll')
    except Exception:
        wl_job = None
    if not wl_job:
        return jsonify(success=False, message="WinLink polling is not running. Start it on the Radio page first."), 400
    # 3) Build current snapshot (all non-empty categories)
    snapshot, human, csv_text = build_inventory_snapshot([])
    if not snapshot.get('rows'):
        return jsonify(success=False, message="No inventory rows to broadcast."), 400
    subject = "AOCT cargo status"
    body = (human or "") + (("\n\n" + (csv_text or "")) if csv_text else "")
    # 4) Resolve “self” address
    to_addr = (get_preference('winlink_callsign_1') or '').strip().upper()
    if not to_addr:
        return jsonify(success=False, message="No WinLink callsign configured in Preferences."), 400
    # 5) Send via PAT
    ok = send_winlink_message(to_addr, subject, body)
    if not ok:
        return jsonify(success=False, message="PAT send failed."), 502
    return jsonify(success=True, to=to_addr)

# ──────────────────────────────────────────────────────────────
# Manual “Send now” — broadcast current snapshot to all recipients,
# honoring the Broadcast CC toggle (fan-out once total).
# Body: (none)  → JSON {success, total, sent, failed:[...]}
# ──────────────────────────────────────────────────────────────
@bp.route('/broadcast/send_now', methods=['POST'])
def broadcast_send_now():
    # 1) PAT must be configured
    pat_ok, _, reason = pat_config_status()
    if not pat_ok:
        return jsonify(success=False, message=f"PAT is not configured: {reason or 'unknown'}"), 400

    # 2) Build snapshot; bail if empty
    snapshot, human, csv_text = build_inventory_snapshot([])
    if not snapshot.get('rows'):
        return jsonify(success=False, message="No inventory rows to broadcast."), 400
    subject = "AOCT cargo status"
    body = (human or "") + (("\n\n" + (csv_text or "")) if csv_text else "")

    # 3) Resolve recipients from preferences (skip our own)
    raw_map = (get_preference('airport_call_mappings') or '').strip()
    self_ap = (get_preference('default_origin') or '').strip().upper()
    self_cs = (get_preference('winlink_callsign_1') or '').strip().upper()
    recipients = []
    seen = set()
    for ln in raw_map.splitlines():
        if ':' not in ln:
            continue
        ap, wl = (x.strip().upper() for x in ln.split(':', 1))
        if not ap or not wl:
            continue
        if ap == self_ap or wl == self_cs:
            continue
        if wl not in seen:
            seen.add(wl)
            recipients.append(wl)
    total = len(recipients)
    if total == 0:
        return jsonify(success=False, message="No recipients found in Preferences."), 400

    # 4) Optionally include CC fan-out (once total, not per-recipient)
    cc_enabled = (get_preference('aoct_cc_broadcast') or 'no').strip().lower() == 'yes'
    targets = list(recipients)  # start with primary recipients
    if cc_enabled:
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

    # 5) Send to each via PAT (fan-out)
    sent = 0
    failed = []
    for wl in targets:
        try:
            if send_winlink_message(wl, subject, body):
                sent += 1
            else:
                failed.append(wl)
        except Exception as exc:
            try: logger.exception("Broadcast send to %s failed: %s", wl, exc)
            except Exception: pass
            failed.append(wl)

    ok = (sent > 0)
    return jsonify(
        success=ok,
        total=len(targets),
        sent=sent,
        failed=failed
    )

# ──────────────────────────────────────────────────────────────
# AOCT outbound query – operator compose + send
# ──────────────────────────────────────────────────────────────
@bp.route('/aoct_query')
def aoct_query():
    """Render a simple compose UI for sending an AOCT cargo query."""
    pat_ok, _, _ = pat_config_status()
    # surface a tiny helper map for hinting To: when Airport is filled
    raw_map = (get_preference('airport_call_mappings') or '').strip()
    hint_map = {}
    for ln in raw_map.splitlines():
        if ':' not in ln: continue
        ap, wl = (x.strip().upper() for x in ln.split(':', 1))
        if ap and wl: hint_map[ap] = wl
    return render_template('inventory_query.html',
                           can_send=bool(pat_ok),
                           map_json=json.dumps(hint_map),
                           active='inventory')

@bp.route('/aoct_query/send', methods=['POST'])
def aoct_query_send():
    """Accept form post and send an AOCT cargo query via PAT."""
    to_addr   = (request.form.get('to') or '').strip().upper()
    airport   = canonical_airport_code((request.form.get('airport') or '').strip().upper())
    cats_raw  = (request.form.get('categories') or '').strip()
    wants_csv = (request.form.get('csv') or 'yes').strip().lower() != 'no'

    if not to_addr:
        return jsonify(success=False, message="Missing destination callsign"), 400
    if not airport:
        return jsonify(success=False, message="Missing airport code"), 400
    pat_ok, _, reason = pat_config_status()
    if not pat_ok:
        return jsonify(success=False, message=f"PAT not configured: {reason or 'unknown'}"), 400

    # Build the canonical query body
    lines = [f"AIRPORT: {airport}"]
    cats = [s.strip() for s in cats_raw.split(",") if s.strip()]
    if cats:
        lines.append("CATEGORIES: " + ", ".join(cats))
    lines.append("CSV: " + ("yes" if wants_csv else "no"))
    subject = "AOCT cargo query"
    body    = "\n".join(lines)

    ok = send_winlink_message(to_addr, subject, body)
    if not ok:
        return jsonify(success=False, message="PAT send failed."), 502
    return jsonify(success=True)
