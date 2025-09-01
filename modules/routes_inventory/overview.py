
import sqlite3
from datetime import datetime, timedelta
import logging

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from app import DB_FILE, publish_inventory_event
from flask import jsonify, render_template, request
from app import inventory_bp as bp  # reuse existing blueprint

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
