from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, session, jsonify
from modules.utils.common import dict_rows, get_preference

bp = Blueprint('wginventory', __name__)

@bp.route('/wargame/inventory')
def wargame_inventory_dashboard():
    # Wargame must be on
    if get_preference('wargame_mode') != 'yes':
        return redirect(url_for('core.dashboard'))
    # Only Inventory role
    if session.get('wargame_role') != 'inventory':
        return redirect(url_for('wgindex.wargame_index'))

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

    def lines_for(bid: int):
        return dict_rows("""
          SELECT name, size_lb, qty_required, qty_done
            FROM wargame_inventory_batch_items
           WHERE batch_id=?
        """, (bid,))

    # compute last inventory timestamp from entries (fallback to now)
    ts_row = dict_rows("""
      SELECT COALESCE(MAX(timestamp), '') AS ts
        FROM inventory_entries
    """)[0]
    last_ts = ts_row['ts'] or datetime.utcnow().isoformat()

    return render_template(
        'wargame_inventory.html',
        incoming_deliveries=[{**b, 'lines': lines_for(b['id'])} for b in incoming_deliveries],
        outgoing_requests=[{**b, 'lines': lines_for(b['id'])} for b in outgoing_requests],
        last_inventory_timestamp=last_ts,
        active='wargame'
    )

@bp.route('/wargame/inventory/last_update')
def wargame_inventory_last_update():
    # Track changes driven by *either* new inventory entries or batch completion.
    row = dict_rows("""
      SELECT COALESCE(MAX(ts), '') AS ts
        FROM (
          SELECT MAX(timestamp)   AS ts FROM inventory_entries
          UNION ALL
          SELECT MAX(satisfied_at) AS ts FROM wargame_inventory_batches
        )
    """)[0]
    ts = row['ts'] or datetime.utcnow().isoformat()
    return jsonify(timestamp=ts)
