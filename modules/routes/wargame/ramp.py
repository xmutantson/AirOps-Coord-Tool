

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from flask import Blueprint, current_app
from flask import redirect, render_template, session, url_for
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

@bp.route('/wargame/ramp')
def wargame_ramp_dashboard():
    wm = dict_rows("SELECT value FROM preferences WHERE name='wargame_mode'")
    if not (wm and wm[0]['value']=='yes'):
        return redirect(url_for('core.dashboard'))

    # only the “ramp” role may visit; everyone else bounces to /wargame
    if session.get('wargame_role') != 'ramp':
        return redirect(url_for('wgindex.wargame_index'))

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
