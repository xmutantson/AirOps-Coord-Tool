
import json
from datetime import datetime, timedelta

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from flask import Blueprint, current_app
from flask import redirect, render_template, session, url_for
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

@bp.route('/wargame/super')
def wargame_super_dashboard():
    wm = dict_rows("SELECT value FROM preferences WHERE name='wargame_mode'")
    if not (wm and wm[0]['value']=='yes'):
        return redirect(url_for('core.dashboard'))

    # only the “super” role may visit; everyone else bounces to /wargame
    if session.get('wargame_role') != 'super':
        return redirect(url_for('wgindex.wargame_index'))

    # 1) per‑role delay metrics
    metrics = {}
    for role in ('radio','ramp','inventory'):
        row = dict_rows("""
            SELECT
              AVG(delta_seconds) AS avg,
              MIN(delta_seconds) AS min,
              MAX(delta_seconds) AS max
            FROM wargame_metrics
           WHERE event_type=?
        """, (role,))[0]
        metrics[role] = {
          'avg': round(row['avg'] or 0,2),
          'min': row['min'] or 0,
          'max': row['max'] or 0
        }

    # 2) throughput over the past hour
    cutoff = (datetime.utcnow() - timedelta(hours=1)).isoformat()

    # 2a) ramp boss entries in the last hour (all inbound & outbound)
    frow = dict_rows("""
      SELECT COUNT(*) AS cnt
        FROM flights
       WHERE is_ramp_entry=1
         AND timestamp >= ?
    """, (cutoff,))[0]
    aircraft_entries_per_hour = frow['cnt'] or 0

    # 2b) total cargo weight entered by ramp boss in the last hour
    crow = dict_rows("""
      SELECT SUM(
               COALESCE(cargo_weight_real,
                        CASE
                          WHEN cargo_weight LIKE '%lb%' THEN CAST(REPLACE(REPLACE(cargo_weight,' lbs',''),' lb','') AS REAL)
                          ELSE CAST(cargo_weight AS REAL)
                        END)
             ) AS sum_wt
        FROM flights
       WHERE is_ramp_entry=1
         AND timestamp >= ?
    """, (cutoff,))[0]
    air_cargo_entries_per_hour = round(crow['sum_wt'] or 0, 1)

    stats = {
      'aircraft_entries_per_hour': aircraft_entries_per_hour,
      'air_cargo_entries_per_hour': air_cargo_entries_per_hour
    }

    # 3) read‑only difficulty settings
    js = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
    settings = json.loads(js[0]['value']) if js else {}

    return render_template(
      'wargame_super.html',
      metrics=metrics,
      stats=stats,
      settings=settings,
      active='wargame'
    )
