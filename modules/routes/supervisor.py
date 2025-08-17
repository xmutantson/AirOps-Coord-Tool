
import sqlite3
from datetime import datetime, timedelta
import time

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from app import DB_FILE
from flask import Blueprint, current_app
from flask import render_template, request
bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)
app = current_app  # legacy shim if route body references 'app'

@bp.route('/supervisor')
def supervisor():
    """Supervisor dashboard showing counts, recent flights, and inventory."""
    return render_template('supervisor.html', active='supervisor')

@bp.route('/_supervisor_counts')
def supervisor_counts_partial():
    """AJAX partial: counts of inbound, outbound, other, and queued flights.

    Logic:
      - If default_origin is set, treat any flight with airfield_takeoff ∈ aliases(origin) as OUTBOUND,
        any with airfield_landing ∈ aliases(origin) as INBOUND, otherwise OTHER. (complete=0 only)
      - If default_origin is not set, fall back to the existing direction field.
    """
    origin = (get_preference('default_origin') or '').strip().upper()
    inbound_cnt = outbound_cnt = other_cnt = 0

    if origin:
        aliases = set(a.strip().upper() for a in airport_aliases(origin))
        rows = dict_rows("""
            SELECT airfield_takeoff, airfield_landing
              FROM flights
             WHERE complete = 0
        """)
        for r in rows:
            dep = (r.get('airfield_takeoff') or '').strip().upper()
            arr = (r.get('airfield_landing')   or '').strip().upper()
            if dep in aliases and arr in aliases:
                other_cnt += 1
            elif dep in aliases:
                outbound_cnt += 1
            elif arr in aliases:
                inbound_cnt += 1
            else:
                other_cnt += 1
    else:
        inbound_cnt  = dict_rows("SELECT COUNT(*) AS c FROM flights WHERE direction='inbound'  AND complete=0")[0]['c'] or 0
        outbound_cnt = dict_rows("SELECT COUNT(*) AS c FROM flights WHERE direction='outbound' AND complete=0")[0]['c'] or 0
        other_cnt    = dict_rows("SELECT COUNT(*) AS c FROM flights WHERE complete=0 AND IFNULL(direction,'') NOT IN ('inbound','outbound')")[0]['c'] or 0

    queued_cnt = dict_rows("SELECT COUNT(*) AS c FROM queued_flights")[0]['c'] or 0

    return render_template(
        'partials/_supervisor_counts.html',
        inbound=inbound_cnt, outbound=outbound_cnt, other=other_cnt, queued=queued_cnt
    )

@bp.route('/_supervisor_recent_flights')
def supervisor_recent_flights_partial():
    """AJAX partial: table of recent active flights."""
    show_dist = bool(app.extensions.get('distances')) and app.extensions.get('recv_loc') is not None
    unit = request.cookies.get('distance_unit','nm')
    rows = []
    raw_rows = dict_rows("""
        SELECT
          id,
          tail_number,
          airfield_takeoff,
          airfield_landing,
          COALESCE(takeoff_time,'----') AS departure,
          COALESCE(eta,'----') AS arrival,
          cargo_weight,
          is_ramp_entry,
          sent,
          complete
        FROM flights
        WHERE complete = 0
        ORDER BY id DESC
        LIMIT 6
    """)
    for r in raw_rows:
        # Add NM distance if enabled and available, using same logic as dashboard
        if show_dist:
            entry = app.extensions['distances'].get(r['tail_number'])
            if entry is not None:
                km_val, ts = entry
                if unit=='mi':
                    val = round(km_val * 0.621371, 1)
                elif unit=='nm':
                    val = round(km_val * 0.539957, 1)
                else:
                    val = round(km_val, 1)
                r['distance'] = val
                r['distance_stale'] = (time.time() - ts) > 300
            else:
                r['distance'] = ''
                r['distance_stale'] = False
        else:
            r['distance'] = ''
            r['distance_stale'] = False
        rows.append(r)
    return render_template(
        'partials/_supervisor_recent_flights.html',
        flights=rows,
        enable_1090_distances=show_dist,
        distance_unit=unit
    )

@bp.route('/_supervisor_inventory')
def supervisor_inventory_partial():
    """AJAX partial: slim inventory overview for supervisor."""
    # replicate inventory overview logic (2h window, mass unit)
    cutoff = (datetime.utcnow() - timedelta(hours=2)).isoformat()
    inv = []
    with sqlite3.connect(DB_FILE) as c:
        cats = c.execute("SELECT id, display_name FROM inventory_categories").fetchall()
        for cid, disp in cats:
            ents = c.execute(
                "SELECT direction, total_weight, timestamp FROM inventory_entries WHERE category_id=?",
                (cid,)
            ).fetchall()
            tot_in  = sum(e[1] for e in ents if e[0]=='in')
            tot_out = sum(e[1] for e in ents if e[0]=='out')
            recent  = [e for e in ents if e[2] >= cutoff]
            in2h    = sum(e[1] for e in recent if e[0]=='in')
            out2h   = sum(e[1] for e in recent if e[0]=='out')
            inv.append({
                'category': disp,
                'net':       tot_in - tot_out,
                'rate_in':   round(in2h / 2, 1),
                'rate_out':  round(out2h / 2, 1)
            })
    mass_pref = request.cookies.get('mass_unit','lbs')
    if mass_pref == 'kg':
        for row in inv:
            row['net']      = round(row['net']    / 2.20462, 1)
            row['rate_in']  = round(row['rate_in']/ 2.20462, 1)
            row['rate_out'] = round(row['rate_out']/2.20462, 1)
    return render_template(
        'partials/_supervisor_inventory.html',
        inventory=inv,
        mass_pref=mass_pref
    )
