

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from flask import render_template, request
from app import inventory_bp as bp  # reuse existing blueprint
@bp.route('/stock')
@bp.route('/stock')
def inventory_stock():
    """
    “What’s on the shelf right now” view – grouped by category, collapsed by
    default.  Inside each category the rows are already ordered by
    sanitized name then package size (small→large).
    """
    rows = dict_rows("""
      SELECT c.display_name AS category,
             e.sanitized_name      AS noun,
             e.weight_per_unit     AS wpu,
             SUM(CASE
                   WHEN e.direction='in'  THEN  e.quantity
                   WHEN e.direction='out' THEN -e.quantity
                 END)               AS qty
        FROM inventory_entries e
        JOIN inventory_categories c ON c.id = e.category_id
       WHERE e.pending = 0
       GROUP BY e.category_id, e.sanitized_name, e.weight_per_unit
       HAVING qty > 0
       ORDER BY c.display_name, e.sanitized_name, e.weight_per_unit
    """)

    # Look up barcodes for each item
    barcode_map = {}
    try:
        bc_rows = dict_rows("""
            SELECT sanitized_name, weight_per_unit, barcode
              FROM inventory_barcodes
             WHERE (deleted=0 OR deleted IS NULL)
        """)
        for br in bc_rows:
            key = f"{br['sanitized_name']}|{br['weight_per_unit']:.4f}"
            barcode_map[key] = br['barcode']
    except Exception:
        pass

    stock = {}
    for r in rows:
        cat = r['category']
        key = f"{r['noun']}|{r['wpu']:.4f}"
        entry = {
          'noun' : r['noun'],
          'size' : r['wpu'],
          'wpu_lbs': r['wpu'],
          'qty'  : r['qty'],
          'total': r['wpu'] * r['qty'],
          'barcode': barcode_map.get(key, ''),
        }
        stock.setdefault(cat, []).append(entry)

    # honour kg / lbs preference
    mass_pref = request.cookies.get('mass_unit','lbs')
    if mass_pref == 'kg':
        for items in stock.values():
            for ent in items:
                ent['size']  = round(ent['size']  / 2.20462, 1)
                ent['total'] = round(ent['total'] / 2.20462, 1)
    else:
        for items in stock.values():
            for ent in items:
                ent['size']  = round(float(ent['size']  or 0), 1)
                ent['total'] = round(float(ent['total'] or 0), 1)

    return render_template(
        'inventory_stock.html',
        stock     = stock,
        mass_pref = mass_pref,
        active    = 'inventory'
    )
