# rebuilt clean by fix_inventory_routes_rewrite.py
import sqlite3
from datetime import datetime

from modules.utils.common import *  # dict_rows, prefs, units, sanitize_name, etc.
from app import DB_FILE, publish_inventory_event
from flask import flash, jsonify, redirect, render_template, request, session, url_for
from app import inventory_bp as bp  # blueprint

@bp.route("/detail", methods=["GET", "POST"])
def inventory_detail():
    if request.method == "POST":
        # ---- Extract & normalize form fields ----
        cat_id       = int(request.form["category"])
        raw          = request.form["name"]
        noun         = sanitize_name(raw)
        weight_val   = float(request.form.get("weight") or 0)
        weight_unit  = request.form.get("weight_unit", "lbs")
        session["inv_weight_unit"] = weight_unit
        if weight_unit == "kg":
            wpu_lbs = kg_to_lbs(weight_val)
        else:
            wpu_lbs = weight_val
        qty   = int(request.form.get("qty") or 0)
        total = wpu_lbs * qty
        dirn  = request.form["direction"]  # 'in' or 'out'
        session["inv_direction"] = dirn
        ts    = datetime.utcnow().isoformat()

        # ---- Enforce no overdraw on OUTBOUND ----
        if dirn == "out":
            row = dict_rows(
                """
                SELECT
                  COALESCE(SUM(
                    CASE WHEN direction='in'  THEN quantity
                         WHEN direction='out' THEN -quantity
                    END
                  ), 0) AS avail
                  FROM inventory_entries
                 WHERE (pending IS NULL OR pending=0)
                   AND category_id=?
                   AND sanitized_name=?
                   AND ABS(weight_per_unit - ?) < 0.001
                """,
                (cat_id, noun, wpu_lbs),
            )[0]
            on_hand = row["avail"] or 0

            if qty > on_hand:
                msg = f"Cannot exceed available qty ({on_hand})"
                # AJAX path
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify({"message": msg}), 400

                # Non-AJAX: flash + re-render with advanced_data rebuilt
                flash(msg, "error")
                categories = dict_rows("SELECT id, display_name FROM inventory_categories")
                cats = dict_rows(
                    """
                    SELECT id AS cid, display_name AS cname
                      FROM inventory_categories
                     ORDER BY display_name
                    """
                )
                advanced_data = {
                    "all_categories": [
                        {"id": str(c["cid"]), "display_name": c["cname"]} for c in cats
                    ],
                    "stock_categories": [],
                    "items": {},
                    "sizes": {},
                    "avail": {},
                }
                rows = dict_rows(
                    """
                    SELECT category_id AS cid,
                           sanitized_name,
                           weight_per_unit,
                           SUM(
                             CASE WHEN direction='in'  THEN quantity
                                  WHEN direction='out' THEN -quantity
                             END
                           ) AS qty
                      FROM inventory_entries
                     WHERE pending=0
                     GROUP BY category_id, sanitized_name, weight_per_unit
                     HAVING qty>0
                    """
                )
                for r in rows:
                    cid = str(r["cid"])
                    # availability
                    advanced_data["avail"].setdefault(cid, {}) \
                        .setdefault(r["sanitized_name"], {})[str(r["weight_per_unit"])] = r["qty"]
                    # items & sizes
                    advanced_data["items"].setdefault(cid, []).append(r["sanitized_name"])
                    advanced_data["sizes"].setdefault(cid, {}) \
                        .setdefault(r["sanitized_name"], []).append(str(r["weight_per_unit"]))
                    # stock-only categories
                    if not any(c["id"] == cid for c in advanced_data["stock_categories"]):
                        name = next((c["cname"] for c in cats if str(c["cid"]) == cid), "")
                        advanced_data["stock_categories"].append(
                            {"id": cid, "display_name": name}
                        )

                return render_template(
                    "inventory_detail.html",
                    initial_direction=session.get("inv_direction", "inbound"),
                    categories=categories,
                    inv_weight_unit=session.get(
                        "inv_weight_unit", request.cookies.get("mass_unit", "lbs")
                    ),
                    active="inventory",
                    advanced_data=advanced_data,
                    form_data=request.form,
                )

        # ---- Insert entry ----
        with sqlite3.connect(DB_FILE) as c:
            cur = c.execute(
                """
                INSERT INTO inventory_entries(
                    category_id, raw_name, sanitized_name,
                    weight_per_unit, quantity, total_weight,
                    direction, timestamp
                ) VALUES (?,?,?,?,?,?,?,?)
                """,
                (cat_id, raw, noun, wpu_lbs, qty, total, dirn, ts),
            )
            eid = cur.lastrowid

        # ---- Wargame reconciliation (lazy import; non-blocking) ----
        try:
            if get_preference("wargame_mode") == "yes":
                # Import here to avoid circulars and make failures visible in logs.
                from modules.services.wargame import reconcile_inventory_entry as _reconcile_inventory_entry
                _reconcile_inventory_entry(int(eid))
        except Exception as e:
            # Never block operator flow, but *do* surface why reconciliation didn't run.
            logger.warning("Wargame reconcile failed for entry %s: %s", eid, e)

        # ---- Notify dashboards (non-blocking) ----
        try:
            publish_inventory_event()
        except Exception:
            pass

        return redirect(url_for("inventory.inventory_detail"))

    # ---- GET: build categories + advanced_data for initial render ----
    categories = dict_rows("SELECT id, display_name FROM inventory_categories")

    cats = dict_rows(
        """
        SELECT id AS cid, display_name AS cname
          FROM inventory_categories
         ORDER BY display_name
        """
    )
    advanced_data = {
        "all_categories": [
            {"id": str(c["cid"]), "display_name": c["cname"]} for c in cats
        ],
        "stock_categories": [],
        "items": {},
        "sizes": {},
        "avail": {},
    }
    rows = dict_rows(
        """
        SELECT category_id AS cid,
               sanitized_name,
               weight_per_unit,
               SUM(
                 CASE WHEN direction='in'  THEN quantity
                      WHEN direction='out' THEN -quantity
                 END
               ) AS qty
          FROM inventory_entries
         WHERE pending=0
         GROUP BY category_id, sanitized_name, weight_per_unit
         HAVING qty>0
        """
    )
    for r in rows:
        cid = str(r["cid"])
        advanced_data["avail"].setdefault(cid, {}) \
            .setdefault(r["sanitized_name"], {})[str(r["weight_per_unit"])] = r["qty"]
        advanced_data["items"].setdefault(cid, []).append(r["sanitized_name"])
        advanced_data["sizes"].setdefault(cid, {}) \
            .setdefault(r["sanitized_name"], []).append(str(r["weight_per_unit"]))
        if not any(c["id"] == cid for c in advanced_data["stock_categories"]):
            name = next((c["cname"] for c in cats if str(c["cid"]) == cid), "")
            advanced_data["stock_categories"].append({"id": cid, "display_name": name})

    # Fetch all entries for display
    entries = dict_rows(
        """
        SELECT e.id,
               c.display_name AS category,
               e.raw_name, e.sanitized_name,
               e.weight_per_unit, e.quantity,
               e.total_weight, e.direction, e.timestamp
          FROM inventory_entries e
          JOIN inventory_categories c ON c.id = e.category_id
         ORDER BY e.timestamp DESC
        """
    )

    # Apply mass-unit preference to view fields
    mass_pref = request.cookies.get("mass_unit", "lbs")
    _ = session.get("inv_weight_unit", mass_pref)
    for e in entries:
        if mass_pref == "kg":
            e["weight_view"] = round_half_kg(e["weight_per_unit"] / 2.20462)
            e["total_view"]  = round_half_kg(e["total_weight"]    / 2.20462)
        else:
            e["weight_view"] = e["weight_per_unit"]
            e["total_view"]  = e["total_weight"]

    return render_template(
        "inventory_detail.html",
        categories=categories,
        inv_weight_unit=session.get("inv_weight_unit", request.cookies.get("mass_unit", "lbs")),
        active="inventory",
        advanced_data=advanced_data,
    )


@bp.route("/edit/<int:entry_id>", methods=["GET", "POST"])
def inventory_edit(entry_id: int):
    categories = dict_rows("SELECT id, display_name FROM inventory_categories")
    rows = dict_rows("SELECT * FROM inventory_entries WHERE id=?", (entry_id,))
    if not rows:
        flash("Entry not found.", "error")
        return redirect(url_for("inventory.inventory_detail"))
    entry = rows[0]

    if request.method == "POST":
        raw         = request.form["name"]
        noun        = sanitize_name(raw)
        weight_val  = float(request.form.get("weight") or 0)
        weight_unit = request.form.get("weight_unit", "lbs")
        wpu         = kg_to_lbs(weight_val) if weight_unit == "kg" else weight_val
        qty         = int(request.form.get("qty") or 0)
        total       = wpu * qty
        dirn        = request.form["direction"]

        with sqlite3.connect(DB_FILE) as c:
            c.execute(
                """
                UPDATE inventory_entries
                   SET category_id=?,
                       raw_name=?, sanitized_name=?,
                       weight_per_unit=?, quantity=?, total_weight=?, direction=?
                 WHERE id=?
                """,
                (
                    int(request.form["category"]),
                    raw, noun,
                    wpu, qty, total, dirn,
                    entry_id,
                ),
            )
        return redirect(url_for("inventory.inventory_detail"))

    return render_template(
        "inventory_edit.html",
        entry=entry,
        categories=categories,
        inv_weight_unit=session.get("inv_weight_unit", request.cookies.get("mass_unit", "lbs")),
        active="inventory",
    )


@bp.route("/delete/<int:entry_id>", methods=["POST"])
def inventory_delete(entry_id: int):
    """Delete a single inventory entry and return to detail page."""
    with sqlite3.connect(DB_FILE) as c:
        c.execute("DELETE FROM inventory_entries WHERE id = ?", (entry_id,))
    return redirect(url_for("inventory.inventory_detail"))
