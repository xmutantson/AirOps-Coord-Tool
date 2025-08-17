# rebuilt clean by fix_inventory_routes_rewrite.py
import sqlite3

from modules.utils.common import *  # dict_rows, prefs, etc.
from app import DB_FILE
from flask import flash, redirect, render_template, request, url_for
from app import inventory_bp as bp


@bp.route("/categories", methods=["GET", "POST"])
def inventory_categories():
    # Minimal, sane implementation to restore compile & basic function.
    if request.method == "POST":
        # Add or rename a category, depending on fields present
        new_name = (request.form.get("new_name") or "").strip()
        if new_name:
            with sqlite3.connect(DB_FILE) as c:
                c.execute("INSERT INTO inventory_categories(display_name) VALUES (?)", (new_name,))
            flash("Category added.", "success")
            return redirect(url_for("inventory.inventory_categories"))

        cat_id   = request.form.get("id")
        disp     = (request.form.get("display_name") or "").strip()
        if cat_id and disp:
            with sqlite3.connect(DB_FILE) as c:
                c.execute("UPDATE inventory_categories SET display_name=? WHERE id=?", (disp, int(cat_id)))
            flash("Category renamed.", "success")
            return redirect(url_for("inventory.inventory_categories"))

        flash("Nothing to do.", "info")
        return redirect(url_for("inventory.inventory_categories"))

    # GET: list categories
    categories = dict_rows("SELECT id, display_name FROM inventory_categories ORDER BY display_name")
    return render_template("inventory_categories.html", categories=categories, active="inventory")
