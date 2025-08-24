# modules/routes_inventory/scan.py
from flask import render_template
from app import inventory_bp as bp

@bp.get("/scan")
def inventory_scan():
    return render_template("inventory_scan.html")
