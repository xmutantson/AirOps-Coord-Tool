# modules/routes_inventory/scan.py
from flask import render_template, request, redirect, url_for, make_response, flash
from app import inventory_bp as bp

def _scanner_mode_from_cookie() -> str:
    """Return 'auto1' (single-qty) or 'prompt' (default) from cookie."""
    m = (request.cookies.get("scanner_mode") or "").strip().lower()
    return "auto1" if m == "auto1" else "prompt"

@bp.get("/scan")
def inventory_scan():
    # Pass current mode to template for JS to read (data attribute).
    return render_template("inventory_scan.html", scanner_mode=_scanner_mode_from_cookie())
