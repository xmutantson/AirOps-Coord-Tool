# modules/routes_inventory/barcodes.py
import sqlite3
from datetime import datetime

from flask import request, render_template, redirect, url_for, flash, jsonify
from app import DB_FILE, publish_inventory_event
from app import inventory_bp as bp
from modules.utils.common import dict_rows, sanitize_name

# ────────────────────────────────────────────────────────────────────
# Admin page (optional to use). Lists and creates/updates mappings.
# ────────────────────────────────────────────────────────────────────
@bp.route("/barcodes", methods=["GET", "POST"])
def inventory_barcodes_admin():
    if request.method == "POST":
        barcode = (request.form.get("barcode") or "").strip()
        raw     = (request.form.get("raw_name") or "").strip()
        name    = sanitize_name(raw or request.form.get("sanitized_name") or "")
        wpu     = float(request.form.get("weight_per_unit") or 0)  # lbs
        cid     = int(request.form.get("category_id") or 0)

        if not (barcode and name and wpu > 0 and cid > 0):
            flash("Missing or invalid fields.", "error")
            return redirect(url_for("inventory.inventory_barcodes_admin"))

        now = datetime.utcnow().isoformat()
        with sqlite3.connect(DB_FILE) as c:
            c.execute("""
              INSERT INTO inventory_barcodes(
                barcode, category_id, sanitized_name, raw_name, weight_per_unit, updated_at
              )
              VALUES (?,?,?,?,?,?)
              ON CONFLICT(barcode) DO UPDATE SET
                category_id    = excluded.category_id,
                sanitized_name = excluded.sanitized_name,
                raw_name       = excluded.raw_name,
                weight_per_unit= excluded.weight_per_unit,
                updated_at     = excluded.updated_at
            """, (barcode, cid, name, raw or name, wpu, now))

        flash("Saved.", "success")
        return redirect(url_for("inventory.inventory_barcodes_admin"))

    cats = dict_rows("SELECT id, display_name FROM inventory_categories ORDER BY display_name")
    rows = dict_rows("""
      SELECT b.barcode, b.category_id, c.display_name AS category,
             b.sanitized_name, b.raw_name, b.weight_per_unit, b.updated_at
        FROM inventory_barcodes b
        JOIN inventory_categories c ON c.id=b.category_id
       ORDER BY c.display_name, b.sanitized_name, b.weight_per_unit
    """)
    return render_template(
        "inventory_barcodes.html",
        barcodes=rows,
        categories=cats,
        active="inventory"
    )

@bp.post("/barcodes/delete/<string:barcode>")
def inventory_barcodes_delete(barcode: str):
    with sqlite3.connect(DB_FILE) as c:
        c.execute("DELETE FROM inventory_barcodes WHERE barcode=?", (barcode.strip(),))
    flash("Deleted.", "info")
    return redirect(url_for("inventory.inventory_barcodes_admin"))

# ────────────────────────────────────────────────────────────────────
# APIs for scanner / programmatic use
# ────────────────────────────────────────────────────────────────────

@bp.get("/api/lookup_barcode/<string:barcode>")
def api_lookup_barcode(barcode: str):
    """Return item metadata for a barcode (to prefill a form)."""
    rows = dict_rows("""
      SELECT barcode, category_id, sanitized_name,
             COALESCE(raw_name, sanitized_name) AS raw_name,
             weight_per_unit
        FROM inventory_barcodes
       WHERE barcode=?
    """, (barcode.strip(),))
    if not rows:
        # Return 200 so the client can show the inline "add mapping" form.
        return jsonify({"status": "unknown"}), 200
    return jsonify({"status": "ok", "item": rows[0]})

@bp.route("/api/lookup_barcode", methods=["POST"])
def api_lookup_barcode_post():
    """POST variant that accepts JSON/form: {'code': '...'}."""
    data = request.get_json(silent=True) or request.form
    code = (data.get("code") or data.get("barcode") or "").strip()
    if not code:
        return jsonify({"status": "error", "message": "Missing code"}), 400
    rows = dict_rows("""
      SELECT barcode, category_id, sanitized_name,
             COALESCE(raw_name, sanitized_name) AS raw_name,
             weight_per_unit
        FROM inventory_barcodes
       WHERE barcode=?
    """, (code,))
    if not rows:
        return jsonify({"status": "unknown"}), 200
    return jsonify({"status": "ok", "item": rows[0]})

@bp.get("/api/categories")
def api_inventory_categories():
    """
    Lightweight categories list for inline 'unknown barcode' form.
    """
    rows = dict_rows("SELECT id, display_name FROM inventory_categories ORDER BY display_name")
    return jsonify({"categories": rows})

@bp.route("/api/save_barcode_mapping", methods=["POST"])
def api_save_barcode_mapping():
    """
    Create or update a barcode→item mapping, then return the normalized item.
    Body JSON/form:
      barcode (str, required)
      category_id (int, required)
      name (str, required)                -> sanitized on server
      raw_name (str, optional)
      weight_per_unit (float, required)   -> lbs
    """
    d = request.get_json(silent=True) or request.form
    barcode = (d.get("barcode") or "").strip()
    name_in = (d.get("name") or "").strip()
    raw_in  = (d.get("raw_name") or "").strip()
    wpu     = float(d.get("weight_per_unit") or 0)
    try: cid = int(d.get("category_id") or 0)
    except Exception: cid = 0
    if not (barcode and name_in and cid > 0 and wpu > 0):
        return jsonify({"status": "error", "message": "Missing or invalid fields"}), 400
    name = sanitize_name(name_in)
    now = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILE) as c:
        c.execute("""
          INSERT INTO inventory_barcodes(barcode, category_id, sanitized_name, raw_name, weight_per_unit, updated_at)
          VALUES (?,?,?,?,?,?)
          ON CONFLICT(barcode) DO UPDATE SET
            category_id     = excluded.category_id,
            sanitized_name  = excluded.sanitized_name,
            raw_name        = excluded.raw_name,
            weight_per_unit = excluded.weight_per_unit,
            updated_at      = excluded.updated_at
        """, (barcode, cid, name, raw_in or name, wpu, now))
    # Mirror the lookup shape so the client can prefill immediately
    return jsonify({"status": "ok", "item": {
        "barcode": barcode, "category_id": cid, "sanitized_name": name,
        "raw_name": (raw_in or name), "weight_per_unit": wpu
    }})

@bp.route("/api/scan_barcode", methods=["POST"])
def api_scan_barcode():
    """
    Body: JSON or form
      barcode      (str, required)
      qty          (int, optional)
                    - if cookie scanner_mode=auto1 and qty omitted/blank → defaults to 1
                    - if cookie scanner_mode=prompt and qty omitted/blank → 400 (required)
      direction    ('inbound'|'outbound'|'in'|'out', default 'inbound')
      manifest_id  (str, optional) → to group as a session
      commit_now   (bool, default False) → pending=1 unless True
    Creates an inventory_entries row using the barcode mapping.
    """
    data = request.get_json(silent=True) or request.form
    barcode = (data.get("barcode") or "").strip()
    if not barcode:
        return jsonify({"status": "error", "message": "Missing barcode"}), 400

    # qty handling respects scanner_mode cookie
    raw_qty = data.get("qty")
    qty = None
    try:
        # allow "0" or whitespace to be handled below; only set if truly an int was provided
        if raw_qty is not None and str(raw_qty).strip() != "":
            qty = int(raw_qty)
    except Exception:
        qty = None
    if qty is None:
        mode = (request.cookies.get("scanner_mode") or "prompt").strip().lower()
        if mode == "auto1":
            qty = 1
        else:
            return jsonify({"status": "error", "message": "qty is required in prompt mode"}), 400
    if qty <= 0:
        return jsonify({"status": "error", "message": "qty must be > 0"}), 400

    direc_raw = (data.get("direction") or "inbound").lower()
    dir_io = "in" if direc_raw.startswith("in") else "out"
    commit  = str(data.get("commit_now") or "").lower() in ("1", "true", "yes")
    mid     = (data.get("manifest_id") or "").strip() or None

    # Lookup the mapping
    row = dict_rows("""
      SELECT category_id, sanitized_name,
             COALESCE(raw_name, sanitized_name) AS raw_name,
             weight_per_unit
        FROM inventory_barcodes
       WHERE barcode=?
    """, (barcode,))
    if not row:
        return jsonify({"status": "unknown", "message": "Barcode not found"}), 404
    item = row[0]

    cat_id = int(item["category_id"])
    name   = item["sanitized_name"]
    raw    = item["raw_name"]
    wpu    = float(item["weight_per_unit"])
    total  = wpu * qty
    ts     = datetime.utcnow().isoformat()

    # Enforce no overdraw for OUTBOUND (same rule as /detail)
    if dir_io == "out":
        avail = dict_rows("""
          SELECT COALESCE(SUM(
            CASE WHEN direction='in' THEN quantity
                 WHEN direction='out' THEN -quantity END
          ),0) AS avail
            FROM inventory_entries
           WHERE (pending IS NULL OR pending=0)
             AND category_id=? AND sanitized_name=? AND ABS(weight_per_unit - ?) < 0.001
        """, (cat_id, name, wpu))[0]["avail"] or 0
        if qty > avail:
            return jsonify({"status": "error", "message": f"Only {int(avail)} available"}), 400

    with sqlite3.connect(DB_FILE) as c:
        cur = c.execute("""
          INSERT INTO inventory_entries(
            category_id, raw_name, sanitized_name,
            weight_per_unit, quantity, total_weight,
            direction, timestamp, pending, pending_ts, session_id, source
          ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
          cat_id, raw, name,
          wpu, qty, total,
          dir_io, ts,
          (0 if commit else 1),
          (None if commit else ts),
          mid,
          "barcode-scan"
        ))
        eid = cur.lastrowid

        manifest_total = 0.0
        if mid and not commit:
            manifest_total = c.execute("""
              SELECT COALESCE(SUM(total_weight),0)
                FROM inventory_entries
               WHERE pending=1 AND session_id=?
            """, (mid,)).fetchone()[0] or 0.0

    try:
        publish_inventory_event()
    except Exception:
        pass

    return jsonify({
        "status": "ok",
        "entry_id": int(eid),
        "direction": dir_io,
        "category_id": cat_id,
        "sanitized_name": name,
        "raw_name": raw,
        "weight_per_unit": wpu,
        "qty": qty,
        "total_weight": total,
        "timestamp": ts,
        "manifest_total": float(manifest_total),
        "pending": (0 if commit else 1)
    })
