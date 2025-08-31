# modules/routes_inventory/barcodes.py
import csv
import io
import sqlite3
from datetime import datetime
from typing import Iterable

from flask import (
    request, render_template, redirect, url_for, flash, jsonify,
    Response
)
from app import DB_FILE, publish_inventory_event
from app import inventory_bp as bp
from modules.utils.common import dict_rows, sanitize_name

# ────────────────────────────────────────────────────────────────────
# Schema helpers (adds columns if missing; safe to run many times)
# ────────────────────────────────────────────────────────────────────
def _ensure_barcode_schema() -> None:
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        have = {r["name"] for r in c.execute("PRAGMA table_info(inventory_barcodes)")}
        if "last_seen" not in have:
            c.execute("ALTER TABLE inventory_barcodes ADD COLUMN last_seen TEXT")
        if "seen_count" not in have:
            c.execute("ALTER TABLE inventory_barcodes ADD COLUMN seen_count INTEGER DEFAULT 0")
        if "deleted" not in have:
            c.execute("ALTER TABLE inventory_barcodes ADD COLUMN deleted INTEGER DEFAULT 0")
        if "deleted_at" not in have:
            c.execute("ALTER TABLE inventory_barcodes ADD COLUMN deleted_at TEXT")
        if "alias_of" not in have:
            c.execute("ALTER TABLE inventory_barcodes ADD COLUMN alias_of TEXT")
        c.commit()

def _param_list(lst: Iterable[str]):
    lst = [s.strip() for s in lst if s and s.strip()]
    return lst, ",".join("?" for _ in lst)

# ────────────────────────────────────────────────────────────────────
# Main admin page + AJAX table
# ────────────────────────────────────────────────────────────────────
@bp.route("/barcodes", methods=["GET", "POST"])
def inventory_barcodes_admin():
    _ensure_barcode_schema()

    if request.method == "POST":
        # Single-row upsert from inline editor
        form = request.form
        barcode = (form.get("barcode") or "").strip()
        raw     = (form.get("raw_name") or "").strip()
        name    = sanitize_name((form.get("sanitized_name") or raw or "").strip())
        wpu     = float(form.get("weight_per_unit") or 0)
        alias   = (form.get("alias_of") or "").strip() or None
        try:
            cid = int(form.get("category_id") or 0)
        except Exception:
            cid = 0

        if not (barcode and name and wpu > 0 and cid > 0):
            return jsonify(success=False, message="Missing/invalid fields"), 400

        now = datetime.utcnow().isoformat()
        with sqlite3.connect(DB_FILE) as c:
            c.execute("""
              INSERT INTO inventory_barcodes(
                barcode, category_id, sanitized_name, raw_name,
                weight_per_unit, updated_at, alias_of, deleted
              ) VALUES (?,?,?,?,?,?,?,0)
              ON CONFLICT(barcode) DO UPDATE SET
                category_id     = excluded.category_id,
                sanitized_name  = excluded.sanitized_name,
                raw_name        = excluded.raw_name,
                weight_per_unit = excluded.weight_per_unit,
                updated_at      = excluded.updated_at,
                alias_of        = excluded.alias_of
            """, (barcode, cid, name, raw or name, wpu, now, alias))
            c.commit()
        return jsonify(success=True)

    # Initial shell; table is AJAX-loaded
    cats = dict_rows("SELECT id, display_name FROM inventory_categories ORDER BY display_name")
    return render_template(
        "inventory_barcodes.html",
        categories=cats,
        active="inventory"
    )

@bp.get("/_barcodes_table")
def inventory_barcodes_table():
    _ensure_barcode_schema()
    q = (request.args.get("q") or "").strip()
    cat = request.args.get("category") or ""
    show_deleted = request.args.get("deleted") == "1"

    where = ["1=1"]
    params: list = []
    if not show_deleted:
        where.append("COALESCE(b.deleted,0)=0")
    if q:
        where.append("(b.barcode LIKE ? OR b.sanitized_name LIKE ? OR b.raw_name LIKE ?)")
        like = f"%{q}%"
        params += [like, like, like]
    if cat:
        try:
            params.append(int(cat))
            where.append("b.category_id=?")
        except Exception:
            pass

    rows = dict_rows(f"""
      SELECT b.barcode, b.category_id, c.display_name AS category,
             b.sanitized_name, b.raw_name, b.weight_per_unit,
             b.updated_at, b.last_seen, COALESCE(b.seen_count,0) AS seen_count,
             b.alias_of, COALESCE(b.deleted,0) AS deleted
        FROM inventory_barcodes b
        JOIN inventory_categories c ON c.id=b.category_id
       WHERE {" AND ".join(where)}
       ORDER BY c.display_name, b.sanitized_name, b.weight_per_unit
    """, tuple(params))
    return render_template("partials/_inventory_barcodes_table.html", rows=rows)

# ────────────────────────────────────────────────────────────────────
# Row actions (soft delete / restore / bulk category / merge)
# ────────────────────────────────────────────────────────────────────
@bp.post("/barcodes/soft_delete")
def inventory_barcodes_soft_delete():
    _ensure_barcode_schema()
    barcodes = request.form.getlist("barcodes[]") or request.form.getlist("barcodes")
    barcodes, ph = _param_list(barcodes)
    if not barcodes:
        return jsonify(success=False, message="No selection"), 400
    now = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILE) as c:
        c.execute(f"UPDATE inventory_barcodes SET deleted=1, deleted_at=? WHERE barcode IN ({ph})",
                  (now, *barcodes))
        c.commit()
    return jsonify(success=True)

@bp.post("/barcodes/restore")
def inventory_barcodes_restore():
    _ensure_barcode_schema()
    barcodes = request.form.getlist("barcodes[]") or request.form.getlist("barcodes")
    barcodes, ph = _param_list(barcodes)
    if not barcodes:
        return jsonify(success=False, message="No selection"), 400
    with sqlite3.connect(DB_FILE) as c:
        c.execute(f"UPDATE inventory_barcodes SET deleted=0, deleted_at=NULL WHERE barcode IN ({ph})", tuple(barcodes))
        c.commit()
    return jsonify(success=True)

@bp.post("/barcodes/bulk_category")
def inventory_barcodes_bulk_category():
    _ensure_barcode_schema()
    try:
        cid = int(request.form.get("category_id") or 0)
    except Exception:
        cid = 0
    barcodes = request.form.getlist("barcodes[]") or request.form.getlist("barcodes")
    barcodes, ph = _param_list(barcodes)
    if cid <= 0 or not barcodes:
        return jsonify(success=False, message="Category and selection required"), 400
    with sqlite3.connect(DB_FILE) as c:
        c.execute(f"UPDATE inventory_barcodes SET category_id=? WHERE barcode IN ({ph})",
                  (cid, *barcodes))
        c.commit()
    return jsonify(success=True)

@bp.post("/barcodes/merge")
def inventory_barcodes_merge():
    """
    Merge many barcodes into one canonical mapping:
      - 'primary' is kept canonical
      - others get alias_of=primary (and fields updated to match)
    """
    _ensure_barcode_schema()
    primary = (request.form.get("primary") or "").strip()
    barcodes = request.form.getlist("barcodes[]") or request.form.getlist("barcodes")
    barcodes = [b for b in barcodes if b and b.strip() and b.strip() != primary]
    if not primary or len(barcodes) < 1:
        return jsonify(success=False, message="Pick a primary + at least one other"), 400

    # Pull primary mapping
    prim = dict_rows("""
      SELECT category_id, sanitized_name, COALESCE(raw_name, sanitized_name) AS raw_name, weight_per_unit
        FROM inventory_barcodes WHERE barcode=? AND COALESCE(deleted,0)=0
    """, (primary,))
    if not prim:
        return jsonify(success=False, message="Primary not found"), 404
    P = prim[0]

    with sqlite3.connect(DB_FILE) as c:
        for code in barcodes:
            c.execute("""
              UPDATE inventory_barcodes
                 SET alias_of=?, category_id=?, sanitized_name=?, raw_name=?, weight_per_unit=?, updated_at=?
               WHERE barcode=?
            """, (primary, P["category_id"], P["sanitized_name"], P["raw_name"], P["weight_per_unit"],
                  datetime.utcnow().isoformat(), code.strip()))
        c.commit()
    return jsonify(success=True)

# ────────────────────────────────────────────────────────────────────
# CSV export / import (compatible with our app)
# ────────────────────────────────────────────────────────────────────
@bp.get("/barcodes/export.csv")
def inventory_barcodes_export_csv():
    _ensure_barcode_schema()
    show_deleted = request.args.get("deleted") == "1"
    rows = dict_rows(f"""
      SELECT barcode, category_id, sanitized_name, COALESCE(raw_name, sanitized_name) AS raw_name,
             weight_per_unit, COALESCE(deleted,0) AS deleted, alias_of,
             last_seen, COALESCE(seen_count,0) AS seen_count, updated_at
        FROM inventory_barcodes
       WHERE {("1=1" if show_deleted else "COALESCE(deleted,0)=0")}
       ORDER BY category_id, sanitized_name, weight_per_unit
    """)
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["barcode","category_id","sanitized_name","raw_name","weight_per_unit",
                "deleted","alias_of","last_seen","seen_count","updated_at"])
    for r in rows:
        w.writerow([
            r["barcode"], r["category_id"], r["sanitized_name"], r["raw_name"],
            r["weight_per_unit"], r["deleted"], r["alias_of"] or "",
            r["last_seen"] or "", r["seen_count"], r["updated_at"] or ""
        ])
    data = output.getvalue()
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=inventory_barcodes.csv"}
    )

@bp.post("/barcodes/import")
def inventory_barcodes_import_csv():
    _ensure_barcode_schema()
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Choose a CSV file.", "error")
        return redirect(url_for("inventory.inventory_barcodes_admin"))
    content = io.TextIOWrapper(f.stream, encoding="utf-8", errors="replace")
    reader = csv.DictReader(content)
    now = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILE) as c:
        for row in reader:
            barcode = (row.get("barcode") or "").strip()
            if not barcode:
                continue
            name = sanitize_name((row.get("sanitized_name") or row.get("raw_name") or "").strip())
            raw  = (row.get("raw_name") or name).strip()
            try:
                cid = int(row.get("category_id") or 0)
                wpu = float(row.get("weight_per_unit") or 0)
            except Exception:
                continue
            alias = (row.get("alias_of") or "").strip() or None
            deleted = 1 if str(row.get("deleted") or "0").strip() in ("1","true","yes") else 0
            last_seen = (row.get("last_seen") or "").strip() or None
            seen_count = int(row.get("seen_count") or 0)

            c.execute("""
              INSERT INTO inventory_barcodes(
                barcode, category_id, sanitized_name, raw_name,
                weight_per_unit, updated_at, alias_of, deleted, deleted_at, last_seen, seen_count
              ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
              ON CONFLICT(barcode) DO UPDATE SET
                category_id     = excluded.category_id,
                sanitized_name  = excluded.sanitized_name,
                raw_name        = excluded.raw_name,
                weight_per_unit = excluded.weight_per_unit,
                updated_at      = excluded.updated_at,
                alias_of        = excluded.alias_of,
                deleted         = excluded.deleted,
                deleted_at      = excluded.deleted_at,
                last_seen       = COALESCE(excluded.last_seen, inventory_barcodes.last_seen),
                seen_count      = COALESCE(NULLIF(excluded.seen_count,0), inventory_barcodes.seen_count)
            """, (barcode, cid, name, raw, wpu, now, alias,
                  deleted, (now if deleted else None), last_seen, seen_count))
        c.commit()
    flash("Import complete.", "success")
    return redirect(url_for("inventory.inventory_barcodes_admin"))

# ────────────────────────────────────────────────────────────────────
# Lookup & save API (scanner-facing) — now resolves alias + updates last_seen
# ────────────────────────────────────────────────────────────────────
def _resolve_mapping_for(barcode: str):
    """Return canonical mapping; follows alias_of if present."""
    row = dict_rows("""
      SELECT barcode, category_id, sanitized_name, COALESCE(raw_name, sanitized_name) AS raw_name,
             weight_per_unit, alias_of
        FROM inventory_barcodes WHERE barcode=? AND COALESCE(deleted,0)=0
    """, (barcode,))
    if not row:
        return None
    r = row[0]
    alias = (r.get("alias_of") or "").strip()
    if alias:
        row2 = dict_rows("""
          SELECT barcode, category_id, sanitized_name, COALESCE(raw_name, sanitized_name) AS raw_name,
                 weight_per_unit
            FROM inventory_barcodes WHERE barcode=? AND COALESCE(deleted,0)=0
        """, (alias,))
        if row2:
            r2 = row2[0]
            r2["alias_of"] = alias
            r2["requested_barcode"] = barcode
            return r2
    return r

@bp.get("/api/lookup_barcode/<string:barcode>")
def api_lookup_barcode(barcode: str):
    _ensure_barcode_schema()
    r = _resolve_mapping_for(barcode.strip())
    if not r:
        return jsonify({"status": "unknown"}), 200
    return jsonify({"status": "ok", "item": r})

@bp.route("/api/lookup_barcode", methods=["POST"])
def api_lookup_barcode_post():
    _ensure_barcode_schema()
    data = request.get_json(silent=True) or request.form
    code = (data.get("code") or data.get("barcode") or "").strip()
    if not code:
        return jsonify({"status": "error", "message": "Missing code"}), 400
    r = _resolve_mapping_for(code)
    if not r:
        return jsonify({"status": "unknown"}), 200
    return jsonify({"status": "ok", "item": r})

@bp.get("/api/categories")
def api_inventory_categories():
    rows = dict_rows("SELECT id, display_name FROM inventory_categories ORDER BY display_name")
    return jsonify({"categories": rows})

@bp.route("/api/save_barcode_mapping", methods=["POST"])
def api_save_barcode_mapping():
    _ensure_barcode_schema()
    d = request.get_json(silent=True) or request.form
    barcode = (d.get("barcode") or "").strip()
    name_in = (d.get("name") or "").strip()
    raw_in  = (d.get("raw_name") or "").strip()
    wpu     = float(d.get("weight_per_unit") or 0)
    try:
        cid = int(d.get("category_id") or 0)
    except Exception:
        cid = 0
    if not (barcode and name_in and cid > 0 and wpu > 0):
        return jsonify({"status": "error", "message": "Missing or invalid fields"}), 400
    name = sanitize_name(name_in)
    now = datetime.utcnow().isoformat()
    with sqlite3.connect(DB_FILE) as c:
        c.execute("""
          INSERT INTO inventory_barcodes(barcode, category_id, sanitized_name, raw_name, weight_per_unit, updated_at, deleted)
          VALUES (?,?,?,?,?,? ,0)
          ON CONFLICT(barcode) DO UPDATE SET
            category_id     = excluded.category_id,
            sanitized_name  = excluded.sanitized_name,
            raw_name        = excluded.raw_name,
            weight_per_unit = excluded.weight_per_unit,
            updated_at      = excluded.updated_at,
            deleted         = 0,
            deleted_at      = NULL
        """, (barcode, cid, name, raw_in or name, wpu, now))
        c.commit()
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
      direction    ('inbound'|'outbound'|'in'|'out', default 'inbound')
      manifest_id  (str, optional)
      commit_now   (bool, default False)
    """
    _ensure_barcode_schema()

    data = request.get_json(silent=True) or request.form
    barcode = (data.get("barcode") or "").strip()
    if not barcode:
        return jsonify({"status": "error", "message": "Missing barcode"}), 400

    # qty handling respects scanner_mode cookie
    raw_qty = data.get("qty")
    qty = None
    try:
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

    # Resolve mapping (follows alias)
    m = _resolve_mapping_for(barcode)
    if not m:
        return jsonify({"status": "unknown", "message": "Barcode not found"}), 404

    cat_id = int(m["category_id"])
    name   = m["sanitized_name"]
    raw    = m["raw_name"]
    wpu    = float(m["weight_per_unit"])
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

        # Track last_seen / seen_count (for both requested + canonical if different)
        codes = {barcode}
        if m.get("requested_barcode") and m["requested_barcode"] != m["barcode"]:
            codes.add(m["requested_barcode"])
        codes.add(m["barcode"])  # canonical row
        for code in codes:
            c.execute("""
              UPDATE inventory_barcodes
                 SET last_seen=?, seen_count=COALESCE(seen_count,0)+1
               WHERE barcode=?
            """, (ts, code))
        # pending total
        manifest_total = 0.0
        if mid and not commit:
            manifest_total = c.execute("""
              SELECT COALESCE(SUM(total_weight),0)
                FROM inventory_entries
               WHERE pending=1 AND session_id=?
            """, (mid,)).fetchone()[0] or 0.0
        c.commit()

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
