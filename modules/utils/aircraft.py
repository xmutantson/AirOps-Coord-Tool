# modules/utils/aircraft.py
from __future__ import annotations
from typing import Optional, Iterable, Any, Dict, List
import sqlite3, os, re
from datetime import datetime, timezone
from flask import Blueprint, request, render_template, redirect, url_for, jsonify, current_app
from werkzeug.exceptions import BadRequest, NotFound
from modules.utils.common import get_db_file, dict_rows, ensure_column

# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

def ensure_aircraft_tables():
    """Idempotently create/upgrade the Pilot & Aircraft tables."""
    with sqlite3.connect(get_db_file()) as c:
        # One aircraft record per pilot (1:1 assumed)
        c.execute("""
            CREATE TABLE IF NOT EXISTS aircraft_info (
              id                INTEGER PRIMARY KEY AUTOINCREMENT,
              staff_id          INTEGER,          -- optional link to staff
              pilot_name        TEXT NOT NULL,
              pilot_cert_no     TEXT,             -- 'Pilot Cert No.' (certificate #)
              ratings_text      TEXT,             -- free-text Type/Ratings
              street_address    TEXT,
              city_state        TEXT,
              zip_code          TEXT,
              pilot_email       TEXT,
              pilot_mobile      TEXT,
              pilot_work_phone  TEXT,
              pilot_home_phone  TEXT,

              make_model        TEXT NOT NULL,    -- e.g., "Cessna 172"
              registration      TEXT NOT NULL,    -- tail (N-number), keep as entered
              net_weight_lb     INTEGER,          -- whole pounds per spec

              ec_full_name      TEXT,             -- Emergency Contact
              ec_mobile_phone   TEXT,
              ec_relationship   TEXT,

              notes             TEXT,             -- free-form "Notes:" block
              reviewed_by       TEXT,             -- "Reviewed by DART – Full Name"
              reviewed_date     TEXT,             -- ISO-8601 (UTC)

              pdf_path          TEXT,             -- stored PDF location (WeasyPrint)
              created_at_utc    TEXT NOT NULL,
              updated_at_utc    TEXT NOT NULL,

              UNIQUE(registration)                -- 1 aircraft per tail; adjust later if needed
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_aircraft_staff ON aircraft_info(staff_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_aircraft_reg   ON aircraft_info(registration)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_aircraft_pilot ON aircraft_info(pilot_name)")

    # future-proof: ensure any newly added columns exist on upgraded DBs
    for col, typ in [
        ("reviewed_by",   "TEXT"),
        ("reviewed_date", "TEXT"),
        ("pdf_path",      "TEXT"),
        ("notes",         "TEXT"),
    ]:
        ensure_column("aircraft_info", col, typ)

# ─────────────────────────────────────────────────────────────────────────────
# Data access helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _exports_root() -> str:
    """
    Persist PAI PDFs under data/exports/pai, matching the ZIP export location.
    Uses AOCT_DATA_DIR if set; else <cwd>/data.
    """
    data_root = os.getenv("AOCT_DATA_DIR") or os.path.join(os.getcwd(), "data")
    out = os.path.join(data_root, "exports", "pai")
    os.makedirs(out, exist_ok=True)
    return out

def _upper_tail(s: Optional[str]) -> str:
    return (s or "").strip().upper()

def pai_pdf_path(row_id: int) -> str:
    rows = dict_rows("SELECT pilot_name, registration FROM aircraft_info WHERE id=?", (int(row_id),))
    reg = _upper_tail((rows[0]["registration"] if rows else "") or "")
    nm  = (rows[0]["pilot_name"] if rows else "") or ""
    parts = [p for p in re.split(r"\s+", nm) if p]
    last_first = f"{parts[-1]}_{parts[0]}" if parts else "pilot"
    base = f"{reg or 'N_A'}_{last_first}_{int(row_id)}.pdf"
    return os.path.join(_exports_root(), base)

def upsert_aircraft(
    *,
    pilot_name: str,
    make_model: str,
    registration: str,
    staff_id: Optional[int] = None,
    pilot_cert_no: Optional[str] = None,
    ratings_text: Optional[str] = None,
    street_address: Optional[str] = None,
    city_state: Optional[str] = None,
    zip_code: Optional[str] = None,
    pilot_email: Optional[str] = None,
    pilot_mobile: Optional[str] = None,
    pilot_work_phone: Optional[str] = None,
    pilot_home_phone: Optional[str] = None,
    net_weight_lb: Optional[int] = None,
    ec_full_name: Optional[str] = None,
    ec_mobile_phone: Optional[str] = None,
    ec_relationship: Optional[str] = None,
    notes: Optional[str] = None,
    reviewed_by: Optional[str] = None,
    reviewed_date: Optional[str] = None,
) -> int:
    """Insert or update by `registration`. Returns row id."""
    ensure_aircraft_tables()
    nowz = _now_iso_utc()
    # ── Validation / normalization per spec ─────────────────────────────────
    pilot_name      = (pilot_name or "").strip()
    make_model      = (make_model or "").strip()
    registration    = _upper_tail(registration)
    if net_weight_lb in ("", None):
        net_weight_lb = None
    else:
        try:
            net_weight_lb = int(net_weight_lb)  # enforce integer pounds
        except Exception:
            raise ValueError("net_weight_lb must be an integer (lbs)")
    missing = [k for k,v in {
        "pilot_name": pilot_name,
        "registration": registration,
        "make_model": make_model,
    }.items() if not v]
    if missing:
        raise ValueError("Missing required fields: " + ", ".join(missing))

    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        row = c.execute(
            "SELECT id FROM aircraft_info WHERE registration=? LIMIT 1",
            (registration,)
        ).fetchone()
        if row:
            c.execute("""
              UPDATE aircraft_info SET
                staff_id=?, pilot_name=?, pilot_cert_no=?, ratings_text=?,
                street_address=?, city_state=?, zip_code=?,
                pilot_email=?, pilot_mobile=?, pilot_work_phone=?, pilot_home_phone=?,
                make_model=?, net_weight_lb=?,
                ec_full_name=?, ec_mobile_phone=?, ec_relationship=?,
                notes=?, reviewed_by=?, reviewed_date=?,
                updated_at_utc=?
              WHERE id=?
            """, (
                staff_id, pilot_name, pilot_cert_no, ratings_text,
                street_address, city_state, zip_code,
                pilot_email, pilot_mobile, pilot_work_phone, pilot_home_phone,
                make_model, net_weight_lb,
                ec_full_name, ec_mobile_phone, ec_relationship,
                notes, reviewed_by, reviewed_date,
                nowz, row["id"]
            ))
            return int(row["id"])
        else:
            c.execute("""
              INSERT INTO aircraft_info (
                staff_id, pilot_name, pilot_cert_no, ratings_text,
                street_address, city_state, zip_code,
                pilot_email, pilot_mobile, pilot_work_phone, pilot_home_phone,
                make_model, registration, net_weight_lb,
                ec_full_name, ec_mobile_phone, ec_relationship,
                notes, reviewed_by, reviewed_date,
                pdf_path, created_at_utc, updated_at_utc
              ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                staff_id, pilot_name, pilot_cert_no, ratings_text,
                street_address, city_state, zip_code,
                pilot_email, pilot_mobile, pilot_work_phone, pilot_home_phone,
                make_model, registration, net_weight_lb,
                ec_full_name, ec_mobile_phone, ec_relationship,
                notes, reviewed_by, reviewed_date,
                None, nowz, nowz
            ))
            return int(c.execute("SELECT last_insert_rowid()").fetchone()[0])

def set_pdf_path(row_id: int, pdf_path: str):
    with sqlite3.connect(get_db_file()) as c:
        c.execute(
            "UPDATE aircraft_info SET pdf_path=?, updated_at_utc=? WHERE id=?",
            (pdf_path, _now_iso_utc(), row_id)
        )

def get_aircraft(row_id: int) -> dict | None:
    rows = dict_rows("SELECT * FROM aircraft_info WHERE id=?", (row_id,))
    return rows[0] if rows else None

def find_by_registration(reg: str) -> dict | None:
    rows = dict_rows("SELECT * FROM aircraft_info WHERE registration=?", (_upper_tail(reg),))
    return rows[0] if rows else None

def list_aircraft(search: str | None = None) -> list[dict]:
    """Search by registration OR pilot_name (case-insensitive).
       Return aliased keys that match templates/partials/_aircraft_table.html."""
    base_select = """
      SELECT
        id,
        staff_id,
        pilot_name,
        registration,
        make_model                AS aircraft_make_model,
        net_weight_lb             AS net_available_weight_lbs,
        pilot_email               AS email,
        pilot_mobile              AS mobile_phone,
        pilot_work_phone          AS work_phone,
        pilot_home_phone          AS home_phone,
        created_at_utc            AS created_at,
        updated_at_utc            AS updated_at
      FROM aircraft_info
    """
    if not search:
        return dict_rows(base_select + " ORDER BY registration COLLATE NOCASE")
    s = f"%{search.strip()}%"
    return dict_rows(
        base_select + """
         WHERE registration LIKE ? OR pilot_name LIKE ?
         ORDER BY registration COLLATE NOCASE
        """,
        (s, s)
    )

# ─────────────────────────────────────────────────────────────────────────────
# Flask blueprint (merged routes)
# ─────────────────────────────────────────────────────────────────────────────
bp = Blueprint("aircraft", __name__, url_prefix="/aircraft")

@bp.before_app_request
def _ensure_schema_once():
    try:
        ensure_aircraft_tables()
    except Exception:
        pass

@bp.get("")
def aircraft_list_view():
    q = (request.args.get("q") or "").strip()
    rows = list_aircraft(q or None)
    return render_template("aircraft_list.html", active='supervisor', q=q, rows=rows)

@bp.get("/new")
def aircraft_new_form():
    staff_id = request.args.get("staff_id", type=int)
    if not staff_id:
        raise BadRequest("staff_id is required")
    # Prefill from staff; EC blank per policy
    staff_rows = dict_rows("SELECT * FROM staff WHERE id=? LIMIT 1", (int(staff_id),))
    staff = staff_rows[0] if staff_rows else {}
    existing = dict_rows("SELECT * FROM aircraft_info WHERE staff_id=? ORDER BY updated_at_utc DESC, id DESC LIMIT 1", (int(staff_id),))
    existing = existing[0] if existing else {}
    prefill = {
        "pilot_name": existing.get("pilot_name") or staff.get("name") or "",
        "pilot_cert_number": existing.get("pilot_cert_no") or "",
        "type_ratings": existing.get("ratings_text") or "",
        "email": existing.get("pilot_email") or staff.get("email") or "",
        "mobile_phone": existing.get("pilot_mobile") or staff.get("phone") or "",
        "work_phone": existing.get("pilot_work_phone") or "",
        "home_phone": existing.get("pilot_home_phone") or "",
        "street_address": existing.get("street_address") or "",
        "city_state": existing.get("city_state") or "",
        "zip_code": existing.get("zip_code") or "",
        "aircraft_make_model": existing.get("make_model") or "",
        "registration": existing.get("registration") or "",
        "net_available_weight_lbs": existing.get("net_weight_lb") or "",
        "emc_name": existing.get("ec_full_name") or "",
        "emc_phone": existing.get("ec_mobile_phone") or "",
        "emc_relationship": existing.get("ec_relationship") or "",
        "reviewed_by": existing.get("reviewed_by") or "",
        "review_notes": existing.get("notes") or "",
        "review_date_utc": existing.get("reviewed_date") or "",
    }
    return render_template("pai_form.html", staff_id=staff_id, prefill=prefill, existing=existing)

@bp.post("/new")
def aircraft_new_post():
    staff_id = request.form.get("staff_id", type=int)
    if not staff_id:
        raise BadRequest("staff_id is required")
    # Map form fields → DB schema
    f = lambda k: (request.form.get(k) or "").strip()
    try:
        row_id = upsert_aircraft(
            staff_id=staff_id,
            pilot_name=f("pilot_name"),
            pilot_cert_no=f("pilot_cert_number"),
            ratings_text=f("type_ratings"),
            street_address=f("street_address"),
            city_state=f("city_state"),
            zip_code=f("zip_code"),
            pilot_email=f("email"),
            pilot_mobile=f("mobile_phone"),
            pilot_work_phone=f("work_phone"),
            pilot_home_phone=f("home_phone"),
            make_model=f("aircraft_make_model"),
            registration=f("registration"),
            net_weight_lb=(request.form.get("net_available_weight_lbs") or "").strip(),
            ec_full_name=f("emc_name"),
            ec_mobile_phone=f("emc_phone"),
            ec_relationship=f("emc_relationship"),
            notes=f("review_notes"),
            reviewed_by=f("reviewed_by"),
            reviewed_date=f("review_date_utc"),
        )
    except ValueError as e:
        # re-render with error
        prefill = {k: request.form.get(k, "") for k in request.form.keys()}
        return render_template("pai_form.html", staff_id=staff_id, prefill=prefill, existing={}, errors={"__all__": str(e)}), 400

    if request.headers.get("X-Requested-With","").lower() == "xmlhttprequest":
        return jsonify(ok=True, id=row_id, pdf_url=url_for("aircraft.pai_print", id=row_id))
    return redirect(url_for("aircraft.pai_print", id=row_id))

@bp.get("/<int:id>/print")
def pai_print(id: int):
    rows = dict_rows("SELECT * FROM aircraft_info WHERE id=?", (int(id),))
    if not rows:
        raise NotFound("PAI not found")
    row = rows[0]
    html = render_template("pai_print.html", row={
        # shape the template context to expected keys
        "pilot_name": row.get("pilot_name",""),
        "pilot_cert_number": row.get("pilot_cert_no",""),
        "type_ratings": row.get("ratings_text",""),
        "email": row.get("pilot_email",""),
        "mobile_phone": row.get("pilot_mobile",""),
        "work_phone": row.get("pilot_work_phone",""),
        "home_phone": row.get("pilot_home_phone",""),
        "street_address": row.get("street_address",""),
        "city_state": row.get("city_state",""),
        "zip_code": row.get("zip_code",""),
        "aircraft_make_model": row.get("make_model",""),
        "registration": _upper_tail(row.get("registration","")),
        "net_available_weight_lbs": row.get("net_weight_lb"),
        "emc_name": row.get("ec_full_name",""),
        "emc_phone": row.get("ec_mobile_phone",""),
        "emc_relationship": row.get("ec_relationship",""),
        "reviewed_by": row.get("reviewed_by",""),
        "review_notes": row.get("notes",""),
        "review_date_utc": row.get("reviewed_date",""),
        "created_at": row.get("created_at_utc",""),
        "updated_at": row.get("updated_at_utc",""),
    })
    # Write PDF best-effort
    wrote = False
    try:
        from weasyprint import HTML, CSS
        out = pai_pdf_path(int(id))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        # Use filesystem base + include app stylesheet so print rules apply
        base = current_app.root_path
        stylesheets = []
        css_file = os.path.join(base, "static", "style.css")
        if os.path.exists(css_file):
            stylesheets.append(CSS(filename=css_file))
        HTML(string=html, base_url=base).write_pdf(out, stylesheets=stylesheets)
        from modules.utils.aircraft import set_pdf_path  # self-import OK
        set_pdf_path(int(id), out)
        wrote = True
    except Exception as e:
        current_app.logger.warning("PAI PDF write skipped: %s", e)
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}

@bp.get("/<int:id>/json")
def pai_json(id: int):
    rows = dict_rows("SELECT * FROM aircraft_info WHERE id=?", (int(id),))
    if not rows:
        raise NotFound("PAI not found")
    return jsonify(rows[0])

# ─────────────────────────────────────────────────────────────────────────────
# Delete aircraft record (documents remain on disk)
# ─────────────────────────────────────────────────────────────────────────────
@bp.post("/<int:id>/delete")
def aircraft_delete(id: int):
    """Delete a single aircraft_info row by id.
       NOTE: Does NOT delete any files referenced by pdf_path. Documents are kept."""
    rows = dict_rows("SELECT id, pdf_path FROM aircraft_info WHERE id=?", (int(id),))
    if not rows:
        # For AJAX callers, return 404 JSON; otherwise redirect back to list.
        if request.headers.get("X-Requested-With","").lower() == "xmlhttprequest":
            return jsonify(ok=False, message="Aircraft not found"), 404
        raise NotFound("Aircraft not found")
    with sqlite3.connect(get_db_file()) as c:
        c.execute("DELETE FROM aircraft_info WHERE id=?", (int(id),))
    if request.headers.get("X-Requested-With","").lower() == "xmlhttprequest":
        return jsonify(ok=True, deleted_id=int(id))
    return redirect(url_for("aircraft.aircraft_list_view"))
