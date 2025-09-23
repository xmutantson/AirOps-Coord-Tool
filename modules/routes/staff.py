from __future__ import annotations
from datetime import datetime, timedelta, timezone
import io

from flask import (
    Blueprint, render_template, render_template_string, request, redirect, url_for, jsonify,
    current_app, send_file, session
)
from app import DB_FILE  # ← required by staff_delete()
from modules.utils.common import dict_rows, get_preference, set_preference  # shared helpers
from modules.utils.staff import (
    ensure_staff_tables,
    get_or_create_staff,
    toggle_shift as _toggle_shift,
    list_staff,
)

from modules.utils.common import get_db_file
import sqlite3

bp = Blueprint(__name__.rsplit('.', 1)[-1], __name__)  # → "staff"
app = current_app  # legacy shim (matches other route files)

_ALLOWED_WINDOWS = {"12h", "24h", "72h", "all"}

def _window_arg() -> str:
    w = (request.args.get("window") or request.form.get("window") or "all").lower()
    return w if w in _ALLOWED_WINDOWS else "all"

@bp.before_app_request
def _ensure_tables_once():
    # Best-effort; idempotent
    try:
        ensure_staff_tables()
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# Staff list + actions
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/supervisor/staff", methods=["GET"])
def staff_list():
    window = _window_arg()
    rows = list_staff(window)
    # Partial table refresh for AJAX
    if request.args.get("partial") == "1" or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return render_template("partials/_staff_table.html", rows=rows, window=window)
    return render_template("supervisor_staff.html", rows=rows, window=window)

@bp.route("/supervisor/staff/new", methods=["POST"])
def staff_new():
    name = (request.form.get("name") or "").strip()
    organization = (request.form.get("organization") or "").strip()
    emc   = (request.form.get("emc") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    window = _window_arg()
    if name:
        try:
            # New signature for get_or_create_staff to support richer fields.
            # (We’ll patch modules.utils.staff accordingly.)
            srow = get_or_create_staff(
                name,
                organization=organization,
                emc=emc,
                email=email,
                phone=phone,
            )
            sid = None
            try:
                sid = int(srow.get("id")) if srow else None
            except Exception:
                sid = None
            # Auto clock-in on add
            try:
                if sid:
                    _toggle_shift(sid, "on", source="add", notes="Auto clock-in on add")
            except Exception:
                pass

            # AJAX path: return a machine-readable success so the client can pop waivers.
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                payload = {
                    "ok": True,
                    "staff_id": sid,
                    "name": name,
                    # handy direct links:
                    "waiver_choose_url": url_for("staff.waiver_choose", staff_id=sid, name=name) if sid else url_for("staff.waiver_choose"),
                    "waiver_pilot_url": url_for("exports.docs_waiver_pilot") + (f"?staff_id={sid}" if sid else ""),
                    "waiver_volunteer_url": url_for("exports.docs_waiver_volunteer") + (f"?staff_id={sid}" if sid else ""),
                }
                return jsonify(payload)

            # Non-AJAX path: if no organization was given, still allow waiver chooser
            if srow and not organization and sid:
                return redirect(url_for("staff.waiver_choose", staff_id=sid, name=name))
        except Exception:
            # Don’t crash the page; just fall back to redirect
            pass
    return redirect(url_for("staff.staff_list", window=window))

@bp.route("/supervisor/staff/<int:staff_id>/delete", methods=["POST"])
def staff_delete(staff_id: int):
    """Hard delete a staff record (and best-effort cleanup)."""
    import sqlite3
    window = _window_arg()
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute("DELETE FROM staff WHERE id=?", (staff_id,))
        for tbl, col in (("staff_shifts","staff_id"), ("staff_status","staff_id")):
            try: conn.execute(f"DELETE FROM {tbl} WHERE {col}=?", (staff_id,))
            except Exception: pass
        conn.commit(); conn.close()
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": True})
    except Exception:
        # Make the failure visible in Docker/stdout logs
        try:
            current_app.logger.exception("Staff delete failed for id=%s", staff_id)
        except Exception:
            pass
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False}), 500
    return redirect(url_for("staff.staff_list", window=window))

# ─────────────────────────────────────────────────────────────────────────────
# Quick check-in from the login-time modal
#   POST /supervisor/staff/quick_checkin
#     • when skip=1 → just set cooldown cookie
#     • else → upsert staff, clock in if not already on duty, set cooldown + prefill cookies
# Cooldown is 14 hours (50,400 seconds).
# ─────────────────────────────────────────────────────────────────────────────
@bp.post("/supervisor/staff/quick_checkin")
def staff_quick_checkin():
    """
    Dashboard first-login modal helper.
    Contract expected by frontend (dashboard.html):
      - If no name found: { ok: true, needs_profile: true }
      - If found & not on duty: opens shift → { ok: true, existing: true, toggled: "started", staff_id, name }
      - If found & on duty: close then open (restart) → { ok: true, existing: true, toggled: "restarted", staff_id, name }
      - Optional: needs_waiver bool + waiver_choose_url if your app uses that
    """
    if request.form.get("skip"):
        return jsonify(ok=True, skipped=True)

    name = (request.form.get("name") or "").strip()
    if not name:
        return jsonify(ok=False, message="Name required"), 400

    # Lookup by case-insensitive name (no .get calls on sqlite3.Row)
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        row = c.execute(
            "SELECT * FROM staff WHERE LOWER(name)=LOWER(?) LIMIT 1", (name,)
        ).fetchone()
        staff = dict(row) if row else None

    if not staff:
        # Frontend will expand to Stage 2 to capture details & create profile
        return jsonify(ok=True, needs_profile=True)

    staff_id = int(staff["id"])

    # Are they currently on duty?
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        open_row = c.execute(
            "SELECT id FROM staff_shifts WHERE staff_id=? AND end_utc IS NULL ORDER BY start_utc DESC, id DESC LIMIT 1",
            (staff_id,),
        ).fetchone()

    if open_row:
        # Restart: clock out then in
        _toggle_shift(staff_id, "off", source="quick_checkin", notes="restart")
        _toggle_shift(staff_id, "on",  source="quick_checkin")
        return jsonify(ok=True, existing=True, toggled="restarted",
                       staff_id=staff_id, name=staff.get("name", name),
                       needs_waiver=False)
    else:
        # Start fresh
        _toggle_shift(staff_id, "on", source="quick_checkin")
        return jsonify(ok=True, existing=True, toggled="started",
                       staff_id=staff_id, name=staff.get("name", name),
                       needs_waiver=False)

# ─────────────────────────────────────────────────────────────────────────────
# Simple waiver choice page (two buttons → open waiver in a new tab)
# GET /staff/waiver/choose?staff_id=…[&name=…][&window=…]
# ─────────────────────────────────────────────────────────────────────────────
@bp.get("/staff/waiver/choose")
def waiver_choose():
    staff_id = request.args.get("staff_id", type=int)
    name     = (request.args.get("name") or "").strip()
    window   = _window_arg()
    # Backfill name if omitted
    if staff_id and not name:
        try:
            row = next((r for r in list_staff("all") if int(r["id"]) == int(staff_id)), None)
            if row:
                name = row.get("name") or name
        except Exception:
            pass
    pilot_href = f"/docs/waiver/pilot?staff_id={staff_id}" if staff_id else "/docs/waiver/pilot"
    vol_href   = f"/docs/waiver/volunteer?staff_id={staff_id}" if staff_id else "/docs/waiver/volunteer"
    back_href  = url_for("staff.staff_list", window=window)
    # Tiny one-shot HTML; no dedicated template needed.
    return render_template_string("""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Choose Waiver</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
  </head>
  <body class="supervisor">
    <main class="container" style="max-width: 680px; margin: 2rem auto;">
      <h2 style="margin:0 0 .5rem 0;">Choose waiver for {{ name or 'new staffer' }}</h2>
      <p class="muted" style="margin:0 0 1rem 0;">Open the correct waiver in a new tab. When done, return to the roster.</p>
      <div style="display:flex; gap:.75rem; flex-wrap:wrap;">
        <a class="button" style="padding:.6rem 1.1rem;" target="_blank" rel="noopener"
           href="{{ pilot_href }}">Pilot</a>
        <a class="button" style="padding:.6rem 1.1rem;" target="_blank" rel="noopener"
           href="{{ vol_href }}">Volunteer</a>
        <a class="button secondary" style="margin-left:auto; padding:.6rem 1.1rem;"
           href="{{ back_href }}">Back to Roster</a>
      </div>
    </main>
  </body>
</html>
    """, name=name, pilot_href=pilot_href, vol_href=vol_href, back_href=back_href)

@bp.route("/supervisor/staff/<int:staff_id>/toggle", methods=["POST"])
def staff_toggle(staff_id: int):
    window = _window_arg()
    on_off = (request.form.get("on_off") or "").strip().lower()
    # If no action provided, infer from current state (toggle)
    if not on_off:
        for r in list_staff("all"):
            if int(r["id"]) == int(staff_id):
                on_off = "off" if r.get("on_duty") else "on"
                break
        if not on_off:
            on_off = "on"

    notes  = (request.form.get("notes") or "").strip()
    source = "ui"
    result = _toggle_shift(staff_id, on_off, source=source, notes=notes)

    # AJAX?
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        fresh = list_staff(window)
        row = next((r for r in fresh if r["id"] == staff_id), None)
        return jsonify({"ok": True, "action": result.get("action"), "row": row, "window": window})

    return redirect(url_for("staff.staff_list", window=window))

# ─────────────────────────────────────────────────────────────────────────────
# ICS-214 (HTML only; single-file download optional)
#   • GET /supervisor/staff/ics214
#   • GET /supervisor/staff/ics214.html
# ─────────────────────────────────────────────────────────────────────────────

def _window_bounds(window: str):
    """Return (since_dt_utc, now_dt_utc or None if 'all')."""
    now = datetime.now(timezone.utc)
    hours = {"12h": 12, "24h": 24, "72h": 72, "all": None}[window]
    return ((now - timedelta(hours=hours), now) if hours is not None else (None, now))

def _iso(dt: datetime | None) -> str:
    if not dt:
        return ""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def _fmt_date(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d") if dt else ""

def _fmt_time(dt: datetime | None) -> str:
    return dt.strftime("%H:%M") if dt else ""

def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None

def _ics214_context(window: str):
    """Build the render context for the ICS-214 page from staff/shift data."""
    ensure_staff_tables()
    since, now = _window_bounds(window)
    since_iso = _iso(since)
    now_iso   = _iso(now)

    # Derive a data-driven operational period when window == 'all'
    # (otherwise the From/To header looks blank or misleading).
    op_from_dt = since
    op_to_dt   = now
    if since is None:
        try:
            rng = dict_rows("""
                SELECT MIN(start_utc) AS min_start,
                       MAX(COALESCE(end_utc, start_utc)) AS max_end
                  FROM staff_shifts
            """)
            if rng:
                smin = _parse_iso(rng[0].get("min_start"))
                smax = _parse_iso(rng[0].get("max_end"))
                if smin: op_from_dt = smin
                if smax: op_to_dt   = smax
        except Exception:
            pass

    # Window predicate for "resources touched this window" (unchanged: overlap)
    where_sql = ""
    params: tuple = ()
    if since:
        where_sql = """
           WHERE
             (IFNULL(start_utc,'') <> '' AND start_utc >= ? AND start_utc <= ?)
          OR (IFNULL(end_utc  ,'') <> '' AND end_utc   >= ? AND end_utc   <= ?)
          OR (IFNULL(start_utc,'') <> '' AND start_utc <  ? AND (end_utc IS NULL OR end_utc >= ?))
        """
        params = (since_iso, now_iso, since_iso, now_iso, since_iso, since_iso)

    # Resources assigned (unique people who touched the window)
    res_rows = dict_rows(f"""
      SELECT DISTINCT s.id, s.name,
                      IFNULL(s.organization,'') AS organization,
                      IFNULL(s.emc,'')          AS emc,
                      IFNULL(s.email,'')        AS email,
                      IFNULL(s.phone,'')        AS phone
        FROM staff s
        LEFT JOIN staff_shifts sh ON sh.staff_id = s.id
        {where_sql}
       ORDER BY s.name COLLATE NOCASE
    """, params)

    # For ICS-214: show each person; map Organization → Home Agency.
    # (ICS position remains a header field; we don't hardcode per person.)
    resources = [{
        "name": r["name"],
        "ics_position": "",                           # leave blank; filled by header field
        "home_agency": r.get("organization") or "",
    } for r in res_rows]

    # Activity log: ONLY shifts that ENDED within the window
    if since:
        end_where = "WHERE IFNULL(sh.end_utc,'') <> '' AND sh.end_utc >= ? AND sh.end_utc <= ?"
        end_params = (since_iso, now_iso)
    else:
        end_where = "WHERE IFNULL(sh.end_utc,'') <> ''"
        end_params = ()

    sh_rows = dict_rows(f"""
      SELECT sh.staff_id,
             s.name,
             IFNULL(s.organization,'') AS organization,
             sh.start_utc, sh.end_utc
        FROM staff_shifts sh
        JOIN staff s ON s.id = sh.staff_id
        {end_where}
       ORDER BY sh.end_utc ASC, s.name COLLATE NOCASE
    """, end_params)

    def _fmt(ts: str | None) -> str:
        dt = _parse_iso(ts)
        return (dt.strftime("%Y-%m-%d %H:%M") + "Z") if dt else ""

    # Build compact "clock-out only" entries
    activities = []
    for sh in sh_rows:
        org = (sh.get("organization") or "").strip()
        st, en = sh.get("start_utc"), sh.get("end_utc")
        sdt, edt = _parse_iso(st), _parse_iso(en)
        # Duration (fallback to 0 if start missing)
        mins = 0
        if sdt and edt and edt >= sdt:
            mins = int((edt - sdt).total_seconds() // 60)
        msg = f"{sh['name']} shift end (duration {mins//60}h {mins%60:02d}m)"
        if org:
            msg += f" [{org}]"
        activities.append({"time": _fmt(en), "text": msg})

    # Sort chronologically (fallback to raw string if parse failed)
    def _key(a): 
        try:
            return datetime.strptime(a["time"].replace("Z",""), "%Y-%m-%d %H:%M")
        except Exception:
            return a["time"]
    activities.sort(key=_key)

    incident_name = get_preference("incident_name") or ""
    # Header values: allow URL overrides, else fall back to stored prefs.
    def _arg_or_pref(arg_key, pref_key, default=""):
        v = (request.args.get(arg_key) or "").strip()
        if v != "":
            return v
        return get_preference(pref_key) or default

    # 1,3,4,5,8 (all independent)
    name_field        = _arg_or_pref("name_field",        "ics214_name",        "")
    ics_position      = _arg_or_pref("ics214_position",   "ics214_position",    "Staffing / Supervisor")
    home_agency       = _arg_or_pref("home_agency",       "home_agency",        "")
    prepared_by_name  = _arg_or_pref("prepared_by_name",  "prepared_by_name",   "")
    prepared_by_title = _arg_or_pref("prepared_by_title", "prepared_by_title",  "")
    # allow incident_name override too
    incident_name     = (request.args.get("incident_name") or incident_name).strip()

    # ── Build a display value that always appends the mission number (if present) ──
    mission_number = (request.args.get("mission_number") or (get_preference("mission_number") or "")).strip()
    if mission_number:
        suffix = f"Mission Number: {mission_number}"
        if suffix.lower() in incident_name.lower():
            incident_name_display = incident_name
        else:
            incident_name_display = (incident_name + (" — " if incident_name else "") + suffix).strip(" —")
    else:
        incident_name_display = incident_name

    ctx = {
        "incident_name": incident_name,                  # base (editable in modal)
        "incident_name_display": incident_name_display,  # rendered in labeled field
        "op_from_date": _fmt_date(op_from_dt),
        "op_from_time": _fmt_time(op_from_dt),
        "op_to_date":   _fmt_date(op_to_dt),
        "op_to_time":   _fmt_time(op_to_dt),
        "name_field": name_field,
        "ics_position": ics_position,
        "home_agency": home_agency,
        "resources": resources,
        "activities": activities,
        "prepared_by": prepared_by_name,       # for template compatibility
        "prepared_by_name": prepared_by_name,  # explicit
        "prepared_by_title": prepared_by_title,
        "prepared_dt": datetime.utcnow().strftime("%Y-%m-%d %H:%MZ"),
        "window": window,
        # If any header field missing, show modal on load
        "show_header_modal": not all([
            incident_name, name_field, ics_position, home_agency,
            prepared_by_name, prepared_by_title
        ]),
        # keep Supervisor highlighted in nav
        "active": "supervisor",
    }
    return ctx

@bp.get("/supervisor/staff/ics214")
def staff_ics214():
    window = _window_arg()
    ctx = _ics214_context(window)
    return render_template("ics214.html", **ctx)

@bp.get("/supervisor/staff/ics214.html", endpoint="staff_ics214_download")
def staff_ics214_download():
    window = _window_arg()
    ctx = _ics214_context(window)
    html = render_template("ics214_standalone.html", **ctx)
    return send_file(
        io.BytesIO(html.encode("utf-8")),
        mimetype="text/html; charset=utf-8",
        as_attachment=True,
        download_name=f"ICS-214_{ctx.get('op_from_date','') or 'all'}_{window}.html",
    )

# ─────────────────────────────────────────────────────────────────────────────
# ICS-214 — save header preferences (AJAX)
# POST /supervisor/staff/ics214/prefs
# Body: form or JSON with incident_name, ics214_name, ics214_position, home_agency,
#       prepared_by_name, prepared_by_title
# ─────────────────────────────────────────────────────────────────────────────
@bp.post("/supervisor/staff/ics214/prefs")
def staff_ics214_save_prefs():
    data = request.get_json(silent=True) or request.form
    fields = {
        "incident_name":     (data.get("incident_name") or "").strip(),
        "ics214_name":       (data.get("ics214_name") or "").strip(),
        "ics214_position":   (data.get("ics214_position") or "").strip(),
        "home_agency":       (data.get("home_agency") or "").strip(),
        "prepared_by_name":  (data.get("prepared_by_name") or "").strip(),
        "prepared_by_title": (data.get("prepared_by_title") or "").strip(),
    }
    # Persist non-empty values (allow clearing by sending an explicit empty string if desired)
    for k, v in fields.items():
        set_preference(k, v)
    return jsonify({"ok": True, "saved": fields})
