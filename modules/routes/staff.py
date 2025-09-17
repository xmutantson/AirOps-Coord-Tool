from __future__ import annotations
from datetime import datetime, timedelta, timezone
import io

from flask import (
    Blueprint, render_template, request, redirect, url_for, jsonify,
    current_app, send_file, session
)
from modules.utils.common import dict_rows, get_preference, set_preference  # shared helpers
from modules.utils.staff import (
    ensure_staff_tables,
    get_or_create_staff,
    toggle_shift as _toggle_shift,
    list_staff,
)

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
    role = (request.form.get("role") or "").strip()
    ew   = (request.form.get("ew_number") or "").strip()
    window = _window_arg()
    if name:
        try:
            get_or_create_staff(name, role=role, ew_number=ew)
        except Exception:
            # Don’t crash the page; just fall back to redirect
            pass
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
    try:
        ensure_staff_tables()
    except Exception:
        pass

    COOLDOWN_S = 14 * 3600  # 14 hours
    resp = jsonify({"ok": True})

    # Always consume the one-shot login flag so refresh won't re-open the modal.
    try:
        session.pop("just_logged_in", None)
    except Exception:
        pass

    # Skip path: only a cooldown cookie
    if (request.form.get("skip") or "") == "1":
        resp.set_cookie("checked_in_recently", "1", max_age=COOLDOWN_S, samesite="Lax")
        return resp

    name = (request.form.get("name") or "").strip()
    role = (request.form.get("role") or "").strip()
    ew   = (request.form.get("ew_number") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name_required"}), 400

    # Upsert staff and open a shift if not already on duty
    srow = get_or_create_staff(name, role=role, ew_number=ew)
    sid = int(srow.get("id"))
    try:
        row = next((r for r in list_staff("all") if int(r["id"]) == sid), None)
        if not (row and row.get("on_duty")):
            _toggle_shift(sid, "on", source="login", notes="Login check-in")
    except Exception:
        pass

    # Prefill cookies for next time (1 year)
    ONE_YEAR = 365 * 24 * 3600
    resp.set_cookie("last_staff_name", name, max_age=ONE_YEAR, samesite="Lax")
    if role:
        resp.set_cookie("last_staff_role", role, max_age=ONE_YEAR, samesite="Lax")
    if ew:
        resp.set_cookie("last_staff_ew",   ew,   max_age=ONE_YEAR, samesite="Lax")

    # Cooldown cookie so we don't nag again for a while
    resp.set_cookie("checked_in_recently", "1", max_age=COOLDOWN_S, samesite="Lax")
    return resp

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
                      IFNULL(s.role,'')      AS role,
                      IFNULL(s.ew_number,'') AS ew_number
        FROM staff s
        LEFT JOIN staff_shifts sh ON sh.staff_id = s.id
        {where_sql}
       ORDER BY s.name COLLATE NOCASE
    """, params)

    resources = [{
        "name": r["name"],
        "ics_position": r.get("role") or "",
        "home_agency": r.get("ew_number") or "",
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
             IFNULL(s.role,'') AS role,
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
        role = (sh.get("role") or "").strip()
        st, en = sh.get("start_utc"), sh.get("end_utc")
        sdt, edt = _parse_iso(st), _parse_iso(en)
        # Duration (fallback to 0 if start missing)
        mins = 0
        if sdt and edt and edt >= sdt:
            mins = int((edt - sdt).total_seconds() // 60)
        msg = f"{sh['name']} shift end (duration {mins//60}h {mins%60:02d}m)"
        if role:
            msg += f" [{role}]"
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

    ctx = {
        "incident_name": incident_name,
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
