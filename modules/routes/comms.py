from __future__ import annotations
import csv, io, json, sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple
from flask import (
    Blueprint, current_app, render_template, request, Response, url_for,
    redirect, flash, session
)

# Shared helpers
from modules.utils.comms import (
    insert_comm,
    parse_comm_filters,
    sql_for_comm_filters,
)
from modules.utils.common import dict_rows  # DB row → dict list

bp = Blueprint("comms", __name__)

# ---- helpers ---------------------------------------------------------------

def _distinct_methods() -> List[str]:
    try:
        rows = dict_rows("SELECT DISTINCT method FROM communications ORDER BY method ASC")
        return [r["method"] for r in rows if r.get("method")]
    except Exception:
        return []

def _parse_meta(meta_json: str) -> Dict[str, Any]:
    try:
        return json.loads(meta_json or "{}") or {}
    except Exception:
        return {}

def _rows_for_filters(filters: Dict[str, Any], limit: int = 500) -> List[Dict[str, Any]]:
    where_sql, params = sql_for_comm_filters(filters)
    sql = f"""
      SELECT id, timestamp_utc, method, direction, from_party, to_party,
             subject, body, operator, metadata_json
        FROM communications
        {where_sql}
       ORDER BY timestamp_utc DESC, id DESC
       LIMIT ?
    """
    return dict_rows(sql, tuple(params) + (limit,))

def _get_operator_label() -> str:
    """
    Prefer operator identity from session (if your app sets it),
    fall back to the operator_call cookie.
    """
    return (session.get('operator_call') or request.cookies.get('operator_call') or '').strip()

# ---- routes ----------------------------------------------------------------
@bp.get("/comms/red_flight", endpoint="red_flight_form")
def red_flight_form():
    """Red Flight entry form (specialized comms entry)."""
    now_utc_value = datetime.utcnow().strftime("%Y-%m-%dT%H:%M")
    return render_template(
        "red_flight.html",
        now_utc_value=now_utc_value,
        operator_label=_get_operator_label() or "",
        active="supervisor",
    )

@bp.post("/comms/red_flight", endpoint="red_flight_submit")
def red_flight_submit():
    """
    Create a Red Flight communication using the communications table.
    Stores structured details in metadata_json.
    """
    def _fnum(x):
        try:
            s = (x or "").strip()
            return float(s) if s != "" else None
        except Exception:
            return None

    ts_raw         = (request.form.get("timestamp_utc") or "").strip()
    origin_airport = (request.form.get("origin_airport") or "").strip().upper()
    area_label     = (request.form.get("area_label") or "").strip()
    lat            = _fnum(request.form.get("lat"))
    lon            = _fnum(request.form.get("lon"))
    notes          = (request.form.get("notes") or "").strip()

    # Repeatable infrastructure rows
    names   = request.form.getlist("infra_name[]") or request.form.getlist("infra_name")
    damages = request.form.getlist("infra_damage[]") or request.form.getlist("infra_damage")
    infra   = []
    for n, d in zip(names, damages):
        n = (n or "").strip()
        d = (d or "").strip()
        if n or d:
            infra.append({"name": n, "damage": d})

    metadata = {
        "kind": "red_flight",
        "origin_airport": origin_airport,
        "area_label": area_label,
        "infrastructure": infra,
        "notes": notes,
        "source": "red_flight_ui",
    }
    if lat is not None and lon is not None:
        metadata["gps"] = {"lat": lat, "lon": lon}

    subject = "Red Flight — " + (area_label or origin_airport or "Unspecified")
    # Short summary body (full details live in metadata)
    body_parts = []
    if area_label:
        body_parts.append(f"Area: {area_label}")
    if origin_airport:
        body_parts.append(f"Origin: {origin_airport}")
    if lat is not None and lon is not None:
        body_parts.append(f"GPS: {lat:.6f}, {lon:.6f}")
    if infra:
        flat = []
        for it in infra:
            nm = (it.get('name') or '').strip()
            dm = (it.get('damage') or '').strip()
            if nm or dm:
                flat.append(f"{nm}: {dm}".strip(": "))
        if flat:
            body_parts.append("Infrastructure: " + "; ".join(flat))
    if notes:
        body_parts.append("Notes: " + notes)
    body = " | ".join([p for p in body_parts if p])

    try:
        insert_comm(
            timestamp_utc=ts_raw or None,
            method="Red Flight",
            direction="internal",     # treat as internal report; adjust if you prefer "in"
            from_party=None,
            to_party=None,
            subject=subject,
            body=body or None,
            operator=_get_operator_label() or None,
            notes=None,
            metadata=metadata,
        )
        flash("Red Flight logged.", "success")
        return redirect(url_for("comms.comms_index", window="all", method="Red Flight"))
    except Exception as e:
        current_app.logger.exception("Red Flight insert failed: %s", e)
        flash("Could not save Red Flight.", "error")
        return redirect(url_for("comms.red_flight_form"))

@bp.route("/comms", methods=["GET"], endpoint="comms_index")
def comms_index():
    filters = parse_comm_filters(request)
    # Default to ALL TIME when no explicit ?window= is provided
    # (overrides any 24h default inside parse_comm_filters on first load).
    if "window" not in request.args or (request.args.get("window") or "").strip() == "":
        filters["window"] = "all"

    rows = _rows_for_filters(filters, limit=500)
    # decorate a few view fields without mutating originals
    view_rows = []
    for r in rows:
        v = dict(r)
        # short subject for table
        subj = (v.get("subject") or "").strip()
        if len(subj) > 120:
            subj = subj[:117] + "…"
        v["subject_short"] = subj
        # ISO → human UTC (keep UTC to avoid TZ drift)
        ts = (v.get("timestamp_utc") or "").split(".")[0].replace("T", " ")
        v["ts_view"] = ts
        view_rows.append(v)

    # Default value for the quick-add datetime-local control (UTC)
    now_utc_value = datetime.utcnow().strftime("%Y-%m-%dT%H:%M")

    ics_params = {k: v for k, v in filters.items() if v}
    return render_template(
        "comms.html",
        rows=view_rows,
        methods=_distinct_methods(),
        filters=filters,
        export_url=url_for("comms.comms_export_csv", **{k: v for k, v in filters.items() if v}),
        ics309_url=url_for("exports.comms_ics309", **ics_params),
        ics309_download_url=url_for("exports.comms_ics309_download", **ics_params),
        now_utc_value=now_utc_value,
        active="supervisor",  # keep Airport Ops highlighted
    )

@bp.get("/comms/<int:comm_id>", endpoint="comms_detail")
def comms_detail(comm_id: int):
    """Return an HTML snippet with the full communication details (for modal)."""
    row = dict_rows("""
        SELECT id, timestamp_utc, method, direction, from_party, to_party,
               subject, body, operator, notes, metadata_json
          FROM communications
         WHERE id=?
         LIMIT 1
    """, (comm_id,))
    if not row:
        return ("<div style='padding:1rem;'>Not found.</div>", 404)
    r = row[0]
    meta = {}
    try:
        meta = json.loads(r.get("metadata_json") or "{}") or {}
    except Exception:
        meta = {"_raw": (r.get("metadata_json") or "")}
    # Pretty JSON for display
    try:
        meta_pretty = json.dumps(meta, indent=2, ensure_ascii=False)
    except Exception:
        meta_pretty = r.get("metadata_json") or ""
    # Derived fields for Red Flight (friendly block)
    rf = None
    if (meta or {}).get("kind") == "red_flight":
        gps = meta.get("gps") or {}
        rf = {
            "origin": (meta.get("origin_airport") or "").strip(),
            "area": (meta.get("area_label") or "").strip(),
            "lat": gps.get("lat"),
            "lon": gps.get("lon"),
            "infra": meta.get("infrastructure") or [],
            "notes": (meta.get("notes") or "").strip(),
        }
    return render_template("partials/_comm_detail.html", r=r, meta_pretty=meta_pretty, rf=rf)

@bp.route("/comms/export.csv", methods=["GET"], endpoint="comms_export_csv")
def comms_export_csv():
    """Back-compat shim: redirect to the authoritative communications.csv exporter."""
    target = url_for("exports.export_communications_csv")
    qs = request.query_string.decode("utf-8")
    return redirect(f"{target}?{qs}" if qs else target, code=302)

@bp.route("/comms/new", methods=["POST"], endpoint="comms_new")
def comms_new():
    """
    Quick Add: create a manual communications row (CSRF-protected).
    Fields:
      timestamp_utc (datetime-local, UTC), method (required), direction (optional),
      from_party, to_party, subject, body, notes.
    Stores operator from session/cookie. Sets metadata.source=manual_comms.
    """
    ts_raw     = (request.form.get("timestamp_utc") or "").strip()
    method     = (request.form.get("method") or "").strip()
    direction  = (request.form.get("direction") or "").strip().lower()
    from_p     = (request.form.get("from_party") or "").strip()
    to_p       = (request.form.get("to_party") or "").strip()
    subject    = (request.form.get("subject") or "").strip()
    body       = (request.form.get("body") or "").strip()
    notes      = (request.form.get("notes") or "").strip()

    if not method:
        flash("Method is required for Quick Add.", "error")
        return redirect(url_for("comms.comms_index"))

    if direction not in ("in", "out", "internal"):
        direction = None

    try:
        insert_comm(
            timestamp_utc=ts_raw or None,   # helper will coerce/now()
            method=method,
            direction=direction,
            from_party=from_p or None,
            to_party=to_p or None,
            subject=subject or None,
            body=body or None,
            operator=_get_operator_label() or None,
            notes=notes or None,
            metadata={"source": "manual_comms"},
        )
        flash("Communication added.", "success")
    except Exception as e:
        current_app.logger.exception("Quick Add failed: %s", e)
        flash("Could not add communication.", "error")
    return redirect(url_for("comms.comms_index"))
