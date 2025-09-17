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
