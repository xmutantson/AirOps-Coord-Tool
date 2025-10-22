# modules/routes/webeoc.py
from __future__ import annotations

from flask import Blueprint, jsonify, request
from modules.services.webeoc.ingest_rr import parse_saved_data
from modules.utils.common import _rr_webeoc_guess_inline_xml, _rr_webeoc_is_wa_message
from modules.utils.common import dict_rows as _dict_rows  # already imported as dict_rows
from modules.utils.common import dict_rows

bp = Blueprint("webeoc", __name__, url_prefix="/webeoc")


def _prio_label_for_ui(code: int | None) -> str:
    """
    Map numeric priority to the exact labels used by the UI drop-down.
    """
    try:
        c = int(code or 1)
    except Exception:
        c = 1
    return {
        3: "Lifesaving",
        2: "Property Preservation",
        1: "Incident Stabilization",
    }.get(c, "Incident Stabilization")


def _to_ui_payload(parsed: dict) -> dict:
    """
    Convert parse_saved_data() → { airport, priority, items:[{name,weight_lb}] }.
    If multiple items disagree, we take the first values seen for airport/priority.
    """
    items = parsed.get("items") or []
    airport = ""
    pri_code = None
    out_items = []
    for it in items:
        if not airport and it.get("airport"):
            airport = str(it["airport"]).upper()
        if pri_code is None and it.get("priority_code") is not None:
            pri_code = int(it["priority_code"])
        out_items.append({
            "name": it.get("need") or "",
            "weight_lb": float(it.get("qty_lb") or 0.0) or 0.0,
        })
    return {"airport": airport, "priority": _prio_label_for_ui(pri_code), "items": out_items}


@bp.post("/import_from_text")
def import_from_text():
    """
    Body: JSON { "text": "<WebEOC Save data JSON or plain text>" }  OR form 'text'/'payload'
    Returns: { ok, payload:{airport,priority,items:[{name,weight_lb}] } }
    """
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        data = {}
    text = (data.get("text") or request.form.get("text") or request.form.get("payload") or "").strip()
    if not text:
        return jsonify({"ok": False, "error": "missing text"}), 400
    try:
        parsed = parse_saved_data(text)
        return jsonify({"ok": True, "payload": _to_ui_payload(parsed)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@bp.post("/import_from_email")
def import_from_email():
    """
    Body: JSON { "email_id": "<id from winlink inbox>" }
    Pulls the stored winlink message body and parses it.
    """
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        data = {}
    email_id = str(data.get("email_id") or "").strip()
    if not email_id:
        return jsonify({"ok": False, "error": "missing email_id"}), 400

    # Read body from stored winlink_messages
    rows = dict_rows("SELECT subject, body FROM winlink_messages WHERE id=?", (email_id,))
    subject = (rows[0].get("subject") or "").strip() if rows else ""
    body    = (rows[0].get("body") or "").strip() if rows else ""
    if not body:
        return jsonify({"ok": False, "error": "email not found"}), 404

    # Prefer inline XML if present; else fall back to body (JSON or text)
    inline_xml = _rr_webeoc_guess_inline_xml(body)
    parsed = parse_saved_data(inline_xml or body)
    return jsonify({"ok": True, "payload": _to_ui_payload(parsed)})
