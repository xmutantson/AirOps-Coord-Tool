# modules/routes_inventory/requests.py
from __future__ import annotations

from flask import request, jsonify, render_template, current_app
from app import inventory_bp
from modules.services import cargo as cargo_svc
from modules.utils.common import sanitize_name as cr_sanitize_item, ensure_column
from modules.utils.common import canonical_airport_code, prio_from_text, cr2_upsert_request_group
from app import DB_FILE
import sqlite3
from datetime import datetime
from typing import Optional
from modules.utils.comms import insert_comm

def _display_from_sanitized(s: str) -> str:
    """UI label from a sanitized key: 'rice-bags' -> 'RICE BAGS'."""
    return (s or "").replace("-", " ").replace("_", " ").upper().strip()


@inventory_bp.get("/requests/intake")
def requests_intake_page():
    """
    Render the Cargo Intake page shell. If present, pass through source_email_id
    (or legacy ?message_id from Step 7) so the client can include it on POST.
    """
    source_email_id: Optional[str] = (request.args.get("source_email_id")
                                      or request.args.get("message_id") or "").strip() or None
    return render_template("cargo_intake.html", active="inventory", source_email_id=source_email_id)

@inventory_bp.post("/requests/intake")
def requests_intake():
    """
    Body JSON:
      {
        "airport": "KELN",
        "items": [{"name":"rice","weight_lb": 50}, {"name":"Rice","weight_lb": 25}],
        "source_email_id": "123"   # optional
      }
    Aggregates duplicate items in the payload, then upserts each.
    """
    data = request.get_json(silent=True) or {}
    airport = (data.get("airport") or "").strip()
    items = data.get("items") or []
    # optional priority from UI ("Incident Stabilization" / "Property Preservation" / "Lifesaving")
    priority_text = (data.get("priority") or "").strip()
    source_email_id = data.get("source_email_id")

    if not airport or not isinstance(items, list):
        return jsonify(ok=False, error="airport and items[] are required"), 400

    # Make sure the column exists so new/legacy rows can carry creation time.
    try:
        ensure_column("cargo_requests", "created_at", "TEXT")
    except Exception:
        pass

    # Aggregate by sanitized item key for idempotent intake of duplicates within this request
    # Keep the last seen raw name for nicer storage in item_raw.
    agg: dict[str, dict] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        raw_name = (it.get("name") or "").strip()
        if not raw_name:
            continue
        try:
            w = float(it.get("weight_lb"))
        except Exception:
            w = 0.0
        if w <= 0.0:  # ignore zero or negative weights
            continue
        key = cr_sanitize_item(raw_name)  # shared normalizer
        node = agg.setdefault(key, {"raw": raw_name, "weight": 0.0})
        node["raw"] = raw_name  # last wins
        node["weight"] += w

    # Create a Communications log entry (provenance for this intake)
    ap_canon = canonical_airport_code(airport) or airport.strip().upper()
    pri_code = prio_from_text(priority_text)
    pretty_lines = "\n".join(f"- {v['raw']}: {v['weight']:.1f} lb" for v in agg.values())
    body_txt = (
        f"Resource Request intake\n"
        f"Airport: {ap_canon}\n"
        f"Priority: {priority_text or 'Incident Stabilization'}\n"
        f"{('Source Winlink ID: ' + str(source_email_id)) if source_email_id else ''}\n\n"
        f"Items:\n{pretty_lines}"
    ).strip()
    comm_id = insert_comm(
        timestamp_utc=None,                 # normalized inside insert_comm()
        method="Resource Request (Intake)", # keep method family consistent with WebEOC path
        direction="in",
        from_party=None,
        to_party=None,
        subject=f"RR — {ap_canon}",
        body=body_txt,
        operator=None,
        notes=None,
        # Keep metadata small & canonical; 'source' is a blessed key in comms.py
        metadata={
            "kind": "resource_request",
            "source": "intake_ui" if not source_email_id else "winlink_ui",
            "priority_code": pri_code,
            "airport_canon": ap_canon,
            "winlink_id": str(source_email_id) if source_email_id else None,
        }
    )

    # Insert rows

    added = 0
    for node in agg.values():
        cargo_svc.upsert_request(airport, node["raw"], node["weight"], source_email_id)
        added += 1

    # ── v2 mirror so the aggregated panel shows progress immediately ───────
    try:
        for node in agg.values():
            name = (node.get("raw") or "").strip()
            qty_lb = float(node.get("weight") or 0.0)
            if not (name and qty_lb > 0):
                continue
            cr2_upsert_request_group(
                airport        = ap_canon,
                priority_code  = pri_code,
                need           = name,
                qty_lb         = qty_lb,
                source_comm_id = comm_id,  # link directly to the comms row we just created
                source_ref     = str(source_email_id) if source_email_id else "manual_intake",
                raw_json       = {"source": "manual_intake"}
            )
    except Exception:
        current_app.logger.warning("CRv2 mirror failed", exc_info=True)

    status = 201 if added > 0 else 200
    # Backfill created_at for any rows that don't have it yet.
    try:
        now_iso = datetime.utcnow().isoformat()
        with sqlite3.connect(DB_FILE) as c:
            c.execute(
                "UPDATE cargo_requests SET created_at = COALESCE(created_at, ?) WHERE created_at IS NULL",
                (now_iso,),
            )
    except Exception:
        pass
    return jsonify({"ok": True, "added": added, "comm_id": comm_id}), status


@inventory_bp.get("/requests/summary")
def requests_summary():
    """
    Returns a UI-ready summary, omitting fully satisfied lines.
    {
      "airports": [
        {"airport":"KELN","open_items":3,"items":[
           {"name":"SPAGHETTI","requested_lb":200,"fulfilled_lb":50,"outstanding_lb":150}
        ]}
      ],
      "open_airports": 1,
      "open_items_total": 3
    }
    """
    # Show DB truth only (fulfilled/outstanding come from cargo_requests).
    # Do NOT re-credit from remote snapshot advisories.
    rows = cargo_svc.get_summary()
    by_ap: dict[str, list[dict]] = {}
    for r in rows:
        ap = (r.get("airport") or "").strip().upper()
        key = (r.get("item_sanitized") or cr_sanitize_item(r.get("name") or r.get("item") or "")).strip()
        req = float(r.get("requested_lb") or 0.0)
        # Fulfillment/outstanding come from DB (reconciler writes these).
        fulfilled = float(r.get("fulfilled_lb") or 0.0)
        outstanding = float(r.get("outstanding_lb") or max(req - fulfilled, 0.0))
        if outstanding <= 0:
            # fully satisfied; omit from UI list
            continue
        items = by_ap.setdefault(ap, [])
        items.append({
            "name": _display_from_sanitized(key),
            "requested_lb": req,
            "fulfilled_lb": fulfilled,
            "outstanding_lb": outstanding,
        })

    airports = []
    for ap, items in sorted(by_ap.items(), key=lambda kv: kv[0]):
        items.sort(key=lambda x: x["name"])
        airports.append({
            "airport": ap,
            "open_items": len(items),
            "items": items,
        })

    return jsonify(
        airports=airports,
        open_airports=len(airports),
        open_items_total=sum(len(ap["items"]) for ap in airports),
    )


@inventory_bp.route("/requests/line", methods=["DELETE", "POST"])
# Alias used by the drawer UI ("Clear Item")
@inventory_bp.route("/requests/item", methods=["POST"])
def requests_delete_line():
    """
    Methods: DELETE or POST
    Paths:
      - /requests/line   (DELETE or POST)
      - /requests/item   (POST alias)
    Body JSON:
      {"airport":"KELN","item":"rice"}
      or {"airport":"KELN","sanitized_name":"rice"}  # aliases allowed
      or form/query params with the same keys.
    'item'/'name' are defensively sanitized.
    """
    data = request.get_json(silent=True) or request.values.to_dict(flat=True) or {}
    airport = (data.get("airport") or "").strip().upper()
    # accept multiple aliases from UI: sanitized_name, item, name
    raw_item = (
        data.get("sanitized_name")
        or data.get("item")
        or data.get("name")
        or ""
    ).strip()
    if not airport or not raw_item:
        return jsonify(ok=False, error="airport and item are required"), 400
    # Defensive sanitize to tolerate either raw or sanitized input
    item_key = cr_sanitize_item(raw_item)
    cargo_svc.delete_line(airport, item_key)
    return jsonify(ok=True)


@inventory_bp.route("/requests/airport", methods=["DELETE", "POST"])
def requests_delete_airport():
    """
    Methods: DELETE or POST
    Body JSON:
      {"airport":"KELN"}
    """
    data = request.get_json(silent=True) or request.values.to_dict(flat=True) or {}
    airport = (data.get("airport") or "").strip().upper()
    if not airport:
        return jsonify(ok=False, error="airport is required"), 400
    deleted = cargo_svc.delete_airport(airport)
    return jsonify(ok=True, deleted=int(deleted))
