"""Content-bound acknowledgements without application or service imports.

Callers hold BEGIN IMMEDIATE while signing, editing, or validating dispatch.
The digest deliberately includes session rows, so even an unsaved scanner edit
invalidates approval. Legacy timestamp-only acknowledgements fail closed.
"""
import hashlib
import json


MATERIAL_FIELDS = (
    "id", "direction", "pilot_name", "pax_count", "tail_number",
    "airfield_takeoff", "airfield_landing", "travel_time", "cargo_type",
    "cargo_weight", "remarks", "manifest_id",
)


def queue_manifest_id(connection, draft):
    mid = str(draft.get("manifest_id") or "").strip()
    if mid and mid.lower() not in ("none", "null", "undefined"):
        return mid
    row = connection.execute(
        "SELECT session_id FROM flight_cargo WHERE queued_id=? "
        "ORDER BY id DESC, timestamp DESC LIMIT 1", (draft["id"],)
    ).fetchone()
    return row[0] if row and row[0] else None


def manifest_fingerprint(connection, draft):
    """Hash the saved header, cargo, and live session on the same connection."""
    columns = ("category_id, sanitized_name, weight_per_unit, quantity, "
               "total_weight, direction, COALESCE(origin,''), session_id, timestamp")
    snapshot = connection.execute(
        f"SELECT {columns} FROM flight_cargo WHERE queued_id=? ORDER BY id",
        (draft["id"],),
    ).fetchall()
    mid = queue_manifest_id(connection, draft)
    ledger = connection.execute(
        f"SELECT {columns}, pending FROM inventory_entries "
        "WHERE session_id=? ORDER BY id", (mid,),
    ).fetchall() if mid else []
    content = {
        "version": 1,
        "header": {key: str(draft.get(key) or "") for key in MATERIAL_FIELDS},
        "snapshot": [list(row) for row in snapshot],
        "session": [list(row) for row in ledger],
    }
    return hashlib.sha256(json.dumps(
        content, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def has_unapplied_cargo(connection, draft):
    """Do not sign while the PDF's saved cargo differs from the live session."""
    mid = queue_manifest_id(connection, draft)
    if not mid:
        return False
    cutline = connection.execute(
        "SELECT MAX(timestamp) FROM flight_cargo WHERE queued_id=?",
        (draft["id"],),
    ).fetchone()[0]
    if connection.execute(
        "SELECT 1 FROM inventory_entries WHERE session_id=? AND pending=1 LIMIT 1",
        (mid,),
    ).fetchone():
        return True
    # A saved empty manifest can retain balanced historical ledger entries.
    # Only a nonzero committed delta would change the cargo at dispatch.
    return connection.execute(
        "SELECT 1 FROM inventory_entries WHERE session_id=? AND pending=0 "
        "AND (? IS NULL OR timestamp>?) "
        "GROUP BY category_id, sanitized_name, weight_per_unit, COALESCE(origin,'') "
        "HAVING SUM(CASE direction WHEN 'out' THEN quantity ELSE -quantity END)<>0 "
        "OR SUM(CASE direction WHEN 'out' THEN total_weight ELSE -total_weight END)<>0 "
        "LIMIT 1", (mid, cutline, cutline),
    ).fetchone() is not None


def acknowledgement_is_current(connection, draft):
    return bool(
        draft.get("pilot_ack_signed_at")
        and draft.get("pilot_ack_manifest_hash")
        and draft["pilot_ack_manifest_hash"] == manifest_fingerprint(connection, draft)
        and not has_unapplied_cargo(connection, draft)
    )


def invalidate_stale_acknowledgement(connection, queue_id):
    row = connection.execute(
        "SELECT * FROM queued_flights WHERE id=?", (queue_id,)
    ).fetchone()
    if row is None:
        return
    draft = dict(row)
    if draft.get("pilot_ack_signed_at") and not acknowledgement_is_current(connection, draft):
        connection.execute(
            "UPDATE queued_flights SET pilot_ack_name=NULL, pilot_ack_method=NULL, "
            "pilot_ack_signature_b64=NULL, pilot_ack_signed_at=NULL, "
            "pilot_ack_manifest_hash=NULL, manifest_pdf_path=NULL WHERE id=?",
            (queue_id,),
        )
