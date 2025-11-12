# ... existing code ...

def _plane_pin_clear_by_flight_ref(flight_ref: str) -> bool:
    """
    Find and clear any plane that has the given flight_ref.
    Returns True if a plane was found and cleared, False otherwise.
    """
    with LOCK:
        pins = STATE.setdefault("plane_pins", {})
        for plane_id, pin in pins.items():
            if pin.get("flight_ref") == flight_ref:
                _plane_pin_clear(plane_id)
                return True
        return False

# ... existing code ...

@bp.post("/api/wargame/plane/paperwork_complete")
def api_plane_paperwork_complete():
    data = request.get_json(force=True) or {}
    plane_id   = _canon_plane_id_or_none(data.get("plane_id"))
    if not plane_id:
        return jsonify({"error": "bad_plane_id"}), 400
    try:
        session_id = int(data.get("session_id") or 1)
    except Exception:
        session_id = 1
    player_id = int(data.get("player_id") or 0)
    with LOCK:
        _ensure_session(session_id)
        pin = _plane_pin_get(plane_id)
        if pin.get("status") != "loaded":
            return jsonify({"error": "not_ready"}), 400
        # Telemetry: paperwork_complete (capture before clearing)
        try:
            _append_claim(session_id, _make_claim(
                "paperwork_complete",
                plane_id=plane_id,
                player_id=player_id,
                flight_ref=pin.get("flight_ref")
            ))
        except Exception: pass
        # return plane to idle and clear selection
        _plane_pin_clear(plane_id)
        print(f"[WG_API] Plane {plane_id} paperwork completed and cleared")
        return jsonify({"ok": True, "pin": _plane_pin_get(plane_id)})

# ... existing code ...
