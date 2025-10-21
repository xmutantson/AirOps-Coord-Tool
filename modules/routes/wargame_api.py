# modules/routes/wargame_api.py
from __future__ import annotations
from flask import Blueprint, jsonify, request, g
from datetime import datetime, timezone
import threading
import time
import os, re

bp = Blueprint("wargame_api", __name__)  # concrete paths below (no url_prefix)
LOCK = threading.RLock()

# --- Tunables ---------------------------------------------------------------
CLAIMS_MAX = int(os.getenv("WGAPI_CLAIMS_MAX", "4000"))
STALE_SEC  = 15.0
VALID_SIZES = ("S", "M", "L", "XL")

# --- In-memory state ----------------------------------------------------------
STATE = {
    # session_id -> {"players": {id: {...}}, "next_player_id": int, "next_claim_id": int}
    "sessions": {},
    "adapters": {
        # Matches client-side default: +4 S, +5 M, +8 L, +10 XL for one generic SKU "box"
        "stockpile": {
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "bins": {
                "box": {"S": 4, "M": 5, "L": 8, "XL": 10},
            },
        },
        # Two trucks like the old client layout; moved DOWN by 100 px as requested
        "trucks": {
            "inbound": [
                {
                    "truck_id": 0,
                    "bay": "E1",
                    "pose": {"x": 1356, "y": 450, "facing": "right"},  # was 350 → 450
                    "manifest": {"box": {"L": 1}},  # truck:0 had 1 large
                    "claims": {},
                },
                {
                    "truck_id": 1,
                    "bay": "E2",
                    "pose": {"x": 1356, "y": 650, "facing": "right"},  # was 550 → 650
                    "manifest": {},
                    "claims": {},
                },
            ],
            "outbound": [],
        },
        "queues": {"loads_waiting": 0, "requests": []},
        # Visual-only aircraft positions for completeness (same as original client)
        "planes": [
            {"id": "plane:0", "pose": {"x": 244, "y": 290, "facing": "right"}},  # 24+220, 450-160
            {"id": "plane:1", "pose": {"x": 244, "y": 610, "facing": "right"}},  # 24+220, 450+160
        ],
    },
    # session_id -> list of carts (with poses); matches client default
    "carts": {},
    # session_id -> ordered list of claim dicts
    "claims": {},
}

# --- Helpers -----------------------------------------------------------------
def _utc_iso():
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

def _touch_stockpile():
    STATE["adapters"]["stockpile"]["updated_at"] = _utc_iso()

def _ensure_session(session_id: int):
    with LOCK:
        sess = STATE["sessions"].setdefault(
            session_id,
            {"players": {}, "next_player_id": 1, "next_claim_id": 1},
        )
        # Seed carts per session to mirror the client default layout:
        # cart:0 has 2× M at y=410; cart:1 empty at y=636 (≈ xl.h*5+16 below).
        carts = STATE["carts"].setdefault(session_id, [])
        if not carts:
            carts.extend([
                {
                    "id": "cart:0",
                    "capacity_lb": 600,
                    "contents": {"box": {"M": 2}},
                    "preview": [],
                    "pose": {"x": 544, "y": 410, "facing": "left"},  # 24+520, 450-40
                },
                {
                    "id": "cart:1",
                    "capacity_lb": 600,
                    "contents": {},
                    "preview": [],
                    "pose": {"x": 544, "y": 636, "facing": "left"},  # ~ (450-40)+(42*5+16)
                },
            ])
        STATE["claims"].setdefault(session_id, [])
        return sess

def _prune_stale_players(session_id: int):
    now = time.time()
    with LOCK:
        sess = _ensure_session(session_id)
        dead = [pid for pid, p in sess["players"].items() if now - float(p.get("last_seen", 0)) > STALE_SEC]
        for pid in dead:
            sess["players"].pop(pid, None)

# size normalization: accept letters & human words
_SIZE_MAP = {
    "s":"S","small":"S",
    "m":"M","medium":"M",
    "l":"L","large":"L","lg":"L",
    "xl":"XL","x-l":"XL","xlarge":"XL","x-large":"XL","extra large":"XL","extra-large":"XL",
}
def _norm_size(s: str) -> str | None:
    if not s: return None
    s = str(s).strip().lower()
    return _SIZE_MAP.get(s, s.upper() if s.upper() in VALID_SIZES else None)

def _manifest_get(manifest: dict, item_key: str, size: str) -> int:
    return int(((manifest.get(item_key) or {}).get(size) or 0))

def _manifest_add(manifest: dict, item_key: str, size: str, delta: int) -> bool:
    size = _norm_size(size) or ""
    if size not in VALID_SIZES:
        return False
    bins = manifest.setdefault(item_key, {s: 0 for s in VALID_SIZES})
    cur = int(bins.get(size) or 0)
    if delta < 0 and cur < -delta:
        return False
    bins[size] = cur + delta
    return True

def _stockpile_add(item_key: str, size: str, delta: int) -> bool:
    sp = STATE["adapters"]["stockpile"]["bins"]
    ok = _manifest_add(sp, item_key, size, delta)
    if ok:
        _touch_stockpile()
    return ok

def _find_truck(carrier_index=None, carrier_uid=None):
    """Return (truck_dict, side) or (None, None). Accepts uid=int truck_id."""
    trucks = STATE["adapters"]["trucks"]
    # uid (truck_id) path first
    try:
        if carrier_uid is not None:
            uid_int = int(carrier_uid)
            for side in ("inbound", "outbound"):
                for t in trucks.get(side, []):
                    if int(t.get("truck_id", -1)) == uid_int:
                        return t, side
    except Exception:
        pass
    # index path
    try:
        if carrier_index is not None:
            idx = int(carrier_index)
            side = "inbound"
            arr = trucks.get(side, [])
            if 0 <= idx < len(arr):
                return arr[idx], side
    except Exception:
        pass
    return None, None

def _find_or_create_cart(session_id: int, cart_id):
    # normalize cart ids (accept 0 / "0" / "cart:0")
    if isinstance(cart_id, int) or (isinstance(cart_id, str) and cart_id.isdigit()):
        cart_id = f"cart:{int(cart_id)}"
    carts = STATE["carts"].setdefault(session_id, [])
    for c in carts:
        if c.get("id") == cart_id:
            c.setdefault("contents", {})
            c.setdefault("preview", [])
            return c
    c = {"id": cart_id, "capacity_lb": 600, "contents": {}, "preview": []}
    carts.append(c)
    return c

def _append_claim(session_id: int, entry: dict) -> dict:
    sess = _ensure_session(session_id)
    e = dict(entry)
    e["id"] = sess["next_claim_id"]
    e.setdefault("created_at", _utc_iso())
    sess["next_claim_id"] += 1
    claims = STATE["claims"].setdefault(session_id, [])
    claims.append(e)
    overflow = len(claims) - max(0, CLAIMS_MAX)
    if overflow > 0:
        STATE["claims"][session_id] = claims[overflow:]
    return e

# carrier parsing: accepts "truck:0", "truck#101", "cart:alpha"
_CUID_RE = re.compile(r"^(truck|cart)[:#](.+)$", re.I)
def _parse_carrier(carrier_type, carrier_index, carrier_uid):
    """
    Return normalized (ctype, cidx, cuid).  TRUCK cuid is an int; CART cuid is "cart:<id>".
    """
    ctype = (carrier_type or "").strip().lower() or None
    cidx  = carrier_index
    cuid  = carrier_uid
    if isinstance(cidx, str):
        try: cidx = int(cidx)
        except Exception: cidx = None
    if isinstance(cuid, str):
        m = _CUID_RE.match(cuid.strip())
        if m:
            ctype = m.group(1).lower()
            rest  = m.group(2).strip()
            if rest.isdigit():
                n = int(rest)
                if ctype == "truck":
                    cuid = n
                    cidx = n if cidx is None else cidx
                else:
                    # carts must keep the "cart:" prefix for canonical ID
                    cuid = f"cart:{n}"
            else:
                # ensure "cart:" prefix for non-numeric cart IDs
                cuid = rest if rest.startswith("cart:") else f"cart:{rest}"
        else:
            if cuid.isdigit() and ctype in (None, "truck"):
                ctype = ctype or "truck"
                cidx = int(cuid)
                cuid = None
    return ctype, cidx, cuid

# Mark WG API requests for app-level fast-lane skips (auth/prefs)
@bp.before_request
def _wgapi_fastlane_flag():
    try:
        g.WGAPI_FASTLANE = True
    except Exception:
        pass

# --- Read-only adapters ------------------------------------------------------
@bp.get("/api/wargame/stockpile")
def api_stockpile():
    with LOCK:
        return jsonify(STATE["adapters"]["stockpile"])

@bp.get("/api/wargame/trucks")
def api_trucks():
    with LOCK:
        return jsonify(STATE["adapters"]["trucks"])

@bp.get("/api/wargame/queues")
def api_queues():
    with LOCK:
        return jsonify(STATE["adapters"]["queues"])

# New: planes endpoint so the client can hydrate visuals purely from server
@bp.get("/api/wargame/planes")
def api_planes():
    with LOCK:
        return jsonify({"planes": STATE["adapters"].get("planes", [])})

# --- Multiplayer presence/state ----------------------------------------------
@bp.get("/wargame/state")
def wargame_state():
    session_id = int(request.args.get("session_id", "1"))
    try:
        since_id = int(request.args.get("since_id", "0") or 0)
    except Exception:
        since_id = 0

    _prune_stale_players(session_id)
    with LOCK:
        sess = _ensure_session(session_id)
        players     = list(sess["players"].values())
        carts       = STATE["carts"][session_id]
        all_claims  = STATE["claims"][session_id]
        claims      = [c for c in all_claims if int(c.get("id", 0)) > since_id] if since_id > 0 else all_claims
        badges      = {"queue": STATE["adapters"]["queues"].get("loads_waiting", 0)}
        return jsonify({
            "server_time": time.time(),
            "players": players,
            "carts": carts,
            "claims": claims,
            "badges": badges,
            "next_claim_id": sess["next_claim_id"],
        })

@bp.get("/wargame/players")
def wargame_players():
    session_id = int(request.args.get("session_id", "1"))
    _prune_stale_players(session_id)
    with LOCK:
        sess = _ensure_session(session_id)
        return jsonify({"players": list(sess["players"].values())})

@bp.post("/wargame/join")
def wargame_join():
    data = request.get_json(force=True) or {}
    session_id = int(data.get("session_id", 1))
    name = (data.get("name") or "Guest").strip()[:24]
    now = time.time()
    with LOCK:
        sess = _ensure_session(session_id)
        pid  = sess["next_player_id"]; sess["next_player_id"] = pid + 1
        color_index = (pid - 1) % 8
        player = {
            "id": pid, "name": name or f"Player {pid}",
            "x": 800, "y": 450, "dir": "S",
            "last_seen": now, "pos_seq": 0,
            "color_index": color_index, "joined_at": _utc_iso(),
            "held": None,
        }
        sess["players"][pid] = player
        return jsonify({"player_id": pid, "name": player["name"], "color_index": color_index})

@bp.post("/wargame/rename")
def wargame_rename():
    data = request.get_json(force=True) or {}
    session_id = int(data.get("session_id", 1))
    player_id  = int(data.get("player_id"))
    new_name   = (data.get("name") or "").strip()[:24]
    with LOCK:
        sess = _ensure_session(session_id)
        if player_id in sess["players"]:
            sess["players"][player_id]["name"] = new_name or sess["players"][player_id]["name"]
            return jsonify({"ok": True, "player": sess["players"][player_id]})
        return jsonify({"ok": False, "error": "not_found"}), 404

@bp.post("/wargame/pos")
def wargame_pos():
    data = request.get_json(force=True) or {}
    session_id = int(data.get("session_id", 1))
    player_id  = int(data.get("player_id"))
    x = float(data.get("x", 0)); y = float(data.get("y", 0))
    dir_ = (data.get("dir") or "S")[:2]
    now = time.time()
    with LOCK:
        sess = _ensure_session(session_id)
        p = sess["players"].get(player_id)
        if not p:
            sess["players"][player_id] = p = {
                "id": player_id, "name": f"Player {player_id}",
                "x": x, "y": y, "dir": dir_,
                "last_seen": now, "pos_seq": 1,
                "color_index": (player_id - 1) % 8, "joined_at": _utc_iso(),
                "held": None,
            }
        else:
            p["x"], p["y"], p["dir"] = x, y, dir_
            p["last_seen"] = now
            p["pos_seq"] = int(p.get("pos_seq", 0)) + 1
        return jsonify({"ok": True, "pos_seq": p["pos_seq"]})

# --- Claims & atomic mutations -----------------------------------------------
@bp.post("/wargame/claim")
def wargame_claim():
    """
    Authoritative world changes with server-side size & carrier normalization.
    Accepts actions: 'stockpile_add' | 'stockpile_remove' | 'carrier_add' | 'carrier_remove'
    """
    data = request.get_json(force=True) or {}
    session_id = int(data.get("session_id", 1))
    with LOCK:
        sess = _ensure_session(session_id)

        # Preferred modern payload
        if "action" in data:
            action        = (data.get("action") or "").lower().strip()
            player_id     = int(data.get("player_id") or 0)
            item_key      = (data.get("item_key") or data.get("item") or "").strip()
            size_in       = data.get("size")
            size          = _norm_size(size_in or "")
            ctype, cidx, cuid = _parse_carrier(data.get("carrier_type"), data.get("carrier_index"), data.get("carrier_uid"))

            if not item_key:
                return jsonify({"ok": False, "error": "bad_item"}), 400
            if size not in VALID_SIZES:
                return jsonify({"ok": False, "error": "bad_size", "got": size_in}), 400
            if action not in ("stockpile_add","stockpile_remove","carrier_add","carrier_remove"):
                return jsonify({"ok": False, "error": "bad_action"}), 400

            player = sess["players"].get(player_id)
            if not player:
                return jsonify({"ok": False, "error": "no_player"}), 404
            held = player.get("held")

            def make_entry(extra: dict):
                base = {"action": action, "player_id": player_id, "item_key": item_key, "size": size, "qty": 1}
                base.update(extra or {})
                return base

            # STOCKPILE TAKE
            if action == "stockpile_remove":
                if held:
                    return jsonify({"ok": False, "error": "already_holding"}), 409
                if not _stockpile_add(item_key, size, -1):
                    return jsonify({"ok": False, "error": "insufficient_stockpile"}), 409
                player["held"] = {"item_key": item_key, "size": size, "qty": 1}
                entry = _append_claim(session_id, make_entry({}))
                return jsonify({"ok": True, "claim": entry, "player": player, "stockpile": STATE["adapters"]["stockpile"]})

            # STOCKPILE PUT
            if action == "stockpile_add":
                if not held or held.get("item_key") != item_key or held.get("size") != size:
                    return jsonify({"ok": False, "error": "not_holding"}), 409
                if not _stockpile_add(item_key, size, +1):
                    return jsonify({"ok": False, "error": "stockpile_update_failed"}), 500
                player["held"] = None
                entry = _append_claim(session_id, make_entry({}))
                return jsonify({"ok": True, "claim": entry, "player": player, "stockpile": STATE["adapters"]["stockpile"]})

            # CARRIER sanity
            if action.startswith("carrier_") and not ctype:
                return jsonify({"ok": False, "error": "missing_carrier_type"}), 400

            # CARRIER TAKE
            if action == "carrier_remove":
                if held:
                    return jsonify({"ok": False, "error": "already_holding"}), 409

                if ctype == "truck":
                    truck, side = _find_truck(cidx, cuid)
                    if not truck:
                        return jsonify({"ok": False, "error": "no_truck"}), 404
                    if not _manifest_add(truck.setdefault("manifest", {}), item_key, size, -1):
                        return jsonify({"ok": False, "error": "insufficient_truck"}), 409
                    player["held"] = {"item_key": item_key, "size": size, "qty": 1}
                    entry = _append_claim(session_id, make_entry({"carrier_type": "truck", "carrier_uid": truck.get("truck_id")}))
                    return jsonify({"ok": True, "claim": entry, "player": player, "trucks": STATE["adapters"]["trucks"]})

                if ctype == "cart":
                    cart_id = cuid if cuid is not None else cidx
                    if cart_id is None:
                        return jsonify({"ok": False, "error": "no_cart_id"}), 400
                    cart = _find_or_create_cart(session_id, cart_id)
                    if not _manifest_add(cart.setdefault("contents", {}), item_key, size, -1):
                        return jsonify({"ok": False, "error": "insufficient_cart"}), 409
                    player["held"] = {"item_key": item_key, "size": size, "qty": 1}
                    # publish canonical id so all clients match
                    entry = _append_claim(session_id, make_entry({"carrier_type": "cart", "carrier_uid": cart.get("id")}))
                    return jsonify({"ok": True, "claim": entry, "player": player, "carts": STATE["carts"][session_id]})

                return jsonify({"ok": False, "error": "bad_carrier_type"}), 400

            # CARRIER PUT
            if action == "carrier_add":
                if not held or held.get("item_key") != item_key or held.get("size") != size:
                    return jsonify({"ok": False, "error": "not_holding"}), 409

                if ctype == "truck":
                    truck, side = _find_truck(cidx, cuid)
                    if not truck:
                        return jsonify({"ok": False, "error": "no_truck"}), 404
                    if not _manifest_add(truck.setdefault("manifest", {}), item_key, size, +1):
                        return jsonify({"ok": False, "error": "truck_update_failed"}), 500
                    player["held"] = None
                    entry = _append_claim(session_id, make_entry({"carrier_type": "truck", "carrier_uid": truck.get("truck_id")}))
                    return jsonify({"ok": True, "claim": entry, "player": player, "trucks": STATE["adapters"]["trucks"]})

                if ctype == "cart":
                    cart_id = cuid if cuid is not None else cidx
                    if cart_id is None:
                        return jsonify({"ok": False, "error": "no_cart_id"}), 400
                    cart = _find_or_create_cart(session_id, cart_id)
                    if not _manifest_add(cart.setdefault("contents", {}), item_key, size, +1):
                        return jsonify({"ok": False, "error": "cart_update_failed"}), 500
                    player["held"] = None
                    entry = _append_claim(session_id, make_entry({"carrier_type": "cart", "carrier_uid": cart.get("id")}))
                    return jsonify({"ok": True, "claim": entry, "player": player, "carts": STATE["carts"][session_id]})

                return jsonify({"ok": False, "error": "bad_carrier_type"}), 400

            return jsonify({"ok": False, "error": "unhandled"}), 400

        # --- Legacy fallback (create/release) --------------------------------
        claims = STATE["claims"][session_id]
        op = (data.get("op") or "create").lower()
        if op == "release":
            pid = int(data.get("player_id", 0))
            item_key = data.get("item_key")
            size     = _norm_size(data.get("size") or "")
            STATE["claims"][session_id] = [
                c for c in claims
                if not (c.get("player_id") == pid and c.get("item_key") == item_key and _norm_size(c.get("size")) == size)
            ]
            return jsonify({"ok": True, "claims": STATE["claims"][session_id]})
        else:
            entry = dict(data)
            entry["size"] = _norm_size(entry.get("size") or "")
            entry["created_at"] = _utc_iso()
            e = _append_claim(session_id, entry)
            return jsonify({"ok": True, "claim": e})

# --- Cart preview (legacy helpers) -------------------------------------------
@bp.post("/wargame/cart/drop")
def wargame_cart_drop():
    data = request.get_json(force=True) or {}
    session_id = int(data.get("session_id", 1))
    cart_id = data.get("cart_id")
    with LOCK:
        cart = _find_or_create_cart(session_id, cart_id)
        cart.setdefault("preview", []).append({
            "item_key": data.get("item_key"),
            "size": _norm_size(data.get("size") or ""),
            "qty": int(data.get("qty", 1)),
            "unit_lb": int(data.get("unit_lb", 0)),
        })
        return jsonify({"ok": True, "cart": cart})

@bp.post("/wargame/cart/clear")
def wargame_cart_clear():
    data = request.get_json(force=True) or {}
    session_id = int(data.get("session_id", 1))
    cart_id = data.get("cart_id")
    with LOCK:
        cart = _find_or_create_cart(session_id, cart_id)
        cart["preview"] = []
        return jsonify({"ok": True, "cart": cart})
