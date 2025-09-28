from __future__ import annotations

from flask import Blueprint, render_template, jsonify, request, abort, make_response
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from jinja2 import TemplateNotFound
from threading import Thread
from typing import List, Dict
import os  # for stem handling (canonicalization)
import time
import hashlib
import json

from modules.utils.common import (
    dict_rows,
    upsert_weather_product,
    get_wx_keys,
    get_wx_display_name,
    infer_mime_for_upload,
)
from modules.services.winlink.core import (
    send_winlink_message,
    pat_config_exists,
)

# Two blueprints so URLs are clean:
#   • /weather/ (page)
#   • /api/weather/... (catalog, blob/text, upload)
bp_page = Blueprint("weather_page", __name__, url_prefix="/weather")
bp_api  = Blueprint("weather_api",  __name__, url_prefix="/api/weather")

# ----------------------------- Helpers --------------------------------
def _stem(s: str) -> str:
    """
    Uppercased basename without extension. Examples:
      'WCVS.JPG' -> 'WCVS', 'wa_for_wa' -> 'WA_FOR_WA'
    """
    return os.path.splitext((s or "").strip())[0].upper()

# ----------------------------- Page ---------------------------------
@bp_page.get("/")
def index():
    # Render template if present; otherwise return a tiny fallback shell.
    try:
        return render_template("weather.html")
    except TemplateNotFound:
        html = """
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Weather</title></head>
  <body>
    <h1>Weather</h1>
    <p>This is a placeholder page. Add <code>templates/weather.html</code> for a full UI.</p>
  </body>
</html>"""
        resp = make_response(html, 200)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp


# ----------------------------- API ----------------------------------
@bp_api.get("/catalog")
def catalog():
    # Normalize configured keys to canonical stems (e.g., WCVS.JPG -> WCVS)
    keys_cfg = list(get_wx_keys() or [])
    wanted = list(dict.fromkeys([_stem(k) for k in keys_cfg]))  # order-preserving de-dupe

    if wanted:
        qmarks = ",".join("?" * len(wanted))
        sql = f"""
          SELECT key, display_name, mime, content_hash AS etag, source,
                 received_at_utc, updated_at_utc
            FROM weather_products
           WHERE key IN ({qmarks})
        """
        rows = dict_rows(sql, tuple(wanted))
    else:
        rows = dict_rows("""
          SELECT key, display_name, mime, content_hash AS etag, source,
                 received_at_utc, updated_at_utc
            FROM weather_products
        """)

    by_key = { _stem(r.get("key")): r for r in rows }
    out = []
    for k in (wanted or []):
        r = by_key.get(_stem(k))
        if r:
            out.append({
                "key": r["key"],
                "display_name": r["display_name"],
                "mime": r["mime"],
                "received_at_utc": r["received_at_utc"],
                "updated_at_utc": r["updated_at_utc"],
                "etag": f"sha256:{r['etag']}" if r.get("etag") else "",
                "source": r.get("source", ""),
            })
        else:
            out.append({
                "key": k,
                "display_name": get_wx_display_name(k),
                "mime": "",
                "received_at_utc": "",
                "updated_at_utc": "",
                "etag": "",
                "source": "",
            })
    return jsonify(out)


@bp_api.get("/blob/<path:key>")
def blob(key):
    # Accept either canonical key or filename with extension
    k = _stem(key)
    rows = dict_rows("SELECT mime, content, content_hash FROM weather_products WHERE key=?", (k,))
    if not rows:
        abort(404)
    r = rows[0]
    resp = make_response(r["content"])
    resp.headers["Content-Type"] = r["mime"] or "application/octet-stream"
    resp.headers["ETag"] = f"sha256:{r['content_hash']}"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp_api.get("/text/<path:key>")
def text(key):
    # Accept either canonical key or filename with extension
    k = _stem(key)
    rows = dict_rows("SELECT content, mime FROM weather_products WHERE key=?", (k,))
    if not rows:
        abort(404)
    r = rows[0]
    if not (r["mime"] or "").startswith("text/"):
        abort(415)
    try:
        body = (r["content"] or b"").decode("utf-8", errors="replace")
    except Exception:
        body = ""
    resp = make_response(body)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp_api.post("/upload")
def upload():
    """
    Authenticated upload into a specific slot via form field `key`.
    Filename does not need to match the slot; we infer MIME safely.
    """
    f = request.files.get("file")
    # Allow users to submit either 'WCVS' or 'WCVS.JPG' for the slot key
    key = _stem(request.form.get("key") or "")
    if not f or not key:
        abort(400)

    data = f.read(12 * 1024 * 1024)  # 12 MiB guardrail
    fname = secure_filename(f.filename or "")
    mime = infer_mime_for_upload(fname, data)

    # Slot-specific constraints
    if key == "WA_FOR_WA":
        mime = "text/plain"
    else:
        # Allow images or (optionally) plain text for other keys.
        if not (mime.startswith("image/") or mime == "text/plain"):
            abort(415)

    info = upsert_weather_product(key, data, mime, source="manual")
    return jsonify({"ok": True, **info})

def _canon_wx_key(raw: str) -> tuple[str, str]:
    """
    Map any incoming token to (product_id, wire_key).
    - product_id: canonical stem used for de-duplication (e.g., 'WCVS')
    - wire_key  : what we actually send in the INQUIRY body (e.g., 'WCVS.JPG')
    """
    s = (raw or "").strip().upper()
    stem = os.path.splitext(s)[0]  # 'WCVS.JPG' → 'WCVS'
    # Known canonical filenames expected by the service:
    mapping = {
        "WCVS":       "WCVS.JPG",      # GOES West visible sector
        "WCIR":       "WCIR.JPG",      # GOES West IR sector
        "USWXRAD":    "USWXRAD.GIF",   # US composite radar
        "WA_FOR_WA":  "WA_FOR_WA",     # Spokane AFD/forecast text
    }
    wire = mapping.get(stem, s)
    return stem, wire

def _catalog_keys_from_request() -> List[str]:
    """
    Read keys from JSON ('keys') or fall back to configured catalog.
    Normalize → de-duplicate by product_id → return canonical wire-keys in order.
    """
    try:
        js = request.get_json(silent=True) or {}
    except Exception:
        js = {}
    raw = js.get("keys") or []
    if not isinstance(raw, list):
        raw = []
    keys = [ (str(k or "").strip().upper()) for k in raw if (k or "").strip() ]
    if not keys:
        keys = list(get_wx_keys() or [])

    out, seen = [], set()
    for k in keys:
        pid, wire = _canon_wx_key(k)
        if not pid:
            continue
        if pid in seen:
            continue
        seen.add(pid)
        out.append(wire)
    return out

def _build_messages(keys: List[str], split: bool, to_addr: str) -> List[Dict[str,str]]:
    """
    Return a list of {to, subject, body} payloads. If split=True, one per key.
    Body spec: one key per line (even when split) for consistency.
    """
    subj = "REQUEST"
    if not split:
        body = "\n".join(keys)
        return [{"to": to_addr, "subject": subj, "body": body}]
    msgs = []
    for k in keys:
        msgs.append({"to": to_addr, "subject": subj, "body": k})
    return msgs

@bp_api.post("/request")
def request_updates():
    """
    Request weather products.
      JSON:
        { "mode": "pat" | "preview",
          "split": true|false,           # default true (one message per product)
          "to": "INQUIRY",               # optional recipient
          "keys": ["WCCOL.JPG", ...] }   # optional; defaults to configured catalog
    - mode=preview → returns list of {to,subject,body} without sending.
    - mode=pat     → sends via PAT; returns per-message status.
    """
    js = request.get_json(silent=True) or {}
    mode  = (js.get("mode") or "pat").strip().lower()
    split = bool(js.get("split", True))
    to    = (js.get("to") or "INQUIRY").strip().upper()
    async_send = bool(js.get("async", True))  # default: async to avoid DB stalls
    keys  = _catalog_keys_from_request()

    # Nothing to request
    if not keys:
        return jsonify({"ok": False, "error": "no keys specified"}), 400

    # Log exactly what we'll send (helps confirm canonicalization/dedupe)
    try:
        from flask import current_app
        current_app.logger.info("WX request: to=%s split=%s keys=%s", to, split, keys)
    except Exception:
        pass

    msgs = _build_messages(keys, split, to)
    if mode == "preview":
        return jsonify({"ok": True, "messages": msgs, "count": len(msgs)})

    # mode=pat → send via Winlink
    if not pat_config_exists():
        return jsonify({"ok": False, "error": "PAT not configured"}), 503

    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Light idempotency guard (prevents double-click duplicates within ~3s)
    # We keep the response shape stable ('mode': 'pat_async') so the UI text stays sane.
    sig_payload = {"to": to, "split": split, "keys": keys}
    req_sig = hashlib.sha256(json.dumps(sig_payload, sort_keys=True).encode()).hexdigest()
    _guard = getattr(request_updates, "_last_req", {"sig": None, "ts": 0.0})
    now_s = time.time()
    if _guard.get("sig") == req_sig and (now_s - float(_guard.get("ts", 0.0))) < 3.0:
        setattr(request_updates, "_last_req", {"sig": req_sig, "ts": now_s})
        return jsonify({"ok": True, "requested_at": ts, "enqueued": 0, "mode": "pat_async", "dupe": True})
    setattr(request_updates, "_last_req", {"sig": req_sig, "ts": now_s})

    if async_send:
        # Fire-and-forget to avoid holding the HTTP request or any DB handle.
        def _worker(batch):
            for m in batch:
                try:
                    send_winlink_message(m["to"], m["subject"], m["body"])
                except Exception:
                    pass
        Thread(target=_worker, args=(msgs,), daemon=True).start()
        return jsonify({"ok": True, "requested_at": ts, "enqueued": len(msgs), "mode": "pat_async"})
    else:
        # Synchronous path (legacy behavior; can cause long waits if PAT is slow)
        results = []
        any_ok = False
        for m in msgs:
            try:
                ok = bool(send_winlink_message(m["to"], m["subject"], m["body"]))
                any_ok = any_ok or ok
                results.append({"to": m["to"], "subject": m["subject"], "ok": ok})
            except Exception as e:
                results.append({"to": m["to"], "subject": m["subject"], "ok": False, "error": str(e)})
        return jsonify({"ok": any_ok, "requested_at": ts, "results": results, "count": len(results), "mode": "pat_sync"})

