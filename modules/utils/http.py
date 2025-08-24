

def _filter_headers(headers):
    # strip hop-by-hop headers
    block = {
        'connection', 'keep-alive', 'proxy-authenticate',
        'proxy-authorization', 'te', 'trailers',
        'transfer-encoding', 'upgrade'
    }
    return [(k, v) for k, v in headers.items() if k.lower() not in block]

# ───────────────────────────── Minimal JSON POST helper (stdlib only) ─────────────────────────────
import json as _json
from urllib import request as _ur
from urllib.error import HTTPError, URLError

def http_post_json(url, payload, headers=None, timeout=10):
    """
    POST JSON and return (status_code, parsed_body_or_text).
    - headers: optional dict; Authorization etc. will be merged.
    - timeout: seconds.
    """
    body = _json.dumps(payload or {}).encode('utf-8')
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if headers:
        for k,v in headers.items():
            if v is not None:
                hdrs[k] = v
    req = _ur.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with _ur.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            data = resp.read()
            try:
                return status, _json.loads(data.decode('utf-8'))
            except Exception:
                return status, data.decode('utf-8', errors='replace')
    except HTTPError as e:
        try:
            data = e.read()
            try:
                return e.code, _json.loads(data.decode('utf-8'))
            except Exception:
                return e.code, data.decode('utf-8', errors='replace')
        except Exception:
            return e.code, str(e)
    except URLError as e:
        return None, f"URLError: {e.reason}"
