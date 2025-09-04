
import re

try:
    from flask import Request as _FlaskRequest, request as _flask_request  # type: ignore
except Exception:  # pragma: no cover
    _FlaskRequest = None
    _flask_request = None

def _parse_read_ranges_cookie(cookie_value: str):
    """
    Parse range-encoded cookie like: '1-10,12,15-18' → list of (start,end) ints.
    Strict: ignore any malformed segments.
    """
    if not cookie_value:
        return []
    ranges = []
    for part in (p.strip() for p in cookie_value.split(',') if p.strip()):
        if part.isdigit():
            v = int(part)
            ranges.append((v, v))
            continue
        m = re.match(r'^(\d+)-(\d+)$', part)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            s, e = (a, b) if a <= b else (b, a)
            ranges.append((s, e))
    # merge overlapping/adjacent
    if not ranges:
        return []
    ranges.sort()
    merged = [list(ranges[0])]
    for s, e in ranges[1:]:
        last = merged[-1]
        if s <= last[1] + 1:
            last[1] = max(last[1], e)
        else:
            merged.append([s, e])
    return [(s, e) for s, e in merged]

def cookie_truthy(name: str, default: bool = False, req: "_FlaskRequest|None" = None) -> bool:
    """
    Return True if cookie value ∈ {1, yes, true, on} (case-insensitive).
    Accepts an explicit Flask request for testability; falls back to global.
    """
    r = req or _flask_request
    if r is None:
        return default
    v = (r.cookies.get(name) or "").strip().lower()
    if v in ("1","yes","true","on"):
        return True
    if v in ("0","no","false","off"):
        return False
    return default
