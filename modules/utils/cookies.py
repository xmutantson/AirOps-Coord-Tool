
import re

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