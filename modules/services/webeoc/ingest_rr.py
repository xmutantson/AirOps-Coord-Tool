# modules/services/webeoc/ingest_rr.py
from __future__ import annotations
from typing import Any, Dict, List
import json, re, math, hashlib
from modules.utils.common import (
    cr2_upsert_request_group,
    cr_sanitize_item, prio_from_text,
    canonical_airport_code
)

def _to_float(x) -> float | None:
    try:
        return float(x)
    except Exception:
        try:
            m = re.search(r'[-+]?\d+(?:\.\d+)?', str(x or ''))
            return float(m.group(0)) if m else None
        except Exception:
            return None

_UNIT_MAP = {
    # pounds
    "lb": 1.0, "lbs": 1.0, "lb.": 1.0, "lbs.": 1.0, "pound": 1.0, "pounds": 1.0, "#": 1.0,
    # ounces
    "oz": 1.0/16.0, "oz.": 1.0/16.0, "ounce": 1.0/16.0, "ounces": 1.0/16.0,
    # kilograms
    "kg": 2.20462262185, "kg.": 2.20462262185, "kilogram": 2.20462262185, "kilograms": 2.20462262185,
    # grams
    "g": 0.00220462262185, "g.": 0.00220462262185, "gram": 0.00220462262185, "grams": 0.00220462262185,
    # tons: default 'ton'/'tons' means short ton (US) = 2000 lb
    "ton": 2000.0, "tons": 2000.0, "short ton": 2000.0, "short tons": 2000.0,
    # long ton (imperial)
    "long ton": 2240.0, "long tons": 2240.0, "lt": 2240.0,
    # metric ton
    "tonne": 2204.62262185, "tonnes": 2204.62262185, "metric ton": 2204.62262185, "metric tons": 2204.62262185,
    "mt": 2204.62262185,
}

_WEIGHT_RE = re.compile(
    r'(?P<num>[-+]?\d+(?:\.\d+)?)\s*(?P<unit>#|lbs?|lb\.?|pounds?|kg|kg\.?|kilograms?|g|g\.?|grams?|oz|oz\.?|ounces?|'
    r'(?:short\s+)?tons?|long\s+tons?|lt|tonne?s?|metric\s+tons?|mt)\b\.?', re.I)

_MULT_RE = re.compile(r'(?:^|[\s\(\[,;@x])(?:x|@|qty|quantity)\s*(?P<q>\d+(?:\.\d+)?)\b', re.I)
_EACH_RE = re.compile(r'(?P<q>\d+(?:\.\d+)?)\s*(?:each|ea\.?)\b', re.I)

def _unit_to_factor(u_raw: str) -> float | None:
    u = (u_raw or "").strip().lower()
    # normalize compound tokens like "short tons"
    u = re.sub(r'\s+', ' ', u)
    return _UNIT_MAP.get(u)

def _weight_from_text(s: str) -> float | None:
    """
    Find first weight occurrence in text and convert to pounds.
    Supports "900lb", "900 lb", "900lbs.", "2 metric tons", "2000#", etc.
    """
    if not s:
        return None
    for m in _WEIGHT_RE.finditer(str(s)):
        num = _to_float(m.group('num'))
        unit = m.group('unit')
        # Normalize some families
        canonical = unit.lower().rstrip('.')
        canonical = re.sub(r'\s+', ' ', canonical)
        if canonical == 't':  # too ambiguous; ignore bare 't'
            continue
        factor = _unit_to_factor(canonical)
        if factor and num is not None:
            return float(num) * factor
    return None

def _mult_from_text(s: str) -> float | None:
    """
    Look for multipliers in free text lines: "x4", "@ 3", "qty 2", "2 each"
    """
    if not s: return None
    m = _MULT_RE.search(s)
    if m:
        q = _to_float(m.group('q'))
        return q if (q is not None and q > 0) else None
    m2 = _EACH_RE.search(s)
    if m2:
        q = _to_float(m2.group('q'))
        return q if (q is not None and q > 0) else None
    return None

def _strip_weight_and_mult_tokens(s: str) -> str:
    """
    Remove any weight unit token and trailing multiplier hints from a free-text name.
    Examples turn into just the label:
      "Beef 900 lb x4"         -> "Beef"
      "Water: 50 kg @ 2 each"  -> "Water"
      "Generators 2 metric tons" -> "Generators"
    """
    if not s: return ""
    text = str(s)
    m = _WEIGHT_RE.search(text)
    if m: text = text[:m.start()]
    text = _MULT_RE.sub("", text)
    text = _EACH_RE.sub("", text)
    return re.sub(r"\s+", " ", text).strip()

def _compute_total_lb_from_size_qty(size: str, qty: str) -> float | None:
    """
    - If size has a weight: treat as "per-each" weight; multiply by numeric qty (default 1).
    - Else if qty has a weight: treat that as total weight.
    - Else: None (unparsable weight).
    """
    size_lb = _weight_from_text(size)
    qty_lb  = _weight_from_text(qty)
    if size_lb is not None:
        q = _to_float(qty)  # qty as count
        count = q if (q is not None and q > 0) else 1.0
        return float(size_lb) * float(count)
    if qty_lb is not None:
        return float(qty_lb)
    return None

def parse_saved_data(text: str) -> Dict[str, Any]:
    """
    Expect the WebEOC “Save data” JSON blob pasted as text.
    This stub accepts either:
      { "requests":[{"priority":"Life Saving","airport":"KELN","need":"water","qty_lb":200, "source":"RR#123"}, ...] }
    OR a single request object with equivalent keys.
    Return a normalized dict:
      {
        "items":[{airport, priority_code, need, qty_lb, source_ref, fingerprint_fields}],
        "raw":<original>,
        "errors":[...]
      }
    Validation (strict):
      - need, priority, destination, qty_lb (parsable to pounds) are REQUIRED.
    """
    raw = json.loads(text)
    items: List[Dict[str, Any]] = []
    errors: List[str] = []
    # If this looks like the real WebEOC Save-data (Input1..Input28), map it.
    if isinstance(raw, dict) and any(str(k).startswith("Input") for k in raw.keys()):
        # pull fields (defensive: keys may be missing)
        priority = raw.get("Input9") or raw.get("Priority") or ""
        deliver  = raw.get("Input20") or raw.get("Input28") or raw.get("Delivery Location Name") or ""
        airport  = canonical_airport_code(deliver) or (deliver or "").strip()
        if airport:
            airport = str(airport).upper()
        requester_tracking = (raw.get("Input7") or "").strip()
        state_tracking     = (raw.get("Input8") or "").strip()

        # 1) Try to parse Input16 free-text lines with weights + optional multipliers
        lines = str(raw.get("Input16", "") or "").splitlines()
        for line in lines:
            s = (line or "").strip()
            if not s:
                continue
            # Need label: prefer left side of colon; else text up to first weight token
            need = None
            name_m = re.match(r"\s*([^:]+)\s*:", s)
            if name_m:
                need = _strip_weight_and_mult_tokens(name_m.group(1))
            else:
                w = _WEIGHT_RE.search(s)
                need = _strip_weight_and_mult_tokens(s[:w.start()] if w else s)
            per_or_total_lb = _weight_from_text(s)
            mult = _mult_from_text(s)
            if per_or_total_lb is None:
                # no weight on this line; skip to next line
                continue
            total_lb = float(per_or_total_lb) * float(mult) if (mult and mult > 1) else float(per_or_total_lb)
            if not (airport and priority and need and total_lb and total_lb > 0):
                errors.append(f"Invalid Input16 line (need/priority/airport/weight): '{s}'")
                continue
            items.append({
                "airport": airport,
                "priority_code": prio_from_text(priority),
                "need": need,
                "qty_lb": round(float(total_lb), 3),
                "source_ref": f"{requester_tracking}/{state_tracking}".strip("/") or None,
                "fingerprint_fields": {
                    "priority_code": prio_from_text(priority),
                    "airport": airport,
                    "need_sanitized": cr_sanitize_item(need),
                    "qty_lb": round(float(total_lb), 3),
                    "requester_tracking": requester_tracking,
                    "state_tracking": state_tracking,
                }
            })

        # 2) If no items yet, fallback to Inputs 17–19:
        #    size may contain weight; quantity is a multiplier (count). If qty has units, treat qty as total weight.
        if not items:
            # IMPORTANT: name should be the "need" field only.
            # Do NOT concatenate Input18 (size/weight) into the name.
            need_raw = (raw.get("Input17") or raw.get("Input15") or "")  # prefer Input17, else Input15
            need = _strip_weight_and_mult_tokens(str(need_raw or "").strip())
            size_field = (raw.get("Input18") or "").strip()
            qty_field  = (raw.get("Input19") or "").strip()
            total_lb = _compute_total_lb_from_size_qty(size_field, qty_field)

            # Strict validation of required fields
            if not airport:
                errors.append("Missing destination (Input20/28).")
            if not priority:
                errors.append("Missing priority (Input9).")
            if not need:
                errors.append("Missing need (Input17 or Input15).")
            if total_lb is None or total_lb <= 0:
                errors.append("Unparsable or zero weight from size/quantity (Inputs 18/19).")
            else:
                items.append({
                    "airport": airport,
                    "priority_code": prio_from_text(priority),
                    "need": need,
                    "qty_lb": round(float(total_lb), 3),
                    "source_ref": f"{requester_tracking}/{state_tracking}".strip("/") or None,
                    "fingerprint_fields": {
                        "priority_code": prio_from_text(priority),
                        "airport": airport,
                        "need_sanitized": cr_sanitize_item(need),
                        "qty_lb": round(float(total_lb), 3),
                        "requester_tracking": requester_tracking,
                        "state_tracking": state_tracking,
                    }
                })

        return {"items": items, "raw": raw, "errors": errors}

    # ---- Generic formats (non-WebEOC) ---------------------------------------
    def emit(obj: Dict[str, Any]):
        ap  = canonical_airport_code(obj.get("airport") or obj.get("deliver_to") or obj.get("deliverTo") or "")
        need= obj.get("need") or obj.get("resource") or obj.get("item") or ""
        qty = _to_float(obj.get("qty_lb") or obj.get("quantity_lb") or obj.get("weight_lb") or obj.get("quantity") or 0)
        pri = prio_from_text(obj.get("priority") or obj.get("pri") or "")
        if not ap or not need or not pri or not qty or qty <= 0:
            errors.append(f"Missing/invalid required fields in object: {obj!r}")
            return
        items.append({
            "airport": ap,
            "priority_code": pri,
            "need": str(need),
            "qty_lb": float(qty),
            "source_ref": obj.get("source") or obj.get("tracking") or obj.get("request_id") or None
        })

    if isinstance(raw, dict) and isinstance(raw.get("requests"), list):
        for r in raw["requests"]:
            if isinstance(r, dict):
                emit(r)
        return {"items": items, "raw": raw, "errors": errors}
    elif isinstance(raw, dict):
        emit(raw)
        return {"items": items, "raw": raw, "errors": errors}
    else:
        # plain text fallback (very permissive)
        s = str(text)
        emit({
            "airport": (re.search(r'\b([A-Z]{3,4})\b', s) or [None, ""])[1],
            "priority": (re.search(r'life|preserv|incident', s, re.I) or ["", "Incident"])[1],
            "need": (re.search(r'need:\s*(.*)$', s, re.I|re.M) or ["",""])[1],
            "qty_lb": _to_float((re.search(r'(\d+(?:\.\d+)?)\s*lb', s, re.I) or ["","0"])[1]),
            "source": None
        })
        return {"items": items, "raw": {"text": s}, "errors": errors}

def ingest_items(items: List[Dict[str, Any]],
                 raw: Dict[str, Any],
                 *,
                 source_comm_id: int | None = None,
                 airport_override: str | None = None,
                 allow_raw_airport: bool = True) -> int:
    """
    Upsert a list of parsed items. If the operator typed an override (not necessarily ICAO-4),
    we normalize it again here; if normalization fails, we keep the raw label (uppercased)
    when allow_raw_airport=True.
    """
    norm_override = None
    if airport_override:
        airport_override = str(airport_override).strip().upper()
        norm = canonical_airport_code(airport_override)
        norm_override = (norm or airport_override).strip().upper()

    n = 0
    for it in (items or []):
        if norm_override and isinstance(it.get("airport"), str):
            it["airport"] = norm_override
        # fingerprint hint (idempotency)
        try:
            fields = it.get("fingerprint_fields") or {
                "priority_code": it.get("priority_code"),
                "airport": it.get("airport"),
                "need_sanitized": cr_sanitize_item(it.get("need","")),
                "qty_lb": it.get("qty_lb"),
            }
            s = json.dumps(fields, sort_keys=True, ensure_ascii=False).encode("utf-8")
            fp_hint = hashlib.sha256(s).hexdigest()
        except Exception:
            fp_hint = None
        cr2_upsert_request_group(
            airport        = it["airport"],
            priority_code  = it["priority_code"],
            need           = it["need"],
            qty_lb         = it["qty_lb"],
            source_comm_id = source_comm_id,
            source_ref     = it.get("source_ref"),
            raw_json       = raw,
            fingerprint_hint = fp_hint,
            allow_raw_airport = bool(allow_raw_airport),
        )
        n += 1
    return n

def ingest_saved_data(text: str, *,
                      source_comm_id: int | None = None,
                      airport_override: str | None = None,
                      allow_raw_airport: bool = True) -> int:
    """
    Parse + validate + upsert; returns count of rows added/linked.
    """
    parsed = parse_saved_data(text)
    items = parsed.get("items") or []
    errs  = parsed.get("errors") or []

    # Fallback: if no items but operator provided an airport, try injecting it and re-parse.
    if not items and airport_override:
        try:
            norm = (canonical_airport_code(airport_override) or str(airport_override).strip().upper())
            raw0 = json.loads(text)
            if isinstance(raw0, dict):
                raw2 = dict(raw0)
                raw2.setdefault("Input20", norm)
                reparsed = parse_saved_data(json.dumps(raw2, ensure_ascii=False))
                if (reparsed.get("items") or []):
                    parsed, items, errs = reparsed, (reparsed.get("items") or []), (reparsed.get("errors") or [])
        except Exception:
            pass

    if not items:
        # Still nothing to ingest → hard fail with combined errors
        raise ValueError("; ".join(errs or ["no valid items"]))

    return ingest_items(
        items, parsed.get("raw") or {},
        source_comm_id=source_comm_id,
        airport_override=airport_override,
        allow_raw_airport=allow_raw_airport
    )
