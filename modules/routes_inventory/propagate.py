# modules/routes_inventory/propagate.py
import sqlite3
from typing import Sequence

from flask import request, jsonify
from app import DB_FILE, publish_inventory_event
from app import inventory_bp as bp
from modules.utils.common import dict_rows, sanitize_name

_TOL = 0.001  # float tolerance for weight (lbs)


def _as_list(values) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (list, tuple)):
        return [str(v).strip() for v in values if str(v).strip()]
    s = str(values).strip()
    return [s] if s else []


def _float_or_none(v):
    try:
        return float(v)
    except Exception:
        return None


def _where_for(op: str, names: Sequence[str], old_wpu_lbs: float | None):
    """Build WHERE clause + params for the target selection."""
    if not names:
        return "1=0", []  # no matches
    params: list = []
    where = ["sanitized_name IN (%s)" % ",".join(["?"] * len(names))]
    params.extend(names)
    if op == "weight":
        if old_wpu_lbs is None:
            return "1=0", []
        where.append("ABS(weight_per_unit - ?) < ?")
        params.extend([old_wpu_lbs, _TOL])
    return " AND ".join(where), params


def _preview_summary(where_sql: str, params: list):
    rows = dict_rows(
        f"""
        SELECT c.display_name AS category,
               COUNT(*) AS rows,
               COALESCE(SUM(e.quantity),0)      AS qty,
               COALESCE(SUM(e.total_weight),0)  AS total_weight
          FROM inventory_entries e
          JOIN inventory_categories c ON c.id = e.category_id
         WHERE {where_sql}
         GROUP BY c.display_name
         ORDER BY c.display_name
        """,
        tuple(params),
    )

    # Normalize types + add total_lbs alias for the UI
    for r in rows:
        r["rows"] = int(r.get("rows") or 0)
        r["qty"] = int(r.get("qty") or 0)
        r["total_weight"] = float(r.get("total_weight") or 0.0)
        r["total_lbs"] = r["total_weight"]

    total_rows = sum(r["rows"] for r in rows) if rows else 0
    total_qty = sum(r["qty"] for r in rows) if rows else 0
    total_wt = sum(r["total_weight"] for r in rows) if rows else 0.0

    totals = {
        "rows": int(total_rows),
        "qty": int(total_qty),
        "total_weight": float(total_wt),
        "total_lbs": float(total_wt),
    }
    return {"groups": rows, "totals": totals}


# Accept BOTH /api/propagate/* (existing) and /propagate/* (new) to match JS
@bp.post("/api/propagate/preview")
@bp.post("/propagate/preview")
def propagate_preview():
    """
    Body (JSON or form):
      kind|op: 'category' | 'name' | 'weight'
      names[] OR match.sanitized_name OR sanitized_name
      old_weight_per_unit OR match.old_weight_per_unit  (required for weight)
      new_category_id  (category)
      new_name         (name)   -- will be sanitize_name()'d
      new_weight_per_unit (weight, lbs)
      (also supports a nested {changes:{...}} form)
    """
    d = request.get_json(silent=True) or request.form
    op = (d.get("op") or d.get("kind") or "").strip().lower()

    # allow a single name or multiple names
    names = (
        _as_list(d.get("names"))
        or _as_list((d.get("match") or {}).get("sanitized_name"))
        or _as_list(d.get("sanitized_name"))
    )
    old_wpu = _float_or_none(
        (d.get("match") or {}).get("old_weight_per_unit") or d.get("old_weight_per_unit")
    )

    if op not in ("category", "name", "weight") or not names:
        return jsonify({"ok": False, "status": "error", "message": "Invalid request"}), 400
    if op == "weight" and old_wpu is None:
        return (
            jsonify(
                {"ok": False, "status": "error", "message": "Missing old_weight_per_unit for weight op"}
            ),
            400,
        )

    where_sql, params = _where_for(op, names, old_wpu)
    summary = _preview_summary(where_sql, params)
    return jsonify(
        {
            "ok": True,
            "status": "ok",
            "op": op,
            "summary": summary,
            "match": {"names": names, "old_weight_per_unit": old_wpu},
        }
    )


@bp.post("/api/propagate/apply")
@bp.post("/propagate/apply")
def propagate_apply():
    d = request.get_json(silent=True) or request.form
    op = (d.get("op") or d.get("kind") or "").strip().lower()
    names = (
        _as_list(d.get("names"))
        or _as_list((d.get("match") or {}).get("sanitized_name"))
        or _as_list(d.get("sanitized_name"))
    )
    old_wpu = _float_or_none(
        (d.get("match") or {}).get("old_weight_per_unit") or d.get("old_weight_per_unit")
    )

    if op not in ("category", "name", "weight") or not names:
        return jsonify({"ok": False, "status": "error", "message": "Invalid request"}), 400
    if op == "weight" and old_wpu is None:
        return (
            jsonify(
                {"ok": False, "status": "error", "message": "Missing old_weight_per_unit for weight op"}
            ),
            400,
        )

    # Extract targets (support both flat and changes.{...})
    changes = d.get("changes") or {}
    if op == "category":
        try:
            new_cat = int(changes.get("new_category_id") or d.get("new_category_id"))
        except Exception:
            new_cat = 0
        if new_cat <= 0:
            return jsonify({"ok": False, "status": "error", "message": "Missing new_category_id"}), 400
    elif op == "name":
        new_name_raw = changes.get("new_name") or d.get("new_name") or ""
        new_name = sanitize_name(new_name_raw)
        if not new_name:
            return jsonify({"ok": False, "status": "error", "message": "Missing new_name"}), 400
    else:  # weight
        new_wpu = _float_or_none(changes.get("new_weight_per_unit") or d.get("new_weight_per_unit"))
        if new_wpu is None or new_wpu <= 0:
            return jsonify({"ok": False, "status": "error", "message": "Missing/invalid new_weight_per_unit"}), 400

    # preview (pre-count) for UI feedback
    where_sql, params = _where_for(op, names, old_wpu)
    summary_before = _preview_summary(where_sql, params)

    changed = 0
    with sqlite3.connect(DB_FILE) as c:
        if op == "category":
            q = f"UPDATE inventory_entries SET category_id=? WHERE {where_sql}"
            cur = c.execute(q, (new_cat, *params))
            changed = cur.rowcount or 0
        elif op == "name":
            # keep raw_name aligned with sanitized_name for simplicity
            q = f"UPDATE inventory_entries SET sanitized_name=?, raw_name=? WHERE {where_sql}"
            cur = c.execute(q, (new_name, new_name, *params))
            changed = cur.rowcount or 0
        else:
            # Update weight_per_unit and recompute total_weight = quantity * new_wpu
            q = f"""
                UPDATE inventory_entries
                   SET weight_per_unit = ?,
                       total_weight    = (quantity * ?)
                 WHERE {where_sql}
            """
            cur = c.execute(q, (new_wpu, new_wpu, *params))
            changed = cur.rowcount or 0

    try:
        publish_inventory_event()
    except Exception:
        pass

    return jsonify(
        {
            "ok": True,
            "status": "ok",
            "op": op,
            "changed": int(changed or 0),
            "summary_before": summary_before,
        }
    )
