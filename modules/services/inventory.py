from __future__ import annotations
from typing import List, Tuple
import math
from datetime import datetime


class InventoryConflict(ValueError):
    """An inventory operation needs operator input or exceeds available stock."""
    def __init__(self, message, code="out_of_stock", origins=None):
        super().__init__(message)
        self.code = code
        self.origins = origins or []

    def payload(self):
        return {"status": self.code, "error": self.code, "message": str(self),
                "origins": self.origins}


def _validate_item(category_id, name, weight, qty):
    if (int(category_id) <= 0 or not str(name).strip() or
            not math.isfinite(float(weight)) or float(weight) <= 0 or int(qty) <= 0):
        raise InventoryConflict("Category, item, positive quantity and finite positive weight are required.",
                                "invalid_item")


def available_by_origin(c, category_id, name, weight):
    """Committed receipts less ALL committed and reserved shipments.

    Pending receipts are not warehouse stock. Call under BEGIN IMMEDIATE when
    using this result to allocate stock, so reads and writes form one operation.
    """
    rows = c.execute("""
        SELECT COALESCE(origin,''), COALESCE(SUM(CASE
            WHEN direction='in' AND COALESCE(pending,0)=0 THEN quantity
            WHEN direction='out' THEN -quantity ELSE 0 END),0)
          FROM inventory_entries
         WHERE category_id=? AND LOWER(sanitized_name)=LOWER(?)
           AND weight_per_unit=?
         GROUP BY COALESCE(origin,'')
    """, (int(category_id), name, float(weight))).fetchall()
    return {str(r[0]): int(r[1]) for r in rows}


def choose_origin(balances, origin=None):
    """Resolve only an unambiguous source. Empty string is an explicit source."""
    if origin is not None:
        return str(origin).strip()
    choices = sorted(k for k, qty in balances.items() if qty > 0)
    if len(choices) > 1:
        raise InventoryConflict("Choose a cargo source before continuing.",
                                "origin_required", choices)
    return choices[0] if choices else ""


def require_stock(c, category_id, name, weight, qty, origin=None):
    _validate_item(category_id, name, weight, qty)
    balances = available_by_origin(c, category_id, name, weight)
    resolved = choose_origin(balances, origin)
    avail = balances.get(resolved, 0)
    if int(qty) > avail:
        raise InventoryConflict(f"Only {max(0, avail)} available from this source (including reservations).")
    return resolved


def insert_entry(c, *, category_id, name, weight, qty, direction,
                 origin=None, session_id=None, pending=False, source="inventory", raw_name=None):
    """Insert one movement using the caller's reserved write transaction."""
    if not c.in_transaction:
        raise RuntimeError("Inventory writes require an explicit transaction")
    _validate_item(category_id, name, weight, qty)
    if direction not in ("in", "out"):
        raise InventoryConflict("Invalid inventory direction.", "invalid_item")
    resolved = (require_stock(c, category_id, name, weight, qty, origin)
                if direction == "out" else str(origin or "").strip())
    ts = datetime.utcnow().isoformat()
    cur = c.execute("""
        INSERT INTO inventory_entries(category_id,raw_name,sanitized_name,
            weight_per_unit,quantity,total_weight,direction,timestamp,
            pending,pending_ts,session_id,source,origin)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (int(category_id), raw_name or name, name, float(weight), int(qty),
          float(weight)*int(qty), direction, ts, int(pending), ts if pending else None,
          session_id, source, resolved))
    return cur.lastrowid, resolved, ts


def validate_session_commit(c, session_id):
    """Reject legacy over-reservations before promoting a manifest's pendings."""
    rows = c.execute("""SELECT DISTINCT category_id,sanitized_name,weight_per_unit,
        COALESCE(origin,'') FROM inventory_entries
        WHERE session_id=? AND direction='out' AND pending=1""", (session_id,)).fetchall()
    for cid,name,weight,origin in rows:
        available = available_by_origin(c,cid,name,weight).get(origin,0)
        returns = c.execute("""SELECT COALESCE(SUM(quantity),0) FROM inventory_entries
            WHERE session_id=? AND category_id=? AND LOWER(sanitized_name)=LOWER(?)
              AND weight_per_unit=? AND COALESCE(origin,'')=? AND direction='in' AND pending=1""",
            (session_id,cid,name,weight,origin)).fetchone()[0]
        if available + int(returns) < 0:
            raise InventoryConflict("Existing reservations exceed stock. Reduce the manifest quantity before saving.")


def adjust_pending(c, *, session_id, category_id, name, weight, direction, delta, origin=None):
    """One atomic scan, preserving source identity and global reservations."""
    if not c.in_transaction:
        raise RuntimeError("Inventory writes require an explicit transaction")
    if delta > 0:
        _validate_item(category_id, name, weight, delta)
        resolved = (require_stock(c, category_id, name, weight, delta, origin)
                    if direction == "out" else str(origin or "").strip())
    else:
        balances = {r[0]: int(r[1]) for r in c.execute("""
            SELECT COALESCE(origin,''), SUM(quantity) FROM inventory_entries
             WHERE session_id=? AND category_id=? AND LOWER(sanitized_name)=LOWER(?)
               AND weight_per_unit=? AND direction=? AND pending=1
             GROUP BY COALESCE(origin,'')
        """, (session_id, int(category_id), name, float(weight), direction))}
        resolved = choose_origin(balances, origin)
    rows = c.execute("""
        SELECT id, quantity FROM inventory_entries WHERE session_id=?
          AND category_id=? AND LOWER(sanitized_name)=LOWER(?) AND weight_per_unit=?
          AND direction=? AND pending=1 AND COALESCE(origin,'')=? ORDER BY id
    """, (session_id, int(category_id), name, float(weight), direction, resolved)).fetchall()
    old_qty = sum(int(r[1]) for r in rows)
    new_qty = max(0, old_qty + int(delta))
    ts = datetime.utcnow().isoformat()
    if rows:
        # Consolidate only rows of the SAME source and item.
        c.executemany("DELETE FROM inventory_entries WHERE id=?", [(r[0],) for r in rows[1:]])
        if new_qty:
            c.execute("""UPDATE inventory_entries SET quantity=?, total_weight=?,
                pending_ts=?, timestamp=? WHERE id=?""",
                (new_qty, float(weight)*new_qty, ts, ts, rows[0][0]))
        else:
            c.execute("DELETE FROM inventory_entries WHERE id=?", (rows[0][0],))
    elif new_qty:
        # Already validated availability above; insertion repeats the same check
        # under this lock, without changing the set of competing reservations.
        insert_entry(c, category_id=category_id, name=name, weight=weight,
                     qty=new_qty, direction=direction, origin=resolved,
                     session_id=session_id, pending=True, source="scanner")
    return new_qty, resolved


def manifest_rows(c, session_id, queued_id=None, flight_id=None):
    """Snapshot plus subsequent ledger deltas, once, grouped by source.

    A queued snapshot copies its session's ledger. Adding that ledger again
    double counts it; use the same snapshot cut line as the save/send paths.
    """
    if flight_id is not None:
        where, args = "flight_id=?", (int(flight_id),)
    elif queued_id is not None:
        where, args = "queued_id=?", (int(queued_id),)
    else:
        where, args = "session_id=?", (session_id,)
    baseline = c.execute(f"""SELECT category_id,sanitized_name,weight_per_unit,
        COALESCE(origin,''),quantity,direction,timestamp FROM flight_cargo
        WHERE {where} ORDER BY id""", args).fetchall()
    cutline = max((r[6] for r in baseline if r[6]), default=None)
    ledger = c.execute("""SELECT category_id,sanitized_name,weight_per_unit,
        COALESCE(origin,''),quantity,direction,timestamp FROM inventory_entries
        WHERE session_id=? AND COALESCE(pending,0) IN (0,1)
          AND (? IS NULL OR timestamp>?) ORDER BY timestamp,id""",
        (session_id, cutline, cutline)).fetchall()
    direction = (baseline or ledger)[0][5] if (baseline or ledger) else "out"
    totals = {}
    for row in [*baseline, *ledger]:
        key = (int(row[0]), row[1].lower().strip(), float(row[2]), row[3])
        totals[key] = totals.get(key, 0) + int(row[4]) * (1 if row[5] == direction else -1)
    return [dict(category_id=k[0], sanitized_name=k[1], weight_per_unit=k[2],
                 origin=k[3], qty=q, total=k[2]*q, direction=direction)
            for k,q in sorted(totals.items()) if q > 0]


def remove_manifest_item(c, *, session_id, name, weight, qty=1, origin=None,
                         category_id=None, queued_id=None, flight_id=None):
    """Remove existing cargo only; never mint excess return stock or guess a source."""
    if not c.in_transaction:
        raise RuntimeError("Inventory writes require an explicit transaction")
    candidates = [r for r in manifest_rows(c, session_id, queued_id, flight_id)
                  if r['sanitized_name'] == name.lower().strip()
                  and r['weight_per_unit'] == float(weight)
                  and (category_id is None or r['category_id'] == int(category_id))]
    if len({r['category_id'] for r in candidates}) > 1:
        raise InventoryConflict("Choose the item category before removing cargo.", "category_required")
    resolved = choose_origin({r['origin']: r['qty'] for r in candidates}, origin)
    item = next((r for r in candidates if r['origin'] == resolved), None)
    if not item:
        return dict(applied=0, effective_qty=0, origin=resolved, removed=True)
    target = item['qty'] if qty is None else min(max(0, int(qty)), item['qty'])
    remaining = target
    pending = c.execute("""SELECT id,quantity FROM inventory_entries
        WHERE session_id=? AND category_id=? AND LOWER(sanitized_name)=LOWER(?)
          AND weight_per_unit=? AND COALESCE(origin,'')=? AND direction=? AND pending=1
        ORDER BY id""", (session_id,item['category_id'],name,float(weight),resolved,item['direction'])).fetchall()
    for row in pending:
        take = min(remaining, int(row[1]))
        if take == int(row[1]):
            c.execute("DELETE FROM inventory_entries WHERE id=?", (row[0],))
        elif take:
            c.execute("UPDATE inventory_entries SET quantity=quantity-?, total_weight=(quantity-?)*weight_per_unit WHERE id=?",
                      (take,take,row[0]))
        remaining -= take
        if not remaining:
            break
    if remaining:
        insert_entry(c, category_id=item['category_id'], name=name, weight=weight,
                     qty=remaining, direction='in' if item['direction']=='out' else 'out',
                     origin=resolved, session_id=session_id, source='scan-nudge/remove')
    effective = item['qty']-target
    return dict(applied=target, effective_qty=effective, origin=resolved,
                removed=effective == 0, reduced_pending=target-remaining,
                applied_committed=remaining)

def get_wargame_seed_items() -> List[Tuple[str, str, int, int]]:
    """
    Canonical Wargame baseline seed list.
    Each tuple is: (category_display_name, item_name, weight_lb, qty)
    Edit THIS list only.
    """
    return [
        ('emergency supplies', 'batteries', 10,  12),
        ('emergency supplies', 'batteries', 25,   8),
        ('food',               'beans',     25,  10),
        ('food',               'rice',      20,  10),
        ('medical supplies',   'bandages',   5,  20),
        ('water',              'water',     20,  20),
    ]
