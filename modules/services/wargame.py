
import uuid
import sqlite3, json
from datetime import datetime
import time

from modules.utils.common import *  # shared helpers (dict_rows, prefs, units, etc.)
from app import DB_FILE

from modules.utils.common import _parse_manifest # Star import won't get this one

# --- Reset/migration helpers (import or safe fallbacks) ---
try:
    from modules.utils.common import _reset_autoincrements, run_migrations
except Exception:
    def _reset_autoincrements(tables):  # no-op fallback
        pass
    def run_migrations():               # no-op fallback
        pass
# --- end helpers ---
def get_wargame_role_epoch() -> str:
    """Return the current epoch; create one if missing."""
    row = dict_rows("SELECT value FROM preferences WHERE name='wargame_role_epoch'")
    if row:
        return row[0]['value']
    ep = uuid.uuid4().hex
    set_preference('wargame_role_epoch', ep)
    return ep

def bump_wargame_role_epoch() -> None:
    """Rotate epoch so all existing role cookies become stale."""
    set_preference('wargame_role_epoch', uuid.uuid4().hex)

def wargame_task_start_once(role: str, kind: str, key: str, gen_at: str, sched_for: str | None = None) -> None:
    rows = dict_rows(
        "SELECT 1 FROM wargame_tasks WHERE role=? AND kind=? AND key=?",
        (role, kind, key)
    )
    if rows:
        return
    wargame_task_start(role=role, kind=kind, key=key, gen_at=gen_at, sched_for=sched_for)

def set_wargame_epoch(epoch=None) -> int:
    """
    Persist a stable epoch for the current Wargame run.
    This namespaces client cookies (e.g., read/unread) so they reset only
    when Wargame is (re)started, not on every page render.
    """
    if epoch is None:
        epoch = int(time.time())
    with sqlite3.connect(DB_FILE) as c:
        c.execute(
            "INSERT OR REPLACE INTO preferences(name, value) VALUES(?, ?)",
            ('wargame_epoch', str(epoch))
        )
        c.commit()
    return epoch

def get_wargame_epoch() -> int:
    """Return current Wargame epoch (0 if not set)."""
    row = dict_rows("SELECT value FROM preferences WHERE name='wargame_epoch'")
    try:
        return int(row[0]['value'])
    except Exception:
        return 0

def reset_wargame_state():
    """
    Wipe transient Wargame queues so a fresh run starts clean.
    Note: delete child rows before parent rows.
    """
    with sqlite3.connect(DB_FILE) as c:
        cur = c.cursor()
        # Radio
        cur.execute("DELETE FROM wargame_emails")
        cur.execute("DELETE FROM wargame_radio_schedule")
        # Ramp
        cur.execute("DELETE FROM wargame_ramp_requests")
        cur.execute("DELETE FROM wargame_inbound_schedule")
        # Inventory (batch items, then batches)
        cur.execute("DELETE FROM wargame_inventory_batch_items")
        cur.execute("DELETE FROM wargame_inventory_batches")
        c.commit()
    # Reset AUTOINCREMENT counters so new runs start from 1 again.
    _reset_autoincrements([
        'wargame_emails',
        'wargame_radio_schedule',
        'wargame_ramp_requests',
        'wargame_inbound_schedule',
        'wargame_inventory_batches',
        'wargame_inventory_batch_items',
        'wargame_tasks'
    ])

def wargame_finish_radio_inbound_if_tagged(subject: str, body: str) -> None:
    """If message carries a WGID and Wargame is on, finish the radio-inbound task."""
    if get_preference('wargame_mode') != 'yes':
        return
    wgid = extract_wgid_from_text(subject, body)
    if wgid:
        try:
            wargame_task_finish('radio', 'inbound', f"msg:{wgid}")
        except Exception:
            pass  # be defensive; this should never break operator flow

def wargame_finish_radio_outbound(fid: int) -> None:
    """Finish radio‑outbound metric when the operator marks the flight as sent."""
    if get_preference('wargame_mode') == 'yes':
        try:
            wargame_task_finish('radio', 'outbound', key=f"flight:{fid}")
        except Exception:
            pass

def wargame_start_radio_outbound(fid: int) -> None:
    """Start radio‑outbound metric for a new outbound ramp flight."""
    if get_preference('wargame_mode') == 'yes':
        try:
            wargame_task_start_once('radio', 'outbound', key=f"flight:{fid}", gen_at=datetime.utcnow().isoformat())
        except Exception:
            pass

def wargame_finish_ramp_inbound(fid: int) -> None:
    """Finish ramp‑inbound metric when an arrival is logged/updated."""
    if get_preference('wargame_mode') == 'yes':
        try:
            wargame_task_finish('ramp', 'inbound', key=f"flight:{fid}")
        except Exception:
            pass

def wargame_start_ramp_inbound(fid: int, started_at: str | None = None) -> None:
    """Start ramp‑inbound timer when an inbound cue appears for this flight."""
    if get_preference('wargame_mode') == 'yes':
        wargame_task_start_once(
            role='ramp',
            kind='inbound',
            key=f"flight:{fid}",
            gen_at=(started_at or datetime.utcnow().isoformat())
        )

def reconcile_inventory_batches(session_id: str) -> None:
    """
    For the just-committed /inventory session:
      • Match **only** by exact item (sanitized name) **and** exact size.
      • Use either parsed lines from raw_name (e.g., "beans 25 lb×3"), or the
        structured columns (sanitized_name, weight_per_unit, quantity).
      • There is **no weight-based fallback**; any remainder stays unapplied
        until exact stock lines are logged.
      • When a batch completes, set satisfied_at and write one inventory SLA metric.
    """
    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        entries = c.execute("""
            SELECT
              id,
              direction,             -- 'in' | 'out'
              quantity,
              total_weight,
              weight_per_unit,
              sanitized_name,
              COALESCE(NULLIF(raw_name,''), '') AS raw_name
            FROM inventory_entries
            WHERE session_id=? AND pending=0
              AND source='inventory'
        """, (session_id,)).fetchall()
        if not entries:
            return
        now_ts = datetime.utcnow().isoformat()

        def load_batches(direction: str):
            bs = c.execute("""
                SELECT id, created_at
                  FROM wargame_inventory_batches
                 WHERE direction=? AND satisfied_at IS NULL
            """, (direction,)).fetchall()
            out = []
            for b in bs:
                items = c.execute("""
                    SELECT id, name, size_lb, qty_required, qty_done
                      FROM wargame_inventory_batch_items
                     WHERE batch_id=?
                """, (b['id'],)).fetchall()
                remain = sum(1 for it in items if it['qty_done'] < it['qty_required'])
                out.append({'b': b, 'items': items, 'remain': remain})
            return out

        def pick_most_complete(cands):
            if not cands:
                return None
            cands.sort(key=lambda r: (r['remain'], r['b']['created_at']))
            return cands[0]

        def close_if_complete(batch_id: int, created_at: str):
            items_now = c.execute("""
                SELECT qty_required, qty_done
                  FROM wargame_inventory_batch_items
                 WHERE batch_id=?
            """, (batch_id,)).fetchall()
            if all(x['qty_done'] >= x['qty_required'] for x in items_now):
                c.execute("UPDATE wargame_inventory_batches SET satisfied_at=? WHERE id=?",
                          (now_ts, batch_id))
                delta = (datetime.fromisoformat(now_ts) - datetime.fromisoformat(created_at)).total_seconds()
                c.execute("""
                  INSERT INTO wargame_metrics(event_type, delta_seconds, recorded_at, key)
                  VALUES ('inventory', ?, ?, ?)
                """, (delta, now_ts, f"invbatch:{batch_id}"))

        def apply_item(direction: str, name_raw: str, size_lb: float, qty: int) -> int:
            """
            Allocate `qty` units of (sanitized(name_raw), size_lb) across batches that still need them.
            Returns the number of units actually applied.
            """
            if qty <= 0 or size_lb <= 0:
                return 0
            applied = 0
            san = sanitize_name(name_raw)
            while qty > 0:
                cands = []
                for r in load_batches(direction):
                    need_here = any(
                        sanitize_name(it['name']) == san and abs(it['size_lb'] - size_lb) < 1e-6 and
                        it['qty_done'] < it['qty_required']
                        for it in r['items']
                    )
                    if need_here:
                        cands.append(r)
                pick = pick_most_complete(cands)
                if not pick:
                    break
                for it in pick['items']:
                    if sanitize_name(it['name']) == san and abs(it['size_lb'] - size_lb) < 1e-6:
                        remaining = it['qty_required'] - it['qty_done']
                        inc = min(qty, remaining)
                        if inc > 0:
                            c.execute(
                              "UPDATE wargame_inventory_batch_items SET qty_done=qty_done+? WHERE id=?",
                              (inc, it['id'])
                            )
                            applied += inc
                            qty     -= inc
                        break
                close_if_complete(pick['b']['id'], pick['b']['created_at'])
            return applied

        for e in entries:
            # 1) Try parsing raw_name ("beans 25 lb×3" etc.)
            parsed = _parse_manifest(e['raw_name'])
            if parsed:
                for it in parsed:
                    # Use the per-token quantity from the parsed manifest line,
                    # not the entry's aggregate quantity.
                    q = int((it.get('qty', 1) or 1))
                    size = float(it['size_lb'])
                    _used = apply_item(e['direction'], it['name'], size, q)
                continue  # next entry

            # 2) No parse → use structured columns (typical for outbound entries)
            qty  = int(e['quantity'] or 0)
            size = float(e['weight_per_unit'] or 0.0)
            name = e['sanitized_name'] or e['raw_name']
            if qty > 0 and size > 0 and name:
                _ = apply_item(e['direction'], name, size, qty)
def reconcile_inventory_entry(entry_id: int) -> None:
    """
    Reconcile a single committed Inventory entry (used by Inventory Detail form).
    Mirrors batch reconciliation:
      • Require exact (sanitized name + size) match using parsed raw_name or
        the structured columns.
    """
    row = dict_rows("""
      SELECT id, direction, quantity, total_weight, weight_per_unit, sanitized_name,
             COALESCE(NULLIF(raw_name,''), '') AS raw_name
        FROM inventory_entries
       WHERE id=? AND pending=0
         AND source='inventory'
    """, (entry_id,))
    if not row:
        return
    e = row[0]

    with sqlite3.connect(DB_FILE) as c:
        c.row_factory = sqlite3.Row
        now_ts = datetime.utcnow().isoformat()

        def load_batches(direction: str):
            bs = c.execute("""
                SELECT id, created_at FROM wargame_inventory_batches
                 WHERE direction=? AND satisfied_at IS NULL
            """, (direction,)).fetchall()
            out = []
            for b in bs:
                items = c.execute("""
                    SELECT id, name, size_lb, qty_required, qty_done
                      FROM wargame_inventory_batch_items
                     WHERE batch_id=?
                """, (b['id'],)).fetchall()
                remain = sum(1 for it in items if it['qty_done'] < it['qty_required'])
                out.append({'b': b, 'items': items, 'remain': remain})
            return out

        def pick_most_complete(cands):
            if not cands: return None
            cands.sort(key=lambda r: (r['remain'], r['b']['created_at']))
            return cands[0]

        def close_if_complete(batch_id: int, created_at: str):
            items_now = c.execute("""
                SELECT qty_required, qty_done
                  FROM wargame_inventory_batch_items
                 WHERE batch_id=?
            """, (batch_id,)).fetchall()
            if all(x['qty_done'] >= x['qty_required'] for x in items_now):
                c.execute("UPDATE wargame_inventory_batches SET satisfied_at=? WHERE id=?",
                          (now_ts, batch_id))
                delta = (datetime.fromisoformat(now_ts) - datetime.fromisoformat(created_at)).total_seconds()
                c.execute("""
                  INSERT INTO wargame_metrics(event_type, delta_seconds, recorded_at, key)
                  VALUES ('inventory', ?, ?, ?)
                """, (delta, now_ts, f"invbatch:{batch_id}"))

        def apply_item(direction: str, name_raw: str, size_lb: float, qty: int) -> int:
            if qty <= 0 or size_lb <= 0: return 0
            applied = 0
            san = sanitize_name(name_raw)
            while qty > 0:
                cands = []
                for r in load_batches(direction):
                    need_here = any(
                        sanitize_name(it['name']) == san and abs(it['size_lb'] - size_lb) < 1e-6 and
                        it['qty_done'] < it['qty_required']
                        for it in r['items']
                    )
                    if need_here: cands.append(r)
                pick = pick_most_complete(cands)
                if not pick: break
                for it in pick['items']:
                    if sanitize_name(it['name']) == san and abs(it['size_lb'] - size_lb) < 1e-6:
                        remaining = it['qty_required'] - it['qty_done']
                        inc = min(qty, remaining)
                        if inc > 0:
                            c.execute("UPDATE wargame_inventory_batch_items SET qty_done=qty_done+? WHERE id=?",
                                      (inc, it['id']))
                            applied += inc
                            qty     -= inc
                        break
                close_if_complete(pick['b']['id'], pick['b']['created_at'])
            return applied

        # Prefer parsed raw_name if present, else the structured columns

        parsed = _parse_manifest(e['raw_name'])
        if parsed:
            for it in parsed:
                # Same fix as the batch reconciler: respect the token's qty.
                q = int((it.get('qty', 1) or 1))
                size = float(it['size_lb'])
                _used = apply_item(e['direction'], it['name'], size, q)

        else:
            qty  = int(e['quantity'] or 0)
            size = float(e['weight_per_unit'] or 0.0)
            name = e['sanitized_name'] or e['raw_name']
            if qty > 0 and size > 0 and name:
                _ = apply_item(e['direction'], name, size, qty)

def wargame_task_start(role: str, kind: str, key: str, gen_at: str, sched_for: str | None = None) -> None:
    """Create or refresh a pending Wargame task anchor."""
    with sqlite3.connect(DB_FILE) as c:
        c.execute("""
          INSERT INTO wargame_tasks(role,kind,key,gen_at,sched_for,created_at)
          VALUES(?,?,?,?,?,?)
          ON CONFLICT(role,kind,key) DO UPDATE SET
            gen_at     = excluded.gen_at,
            sched_for  = excluded.sched_for,
            created_at = excluded.created_at
        """, (role, kind, key, gen_at, sched_for, datetime.utcnow().isoformat()))

def wargame_task_finish(role: str, kind: str, key: str) -> bool:
    """
    Resolve a pending Wargame task into a finalized metric.
    Returns True if a task was found & recorded; False if no pending task existed.
    """
    rows = dict_rows(
        "SELECT gen_at, sched_for FROM wargame_tasks WHERE role=? AND kind=? AND key=?",
        (role, kind, key)
    )
    if not rows:
        return False

    now       = datetime.utcnow()
    now_iso   = now.isoformat()
    gen_dt    = datetime.fromisoformat(rows[0]['gen_at'])
    sched_for = rows[0]['sched_for']

    # Radio inbound uses batch semantics; others are simple now - gen_at.
    if role == 'radio' and kind == 'inbound':
        srow = dict_rows("SELECT value FROM preferences WHERE name='wargame_settings'")
        settings    = json.loads(srow[0]['value'] or '{}') if srow else {}
        use_batch   = (settings.get('radio_use_batch','no')   == 'yes')
        count_batch = (settings.get('radio_count_batch','yes') == 'yes')
        anchor_dt   = (datetime.fromisoformat(sched_for)
                       if (use_batch and not count_batch and sched_for)
                       else gen_dt)
    else:
        anchor_dt = gen_dt

    delta = (now - anchor_dt).total_seconds()

    with sqlite3.connect(DB_FILE) as c:
        c.execute("""
          INSERT INTO wargame_metrics(event_type, delta_seconds, recorded_at, key)
          VALUES (?, ?, ?, ?)
        """, (role, delta, now_iso, key))
        c.execute("DELETE FROM wargame_tasks WHERE role=? AND kind=? AND key=?",
                  (role, kind, key))
    return True
