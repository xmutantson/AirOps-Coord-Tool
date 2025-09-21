# modules/utils/staff.py
from __future__ import annotations
import sqlite3
from typing import Any, Dict, Iterable, List, Tuple, Optional
from datetime import datetime, timedelta

from modules.utils.common import get_db_file, dict_rows, ensure_column

# Supported windows (hours); "all" means no lower bound
_WINDOWS = {
    "12h": 12,
    "24h": 24,
    "72h": 72,
    "all": None,
}

def _now_iso() -> str:
    return datetime.utcnow().isoformat()

def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        # Accept both naive and Z-suffixed
        t = ts.replace("Z", "")
        return datetime.fromisoformat(t)
    except Exception:
        return None

def _fmt_hhmm_from_seconds(seconds: int) -> str:
    if seconds <= 0:
        return "0:00"
    m = seconds // 60
    h = m // 60
    mm = m % 60
    return f"{h}:{mm:02d}"

def _asdict(row: Any) -> Dict[str, Any]:
    """Normalize sqlite3.Row → dict for safe .get() usage."""
    if row is None:
        return {}
    try:
        # sqlite3.Row is already mapping-like, but lacks .get; dict() makes a real dict
        return dict(row)
    except Exception:
        # if it's already a dict, or something else mapping-like
        return row  # type: ignore[return-value]

# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

def ensure_staff_tables() -> None:
    """
    Create minimal staff + staff_shifts tables and helpful indexes, idempotently.
    """
    with sqlite3.connect(get_db_file()) as c:
        # Master staff roster
        c.execute("""
          CREATE TABLE IF NOT EXISTS staff (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            role       TEXT,
            ew_number  TEXT,
            is_active  INTEGER NOT NULL DEFAULT 1,
            created_at TEXT    NOT NULL,
            updated_at TEXT
          )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_staff_name     ON staff(name)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_staff_ew       ON staff(ew_number)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_staff_active   ON staff(is_active)")

        # Shift log (on/off)
        c.execute("""
          CREATE TABLE IF NOT EXISTS staff_shifts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id   INTEGER NOT NULL,
            start_utc  TEXT    NOT NULL,
            end_utc    TEXT,
            source     TEXT,
            notes      TEXT,
            created_at TEXT    NOT NULL,
            updated_at TEXT,
            FOREIGN KEY(staff_id) REFERENCES staff(id)
          )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_shifts_staff    ON staff_shifts(staff_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_shifts_open     ON staff_shifts(staff_id, end_utc)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_shifts_window   ON staff_shifts(start_utc, end_utc)")

        # ── New contact/affiliation columns (idempotent on upgraded DBs) ─────
        ensure_column("staff", "organization", "TEXT")
        ensure_column("staff", "emc",          "TEXT")
        ensure_column("staff", "email",        "TEXT")
        ensure_column("staff", "phone",        "TEXT")
# ─────────────────────────────────────────────────────────────────────────────
# CRUD-ish helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_or_create_staff(
    name: str,
    role: str = "",
    ew_number: str = "",
    *,
    organization: str = "",
    emc: str = "",
    email: str = "",
    phone: str = "",
) -> Dict[str, Any]:
    """
    Find a staff record by ew_number (preferred) or case-insensitive name.
    Upsert role/EW # if a record exists but those fields changed.
    Returns the full row as a dict.
    """
    nm = (name or "").strip()
    role = (role or "").strip()
    ew   = (ew_number or "").strip()
    org  = (organization or "").strip()
    emc_ = (emc or "").strip()
    mail = (email or "").strip()
    ph   = (phone or "").strip()

    if not nm:
        raise ValueError("name is required")

    now = _now_iso()
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row

        row = None
        if ew:
            row = c.execute("SELECT * FROM staff WHERE ew_number=? LIMIT 1", (ew,)).fetchone()
        if not row:
            row = c.execute("SELECT * FROM staff WHERE LOWER(name)=LOWER(?) LIMIT 1", (nm,)).fetchone()
        # ── Normalize for safe .get(...) usage below ─────────────────────────
        # sqlite3.Row does NOT implement .get; convert to a real dict.
        if row is None:
            row = None
        elif isinstance(row, dict):
            pass
        else:
            try:
                row = dict(row)
            except Exception:
                # As a last resort, avoid .get on non-dict rows
                row = {"id": row["id"], "name": row["name"], "role": row["role"], "ew_number": row["ew_number"]}

        if row:
            # Update only when a provided field is non-blank and different
            cur_role = row["role"] or ""
            cur_ew   = row["ew_number"] or ""
            cur_org  = row.get("organization") or ""
            cur_emc  = row.get("emc") or ""
            cur_mail = row.get("email") or ""
            cur_ph   = row.get("phone") or ""

            new_role = cur_role if not role else role
            new_ew   = cur_ew   if not ew   else ew
            new_org  = cur_org  if not org  else org
            new_emc  = cur_emc  if not emc_ else emc_
            new_mail = cur_mail if not mail else mail
            new_ph   = cur_ph   if not ph   else ph

            if (new_role, new_ew, new_org, new_emc, new_mail, new_ph) != (cur_role, cur_ew, cur_org, cur_emc, cur_mail, cur_ph):
                c.execute("""
                  UPDATE staff
                     SET role=?, ew_number=?, organization=?, emc=?, email=?, phone=?, updated_at=?
                   WHERE id=?
                """, (new_role or None, new_ew or None, new_org or None, new_emc or None, new_mail or None, new_ph or None, now, int(row["id"])))
                row = c.execute("SELECT * FROM staff WHERE id=?", (int(row["id"]),)).fetchone()
            return dict(row) if row is not None else {}

        # Insert new
        cur = c.execute("""
          INSERT INTO staff(name, role, ew_number, organization, emc, email, phone, is_active, created_at)
          VALUES(?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (nm, role or None, ew or None, org or None, emc_ or None, mail or None, ph or None, now))
        sid = cur.lastrowid
        return dict(c.execute("SELECT * FROM staff WHERE id=?", (sid,)).fetchone())

# ─────────────────────────────────────────────────────────────────────────────
# Shift helpers
# ─────────────────────────────────────────────────────────────────────────────

def toggle_shift(staff_id: int, on_off: str | bool, source: str = "", notes: str = "") -> Dict[str, Any]:
    """
    Open or close a shift for the given staff_id.
    - on_off truthy / 'on' / 'start' → open (if not already open)
    - on_off falsy / 'off' / 'stop'  → close (if open)
    Returns {'action': 'opened'|'closed'|'noop'|'updated', 'shift_id': int, ...}
    """
    s = str(on_off).strip().lower()
    want_on = (on_off is True) or (s in ("on", "start", "open", "1", "true", "yes"))

    now = _now_iso()
    with sqlite3.connect(get_db_file()) as c:
        c.row_factory = sqlite3.Row
        open_row = c.execute("""
          SELECT * FROM staff_shifts
           WHERE staff_id=? AND end_utc IS NULL
           ORDER BY start_utc DESC, id DESC
           LIMIT 1
        """, (int(staff_id),)).fetchone()

        if want_on:
            if open_row:
                # already open → optionally update notes/source
                if (notes or source):
                    new_notes = (open_row["notes"] or "")
                    if notes:
                        new_notes = (new_notes + "\n" if new_notes else "") + notes.strip()
                    c.execute("""
                      UPDATE staff_shifts
                         SET source=COALESCE(?, source),
                             notes=?,
                             updated_at=?
                       WHERE id=?
                    """, (source or None, new_notes or None, now, int(open_row["id"])))
                return {"action": "noop", "reason": "already_open", "shift_id": int(open_row["id"])}

            cur = c.execute("""
              INSERT INTO staff_shifts(staff_id, start_utc, source, notes, created_at)
              VALUES(?, ?, ?, ?, ?)
            """, (int(staff_id), now, source or None, (notes or None), now))
            return {"action": "opened", "shift_id": int(cur.lastrowid), "start_utc": now}

        # want OFF
        if not open_row:
            return {"action": "noop", "reason": "not_open"}

        c.execute("""
          UPDATE staff_shifts
             SET end_utc=?, source=COALESCE(?, source),
                 notes=COALESCE(?, notes), updated_at=?
           WHERE id=?
        """, (now, source or None, (notes or None), now, int(open_row["id"])))
        return {"action": "closed", "shift_id": int(open_row["id"]), "end_utc": now}

# ─────────────────────────────────────────────────────────────────────────────
# Queries / exports
# ─────────────────────────────────────────────────────────────────────────────

def _window_bounds(window: str) -> Tuple[Optional[datetime], datetime]:
    win = (window or "all").lower()
    hours = _WINDOWS.get(win, None)
    now = datetime.utcnow()
    if hours is None:
        return None, now
    return now - timedelta(hours=hours), now

def list_staff(window: str = "all") -> List[Dict[str, Any]]:
    """
    Return one row per staff with computed:
      - on_duty (bool), current_elapsed_s (if on), total_in_window_s
      - optionally the open shift start (shift_start_utc)
    """
    since_dt, now_dt = _window_bounds(window)
    since_iso = since_dt.isoformat() if since_dt else None
    now_iso = now_dt.isoformat()

    # 1) roster
    roster = dict_rows("SELECT * FROM staff WHERE is_active=1 ORDER BY name ASC")
    by_id = {int(r["id"]): r for r in roster}

    if not roster:
        return []

    # 2) relevant shift rows (overlapping the window)
    # overlap condition: start <= now AND (end IS NULL OR end >= since)
    params: Tuple[Any, ...]
    if since_iso:
        sql = """
          SELECT *
            FROM staff_shifts
           WHERE start_utc <= ?
             AND (end_utc IS NULL OR end_utc >= ?)
        """
        params = (now_iso, since_iso)
    else:
        sql = "SELECT * FROM staff_shifts"
        params = ()
    shifts = dict_rows(sql, params)

    # index by staff_id
    per_staff: Dict[int, List[Dict[str, Any]]] = {}
    for s in shifts:
        per_staff.setdefault(int(s["staff_id"]), []).append(s)

    rows: List[Dict[str, Any]] = []
    for sid, base in by_id.items():
        slist = per_staff.get(sid, [])
        slist.sort(key=lambda r: (r.get("start_utc") or "", r.get("id") or 0))

        on_row = next((r for r in reversed(slist) if r.get("end_utc") in (None, "")), None)
        on_duty = on_row is not None
        current_elapsed = 0
        open_start_iso = None
        if on_row:
            start_dt = _parse_iso(on_row.get("start_utc"))
            if start_dt:
                current_elapsed = max(0, int((now_dt - start_dt).total_seconds()))
                open_start_iso = on_row.get("start_utc") or ""

        # Total time overlapped with window
        total_s = 0
        for r in slist:
            st = _parse_iso(r.get("start_utc"))
            en = _parse_iso(r.get("end_utc")) or now_dt
            if not st:
                continue
            lo = st if not since_dt else max(st, since_dt)
            hi = min(en, now_dt)
            dt = (hi - lo).total_seconds()
            if dt > 0:
                total_s += int(dt)

        rows.append({
            "id": sid,
            "name": base.get("name", ""),
            "role": base.get("role", ""),
            "ew_number": base.get("ew_number", ""),
            "organization": base.get("organization", ""),
            "emc": base.get("emc", ""),
            "email": base.get("email", ""),
            "phone": base.get("phone", ""),
            "on_duty": bool(on_duty),
            "shift_start_utc": open_start_iso or "",
            "current_elapsed_s": current_elapsed,
            "current_elapsed_hhmm": _fmt_hhmm_from_seconds(current_elapsed),
            "total_in_window_s": total_s,
            "total_in_window_hhmm": _fmt_hhmm_from_seconds(total_s),
        })

    return rows

def export_211(window: str = "all") -> Tuple[List[str], List[List[Any]]]:
    """
    Produce an ICS-211-ish roster view from staff + current/open shift state.
    Returns (headers, rows) ready for CSV writing.
    """
    rows = list_staff(window)
    headers = [
        "Name", "Role", "EW Number",
        "On Duty", "Shift Start (UTC)",
        "Current Elapsed (H:MM)", "Total in Window (H:MM)"
    ]
    out: List[List[Any]] = []
    for r in rows:
        out.append([
            r["name"], r["role"], r["ew_number"],
            "Yes" if r["on_duty"] else "No",
            r["shift_start_utc"],
            r["current_elapsed_hhmm"],
            r["total_in_window_hhmm"],
        ])
    return headers, out

def export_214(window: str = "all") -> Tuple[List[str], List[List[Any]]]:
    """
    Produce an ICS-214-style activity log using shift start/stop events as activities.
    Returns (headers, rows) ready for CSV writing.
    """
    since_dt, now_dt = _window_bounds(window)
    since_iso = since_dt.isoformat() if since_dt else None
    now_iso = now_dt.isoformat()

    # Build a name/role map
    staff_map = {int(r["id"]): r for r in dict_rows("SELECT id, name, role FROM staff")}
    # Fetch shifts overlapping window (for events)
    params: Tuple[Any, ...]
    if since_iso:
        sql = """
          SELECT *
            FROM staff_shifts
           WHERE start_utc <= ?
             AND (end_utc IS NULL OR end_utc >= ?)
        """
        params = (now_iso, since_iso)
    else:
        sql = "SELECT * FROM staff_shifts"
        params = ()
    shifts = dict_rows(sql, params)

    events: List[Tuple[datetime, List[Any]]] = []
    for s in shifts:
        sid = int(s["staff_id"])
        who = staff_map.get(sid, {})
        nm  = who.get("name", "")
        rl  = who.get("role", "")

        st = _parse_iso(s.get("start_utc"))
        en = _parse_iso(s.get("end_utc"))

        # Start event (if within window or window is 'all')
        if st and (not since_dt or st >= since_dt):
            events.append((
                st,
                [st.date().isoformat(), st.strftime("%H:%M"), "Went ON duty", nm, rl, s.get("source",""), s.get("notes","")]
            ))
        # End event (if present and within window)
        if en and (not since_dt or en >= since_dt):
            events.append((
                en,
                [en.date().isoformat(), en.strftime("%H:%M"), "Went OFF duty", nm, rl, s.get("source",""), s.get("notes","")]
            ))

    events.sort(key=lambda t: t[0])
    headers = ["Date", "Time (UTC)", "Activity", "Name", "Role", "Source", "Notes"]
    out = [row for _, row in events]
    return headers, out
