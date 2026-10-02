"""Inventory invariants against disposable SQLite files; never import app.py.

Route tests execute the actual function AST with inert request/response adapters.
They exercise transaction boundaries and SQL, without Flask startup, radios, jobs,
printers, or network services. Run: python -m unittest discover -s tests -p test_inventory_integrity.py
"""
import ast
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import logging
from pathlib import Path
import sqlite3
import sys
import tempfile
from threading import Barrier
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from modules.services import inventory as inv


def extracted(relative_path, name, namespace):
    """Compile only the requested real function, excluding module startup."""
    path = ROOT / relative_path
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
    return namespace[name]


def jsonify(*args, **kwargs):
    return dict(args[0]) if args else kwargs


class ClosingConnection(sqlite3.Connection):
    """Retain real transaction semantics and release Windows file handles."""
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


class InventoryFixture(unittest.TestCase):
    def connect(self, path=None):
        return sqlite3.connect(path or self.db, factory=ClosingConnection)

    @property
    def sqlite_api(self):
        return SimpleNamespace(connect=self.connect, Row=sqlite3.Row)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "inventory.sqlite")
        with self.connect() as c:
            c.executescript("""
                CREATE TABLE inventory_entries (
                    id INTEGER PRIMARY KEY, category_id INTEGER, raw_name TEXT,
                    sanitized_name TEXT, weight_per_unit REAL, quantity INTEGER,
                    total_weight REAL, direction TEXT, timestamp TEXT,
                    pending INTEGER DEFAULT 0, pending_ts TEXT, session_id TEXT,
                    source TEXT, origin TEXT);
                CREATE TABLE flight_cargo (
                    id INTEGER PRIMARY KEY, category_id INTEGER, sanitized_name TEXT,
                    weight_per_unit REAL, quantity INTEGER, direction TEXT,
                    timestamp TEXT, origin TEXT, session_id TEXT,
                    queued_id INTEGER, flight_id INTEGER);
                CREATE TABLE inventory_barcodes (
                    barcode TEXT PRIMARY KEY, last_seen TEXT, seen_count INTEGER);
                INSERT INTO inventory_barcodes VALUES ('AOT-TEST', NULL, 0);
            """)

    def seed(self, qty, *, origin="A", direction="in", pending=0,
             session=None, timestamp="2000-01-01T00:00:00", category=1):
        with self.connect() as c:
            c.execute("""INSERT INTO inventory_entries
                (category_id,raw_name,sanitized_name,weight_per_unit,quantity,
                 total_weight,direction,timestamp,pending,session_id,source,origin)
                VALUES (?, 'water','water',10,?,?, ?,?,?,?,'fixture',?)""",
                (category, qty, qty * 10, direction, timestamp, pending, session, origin))

    def snapshot(self, qty, *, origin="A", direction="out", session="m", queued_id=7):
        with self.connect() as c:
            c.execute("""INSERT INTO flight_cargo
                (category_id,sanitized_name,weight_per_unit,quantity,direction,
                 timestamp,origin,session_id,queued_id)
                VALUES (1,'water',10,?,?,'2001-01-01T00:00:00',?,?,?)""",
                (qty, direction, origin, session, queued_id))

    def reserve(self, session="m", qty=1, origin=None):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            return inv.adjust_pending(c, session_id=session, category_id=1,
                                      name="water", weight=10, direction="out",
                                      delta=qty, origin=origin)

    def balances(self):
        with self.connect() as c:
            return inv.available_by_origin(c, 1, "water", 10)

    def entries(self):
        with self.connect() as c:
            return c.execute("SELECT * FROM inventory_entries ORDER BY id").fetchall()

    def chips(self, queued_id=None):
        with self.connect() as c:
            return inv.manifest_rows(c, "m", queued_id=queued_id)

    def remove(self, qty=1, origin=None, queued_id=None):
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            return inv.remove_manifest_item(c, session_id="m", category_id=1,
                name="water", weight=10, qty=qty, origin=origin, queued_id=queued_id)


class InventoryIntegrityTests(InventoryFixture):
    def test_two_manifests_compete_for_last_unit(self):
        self.seed(1)
        barrier = Barrier(2)
        def compete(mid):
            barrier.wait(timeout=5)
            try:
                self.reserve(session=mid)
                return "reserved"
            except inv.InventoryConflict as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(compete, ("alpha", "bravo")))
        self.assertCountEqual(results, ["reserved", "out_of_stock"])
        self.assertEqual(self.balances(), {"A": 0})
        self.assertEqual(len(self.entries()), 2)

    def test_pending_receipt_is_not_available_stock(self):
        self.seed(9, pending=1, session="arrival")
        before = self.entries()
        with self.assertRaises(inv.InventoryConflict):
            self.reserve()
        self.assertEqual(self.entries(), before)
        self.assertEqual(self.balances(), {"A": 0})

    def test_committed_manual_shipments_respect_other_manifest_reservations(self):
        self.seed(2)
        self.reserve("other", qty=2)
        before = self.entries()
        with self.assertRaises(inv.InventoryConflict):
            with self.connect() as c:
                c.execute("BEGIN IMMEDIATE")
                inv.insert_entry(c, category_id=1, name="water", weight=10,
                                 qty=1, direction="out", pending=False)
        self.assertEqual(self.entries(), before)

    def test_ambiguous_source_requires_choice_without_writing(self):
        self.seed(2, origin="A")
        self.seed(3, origin="B")
        before = self.entries()
        with self.assertRaises(inv.InventoryConflict) as cm:
            self.reserve()
        self.assertEqual(cm.exception.code, "origin_required")
        self.assertEqual(cm.exception.origins, ["A", "B"])
        self.assertEqual(self.entries(), before)

    def test_explicit_sources_stay_distinct_during_allocation_and_removal(self):
        self.seed(3, origin="A")
        self.seed(3, origin="B")
        self.reserve(qty=2, origin="A")
        self.reserve(qty=1, origin="B")
        with self.assertRaises(inv.InventoryConflict) as cm:
            self.remove()
        self.assertEqual(cm.exception.code, "origin_required")
        self.remove(qty=1, origin="A")
        self.assertEqual({r["origin"]: r["qty"] for r in self.chips()}, {"A": 1, "B": 1})
        self.assertEqual(self.balances(), {"A": 2, "B": 2})

    def test_explicit_empty_source_is_not_ambiguous(self):
        self.seed(1, origin="")
        self.seed(2, origin="B")
        self.assertEqual(self.reserve(origin=""), (1, ""))
        self.assertEqual(self.balances(), {"": 0, "B": 2})

    def test_snapshot_counted_once_with_later_ledger_deltas(self):
        self.seed(10)
        self.seed(4, direction="out", session="m", timestamp="2001-01-01T00:00:00")
        self.snapshot(4)
        self.reserve(qty=2, origin="A")
        self.assertEqual(self.chips(7)[0]["qty"], 6)
        self.assertEqual(self.chips(7)[0]["total"], 60)
        self.assertEqual(self.balances(), {"A": 4})

    def test_removal_is_capped_and_repeated_remove_never_creates_stock(self):
        self.seed(10)
        self.seed(4, direction="out", session="m", timestamp="2001-01-01T00:00:00")
        self.snapshot(4)
        self.reserve(qty=2, origin="A")
        result = self.remove(qty=100, origin="A", queued_id=7)
        self.assertEqual((result["applied"], result["effective_qty"]), (6, 0))
        self.assertEqual(self.chips(7), [])
        self.assertEqual(self.balances(), {"A": 10})
        before = self.entries()
        self.assertEqual(self.remove(qty=100, origin="A", queued_id=7)["applied"], 0)
        self.assertEqual(self.entries(), before)

    def test_failed_receipt_reversal_rolls_back_pending_removal(self):
        # All committed receipt stock has been reserved elsewhere. Removing the
        # receipt's pending unit first must roll back when its reversal fails.
        self.seed(3, session="m", timestamp="2001-01-01T00:00:00")
        self.snapshot(3, direction="in")
        self.seed(1, pending=1, session="m", timestamp="2002-01-01T00:00:00")
        self.reserve(session="other", qty=3)
        before = self.entries()
        with self.assertRaises(inv.InventoryConflict):
            self.remove(qty=2, origin="A", queued_id=7)
        self.assertEqual(self.entries(), before)
        self.assertEqual(self.chips(7)[0]["qty"], 4)

    def test_real_common_wrapper_serializes_competing_reservations(self):
        self.seed(1)
        wrapper = extracted("modules/utils/common.py", "upsert_scan_pending",
                            {"sqlite3": self.sqlite_api, "get_db_file": lambda: self.db})
        barrier = Barrier(2)
        def compete(mid):
            barrier.wait(timeout=5)
            try:
                wrapper(session_id=mid, category_id=1, sanitized_name="water",
                        weight_per_unit=10, direction="out", delta_qty=1)
                return "reserved"
            except inv.InventoryConflict as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(list(pool.map(compete, ("a", "b"))),
                                  ["reserved", "out_of_stock"])

    def test_commit_guard_rejects_legacy_overreservation_without_promoting_rows(self):
        self.seed(1)
        self.seed(1, direction="out", pending=1, session="m")
        self.seed(1, direction="out", pending=1, session="other")
        before = self.entries()
        with self.assertRaises(inv.InventoryConflict):
            with self.connect() as c:
                c.execute("BEGIN IMMEDIATE")
                inv.validate_session_commit(c, "m")
                c.execute("UPDATE inventory_entries SET pending=0 WHERE session_id='m'")
        self.assertEqual(self.entries(), before)

    def test_empty_saved_snapshot_can_be_rebuilt_without_resurrecting_old_cargo(self):
        self.seed(5)
        self.seed(2, direction="out", session="m", timestamp="2001-01-01T00:00:00")
        self.snapshot(2)
        self.remove(qty=2, origin="A", queued_id=7)
        # A save of an empty manifest removes all snapshot rows. Its old ledger
        # and reversal must continue to cancel when a later edit starts again.
        with self.connect() as c:
            c.execute("DELETE FROM flight_cargo WHERE queued_id=7")
        self.assertEqual(self.chips(7), [])
        self.reserve(qty=1, origin="A")
        self.assertEqual(self.chips(7)[0]["qty"], 1)
        self.assertEqual(self.balances(), {"A": 4})

    def test_real_aggregate_wrapper_uses_snapshot_and_source_identity(self):
        self.seed(5, origin="A")
        self.seed(5, origin="B")
        self.seed(2, direction="out", session="m", timestamp="2001-01-01T00:00:00")
        self.snapshot(2)
        self.reserve(qty=1, origin="B")
        wrapper = extracted("modules/utils/common.py", "aggregate_manifest_net",
                            {"sqlite3": self.sqlite_api, "get_db_file": lambda: self.db})
        rows = wrapper("m", queued_id=7)
        self.assertEqual({r["origin"]: r["qty"] for r in rows}, {"A": 2, "B": 1})


class InventoryRouteTests(InventoryFixture):
    def route(self, path, name, data, *, form=False):
        item = dict(category_id=1, sanitized_name="water", raw_name="water",
                    weight_per_unit=10.0, barcode="AOT-TEST")
        request = SimpleNamespace(get_json=lambda **_: None if form else data,
            form=data if form else {}, cookies={}, headers={"X-Requested-With": "XMLHttpRequest"},
            method="POST")
        namespace = dict(sqlite3=self.sqlite_api, DB_FILE=self.db, request=request,
            jsonify=jsonify, datetime=datetime, InventoryConflict=inv.InventoryConflict,
            insert_entry=inv.insert_entry, clean_mid=lambda mid: mid,
            touch_pending_session=lambda *_: None, cleanup_pending=lambda: None,
            sanitize_name=lambda name: name.lower().strip(), session={},
            is_aot_barcode=lambda code: code == "AOT-TEST",
            lookup_barcode=lambda _: item, _resolve_mapping_for=lambda _: item,
            _ensure_barcode_schema=lambda: None, publish_inventory_event=lambda: None,
            get_preference=lambda _: "no", logger=logging.getLogger(__name__),
            flash=lambda *_: None, redirect=lambda x: x, url_for=lambda x: x)
        common = ModuleType("modules.utils.common")
        common.clean_mid = namespace["clean_mid"]
        common.touch_pending_session = namespace["touch_pending_session"]
        function = extracted(path, name, namespace)
        with patch.dict(sys.modules, {"modules.utils.common": common}):
            return function("m") if name in (
                "api_manifest_scan", "api_manifest_nudge", "_api_manifest_delete_key_impl"
            ) else function()

    def scan(self, **data):
        return self.route("modules/routes/api.py", "api_manifest_scan",
                          dict(barcode="AOT-TEST", **data))

    def test_scan_route_returns_source_conflict_without_write(self):
        self.seed(1, origin="A")
        self.seed(2, origin="B")
        before = self.entries()
        body, status = self.scan()
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "origin_required")
        self.assertEqual(self.entries(), before)

    def test_scan_response_quantity_is_for_selected_source(self):
        self.seed(5, origin="A")
        self.seed(5, origin="B")
        self.assertEqual(self.scan(qty=3, origin="A")["qty"], 3)
        result = self.scan(qty=1, origin="B")
        self.assertEqual((result["qty"], result["origin"]), (1, "B"))
        result = self.scan(mode="remove", origin="B")
        self.assertEqual(result["qty"], 0)
        self.assertEqual({r["origin"]: r["qty"] for r in self.chips()}, {"A": 3})

    def test_scan_edit_remove_is_capped_against_snapshot(self):
        self.seed(3)
        self.seed(2, direction="out", session="m", timestamp="2001-01-01T00:00:00")
        self.snapshot(2)
        self.assertEqual(self.scan(mode="remove", qty=99, draft_id=7, origin="A")["qty"], 0)
        before = self.entries()
        self.assertEqual(self.scan(mode="remove", qty=99, draft_id=7, origin="A")["qty"], 0)
        self.assertEqual(self.entries(), before)
        self.assertEqual(self.balances(), {"A": 3})

    def test_nudge_ambiguous_source_and_explicit_removal(self):
        self.seed(2, origin="A")
        self.seed(2, origin="B")
        self.reserve(origin="A")
        self.reserve(origin="B")
        data = dict(name="water", weight_per_unit=10, category_id=1, qty=99)
        before = self.entries()
        body, status = self.route("modules/routes/ramp.py", "api_manifest_nudge", data)
        self.assertEqual((status, body["error"]), (409, "origin_required"))
        self.assertEqual(self.entries(), before)
        result = self.route("modules/routes/ramp.py", "api_manifest_nudge", dict(data, origin="B"))
        self.assertEqual((result["applied"], result["remaining"]), (1, 0))
        self.assertEqual(self.balances(), {"A": 1, "B": 2})

    def test_all_manual_entry_routes_reject_stock_reserved_elsewhere(self):
        self.seed(1)
        self.reserve(session="other")
        routes = [
            ("modules/routes_inventory/overview.py", "inventory_advance_line", True,
             dict(action="add", manifest_id="m", direction="outbound", category="1",
                  item="water", size="10", qty="1")),
            ("modules/routes_inventory/detail.py", "inventory_detail", True,
             dict(category="1", name="water", weight="10", qty="1", direction="out")),
            ("modules/routes_inventory/barcodes.py", "api_scan_barcode", False,
             dict(barcode="AOT-TEST", qty=1, direction="out", commit_now=True)),
        ]
        before = self.entries()
        for path, name, form, data in routes:
            with self.subTest(route=name):
                body, status = self.route(path, name, data, form=form)
                self.assertEqual((status, body["error"]), (409, "out_of_stock"))
                self.assertEqual(self.entries(), before)

    def test_manual_and_barcode_paths_preserve_explicit_empty_origin(self):
        self.seed(3, origin="")
        self.seed(4, origin="B")
        manual = dict(action="add", manifest_id="m", direction="outbound", category="1",
                      item="water", size="10", qty="1", origin="")
        result = self.route("modules/routes_inventory/overview.py", "inventory_advance_line",
                            manual, form=True)
        self.assertTrue(result["success"])
        result = self.route("modules/routes_inventory/barcodes.py", "api_scan_barcode",
            dict(barcode="AOT-TEST", qty=1, direction="out", commit_now=True, origin=""))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self.balances(), {"": 1, "B": 4})

    def test_legacy_snapshot_delete_preserves_other_source_pending_and_committed_rows(self):
        self.seed(10, origin="A")
        self.seed(10, origin="B")
        self.seed(2, origin="A", direction="out", session="m", timestamp="2001-01-01T00:00:00")
        self.seed(3, origin="B", direction="out", session="m", timestamp="2001-01-01T00:00:00")
        self.snapshot(2, origin="A")
        self.snapshot(3, origin="B")
        self.reserve(qty=1, origin="A")
        self.reserve(qty=1, origin="B")
        with self.connect() as c:
            source_b_before = c.execute("SELECT * FROM inventory_entries WHERE origin='B'").fetchall()
        function = extracted("modules/routes/ramp.py", "delete_flight_cargo",
            dict(sqlite3=self.sqlite_api, DB_FILE=self.db, datetime=datetime,
                 clean_mid=lambda mid: mid, jsonify=jsonify,
                 request=SimpleNamespace(form={"manifest_id": "m"})))
        self.assertEqual(function(1)["status"], "ok")
        with self.connect() as c:
            source_b_after = c.execute("SELECT * FROM inventory_entries WHERE origin='B'").fetchall()
            snapshots = c.execute("SELECT origin,quantity FROM flight_cargo").fetchall()
        self.assertEqual(source_b_after, source_b_before)
        self.assertEqual(snapshots, [("B", 3)])
        self.assertEqual(self.balances(), {"A": 10, "B": 6})

    def test_delete_key_removes_selected_source_pending_and_baseline_only(self):
        for origin, committed in (("A", 2), ("B", 3)):
            self.seed(10, origin=origin)
            self.seed(committed, origin=origin, direction="out", session="m",
                      timestamp="2001-01-01T00:00:00")
            self.snapshot(committed, origin=origin)
            self.reserve(qty=1, origin=origin)
        with self.connect() as c:
            other_source_before = c.execute(
                "SELECT * FROM inventory_entries WHERE origin='B' ORDER BY id").fetchall()
        result = self.route("modules/routes/ramp.py", "_api_manifest_delete_key_impl",
            dict(sanitized_name="water", weight_per_unit=10, category_id=1,
                 origin="A", draft_id=7, qty=999))
        self.assertTrue(result["ok"])
        self.assertEqual((result["qty"], result["origin"]), (3, "A"))
        self.assertEqual({r["origin"]: r["qty"] for r in self.chips(7)}, {"B": 4})
        self.assertEqual(self.balances(), {"A": 10, "B": 6})
        with self.connect() as c:
            other_source_after = c.execute(
                "SELECT * FROM inventory_entries WHERE origin='B' ORDER BY id").fetchall()
        self.assertEqual(other_source_after, other_source_before)

    def test_repeated_delete_key_does_not_credit_stock_twice(self):
        self.seed(10)
        self.seed(2, direction="out", session="m", timestamp="2001-01-01T00:00:00")
        self.snapshot(2)
        self.reserve(qty=3, origin="A")
        payload = dict(sanitized_name="water", weight_per_unit=10, category_id=1,
                       origin="A", draft_id=7)
        result = self.route("modules/routes/ramp.py", "_api_manifest_delete_key_impl", payload)
        self.assertEqual(result["qty"], 5)
        self.assertEqual(self.chips(7), [])
        self.assertEqual(self.balances(), {"A": 10})
        after_first_delete = self.entries()
        result = self.route("modules/routes/ramp.py", "_api_manifest_delete_key_impl", payload)
        self.assertTrue(result["ok"])
        self.assertEqual(result["qty"], 0)
        self.assertEqual(self.entries(), after_first_delete)
        self.assertEqual(self.balances(), {"A": 10})


if __name__ == "__main__":
    unittest.main()
