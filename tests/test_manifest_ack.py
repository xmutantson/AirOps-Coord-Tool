"""Offline tests: temp SQLite plus route AST extraction; never import app.py."""
import ast
from datetime import datetime
import importlib.util
import os
from pathlib import Path
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import patch

from flask import Flask, abort, jsonify, request

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("manifest_ack_under_test", ROOT / "modules/services/manifest_ack.py")
ack = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ack)


class ManifestAcknowledgementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "isolated.sqlite")
        fields = [key for key in ack.MATERIAL_FIELDS if key != "id"]
        fields += ["created_at", "pilot_ack_name", "pilot_ack_method", "pilot_ack_signature_b64",
                   "pilot_ack_signed_at", "pilot_ack_manifest_hash", "manifest_pdf_path"]
        with self.connect() as c:
            c.execute("CREATE TABLE queued_flights (id INTEGER PRIMARY KEY, consumed INTEGER DEFAULT 0, "
                      + ", ".join(f"{key} TEXT" for key in fields) + ")")
            cargo = ("id INTEGER PRIMARY KEY, session_id TEXT, category_id INTEGER, sanitized_name TEXT, "
                     "weight_per_unit REAL, quantity INTEGER, total_weight REAL, direction TEXT, "
                     "timestamp TEXT, origin TEXT")
            c.execute("CREATE TABLE flight_cargo (queued_id INTEGER, flight_id INTEGER, " + cargo + ")")
            c.execute("CREATE TABLE inventory_entries (pending INTEGER, " + cargo + ")")
            c.execute("CREATE TABLE inventory_categories (id INTEGER PRIMARY KEY, display_name TEXT)")
            c.execute("INSERT INTO inventory_categories VALUES (1, 'Food')")
            flight_fields = [key for key in fields if key not in ("manifest_id", "travel_time")]
            flight_fields += ["takeoff_time", "eta", "flight_code"]
            c.execute("CREATE TABLE flights (id INTEGER PRIMARY KEY, is_ramp_entry INTEGER, cargo_weight_real REAL, "
                      + ", ".join(f"{key} TEXT" for key in flight_fields) + ")")
            c.execute("""INSERT INTO queued_flights
                (id, direction, pilot_name, pax_count, tail_number, airfield_takeoff, airfield_landing,
                 travel_time, cargo_type, cargo_weight, remarks, manifest_id, created_at)
                VALUES (1, 'outbound', 'Pilot', '2', 'N123', 'KAAA', 'KBBB', '0030',
                        'Food', '10', 'Manifest: Rice 5 lbx2;', 'session-1', '2026-10-02T10:00:00')""")
            self.add_cargo(c, snapshot=True)
            self.add_cargo(c, snapshot=False)
        self.app = Flask(__name__)
        self.app.secret_key = "isolated-test"
        self.env = {
            "sqlite3": types.SimpleNamespace(connect=self.connect, Row=sqlite3.Row), "DB_FILE": self.db, "datetime": datetime,
            "request": request, "jsonify": jsonify, "abort": abort, "os": os,
            "current_app": self.app, "dict_rows": self.dict_rows,
            "ensure_column": lambda *args: None,
            "flash": lambda *args: None,
            "redirect": lambda target: ("redirect", target),
            "url_for": lambda endpoint, **kwargs: "/" + endpoint,
            "now_hhmm": lambda: "1200", "_add_hhmm": lambda *args: "1230",
            "_compute_fcode_from_form": lambda *args: None,
            "try_satisfy_ramp_request": lambda *args: None,
            "_plane_pin_clear_by_flight_ref": lambda *args: None,
            "norm_weight": lambda value, unit: value,
            "clean_mid": lambda value: str(value or "").strip(),
        }
        for name in ("acknowledgement_is_current", "has_unapplied_cargo", "manifest_fingerprint",
                     "invalidate_stale_acknowledgement", "queue_manifest_id"):
            self.env[name] = getattr(ack, name)
        tree = ast.parse((ROOT / "modules/routes/ramp.py").read_text(encoding="utf-8"))
        names = {"ramp_pilot_ack", "send_queued_flight", "edit_queued_flight", "_queue_manifest_pdf", "api_send_now"}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        for node in nodes:
            node.decorator_list = []
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "ramp_routes_ast", "exec"), self.env)

    def connect(self, database=None, **kwargs):
        c = sqlite3.connect(database or self.db, **kwargs)
        self.addCleanup(c.close)
        c.row_factory = sqlite3.Row
        return c

    def dict_rows(self, sql, params=()):
        with self.connect() as c:
            return [dict(row) for row in c.execute(sql, params)]

    def draft(self, c):
        return dict(c.execute("SELECT * FROM queued_flights WHERE id=1").fetchone())

    def add_cargo(self, c, snapshot=False, direction="out", quantity=2,
                  timestamp="2026-10-02T10:01:00", pending=0, origin="Warehouse A"):
        table = "flight_cargo" if snapshot else "inventory_entries"
        prefix = "queued_id" if snapshot else "pending"
        c.execute(f"""INSERT INTO {table}
            ({prefix}, session_id, category_id, sanitized_name, weight_per_unit, quantity,
             total_weight, direction, timestamp, origin) VALUES (?, 'session-1', 1, 'Rice', 5, ?, ?, ?, ?, ?)""",
                  (1 if snapshot else pending, quantity, quantity * 5, direction, timestamp, origin))

    def sign(self, build=False):
        # Simulate reviewing the current saved revision. Stale-client tests post
        # their captured token (or omit it) directly instead.
        with self.connect() as c:
            row = c.execute('SELECT * FROM queued_flights WHERE id=1').fetchone()
            revision = ack.manifest_fingerprint(c, dict(row)) if row else ''
        def submit():
            with self.app.test_request_context(json={"typed_name": "Pilot", "expected_revision": revision,
                                                     "build_pdf": "yes" if build else "no"}):
                return self.env["ramp_pilot_ack"](1)
        if build:
            return submit()
        pdf = Path(self.tmp.name) / 'fixture-signed.pdf'
        fake = types.ModuleType('modules.utils.manifest')
        def render(*args):
            pdf.write_bytes(b'OFFLINE SIGNED ARTIFACT FIXTURE')
            return pdf.read_bytes(), str(pdf)
        fake.build_manifest_pdf = render
        with patch.dict('sys.modules', {'modules.utils.manifest': fake}):
            return submit()

    def fund_stock(self):
        with self.connect() as c:
            c.execute("""INSERT INTO inventory_entries (category_id,sanitized_name,weight_per_unit,
                quantity,total_weight,direction,timestamp,origin,pending)
                VALUES (1,'Rice',5,10,50,'in','2026-10-02T09:00:00','Warehouse A',0)""")

    def send(self, form=None):
        with self.app.test_request_context(method="POST", data=form or {},
                                           headers={"X-Requested-With": "XMLHttpRequest"}):
            return self.env["send_queued_flight"](1)

    def test_legacy_acknowledgement_fails_closed(self):
        with self.connect() as c:
            c.execute("UPDATE queued_flights SET pilot_ack_signed_at='old'")
            self.assertFalse(ack.acknowledgement_is_current(c, self.draft(c)))
        response, status = self.send()
        self.assertEqual(status, 400)
        self.assertEqual(response.get_json()["error"], "pilot_ack_required")
        self.assertEqual(self.dict_rows("SELECT COUNT(*) AS n FROM flights")[0]["n"], 0)

    def test_material_headers_cargo_and_source_require_renewal(self):
        self.assertTrue(self.sign().get_json()["ok"])
        with self.connect() as c:
            draft = self.draft(c)
            self.assertTrue(ack.acknowledgement_is_current(c, draft))
            for field in ("tail_number", "pilot_name", "pax_count", "airfield_landing", "cargo_weight", "remarks"):
                changed = dict(draft, **{field: "changed"})
                self.assertFalse(ack.acknowledgement_is_current(c, changed), field)
            c.execute("UPDATE flight_cargo SET origin='Warehouse B'")
            self.assertFalse(ack.acknowledgement_is_current(c, draft))

    def test_pending_edit_even_at_snapshot_timestamp_blocks_send(self):
        self.sign()
        with self.connect() as c:
            self.add_cargo(c, pending=1)
        response, status = self.send()
        self.assertEqual(status, 400)
        self.assertEqual(response.get_json()["error"], "pilot_ack_required")
        self.assertIsNone(self.dict_rows("SELECT pilot_ack_signed_at FROM queued_flights")[0]["pilot_ack_signed_at"])
        self.assertEqual(self.dict_rows("SELECT COUNT(*) AS n FROM flights")[0]["n"], 0)

    def test_sign_rejects_unsaved_cargo_and_missing_draft(self):
        with self.connect() as c:
            self.add_cargo(c, timestamp="2026-10-02T10:02:00")
        response, status = self.sign()
        self.assertEqual(status, 409)
        self.assertEqual(response.get_json()["error"], "manifest_changes_pending")
        with self.connect() as c:
            c.execute("DELETE FROM queued_flights")
        self.assertEqual(self.sign()[1], 404)

    def test_empty_saved_manifest_with_balanced_ledger_can_be_signed(self):
        with self.connect() as c:
            c.execute("DELETE FROM flight_cargo")
            self.add_cargo(c, direction="in", timestamp="2026-10-02T10:02:00")
            self.assertFalse(ack.has_unapplied_cargo(c, self.draft(c)))
        self.assertTrue(self.sign().get_json()["ok"])

    def test_dispatch_checks_under_write_lock_and_ignores_posted_manifest(self):
        self.fund_stock()
        self.sign()
        original = self.env["acknowledgement_is_current"]
        checked = []
        def validate(c, draft):
            checked.append(c.in_transaction)
            with self.connect(timeout=0) as competing:
                with self.assertRaises(sqlite3.OperationalError):
                    competing.execute("UPDATE queued_flights SET pax_count='99' WHERE id=1")
            return original(c, draft)
        self.env["acknowledgement_is_current"] = validate
        response = self.send({"manifest_id": "unrelated-session"})
        self.assertEqual(response.get_json()["status"], "sent")
        self.assertEqual(checked, [True])
        self.assertEqual(self.dict_rows("SELECT pax_count, cargo_weight FROM flights"),
                         [{"pax_count": "2", "cargo_weight": "10 lbs"}])
        self.assertEqual(self.dict_rows("SELECT quantity FROM flight_cargo"), [{"quantity": 2}])
        self.assertEqual(self.dict_rows("SELECT * FROM queued_flights"), [])

    def test_edit_clears_signature_and_cannot_edit_consumed_draft(self):
        self.sign()
        form = {"direction": "outbound", "pilot_name": "Pilot", "pax_count": "3", "tail_number": "N123",
                "origin": "KAAA", "destination": "KBBB", "travel_time": "0030", "cargo_weight": "10"}
        with self.app.test_request_context(method="POST", data=form):
            self.env["edit_queued_flight"](1)
        self.assertIsNone(self.dict_rows("SELECT pilot_ack_signed_at FROM queued_flights")[0]["pilot_ack_signed_at"])
        with self.connect() as c:
            c.execute("UPDATE queued_flights SET consumed=1")
        form["pax_count"] = "7"
        with self.app.test_request_context(method="POST", data=form):
            self.env["edit_queued_flight"](1)
        self.assertEqual(self.dict_rows("SELECT pax_count FROM queued_flights")[0]["pax_count"], "3")

    def test_duplicate_flight_code_cannot_merge_signed_manifests(self):
        self.fund_stock()
        self.sign()
        self.env["_compute_fcode_from_form"] = lambda *args: "EXISTING"
        with self.connect() as c:
            c.execute("INSERT INTO flights (flight_code, tail_number) VALUES ('EXISTING', 'N999')")
        response, status = self.send()
        self.assertEqual(status, 409)
        self.assertEqual(response.get_json()["error"], "flight_code_conflict")
        self.assertEqual(self.dict_rows("SELECT consumed FROM queued_flights"), [{"consumed": 0}])
        self.assertEqual(self.dict_rows("SELECT tail_number FROM flights"), [{"tail_number": "N999"}])
        self.assertEqual(self.dict_rows("SELECT queued_id, flight_id FROM flight_cargo"),
                         [{"queued_id": 1, "flight_id": None}])

    def test_stale_editor_read_cannot_recreate_cargo_after_dispatch(self):
        original = self.env["dict_rows"]
        def concurrent_delete(sql, params=()):
            rows = original(sql, params)
            with self.connect() as c:
                c.execute("DELETE FROM queued_flights WHERE id=1")
                c.execute("DELETE FROM flight_cargo WHERE queued_id=1")
            return rows
        self.env["dict_rows"] = concurrent_delete
        with self.app.test_request_context(method="POST", data={"direction": "outbound", "tail_number": "N123"}):
            self.env["edit_queued_flight"](1)
        self.assertEqual(self.dict_rows("SELECT * FROM flight_cargo"), [])

    def test_signed_pdf_is_preserved_and_transferred_to_flight(self):
        self.fund_stock()
        pdf = Path(self.tmp.name) / "signed.pdf"
        pdf.write_bytes(b"original signed snapshot")
        fake = types.ModuleType("modules.utils.manifest")
        calls = []
        def build(app, draft):
            calls.append(draft["pilot_ack_name"])
            # Rendering occurs while edits are locked out.
            with self.connect(timeout=0) as competing:
                with self.assertRaises(sqlite3.OperationalError):
                    competing.execute("UPDATE queued_flights SET pax_count='99'")
            return pdf.read_bytes(), str(pdf)
        fake.build_manifest_pdf = build
        with patch.dict("sys.modules", {"modules.utils.manifest": fake}):
            self.assertTrue(self.sign(build=True).get_json()["ok"])
            with self.app.test_request_context():
                self.assertEqual(self.env["_queue_manifest_pdf"](1), str(pdf))
            self.assertEqual(calls, ["Pilot"])
            self.send()
        flight = self.dict_rows("SELECT manifest_pdf_path, pilot_ack_manifest_hash FROM flights")[0]
        self.assertEqual(flight["manifest_pdf_path"], str(pdf))
        self.assertTrue(flight["pilot_ack_manifest_hash"])
        self.assertEqual(pdf.read_bytes(), b"original signed snapshot")

    def test_missing_signed_pdf_requires_renewal_instead_of_regeneration(self):
        self.sign()
        (Path(self.tmp.name) / "fixture-signed.pdf").unlink()
        with self.app.test_request_context():
            from werkzeug.exceptions import Conflict
            with self.assertRaises(Conflict):
                self.env["_queue_manifest_pdf"](1)

    def test_pdf_failure_does_not_save_acknowledgement(self):
        fake = types.ModuleType("modules.utils.manifest")
        def fail(*args):
            raise RuntimeError("controlled render failure")
        fake.build_manifest_pdf = fail
        with patch.dict("sys.modules", {"modules.utils.manifest": fake}), self.assertLogs(level="ERROR"):
            response, status = self.sign(build=True)
        self.assertEqual(status, 500)
        self.assertEqual(response.get_json()["error"], "build_failed")
        self.assertIsNone(self.dict_rows("SELECT pilot_ack_signed_at FROM queued_flights")[0]["pilot_ack_signed_at"])


if __name__ == "__main__":
    unittest.main()
