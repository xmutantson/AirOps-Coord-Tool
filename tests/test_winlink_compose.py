"""Offline regressions for the generic PAT composition helper.

Compile the actual function AST rather than importing app/common, whose imports
initialize application services. All subprocess, database, request, and mirror
dependencies are mocks; these tests never start PAT or contact a radio/network.
"""

import ast
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
from typing import Dict, Optional
import unittest
from unittest.mock import MagicMock, Mock


CORE = Path(__file__).resolve().parents[1] / "modules/services/winlink/core.py"


class WinlinkComposeTests(unittest.TestCase):
    def setUp(self):
        self.run = Mock(return_value=subprocess.CompletedProcess(["pat"], 0))
        self.connection = MagicMock()
        self.connect = Mock(return_value=self.connection)
        self.mirror = Mock()
        self.logger = Mock()
        self.callsign = Mock(return_value="N0CALL")
        self.globals = {
            "Optional": Optional,
            "Dict": Dict,
            "subprocess": SimpleNamespace(
                run=self.run,
                PIPE=subprocess.PIPE,
                TimeoutExpired=subprocess.TimeoutExpired,
                CalledProcessError=subprocess.CalledProcessError,
            ),
            "sqlite3": SimpleNamespace(connect=self.connect),
            "DB_FILE": "unused-mocked-database",
            "get_send_as_callsign": self.callsign,
            "has_request_context": Mock(return_value=False),
            "request": SimpleNamespace(cookies={"operator_call": "k7operator"}),
            "app": SimpleNamespace(logger=self.logger),
            "iso8601_ceil_utc": Mock(return_value="2026-10-02T00:00:00Z"),
            "_normalize_comm_metadata": Mock(side_effect=lambda metadata: metadata),
            "_mirror_comm_winlink": self.mirror,
            "classify_aoct_subject": Mock(return_value=None),
            "parse_winlink": Mock(return_value={}),
            "re": re,
        }
        tree = ast.parse(CORE.read_text(encoding="utf-8"), filename=str(CORE))
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "send_winlink_message"
        )
        module = ast.Module(body=[function], type_ignores=[])
        exec(compile(module, str(CORE), "exec"), self.globals)
        self.send = self.globals["send_winlink_message"]

    def test_success_waits_for_compose_before_recording_history(self):
        def compose(*args, **kwargs):
            self.connect.assert_not_called()
            self.mirror.assert_not_called()
            return subprocess.CompletedProcess(args[0], 0)

        self.run.side_effect = compose
        self.assertIs(self.send("  DEST  ", "Subject", "Body"), True)
        self.run.assert_called_once_with(
            ["pat", "compose", "--from", "N0CALL", "-s", "Subject", "DEST"],
            input="Body", text=True, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        self.connect.assert_called_once_with("unused-mocked-database")
        execute = self.connection.__enter__.return_value.execute
        self.assertEqual(execute.call_count, 2)
        self.assertIn("INSERT INTO winlink_messages", execute.call_args_list[0].args[0])
        self.assertEqual(execute.call_args_list[0].args[1], ("N0CALL", "DEST", "Subject", "Body"))
        self.assertIn("INSERT INTO outgoing_messages", execute.call_args_list[1].args[0])
        self.assertEqual(execute.call_args_list[1].args[1], (
            0, "N0CALL", "2026-10-02T00:00:00Z", "Subject", "Body",
        ))
        self.mirror.assert_called_once()

    def test_failed_composition_returns_false_without_outbound_records(self):
        failures = [
            subprocess.CalledProcessError(1, ["pat"], stderr="compose failed"),
            subprocess.TimeoutExpired(["pat"], 60),
            FileNotFoundError("pat is not installed"),
            PermissionError("pat is not executable"),
        ]
        for error in failures:
            with self.subTest(error=type(error).__name__):
                self.run.reset_mock()
                self.run.side_effect = error
                self.assertIs(self.send("DEST", "Subject", "Body"), False)
                self.run.assert_called_once()
                self.connect.assert_not_called()
                self.mirror.assert_not_called()
        self.assertEqual(self.logger.error.call_count, len(failures))

    def test_missing_recipient_or_callsign_returns_false_without_composing(self):
        self.assertIs(self.send("  ", "Subject", "Body"), False)
        self.callsign.return_value = ""
        self.assertIs(self.send("DEST", "Subject", "Body"), False)
        self.run.assert_not_called()
        self.connect.assert_not_called()
        self.mirror.assert_not_called()

    def test_success_retains_request_operator_and_metadata(self):
        self.globals["has_request_context"].return_value = True
        metadata = {"tail_number": "N123", "source": "TAR1090"}
        self.assertIs(self.send("DEST", "Subject", "Body", metadata=metadata), True)
        self.mirror.assert_called_once_with(
            "2026-10-02T00:00:00Z", "out", from_party="N0CALL", to_party="DEST",
            subject="Subject", body="Body", operator="K7OPERATOR", metadata=metadata,
        )

    def test_history_failure_does_not_invite_duplicate_composition(self):
        self.connect.side_effect = RuntimeError("database unavailable")
        self.assertIs(self.send("DEST", "Subject", "Body"), True)
        self.run.assert_called_once()
        self.logger.exception.assert_called_once()
        self.mirror.assert_not_called()

    def test_missing_logging_context_does_not_hide_compose_failure(self):
        self.run.side_effect = subprocess.TimeoutExpired(["pat"], 60)
        self.logger.error.side_effect = RuntimeError("no application context")
        self.assertIs(self.send("DEST", "Subject", "Body"), False)
        self.connect.assert_not_called()

    def test_empty_body_is_passed_as_text(self):
        self.assertIs(self.send("DEST", "Subject", None), True)
        self.assertEqual(self.run.call_args.kwargs["input"], "")


class AoctComposeRouteTests(unittest.TestCase):
    def setUp(self):
        route_path = CORE.parents[2] / "routes/winlink.py"
        tree = ast.parse(route_path.read_text(encoding="utf-8"), filename=str(route_path))
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "aoct_send"
        )
        function.decorator_list = []
        self.send = Mock(return_value=True)
        dependencies = {
            "pat_config_status": Mock(return_value=(True, None, "")),
            "request": SimpleNamespace(form={"to": "dest", "subject": "Subject", "body": "Body"}),
            "scheduler": SimpleNamespace(get_job=Mock(return_value=object())),
            "send_winlink_message": self.send,
            "jsonify": lambda value: value,
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(route_path), "exec"), dependencies)
        self.route = dependencies["aoct_send"]

    def test_success_explicitly_reports_composed(self):
        self.assertEqual(self.route(), {"ok": True, "status": "composed"})
        self.send.assert_called_once_with("DEST", "Subject", "Body")

    def test_compose_failure_returns_bad_gateway(self):
        self.send.return_value = False
        self.assertEqual(self.route(), ({"ok": False, "message": "PAT compose failed"}, 502))


if __name__ == "__main__":
    unittest.main()
