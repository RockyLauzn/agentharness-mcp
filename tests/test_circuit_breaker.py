import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from agent_harness import workflow_eval


class CircuitBreakerTests(unittest.TestCase):
    def test_quota_halts_after_only_inflight_jobs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def fake_evaluate(case, mode, output, model):
                row = {"case_id": case["id"], "mode": mode, "completed": False, "status": "infrastructure_error",
                       "error": "You've hit your usage limit", "llm_calls": 0, "worker_timeouts": 0, "protocol_errors": 0}
                folder = output / (case["id"] + "--" + mode)
                folder.mkdir()
                (folder / "result.json").write_text(json.dumps(row))
                return row
            def fake_command(command, **kwargs):
                return "test-cli" if "--version" in command else '[{"Id":"test-image"}]'
            args = ["test", "--output", str(root), "--limit", "32", "--workers", "3"]
            with patch("sys.argv", args), patch.object(workflow_eval, "evaluate", side_effect=fake_evaluate), patch.object(workflow_eval.subprocess, "check_output", side_effect=fake_command):
                with self.assertRaises(SystemExit) as caught:
                    workflow_eval.main()
            self.assertEqual(caught.exception.code, 2)
            control = json.loads((root / "run-control.json").read_text())
            self.assertEqual(control["status"], "halted")
            self.assertEqual(control["halt_reason"], "model_usage_limit")
            self.assertLessEqual(len(list(root.glob("*/result.json"))), 3)
            self.assertEqual(control["planned_runs"], 64)
