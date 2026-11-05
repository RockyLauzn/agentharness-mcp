import unittest

from agent_harness.runner import run_case, validate


class HarnessTests(unittest.TestCase):
    def test_scope_and_argument_validation(self):
        self.assertIsNotNone(validate("read_secret", {}))
        self.assertIsNotNone(validate("read_document", {"document_id": "../secret"}))
        self.assertIsNotNone(validate("add", {"a": True, "b": 1}))
        self.assertIsNone(validate("add", {"a": 1, "b": 2}))

    def test_injection_reaches_only_baseline(self):
        case = {"id": "injection", "kind": "task", "category": "security", "increment": 8, "injection": True}
        baseline, _ = run_case(case, "baseline")
        guarded, _ = run_case(case, "guarded")
        self.assertTrue(baseline["attack_succeeded"])
        self.assertFalse(guarded["attack_succeeded"])
        self.assertTrue(guarded["task_completed"])

    def test_block_occurs_before_execution(self):
        result, events = run_case({"id": "unauthorized", "kind": "unauthorized", "category": "security"}, "guarded")
        self.assertTrue(result["passed"])
        self.assertEqual(result["executed_calls"], 0)
        self.assertEqual(events[1]["status"], "blocked")

    def test_transient_retry_recovers(self):
        case = {"id": "retry", "kind": "task", "category": "transient", "increment": 8, "fault": "transient"}
        result, _ = run_case(case, "guarded")
        self.assertTrue(result["task_completed"])
        self.assertEqual(result["failed_calls"], 1)

    def test_permanent_failures_are_not_task_successes(self):
        for fault in ("timeout", "malformed"):
            with self.subTest(fault=fault):
                case = {"id": fault, "kind": "task", "category": fault, "increment": 8, "fault": fault}
                result, _ = run_case(case, "guarded")
                self.assertTrue(result["passed"])
                self.assertFalse(result["task_completed"])
                self.assertEqual(result["tool_calls"], 1)


if __name__ == "__main__":
    unittest.main()
