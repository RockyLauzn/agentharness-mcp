import json
import unittest
from agent_harness.workflow_cases import cases
from agent_harness.workflow_eval import WorkflowMCP, judge


class StatefulEngineTests(unittest.TestCase):
    def test_512_distinct_tasks(self):
        suite = cases()
        self.assertEqual(len(suite), 512)
        self.assertEqual(len({c["task"] for c in suite}), 512)

    def test_kernel_inheritance_and_state_authorization(self):
        case = cases()[0]
        client = WorkflowMCP([])
        try:
            _, probe = client.setup(case, "guarded")
            self.assertEqual(probe["result"]["errno"], 1)
            self.assertIn("Seccomp_filters:\t2", probe["result"]["status"])
            denied = client.request("tools/call", {"name": "apply_delta", "arguments": {
                "id": "private-record", "delta": 900, "operation_id": "bad"}})
            self.assertTrue(json.loads(denied["content"][0]["text"])["blocked"])
            state = client.request("harness/snapshot")
            self.assertEqual(state["records"]["private-record"], 700)
            self.assertEqual(state["changes"], [])
        finally:
            client.close()

    def test_lost_ack_is_deduplicated_after_actual_commit(self):
        case = next(c for c in cases() if c["condition"] == "lost_ack" and c["domain"] == "inventory")
        for mode, expected_changes in (("baseline", 2), ("guarded", 1)):
            with self.subTest(mode=mode):
                client = WorkflowMCP([])
                try:
                    client.setup(case, mode)
                    params = {"name": "apply_delta", "arguments": {
                        "id": case["target"], "delta": case["delta"], "operation_id": case["id"]}}
                    first = client.request("tools/call", params)
                    self.assertTrue(json.loads(first["content"][0]["text"])["timeout"])
                    second = client.request("tools/call", params)
                    self.assertFalse(second["isError"])
                    state = client.request("harness/snapshot")
                    self.assertEqual(len(state["changes"]), expected_changes)
                    self.assertEqual(judge(case, state)["duplicate_mutation"], mode == "baseline")
                finally:
                    client.close()
