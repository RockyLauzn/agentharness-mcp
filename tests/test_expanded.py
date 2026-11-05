import json
import subprocess
import sys
import unittest
from agent_harness.expanded_cases import cases, ATTACKS
from agent_harness.expanded_eval import allowed


class ExpandedTests(unittest.TestCase):
    def test_manifest_has_30_unique_combinations(self):
        suite = cases()
        self.assertEqual(len(suite), 30)
        self.assertEqual(len({c["id"] for c in suite}), 30)
        self.assertEqual(sum(c["attack"] for c in suite), 18)

    def test_gateway_denies_privilege_and_parameter_misuse(self):
        case = cases()[0]
        self.assertFalse(allowed("read_secret", {}, case))
        self.assertFalse(allowed("read_document", {"id": "../../private"}, case))
        self.assertFalse(allowed("calculate", {"operation": [], "a": 1, "b": 2}, case))
        self.assertFalse(allowed("calculate", {"operation": "add", "a": True, "b": 2}, case))
        self.assertTrue(allowed("calculate", {"operation": "add", "a": 1, "b": 2}, case))

    def test_wire_values_and_injection_placement(self):
        for case in cases():
            if case["condition"] in {"timeout", "malformed", "transient"}:
                continue
            with self.subTest(case=case["id"]):
                condition = case["condition"]
                payload = ATTACKS.get(condition.split("_", 1)[-1], "")
                requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                            {"jsonrpc": "2.0", "id": 2, "method": "harness/configure", "params": {
                                "documents": case["documents"], "condition": condition, "payload": payload}},
                            {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
                            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
                                "name": "read_document", "arguments": {"id": next(iter(case["documents"]))}}}]
                proc = subprocess.run([sys.executable, "-m", "agent_harness.expanded_server"],
                    input="\n".join(json.dumps(r) for r in requests) + "\n", capture_output=True, text=True, check=True, timeout=5)
                rows = [json.loads(line)["result"] for line in proc.stdout.splitlines()]
                self.assertEqual(json.loads(rows[3]["content"][0]["text"])["value"], next(iter(case["documents"].values())))
                if condition.startswith("description_"):
                    self.assertIn(payload, rows[2]["tools"][0]["description"])
                elif condition.startswith("output_"):
                    self.assertIn(payload, json.loads(rows[3]["content"][0]["text"])["text"])
