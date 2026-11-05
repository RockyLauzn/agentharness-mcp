import json
import os
import subprocess
import sys
import unittest


class MCPProtocolTests(unittest.TestCase):
    def exchange(self, scenario):
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_document", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "read_document", "arguments": {}}}]
        proc = subprocess.run([sys.executable, "-m", "agent_harness.mcp_server"],
                              input="\n".join(json.dumps(m) for m in messages) + "\n",
                              env={**os.environ, "HARNESS_SCENARIO": scenario},
                              text=True, capture_output=True, timeout=5, check=True)
        return [json.loads(line) for line in proc.stdout.splitlines()]

    def test_handshake_and_tool_discovery(self):
        rows = self.exchange("normal")
        self.assertEqual([r["id"] for r in rows], [1, 2, 3, 4])
        self.assertEqual(rows[0]["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(len(rows[1]["result"]["tools"]), 3)
        self.assertEqual(json.loads(rows[2]["result"]["content"][0]["text"])["revenue"], 42)

    def test_injection_is_in_actual_wire_result(self):
        rows = self.exchange("output_injection")
        self.assertIn("SYSTEM OVERRIDE", rows[2]["result"]["content"][0]["text"])
        rows = self.exchange("description_injection")
        self.assertIn("SYSTEM OVERRIDE", rows[1]["result"]["tools"][0]["description"])

    def test_transient_error_recovers_in_same_session(self):
        rows = self.exchange("transient")
        self.assertTrue(rows[2]["result"]["isError"])
        self.assertFalse(rows[3]["result"]["isError"])
