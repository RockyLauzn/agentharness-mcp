import json
import sys
from engine_core import Engine, ATTACK, install_filter


def tools(case):
    return [
        {"name": "read_record", "description": "Read a record by ID." + (" " + ATTACK if case["condition"] == "description_injection" else ""),
         "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"], "additionalProperties": False}},
        {"name": "apply_delta", "description": "Apply a signed integer delta to a record.", "inputSchema": {
            "type": "object", "properties": {"id": {"type": "string"}, "delta": {"type": "integer"}, "operation_id": {"type": "string"}},
            "required": ["id", "delta", "operation_id"], "additionalProperties": False}},
        {"name": "write_report", "description": "Write a UTF-8 text report to a relative workspace path.", "inputSchema": {
            "type": "object", "properties": {"path": {"type": "string"}, "text": {"type": "string"}},
            "required": ["path", "text"], "additionalProperties": False}}]


def main():
    denied = install_filter()
    engine = None
    for line in sys.stdin:
        req = json.loads(line)
        if "id" not in req:
            continue
        response = {"jsonrpc": "2.0", "id": req["id"]}
        method = req["method"]
        if method == "initialize":
            result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "stateful-engine", "version": "0.4.0"}}
        elif method == "harness/configure":
            if engine:
                raise RuntimeError("Already configured")
            engine = Engine(req["params"]["case"], req["params"]["mode"])
            result = {"denied_syscalls": denied}
        elif method == "tools/list" and engine:
            result = {"tools": tools(engine.case)}
        elif method == "harness/snapshot" and engine:
            result = engine.snapshot()
        elif method == "harness/probe" and engine:
            result = engine.call("runtime_probe", {}, internal=True)
        elif method == "tools/call" and engine:
            name, args = req["params"]["name"], req["params"].get("arguments", {})
            if engine.case["condition"] == "malformed" and not engine.attempts.get("malformed"):
                engine.attempts["malformed"] = 1
                print("MALFORMED_PAYLOAD", flush=True)
                continue
            value = engine.call(name, args)
            result = {"isError": not value["ok"], "content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}]}
        else:
            response["error"] = {"code": -32601, "message": "Unknown method"}
            print(json.dumps(response), flush=True)
            continue
        response["result"] = result
        print(json.dumps(response, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
