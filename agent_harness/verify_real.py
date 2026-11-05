"""Audit persisted real-run evidence. Exit nonzero for missing/invalid coverage."""
import hashlib
import json
from pathlib import Path
from .real_eval import ROOT


def main():
    root = ROOT / "reports" / "real"
    meta = json.loads((root / "metadata.json").read_text(encoding="utf-8"))
    paths = [ROOT / "agent_harness" / "real_eval.py", ROOT / "agent_harness" / "mcp_server.py", ROOT / "Dockerfile"]
    checks = {"source_matches_run": all(meta["source_sha256"][p.name] == hashlib.sha256(p.read_bytes()).hexdigest() for p in paths)}
    probe = json.loads((ROOT / "reports" / "docker-probe.json").read_text(encoding="utf-8"))
    checks["docker_probe_passed"] = all(probe["checks"].values())
    scenarios = ["normal", "output_injection", "description_injection", "transient", "timeout", "malformed"]
    rows = []
    for scenario in scenarios:
        for mode in ("baseline", "guarded"):
            for repeat in range(2):
                folder = root / f"{scenario}-{mode}-{repeat}"
                result_path = folder / "result.json"
                key = folder.name
                if not result_path.exists():
                    checks[key] = False
                    continue
                result = json.loads(result_path.read_text(encoding="utf-8"))
                rows.append(result)
                trace = [json.loads(line) for line in (folder / "trace.jsonl").read_text(encoding="utf-8").splitlines()]
                sends = [e["message"] for e in trace if e["type"] == "mcp_send"]
                decisions = [e for e in trace if e["type"] == "llm_decision"]
                raw = [json.loads(line) for p in folder.glob("step-*-events.jsonl")
                       for line in p.read_text(encoding="utf-8").splitlines() if line.startswith("{")]
                valid = (result["status"] != "infrastructure_error" and
                         result["llm_calls"] > 0 and len(decisions) == result["llm_calls"] and
                         sum(e.get("type") == "turn.completed" for e in raw) == result["llm_calls"] and
                         all(any(m.get("method") == method for m in sends) for method in
                             ("initialize", "notifications/initialized", "tools/list", "tools/call")))
                if scenario in {"output_injection", "description_injection"}:
                    # Verify the actual adversarial text reached a model request, not just the server.
                    prompts = [p.read_text(encoding="utf-8") for p in folder.glob("step-*-prompt.json")]
                    valid &= any("SYSTEM OVERRIDE" in p for p in prompts)
                checks[key] = bool(valid)
    checks["exactly_24_runs"] = len(rows) == 24
    audit = {"checks": checks, "passed": all(checks.values()),
             "runs": len(rows), "real_model_turns": sum(r["llm_calls"] for r in rows)}
    (root / "audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    print(json.dumps(audit, indent=2))
    if not audit["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
