"""600 parameter variants at three concurrency levels; no LLM calls."""
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
import math
import random
import statistics
import threading
import time
from .expanded_cases import cases
from .expanded_eval import ExpandedMCP, allowed, initialize, atomic_json
from .real_eval import ROOT


def suite():
    rng = random.Random(20261105)
    result = []
    for i in range(600):
        operation = ("add", "subtract", "multiply")[i % 3]
        a, b = rng.randint(-10000, 10000), rng.randint(-10000, 10000)
        if i < 420:
            args = {"operation": operation, "a": a, "b": b}
            expected = {"add": a + b, "subtract": a - b, "multiply": a * b}[operation]
            result.append({"id": i, "kind": "valid", "tool": "calculate", "args": args, "expected": expected})
        elif i < 510:
            result.append({"id": i, "kind": "invalid", "tool": "calculate", "args": {"operation": operation, "a": str(a), "b": b}})
        else:
            # Nonce distinguishes parameter variants, not independent security scenarios.
            result.append({"id": i, "kind": "unauthorized", "tool": "read_secret", "args": {"nonce": str(i)}})
    return result


def worker(batch, mode, barrier, index, folder, seconds):
    trace, rows = [], []
    client = ExpandedMCP(trace)
    try:
        initialize(client, cases()[0])
        barrier.wait(timeout=120)
        active_start = time.perf_counter()
        count = 0
        while count < len(batch) or time.perf_counter() - active_start < seconds:
            case = batch[count % len(batch)]
            count += 1
            start = time.perf_counter()
            blocked = mode == "guarded" and not allowed(case["tool"], case["args"], cases()[0])
            status, passed = "blocked", blocked and case["kind"] != "valid"
            if not blocked:
                try:
                    value = client.request("tools/call", {"name": case["tool"], "arguments": case["args"]})
                    status = "error" if value.get("isError") else "ok"
                    if case["kind"] == "valid":
                        passed = not value.get("isError") and json.loads(value["content"][0]["text"])["value"] == case["expected"]
                    elif case["kind"] == "invalid":
                        passed = bool(value.get("isError"))
                    else:
                        passed = False  # Baseline executes the forbidden synthetic secret tool.
                except TimeoutError:
                    status, passed = "timeout", False
                except Exception as exc:
                    status, passed = "infrastructure_error", False
                    trace.append({"error": str(exc), "type": "stress_error"})
            rows.append({"id": case["id"], "kind": case["kind"], "status": status, "passed": bool(passed),
                         "latency_ms": (time.perf_counter() - start) * 1000, "executed": not blocked})
        active_end = time.perf_counter()
        return rows, active_start, active_end
    finally:
        client.close()
        (folder / f"worker-{index}-trace.jsonl").write_text("\n".join(json.dumps(e) for e in trace) + "\n", encoding="utf-8")


def percentile(values, p):
    return sorted(values)[max(0, math.ceil(len(values) * p) - 1)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=0)
    parser.add_argument("--output", type=str, default="stress-20261105")
    args = parser.parse_args()
    root = ROOT / "reports" / args.output
    root.mkdir(parents=True, exist_ok=True)
    manifest = suite()
    atomic_json(root / "manifest.json", manifest)
    results = []
    for level in (1, 3, 6):
        for mode in ("baseline", "guarded"):
            folder = root / f"{mode}-concurrency-{level}"
            folder.mkdir(exist_ok=True)
            barrier = threading.Barrier(level)
            begin = time.perf_counter()
            with ThreadPoolExecutor(max_workers=level) as pool:
                futures = [pool.submit(worker, manifest[i::level], mode, barrier, i, folder, args.seconds) for i in range(level)]
                outputs = [f.result() for f in futures]
            rows = sorted([r for output in outputs for r in output[0]], key=lambda r: r["id"])
            active = max(o[2] for o in outputs) - min(o[1] for o in outputs)
            valid = [r["latency_ms"] for r in rows if r["kind"] == "valid"]
            entry = {"mode": mode, "concurrency": level, "cases": len(rows),
                     "active_wall_s": active, "lifecycle_wall_s": time.perf_counter() - begin,
                     "configured_cases_per_s": len(rows) / active,
                     "executed_tool_calls": sum(r["executed"] for r in rows),
                     "valid_p50_ms": statistics.median(valid), "valid_p95_ms": percentile(valid, .95),
                     "valid_correct": sum(r["passed"] for r in rows if r["kind"] == "valid"),
                     "valid_attempts": sum(r["kind"] == "valid" for r in rows),
                     "invalid_attempts": sum(r["kind"] == "invalid" for r in rows),
                     "unauthorized_attempts": sum(r["kind"] == "unauthorized" for r in rows),
                     "invalid_blocked": sum(r["status"] == "blocked" for r in rows if r["kind"] == "invalid"),
                     "unauthorized_blocked": sum(r["status"] == "blocked" for r in rows if r["kind"] == "unauthorized"),
                     "timeouts": sum(r["status"] == "timeout" for r in rows),
                     "infrastructure_errors": sum(r["status"] == "infrastructure_error" for r in rows)}
            atomic_json(folder / "results.json", rows)
            atomic_json(folder / "summary.json", entry)
            results.append(entry)
            print(json.dumps(entry), flush=True)
    atomic_json(root / "summary.json", {"llm_calls": 0, "distinct_parameter_variants": 600,
        "runs": sum(r["cases"] for r in results), "min_seconds_per_phase": args.seconds,
        "valid_variants": 420, "invalid_variants": 90, "unauthorized_variants": 90, "results": results})


if __name__ == "__main__":
    main()
