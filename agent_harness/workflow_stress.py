"""Equal read-only workload through hardened subprocess / SQLite runtime; no model calls."""
from concurrent.futures import ThreadPoolExecutor
import json
import math
import statistics
import threading
import time
from .workflow_eval import ROOT, WorkflowMCP
from .workflow_cases import cases
from .expanded_eval import atomic_json


def worker(index, level, root, barrier):
    trace, rows = [], []
    case = cases()[index]
    case["condition"] = "clean"
    client = WorkflowMCP(trace)
    try:
        _, probe = client.setup(case, "guarded")
        barrier.wait(timeout=60)
        start = time.perf_counter()
        while time.perf_counter() - start < 5:
            before = time.perf_counter()
            result = client.request("tools/call", {"name": "read_record", "arguments": {"id": case["target"]}})
            body = json.loads(result["content"][0]["text"])
            rows.append({"latency_ms": (time.perf_counter() - before) * 1000,
                         "correct": body.get("ok") and body["result"]["value"] == case["initial"]})
        end = time.perf_counter()
        atomic_json(root / f"worker-{index}.json", {"rows": rows, "probe": probe, "start": start, "end": end})
        return rows, start, end
    finally:
        client.close()
        (root / f"worker-{index}-trace.jsonl").write_text("\n".join(json.dumps(e) for e in trace) + "\n", encoding="utf-8")


def main():
    root = ROOT / "reports/workflow-stress"
    root.mkdir(parents=True, exist_ok=True)
    summary = []
    for level in (1, 4, 8):
        folder = root / f"concurrency-{level}"
        folder.mkdir(exist_ok=True)
        barrier = threading.Barrier(level)
        with ThreadPoolExecutor(max_workers=level) as pool:
            futures = [pool.submit(worker, i, level, folder, barrier) for i in range(level)]
            batches = [f.result() for f in futures]
        rows = [r for batch in batches for r in batch[0]]
        latencies = sorted(r["latency_ms"] for r in rows)
        active = max(b[2] for b in batches) - min(b[1] for b in batches)
        entry = {"concurrency": level, "attempts": len(rows), "correct": sum(r["correct"] for r in rows),
            "active_seconds": active, "requests_per_second": len(rows) / active,
            "p50_ms": statistics.median(latencies), "p95_ms": latencies[math.ceil(len(rows)*.95)-1]}
        summary.append(entry)
        print(json.dumps(entry), flush=True)
    atomic_json(root / "summary.json", {"llm_calls": 0, "workload": "same read_record operation through per-tool fork and SQLite transaction", "results": summary})


if __name__ == "__main__":
    main()
