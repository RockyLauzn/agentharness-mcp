"""Export observable workflow traces with stable run IDs and source digests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
from collections import Counter

import jsonschema

from .workflow_eval import ROOT


KINDS = {"mcp_send", "mcp_receive", "mcp_timeout", "transport_latency", "llm_decision", "blocked"}


def export(root: Path):
    root = root.resolve()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    expected = [f"{case['id']}--{mode}" for case in manifest for mode in ("baseline", "guarded")]
    selected = [name for name in expected if (root / name / "result.json").is_file()]
    index = {"schema_version": "1.0", "experiment_id": root.name, "planned_runs": len(expected),
             "exported_runs": len(selected), "runs": {}}
    fd, temp_name = tempfile.mkstemp(prefix=".trajectory-", suffix=".jsonl", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
            for name in selected:
                data = (root / name / "trace.jsonl").read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                lines = data.decode("utf-8").splitlines()
                for seq, line in enumerate(lines):
                    raw = json.loads(line)
                    if raw.get("type") not in KINDS:
                        raise ValueError(f"Unsupported event kind in {name}: {raw.get('type')}")
                    event = {"schema_version": "1.0", "experiment_id": root.name,
                             "run_id": name, "sequence": seq, "kind": raw["type"],
                             "payload": raw, "source_sha256": digest}
                    out.write(json.dumps(event, ensure_ascii=False) + "\n")
                index["runs"][name] = {"events": len(lines), "source_sha256": digest}
        os.replace(temp_name, root / "trajectory-v1.jsonl")
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    index_path = root / "trajectory-v1-index.json"
    fd, temp_name = tempfile.mkstemp(prefix=".trajectory-index-", suffix=".json", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(index, out, ensure_ascii=False, indent=2)
        os.replace(temp_name, index_path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    return index


def verify(root: Path):
    root = root.resolve()
    index = json.loads((root / "trajectory-v1-index.json").read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "schemas/trajectory-v1.schema.json").read_text(encoding="utf-8"))
    counts = Counter()
    for line in (root / "trajectory-v1.jsonl").read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        jsonschema.validate(event, schema)
        name = event["run_id"]
        if name not in index["runs"] or event["experiment_id"] != root.name:
            raise ValueError(f"Unexpected run or experiment: {name}")
        if event["sequence"] != counts[name] or event["kind"] != event["payload"]["type"]:
            raise ValueError(f"Out-of-order or inconsistent event: {name}")
        if event["source_sha256"] != index["runs"][name]["source_sha256"]:
            raise ValueError(f"Source digest mismatch: {name}")
        counts[name] += 1
    if set(counts) != set(index["runs"]):
        raise ValueError("Exported run set does not match index")
    for name, metadata in index["runs"].items():
        source = (root / name / "trace.jsonl").read_bytes()
        if counts[name] != metadata["events"] or hashlib.sha256(source).hexdigest() != metadata["source_sha256"]:
            raise ValueError(f"Source trace mismatch: {name}")
    if len(index["runs"]) != index["exported_runs"]:
        raise ValueError("Exported run count mismatch")
    return {"verified_runs": len(counts), "verified_events": sum(counts.values())}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT / "reports/workflow-512-r2")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        print(json.dumps(verify(args.root), indent=2))
    else:
        index = export(args.root)
        print(json.dumps({k: index[k] for k in ("planned_runs", "exported_runs")}, indent=2))


if __name__ == "__main__":
    main()
