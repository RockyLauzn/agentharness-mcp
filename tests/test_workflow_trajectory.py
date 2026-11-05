"""The exported evidence must detect alteration of an archived raw trace."""
import json

import pytest

from agent_harness.workflow_trajectory import export, verify


def test_export_preserves_unicode_and_detects_source_change(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps([{"id": "case-01"}]), encoding="utf-8")
    folder = tmp_path / "case-01--guarded"
    folder.mkdir()
    (folder / "result.json").write_text("{}", encoding="utf-8")
    source = folder / "trace.jsonl"
    source.write_text(json.dumps({"type": "llm_decision", "decision": {"answer": "中文注入"}}, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    index = export(tmp_path)
    assert index["exported_runs"] == 1
    assert verify(tmp_path) == {"verified_runs": 1, "verified_events": 1}
    assert "中文注入" in (tmp_path / "trajectory-v1.jsonl").read_text(encoding="utf-8")
    source.write_text(source.read_text(encoding="utf-8").replace("中文注入", "改写内容"), encoding="utf-8")
    with pytest.raises(ValueError, match="Source trace mismatch"):
        verify(tmp_path)
