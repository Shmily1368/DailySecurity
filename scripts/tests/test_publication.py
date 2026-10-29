import json
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

import publication as m


@pytest.mark.parametrize("live_commit,deploy", [("older", "true"), ("checkout", "false")])
def test_gate_recovers_unpublished_commit(tmp_path, monkeypatch, live_commit, deploy):
    today = datetime.now(ZoneInfo("Asia/Shanghai")).date().isoformat()
    pointer = {"date": today, "sha256": "same-data", "health": {"status": "healthy"}}
    monkeypatch.setattr(m, "local_snapshot", lambda: pointer)
    monkeypatch.setattr(m, "public_manifest", lambda: {
        "version": "same-data", "date": today, "commit": live_commit, "is_mock": False})
    monkeypatch.setenv("DATA_COMMIT", "checkout")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "outputs"))
    monkeypatch.setattr(sys, "argv", ["publication.py", "gate"])
    assert m.main() == 0
    assert (tmp_path / "outputs").read_text() == f"collect=false\ndeploy={deploy}\n"


def test_legacy_publication_rejects_invalid_schema(tmp_path, monkeypatch):
    (tmp_path / "data/daily").mkdir(parents=True)
    (tmp_path / "data/daily/latest.json").write_text(json.dumps({"date": "2026-10-29", "items": []}))
    monkeypatch.setattr(m, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["publication.py", "validate"])
    with pytest.raises(ValueError, match="schema validation"):
        m.main()
