from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

import watch_publication as m


@pytest.mark.parametrize("state", ["current", "updating", "needs_recovery", "recovery_requested"])
def test_watchdog_checks_before_dispatch(monkeypatch, state):
    today = datetime.now(ZoneInfo("Asia/Shanghai")).date().isoformat()
    live = {"date": today, "commit": "head", "is_mock": False}
    if state != "current":
        live["date"] = "2000-01-01"
    monkeypatch.setattr(m, "public_manifest", lambda: live)
    calls = []

    def github(endpoint, *, body=None, token=None):
        calls.append((endpoint, body, token))
        if endpoint == "/commits/main":
            return {"sha": "head"}
        if body is not None:
            assert token == "fixture-token"
            assert body == {"ref": "main", "inputs": {"force_refresh": False}}
            return {"accepted": True}
        return {"workflow_runs": [{"status": "in_progress" if state == "updating" else "completed"}]}

    monkeypatch.setattr(m, "github", github)
    monkeypatch.setattr(m, "credential", lambda: "fixture-token")
    assert m.check(recover=state == "recovery_requested")["status"] == state
    assert sum(body is not None for _, body, _ in calls) == (state == "recovery_requested")


def test_watchdog_recovers_code_version_mismatch(monkeypatch):
    today = datetime.now(ZoneInfo("Asia/Shanghai")).date().isoformat()
    monkeypatch.setattr(m, "public_manifest", lambda: {"date": today, "commit": "old", "is_mock": False})
    monkeypatch.setattr(m, "github", lambda endpoint, **_: {"sha": "new"} if endpoint == "/commits/main" else {"workflow_runs": []})
    assert m.check()["status"] == "needs_recovery"
