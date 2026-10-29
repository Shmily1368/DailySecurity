import pytest

import fetch_threat_intel as m
from test_vendor_driver import exercise_driver, exercise_entry_health


@pytest.mark.parametrize("case", ["normal", "empty", "all_failed", "partial", "missing_config", "replay"])
def test_threat_collection(tmp_path, monkeypatch, case):
    exercise_driver(m, tmp_path, monkeypatch, case)


@pytest.mark.parametrize("case", ["empty", "all_bad", "partial", "old", "partial_old", "unknown", "limited"])
def test_threat_entry_health(tmp_path, monkeypatch, case):
    from parsers import threat_intel_parsers
    exercise_entry_health(tmp_path, monkeypatch, threat_intel_parsers, "rss", case)
