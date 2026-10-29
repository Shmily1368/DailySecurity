import json
from datetime import datetime, timezone
from unittest.mock import patch

import fetch_github_advisory as m


def test_nullable_dates_have_stable_order_without_fabricated_publication():
    now = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
    entries = [
        {"ghsa_id": "GHSA-known", "published_at": "2026-10-29T04:00:00Z"},
        {"ghsa_id": "GHSA-updated", "updated_at": "2026-10-29T06:00:00+02:00"},
        {"ghsa_id": "GHSA-invalid", "published_at": "not a date",
         "updated_at": "2026-10-29T05:00:00"},
        {"ghsa_id": "GHSA-unknown"},
        {"ghsa_id": "GHSA-null", "published_at": None, "updated_at": None},
    ]
    items = m.normalize(entries, now)
    assert [item.id for item in items] == [
        "ghsa:GHSA-unknown", "ghsa:GHSA-null", "ghsa:GHSA-invalid",
        "ghsa:GHSA-updated", "ghsa:GHSA-known",
    ]
    assert [item.id for item in m.normalize(reversed(entries), now)] == [
        item.id for item in items
    ]
    for item in items:
        assert item.fetched_at.tzinfo is not None
        if item.id != "ghsa:GHSA-known":
            assert item.published_at is None
            assert item.date_precision == "unknown"


def test_cli_writes_mixed_date_advisories(tmp_path, monkeypatch):
    output = tmp_path / "ghsa.json"
    monkeypatch.setattr("sys.argv", ["ghsa", "--output", str(output)])
    entries = [{"ghsa_id": "GHSA-known", "published_at": "2026-10-29T00:00:00Z"},
               {"ghsa_id": "GHSA-unknown", "updated_at": "2026-10-29T01:00:00Z"}]
    with patch.object(m, "fetch_advisories", return_value=entries):
        assert m.main() == 0
    payload = json.loads(output.read_text())
    assert payload["meta"]["raw_count"] == payload["meta"]["normalized_count"] == 2
    assert {item["id"] for item in payload["items"]} == {
        "ghsa:GHSA-known", "ghsa:GHSA-unknown"
    }
    unknown = next(item for item in payload["items"] if item["id"] == "ghsa:GHSA-unknown")
    assert unknown["published_at"] is None
    assert unknown["date_precision"] == "unknown"
