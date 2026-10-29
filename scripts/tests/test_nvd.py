import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx
import pytest

import fetch_nvd as m


@pytest.mark.parametrize("total", [0, 2, 3])
def test_pagination_health(total):
    def page(client, url, params):
        start = params["startIndex"]
        return {"totalResults": total, "vulnerabilities": [{"cve": {"id": str(i)}}
                for i in range(start, min(start + 2, total))]}
    with patch.object(m, "_http_get_json", side_effect=page), \
         patch.object(m, "PAGE_SIZE", 2), patch.object(m, "MAX_PAGES", 1):
        result = m.fetch_nvd_window(datetime(2026, 10, 28, tzinfo=timezone.utc),
                                    datetime(2026, 10, 29, tzinfo=timezone.utc), None)
    assert len(result) == min(total, 2)
    assert result.meta["status"] == ("partial" if total > 2 else "success")
    assert result.meta["next_start_index"] == (2 if total > 2 else None)
    assert result.meta["total_results"] == total


@pytest.mark.parametrize("payload", [{}, {"totalResults": 1}, {"vulnerabilities": "invalid"}])
def test_invalid_response(payload):
    with patch.object(m, "_http_get_json", return_value=payload):
        with pytest.raises(m.NvdFetchError):
            m.fetch_nvd_window(datetime.now(timezone.utc), datetime.now(timezone.utc), None)


def test_normalize_evidence():
    item = m.entry_to_raw_item({"cve": {
        "id": "CVE-2026-1234", "published": "2026-10-29T00:00:00Z",
        "lastModified": "2026-10-29T01:00:00Z",
        "descriptions": [{"lang": "en", "value": "Critical vulnerability"}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8}}]},
        "references": [{"url": "https://example.org/exploit-reference", "tags": ["Exploit"]}],
    }}, datetime.now(timezone.utc))
    assert item.risk.cvss_score == 9.8
    assert item.risk.has_public_exploit
    assert str(item.risk.exploit_references[0].url) == "https://example.org/exploit-reference"


def test_cursor_resumes_window(tmp_path, monkeypatch):
    output = tmp_path / "nvd.json"
    state = tmp_path / "cursor.json"
    FrozenDate.current = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
    monkeypatch.setattr(m, "datetime", FrozenDate)
    monkeypatch.setattr("sys.argv", ["nvd", "--output", str(output), "--state-file", str(state)])
    calls = []
    def page(client, url, params):
        start = params["startIndex"]
        calls.append(start)
        return {"totalResults": 3, "vulnerabilities": [{"cve": {
            "id": f"CVE-2026-{1234+i}", "published": "2026-10-29T00:00:00Z"}}
            for i in range(start, min(start + 2, 3))]}
    with patch.object(m, "_http_get_json", side_effect=page), \
         patch.object(m, "PAGE_SIZE", 2), patch.object(m, "MAX_PAGES", 1):
        assert m.main() == 0
        first = json.loads(output.read_text())
        assert state.exists() and first["meta"]["status"] == "partial"
        assert m.main() == 0
        second = json.loads(output.read_text())
    assert calls == [0, 2]
    assert len(second["items"]) == 3
    assert first["meta"]["window_end"] == second["meta"]["window_end"]
    assert json.loads(state.read_text()) == {
        "completed_until": "2026-10-29T12:00:00+00:00"
    }


class FrozenDate(datetime):
    current = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        return cls.current.astimezone(tz) if tz else cls.current.replace(tzinfo=None)


def cve_entry(number):
    return {"cve": {"id": f"CVE-2026-{number}",
                    "published": "2026-10-29T00:00:00Z"}}


@pytest.mark.parametrize("page_budget,page_size,total", [(5, 500, 2501), (1, 2, 3)])
def test_cross_day_watermark_covers_intervening_dates(
    tmp_path, monkeypatch, page_budget, page_size, total
):
    output, state = tmp_path / "nvd.json", tmp_path / "cursor.json"
    monkeypatch.setattr("sys.argv", ["nvd", "--days", "1", "--output", str(output),
                                   "--state-file", str(state)])
    monkeypatch.setattr(m, "datetime", FrozenDate)
    monkeypatch.setattr(m, "MAX_PAGES", page_budget)
    monkeypatch.setattr(m, "PAGE_SIZE", page_size)
    calls = []

    def page(client, url, params):
        calls.append(dict(params))
        index = params["startIndex"]
        old_window = params["lastModEndDate"].startswith("2026-10-29")
        count = total if old_window else 1
        entries = [cve_entry(10000 + i) for i in range(index, min(index + page_size, count))]
        if not old_window:
            entries = [{"cve": {"id": "CVE-2026-99999",
                                "published": "2026-10-30T00:00:00Z"}}]
        return {"totalResults": count, "vulnerabilities": entries}

    outputs = []
    pages_per_run = []
    with patch.object(m, "_http_get_json", side_effect=page), \
         patch.object(m.time, "sleep", return_value=None):
        for day in (29, 30, 31):
            FrozenDate.current = datetime(2026, 10, day, 12, tzinfo=timezone.utc)
            before = len(calls)
            assert m.main() == 0
            pages_per_run.append(len(calls) - before)
            outputs.append(json.loads(output.read_text()))

    assert all(count <= page_budget for count in pages_per_run)
    assert pages_per_run == ([5, 2, 1] if page_budget == 5 else [1, 1, 1])
    assert outputs[0]["meta"]["status"] == "partial"
    assert any(item["id"] == "nvd:CVE-2026-99999"
               for result in outputs[1:] for item in result["items"])
    # The first window is frozen while paging; every later query starts at its end.
    windows = list(dict.fromkeys((row["lastModStartDate"], row["lastModEndDate"])
                                for row in calls))
    assert windows[0] == ("2026-10-28T12:00:00.000", "2026-10-29T12:00:00.000")
    assert all(left[1] == right[0] for left, right in zip(windows, windows[1:]))
    assert json.loads(state.read_text()) == {
        "completed_until": "2026-10-31T12:00:00+00:00"
    }
    if page_budget == 1:
        assert outputs[1]["meta"]["status"] == "partial"
        assert windows[1] == ("2026-10-29T12:00:00.000", "2026-10-31T12:00:00.000")


def test_old_watermark_splits_nvd_maximum_window(tmp_path, monkeypatch):
    output, state = tmp_path / "nvd.json", tmp_path / "cursor.json"
    start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    state.write_text(json.dumps({"completed_until": start.isoformat()}))
    FrozenDate.current = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
    monkeypatch.setattr(m, "datetime", FrozenDate)
    monkeypatch.setattr("sys.argv", ["nvd", "--days", "1", "--output", str(output),
                                   "--state-file", str(state)])
    calls = []

    def page(client, url, params):
        calls.append(dict(params))
        return {"totalResults": 0, "vulnerabilities": []}

    with patch.object(m, "_http_get_json", side_effect=page), \
         patch.object(m.time, "sleep", return_value=None):
        assert m.main() == 0
    assert len(calls) == 3
    assert calls[0]["lastModStartDate"] == "2026-01-01T12:00:00.000"
    assert calls[-1]["lastModEndDate"] == "2026-10-29T12:00:00.000"
    for row in calls:
        assert datetime.fromisoformat(row["lastModEndDate"]) - datetime.fromisoformat(
            row["lastModStartDate"]
        ) <= timedelta(days=m.MAX_DAYS)
    assert json.loads(state.read_text())["completed_until"] == FrozenDate.current.isoformat()


def test_legacy_cursor_catchup_failure_keeps_completed_progress(tmp_path, monkeypatch):
    output, state = tmp_path / "nvd.json", tmp_path / "cursor.json"
    state.write_text(json.dumps({
        "window_start": "2026-10-28T12:00:00+00:00",
        "window_end": "2026-10-29T12:00:00+00:00",
        "next_start_index": 1, "entries": [cve_entry(1234)]
    }))
    FrozenDate.current = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)
    monkeypatch.setattr(m, "datetime", FrozenDate)
    monkeypatch.setattr("sys.argv", ["nvd", "--days", "1", "--output", str(output),
                                   "--state-file", str(state)])

    def page(client, url, params):
        if params["lastModEndDate"].startswith("2026-10-30"):
            raise httpx.ReadTimeout("Catchup unavailable")
        assert params["startIndex"] == 1
        return {"totalResults": 2, "vulnerabilities": [cve_entry(1235)]}

    with patch.object(m, "_http_get_json", side_effect=page), \
         patch.object(m.time, "sleep", return_value=None):
        assert m.main() == 0
    result = json.loads(output.read_text())
    cursor = json.loads(state.read_text())
    assert len(result["items"]) == 2
    assert result["meta"]["status"] == "partial"
    assert result["meta"]["errors"]
    assert cursor["completed_until"] == "2026-10-29T12:00:00+00:00"
    assert cursor["window_start"] == "2026-10-29T12:00:00+00:00"
    assert cursor["window_end"] == FrozenDate.current.isoformat()
    assert cursor["next_start_index"] == 0
    assert cursor["entries"] == []


def test_watermark_does_not_advance_before_output(tmp_path, monkeypatch):
    output, state = tmp_path / "nvd.json", tmp_path / "cursor.json"
    previous = {"completed_until": "2026-10-28T12:00:00+00:00"}
    state.write_text(json.dumps(previous))
    FrozenDate.current = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
    monkeypatch.setattr(m, "datetime", FrozenDate)
    monkeypatch.setattr("sys.argv", ["nvd", "--output", str(output),
                                   "--state-file", str(state)])
    with patch.object(m, "_http_get_json", return_value={"totalResults": 0, "vulnerabilities": []}), \
         patch.object(m, "dump_items", side_effect=OSError("Output disk failure")):
        with pytest.raises(OSError):
            m.main()
    assert json.loads(state.read_text()) == previous


def test_page_budget_shared_by_resume_and_partially_fetched_catchup(tmp_path, monkeypatch):
    output, state = tmp_path / "nvd.json", tmp_path / "cursor.json"
    monkeypatch.setattr(m, "datetime", FrozenDate)
    monkeypatch.setattr("sys.argv", ["nvd", "--days", "1", "--output", str(output),
                                   "--state-file", str(state)])
    calls = []

    def page(client, url, params):
        calls.append(dict(params))
        index = params["startIndex"]
        total = 1 if params["lastModEndDate"].startswith("2026-10-31") else 2501
        base = 20000 if params["lastModEndDate"].startswith("2026-10-30") else 10000
        return {"totalResults": total, "vulnerabilities": [
            cve_entry(base + i) for i in range(index, min(index + m.PAGE_SIZE, total))
        ]}

    with patch.object(m, "_http_get_json", side_effect=page), \
         patch.object(m.time, "sleep", return_value=None):
        FrozenDate.current = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
        assert m.main() == 0
        assert len(calls) == 5
        FrozenDate.current = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)
        assert m.main() == 0
        assert len(calls) == 10
        cursor = json.loads(state.read_text())
        assert cursor["completed_until"] == "2026-10-29T12:00:00+00:00"
        assert cursor["window_start"] == cursor["completed_until"]
        assert cursor["window_end"] == FrozenDate.current.isoformat()
        assert cursor["next_start_index"] == 2000
        assert len(cursor["entries"]) == 2000
        assert json.loads(output.read_text())["meta"]["status"] == "partial"
        FrozenDate.current = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)
        assert m.main() == 0
    assert len(calls) == 13
    assert calls[10]["startIndex"] == 2000
    assert calls[10]["lastModEndDate"] == "2026-10-30T12:00:00.000"
    result = json.loads(output.read_text())
    assert len(result["items"]) == 2502
    assert result["meta"]["status"] == "success"
    assert json.loads(state.read_text()) == {"completed_until": FrozenDate.current.isoformat()}


@pytest.mark.parametrize("offset", [timedelta(0), timedelta(hours=1)])
def test_caught_up_or_backward_clock_keeps_watermark(tmp_path, monkeypatch, offset):
    output, state = tmp_path / "nvd.json", tmp_path / "cursor.json"
    FrozenDate.current = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
    previous = {"completed_until": (FrozenDate.current + offset).isoformat()}
    state.write_text(json.dumps(previous))
    monkeypatch.setattr(m, "datetime", FrozenDate)
    monkeypatch.setattr("sys.argv", ["nvd", "--output", str(output),
                                   "--state-file", str(state)])
    with patch.object(m, "_http_get_json") as fetcher:
        assert m.main() == 0
    fetcher.assert_not_called()
    assert json.loads(state.read_text()) == previous
    assert json.loads(output.read_text())["meta"]["status"] == "no_new"


@pytest.mark.parametrize("cursor", [
    [], {}, {"completed_until": "invalid"},
    {"window_start": "2026-10-28", "window_end": "2026-10-29", "next_start_index": -1},
])
def test_invalid_state_fails_without_resetting_coverage(tmp_path, monkeypatch, cursor):
    output, state = tmp_path / "nvd.json", tmp_path / "cursor.json"
    state.write_text(json.dumps(cursor))
    monkeypatch.setattr("sys.argv", ["nvd", "--output", str(output),
                                   "--state-file", str(state)])
    with patch.object(m, "_http_get_json") as fetcher:
        assert m.main() == 1
    fetcher.assert_not_called()
    assert not output.exists()
    assert json.loads(state.read_text()) == cursor
