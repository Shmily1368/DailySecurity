import json
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock

import pytest

import fetch_vendor_advisories as m
from source_registry import SourceConfig
from test_llm import raw_item


def exercise_driver(module, tmp_path, monkeypatch, case):
    output = tmp_path / "items.json"
    state = tmp_path / "seen.json"
    config = tmp_path / "source.yml"
    config.write_text("sources: []")
    source = SourceConfig({"id": "fixture", "name": "Fixture", "url": "https://example.org",
                           "enabled": True, "parser": "rss"})
    second = SourceConfig({"id": "failed", "name": "Failed", "url": "https://example.org",
                           "enabled": True, "parser": "html"})
    recent, old, unknown = raw_item(), raw_item(1), raw_item(2)
    old.published_at -= timedelta(days=30)
    unknown.published_at = None
    unknown.first_seen_at = datetime.now(timezone.utc)
    unknown.date_precision = "unknown"
    sources = [source, second] if case == "partial" else [source]
    def load(path):
        from pathlib import Path
        if not Path(path).exists():
            raise FileNotFoundError(path)
        return sources
    monkeypatch.setattr(module, "load_sources", load)
    parser = Mock()
    def parse(selected, **kwargs):
        if case == "all_failed" or selected.id == "failed":
            raise RuntimeError("offline timeout")
        return [] if case == "empty" else [recent, old, unknown]
    parser.parse.side_effect = parse
    monkeypatch.setattr(module, "get_parser", lambda _: parser)
    args = ["fetch", "--config", str(config), "--output", str(output)]
    if case == "missing_config":
        args[2] = str(tmp_path / "missing.yml")
    if case == "replay":
        args += ["--state-file", str(state)]
    monkeypatch.setattr(sys, "argv", args)
    result = module.main()
    if case == "missing_config":
        assert result == 1
        return
    assert result == (1 if case == "all_failed" else 0)
    payload = json.loads(output.read_text())
    status = payload["meta"]["status"]
    assert status == {"all_failed": "failed", "partial": "partial", "empty": "no_new"}.get(case, "success")
    assert {i["id"] for i in payload["items"]} == (set() if case in {"all_failed", "empty"} else {recent.id, unknown.id})
    assert json.loads(output.with_name("items_status.json").read_text())
    if case == "replay":
        saved = json.loads(state.read_text())
        first_seen = payload["items"][1]["first_seen_at"]
        unknown.first_seen_at += timedelta(days=1)
        parser.parse.side_effect = [[unknown]]
        assert module.main() == 0
        again = json.loads(output.read_text())
        assert {i["id"] for i in again["items"]} == {unknown.id}
        assert again["items"][0]["first_seen_at"] == first_seen
        assert saved


@pytest.mark.parametrize("case", ["normal", "empty", "all_failed", "partial", "missing_config", "replay"])
def test_vendor_collection(tmp_path, monkeypatch, case):
    exercise_driver(m, tmp_path, monkeypatch, case)


def exercise_entry_health(tmp_path, monkeypatch, parser_module, parser_type, case):
    from types import SimpleNamespace
    from xml.etree.ElementTree import Element, SubElement, tostring

    import source_driver
    from test_vendor_parsers import client_factory

    now = datetime.now(timezone.utc)
    good = {"id": "good", "title": "Security report", "url": "https://example.org/report/good",
            "date": now.isoformat()}
    bad = {**good, "id": "bad", "url": "https://example.org/report/bad", "date": "invalid date"}
    if case in {"old", "partial_old"}:
        good["date"] = (now - timedelta(days=30)).isoformat()
    if case == "unknown":
        good.pop("date")
    entries = {
        "empty": [], "all_bad": [bad], "partial": [good, bad], "partial_old": [good, bad],
        "old": [good], "unknown": [good], "limited": [good, bad],
        "nonobject": [good, None, "not an entry"], "missing_title": [good, {"id": "no-title"}],
    }[case]
    if parser_type == "rss":
        rss = Element("rss", version="2.0")
        channel = SubElement(rss, "channel")
        for key, value in {"title": "Reports", "link": "https://example.org",
                           "description": "Security reports"}.items():
            SubElement(channel, key).text = value
        for entry in entries:
            item = SubElement(channel, "item")
            for key, field in (("title", "title"), ("url", "link"), ("id", "guid"), ("date", "pubDate")):
                if entry.get(key):
                    SubElement(item, field).text = entry[key]
        body = tostring(rss, encoding="unicode")
    else:
        body = json.dumps({"items": entries})
    monkeypatch.setattr(parser_module, "httpx", SimpleNamespace(Client=client_factory(body, [])))
    source = SourceConfig({"id": "fixture", "name": "Fixture", "url": "https://example.org/feed",
                           "enabled": True, "parser": parser_type})
    output, state = tmp_path / "items.json", tmp_path / "seen.json"
    previous = {"keep": {"at": (now - timedelta(days=20)).isoformat(), "source": source.id}}
    state.write_text(json.dumps({"first_seen": previous}))
    args = SimpleNamespace(days=1, limit_per_source=1 if case == "limited" else 50,
                           workers=1, source=None, state_file=state, output=output, dry_run=False)
    result = source_driver.collect_sources(args, [source], parser_module.get_parser)
    payload = json.loads(output.read_text())
    child = json.loads(output.with_name("items_status.json").read_text())[0]
    errors = json.loads(output.with_name("items_errors.json").read_text())
    expected_status = {
        "empty": "no_new", "old": "no_new", "all_bad": "failed",
        "partial": "partial", "partial_old": "partial", "nonobject": "partial",
        "missing_title": "partial",
    }.get(case, "success")
    expected_errors = 2 if case == "nonobject" else int(
        case in {"all_bad", "partial", "partial_old", "missing_title"})
    attempted = 1 if case == "limited" else len(entries)
    assert result == int(expected_status == "failed")
    assert payload["meta"]["status"] == child["status"] == expected_status
    assert child["fetched_count"] == len(entries)
    assert child["attempted_count"] == attempted
    assert child["parsed_count"] == attempted - expected_errors
    assert child["error_count"] == payload["meta"]["error_count"] == len(errors) == expected_errors
    assert child["errors"] == errors
    assert payload["meta"]["failed_count"] == int(expected_status == "failed")
    assert payload["meta"]["partial_count"] == int(expected_status == "partial")
    assert child["item_count"] == len(payload["items"]) == int(
        case not in {"empty", "all_bad", "old", "partial_old"})
    if errors:
        assert all(error["source_id"] == source.id for error in errors)
        assert [error["entry_index"] for error in errors] == (
            [0] if case == "all_bad" else [1, 2] if case == "nonobject" else [1])
        assert all(error["error_type"] for error in errors)
    saved = json.loads(state.read_text())["first_seen"]
    assert saved["keep"] == previous["keep"]
    assert all(not item_id.endswith(":bad") and not item_id.endswith(":no-title") for item_id in saved)
    if case == "all_bad":
        assert saved == previous
    from run_pipeline import source_status
    pipeline_status, details, usable = source_status(output, result == 0)
    assert pipeline_status == expected_status
    assert details["errors"] == errors
    assert usable == (expected_status != "failed")
    print(json.dumps({"parser": f"{parser_module.__name__}.{parser_type}", "case": case,
                      "exit_code": result, "status": expected_status,
                      "fetched_count": child["fetched_count"], "attempted_count": attempted,
                      "parsed_count": child["parsed_count"], "item_count": child["item_count"],
                      "error_count": expected_errors, "errors": errors}, ensure_ascii=True))
    return payload, child, errors


@pytest.mark.parametrize("parser_type,case", [
    (parser_type, case) for parser_type in ("rss", "api")
    for case in ("empty", "all_bad", "partial", "old", "partial_old", "unknown", "limited")
] + [("api", "nonobject"), ("api", "missing_title")])
def test_vendor_entry_health(tmp_path, monkeypatch, parser_type, case):
    from parsers import vendor_advisory_parsers
    exercise_entry_health(tmp_path, monkeypatch, vendor_advisory_parsers, parser_type, case)


@pytest.mark.parametrize("other_failed", [False, True])
def test_aggregate_partial_parser_health_without_recent_items(tmp_path, other_failed):
    from types import SimpleNamespace
    from fetch_result import FetchBatch
    from source_driver import collect_sources

    first = SourceConfig({"id": "partial", "name": "Partial", "url": "https://example.org"})
    second = SourceConfig({"id": "other", "name": "Other", "url": "https://example.org"})
    old = raw_item()
    old.published_at -= timedelta(days=30)
    error = {"source_id": first.id, "entry_index": 1, "error_type": "ParserError"}
    def parse(source, **kwargs):
        if source.id == second.id:
            if other_failed:
                raise RuntimeError("source unavailable")
            return []
        return FetchBatch([old], fetched_count=2, attempted_count=2, parsed_count=1, errors=[error])
    output = tmp_path / "items.json"
    args = SimpleNamespace(days=1, limit_per_source=20, workers=2, source=None,
                           state_file=None, output=output, dry_run=False)
    assert collect_sources(args, [first, second], lambda _: SimpleNamespace(parse=parse)) == 0
    payload = json.loads(output.read_text())
    errors = json.loads(output.with_name("items_errors.json").read_text())
    assert payload["meta"]["status"] == "partial"
    assert payload["items"] == []
    assert errors[0] == error
    assert len(errors) == 1 + int(other_failed)
