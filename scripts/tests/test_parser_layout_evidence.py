"""Replay captured production HTML with the checked-in source selectors."""
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from bs4 import BeautifulSoup

from parsers import threat_intel_parsers as threat, vendor_advisory_parsers as vendor
from source_registry import load_sources
from test_vendor_parsers import client_factory

REPO = Path(__file__).resolve().parents[2]


def evidence_path(source_id):
    evidence = os.environ.get("PARSER_EVIDENCE_DIR")
    if not evidence:
        pytest.skip("PARSER_EVIDENCE_DIR required for production replay")
    if source_id == "android_security":
        overview = os.environ.get("PARSER_ANDROID_EVIDENCE")
        if not overview:
            pytest.skip("PARSER_ANDROID_EVIDENCE required for Android bulletin table")
        return Path(overview)
    return Path(evidence) / f"{source_id}.html"


@pytest.mark.parametrize("channel,source_id", [
    ("vendor_advisories", "apple_security"), ("vendor_advisories", "mozilla_advisories"),
    ("vendor_advisories", "knownsec_seebug"), ("vendor_advisories", "tencent_cloud_advisory"),
    ("vendor_advisories", "oracle_cpu"), ("vendor_advisories", "android_security"),
    ("threat_intel", "cncert_report"), ("threat_intel", "crowdstrike"),
    ("threat_intel", "xianzhi"), ("threat_intel", "kanxue"),
])
def test_production_html_selectors(monkeypatch, channel, source_id):
    from urllib.parse import urlparse

    path = evidence_path(source_id)
    source = next(s for s in load_sources(REPO / "config/sources" / f"{channel}.yml")
                  if s.id == source_id)
    assert source.enabled and source.parser == "html"
    assert source.article_selector and source.article_selector != "a[href]"
    assert source.article_url_pattern
    body = path.read_text()
    module = vendor if channel == "vendor_advisories" else threat
    monkeypatch.setattr(module, "httpx", SimpleNamespace(Client=client_factory(body, [])))
    items = module.HtmlParser().parse(source, limit=50)
    assert items
    assert len({str(item.source_info.source_url) for item in items}) == len(items)
    assert all(re.search(source.article_url_pattern, urlparse(str(item.source_info.source_url)).path)
               for item in items)
    assert all(item.source_info.link_kind == "article" for item in items)
    if source_id == "oracle_cpu":
        july = next(i for i in items if str(i.source_info.source_url).endswith("cpujul2026.html"))
        assert july.published_at is None and july.date_precision == "unknown"
        assert july.updated_at.isoformat() == "2026-08-20T00:00:00+00:00"
        assert all(i.published_at is None and i.updated_at for i in items)
    elif source_id == "android_security":
        october = next(i for i in items if str(i.source_info.source_url).endswith("2026/2026-10-01"))
        assert october.published_at.isoformat() == "2026-10-05T00:00:00+00:00"
        assert all(i.title != "Security" and i.published_at for i in items)
    elif source_id in {"xianzhi", "kanxue"}:
        expected = "/news/92968" if source_id == "xianzhi" else "/thread-293304.htm"
        assert any(str(i.source_info.source_url).endswith(expected) for i in items)
        assert all(i.published_at is None and i.date_precision == "unknown" for i in items)
    elif source_id != "knownsec_seebug":
        assert all(i.published_at for i in items)
    soup = BeautifulSoup(body, "html.parser")
    print(json.dumps({
        "source_id": source_id, "evidence": str(path),
        "selector_count": len(soup.select(source.article_selector)), "parsed_count": len(items),
        "published_count": sum(i.published_at is not None for i in items),
        "updated_count": sum(i.updated_at is not None for i in items),
        "unknown_count": sum(i.date_precision == "unknown" for i in items),
        "samples": [{"title": i.title, "url": str(i.source_info.source_url),
                     "published_at": i.published_at.isoformat() if i.published_at else None,
                     "updated_at": i.updated_at.isoformat() if i.updated_at else None}
                    for i in items[:2]],
    }, ensure_ascii=True))


def test_old_android_portal_is_not_an_advisory(monkeypatch):
    evidence_path("oracle_cpu")
    path = Path(os.environ["PARSER_EVIDENCE_DIR"]) / "android_security.html"
    source = next(s for s in load_sources(REPO / "config/sources/vendor_advisories.yml")
                  if s.id == "android_security")
    monkeypatch.setattr(vendor, "httpx", SimpleNamespace(Client=client_factory(path.read_text(), [])))
    with pytest.raises(ValueError, match="No recognizable"):
        vendor.HtmlParser().parse(source)


class ReplayDate(datetime):
    current = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        return cls.current.astimezone(tz) if tz else cls.current.replace(tzinfo=None)


@pytest.mark.parametrize("channel,source_id", [
    ("vendor_advisories", "oracle_cpu"), ("vendor_advisories", "android_security"),
    ("threat_intel", "xianzhi"), ("threat_intel", "kanxue"),
])
def test_production_html_driver_replay(monkeypatch, tmp_path, channel, source_id):
    import source_driver
    from run_pipeline import source_status

    path = evidence_path(source_id)
    source = next(s for s in load_sources(REPO / "config/sources" / f"{channel}.yml")
                  if s.id == source_id)
    module = vendor if channel == "vendor_advisories" else threat
    monkeypatch.setattr(module, "httpx", SimpleNamespace(Client=client_factory(path.read_text(), [])))
    monkeypatch.setattr(source_driver, "datetime", ReplayDate)
    ReplayDate.current = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
    output, state = tmp_path / "items.json", tmp_path / "seen.json"
    args = SimpleNamespace(days=1, limit_per_source=50, workers=3, source=None,
                           state_file=state, output=output, dry_run=False)
    try:
        assert source_driver.collect_sources(args, [source], module.get_parser) == 0
        first = json.loads(output.read_text())
        child = json.loads(output.with_name("items_status.json").read_text())[0]
        saved = json.loads(state.read_text())
        expected = "success" if source_id in {"xianzhi", "kanxue"} else "no_new"
        assert first["meta"]["status"] == child["status"] == expected
        assert child["parsed_count"] == {
            "oracle_cpu": 29, "android_security": 50, "xianzhi": 5, "kanxue": 28,
        }[source_id]
        assert child["item_count"] == (child["parsed_count"] if expected == "success" else 0)
        assert child["error_count"] == 0
        assert source_status(output, True)[0] == expected
        ReplayDate.current += timedelta(days=2)
        assert source_driver.collect_sources(args, [source], module.get_parser) == 0
        second = json.loads(output.read_text())
        assert second["meta"]["status"] == "no_new"
        assert second["items"] == []
        assert json.loads(state.read_text()) == saved
        print(json.dumps({
            "probe": "production_driver_replay", "source_id": source_id,
            "days": args.days, "limit_per_source": args.limit_per_source,
            "first_status": expected, "parsed_count": child["parsed_count"],
            "item_count": child["item_count"], "replay_after_hours": 48,
            "replay_status": second["meta"]["status"], "state_unchanged": True,
        }, ensure_ascii=True))
    finally:
        ReplayDate.current = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize("channel,source_id", [
    ("vendor_advisories", "msrc_advisory"), ("vendor_advisories", "cisco_psirt"),
    ("vendor_advisories", "gitlab_security"), ("vendor_advisories", "fortinet_psirt"),
    ("vendor_advisories", "palo_alto_advisories"),
    ("threat_intel", "freebuf"), ("threat_intel", "microsoft_ti"),
    ("threat_intel", "palo_alto_unit42"), ("threat_intel", "cisco_talos"),
    ("threat_intel", "eset_research"), ("threat_intel", "checkpoint_research"),
    ("threat_intel", "cloudflare_security"), ("threat_intel", "elastic_security_labs"),
    ("threat_intel", "sans_isc"),
])
def test_production_feed_api_health(monkeypatch, tmp_path, channel, source_id):
    import source_driver
    from run_pipeline import source_status

    path = evidence_path(source_id)
    source = next(s for s in load_sources(REPO / "config/sources" / f"{channel}.yml")
                  if s.id == source_id)
    assert source.enabled and source.parser in {"rss", "api"}
    module = vendor if channel == "vendor_advisories" else threat
    monkeypatch.setattr(module, "httpx", SimpleNamespace(Client=client_factory(path.read_text(), [])))
    monkeypatch.setattr(source_driver, "datetime", ReplayDate)
    output = tmp_path / "items.json"
    args = SimpleNamespace(days=1, limit_per_source=50, workers=3, source=None,
                           state_file=tmp_path / "seen.json", output=output, dry_run=False)
    result = source_driver.collect_sources(args, [source], module.get_parser)
    payload = json.loads(output.read_text())
    child = json.loads(output.with_name("items_status.json").read_text())[0]
    errors = json.loads(output.with_name("items_errors.json").read_text())
    if source_id == "cisco_psirt":
        # The captured HTTP 200 body is an HTML subscription page, not RSS.
        soup = BeautifulSoup(path.read_text(), "html.parser")
        assert soup.find("body") and not soup.find(["rss", "feed"])
        assert "RSS is a Web content syndication format" in soup.get_text(" ", strip=True)
        assert result == 1 and child["status"] == payload["meta"]["status"] == "failed"
        assert child["parsed_count"] == child["item_count"] == 0
        assert child["error_type"] == "RuntimeError"
        assert len(errors) == payload["meta"]["error_count"] == 1
        assert source_status(output, False)[0] == "failed"
        print(json.dumps({"probe": "production_feed_api_health", "captured_body": "html",
                          **child}, ensure_ascii=True))
        return
    assert result == 0
    assert child["status"] in {"success", "no_new"}
    assert child["parsed_count"] == child["attempted_count"] == min(50, child["fetched_count"])
    assert child["error_count"] == payload["meta"]["error_count"] == len(errors) == 0
    assert child["item_count"] == len(payload["items"])
    assert source_status(output, True)[0] == child["status"]
    print(json.dumps({"probe": "production_feed_api_health", **child}, ensure_ascii=True))
