from unittest.mock import patch

import feedparser
import httpx
import pytest

from parsers import threat_intel_parsers as m
from test_vendor_parsers import client_factory


@pytest.mark.parametrize("text,expected", [
    ("CVE-2026-12345678", ["CVE-2026-12345678"]),
    ("XCVE-2026-12345suffix", []),
    ("cve-2026-1234", ["CVE-2026-1234"]),
    ("", []),
])
def test_extract_cves(text, expected):
    assert sorted(m.extract_cves(text)) == expected


@pytest.mark.parametrize("scenario", ["normal", "guids", "bad_entry", "failure"])
def test_rss(source, scenario):
    entries = [feedparser.FeedParserDict(
        title=f"APT29 threat report {i}", id=f"report-{i}",
        published="invalid date" if scenario == "bad_entry" and i == 0 else "2026-10-29T00:00:00Z",
        summary="<p>LockBit T1059.001 YARA</p>",
        **({"link": f"https://example.org/report/{i}"} if scenario != "guids" else {}),
    ) for i in range(2)]
    feed = feedparser.FeedParserDict(entries=entries, status=503 if scenario == "failure" else 200, bozo=False)
    with patch.object(m, "httpx") as client_module, patch.object(m.feedparser, "parse", return_value=feed):
        options = []
        client_module.Client.side_effect = client_factory("", options)
        if scenario == "failure":
            with pytest.raises(Exception):
                m.RssParser().parse(source)
        else:
            items = m.RssParser().parse(source)
            assert len(items) == (1 if scenario == "bad_entry" else 2)
            assert items.meta["fetched_count"] == items.meta["attempted_count"] == 2
            assert items.meta["parsed_count"] == len(items)
            assert len(items.meta["errors"]) == (1 if scenario == "bad_entry" else 0)
            if scenario == "bad_entry":
                assert items.meta["errors"][0] == {
                    "source_id": source.id, "entry_index": 0,
                    "entry_id": "report-0", "error_type": "ParserError",
                }
            assert len({i.id for i in items}) == len(items)
            assert items[-1].threat_meta.iocs_present
            assert "T1059.001" in items[-1].threat_meta.attack_techniques
            assert options[0]["timeout"] == 15.0
            assert options[0].get("verify", True)


@pytest.mark.parametrize("scenario", ["article", "failure", "tls"])
def test_html(source, scenario):
    body = """<nav><a href="/privacy/cookie-settings/">Privacy and cookie settings</a></nav>
    <article><a href="/report/42">APT29 activity report with defensive findings</a>
    <time datetime="2020-01-02"></time></article>"""
    options = []
    with patch.object(m, "httpx") as client_module:
        client_module.Client.side_effect = client_factory(body, options, 503 if scenario == "failure" else 200)
        if scenario == "failure":
            with pytest.raises(httpx.HTTPStatusError):
                m.HtmlParser().parse(source)
        else:
            items = m.HtmlParser().parse(source)
            if scenario == "article":
                assert len(items) == 1
                assert items[0].published_at.year == 2020
            else:
                assert all(o.get("verify", True) is not False for o in options)


@pytest.mark.parametrize("text,actor,family", [
    ("APT29 deploys LockBit. T1059.001 and YARA", "APT29", "Lockbit"),
    ("Lazarus using Qakbot", "Lazarus", "Qakbot"),
])
def test_threat_keywords(text, actor, family):
    meta = m.extract_threat_keywords(text)
    assert actor in meta["threat_actors"]
    assert family in meta["malware_families"]
