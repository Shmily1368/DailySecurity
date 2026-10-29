from unittest.mock import patch

import feedparser
import httpx
import pytest

from parsers import vendor_advisory_parsers as m


@pytest.mark.parametrize("text, expected", [
    ("CVE-2026-12345678 cve-2026-12345678", ["CVE-2026-12345678"]),
    ("XCVE-2026-12345suffix", []),
    ("CVE-2026-1234", ["CVE-2026-1234"]),
    ("", []),
])
def test_extract_cves(text, expected):
    assert sorted(m.extract_cves(text)) == expected


@pytest.mark.parametrize("scenario", ["normal", "guids", "http_failure", "malformed_feed"])
def test_rss(source, scenario):
    entries = [feedparser.FeedParserDict(
        title=f"Security update {i}", id=f"guid-{i}",
        published="2026-10-29T00:00:00Z", summary="<p>Source evidence</p>",
        **({"link": f"https://example.org/security/{i}"} if scenario != "guids" else {}),
    ) for i in range(2)]
    feed = feedparser.FeedParserDict(entries=entries, status=200, bozo=False)
    if scenario == "http_failure":
        feed["status"] = 503
    if scenario == "malformed_feed":
        feed["bozo"] = True
        feed["bozo_exception"] = ValueError("invalid feed")
    with patch.object(m, "httpx") as client_module, patch.object(m.feedparser, "parse", return_value=feed):
        options = []
        client_module.Client.side_effect = client_factory("", options)
        if scenario in {"http_failure", "malformed_feed"}:
            with pytest.raises(Exception):
                m.RssParser().parse(source)
        else:
            items = m.RssParser().parse(source)
            assert len(items) == 2
            assert len({i.id for i in items}) == 2
            assert items[0].summary == "Source evidence"
            assert options[0]["timeout"] == 15.0
            assert options[0].get("verify", True)


def client_factory(body, options, status=200):
    def factory(**kwargs):
        options.append(kwargs)
        return httpx.Client(transport=httpx.MockTransport(
            lambda request: httpx.Response(status, text=body, request=request)
        ))
    return factory


@pytest.mark.parametrize("scenario", ["article", "navigation", "failure", "tls"])
def test_html(source, scenario):
    body = """<nav><a href="https://beian.miit.gov.cn/">京ICP证080047号[京ICP备08010314号-6]</a>
    <a href="/privacy/websites/cookie-settings/">Cookie settings</a></nav>
    <article><h2><a href="/security/2020/notice-42">Security advisory about an affected product</a></h2>
    <time datetime="2020-01-02T03:04:05Z"></time></article>"""
    options = []
    # Patch only the parser namespace, leaving the real HTTPX client usable.
    real_factory = client_factory(body, options, 503 if scenario == "failure" else 200)
    with patch.object(m, "httpx") as client_module:
        client_module.Client.side_effect = real_factory
        if scenario == "failure":
            with pytest.raises(httpx.HTTPStatusError):
                m.HtmlParser().parse(source)
        else:
            items = m.HtmlParser().parse(source)
            if scenario == "article":
                assert len(items) == 1
                assert items[0].published_at.year == 2020
            elif scenario == "navigation":
                assert all("beian" not in str(i.source_info.source_url) for i in items)
                assert all("cookie" not in i.title.lower() for i in items)
            else:
                assert all(o.get("verify", True) is not False for o in options)


@pytest.mark.parametrize("scenario", ["normal", "failure", "tls"])
def test_api(source, scenario):
    options = []
    body = '[{"Id":"42","title":"Security update","date":"2026-10-29","url":"https://example.org/security/42"}]'
    with patch.object(m, "httpx") as client_module:
        client_module.Client.side_effect = client_factory(body, options, 503 if scenario == "failure" else 200)
        if scenario == "failure":
            with pytest.raises(httpx.HTTPStatusError):
                m.ApiParser().parse(source)
        else:
            items = m.ApiParser().parse(source)
            if scenario == "normal":
                assert len(items) == 1
                assert items[0].source_info.native_id == "42"
            else:
                assert all(o.get("verify", True) is not False for o in options)


def test_html_revision_date_is_not_publication():
    from source_registry import SourceConfig
    source = SourceConfig({
        "id": "oracle", "name": "Oracle", "url": "https://example.org/security/",
        "article_selector": "table td:first-child a[href]",
        "article_container_selector": "table tr",
        "article_date_selector": "td:last-child", "article_date_field": "updated_at",
    })
    body = """<article><table>
    <tr><th>Critical Patch Update</th><th>Latest Version/Date</th></tr>
    <tr><td><a href="/security/cpujul2026.html">Critical Patch Update - July 2026</a></td>
    <td><time datetime="2026-07-01"></time>Rev 7, 20 August 2026</td></tr>
    <tr><td><a href="/security/cpuapr2026.html">Critical Patch Update - April 2026</a></td>
    <td>Unknown revision date</td></tr>
    </table></article>"""
    with patch.object(m, "httpx") as client_module:
        client_module.Client.side_effect = client_factory(body, [])
        items = m.HtmlParser().parse(source)
    assert items[0].published_at is None
    assert items[0].updated_at.isoformat() == "2026-08-20T00:00:00+00:00"
    assert items[0].date_precision == "unknown"
    assert items[1].published_at is items[1].updated_at is None


@pytest.mark.parametrize("excluded", [
    '<div role="navigation"><a href="/security">Security</a></div>',
    '<div role="banner"><a href="/security">Security</a></div>',
    '<ul class="devsite-breadcrumb-list"><li><a href="/security">Security</a></li></ul>',
    '<div id="breadcrumb"><a href="/security">Security</a></div>',
])
def test_html_excludes_navigation_inside_article(source, excluded):
    body = f"""<article>{excluded}
    <table><tr><td><a href="/security/bulletin/2026/2026-10-01">October 2026</a></td>
    <td>October 5, 2026</td></tr></table></article>"""
    with patch.object(m, "httpx") as client_module:
        client_module.Client.side_effect = client_factory(body, [])
        items = m.HtmlParser().parse(source)
    assert [item.title for item in items] == ["October 2026"]
    assert items[0].published_at.isoformat() == "2026-10-05T00:00:00+00:00"


def test_explicit_date_column_does_not_use_patch_level():
    from source_registry import SourceConfig
    source = SourceConfig({
        "id": "android", "name": "Android", "url": "https://example.org/security/",
        "article_selector": "table td:first-child a[href]",
        "article_container_selector": "table tr", "article_date_selector": "td:nth-child(3)",
    })
    body = """<article><table><tr>
    <td><a href="/security/bulletin/2026/2026-10-01">October 2026</a></td>
    <td>Languages</td><td>Unavailable</td><td>2026-10-01</td>
    </tr></table></article>"""
    with patch.object(m, "httpx") as client_module:
        client_module.Client.side_effect = client_factory(body, [])
        item = m.HtmlParser().parse(source)[0]
    assert item.published_at is None
    assert item.date_precision == "unknown"


def test_html_requires_configured_container(source):
    source.article_selector = "article a[href]"
    source.article_container_selector = ".report"
    body = """<article><a href="/security/other">Unrelated security navigation</a></article>"""
    with patch.object(m, "httpx") as client_module:
        client_module.Client.side_effect = client_factory(body, [])
        with pytest.raises(ValueError, match="No recognizable"):
            m.HtmlParser().parse(source)
