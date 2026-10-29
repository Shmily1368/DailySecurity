import feedparser
import httpx

from bs4 import BeautifulSoup
from models import RiskSignal
from parsers.common import article_links, check_feed, clean_text, extract_cves, make_item, parse_date, parse_entries


class BaseParser:
    def parse(self, source, limit=20):
        raise NotImplementedError


class RssParser(BaseParser):
    def parse(self, source, limit=20):
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            response = client.get(source.url, headers={"User-Agent": "DailySecurity/1.0"})
            response.raise_for_status()
            feed = feedparser.parse(response.content)
        check_feed(feed)
        def parse_entry(entry):
            title = entry.get("title") or "Untitled security entry"
            link = entry.get("link") or source.url
            identity = entry.get("id") or entry.get("guid") or link
            date = parse_date(entry.get("published") or entry.get("updated"))
            return make_item(source, title, link, clean_text(entry.get("summary")),
                             date, native_id=identity)
        return parse_entries(source, feed.entries, parse_entry, limit)


class ApiParser(BaseParser):
    def parse(self, source, limit=20):
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            resp = client.get(source.url, headers={"User-Agent": "DailySecurity/1.0"})
            resp.raise_for_status()
            data = resp.json()
        entries = data if isinstance(data, list) else next(
            (data[k] for k in ("value", "items", "data", "updates") if k in data), None
        ) if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise ValueError("API article list missing")
        def parse_entry(entry):
            title = entry.get("cveTitle") or entry.get("Title") or entry.get("title") or entry.get("name")
            if not title:
                raise ValueError("API entry title missing")
            date_value = next((entry[k] for k in ("releaseDate", "PublishedDate", "publishedAt", "date", "published") if entry.get(k)), None)
            link = entry.get("Url") or entry.get("url") or entry.get("link")
            if not link and entry.get("cveNumber"):
                link = f"https://msrc.microsoft.com/update-guide/vulnerability/{entry['cveNumber']}"
            link = link or source.url
            text = next((entry[k] for k in ("unformattedDescription", "description", "Summary", "summary") if entry.get(k)), "")
            item = make_item(source, title, link, clean_text(text), parse_date(date_value),
                             native_id=entry.get("Id") or entry.get("id"))
            item.cves = sorted(set(item.cves + extract_cves(str(entry.get("cveNumber", "")) + " " + str(entry.get("Cves", "")))))
            severity = str(entry.get("severity", "")).lower()
            if severity in {"critical", "high", "medium", "low", "info"}:
                item.risk = RiskSignal(severity=severity)
            return item
        return parse_entries(source, entries, parse_entry, limit)


class HtmlParser(BaseParser):
    def parse(self, source, limit=20):
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            resp = client.get(source.url, headers={"User-Agent": "DailySecurity/1.0"})
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
        items, seen = [], set()
        for title, link, date in article_links(soup, source):
            if link in seen:
                continue
            seen.add(link)
            items.append(make_item(source, title, link, date=date))
            if len(items) >= limit:
                break
        # An unrecognized HTML layout is a parser failure, not proof of no new entries.
        if not items:
            raise ValueError("No recognizable article entries in HTML source")
        return items


def get_parser(parser_type):
    return {"rss": RssParser, "api": ApiParser, "html": HtmlParser}.get(parser_type, BaseParser)()
