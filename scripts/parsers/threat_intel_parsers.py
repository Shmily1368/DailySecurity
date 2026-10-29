import re

import feedparser
import httpx
from bs4 import BeautifulSoup

from models import ThreatMeta
from parsers.common import article_links, check_feed, clean_text, extract_cves, make_item, parse_date, parse_entries


def extract_threat_keywords(text):
    actors = []
    families = []
    for pattern in [r"\bapt\d+\b", "lazarus", r"volt\s*typhoon", "muddywater", "sandworm",
                    r"fancy\s*bear", r"cozy\s*bear", r"equation\s*group"]:
        for match in re.findall(pattern, text.lower()):
            actors.append(match.upper() if match.startswith("apt") else match.title())
    for pattern in ["lockbit", "blackcat", "clop", "conti", "revil", "ryuk", "qakbot",
                    "emotet", "trickbot", r"cobalt\s*strike"]:
        families.extend(m.title() for m in re.findall(pattern, text.lower()))
    return {
        "threat_actors": sorted(set(actors)),
        "malware_families": sorted(set(families)),
        "attack_techniques": sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text))),
        "iocs_present": bool(re.search(r"\b(?:ioc|iocs|sha256|yara)\b|indicators of compromise", text, re.I)),
    }


def threat_item(source, title, link, summary="", date=None, native_id=None):
    meta = extract_threat_keywords(title + " " + summary)
    item = make_item(source, title, link, summary, date, native_id=native_id,
                     channel="threat_intel", threat_meta=ThreatMeta(**meta))
    item.topics = sorted(set(item.topics + [a.lower() for a in meta["threat_actors"] + meta["malware_families"]]))
    return item


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
            link = entry.get("link") or source.url
            return threat_item(
                source, entry.get("title") or "Untitled threat report", link,
                clean_text(entry.get("summary")),
                parse_date(entry.get("published") or entry.get("updated")),
                native_id=entry.get("id") or entry.get("guid") or link,
            )
        return parse_entries(source, feed.entries, parse_entry, limit)


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
            items.append(threat_item(source, title, link, date=date))
            if len(items) >= limit:
                break
        if not items:
            raise ValueError("No recognizable report entries in HTML source")
        return items


def get_parser(parser_type):
    return {"rss": RssParser, "html": HtmlParser}.get(parser_type, BaseParser)()
