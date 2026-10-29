"""Shared source parsing rules; unknown dates stay unknown."""
import hashlib
import logging
import re
from datetime import datetime, timezone, timedelta
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from dateutil import parser as date_parser

from fetch_result import FetchBatch
from models import ItemType, RawItem, SourceInfo

logger = logging.getLogger(__name__)


def parse_entries(source, entries, parse_entry, limit):
    """Keep entry failures separate from genuinely empty upstream lists."""
    items, errors = [], []
    selected = entries[:limit]
    for index, entry in enumerate(selected):
        try:
            if not isinstance(entry, dict):
                raise TypeError("Entry must be an object")
            items.append(parse_entry(entry))
        except (ValueError, TypeError, OverflowError) as exc:
            error = {"source_id": source.id, "entry_index": index,
                     "error_type": type(exc).__name__}
            if isinstance(entry, dict):
                identity = next((entry.get(k) for k in ("id", "Id", "guid", "link", "url")
                                 if entry.get(k)), None)
                if identity is not None:
                    error["entry_id"] = str(identity)
            errors.append(error)
            logger.warning("Invalid entry %s in %s: %s", index, source.id, type(exc).__name__)
    return FetchBatch(items, fetched_count=len(entries), attempted_count=len(selected),
                      parsed_count=len(items), errors=errors)


def extract_cves(text):
    return sorted({c.upper() for c in re.findall(r"\bCVE-\d{4}-\d{4,}\b", text or "", re.I)})


def parse_date(value, default_timezone=timezone.utc):
    if not value:
        return None
    dt = date_parser.parse(str(value))
    return dt if dt.tzinfo else dt.replace(tzinfo=default_timezone)


def clean_text(value):
    return BeautifulSoup(str(value or ""), "html.parser").get_text(" ", strip=True)[:4000]


def check_feed(feed):
    if feed.get("status", 200) >= 400:
        raise RuntimeError(f"RSS HTTP {feed.get('status')}")
    if feed.get("bozo"):
        raise RuntimeError(f"Malformed RSS: {type(feed.get('bozo_exception')).__name__}")
    if "entries" not in feed:
        raise ValueError("RSS entries missing")


def make_item(source, title, link, summary="", date=None, native_id=None, channel="vendor", **kwargs):
    now = datetime.now(timezone.utc)
    native_id = str(native_id or hashlib.sha256(link.encode()).hexdigest()[:16])
    prefix = "vendor" if channel == "vendor" else "ti"
    published_at = date
    if source.article_date_field == "updated_at":
        published_at = None
        kwargs["updated_at"] = date
    return RawItem(
        id=f"{prefix}:{source.id}:{native_id}",
        type=ItemType.ADVISORY if channel == "vendor" else ItemType.THREAT_REPORT,
        source_info=SourceInfo(
            source=channel, source_sub=source.id, source_name=source.name,
            source_url=link, native_id=native_id,
            source_quality=source.source_quality,
            link_kind="feed" if link == source.url else "article",
        ),
        title=title, summary=summary, published_at=published_at, fetched_at=now,
        first_seen_at=now, date_precision="exact" if published_at else "unknown",
        cves=extract_cves(title + " " + summary),
        vendors=[source.name] if channel == "vendor" else [],
        topics=source.tags, lang="zh" if source.region == "CN" else "en", **kwargs,
    )


def article_links(soup, source):
    """Require an article container or an explicitly configured detail URL."""
    selector = getattr(source, "article_selector", None)
    pattern = getattr(source, "article_url_pattern", None)
    container_selector = getattr(source, "article_container_selector", None)
    container_ids = {id(node) for node in soup.select(container_selector)} if container_selector else set()
    excluded_ids = {id(node) for node in soup.select(
        "nav, footer, header, aside, [role='navigation'], [role='banner'], "
        "[class*='breadcrumb'], [id*='breadcrumb']"
    )}
    base_host = urlparse(source.url).hostname
    for a in soup.select(selector or "article a[href], [itemtype*='Article'] a[href], tr a[href]"):
        if not a.get("href") or id(a) in excluded_ids or any(id(p) in excluded_ids for p in a.parents):
            continue
        link = urljoin(source.url, a["href"])
        parsed = urlparse(link)
        if parsed.scheme not in {"https", "http"} or parsed.hostname != base_host:
            continue
        if link.rstrip("/") == source.url.rstrip("/"):
            continue
        if re.search(r"(?:privacy|cookie|login|signup|contact|about|search|beian)", parsed.path, re.I):
            continue
        if pattern and not re.search(pattern, parsed.path):
            continue
        title = a.get_text(" ", strip=True)
        if len(title) < 8:
            continue
        title_pattern = getattr(source, "article_title_pattern", None)
        if title_pattern and not re.search(title_pattern, title, re.I):
            continue
        container = (next((p for p in a.parents if id(p) in container_ids), None)
                     if container_selector else a.find_parent(["tr", "li", "article"]))
        if container_selector and container is None:
            continue
        container = container or a.parent
        date_selector = getattr(source, "article_date_selector", None)
        if date_selector:
            date_tag = container.select_one(date_selector)
            date_value = date_tag.get_text(" ", strip=True) if date_tag else None
        else:
            time_tag = container.find("time")
            date_value = time_tag.get("datetime") or time_tag.get_text() if time_tag else None
        heading = getattr(source, "article_date_heading", None)
        if not date_selector and not date_value and heading:
            heading_tag = a.find_previous(heading)
            date_value = heading_tag.get_text(" ", strip=True) if heading_tag else None
        # An explicit date column must not fall back to unrelated row dates.
        if date_selector or not date_value:
            month = r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
            date_match = re.search(
                rf"\b(?:\d{{4}}[-/]\d{{1,2}}[-/]\d{{1,2}}|{month}\s+\d{{1,2}},?\s+\d{{4}}|\d{{1,2}}\s+{month}\s+\d{{4}})\b",
                date_value or ("" if date_selector else container.get_text(" ")), re.I)
            date_value = date_match.group(0) if date_match else None
        try:
            date = parse_date(date_value, timezone(timedelta(hours=8)) if source.region == "CN" else timezone.utc)
        except (ValueError, OverflowError):
            date = None
        yield title, link, date
