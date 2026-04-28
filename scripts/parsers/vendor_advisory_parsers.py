import logging
import feedparser
import httpx
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from dateutil import parser as date_parser
from typing import List, Dict, Any, Optional
import re
from urllib.parse import urljoin
import hashlib

from models import RawItem, ItemType, SourceInfo, RiskSignal
from source_registry import SourceConfig

logger = logging.getLogger(__name__)

def extract_cves(text: str) -> List[str]:
    if not text:
        return []
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return list(set(cve.upper() for cve in cves))

class BaseParser:
    def parse(self, source: SourceConfig, limit: int = 20) -> List[RawItem]:
        raise NotImplementedError

class RssParser(BaseParser):
    def parse(self, source: SourceConfig, limit: int = 20) -> List[RawItem]:
        items = []
        try:
            feed = feedparser.parse(source.url)
            for entry in feed.entries[:limit]:
                pub_date = None
                if hasattr(entry, "published"):
                    pub_date = date_parser.parse(entry.published)
                elif hasattr(entry, "updated"):
                    pub_date = date_parser.parse(entry.updated)
                else:
                    pub_date = datetime.now(timezone.utc)
                
                if pub_date.tzinfo is None:
                    pub_date = pub_date.replace(tzinfo=timezone.utc)

                title = entry.get("title", "No Title")
                link = entry.get("link", source.url)
                summary = entry.get("summary", "")
                if summary:
                    summary = BeautifulSoup(summary, "html.parser").get_text()[:4000]

                cves = extract_cves(title + " " + summary)
                native_id = hashlib.md5(link.encode()).hexdigest()[:16]
                item_id = f"vendor:{source.id}:{native_id}"

                item = RawItem(
                    id=item_id,
                    type=ItemType.ADVISORY,
                    source_info=SourceInfo(
                        source="vendor",
                        source_sub=source.id,
                        source_name=source.name,
                        source_url=link,
                        native_id=native_id
                    ),
                    title=title,
                    summary=summary,
                    published_at=pub_date,
                    fetched_at=datetime.now(timezone.utc),
                    cves=cves,
                    vendors=[source.name],
                    topics=source.tags,
                    lang="zh" if source.region == "CN" else "en"
                )
                items.append(item)
        except Exception as e:
            logger.error(f"RSS parse failed for {source.id}: {e}")
        return items

class ApiParser(BaseParser):
    def parse(self, source: SourceConfig, limit: int = 20) -> List[RawItem]:
        items = []
        try:
            headers = {"User-Agent": "CyberSecurityDailyRadar/1.0"}
            with httpx.Client(verify=False, timeout=10.0, follow_redirects=True) as client:
                resp = client.get(source.url, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            
            entries = []
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                entries = data.get("value", []) or data.get("items", []) or data.get("data", []) or data.get("updates", [])

            for entry in entries[:limit]:
                title = entry.get("Title") or entry.get("title") or entry.get("name") or "No Title"
                pub_date_str = entry.get("PublishedDate") or entry.get("publishedAt") or entry.get("date") or entry.get("published")
                pub_date = date_parser.parse(pub_date_str) if pub_date_str else datetime.now(timezone.utc)
                if pub_date.tzinfo is None:
                    pub_date = pub_date.replace(tzinfo=timezone.utc)
                
                link = entry.get("Url") or entry.get("url") or entry.get("link") or source.url
                summary = entry.get("Summary") or entry.get("summary") or entry.get("description") or ""
                
                cves = extract_cves(title + " " + summary)
                if "Cves" in entry and isinstance(entry["Cves"], list):
                    cves.extend(entry["Cves"])
                cves = list(set(cves))

                native_id = entry.get("Id") or entry.get("id") or hashlib.md5(link.encode()).hexdigest()[:16]
                item_id = f"vendor:{source.id}:{native_id}"

                item = RawItem(
                    id=item_id,
                    type=ItemType.ADVISORY,
                    source_info=SourceInfo(
                        source="vendor",
                        source_sub=source.id,
                        source_name=source.name,
                        source_url=link,
                        native_id=str(native_id)
                    ),
                    title=title,
                    summary=summary[:4000] if summary else "",
                    published_at=pub_date,
                    fetched_at=datetime.now(timezone.utc),
                    cves=cves,
                    vendors=[source.name],
                    topics=source.tags,
                    lang="zh" if source.region == "CN" else "en"
                )
                items.append(item)
        except Exception as e:
            logger.error(f"API parse failed for {source.id}: {e}")
        return items

class HtmlParser(BaseParser):
    def parse(self, source: SourceConfig, limit: int = 20) -> List[RawItem]:
        items = []
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            with httpx.Client(verify=False, timeout=10.0, follow_redirects=True) as client:
                resp = client.get(source.url, headers=headers)
                resp.raise_for_status()
                soup = BeautifulSoup(resp.text, "html.parser")
            
            # Use generic heuristic parser for HTML pages
            links = soup.find_all("a", href=True)
            seen_titles = set()
            
            for a in links:
                if len(items) >= limit:
                    break
                    
                title = a.get_text(strip=True)
                href = a['href']
                
                # Heuristics: title should be long enough, href shouldn't be javascript or #
                if len(title) < 15 or "javascript:" in href or href.startswith("#"):
                    continue
                if title in seen_titles:
                    continue
                    
                full_url = urljoin(source.url, href)
                seen_titles.add(title)
                
                cves = extract_cves(title)
                pub_date = datetime.now(timezone.utc)
                
                native_id = hashlib.md5(full_url.encode()).hexdigest()[:16]
                item_id = f"vendor:{source.id}:{native_id}"
                
                item = RawItem(
                    id=item_id,
                    type=ItemType.ADVISORY,
                    source_info=SourceInfo(
                        source="vendor",
                        source_sub=source.id,
                        source_name=source.name,
                        source_url=full_url,
                        native_id=str(native_id)
                    ),
                    title=title,
                    summary="",
                    published_at=pub_date,
                    fetched_at=datetime.now(timezone.utc),
                    cves=cves,
                    vendors=[source.name],
                    topics=source.tags,
                    lang="zh" if source.region == "CN" else "en"
                )
                items.append(item)
                
        except Exception as e:
            logger.error(f"HTML parse failed for {source.id}: {e}")
        return items

def get_parser(parser_type: str) -> BaseParser:
    if parser_type == "rss":
        return RssParser()
    elif parser_type == "api":
        return ApiParser()
    elif parser_type == "html":
        return HtmlParser()
    else:
        return BaseParser()
