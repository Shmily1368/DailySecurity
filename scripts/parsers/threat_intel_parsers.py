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

from models import RawItem, ItemType, SourceInfo, RiskSignal, ThreatMeta
from source_registry import SourceConfig

logger = logging.getLogger(__name__)

def extract_cves(text: str) -> List[str]:
    if not text:
        return []
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return list(set(cve.upper() for cve in cves))

def extract_threat_keywords(text: str) -> Dict[str, Any]:
    text_lower = text.lower()
    
    # 提取常见组织
    actors = []
    actor_patterns = [
        r"\bapt\d+\b", r"lazarus", r"volt\s*typhoon", r"muddywater", r"sandworm", r"fancy\s*bear", r"cozy\s*bear", r"equation\s*group"
    ]
    for p in actor_patterns:
        matches = re.findall(p, text_lower)
        if matches:
            for m in matches:
                # normalize
                actors.append(m.replace(" ", "").upper() if m.startswith("apt") else m.title())
                
    # 提取常见勒索软件和家族
    families = []
    family_patterns = [
        r"lockbit", r"blackcat", r"clop", r"conti", r"revil", r"ryuk", r"qakbot", r"emotet", r"trickbot", r"cobalt\s*strike"
    ]
    for p in family_patterns:
        matches = re.findall(p, text_lower)
        if matches:
            for m in matches:
                families.append(m.title())
                
    # MITRE ATT&CK
    techniques = []
    mitre_matches = re.findall(r"T\d{4}(?:\.\d{3})?", text)
    if mitre_matches:
        techniques.extend(mitre_matches)
        
    # IOC present heuristically
    iocs_present = False
    ioc_kws = ["indicators of compromise", "ioc", "iocs", "sha256", "yara"]
    for kw in ioc_kws:
        if kw in text_lower:
            iocs_present = True
            break
            
    return {
        "threat_actors": list(set(actors)),
        "malware_families": list(set(families)),
        "attack_techniques": list(set(techniques)),
        "iocs_present": iocs_present
    }

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

                combined_text = title + " " + summary
                cves = extract_cves(combined_text)
                extracted_meta = extract_threat_keywords(combined_text)
                
                native_id = hashlib.md5(link.encode()).hexdigest()[:16]
                item_id = f"ti:{source.id}:{native_id}"
                
                tags = list(source.tags)
                tags.extend([a.lower() for a in extracted_meta["threat_actors"]])
                tags.extend([f.lower() for f in extracted_meta["malware_families"]])
                tags = list(set(tags))

                item = RawItem(
                    id=item_id,
                    type=ItemType.THREAT_REPORT,
                    source_info=SourceInfo(
                        source="threat_intel",
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
                    topics=tags,
                    lang="zh" if source.region == "CN" else "en",
                    threat_meta=ThreatMeta(
                        threat_actors=extracted_meta["threat_actors"],
                        malware_families=extracted_meta["malware_families"],
                        attack_techniques=extracted_meta["attack_techniques"],
                        iocs_present=extracted_meta["iocs_present"]
                    )
                )
                # Currently we map these extra fields to topics and summary, as they are not native RawItem fields unless we add them
                items.append(item)
        except Exception as e:
            logger.error(f"RSS parse failed for {source.id}: {e}")
        return items

class HtmlParser(BaseParser):
    def parse(self, source: SourceConfig, limit: int = 20) -> List[RawItem]:
        items = []
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            with httpx.Client(verify=False, timeout=10.0, follow_redirects=True) as client:
                resp = client.get(source.url, headers=headers)
                resp.raise_for_status()
                soup = BeautifulSoup(resp.text, "html.parser")
            
            links = soup.find_all("a", href=True)
            seen_titles = set()
            
            for a in links:
                if len(items) >= limit:
                    break
                    
                title = a.get_text(strip=True)
                href = a['href']
                
                if len(title) < 15 or "javascript:" in href or href.startswith("#"):
                    continue
                if title in seen_titles:
                    continue
                    
                full_url = urljoin(source.url, href)
                seen_titles.add(title)
                
                cves = extract_cves(title)
                extracted_meta = extract_threat_keywords(title)
                pub_date = datetime.now(timezone.utc)
                
                native_id = hashlib.md5(full_url.encode()).hexdigest()[:16]
                item_id = f"ti:{source.id}:{native_id}"
                
                tags = list(source.tags)
                tags.extend([actor.lower() for actor in extracted_meta["threat_actors"]])
                tags = list(set(tags))
                
                item = RawItem(
                    id=item_id,
                    type=ItemType.THREAT_REPORT,
                    source_info=SourceInfo(
                        source="threat_intel",
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
                    topics=tags,
                    lang="zh" if source.region == "CN" else "en",
                    threat_meta=ThreatMeta(
                        threat_actors=extracted_meta["threat_actors"],
                        malware_families=extracted_meta["malware_families"],
                        attack_techniques=extracted_meta["attack_techniques"],
                        iocs_present=extracted_meta["iocs_present"]
                    )
                )
                items.append(item)
                
        except Exception as e:
            logger.error(f"HTML parse failed for {source.id}: {e}")
        return items

def get_parser(parser_type: str) -> BaseParser:
    if parser_type == "rss":
        return RssParser()
    elif parser_type == "html":
        return HtmlParser()
    else:
        return BaseParser()
