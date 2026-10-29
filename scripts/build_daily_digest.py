import json
import glob
import os
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
import argparse
from urllib.parse import urlparse
from typing import Dict, List, Any
from storage import atomic_json

from models import DigestItem, DailyDigest, Hero, HeroStats, ItemType, Severity, RawItem, RiskSignal
from rank_items import rank_items
from summarize_with_llm import build_llm_summary, build_digest_item, MockLlmClient, OpenAiLlmClient

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--processed-dir", default="data/processed", help="Dir containing processed JSON files")
    parser.add_argument("--raw-dir", default="data/raw", help="Dir containing raw JSON files")
    parser.add_argument("--output-dir", default="data/daily", help="Dir to output daily digest")
    parser.add_argument("--previous-digest", type=Path)
    parser.add_argument("--health-file", type=Path)
    parser.add_argument("--date", default=None, help="Publication date; default Asia/Shanghai")
    return parser.parse_args()

def load_processed_items(input_dir: str, aggregate: bool = True) -> Dict[str, DigestItem]:
    items_map: Dict[str, DigestItem] = {}
    
    for filepath in glob.glob(f"{input_dir}/*.json"):
        # Ignore mock files or any test files when building production digest
        filename = Path(filepath).name
        if "mock" in filename or "test" in filename or filename == "digest_items.json":
            print(f"[INFO] Skipping mock/test file: {filepath}")
            continue
            
        with open(filepath, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print(f"[WARN] Failed to parse JSON: {filepath}")
                continue
                
            raw_items = []
            if isinstance(data, dict) and "items" in data:
                raw_items = data["items"]
            elif isinstance(data, list):
                raw_items = data
            
            for raw in raw_items:
                try:
                    item = DigestItem.model_validate(raw)
                    # 去重：同 ID 的保留最新的 published_at
                    if item.id not in items_map:
                        items_map[item.id] = item
                    else:
                        existing = items_map[item.id]
                        if item_time(item) > item_time(existing):
                            items_map[item.id] = item
                except Exception as e:
                    print(f"[WARN] Failed to validate item in {filepath}: {e}")
                    
    if not aggregate:
        return items_map
    return {item.id: item for item in aggregate_vulnerabilities(list(items_map.values()))}


def item_time(item):
    return item.updated_at or item.published_at or item.first_seen_at or item.fetched_at or datetime.min.replace(tzinfo=timezone.utc)


def article_is_valid(item):
    url = urlparse(str(item.source_url if isinstance(item, DigestItem) else item.source_info.source_url))
    if url.hostname in {"beian.miit.gov.cn", "android.googlesource.com", "www.android.com"}:
        return False
    return not any(word in url.path.lower() for word in ("/cookie-settings", "/privacy/", "/login", "/signup"))


def entity_key(item):
    if item.type in {ItemType.CVE, ItemType.KEV, ItemType.ADVISORY} and len(item.cves) == 1 and item.source in {
        "nvd", "kev", "cisa", "ghsa", "github_advisory", "osv"
    }:
        return "cve:" + item.cves[0].upper()
    return "item:" + item.id


def aggregate_vulnerabilities(items):
    from models import SourceInfo
    groups = {}
    for item in items:
        groups.setdefault(entity_key(item), []).append(item)
    merged = []
    levels = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    for records in groups.values():
        # Current records precede retained same-ID copies; only their content competes for the base.
        candidates = {}
        for item in records:
            candidates.setdefault(item.id, item)
        base = max(candidates.values(), key=lambda it: (it.summary_status == "model", it.source == "nvd", item_time(it), it.id)).model_copy(deep=True)
        sources = {}
        for item in records:
            base.aliases = sorted(set(base.aliases + item.aliases + [item.id]))
            for field in ("cves", "vendors", "products", "topics"):
                setattr(base, field, sorted(set(getattr(base, field) + getattr(item, field))))
            for source in item.related_sources + [SourceInfo(
                source=item.source, source_sub=item.source_sub, source_quality=item.source_quality,
                source_name=item.source_name, source_url=item.source_url,
                native_id=item.aliases[0] if item.aliases else item.id,
            )]:
                sources[(source.source, str(source.source_url))] = source
            base.severity = max([base.severity, item.severity], key=levels.index)
            if not item.risk:
                continue
            if not base.risk:
                base.risk = RiskSignal()
            for field in ("cvss_score", "epss_score", "epss_percentile"):
                value = getattr(item.risk, field)
                if value is not None and (getattr(base.risk, field) is None or value > getattr(base.risk, field)):
                    setattr(base.risk, field, value)
                    if field == "cvss_score":
                        base.risk.cvss_vector = item.risk.cvss_vector
            for field in ("kev_listed", "known_exploited", "exploit_in_the_wild", "has_public_exploit"):
                if getattr(item.risk, field):
                    setattr(base.risk, field, True)
            if item.risk.known_ransomware is True:
                base.risk.known_ransomware = True
            elif item.risk.known_ransomware is False and base.risk.known_ransomware is None:
                base.risk.known_ransomware = False
            if item.risk.kev_listed:
                base.risk.kev_status = "listed"
                base.risk.kev_date_added = item.risk.kev_date_added
                base.risk.due_date = item.risk.due_date
            if item.risk.patch_status == "available":
                base.risk.patch_status = "available"
            base.risk.patch_references = list({str(r): r for r in base.risk.patch_references + item.risk.patch_references}.values())
            base.risk.exploit_references = list({str(r.url): r for r in base.risk.exploit_references + item.risk.exploit_references}.values())
        base.related_sources = [s for key, s in sources.items() if key != (base.source, str(base.source_url))]
        if base.risk:
            if base.risk.known_exploited or base.risk.kev_listed:
                base.risk.exploit_maturity = "in_the_wild"
            elif base.risk.has_public_exploit:
                base.risk.exploit_maturity = "poc"
        merged.append(base)
    return merged

def load_epss_scores(raw_dir: str) -> Dict[str, float]:
    """Load EPSS scores mapping from epss_scores.json to merge into items."""
    epss_map = {}
    epss_path = Path(raw_dir) / "epss_scores.json"
    if not epss_path.exists():
        return epss_map
        
    try:
        with open(epss_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        raw_list = data.get("items", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        for raw_dict in raw_list:
            cves = raw_dict.get("cves", [])
            risk = raw_dict.get("risk", {})
            if cves and risk and "epss_score" in risk:
                for cve in cves:
                    epss_map[cve] = risk["epss_score"]
    except Exception as e:
        print(f"[WARN] Failed to load EPSS scores: {e}")
        
    return epss_map

def load_missing_raw_items(raw_dir: str, existing_ids: set) -> List[DigestItem]:
    """
    Load raw items that were NOT processed by LLM, create a basic fallback DigestItem.
    We apply a strict cutoff (e.g. 3 days) to avoid old data lingering.
    """
    missing_items = []
    
    # We only want to display "Daily" items. Skip anything older than 4 days to bridge weekend gaps.
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=4)
    
    for filepath in glob.glob(f"{raw_dir}/*.json"):
        # Ignore error files and EPSS scores (which are purely metadata to be merged)
        filename = Path(filepath).name
        if filename.endswith(("_errors.json", "_status.json")) or "epss" in filename or "mock" in filename or "test" in filename:
            continue
            
        with open(filepath, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                continue
                
            raw_list = []
            if isinstance(data, dict) and "items" in data:
                raw_list = data["items"]
            elif isinstance(data, list):
                raw_list = data
            else:
                # Some files might just be a direct array at root or have a different structure
                raw_list = data
                
            for raw_dict in raw_list:
                try:
                    item_id = raw_dict.get("id")
                    if not item_id or item_id in existing_ids:
                        continue
                        
                    raw_item = RawItem.model_validate(raw_dict)
                    
                    # Skip old historical data (especially important for cisa_kev.json which has 1500+ items)
                    # For threat intelligence, we also want to stay daily.
                    if not article_is_valid(raw_item) or item_time(raw_item) < cutoff_date:
                        continue
                        
                    import re
                    clean_summary = re.sub(r'<[^>]+>', '', raw_item.summary) if raw_item.summary else raw_item.title
                    
                    # Create a minimal fallback LlmSummary
                    summary_data = {
                        "summary_zh": clean_summary[:400] or "（暂无可用摘要）",
                        "why_it_matters_zh": "原文摘录（未生成 LLM 摘要，请结合来源自行核实）",
                        "recommended_action_zh": "建议根据原文自行评估",
                        "confidence_label": "metadata_only",
                        "confidence": 0.5,
                        "category": "vuln"
                        , "prompt_version": "fallback"
                    }
                    
                    if raw_item.type == ItemType.PAPER:
                        summary_data["category"] = "research"
                        summary_data["confidence_label"] = "abstract_only"
                    elif raw_item.type == ItemType.ADVISORY:
                        summary_data["category"] = "advisory"
                    elif raw_item.type == ItemType.THREAT_REPORT:
                        summary_data["category"] = "threat-intel"
                    elif raw_item.type == ItemType.DETECTION_RULE:
                        summary_data["category"] = "detection"
                        
                    llm_summary = build_llm_summary(raw_item, summary_data)
                    llm_summary.prompt_version = "fallback"
                    digest_item = build_digest_item(raw_item, llm_summary)
                    missing_items.append(digest_item)
                    existing_ids.add(raw_item.id)
                except Exception as e:
                    # Ignore validation errors for raw items here to not spam logs
                    pass
                    
    return missing_items

def build_sections(items: List[DigestItem], top_10_ids: List[str] = None) -> Dict[str, List[str]]:
    sections = {
        "top_10": [],
        # Research
        "research_ai": [],
        "research_systems": [],
        "research_crypto": [],
        "research_others": [],
        "research_history": [],
        "detection_rules": [],
        # Vuln
        "vuln_exploited": [],
        "vuln_poc": [],
        "vuln_supply_chain": [],
        "vuln_baseline": [],
        # Threat Intel
        "threat_apt": [],
        "threat_cybercrime": [],
        "threat_campaigns": [],
        "threat_macro": [],
        # Vendor
        "vendor_cloud": [],
        "vendor_os": [],
        "vendor_iot": [],
    }
    
    for item in items:
        # ======= 1. Threat Intel =======
        if item.type == ItemType.THREAT_REPORT:
            threat_type = (item.llm_summary.threat_type or "").lower()
            tags = " ".join(item.llm_summary.tags).lower()
            if "apt" in threat_type or "apt" in tags:
                sections["threat_apt"].append(item.id)
            elif "ransomware" in threat_type or "cybercrime" in tags or "botnet" in tags:
                sections["threat_cybercrime"].append(item.id)
            elif "macro" in tags or "态势" in tags or "周报" in item.title:
                sections["threat_macro"].append(item.id)
            else:
                sections["threat_campaigns"].append(item.id)
                
        # ======= 2. Vendor Advisories (Only Primary Vendors) =======
        elif item.type == ItemType.ADVISORY and item.source.lower() == "vendor" and item.source_quality == "primary":
            # Assuming product_vendor from source config, we heuristically split based on tags or source name
            title_lower = item.title.lower()
            if "cloud" in title_lower or "aws" in title_lower or "aliyun" in title_lower or "tencent" in title_lower:
                sections["vendor_cloud"].append(item.id)
            elif "router" in title_lower or "camera" in title_lower or "iot" in title_lower:
                sections["vendor_iot"].append(item.id)
            else:
                sections["vendor_os"].append(item.id)
                
        # ======= 3. Vulnerability Alerts (CVE, KEV, and Secondary Advisories like Seebug) =======
        elif item.type in [ItemType.CVE, ItemType.KEV, ItemType.ADVISORY]:
            is_exploited = bool(item.risk and (
                item.risk.kev_listed or item.risk.known_exploited or item.risk.exploit_in_the_wild
                or item.risk.exploit_maturity == "in_the_wild"
            ))
            
            text_to_check = (item.title + " " + str(item.summary) + " " + str(item.topics)).lower()
            is_supply_chain = "supply chain" in text_to_check or "供应链" in text_to_check
            
            is_research_poc = bool(item.risk and (item.risk.has_public_exploit or item.risk.exploit_references))
            
            if is_exploited:
                sections["vuln_exploited"].append(item.id)
            elif is_research_poc:
                sections["vuln_poc"].append(item.id)
            elif is_supply_chain:
                sections["vuln_supply_chain"].append(item.id)
            else:
                sections["vuln_baseline"].append(item.id)
                
        # ======= 4. Research / Papers =======
        elif item.type == ItemType.PAPER:
            if item.is_backfill:
                sections["research_history"].append(item.id)
                continue
            title_lower = item.title.lower()
            
            if any(k in title_lower for k in ["ai ", " ai", "llm", "machine learning", "deep learning", "adversarial", "federated"]):
                sections["research_ai"].append(item.id)
            elif any(k in title_lower for k in ["fuzzing", "malware", "side-channel", "vulnerability", "web", "network", "protocol", "binary", "cache", "memory", "exploit", "forensic", "system", "kernel", "sandbox", "hypervisor"]):
                sections["research_systems"].append(item.id)
            elif any(k in title_lower for k in ["crypto", "signature", "privacy", "zk-snark", "mpc", "authentication", "anonymity", "obfuscation", "homomorphic", "differential", "key exchange"]):
                sections["research_crypto"].append(item.id)
            else:
                sections["research_others"].append(item.id)
        elif item.type == ItemType.DETECTION_RULE:
            sections["detection_rules"].append(item.id)
            
    # Top 10
    if top_10_ids is not None:
        sections["top_10"] = top_10_ids
    else:
        sections["top_10"] = [item.id for item in items[:10]]
    
    # 填充每个 item 的 shown_in_sections
    for item in items:
        item.shown_in_sections = []
        for sec_name, sec_items in sections.items():
            if item.id in sec_items:
                item.shown_in_sections.append(sec_name)
                
    # Sort items within each category:
    # Rule 1: Papers from 'top_conferences' always bubble to the top of their respective lists.
    # Rule 2: Then by descending risk score.
    valid_items_dict = {it.id: it for it in items}
    for key in sections:
        if key == "top_10":
            continue
        
        def sort_key(item_id):
            it = valid_items_dict.get(item_id)
            if not it:
                return (0, 0)
            
            # Check source for top_conferences
            is_top_conf = 1 if getattr(it, "source", "") == "top_conferences" else 0
            score = getattr(it, "risk_score", 0.0) or 0.0
            return (is_top_conf, score)
            
        sections[key] = sorted(sections[key], key=sort_key, reverse=True)

    return sections

def build_hero(items: List[DigestItem]) -> Hero:
    stats = HeroStats()
    stats.advisory_count = 0
    for item in items:
        if item.type == ItemType.CVE:
            stats.cve_count += 1
        if item.risk and getattr(item.risk, "kev_listed", False):
            stats.kev_added += 1
        if item.type == ItemType.PAPER:
            stats.paper_count += 1
        if item.type == ItemType.ADVISORY:
            stats.advisory_count += 1
        if item.risk and getattr(item.risk, "epss_score", None) is not None:
            stats.max_epss = max(stats.max_epss, item.risk.epss_score)
            
    one_liner = f"今日共收录 {len(items)} 条安全情报，包含 {stats.cve_count} 个 CVE，{stats.advisory_count} 篇安全通告，以及 {stats.paper_count} 篇研究论文。"
    return Hero(one_liner_zh=one_liner, stats=stats)

def process_missing_top_items_with_llm(top_items: List[DigestItem], raw_dir: str, is_mock: bool = False) -> List[DigestItem]:
    """
    Find items in the top N list that only have fallback summaries,
    and process them with LLM on the fly to ensure high quality for the top picks.
    """
    if not is_mock:
        return top_items
    missing_items = [item for item in top_items if item.llm_summary.prompt_version == "fallback"]
    if not missing_items:
        return top_items

    if not is_mock and not os.getenv("OPENAI_API_KEY"):
        print("[WARN] No LLM API key; keeping explicitly marked source excerpts.")
        return top_items

    print(f"[INFO] Found {len(missing_items)} Top items missing LLM summary. Processing them now...")
    
    # Initialize LLM Client
    client = None
    if is_mock:
        print("[INFO] build_daily_digest: Using MockLlmClient for missing Top items.")
        client = MockLlmClient()
    else:
        print("[INFO] build_daily_digest: Using OpenAiLlmClient for missing Top items.")
        api_key = os.getenv("OPENAI_API_KEY")
        client = OpenAiLlmClient(api_key=api_key, model=os.getenv("LLM_MODEL", "gpt-4o-mini"))

    # Load corresponding raw items
    raw_files = glob.glob(f"{raw_dir}/*.json")
    raw_map = {}
    for rf_path in raw_files:
        filename = Path(rf_path).name
        if "mock" in filename or "test" in filename or "epss" in filename or filename.endswith("_errors.json"):
            continue
        try:
            with open(rf_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                
                raw_list = []
                if isinstance(data, dict) and "items" in data:
                    raw_list = data["items"]
                elif isinstance(data, list):
                    raw_list = data
                else:
                    raw_list = data
                
                for d in raw_list:
                    try:
                        raw_item = RawItem.model_validate(d)
                        raw_map[raw_item.id] = raw_item
                    except Exception:
                        pass
        except Exception:
            pass

    updated_items_map = {}
    for item in missing_items:
        raw_item = raw_map.get(item.id)
        if not raw_item:
            print(f"[WARN] Raw data not found for {item.id}, skipping LLM processing.")
            continue
            
        try:
            # Correct order: summarize first, then build summary object
            raw_summary_dict = client.summarize(raw_item)
            summary = build_llm_summary(raw_item, raw_summary_dict)
            new_digest_item = build_digest_item(raw_item, summary)
            # 保留排名前合并的 EPSS 等风险信号。
            new_digest_item.risk = item.risk
            updated_items_map[item.id] = new_digest_item
            print(f"[OK] Successfully generated LLM summary for {item.id}")
        except Exception as e:
            print(f"[WARN] Failed to generate LLM summary for {item.id}: {e}")

    # Replace the items in the original list
    final_items = []
    for item in top_items:
        if item.id in updated_items_map:
            final_items.append(updated_items_map[item.id])
        else:
            final_items.append(item)
            
    return final_items

def get_diverse_top_10(items: List[DigestItem]) -> List[DigestItem]:
    """从已排序的 items 中挑选出多样化的 Top 10 (4:3:3 比例)"""
    vulns = [it for it in items if it.type in [ItemType.CVE, ItemType.KEV, ItemType.ADVISORY]]
    threats = [it for it in items if it.type == ItemType.THREAT_REPORT]
    papers = [it for it in items if it.type == ItemType.PAPER]
    
    selected = []
    seen_ids = set()
    seen_entities = set()
    
    # 按照漏洞4、情报3、论文3的比例挑选最高分
    for category_list, limit in [(vulns, 4), (threats, 3), (papers, 3)]:
        count = 0
        for it in category_list:
            if count >= limit:
                break
            if it.id not in seen_ids and entity_key(it) not in seen_entities:
                selected.append(it)
                seen_ids.add(it.id)
                seen_entities.add(entity_key(it))
                count += 1
                
    # 如果名额没招满（比如某天没有足够的论文），用剩余最高分补齐至 10 条
    remaining = [it for it in items if it.id not in seen_ids]
    for it in remaining:
        if len(selected) >= 10:
            break
        if entity_key(it) in seen_entities:
            continue
        selected.append(it)
        seen_ids.add(it.id)
        seen_entities.add(entity_key(it))
        
    # 重新按分数降序排列
    return sorted(selected, key=lambda x: x.recommendation_score, reverse=True)

def main():
    args = parse_args()
    processed_dir = Path(args.processed_dir)
    raw_dir = Path(args.raw_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. 读取已经通过 LLM 总结好的 items
    processed_items_map = load_processed_items(str(processed_dir), aggregate=False)
    existing_ids = set(processed_items_map.keys()) | {a for i in processed_items_map.values() for a in i.aliases}
    
    # 1.5 读取漏网之鱼 (被 LLM limit 卡掉的 raw_items)，生成 fallback 结构
    missing_items = load_missing_raw_items(str(raw_dir), existing_ids)
    
    items = list(processed_items_map.values()) + missing_items
    now = datetime.now(timezone.utc)
    date_str = args.date or now.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d")
    
    # 1.6 严格过滤，确保只展示“当日”数据 (过去 24-36 小时)
    # 论文类因为周末断层，放宽到 96 小时
    now_utc = now
    cutoff_date_default = now_utc - timedelta(hours=36)
    cutoff_date_paper = now_utc - timedelta(hours=96)
    
    valid_items = []
    for item in items:
        if not article_is_valid(item):
            continue
        # 有些特殊的 fallback 没有 published_at，或者确保只过滤确实有发表时间且较新的
        if item.published_at or item.updated_at:
            cutoff = cutoff_date_paper if item.type == ItemType.PAPER else cutoff_date_default
            if item_time(item) >= cutoff:
                valid_items.append(item)
        else:
            # 未知日期只展示近期首次发现，不把每天重新抓取当成新发表。
            if item.first_seen_at and item.first_seen_at >= cutoff_date_default:
                valid_items.append(item)
    
    # Published same-day items outlive the rolling window and retain evidence even for current IDs.
    if args.previous_digest and args.previous_digest.exists():
        previous = DailyDigest.model_validate_json(args.previous_digest.read_text())
        if previous.date == date_str:
            valid_items.extend(i for i in previous.items if article_is_valid(i))

    items = aggregate_vulnerabilities(valid_items)

    # 1.8 Merge EPSS scores
    epss_map = load_epss_scores(str(raw_dir))
    if epss_map:
        for item in items:
            if not item.cves:
                continue
            max_epss = -1.0
            for cve in item.cves:
                if cve in epss_map and epss_map[cve] > max_epss:
                    max_epss = epss_map[cve]
            if max_epss >= 0.0:
                if not item.risk:
                    item.risk = RiskSignal()
                if item.risk.epss_score is None or max_epss > item.risk.epss_score:
                    item.risk.epss_score = max_epss
    
    health = json.loads(args.health_file.read_text()) if args.health_file and args.health_file.exists() else {}
    if not items and not any(row.get("status") in {"success", "no_new", "not_found", "partial"}
                             for row in health.get("sources", {}).values()):
        print("[ERROR] No current items found; preserving the previously published digest.")
        return 1
        
    # 2. 排序并补录 Top 10 的 LLM 摘要
    # First ranking pass to find top candidates
    ranked_items = rank_items(items)
    
    # 从中筛选出具备类别多样性的 Top 10，避免全被高危漏洞霸榜
    top_10_candidates = get_diverse_top_10(ranked_items)
    
    is_mock = os.getenv("LLM_MOCK", "0") == "1"
    top_10_processed = process_missing_top_items_with_llm(top_10_candidates, str(raw_dir), is_mock=is_mock)
    
    # Replace top 10 items in the main list
    for i, item in enumerate(top_10_processed):
        # 找到它在总榜单中的位置并替换
        for j, ranked in enumerate(ranked_items):
            if ranked.id == item.id:
                ranked_items[j] = item
                break
        
    # Second ranking pass: scores might have changed due to LLM processing (confidence score addition)
    ranked_items = rank_items(ranked_items)

    print(f"[INFO] 过滤 & 排序后剩余: {len(ranked_items)} 条")
    
    # 提取经过配额与 LLM 处理的那 10 个候选者 ID，按最新分数排序
    top_10_ids_set = {item.id for item in top_10_processed}
    final_top_10_ids = [item.id for item in ranked_items if item.id in top_10_ids_set]
    
    # 3. 构建区块
    sections = build_sections(ranked_items, top_10_ids=final_top_10_ids)
    
    # 4. 构建 Hero
    hero = build_hero(ranked_items)
    
    # 5. 组装 DailyDigest
    model_count = sum(i.summary_status == "model" for i in ranked_items)
    health["summary"] = {"input_count": len(ranked_items), "model_count": model_count,
                         "excerpt_count": sum(i.summary_status == "excerpt" for i in ranked_items),
                         "coverage": model_count / len(ranked_items) if ranked_items else 0}
    
    digest = DailyDigest(
        date=date_str,
        generated_at=now,
        is_mock=is_mock,
        hero=hero,
        sections=sections,
        items=ranked_items,
        health=health,
    )
    
    # 6. 输出
    output_data = digest.model_dump(mode="json")
    
    date_path = output_dir / f"{date_str}.json"
    atomic_json(date_path, output_data)
        
    latest_path = output_dir / "latest.json"
    atomic_json(latest_path, output_data)

    # 7. 更新 index.json
    index_path = output_dir / "index.json"
    if index_path.exists():
        with open(index_path, "r", encoding="utf-8") as f:
            index_data = json.load(f)
    else:
        index_data = {"latest": "", "dates": []}
        
    index_data["latest"] = date_str
    if date_str not in index_data["dates"]:
        index_data["dates"].append(date_str)
        index_data["dates"].sort(reverse=True)
        
    atomic_json(index_path, index_data)
        
    print(f"[OK] Built daily digest with {len(ranked_items)} items.")
    print(f"  -> {date_path}")
    print(f"  -> {latest_path}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
