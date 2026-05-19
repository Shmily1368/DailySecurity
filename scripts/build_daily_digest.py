import json
import glob
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta
import argparse
from typing import Dict, List, Any

from models import DigestItem, DailyDigest, Hero, HeroStats, ItemType, Severity, RawItem, RiskSignal
from rank_items import rank_items
from summarize_with_llm import build_llm_summary, build_digest_item, MockLlmClient, OpenAiLlmClient

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--processed-dir", default="data/processed", help="Dir containing processed JSON files")
    parser.add_argument("--raw-dir", default="data/raw", help="Dir containing raw JSON files")
    parser.add_argument("--output-dir", default="data/daily", help="Dir to output daily digest")
    return parser.parse_args()

def load_processed_items(input_dir: str) -> Dict[str, DigestItem]:
    items_map: Dict[str, DigestItem] = {}
    
    for filepath in glob.glob(f"{input_dir}/*.json"):
        # Ignore mock files or any test files when building production digest
        if "mock" in filepath or "test" in filepath or filepath.endswith("digest_items.json"):
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
                        if item.published_at > existing.published_at:
                            items_map[item.id] = item
                except Exception as e:
                    print(f"[WARN] Failed to validate item in {filepath}: {e}")
                    
    return items_map

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
        if "errors" in filepath or "epss" in filepath:
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
                    if raw_item.published_at and raw_item.published_at < cutoff_date:
                        continue
                        
                    import re
                    clean_summary = re.sub(r'<[^>]+>', '', raw_item.summary) if raw_item.summary else raw_item.title
                    
                    # Create a minimal fallback LlmSummary
                    summary_data = {
                        "summary_zh": clean_summary[:400] or "（暂无可用摘要）",
                        "why_it_matters_zh": "原文内容（由于配额限制，未进行深度 LLM 分析）",
                        "recommended_action_zh": "建议根据原文自行评估",
                        "confidence_label": "metadata_only",
                        "confidence": 0.5,
                        "category": "vuln"
                    }
                    
                    if raw_item.type == ItemType.PAPER:
                        summary_data["category"] = "research"
                        summary_data["confidence_label"] = "abstract_only"
                    elif raw_item.type == ItemType.ADVISORY:
                        summary_data["category"] = "advisory"
                    elif raw_item.type == ItemType.THREAT_REPORT:
                        summary_data["category"] = "threat-intel"
                        
                    llm_summary = build_llm_summary(raw_item, summary_data)
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
            threat_type = getattr(item.summary, "threat_type", "").lower() if item.summary else ""
            tags = " ".join(getattr(item.summary, "tags", [])).lower() if item.summary else ""
            if "apt" in threat_type or "apt" in tags:
                sections["threat_apt"].append(item.id)
            elif "ransomware" in threat_type or "cybercrime" in tags or "botnet" in tags:
                sections["threat_cybercrime"].append(item.id)
            elif "macro" in tags or "态势" in tags or "周报" in item.title:
                sections["threat_macro"].append(item.id)
            else:
                sections["threat_campaigns"].append(item.id)
                
        # ======= 2. Vendor Advisories (Only Primary Vendors) =======
        elif item.type == ItemType.ADVISORY and item.source.lower() == "vendor":
            # Assuming product_vendor from source config, we heuristically split based on tags or source name
            title_lower = item.title.lower()
            if "cloud" in title_lower or "aws" in title_lower or "aliyun" in title_lower or "tencent" in title_lower:
                sections["vendor_cloud"].append(item.id)
            elif "router" in title_lower or "camera" in title_lower or "iot" in title_lower:
                sections["vendor_iot"].append(item.id)
            else:
                sections["vendor_os"].append(item.id)
                
        # ======= 3. Vulnerability Alerts (CVE, KEV, and Secondary Advisories like Seebug) =======
        elif item.type in [ItemType.CVE, ItemType.KEV] or (item.type == ItemType.ADVISORY and item.source.lower() != "vendor"):
            is_exploited = (item.risk and getattr(item.risk, "kev_listed", False)) or (item.summary and "exploited" in getattr(item.summary, "tags", []))
            
            text_to_check = (item.title + " " + str(item.summary) + " " + str(item.topics)).lower()
            is_supply_chain = "supply chain" in text_to_check or "供应链" in text_to_check or item.source in ["github_advisory", "osv"]
            
            is_research_poc = item.type == ItemType.ADVISORY and item.source.lower() != "vendor" # e.g. Seebug, 360CERT
            
            if is_exploited:
                sections["vuln_exploited"].append(item.id)
            elif is_supply_chain:
                sections["vuln_supply_chain"].append(item.id)
            elif is_research_poc:
                sections["vuln_poc"].append(item.id)
            else:
                sections["vuln_baseline"].append(item.id)
                
        # ======= 4. Research / Papers =======
        elif item.type == ItemType.PAPER:
            title_lower = item.title.lower()
            
            if any(k in title_lower for k in ["ai ", " ai", "llm", "machine learning", "deep learning", "adversarial", "federated"]):
                sections["research_ai"].append(item.id)
            elif any(k in title_lower for k in ["fuzzing", "malware", "side-channel", "vulnerability", "web", "network", "protocol", "binary", "cache", "memory", "exploit", "forensic", "system", "kernel", "sandbox", "hypervisor"]):
                sections["research_systems"].append(item.id)
            elif any(k in title_lower for k in ["crypto", "signature", "privacy", "zk-snark", "mpc", "authentication", "anonymity", "obfuscation", "homomorphic", "differential", "key exchange"]):
                sections["research_crypto"].append(item.id)
            else:
                sections["research_others"].append(item.id)
            
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
    Find items in the top N list that only have fallback summaries (metadata_only),
    and process them with LLM on the fly to ensure high quality for the top picks.
    """
    missing_items = [item for item in top_items if getattr(item.llm_summary, "confidence_label", "") == "metadata_only"]
    if not missing_items:
        return top_items

    print(f"[INFO] Found {len(missing_items)} Top items missing LLM summary. Processing them now...")
    
    # Initialize LLM Client
    client = None
    if is_mock or not os.getenv("OPENAI_API_KEY"):
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
        if "mock" in rf_path or "test" in rf_path or "epss" in rf_path:
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
    
    # 按照漏洞4、情报3、论文3的比例挑选最高分
    for category_list, limit in [(vulns, 4), (threats, 3), (papers, 3)]:
        count = 0
        for it in category_list:
            if count >= limit:
                break
            if it.id not in seen_ids:
                selected.append(it)
                seen_ids.add(it.id)
                count += 1
                
    # 如果名额没招满（比如某天没有足够的论文），用剩余最高分补齐至 10 条
    remaining = [it for it in items if it.id not in seen_ids]
    for it in remaining:
        if len(selected) >= 10:
            break
        selected.append(it)
        seen_ids.add(it.id)
        
    # 重新按分数降序排列
    return sorted(selected, key=lambda x: x.recommendation_score, reverse=True)

def main():
    args = parse_args()
    processed_dir = Path(args.processed_dir)
    raw_dir = Path(args.raw_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. 读取已经通过 LLM 总结好的 items
    processed_items_map = load_processed_items(str(processed_dir))
    existing_ids = set(processed_items_map.keys())
    
    # 1.5 读取漏网之鱼 (被 LLM limit 卡掉的 raw_items)，生成 fallback 结构
    missing_items = load_missing_raw_items(str(raw_dir), existing_ids)
    
    items = list(processed_items_map.values()) + missing_items
    
    # 1.6 严格过滤，确保只展示“当日”数据 (过去 24-36 小时)
    # 论文类因为周末断层，放宽到 96 小时
    now_utc = datetime.now(timezone.utc)
    cutoff_date_default = now_utc - timedelta(hours=36)
    cutoff_date_paper = now_utc - timedelta(hours=96)
    
    valid_items = []
    for item in items:
        # 有些特殊的 fallback 没有 published_at，或者确保只过滤确实有发表时间且较新的
        if getattr(item, "published_at", None):
            cutoff = cutoff_date_paper if item.type == ItemType.PAPER else cutoff_date_default
            if item.published_at >= cutoff:
                valid_items.append(item)
        else:
            # 没有明确发布时间的，保守起见默认放行 (可能是今天新产生的合成数据)
            valid_items.append(item)
    
    items = valid_items

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
    
    if not items:
        print("[WARN] No items found in processed or raw dir.")
        return
        
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
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    
    digest = DailyDigest(
        date=date_str,
        generated_at=now,
        is_mock=False,
        hero=hero,
        sections=sections,
        items=ranked_items
    )
    
    # 6. 输出
    output_data = digest.model_dump(mode="json")
    
    date_path = output_dir / f"{date_str}.json"
    with open(date_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
        
    latest_path = output_dir / "latest.json"
    with open(latest_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)

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
        
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index_data, f, ensure_ascii=False, indent=2)
        
    print(f"[OK] Built daily digest with {len(ranked_items)} items.")
    print(f"  -> {date_path}")
    print(f"  -> {latest_path}")

if __name__ == "__main__":
    main()
