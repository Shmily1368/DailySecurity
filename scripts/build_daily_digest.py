import json
import glob
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta
import argparse
from typing import Dict, List, Any

from models import DigestItem, DailyDigest, Hero, HeroStats, ItemType, Severity, RawItem, RiskSignal
from rank_items import rank_items
from summarize_with_llm import build_llm_summary, build_digest_item

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--processed-dir", default="data/processed", help="Dir containing processed JSON files")
    parser.add_argument("--raw-dir", default="data/raw", help="Dir containing raw JSON files")
    parser.add_argument("--output-dir", default="data/daily", help="Dir to output daily digest")
    return parser.parse_args()

def load_processed_items(input_dir: str) -> Dict[str, DigestItem]:
    items_map: Dict[str, DigestItem] = {}
    
    for filepath in glob.glob(f"{input_dir}/*.json"):
        # 忽略已经存在的旧 daily 文件如果混进来的话 (虽然不应该在 processed)
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
    """Load raw items that didn't get processed by LLM and create mock/fallback DigestItems for them."""
    missing_items = []
    
    # We only want to display "Daily" items. Skip anything older than 3 days.
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=3)
    
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
                        
                    # Create a minimal fallback LlmSummary
                    summary_data = {
                        "summary_zh": raw_item.title[:120],
                        "why_it_matters_zh": "由于配额限制，未进行深度 LLM 分析。",
                        "recommended_action_zh": "建议根据原标题自行评估",
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

def build_sections(items: List[DigestItem]) -> Dict[str, List[str]]:
    sections = {
        "top_10": [],
        "high_risk": [],
        "research": [],
        "supply_chain": [],
        "vendor_advisories": [],
        "threat_intel": []
    }
    
    for item in items:
        # 威胁情报
        if item.type == ItemType.THREAT_REPORT:
            sections["threat_intel"].append(item.id)
            
        # 厂商安全公告
        if item.type == ItemType.ADVISORY and item.source.lower() == "vendor":
            sections["vendor_advisories"].append(item.id)
            
        # 供应链安全
        text_to_check = (item.title + " " + str(item.summary) + " " + str(item.topics)).lower()
        if "supply chain" in text_to_check or "供应链" in text_to_check or (item.type == ItemType.ADVISORY and item.source.lower() != "vendor"):
            sections["supply_chain"].append(item.id)
            
        # 高风险漏洞 (排除论文和威胁情报) - 包含所有该类型项目，不卡 risk_score
        if item.type in [ItemType.CVE, ItemType.KEV, ItemType.ADVISORY]:
            sections["high_risk"].append(item.id)
            
        # 研究前沿
        if item.type == ItemType.PAPER:
            sections["research"].append(item.id)
            
    # Top 10 取总榜前 10
    sections["top_10"] = [item.id for item in items[:10]]
    
    # 填充每个 item 的 shown_in_sections
    for item in items:
        item.shown_in_sections = []
        for sec_name, sec_items in sections.items():
            if item.id in sec_items:
                item.shown_in_sections.append(sec_name)
                
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
    cutoff_date = datetime.now(timezone.utc) - timedelta(hours=36)
    valid_items = []
    for item in items:
        # 有些特殊的 fallback 没有 published_at，或者确保只过滤确实有发表时间且较新的
        if getattr(item, "published_at", None):
            if item.published_at >= cutoff_date:
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
        
    # 2. 排序打分
    ranked_items = rank_items(items)
    
    # 3. 构建区块
    sections = build_sections(ranked_items)
    
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
