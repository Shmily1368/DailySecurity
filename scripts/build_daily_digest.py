import json
import glob
from pathlib import Path
from datetime import datetime, timezone
import argparse
from typing import Dict, List, Any

from models import DigestItem, DailyDigest, Hero, HeroStats, ItemType, Severity
from rank_items import rank_items

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", default="data/processed", help="Dir containing processed JSON files")
    parser.add_argument("--output-dir", default="data/daily", help="Dir to output daily digest")
    return parser.parse_args()

def load_processed_items(input_dir: str) -> List[DigestItem]:
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
                    
    return list(items_map.values())

def build_sections(items: List[DigestItem]) -> Dict[str, List[str]]:
    sections = {
        "top_10": [],
        "high_risk": [],
        "research": [],
        "supply_chain": []
    }
    
    for item in items:
        # 供应链安全
        text_to_check = (item.title + " " + str(item.summary) + " " + str(item.topics)).lower()
        if "supply chain" in text_to_check or "供应链" in text_to_check or item.type == ItemType.ADVISORY:
            sections["supply_chain"].append(item.id)
            
        # 高风险漏洞
        if item.risk_score >= 4.0 or item.severity in [Severity.CRITICAL, Severity.HIGH]:
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
    for item in items:
        if item.type == ItemType.CVE:
            stats.cve_count += 1
        if item.risk and item.risk.kev_listed:
            stats.kev_added += 1
        if item.type == ItemType.PAPER:
            stats.paper_count += 1
        if item.type == ItemType.ADVISORY:
            stats.advisory_count += 1
        if item.risk and item.risk.epss_score is not None:
            stats.max_epss = max(stats.max_epss, item.risk.epss_score)
            
    one_liner = f"今日共收录 {len(items)} 条安全情报，包含 {stats.cve_count} 个 CVE 和 {stats.paper_count} 篇研究论文。"
    return Hero(one_liner_zh=one_liner, stats=stats)

def main():
    args = parse_args()
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. 读取并去重
    items = load_processed_items(str(input_dir))
    if not items:
        print("[WARN] No items found in processed dir.")
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
