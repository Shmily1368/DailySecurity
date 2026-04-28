import argparse
import json
import logging
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

# Ensure scripts directory is in sys.path when running from project root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from source_registry import load_sources, get_enabled_sources
from parsers.threat_intel_parsers import get_parser
from models import RawItem

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Fetch threat intelligence reports")
    parser.add_argument("--config", type=str, default="config/sources/threat_intel.yml", help="Path to config YAML")
    parser.add_argument("--output", type=str, default="data/raw/threat_intel.json", help="Output JSON path")
    parser.add_argument("--days", type=int, default=2, help="Fetch items from last N days")
    parser.add_argument("--source", type=str, help="Fetch only from this source ID")
    parser.add_argument("--limit-per-source", type=int, default=20, help="Max items to fetch per source")
    parser.add_argument("--dry-run", action="store_true", help="Run without saving")
    
    args = parser.parse_args()
    
    config_path = Path(args.config)
    output_path = Path(args.output)
    error_path = output_path.parent / f"{output_path.stem}_errors.json"
    
    if not config_path.exists():
        logger.error(f"Config file not found: {config_path}")
        return
        
    sources = load_sources(config_path)
    enabled_sources = get_enabled_sources(sources)
    
    if args.source:
        enabled_sources = [s for s in enabled_sources if s.id == args.source]
        
    logger.info(f"Loaded {len(enabled_sources)} enabled sources for threat intel")
    
    all_items: List[RawItem] = []
    errors: List[Dict[str, Any]] = []
    # Use 36h rolling window consistently, if days is 1 it means last 36h, otherwise days * 24 + 12h
    hours_back = max(36, args.days * 24)
    cutoff_date = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    
    for source in enabled_sources:
        logger.info(f"Fetching from {source.id} ({source.parser})")
        parser_impl = get_parser(source.parser)
        
        try:
            items = parser_impl.parse(source, limit=args.limit_per_source)
            
            # Filter by date
            valid_items = []
            for item in items:
                if item.published_at >= cutoff_date:
                    valid_items.append(item)
            
            all_items.extend(valid_items)
            logger.info(f"Fetched {len(valid_items)} valid items from {source.id}")
            
        except Exception as e:
            logger.error(f"Failed to fetch {source.id}: {e}")
            errors.append({
                "source_id": source.id,
                "error": str(e),
                "time": datetime.now(timezone.utc).isoformat()
            })
            
    if args.dry_run:
        logger.info(f"[DRY RUN] Fetched {len(all_items)} total items. Errors: {len(errors)}")
        return
        
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    existing_items = {}
    if output_path.exists():
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item_dict in data:
                    existing_items[item_dict["id"]] = item_dict
        except Exception:
            pass
            
    for item in all_items:
        existing_items[item.id] = item.model_dump(mode="json")
        
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(list(existing_items.values()), f, ensure_ascii=False, indent=2)
        
    if errors:
        with open(error_path, "w", encoding="utf-8") as f:
            json.dump(errors, f, ensure_ascii=False, indent=2)
            
    logger.info(f"Saved {len(existing_items)} total items to {output_path}")
    if errors:
        logger.warning(f"Recorded {len(errors)} errors to {error_path}")

if __name__ == "__main__":
    main()
