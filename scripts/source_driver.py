"""Shared registered-source collection with per-source health and first-seen state."""
import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from pathlib import Path

from storage import atomic_json


def parse_args(channel):
    parser = argparse.ArgumentParser(description=f"Fetch {channel} sources")
    filename = "vendor_advisories" if channel == "vendor" else "threat_intel"
    parser.add_argument("--config", default=f"config/sources/{filename}.yml")
    parser.add_argument("--output", type=Path, default=Path(f"data/raw/{filename}.json"))
    parser.add_argument("--state-file", type=Path)
    parser.add_argument("--days", type=int, default=2)
    parser.add_argument("--source")
    parser.add_argument("--limit-per-source", type=int, default=20)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if min(args.days, args.limit_per_source, args.workers) <= 0 or args.workers > 4:
        parser.error("Positive limits required; workers must not exceed 4")
    return args


def collect_sources(args, sources, get_parser):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=max(36, args.days * 24))
    seen = {}
    if args.state_file and args.state_file.exists():
        seen = json.loads(args.state_file.read_text()).get("first_seen", {})
    if args.source:
        sources = [source for source in sources if source.id == args.source]

    def fetch(source):
        try:
            records = get_parser(source.parser).parse(source, limit=args.limit_per_source)
            meta = getattr(records, "meta", {})
            errors = meta.get("errors", [])
            valid, updates = [], {}
            for item in records:
                stored = seen.get(item.id)
                first = datetime.fromisoformat(stored["at"]) if stored else now
                item.first_seen_at = first
                updates[item.id] = {"at": first.isoformat(), "source": source.id}
                evidence_time = item.updated_at or item.published_at or first
                if evidence_time >= cutoff:
                    valid.append(item)
            status = ("partial" if records else "failed") if errors else "success" if valid else "no_new"
            return valid, updates, {
                "source_id": source.id, "status": status,
                "fetched_count": meta.get("fetched_count", len(records)),
                "attempted_count": meta.get("attempted_count", len(records)),
                "parsed_count": len(records), "item_count": len(valid),
                "error_count": len(errors), "errors": errors,
            }
        except Exception as exc:
            return [], {}, {"source_id": source.id, "status": "failed", "error_type": type(exc).__name__,
                            "fetched_count": 0, "attempted_count": 0, "parsed_count": 0,
                            "item_count": 0, "error_count": 1}

    items, statuses = {}, []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        for valid, updates, status in executor.map(fetch, sources):
            statuses.append(status)
            seen.update(updates)
            items.update({item.id: item for item in valid})
    failures = [row for row in statuses if row["status"] == "failed"]
    partials = [row for row in statuses if row["status"] == "partial"]
    errors = [error for row in statuses for error in
              (row.get("errors") or ([row] if row["status"] == "failed" else []))]
    status = ("failed" if not statuses or len(failures) == len(statuses) else "partial" if failures or partials
              else "success" if items else "no_new")
    if not args.dry_run:
        atomic_json(args.output, {"items": [item.model_dump(mode="json") for item in items.values()],
                                 "meta": {"status": status, "subsource_count": len(statuses),
                                          "failed_count": len(failures), "partial_count": len(partials),
                                          "error_count": len(errors), "fetched_at": now.isoformat()}})
        atomic_json(args.output.with_name(args.output.stem + "_status.json"), statuses)
        atomic_json(args.output.with_name(args.output.stem + "_errors.json"), errors)
        if args.state_file:
            # Preserve old identity state on failure; commit only successful subsource discoveries.
            bounded = dict(sorted(seen.items(), key=lambda row: row[1]["at"], reverse=True)[:20000])
            atomic_json(args.state_file, {"first_seen": bounded})
    print(f"[INFO] Registered sources: {status}, {len(items)} items, {len(failures)} failed")
    return 1 if status == "failed" else 0
