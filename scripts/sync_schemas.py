"""Add model fields to the historical schemas without dropping semantic constraints."""
import json
from pathlib import Path

from models import DailyDigest, RawItem
from storage import atomic_json


def synchronize(existing, generated):
    for name, definition in generated.get("$defs", {}).items():
        if name not in existing.setdefault("$defs", {}):
            existing["$defs"][name] = definition
        else:
            synchronize(existing["$defs"][name], definition)
    for name, definition in generated.get("properties", {}).items():
        properties = existing.setdefault("properties", {})
        if name not in properties or name in {"source_quality", "link_kind", "patch_status", "date_precision", "summary_status"}:
            properties[name] = definition
        elif name == "published_at":
            properties[name] = {"type": ["string", "null"], "format": "date-time"}
    return existing


def main():
    root = Path(__file__).resolve().parents[1] / "schemas"
    for name, model in (("raw_item", RawItem), ("digest_item", DailyDigest)):
        path = root / f"{name}.schema.json"
        atomic_json(path, synchronize(json.loads(path.read_text()), model.model_json_schema()), indent=2)


if __name__ == "__main__":
    main()
