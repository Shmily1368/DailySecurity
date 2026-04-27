"""
scripts/validate_data.py

统一数据校验入口。使用:
- Pydantic (scripts/models.py) 做类型/枚举校验
- jsonschema (schemas/*.json) 做正式合规校验

用法:
    # 校验单个文件 (自动识别 schema)
    python scripts/validate_data.py data/raw/mock_items.json
    python scripts/validate_data.py data/processed/mock_digest.json

    # 显式指定 schema
    python scripts/validate_data.py --schema raw_item data/raw/mock_items.json
    python scripts/validate_data.py --schema digest   data/daily/2026-04-27.json

    # 校验常用目录下所有 JSON
    python scripts/validate_data.py --all

    # 只做 pydantic 校验 (用于 schema 文件暂时缺失的场景)
    python scripts/validate_data.py --only pydantic data/raw/mock_items.json

退出码:
    0 = 全部通过
    1 = 至少一个文件校验失败
    2 = CLI 参数错误
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, List, Tuple

from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

# 允许从 scripts/ 同级导入
sys.path.insert(0, str(Path(__file__).resolve().parent))
from models import DailyDigest, RawItem  # noqa: E402


# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMAS_DIR = PROJECT_ROOT / "schemas"

SCHEMA_FILES = {
    "raw_item": SCHEMAS_DIR / "raw_item.schema.json",
    "digest": SCHEMAS_DIR / "digest_item.schema.json",
}

# 默认扫描的目录 (供 --all 使用)
DEFAULT_DIRS = [
    PROJECT_ROOT / "data" / "raw",
    PROJECT_ROOT / "data" / "processed",
    PROJECT_ROOT / "data" / "daily",
]


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_schema(name: str) -> dict:
    schema_path = SCHEMA_FILES[name]
    if not schema_path.exists():
        raise FileNotFoundError(f"schema 文件不存在: {schema_path}")
    return _load_json(schema_path)


def _looks_like_digest_items(data: Any) -> bool:
    """判断 data 是否为一组 DigestItem (不含 hero)。"""
    if not isinstance(data, dict):
        return False
    items = data.get("items")
    if not isinstance(items, list) or not items:
        return False
    first = items[0]
    return isinstance(first, dict) and "llm_summary" in first


def _infer_schema(path: Path, data: Any) -> str:
    """根据文件位置/内容推断应使用哪个 schema。"""
    parts = {p.name for p in path.parents}
    if "raw" in parts:
        return "raw_item"
    if "daily" in parts:
        return "digest"
    if "processed" in parts:
        # processed 目录同时存在归一 raw 和 digest, 用内容特征区分
        if isinstance(data, dict) and "items" in data and "hero" in data:
            return "digest"
        if _looks_like_digest_items(data):
            return "digest"
        return "raw_item"
    # 兜底: 看结构
    if isinstance(data, dict) and "items" in data and "hero" in data:
        return "digest"
    if _looks_like_digest_items(data):
        return "digest"
    return "raw_item"


# ---------------------------------------------------------------------------
# 校验逻辑
# ---------------------------------------------------------------------------


def _validate_raw_items(data: Any) -> List[str]:
    """data 必须是 RawItem 列表或 {items: [...]} 结构。"""
    errors: List[str] = []
    items = data
    if isinstance(data, dict) and "items" in data and isinstance(data["items"], list):
        items = data["items"]
    if not isinstance(items, list):
        return ["raw_item 文件顶层应为数组, 或含 items: [...] 的对象"]
    try:
        TypeAdapter(List[RawItem]).validate_python(items)
    except ValidationError as e:
        for err in e.errors():
            loc = ".".join(str(x) for x in err["loc"])
            errors.append(f"[pydantic] {loc}: {err['msg']}")
    return errors


def _validate_digest(data: Any) -> List[str]:
    errors: List[str] = []
    # 若只是 DigestItem 列表 (无 hero / date), 每条单独校验
    if _looks_like_digest_items(data):
        from models import DigestItem  # 局部 import, 避免循环

        for i, it in enumerate(data.get("items", [])):
            try:
                DigestItem.model_validate(it)
            except ValidationError as e:
                for err in e.errors():
                    loc = ".".join(str(x) for x in err["loc"])
                    errors.append(f"[pydantic] items[{i}].{loc}: {err['msg']}")
        return errors

    try:
        DailyDigest.model_validate(data)
    except ValidationError as e:
        for err in e.errors():
            loc = ".".join(str(x) for x in err["loc"])
            errors.append(f"[pydantic] {loc}: {err['msg']}")
    return errors


def _jsonschema_check(data: Any, schema: dict) -> List[str]:
    """对 raw_item 列表或 digest 对象执行 JSON Schema 校验。"""
    errors: List[str] = []
    # raw_item schema 针对单条; digest schema 针对整包。通过 $id 判断。
    schema_id = schema.get("$id", "")
    if "raw_item" in schema_id:
        validator = Draft202012Validator(schema)
        items = data
        if isinstance(data, dict) and "items" in data:
            items = data["items"]
        if not isinstance(items, list):
            return ["[jsonschema] raw_item 文件顶层应为数组"]
        for i, item in enumerate(items):
            for err in validator.iter_errors(item):
                loc = "/".join(str(x) for x in err.absolute_path)
                errors.append(f"[jsonschema] items[{i}].{loc}: {err.message}")
    else:
        # digest schema: 支持两种形态
        #   1) DailyDigest 整包 (含 hero/date)
        #   2) DigestItem 列表 (processed/digest_items.json 中间产物)
        if _looks_like_digest_items(data):
            # 构造仅校验单条 DigestItem 的子 schema (复用 $defs)
            item_schema = {
                "$schema": schema.get(
                    "$schema",
                    "https://json-schema.org/draft/2020-12/schema",
                ),
                "$ref": "#/$defs/DigestItem",
                "$defs": schema.get("$defs", {}),
            }
            item_validator = Draft202012Validator(item_schema)
            for i, item in enumerate(data.get("items", [])):
                for err in item_validator.iter_errors(item):
                    loc = "/".join(str(x) for x in err.absolute_path)
                    errors.append(f"[jsonschema] items[{i}].{loc}: {err.message}")
        else:
            validator = Draft202012Validator(schema)
            for err in validator.iter_errors(data):
                loc = "/".join(str(x) for x in err.absolute_path)
                errors.append(f"[jsonschema] {loc or '<root>'}: {err.message}")
    return errors


def validate_file(
    path: Path,
    schema_name: str | None = None,
    only: str = "all",
) -> Tuple[bool, List[str]]:
    """返回 (是否通过, 错误列表)。"""
    if not path.exists():
        return False, [f"文件不存在: {path}"]

    try:
        data = _load_json(path)
    except json.JSONDecodeError as e:
        return False, [f"JSON 解析失败: {e}"]

    if schema_name is None:
        schema_name = _infer_schema(path, data)
    if schema_name not in SCHEMA_FILES:
        return False, [f"未知 schema 名: {schema_name}"]

    errors: List[str] = []

    if only in ("all", "pydantic"):
        if schema_name == "raw_item":
            errors.extend(_validate_raw_items(data))
        else:
            errors.extend(_validate_digest(data))

    if only in ("all", "jsonschema"):
        try:
            schema = _load_schema(schema_name)
            errors.extend(_jsonschema_check(data, schema))
        except FileNotFoundError as e:
            errors.append(str(e))

    return (len(errors) == 0), errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _collect_all_files() -> List[Path]:
    files: List[Path] = []
    for d in DEFAULT_DIRS:
        if not d.exists():
            continue
        files.extend(sorted(d.rglob("*.json")))
    # 排除 index.json (非本 schema)
    return [f for f in files if f.name != "index.json"]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="校验 RawItem / DigestItem JSON 文件"
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="待校验的 JSON 文件路径, 支持多个",
    )
    parser.add_argument(
        "--schema",
        choices=list(SCHEMA_FILES.keys()),
        default=None,
        help="显式指定 schema; 不指定则按路径推断",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="扫描 data/raw、data/processed、data/daily 下所有 JSON",
    )
    parser.add_argument(
        "--only",
        choices=["all", "pydantic", "jsonschema"],
        default="all",
        help="仅跑一种校验 (默认两种都跑)",
    )

    args = parser.parse_args()

    if args.all:
        target_files = _collect_all_files()
        if not target_files:
            print("[INFO] 无 JSON 文件可校验")
            return 0
    elif args.files:
        target_files = [Path(f) for f in args.files]
    else:
        parser.print_help()
        return 2

    any_fail = False
    for path in target_files:
        ok, errs = validate_file(path, args.schema, args.only)
        if ok:
            print(f"✅ {path}")
        else:
            any_fail = True
            print(f"❌ {path}")
            for e in errs:
                print(f"   - {e}")

    return 1 if any_fail else 0


if __name__ == "__main__":
    sys.exit(main())
