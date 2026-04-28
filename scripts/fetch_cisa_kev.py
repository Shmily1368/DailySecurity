"""
scripts/fetch_cisa_kev.py

抓取 CISA 已知被利用漏洞 (KEV) 目录, 归一为 RawItem 结构落盘。

数据源:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

字段契约:
    - id = "kev:{cveID}"
    - type = "kev"
    - cves = [cveID]
    - vendors = [vendorProject]
    - products = [product]
    - risk.kev_status = "listed"
    - risk.kev_listed = True
    - risk.kev_date_added = dateAdded
    - risk.due_date = dueDate
    - risk.known_ransomware = (knownRansomwareCampaignUse == "Known")
    - risk.known_exploited = True  # KEV 条目按定义均已被利用
    - references = [source_url]

安全红线:
    KEV 原文本身只含漏洞元数据和修复要求, 不含 exploit 代码。
    fetcher 层不做任何二次加工; 后续 LLM 摘要层禁止生成攻击步骤。

用法:
    python scripts/fetch_cisa_kev.py
    python scripts/fetch_cisa_kev.py --output data/raw/2026-04-27/kev.json

退出码:
    0 = 成功
    1 = 网络 / 解析失败
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, time, timezone
from pathlib import Path
from typing import Any, Iterable, List, Optional

import httpx
from tenacity import (
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from models import (  # noqa: E402
    ExploitMaturity,
    ExploitRef,
    ItemType,
    KevStatus,
    RawItem,
    RiskSignal,
    SourceInfo,
)


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
DEFAULT_OUTPUT = Path("data/raw/cisa_kev.json")
HTTP_TIMEOUT = 30.0
USER_AGENT = "cyber-daily-radar/0.1 (+https://github.com/)"

# 面向防御者的固定文案, 由 fetcher 层提前落入 source_info / 后续可被 LLM 覆盖
KEV_RECOMMENDED_ACTION = (
    "优先级置顶处理: 参考厂商公告尽快打补丁, 排查资产暴露面, "
    "验证修复后关闭相关管理端口。"
)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class KevFetchError(RuntimeError):
    """CISA KEV 抓取失败统一异常。"""


@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((httpx.HTTPError,)),
)
def _http_get_json(url: str) -> dict:
    with httpx.Client(
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()


def fetch_kev_feed(url: str = KEV_FEED_URL) -> dict:
    try:
        return _http_get_json(url)
    except RetryError as e:
        raise KevFetchError(f"CISA KEV 请求在重试后仍失败: {e}") from e
    except httpx.HTTPError as e:
        raise KevFetchError(f"CISA KEV 请求失败: {e!r}") from e
    except json.JSONDecodeError as e:
        raise KevFetchError(f"CISA KEV JSON 解析失败: {e}") from e


# ---------------------------------------------------------------------------
# 归一
# ---------------------------------------------------------------------------


def _to_utc_datetime(date_str: str | None) -> datetime | None:
    """CISA KEV 的 dateAdded / dueDate 是 YYYY-MM-DD, 统一取当日 00:00 UTC。"""
    if not date_str:
        return None
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return None
    return datetime.combine(d, time.min, tzinfo=timezone.utc)


def _cve_source_url(cve_id: str) -> str:
    """KEV 条目自身没有稳定的 per-item URL, 用 NVD 详情页作为 canonical 源链接。"""
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def _build_title(entry: dict) -> str:
    name = (entry.get("vulnerabilityName") or "").strip()
    cve_id = entry.get("cveID", "").strip()
    vendor = (entry.get("vendorProject") or "").strip()
    product = (entry.get("product") or "").strip()
    prefix = f"{vendor} {product}".strip()
    if name and prefix:
        return f"{prefix} — {name} ({cve_id})"
    if name:
        return f"{name} ({cve_id})"
    return cve_id or "Unknown KEV entry"


def _summary(entry: dict) -> Optional[str]:
    short_desc = (entry.get("shortDescription") or "").strip()
    required_action = (entry.get("requiredAction") or "").strip()
    parts = []
    if short_desc:
        parts.append(short_desc)
    if required_action:
        parts.append(f"CISA 要求: {required_action}")
    text = " ".join(parts).strip()
    return text[:4000] if text else None


def entry_to_raw_item(entry: dict, fetched_at: datetime) -> RawItem | None:
    cve_id = (entry.get("cveID") or "").strip()
    if not cve_id:
        return None

    date_added = entry.get("dateAdded")
    due_date = entry.get("dueDate")

    published = _to_utc_datetime(date_added) or fetched_at

    known_ransomware = (entry.get("knownRansomwareCampaignUse") or "").strip() == "Known"

    # KEV 按定义均已在野利用, 对应最高成熟度; 仅给一条 CISA 官方目录链接作为权威来源,
    # 不抓取 / 不链接任何 PoC 代码页面。
    exploit_refs: list[ExploitRef] = [
        ExploitRef(
            url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",  # type: ignore[arg-type]
            source="cisa",
            label="CISA KEV Catalog",
        )
    ]

    risk = RiskSignal(
        kev_status=KevStatus.LISTED,
        kev_listed=True,
        kev_date_added=date_added if isinstance(date_added, str) else None,
        due_date=due_date if isinstance(due_date, str) else None,
        known_ransomware=known_ransomware,
        known_exploited=True,  # KEV 条目按定义均已在野利用
        exploit_in_the_wild=True,  # 兼容字段同步
        has_public_exploit=True,
        exploit_maturity=ExploitMaturity.IN_THE_WILD,
        exploit_references=exploit_refs,
    )

    vendor = (entry.get("vendorProject") or "").strip()
    product = (entry.get("product") or "").strip()

    source_info = SourceInfo(
        source="kev",
        source_sub="CISA",
        source_name="CISA KEV",
        source_url=_cve_source_url(cve_id),  # type: ignore[arg-type]
        native_id=cve_id,
    )

    references: list[str] = [
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    ]
    notes = (entry.get("notes") or "").strip()
    if notes.startswith("http"):
        # KEV notes 字段偶尔放的是参考 URL
        for url in notes.split():
            if url.startswith("http"):
                references.append(url)

    return RawItem(
        id=f"kev:{cve_id}",
        type=ItemType.KEV,
        source_info=source_info,
        title=_build_title(entry),
        summary=_summary(entry),
        raw_text=None,
        published_at=published,
        updated_at=None,
        fetched_at=fetched_at,
        authors=[],
        affiliations=[],
        cves=[cve_id],
        vendors=[vendor] if vendor else [],
        products=[product] if product else [],
        affected_versions=[],
        topics=["kev", "exploited"],
        lang="en",
        risk=risk,
        references=references,  # type: ignore[arg-type]
    )


def normalize_feed(feed: dict, fetched_at: datetime) -> List[RawItem]:
    vulns = feed.get("vulnerabilities") or []
    if not isinstance(vulns, list):
        raise KevFetchError("CISA KEV JSON 缺少 vulnerabilities 数组")
    items: List[RawItem] = []
    for entry in vulns:
        if not isinstance(entry, dict):
            continue
        try:
            item = entry_to_raw_item(entry, fetched_at)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[WARN] 跳过一条 KEV 解析失败: {exc}\n")
            continue
        if item is not None:
            items.append(item)
    return items


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------


def dump_items(
    items: Iterable[RawItem],
    output_path: Path,
    feed_meta: dict[str, Any] | None = None,
) -> int:
    items_list = list(items)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "items": [item.model_dump(mode="json") for item in items_list],
    }
    if feed_meta:
        payload["meta"] = feed_meta  # type: ignore[assignment]
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")
    return len(items_list)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="抓取 CISA KEV 目录, 输出 RawItem JSON"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"输出文件路径 (默认 {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--url",
        default=KEV_FEED_URL,
        help="自定义 KEV JSON URL (调试用)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=0,
        help="如果 > 0，则仅保留最近 N 天新增的 KEV。0 代表全量 (默认 0)。",
    )
    args = parser.parse_args()

    print(f"[INFO] 拉取 CISA KEV: {args.url}", file=sys.stderr)

    try:
        feed = fetch_kev_feed(args.url)
    except KevFetchError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1

    fetched_at = datetime.now(timezone.utc)

    try:
        items = normalize_feed(feed, fetched_at)
    except KevFetchError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
        
    if args.days > 0:
        from datetime import timedelta
        cutoff = fetched_at - timedelta(hours=args.days * 24)
        items = [item for item in items if item.published_at and item.published_at >= cutoff]

    meta = {
        "catalog_version": feed.get("catalogVersion"),
        "date_released": feed.get("dateReleased"),
        "count": feed.get("count"),
        "fetched_at": fetched_at.isoformat(),
        "recommended_action_zh": KEV_RECOMMENDED_ACTION,
    }

    count = dump_items(items, args.output, meta)
    print(f"[OK] 写入 {count} 条 KEV 到 {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
