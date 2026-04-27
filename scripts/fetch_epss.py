"""
scripts/fetch_epss.py

查询 FIRST.org EPSS API 获取 CVE 的利用概率评分, 归一为 RawItem 结构落盘。

数据源:
    https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNN,CVE-...

字段契约:
    - id = "epss:{cveID}"
    - type = "cve"
    - cves = [cveID]
    - risk.epss_score / risk.epss_percentile
    - title 形如 "EPSS Score for CVE-XXXX-YYYY (pct=..., score=...)"

行为:
    - 如果命令行未传 --cve / --cve-file, 则自动从 data/raw/cisa_kev.json 读取最近
      N 天 (默认 30) 加入 KEV 的 CVE 作为查询集。
    - API 按 100 个 CVE / 批 分批请求, 避免 URL 超长。

安全红线:
    只保存统计评分, 不包含任何利用细节。

用法:
    python scripts/fetch_epss.py
    python scripts/fetch_epss.py --cve CVE-2024-12345 --cve CVE-2024-67890
    python scripts/fetch_epss.py --cve-file cve_list.txt
    python scripts/fetch_epss.py --kev-days 7 --output data/raw/epss_scores.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from typing import Iterable, List

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
    ItemType,
    RawItem,
    RiskSignal,
    SourceInfo,
)


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

EPSS_API = "https://api.first.org/data/v1/epss"
DEFAULT_OUTPUT = Path("data/raw/epss_scores.json")
DEFAULT_KEV_SOURCE = Path("data/raw/cisa_kev.json")
DEFAULT_KEV_WINDOW_DAYS = 30
BATCH_SIZE = 100
HTTP_TIMEOUT = 30.0
USER_AGENT = "cyber-daily-radar/0.1 (+https://github.com/)"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


# ---------------------------------------------------------------------------
# 错误
# ---------------------------------------------------------------------------


class EpssFetchError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((httpx.HTTPError,)),
)
def _http_get_json(client: httpx.Client, url: str, params: dict) -> dict:
    resp = client.get(url, params=params)
    resp.raise_for_status()
    return resp.json()


def query_epss(cves: List[str]) -> List[dict]:
    """按批查询 EPSS, 返回 API 原始 data 列表 (每项含 cve/epss/percentile/date)。"""
    if not cves:
        return []
    results: List[dict] = []
    with httpx.Client(
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as client:
        for i in range(0, len(cves), BATCH_SIZE):
            batch = cves[i : i + BATCH_SIZE]
            params = {"cve": ",".join(batch)}
            try:
                data = _http_get_json(client, EPSS_API, params)
            except RetryError as e:
                raise EpssFetchError(
                    f"EPSS 请求批次 {i // BATCH_SIZE} 在重试后仍失败: {e}"
                ) from e
            except httpx.HTTPError as e:
                raise EpssFetchError(f"EPSS 请求失败: {e!r}") from e
            except json.JSONDecodeError as e:
                raise EpssFetchError(f"EPSS JSON 解析失败: {e}") from e

            if data.get("status") != "OK":
                raise EpssFetchError(
                    f"EPSS API 返回非 OK: {data.get('status')} {data.get('status-code')}"
                )
            results.extend(data.get("data") or [])
    return results


# ---------------------------------------------------------------------------
# 输入: CVE 列表解析
# ---------------------------------------------------------------------------


def _read_cve_file(path: Path) -> List[str]:
    out: List[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            cve = line.strip()
            if cve and CVE_RE.match(cve):
                out.append(cve)
    return out


def _validate_cves(cves: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for cve in cves:
        cve = cve.strip()
        if not CVE_RE.match(cve):
            sys.stderr.write(f"[WARN] 忽略非法 CVE 格式: {cve!r}\n")
            continue
        if cve in seen:
            continue
        seen.add(cve)
        out.append(cve)
    return out


def collect_from_kev(
    kev_path: Path,
    days: int,
    now_utc: datetime,
) -> List[str]:
    """从 data/raw/cisa_kev.json 取最近 days 天加入 KEV 的 CVE。"""
    if not kev_path.exists():
        raise EpssFetchError(
            f"KEV 文件不存在: {kev_path}; 请先运行 scripts/fetch_cisa_kev.py "
            "或显式通过 --cve / --cve-file 指定查询集"
        )
    try:
        with kev_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise EpssFetchError(f"KEV 文件 JSON 解析失败: {e}") from e

    items = data.get("items") or []
    cutoff = now_utc.date() - timedelta(days=days)
    out: List[str] = []
    for item in items:
        risk = item.get("risk") or {}
        date_added = risk.get("kev_date_added")
        cves = item.get("cves") or []
        if not cves:
            continue
        if not date_added:
            # 没有日期就一律纳入 (保守)
            out.extend(cves)
            continue
        try:
            d = datetime.strptime(date_added, "%Y-%m-%d").date()
        except ValueError:
            continue
        if d >= cutoff:
            out.extend(cves)
    return _validate_cves(out)


# ---------------------------------------------------------------------------
# 归一
# ---------------------------------------------------------------------------


def _to_utc_datetime(date_str: str | None) -> datetime:
    if not date_str:
        return datetime.now(timezone.utc)
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d").date()
        return datetime.combine(d, time.min, tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def epss_entry_to_raw_item(entry: dict, fetched_at: datetime) -> RawItem | None:
    cve = (entry.get("cve") or "").strip()
    if not CVE_RE.match(cve):
        return None
    try:
        epss_score = float(entry["epss"])
    except (KeyError, TypeError, ValueError):
        return None
    try:
        percentile = float(entry["percentile"]) if entry.get("percentile") is not None else None
    except (TypeError, ValueError):
        percentile = None

    epss_date = entry.get("date")
    published_at = _to_utc_datetime(epss_date)

    risk = RiskSignal(
        epss_score=max(0.0, min(1.0, epss_score)),
        epss_percentile=(
            max(0.0, min(1.0, percentile)) if percentile is not None else None
        ),
    )

    source_info = SourceInfo(
        source="epss",
        source_sub="FIRST.org",
        source_name="FIRST EPSS",
        source_url=f"https://www.first.org/epss/data_stats#search-{cve}",  # type: ignore[arg-type]
        native_id=cve,
    )

    title = (
        f"EPSS score for {cve} "
        f"(score={epss_score:.4f}"
        + (f", pct={percentile:.4f}" if percentile is not None else "")
        + ")"
    )

    return RawItem(
        id=f"epss:{cve}",
        type=ItemType.CVE,
        source_info=source_info,
        title=title,
        summary=None,
        raw_text=None,
        published_at=published_at,
        updated_at=None,
        fetched_at=fetched_at,
        authors=[],
        affiliations=[],
        cves=[cve],
        vendors=[],
        products=[],
        affected_versions=[],
        topics=["epss"],
        lang="en",
        risk=risk,
        references=["https://www.first.org/epss/"],  # type: ignore[list-item]
    )


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------


def dump_items(
    items: List[RawItem],
    output_path: Path,
    meta: dict | None = None,
) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict = {"items": [i.model_dump(mode="json") for i in items]}
    if meta:
        payload["meta"] = meta
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")
    return len(items)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="查询 EPSS 评分, 输出 RawItem JSON"
    )
    parser.add_argument(
        "--cve",
        action="append",
        default=[],
        help="CVE id, 可多次传入 (如 --cve CVE-2024-12345 --cve CVE-2024-67890)",
    )
    parser.add_argument(
        "--cve-file",
        type=Path,
        default=None,
        help="每行一个 CVE 的文件路径",
    )
    parser.add_argument(
        "--kev-source",
        type=Path,
        default=DEFAULT_KEV_SOURCE,
        help=f"无 --cve 时从此 KEV 文件读取 (默认 {DEFAULT_KEV_SOURCE})",
    )
    parser.add_argument(
        "--kev-days",
        type=int,
        default=DEFAULT_KEV_WINDOW_DAYS,
        help=f"从 KEV 取最近 N 天加入的条目 (默认 {DEFAULT_KEV_WINDOW_DAYS})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"输出路径 (默认 {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    now_utc = datetime.now(timezone.utc)

    # 1. 组装 CVE 列表
    cves: List[str] = []
    cves.extend(_validate_cves(args.cve))
    if args.cve_file:
        if not args.cve_file.exists():
            print(f"[ERROR] --cve-file 不存在: {args.cve_file}", file=sys.stderr)
            return 2
        cves.extend(_validate_cves(_read_cve_file(args.cve_file)))

    if not cves:
        try:
            cves = collect_from_kev(args.kev_source, args.kev_days, now_utc)
        except EpssFetchError as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            return 2
        if not cves:
            print(
                f"[WARN] KEV 文件 {args.kev_source} 最近 {args.kev_days} 天无 CVE, 退出",
                file=sys.stderr,
            )
            return 0
        print(
            f"[INFO] 从 KEV 取得 {len(cves)} 个 CVE (最近 {args.kev_days} 天)",
            file=sys.stderr,
        )
    else:
        # 去重
        cves = _validate_cves(cves)
        print(f"[INFO] 从命令行取得 {len(cves)} 个 CVE", file=sys.stderr)

    # 2. 查询 EPSS
    try:
        entries = query_epss(cves)
    except EpssFetchError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1

    fetched_at = datetime.now(timezone.utc)

    # 3. 归一
    items: List[RawItem] = []
    for entry in entries:
        item = epss_entry_to_raw_item(entry, fetched_at)
        if item is not None:
            items.append(item)

    missing = sorted(set(cves) - {e.get("cve") for e in entries if e.get("cve")})
    if missing:
        print(
            f"[INFO] EPSS 无评分 (可能因 CVE 太新): {len(missing)} 条",
            file=sys.stderr,
        )

    meta = {
        "requested_count": len(cves),
        "returned_count": len(entries),
        "missing_count": len(missing),
        "fetched_at": fetched_at.isoformat(),
    }

    count = dump_items(items, args.output, meta)
    print(f"[OK] 写入 {count} 条 EPSS 到 {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
