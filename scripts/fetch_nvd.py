"""
scripts/fetch_nvd.py

抓取 NVD CVE API 2.0 最近 N 天发布或修改的 CVE, 归一为 RawItem 落盘。
首次按 --days 初始化窗口, 后续从持久化水位连续续抓, 每轮共享翻页预算。

数据源:
    https://services.nvd.nist.gov/rest/json/cves/2.0

字段契约 (NVD 2.0 -> RawItem):
    - id                = "nvd:{cveId}"
    - type              = cve
    - source_info       = {source: nvd, source_name: 'NVD', source_url: nvd 详情页}
    - title / summary   = cve.descriptions[lang=en].value (title 截断)
    - published_at      = cve.published
    - updated_at        = cve.lastModified
    - cves              = [cveId]
    - vendors/products  = 解析 configurations[].nodes[].cpeMatch[].criteria
    - topics            = CWE 前缀 (e.g. cwe-79) + "cve"
    - risk.cvss_score   = 优先 CVSS v3.1 > v3.0 > v2 baseScore
    - risk.cvss_vector  = 对应 vectorString
    - risk.has_public_exploit / exploit_references
                        = 当 references[].tags 含 "Exploit" 时填充
                          (只记录 URL + 来源, 严禁抓取 / 缓存正文)
    - references        = cve.references[].url 的前 N 条

安全红线:
    本脚本只读取 NVD 元数据; 不下载、不解析、不存储任何 exploit / PoC
    正文、payload、shellcode、攻击步骤。对 references 中带 "Exploit" 标签
    的链接, 仅保留 URL + source + label, 由前端让读者自行跳转第三方站点。

用法:
    python scripts/fetch_nvd.py                  # 默认最近 2 天
    python scripts/fetch_nvd.py --days 7
    python scripts/fetch_nvd.py --output data/raw/2026-04-27/nvd.json
    NVD_API_KEY=xxx python scripts/fetch_nvd.py  # 限速放宽到 50/30s

退出码:
    0 = 成功
    1 = 网络 / 解析失败
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, List, Optional

import httpx
from fetch_result import FetchBatch
from storage import atomic_json
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
    RawItem,
    RiskSignal,
    SourceInfo,
)


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_OUTPUT = Path("data/raw/nvd_recent.json")
DEFAULT_DAYS = 2
MAX_DAYS = 120  # NVD 单次查询窗口硬上限
PAGE_SIZE = 500  # 降低单页大小以防 NVD 服务器超时断流 (最大 2000)
HTTP_TIMEOUT = 60.0
USER_AGENT = "cyber-daily-radar/0.1 (+https://github.com/)"

# NVD 限速 (参见 https://nvd.nist.gov/developers/start-here)
# 无 key: 5 请求 / 30s => 保守 6.5s 间隔
# 有 key: 50 请求 / 30s => 保守 0.7s 间隔
SLEEP_NO_KEY = 7.5  # Increased slightly to be safe
SLEEP_WITH_KEY = 1.0

# 当 API 返回总数非常大（如几千条）时，限制最大翻页次数以防止 CI/CD 运行时间过长
MAX_PAGES = 5

# NVD references 上如果带 "Exploit" 标签, 仅保留 URL 元数据;
# 不抓取也不镜像第三方页面正文。
EXPLOIT_REF_TAG = "Exploit"


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class NvdFetchError(RuntimeError):
    """NVD 抓取失败统一异常。"""


@retry(
    reraise=True,
    stop=stop_after_attempt(6),
    wait=wait_exponential(multiplier=2, min=3, max=30),
    retry=retry_if_exception_type((httpx.HTTPError, httpx.ReadError, httpx.RemoteProtocolError)),
)
def _http_get_json(
    client: httpx.Client, url: str, params: dict[str, Any]
) -> dict:
    resp = client.get(url, params=params)
    if resp.status_code == 403 or resp.status_code == 429:
        print(f"[WARN] NVD API limit hit ({resp.status_code}). Sleeping for 30s before retry...", file=sys.stderr)
        time.sleep(30)
        resp.raise_for_status()
    # 429 / 5xx 直接 raise, 由 tenacity 重试
    resp.raise_for_status()
    return resp.json()


def fetch_nvd_window(
    start: datetime,
    end: datetime,
    api_key: Optional[str],
    *,
    url: str = NVD_API_URL,
    start_index: int = 0,
    max_pages: Optional[int] = None,
) -> list[dict]:
    """
    拉取 [start, end] 范围内所有 lastModified 的 CVE, 自动翻页。
    时间使用 ISO 8601 UTC (YYYY-MM-DDTHH:MM:SS.sssZ 形式, NVD 要求 extended)。
    """
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key

    sleep = SLEEP_WITH_KEY if api_key else SLEEP_NO_KEY

    # NVD 要求 ISO 格式, 这里用 milliseconds + Z
    def _fmt(ts: datetime) -> str:
        return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    all_items: list[dict] = []
    total_results: Optional[int] = None
    page_count = 0
    page_limit = MAX_PAGES if max_pages is None else max_pages
    errors = []

    with httpx.Client(
        timeout=HTTP_TIMEOUT,
        headers=headers,
        follow_redirects=True,
    ) as client:
        while True:
            params: dict[str, Any] = {
                "lastModStartDate": _fmt(start),
                "lastModEndDate": _fmt(end),
                "resultsPerPage": PAGE_SIZE,
                "startIndex": start_index,
            }
            try:
                payload = _http_get_json(client, url, params)
            except RetryError as e:
                if all_items:
                    errors.append({"error_type": type(e).__name__, "start_index": start_index})
                    break
                raise NvdFetchError(f"NVD 请求在重试后仍失败: {e}") from e
            except httpx.HTTPError as e:
                if all_items:
                    errors.append({"error_type": type(e).__name__, "start_index": start_index})
                    break
                raise NvdFetchError(f"NVD 请求失败: {e!r}") from e
            except json.JSONDecodeError as e:
                raise NvdFetchError(f"NVD JSON 解析失败: {e}") from e

            if not isinstance(payload, dict):
                raise NvdFetchError("NVD 返回非对象 JSON")

            vulns = payload.get("vulnerabilities")
            if not isinstance(vulns, list):
                raise NvdFetchError("NVD 返回 vulnerabilities 字段非数组")
            if not isinstance(payload.get("totalResults"), int) or payload["totalResults"] < 0:
                raise NvdFetchError("NVD totalResults missing or invalid")

            all_items.extend(vulns)
            page_count += 1

            if total_results is None:
                tr = payload.get("totalResults")
                total_results = int(tr) if isinstance(tr, int) else len(vulns)

            start_index += len(vulns)
            # 翻页结束: 本次返回 0 条, 或者已经覆盖 totalResults，或者达到了最大的翻页次数
            if not vulns or start_index >= (total_results or 0) or page_count >= page_limit:
                if page_count >= page_limit and start_index < (total_results or 0):
                    print(f"[WARN] 达到最大翻页限制 ({page_limit})。总数: {total_results}，已获取: {start_index}。", file=sys.stderr)
                break

            # 主动限速, 避免触发 NVD 的 429
            time.sleep(sleep)

    partial = bool(errors) or start_index < (total_results or 0)
    return FetchBatch(all_items, status="partial" if partial else "success",
                      next_start_index=start_index if partial else None,
                      total_results=total_results, errors=errors, page_count=page_count,
                      window_start=start.isoformat(), window_end=end.isoformat())


# ---------------------------------------------------------------------------
# 归一
# ---------------------------------------------------------------------------


def _parse_iso(ts: Any) -> Optional[datetime]:
    if not isinstance(ts, str) or not ts:
        return None
    s = ts.strip()
    # NVD 返回的 published/lastModified 通常像 "2026-04-25T12:34:56.789"
    # 视为 UTC
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _pick_english_description(cve: dict) -> Optional[str]:
    descs = cve.get("descriptions") or []
    if not isinstance(descs, list):
        return None
    for d in descs:
        if isinstance(d, dict) and d.get("lang") == "en":
            val = d.get("value")
            if isinstance(val, str) and val.strip():
                return val.strip()
    # 没找到英文就退而求其次
    for d in descs:
        if isinstance(d, dict):
            val = d.get("value")
            if isinstance(val, str) and val.strip():
                return val.strip()
    return None


def _pick_cvss(cve: dict) -> tuple[Optional[float], Optional[str]]:
    """
    CVSS 选择优先级: v3.1 > v3.0 > v2。
    取第一条 Primary, 没有 Primary 就用第一条。
    """
    metrics = cve.get("metrics") or {}
    if not isinstance(metrics, dict):
        return None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if not isinstance(arr, list) or not arr:
            continue
        chosen: Optional[dict] = None
        for m in arr:
            if isinstance(m, dict) and m.get("type") == "Primary":
                chosen = m
                break
        if chosen is None and isinstance(arr[0], dict):
            chosen = arr[0]
        if not chosen:
            continue
        data = chosen.get("cvssData") or {}
        score = data.get("baseScore")
        vector = data.get("vectorString")
        try:
            score_f = float(score) if score is not None else None
        except (TypeError, ValueError):
            score_f = None
        vector_s = vector if isinstance(vector, str) else None
        if score_f is not None or vector_s is not None:
            return score_f, vector_s
    return None, None


def _pick_cwes(cve: dict) -> list[str]:
    out: list[str] = []
    weaknesses = cve.get("weaknesses") or []
    if not isinstance(weaknesses, list):
        return out
    for w in weaknesses:
        if not isinstance(w, dict):
            continue
        for d in w.get("description") or []:
            if isinstance(d, dict) and d.get("lang") == "en":
                val = d.get("value")
                if isinstance(val, str) and val.startswith("CWE-"):
                    tag = val.lower()  # cwe-79
                    if tag not in out:
                        out.append(tag)
    return out


def _parse_vendors_products(cve: dict) -> tuple[list[str], list[str]]:
    """
    从 configurations[].nodes[].cpeMatch[].criteria 解析 vendor/product。
    CPE 2.3 URI: cpe:2.3:a:<vendor>:<product>:<version>:...
    """
    vendors: list[str] = []
    products: list[str] = []
    configs = cve.get("configurations") or []
    if not isinstance(configs, list):
        return vendors, products
    for conf in configs:
        if not isinstance(conf, dict):
            continue
        for node in conf.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict):
                    continue
                cpe = match.get("criteria")
                if not isinstance(cpe, str) or not cpe.startswith("cpe:2.3:"):
                    continue
                parts = cpe.split(":")
                # cpe:2.3:a:vendor:product:version:...
                if len(parts) < 5:
                    continue
                vendor = parts[3].replace("_", " ").strip()
                product = parts[4].replace("_", " ").strip()
                if vendor and vendor != "*" and vendor not in vendors:
                    vendors.append(vendor)
                if product and product != "*" and product not in products:
                    products.append(product)
    return vendors, products


def _pick_references(cve: dict) -> tuple[list[str], list[ExploitRef]]:
    """
    返回 (references 原始 URL 列表, exploit 外链 ExploitRef 列表)。
    仅存 URL + source + label, 不抓取第三方正文。
    """
    refs: list[str] = []
    exploit_refs: list[ExploitRef] = []
    raw = cve.get("references") or []
    if not isinstance(raw, list):
        return refs, exploit_refs
    for r in raw:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        if not isinstance(url, str) or not url.startswith("http"):
            continue
        if url not in refs:
            refs.append(url)
        tags = r.get("tags") or []
        if isinstance(tags, list) and EXPLOIT_REF_TAG in tags:
            source = r.get("source") or ""
            try:
                exploit_refs.append(
                    ExploitRef(
                        url=url,  # type: ignore[arg-type]
                        source="nvd-ref" if not source else str(source),
                        label=f"NVD reference ({EXPLOIT_REF_TAG})",
                    )
                )
            except Exception:  # noqa: BLE001
                # 极端情况下 URL 校验失败, 忽略单条
                continue
    return refs, exploit_refs


def _nvd_detail_url(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def entry_to_raw_item(entry: dict, fetched_at: datetime) -> Optional[RawItem]:
    cve = entry.get("cve") if isinstance(entry, dict) else None
    if not isinstance(cve, dict):
        return None
    cve_id = (cve.get("id") or "").strip()
    if not cve_id.startswith("CVE-"):
        return None

    desc = _pick_english_description(cve) or cve_id
    # title 截断; summary 最长 4000
    title = desc if len(desc) <= 180 else desc[:177] + "..."
    summary = desc[:4000] if desc else None

    published = _parse_iso(cve.get("published"))
    updated = _parse_iso(cve.get("lastModified"))

    cvss_score, cvss_vector = _pick_cvss(cve)
    cwes = _pick_cwes(cve)
    vendors, products = _parse_vendors_products(cve)
    refs, exploit_refs = _pick_references(cve)

    has_exploit = len(exploit_refs) > 0
    maturity = ExploitMaturity.POC if has_exploit else ExploitMaturity.UNREPORTED

    risk = RiskSignal(
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        has_public_exploit=has_exploit,
        exploit_maturity=maturity,
        exploit_references=exploit_refs,
        patch_status="available" if any(
            "Patch" in (ref.get("tags") or []) for ref in cve.get("references", [])
            if isinstance(ref, dict) and str(ref.get("url", "")).startswith("http")
        ) else "unknown",
        patch_references=[ref["url"] for ref in cve.get("references", [])
                          if isinstance(ref, dict) and "Patch" in (ref.get("tags") or [])
                          and str(ref.get("url", "")).startswith("http")],
    )

    source_info = SourceInfo(
        source="nvd",
        source_sub="NIST",
        source_name="NVD",
        source_url=_nvd_detail_url(cve_id),  # type: ignore[arg-type]
        native_id=cve_id,
        source_quality="primary",
    )

    topics = ["cve"] + cwes

    return RawItem(
        id=f"nvd:{cve_id}",
        type=ItemType.CVE,
        source_info=source_info,
        title=title,
        summary=summary,
        raw_text=None,
        published_at=published,
        updated_at=updated,
        fetched_at=fetched_at,
        first_seen_at=fetched_at,
        date_precision="exact" if published else "unknown",
        authors=[],
        affiliations=[],
        cves=[cve_id],
        vendors=vendors,
        products=products,
        affected_versions=[],
        topics=topics,
        lang="en",
        risk=risk,
        references=refs[:20],  # type: ignore[arg-type]
    )


def normalize(vulns: Iterable[dict], fetched_at: datetime) -> list[RawItem]:
    items: list[RawItem] = []
    for entry in vulns:
        try:
            item = entry_to_raw_item(entry, fetched_at)
        except Exception as exc:  # noqa: BLE001
            # NVD 结构偶尔异常, 单条失败不应影响整体
            sys.stderr.write(f"[WARN] 跳过一条 NVD 条目解析失败: {exc}\n")
            continue
        if item is not None:
            items.append(item)
    # 按 published_at 倒序, 便于后续排序 / 稳定 diff
    items.sort(key=lambda x: (x.updated_at or x.published_at or x.fetched_at, x.id), reverse=True)
    return items


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------


def dump_items(
    items: Iterable[RawItem],
    output_path: Path,
    meta: dict[str, Any] | None = None,
) -> int:
    items_list = list(items)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "items": [item.model_dump(mode="json") for item in items_list],
    }
    if meta:
        payload["meta"] = meta
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")
    return len(items_list)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="抓取 NVD CVE 最近 N 天变更, 输出 RawItem JSON"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_DAYS,
        help=f"首次运行回溯天数 (默认 {DEFAULT_DAYS}, 最大 {MAX_DAYS}); 后续从水位续抓",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"输出文件路径 (默认 {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--url",
        default=NVD_API_URL,
        help="自定义 NVD API URL (调试用)",
    )
    parser.add_argument("--state-file", type=Path, default=Path("data/state/nvd_cursor.json"))
    args = parser.parse_args()

    days = max(1, min(args.days, MAX_DAYS))
    if days != args.days:
        print(f"[WARN] --days 调整为 {days} (允许范围 1~{MAX_DAYS})", file=sys.stderr)

    api_key = os.environ.get("NVD_API_KEY") or None
    if api_key:
        print("[INFO] 使用 NVD_API_KEY (限速放宽)", file=sys.stderr)
    else:
        print("[INFO] 未设置 NVD_API_KEY, 使用公共限速 (5 req / 30s)", file=sys.stderr)

    target_end = datetime.now(timezone.utc).replace(microsecond=0)
    start = target_end - timedelta(days=days)
    cursor = {}
    completed_until = None
    if args.state_file.exists():
        try:
            cursor = json.loads(args.state_file.read_text())
            if not isinstance(cursor, dict):
                raise ValueError("NVD cursor must be an object")
            completed_until = _parse_iso(cursor.get("completed_until"))
            if "completed_until" in cursor and completed_until is None:
                raise ValueError("Invalid completed_until")
            if cursor.get("next_start_index") is not None:
                start = _parse_iso(cursor.get("window_start"))
                end = _parse_iso(cursor.get("window_end"))
                index = cursor["next_start_index"]
                if (start is None or end is None or start >= end
                        or type(index) is not int or index < 0
                        or not isinstance(cursor.get("entries", []), list)):
                    raise ValueError("Invalid pending NVD window")
            elif completed_until is not None:
                start = completed_until
            else:
                raise ValueError("NVD cursor has no coverage state")
        except (OSError, ValueError) as exc:
            print(f"[ERROR] 读取 NVD 状态失败: {exc}", file=sys.stderr)
            return 1

    initial_start = start
    remaining_pages = MAX_PAGES
    pending = cursor if cursor.get("next_start_index") is not None else None
    next_state = cursor
    vulns = []
    windows = []
    errors = []
    while remaining_pages > 0 and (pending is not None or start < target_end):
        # Resume a frozen page window, then catch up from its end, never from now-days.
        end = (_parse_iso(pending["window_end"]) if pending is not None
               else min(target_end, start + timedelta(days=MAX_DAYS)))
        index = pending["next_start_index"] if pending is not None else 0
        entries = pending.get("entries", []) if pending is not None else []
        print(f"[INFO] 拉取 NVD CVE: lastMod {start.isoformat()} ~ {end.isoformat()}",
              file=sys.stderr)
        try:
            batch = fetch_nvd_window(start, end, api_key, url=args.url,
                                    start_index=index, max_pages=remaining_pages)
        except NvdFetchError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            if not windows:
                return 1
            errors.append({"error_type": type(exc).__name__, "window_start": start.isoformat(),
                           "window_end": end.isoformat(), "start_index": index})
            next_state = {"completed_until": completed_until.isoformat(),
                          "window_start": start.isoformat(), "window_end": end.isoformat(),
                          "next_start_index": index, "entries": entries}
            break

        window_entries = entries + list(batch)
        vulns.extend(window_entries)
        windows.append(batch.meta)
        errors.extend(batch.meta["errors"])
        remaining_pages -= batch.meta["page_count"]
        if batch.meta["next_start_index"] is not None:
            next_state = {**batch.meta, "entries": window_entries}
            if completed_until is not None:
                next_state["completed_until"] = completed_until.isoformat()
            break
        completed_until = end
        next_state = {"completed_until": completed_until.isoformat()}
        pending = None
        start = end
        if remaining_pages > 0 and start < target_end:
            time.sleep(SLEEP_WITH_KEY if api_key else SLEEP_NO_KEY)

    fetched_at = datetime.now(timezone.utc)
    items = normalize(vulns, fetched_at)

    meta = {
        **(windows[-1] if windows else {}),
        "window_start": initial_start.isoformat(),
        "window_end": windows[-1]["window_end"] if windows else start.isoformat(),
        "target_end": target_end.isoformat(),
        "completed_until": completed_until.isoformat() if completed_until is not None else None,
        "next_start_index": next_state.get("next_start_index"),
        "page_count": MAX_PAGES - remaining_pages,
        "status": ("partial" if next_state.get("next_start_index") is not None
                   or completed_until is not None and completed_until < target_end
                   else "success" if vulns else "no_new"),
        "errors": errors,
        "windows": windows,
        "raw_count": len(vulns),
        "normalized_count": len(items),
        "fetched_at": fetched_at.isoformat(),
        "source": "NVD CVE API 2.0",
    }

    count = dump_items(items, args.output, meta)
    atomic_json(args.state_file, next_state)
    print(f"[OK] 写入 {count} 条 CVE 到 {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
