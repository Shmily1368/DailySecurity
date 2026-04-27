"""
scripts/fetch_osv.py

抓取 OSV.dev 漏洞数据, 归一为 RawItem 落盘。

设计:
    OSV.dev 没有 "最近 N 天" 的通用列表 API (官方 ZIP bucket 太大,
    不适合每日增量)。因此 MVP 采用 "按生态 + CVE 列表批量反查" 策略:

    输入 CVE 列表 (来源: NVD / CISA KEV / GHSA 等上游文件) ->
    调用 POST /v1/querybatch 批量查询 ->
    针对每个 CVE 返回多个 OSV 记录 (不同生态) ->
    再针对每个记录调用 GET /v1/vulns/{id} 取详情并归一化。

    也支持直接传入 OSV ID (GHSA-*, PYSEC-*, ...) 的模式。

支持的生态 (仅用于 topics 归一):
    PyPI / npm / Maven / Go / crates.io / RubyGems / NuGet / Packagist / Pub
    (OSV 实际支持更多; 这里不做白名单限制, 不认识的 ecosystem 原样保留)

字段契约 (OSV -> RawItem):
    - id                = "osv:{osv_id}"  例如 osv:GHSA-xxxx / osv:PYSEC-xxxx
    - type              = advisory
    - source_info       = {source: osv, source_name: 'OSV.dev', ...}
    - title / summary   = summary / details
    - published_at      = published
    - updated_at        = modified
    - cves              = aliases 中 CVE-xxxx
    - products          = affected[].package.name 去重
    - topics            = ["advisory", ecosystem 小写, "cwe-xx"...]
    - risk.cvss_score   = severity[] 取 CVSS_V3 的 score
    - references        = references[].url

安全红线:
    - 不抓取 references 页面正文
    - 不展示 / 不缓存 PoC / 攻击步骤

用法:
    # 按 CVE 列表反查 (推荐)
    python scripts/fetch_osv.py --cve CVE-2024-3094 --cve CVE-2024-21626

    # 从文件取 CVE 列表
    python scripts/fetch_osv.py --cve-file cves.txt

    # 自动从 data/raw/nvd_recent.json 取最近 CVE
    python scripts/fetch_osv.py --nvd-source data/raw/nvd_recent.json --limit 50

    # 直接传入 OSV ID
    python scripts/fetch_osv.py --osv-id GHSA-jfh8-c2jp-5v3q
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

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

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{osv_id}"
OSV_WEB_URL = "https://osv.dev/vulnerability/{osv_id}"

DEFAULT_OUTPUT = Path("data/raw/osv_latest.json")
QUERYBATCH_SIZE = 100
HTTP_TIMEOUT = 30.0
USER_AGENT = "cyber-daily-radar/0.1"


class OsvFetchError(RuntimeError):
    pass


@retry(
    reraise=True,
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=2, min=2, max=20),
    retry=retry_if_exception_type((httpx.HTTPError,)),
)
def _http_post_json(client: httpx.Client, url: str, body: Any) -> Any:
    resp = client.post(url, json=body)
    resp.raise_for_status()
    return resp.json()


@retry(
    reraise=True,
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=2, min=2, max=20),
    retry=retry_if_exception_type((httpx.HTTPError,)),
)
def _http_get_json(client: httpx.Client, url: str) -> Any:
    resp = client.get(url)
    resp.raise_for_status()
    return resp.json()


def query_osv_ids_by_cves(
    client: httpx.Client, cves: list[str]
) -> list[str]:
    """
    POST /v1/querybatch 按 CVE 反查, 返回所有 OSV ID 列表 (去重)。
    Body: {"queries": [{"package": null, "commit": null, ...}]}
    注意: OSV querybatch 要求每个 query 至少有 package 或 commit,
    但对 CVE 反查实际上更推荐 GET /v1/vulns/{CVE-xxxx} (OSV 会把 CVE
    作为 alias, 如果某个 OSV 记录把该 CVE 作为 alias, 直接走 vulns 入口)。

    这里采用更直接的方式: 直接 GET /v1/vulns/{cve_id}, 若 404 则跳过。
    OSV 实际上会把 CVE 作为 alias 分派到对应 OSV ID, 所以这是有效的。
    """
    out: list[str] = []
    for cve in cves:
        try:
            data = _http_get_json(client, OSV_VULN_URL.format(osv_id=cve))
        except RetryError:
            continue
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                continue
            raise
        except httpx.HTTPError:
            continue
        # /v1/vulns/CVE-xxxx 如果命中, 会直接返回一条 OSV 记录 (或者 alias 重定向后的)
        osv_id = data.get("id") if isinstance(data, dict) else None
        if isinstance(osv_id, str) and osv_id and osv_id not in out:
            out.append(osv_id)
        # 保护性限速
        time.sleep(0.1)
    return out


def fetch_osv_vulns(client: httpx.Client, osv_ids: list[str]) -> list[dict]:
    out: list[dict] = []
    for oid in osv_ids:
        try:
            data = _http_get_json(client, OSV_VULN_URL.format(osv_id=oid))
        except RetryError as e:
            sys.stderr.write(f"[WARN] OSV {oid} 取详情失败(重试后): {e}\n")
            continue
        except httpx.HTTPError as e:
            sys.stderr.write(f"[WARN] OSV {oid} 取详情失败: {e!r}\n")
            continue
        if isinstance(data, dict) and data.get("id"):
            out.append(data)
        time.sleep(0.1)
    return out


# ---------------------------------------------------------------------------
# 归一
# ---------------------------------------------------------------------------


def _parse_iso(ts: Any) -> Optional[datetime]:
    if not isinstance(ts, str) or not ts:
        return None
    s = ts.strip()
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _pick_cvss_score(entry: dict) -> tuple[Optional[float], Optional[str]]:
    """
    severity: [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}]
    OSV 的 score 字段实际是 vector string; baseScore 需要自己算或没有。
    策略: 优先 CVSS_V4 > CVSS_V3 > CVSS_V2; 只保留 vector, score 留给后续 CVSS 解析工具。
    为避免在 fetcher 里引入 CVSS 计算依赖, 这里仅返回 vector; cvss_score 留 None。
    """
    severities = entry.get("severity") or []
    if not isinstance(severities, list):
        return None, None
    preferred = ["CVSS_V4", "CVSS_V3", "CVSS_V2"]
    best: Optional[dict] = None
    best_rank = len(preferred)
    for s in severities:
        if not isinstance(s, dict):
            continue
        t = s.get("type")
        if t in preferred:
            rank = preferred.index(t)
            if rank < best_rank:
                best = s
                best_rank = rank
    if not best:
        return None, None
    vec = best.get("score")
    return None, vec if isinstance(vec, str) else None


def _extract_cwes(entry: dict) -> list[str]:
    out: list[str] = []
    db_spec = entry.get("database_specific") or {}
    if isinstance(db_spec, dict):
        cwes = db_spec.get("cwe_ids") or []
        if isinstance(cwes, list):
            for c in cwes:
                if isinstance(c, str) and c.startswith("CWE-"):
                    tag = c.lower()
                    if tag not in out:
                        out.append(tag)
    return out


def _extract_ecosystems_and_products(entry: dict) -> tuple[list[str], list[str]]:
    ecosystems: list[str] = []
    products: list[str] = []
    for a in entry.get("affected") or []:
        if not isinstance(a, dict):
            continue
        pkg = a.get("package") or {}
        if not isinstance(pkg, dict):
            continue
        eco = pkg.get("ecosystem")
        name = pkg.get("name")
        if isinstance(eco, str) and eco:
            eco_norm = eco.lower()
            if eco_norm not in ecosystems:
                ecosystems.append(eco_norm)
        if isinstance(name, str) and name and name not in products:
            products.append(name)
    return ecosystems, products


def entry_to_raw_item(entry: dict, fetched_at: datetime) -> Optional[RawItem]:
    osv_id = entry.get("id")
    if not isinstance(osv_id, str) or not osv_id:
        return None

    summary = (entry.get("summary") or "").strip()
    details = (entry.get("details") or "").strip()
    title = summary or osv_id
    title = title if len(title) <= 180 else title[:177] + "..."
    summary_final = (details or summary or None)
    if summary_final and len(summary_final) > 4000:
        summary_final = summary_final[:4000]

    published = _parse_iso(entry.get("published")) or fetched_at
    updated = _parse_iso(entry.get("modified"))

    # aliases -> CVE
    cves: list[str] = []
    for a in entry.get("aliases") or []:
        if isinstance(a, str) and a.startswith("CVE-") and a not in cves:
            cves.append(a)

    # 主条目 id 本身可能是 CVE-xxxx
    if osv_id.startswith("CVE-") and osv_id not in cves:
        cves.append(osv_id)

    ecosystems, products = _extract_ecosystems_and_products(entry)
    cwes = _extract_cwes(entry)
    _, cvss_vector = _pick_cvss_score(entry)

    # references
    refs: list[str] = []
    for r in entry.get("references") or []:
        if isinstance(r, dict):
            url = r.get("url")
            if isinstance(url, str) and url.startswith("http") and url not in refs:
                refs.append(url)

    risk = RiskSignal(
        cvss_score=None,
        cvss_vector=cvss_vector,
    )

    source_info = SourceInfo(
        source="osv",
        source_sub="osv.dev",
        source_name="OSV.dev",
        source_url=OSV_WEB_URL.format(osv_id=osv_id),  # type: ignore[arg-type]
        native_id=osv_id,
    )

    topics = ["advisory"] + ecosystems + cwes

    return RawItem(
        id=f"osv:{osv_id}",
        type=ItemType.ADVISORY,
        source_info=source_info,
        title=title,
        summary=summary_final,
        raw_text=None,
        published_at=published,
        updated_at=updated,
        fetched_at=fetched_at,
        authors=[],
        affiliations=[],
        cves=cves,
        vendors=[],
        products=products,
        affected_versions=[],
        topics=topics,
        lang="en",
        risk=risk,
        references=refs[:20],  # type: ignore[arg-type]
    )


def normalize(entries: Iterable[dict], fetched_at: datetime) -> list[RawItem]:
    out: list[RawItem] = []
    for e in entries:
        try:
            item = entry_to_raw_item(e, fetched_at)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[WARN] 跳过一条 OSV 条目解析失败: {exc}\n")
            continue
        if item is not None:
            out.append(item)
    out.sort(key=lambda x: (x.published_at, x.id), reverse=True)
    return out


# ---------------------------------------------------------------------------
# 输入源
# ---------------------------------------------------------------------------


def _load_cves_from_nvd(path: Path, limit: int) -> list[str]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise OsvFetchError(f"读取 NVD 源失败: {path} ({e})") from e
    items = data.get("items", []) if isinstance(data, dict) else []
    cves: list[str] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        for c in it.get("cves") or []:
            if isinstance(c, str) and c.startswith("CVE-") and c not in cves:
                cves.append(c)
                if len(cves) >= limit:
                    return cves
    return cves


def _load_cves_from_file(path: Path) -> list[str]:
    out: list[str] = []
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("CVE-") and line not in out:
                    out.append(line)
    except OSError as e:
        raise OsvFetchError(f"读取 CVE 文件失败: {path} ({e})") from e
    return out


def dump_items(
    items: Iterable[RawItem],
    output_path: Path,
    meta: dict[str, Any] | None = None,
) -> int:
    items_list = list(items)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "items": [x.model_dump(mode="json") for x in items_list],
    }
    if meta:
        payload["meta"] = meta
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")
    return len(items_list)


def main() -> int:
    parser = argparse.ArgumentParser(description="按 CVE / OSV ID 批量拉取 OSV.dev")
    parser.add_argument("--cve", action="append", default=[], help="CVE 编号, 可重复")
    parser.add_argument("--cve-file", type=Path, help="每行一个 CVE 的文件")
    parser.add_argument(
        "--nvd-source",
        type=Path,
        help="从已有的 NVD RawItem 文件中提取 CVE 列表",
    )
    parser.add_argument(
        "--osv-id",
        action="append",
        default=[],
        help="直接传 OSV ID (GHSA-xxx / PYSEC-xxx), 可重复",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="从 --nvd-source 提取的最大 CVE 数量 (默认 50)",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    cves: list[str] = []
    for c in args.cve or []:
        if c.startswith("CVE-") and c not in cves:
            cves.append(c)

    if args.cve_file:
        for c in _load_cves_from_file(args.cve_file):
            if c not in cves:
                cves.append(c)

    if args.nvd_source:
        for c in _load_cves_from_nvd(args.nvd_source, args.limit):
            if c not in cves:
                cves.append(c)

    osv_ids: list[str] = list(dict.fromkeys(args.osv_id or []))

    if not cves and not osv_ids:
        print(
            "[ERROR] 未提供任何输入 (--cve / --cve-file / --nvd-source / --osv-id)",
            file=sys.stderr,
        )
        return 1

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    with httpx.Client(
        timeout=HTTP_TIMEOUT, headers=headers, follow_redirects=True
    ) as client:
        try:
            if cves:
                print(
                    f"[INFO] 反查 {len(cves)} 个 CVE 对应的 OSV ID...",
                    file=sys.stderr,
                )
                resolved = query_osv_ids_by_cves(client, cves)
                print(
                    f"[INFO] 命中 {len(resolved)} 个 OSV 记录",
                    file=sys.stderr,
                )
                for oid in resolved:
                    if oid not in osv_ids:
                        osv_ids.append(oid)

            if not osv_ids:
                print("[WARN] 未命中任何 OSV 记录", file=sys.stderr)
                fetched_at = datetime.now(timezone.utc)
                dump_items(
                    [],
                    args.output,
                    meta={
                        "cve_inputs": cves,
                        "raw_count": 0,
                        "normalized_count": 0,
                        "fetched_at": fetched_at.isoformat(),
                        "source": "OSV.dev /v1/vulns",
                    },
                )
                return 0

            print(
                f"[INFO] 拉取 {len(osv_ids)} 个 OSV 详情...",
                file=sys.stderr,
            )
            entries = fetch_osv_vulns(client, osv_ids)
        except OsvFetchError as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            return 1

    fetched_at = datetime.now(timezone.utc)
    items = normalize(entries, fetched_at)

    meta = {
        "cve_inputs": cves,
        "osv_id_count": len(osv_ids),
        "raw_count": len(entries),
        "normalized_count": len(items),
        "fetched_at": fetched_at.isoformat(),
        "source": "OSV.dev /v1/vulns",
    }

    count = dump_items(items, args.output, meta)
    print(f"[OK] 写入 {count} 条 OSV 到 {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
