"""
scripts/fetch_github_advisory.py

抓取 GitHub Advisory Database (GHSA) 最近 N 天发布 / 更新的 advisory,
归一为 RawItem 落盘。

数据源:
    https://api.github.com/advisories (REST v2022-11-28)

认证:
    GITHUB_TOKEN 环境变量, 可选。
    - 无 token: 匿名访问, 限速 60 请求 / 小时
    - 有 token: 5000 请求 / 小时

字段契约 (GHSA REST -> RawItem):
    - id                = "ghsa:{ghsa_id}"
    - type              = advisory
    - source_info       = {source: ghsa, source_name: 'GitHub Advisory', ...}
    - title / summary   = summary / description
    - published_at      = published_at
    - updated_at        = updated_at
    - cves              = [cve_id] (如果有)
    - vendors/products  = 从 vulnerabilities[].package 提取
    - topics            = ["advisory", ecosystem, "cwe-XX"...]
    - risk.cvss_score   = cvss.score (GHSA 返回)
    - risk.cvss_vector  = cvss.vector_string
    - references        = references[].url

安全红线:
    - 不抓取第三方 references 页面正文
    - 不展示 PoC / 攻击步骤

用法:
    python scripts/fetch_github_advisory.py                 # 默认最近 3 天
    python scripts/fetch_github_advisory.py --days 7
    python scripts/fetch_github_advisory.py --ecosystem pip --severity high
    GITHUB_TOKEN=xxx python scripts/fetch_github_advisory.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
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
    Severity,
    SourceInfo,
)

GHSA_API_URL = "https://api.github.com/advisories"
DEFAULT_OUTPUT = Path("data/raw/github_advisory_latest.json")
DEFAULT_DAYS = 3
DEFAULT_PER_PAGE = 100  # GitHub 最大
MAX_PAGES = 20  # MVP 硬上限, 避免异常翻页
HTTP_TIMEOUT = 30.0
USER_AGENT = "cyber-daily-radar/0.1"

# 允许的 ecosystem 白名单 (传给 API 使用 GitHub 内部枚举)
ECOSYSTEMS = {
    "composer", "erlang", "actions", "go", "maven", "npm",
    "nuget", "pip", "pub", "rubygems", "rust", "swift",
}


class GhsaFetchError(RuntimeError):
    pass


@retry(
    reraise=True,
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=2, min=2, max=20),
    retry=retry_if_exception_type((httpx.HTTPError,)),
)
def _http_get(client: httpx.Client, url: str, params: dict[str, Any]) -> httpx.Response:
    resp = client.get(url, params=params)
    # 429 / 5xx 触发重试
    if resp.status_code >= 500 or resp.status_code == 429:
        resp.raise_for_status()
    return resp


def fetch_advisories(
    since: datetime,
    *,
    ecosystem: Optional[str],
    severity: Optional[str],
    per_page: int,
    token: Optional[str],
    url: str = GHSA_API_URL,
) -> list[dict]:
    """
    调用 /advisories 分页拉取。
    API 参数参考: https://docs.github.com/en/rest/security-advisories/global-advisories
    - published: >=YYYY-MM-DD 支持
    - sort: published / updated
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    since_str = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    base_params: dict[str, Any] = {
        "per_page": per_page,
        "sort": "published",
        "direction": "desc",
        "published": f">={since_str}",
    }
    if ecosystem:
        base_params["ecosystem"] = ecosystem
    if severity:
        base_params["severity"] = severity

    out: list[dict] = []
    current_url: Optional[str] = url
    current_params: Optional[dict[str, Any]] = base_params
    pages = 0

    with httpx.Client(
        timeout=HTTP_TIMEOUT,
        headers=headers,
        follow_redirects=True,
    ) as client:
        while current_url and pages < MAX_PAGES:
            try:
                resp = _http_get(
                    client, current_url, current_params if current_params else {}
                )
            except RetryError as e:
                raise GhsaFetchError(f"GHSA 请求重试后仍失败: {e}") from e
            except httpx.HTTPError as e:
                raise GhsaFetchError(f"GHSA 请求失败: {e!r}") from e

            if resp.status_code == 401:
                raise GhsaFetchError("GITHUB_TOKEN 无效或权限不足")
            if resp.status_code == 403:
                # 大概率是限速, 给出清晰提示
                remaining = resp.headers.get("X-RateLimit-Remaining")
                reset = resp.headers.get("X-RateLimit-Reset")
                raise GhsaFetchError(
                    f"GHSA 被限速 (403); remaining={remaining}, reset_at={reset}。"
                    " 请设置 GITHUB_TOKEN 环境变量或稍后再试。"
                )
            if resp.status_code >= 400:
                raise GhsaFetchError(
                    f"GHSA 返回 {resp.status_code}: {resp.text[:200]}"
                )

            try:
                payload = resp.json()
            except json.JSONDecodeError as e:
                raise GhsaFetchError(f"GHSA JSON 解析失败: {e}") from e

            if not isinstance(payload, list):
                raise GhsaFetchError("GHSA 返回非数组")

            out.extend(payload)
            pages += 1

            # 通过 Link header 翻页, 仅跟随 rel="next"
            next_url = _parse_link_next(resp.headers.get("link"))
            if not next_url or len(payload) < per_page:
                break
            current_url = next_url
            current_params = None  # Link next URL 已自带 query

            # 主动限速, 匿名访问时尤其重要
            time.sleep(0.3 if token else 1.5)

    return out


def _parse_link_next(link_header: Optional[str]) -> Optional[str]:
    """解析 RFC 5988 Link header, 找出 rel="next"。"""
    if not link_header:
        return None
    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' not in part:
            continue
        left = part.split(";", 1)[0].strip()
        if left.startswith("<") and left.endswith(">"):
            return left[1:-1]
    return None


# ---------------------------------------------------------------------------
# 归一
# ---------------------------------------------------------------------------


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,  # GHSA 用 moderate
    "low": Severity.LOW,
    "unknown": Severity.INFO,
}


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


def entry_to_raw_item(entry: dict, fetched_at: datetime) -> Optional[RawItem]:
    if not isinstance(entry, dict):
        return None
    ghsa_id = (entry.get("ghsa_id") or "").strip()
    if not ghsa_id:
        return None

    summary = (entry.get("summary") or "").strip()
    description = (entry.get("description") or "").strip()
    title = summary or ghsa_id
    title = title if len(title) <= 180 else title[:177] + "..."
    summary_final = (description or summary or None)
    if summary_final and len(summary_final) > 4000:
        summary_final = summary_final[:4000]

    published = _parse_iso(entry.get("published_at")) or fetched_at
    updated = _parse_iso(entry.get("updated_at"))

    # CVE
    cves: list[str] = []
    cve_id = entry.get("cve_id")
    if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
        cves.append(cve_id)

    # CVSS
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss = entry.get("cvss")
    if isinstance(cvss, dict):
        raw_score = cvss.get("score")
        try:
            cvss_score = float(raw_score) if raw_score is not None else None
        except (TypeError, ValueError):
            cvss_score = None
        vs = cvss.get("vector_string")
        cvss_vector = vs if isinstance(vs, str) else None

    # CWE
    cwes: list[str] = []
    for w in entry.get("cwes") or []:
        if isinstance(w, dict):
            cid = w.get("cwe_id")
            if isinstance(cid, str) and cid.startswith("CWE-"):
                tag = cid.lower()
                if tag not in cwes:
                    cwes.append(tag)

    # 生态 / 包名
    ecosystems: list[str] = []
    products: list[str] = []
    for v in entry.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        pkg = v.get("package") or {}
        if isinstance(pkg, dict):
            eco = pkg.get("ecosystem")
            name = pkg.get("name")
            if isinstance(eco, str) and eco and eco not in ecosystems:
                ecosystems.append(eco)
            if isinstance(name, str) and name and name not in products:
                products.append(name)

    # references
    refs: list[str] = []
    for r in entry.get("references") or []:
        if isinstance(r, dict):
            url = r.get("url")
            if isinstance(url, str) and url.startswith("http") and url not in refs:
                refs.append(url)
        elif isinstance(r, str) and r.startswith("http") and r not in refs:
            refs.append(r)

    # severity
    sev_raw = (entry.get("severity") or "").strip().lower()
    severity = SEVERITY_MAP.get(sev_raw, Severity.INFO)

    source_url = entry.get("html_url") or f"https://github.com/advisories/{ghsa_id}"

    risk = RiskSignal(
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
    )

    source_info = SourceInfo(
        source="ghsa",
        source_sub="github",
        source_name="GitHub Advisory",
        source_url=source_url,  # type: ignore[arg-type]
        native_id=ghsa_id,
    )

    topics = ["advisory"] + ecosystems + cwes
    # severity 作为 topic 以便前端过滤, 同时保留在 RawItem.severity 语义由下游 rank 处理
    # RawItem 模型暂未在顶层存 severity, 通过 topics 透传
    if severity != Severity.INFO:
        topics.append(f"severity:{severity.value}")

    return RawItem(
        id=f"ghsa:{ghsa_id}",
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
        vendors=[],  # GHSA 通常没有独立 vendor, 包名已在 products
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
            sys.stderr.write(f"[WARN] 跳过一条 GHSA 条目解析失败: {exc}\n")
            continue
        if item is not None:
            out.append(item)
    out.sort(key=lambda x: (x.published_at, x.id), reverse=True)
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
    parser = argparse.ArgumentParser(
        description="抓取 GitHub Advisory Database 最近 N 天"
    )
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument(
        "--ecosystem",
        choices=sorted(ECOSYSTEMS),
        help="限定 ecosystem (可选)",
    )
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        help="限定 severity (可选)",
    )
    parser.add_argument("--per-page", type=int, default=DEFAULT_PER_PAGE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--skip-if-no-token",
        action="store_true",
        help="未设置 GITHUB_TOKEN 时直接退出 0, 不抓取 (CI 场景常用)",
    )
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or None
    if not token:
        msg = (
            "[INFO] 未设置 GITHUB_TOKEN: 将以匿名访问 GHSA, 限速 60 请求/小时。\n"
            "       如需更高限速, 请设置环境变量 GITHUB_TOKEN=<personal access token>\n"
        )
        sys.stderr.write(msg)
        if args.skip_if_no_token:
            sys.stderr.write("[INFO] --skip-if-no-token 已指定, 跳过抓取。\n")
            return 0
    else:
        sys.stderr.write("[INFO] 使用 GITHUB_TOKEN 访问 GHSA (5000 请求/小时)\n")

    since = datetime.now(timezone.utc) - timedelta(days=max(1, args.days))
    try:
        entries = fetch_advisories(
            since,
            ecosystem=args.ecosystem,
            severity=args.severity,
            per_page=max(1, min(args.per_page, 100)),
            token=token,
        )
    except GhsaFetchError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1

    fetched_at = datetime.now(timezone.utc)
    items = normalize(entries, fetched_at)

    meta = {
        "since": since.isoformat(),
        "raw_count": len(entries),
        "normalized_count": len(items),
        "ecosystem": args.ecosystem,
        "severity": args.severity,
        "authenticated": bool(token),
        "fetched_at": fetched_at.isoformat(),
        "source": "GitHub Advisory REST v2022-11-28",
    }

    count = dump_items(items, args.output, meta)
    print(f"[OK] 写入 {count} 条 GHSA 到 {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
