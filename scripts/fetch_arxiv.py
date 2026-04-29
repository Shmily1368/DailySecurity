"""
scripts/fetch_arxiv.py

抓取 arXiv cs.CR 分类最新论文, 归一为 RawItem 结构并落盘。

用法:
    python scripts/fetch_arxiv.py
    python scripts/fetch_arxiv.py --max-results 10
    python scripts/fetch_arxiv.py --max-results 50 --output data/raw/arxiv_latest.json

退出码:
    0 = 成功
    1 = 网络/解析失败
    2 = CLI 参数错误

说明:
    - 使用 arXiv Query API (Atom XML), 无需鉴权。
    - 失败自动指数退避重试。
    - 不调用 LLM。输出结构与 RawItem schema 对齐,
      可直接交给 scripts/validate_data.py --schema raw_item 校验。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List
from urllib.parse import urlencode

import feedparser
import httpx
from tenacity import (
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# 允许导入 scripts/models.py
sys.path.insert(0, str(Path(__file__).resolve().parent))
from models import ItemType, RawItem, SourceInfo  # noqa: E402


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

ARXIV_API_ENDPOINT = "http://export.arxiv.org/api/query"
ARXIV_CATEGORY = "cs.CR"
DEFAULT_MAX_RESULTS = 200  # Increased to capture all daily papers
DEFAULT_OUTPUT = Path("data/raw/arxiv_latest.json")
HTTP_TIMEOUT = 20.0
USER_AGENT = "cyber-daily-radar/0.1 (+https://github.com/)"


# ---------------------------------------------------------------------------
# 抓取
# ---------------------------------------------------------------------------


class ArxivFetchError(RuntimeError):
    """arXiv 抓取失败的统一异常。"""


import time

@retry(
    reraise=True,
    stop=stop_after_attempt(7),
    wait=wait_exponential(multiplier=2, min=10, max=120),
    retry=retry_if_exception_type((httpx.HTTPError,)),
)
def _http_get(url: str) -> str:
    """带重试的 HTTP GET, 失败抛 httpx.HTTPError 触发 tenacity 重试。"""
    with httpx.Client(
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        follow_redirects=True,
    ) as client:
        resp = client.get(url)
        if resp.status_code == 429:
            # Check for Retry-After header, otherwise default to 30 seconds
            retry_after = int(resp.headers.get("Retry-After", 30))
            print(f"[WARN] arXiv API rate limit (429) hit. Sleeping for {retry_after} seconds...", file=sys.stderr)
            time.sleep(retry_after)
            resp.raise_for_status()
        resp.raise_for_status()
        return resp.text


def fetch_arxiv_feed(category: str, max_results: int) -> str:
    """拉取 arXiv Atom XML 原文。"""
    params = {
        "search_query": f"cat:{category}",
        "sortBy": "submittedDate",
        "sortOrder": "descending",
        "start": 0,
        "max_results": max_results,
    }
    url = f"{ARXIV_API_ENDPOINT}?{urlencode(params)}"
    try:
        return _http_get(url)
    except RetryError as e:
        raise ArxivFetchError(f"arXiv 请求在重试后仍失败: {e}") from e
    except httpx.HTTPError as e:
        raise ArxivFetchError(f"arXiv 请求失败: {e!r}") from e


# ---------------------------------------------------------------------------
# 解析与归一
# ---------------------------------------------------------------------------


def _parse_arxiv_id(raw_id: str) -> str:
    """
    arXiv Atom 里 id 形如:
        http://arxiv.org/abs/2604.01234v1
    我们取末段并去掉 vN 版本号。
    """
    slug = raw_id.rstrip("/").rsplit("/", 1)[-1]
    # 去除末尾版本号 vN
    if "v" in slug:
        head, _, tail = slug.rpartition("v")
        if tail.isdigit():
            return head
    return slug


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # feedparser 已把时间标准化为 RFC3339 字符串
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _extract_pdf_url(entry: Any) -> str | None:
    """从 entry.links 中找 application/pdf。"""
    for link in getattr(entry, "links", []) or []:
        if getattr(link, "type", "") == "application/pdf":
            return getattr(link, "href", None)
        if getattr(link, "rel", "") == "related" and getattr(link, "href", "").endswith(
            ".pdf"
        ):
            return link.href
    return None


def _extract_categories(entry: Any) -> List[str]:
    """arXiv 的 tags 里 term 即为分类名, 如 cs.CR / cs.AI。"""
    cats: List[str] = []
    for tag in getattr(entry, "tags", []) or []:
        term = getattr(tag, "term", None)
        if term:
            cats.append(term)
    return cats


def _normalize_summary(s: str | None) -> str | None:
    if not s:
        return None
    # arXiv 摘要内常有换行与多空格, 压缩一下
    cleaned = " ".join(s.split())
    # 与 RawItem schema 对齐: <= 4000 字符
    return cleaned[:4000]


def entry_to_raw_item(entry: Any, fetched_at: datetime) -> RawItem | None:
    """把 feedparser 解析出的单个 entry 转为 RawItem。解析失败返回 None。"""
    raw_id = getattr(entry, "id", None)
    title = getattr(entry, "title", None)
    if not raw_id or not title:
        return None

    native_id = _parse_arxiv_id(raw_id)
    abs_url = f"https://arxiv.org/abs/{native_id}"
    pdf_url = _extract_pdf_url(entry) or f"https://arxiv.org/pdf/{native_id}"

    authors = [
        getattr(a, "name", "").strip()
        for a in getattr(entry, "authors", []) or []
        if getattr(a, "name", None)
    ]

    published_at = _parse_datetime(getattr(entry, "published", None))
    updated_at = _parse_datetime(getattr(entry, "updated", None))
    if published_at is None:
        # arXiv 条目必然有 published; 拿不到就放弃该条
        return None

    categories = _extract_categories(entry)

    source_info = SourceInfo(
        source="arxiv",
        source_sub=ARXIV_CATEGORY,
        source_name="arXiv cs.CR",
        source_url=abs_url,  # type: ignore[arg-type]
        native_id=native_id,
    )

    return RawItem(
        id=f"arxiv:{native_id}",
        type=ItemType.PAPER,
        source_info=source_info,
        title=" ".join(title.split()),
        summary=_normalize_summary(getattr(entry, "summary", None)),
        raw_text=None,
        published_at=published_at,
        updated_at=updated_at,
        fetched_at=fetched_at,
        authors=authors,
        affiliations=[],
        cves=[],
        vendors=[],
        products=[],
        affected_versions=[],
        # 把 arXiv 原始分类放到 topics; 去掉主分类 cs.CR 避免噪声
        topics=[c for c in categories if c != ARXIV_CATEGORY],
        lang="en",
        risk=None,
        references=[pdf_url],  # type: ignore[list-item]
    )


def parse_feed(xml_text: str, fetched_at: datetime) -> List[RawItem]:
    parsed = feedparser.parse(xml_text)
    if parsed.bozo and not parsed.entries:
        raise ArxivFetchError(
            f"arXiv Atom 解析失败: {parsed.bozo_exception!r}"
        )
    out: List[RawItem] = []
    for entry in parsed.entries or []:
        try:
            item = entry_to_raw_item(entry, fetched_at)
        except Exception as exc:  # noqa: BLE001 单条异常不应拖垮整体
            sys.stderr.write(f"[WARN] 跳过一条解析失败的 entry: {exc}\n")
            continue
        if item is not None:
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------


def dump_items(items: Iterable[RawItem], output_path: Path) -> int:
    """以 {items: [...]} 格式写入 JSON, 返回条目数。"""
    items_list = list(items)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "items": [
            # Pydantic 2: model_dump(mode="json") 会输出 ISO 时间字符串、str(HttpUrl)
            item.model_dump(mode="json")
            for item in items_list
        ]
    }
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")
    return len(items_list)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="抓取 arXiv cs.CR 最新论文, 输出 RawItem JSON"
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=DEFAULT_MAX_RESULTS,
        help=f"最大返回条数 (默认 {DEFAULT_MAX_RESULTS})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"输出文件路径 (默认 {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--category",
        default=ARXIV_CATEGORY,
        help=f"arXiv 分类 (默认 {ARXIV_CATEGORY})",
    )
    args = parser.parse_args()

    if args.max_results <= 0:
        parser.error("--max-results 必须 > 0")

    print(
        f"[INFO] 抓取 arXiv {args.category}, max_results={args.max_results}",
        file=sys.stderr,
    )

    try:
        xml_text = fetch_arxiv_feed(args.category, args.max_results)
    except ArxivFetchError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1

    fetched_at = datetime.now(timezone.utc)

    try:
        items = parse_feed(xml_text, fetched_at)
    except ArxivFetchError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
        
    # Filter for today's papers
    # Use 36 hours rolling window similar to other sources to avoid timezone cutoffs
    from datetime import timedelta
    cutoff_date = fetched_at - timedelta(hours=36)
    items = [item for item in items if item.published_at and item.published_at >= cutoff_date]

    if not items:
        print("[WARN] 未解析到任何今日条目", file=sys.stderr)

    count = dump_items(items, args.output)
    print(f"[OK] 写入 {count} 条到 {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
