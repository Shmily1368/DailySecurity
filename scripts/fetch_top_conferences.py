import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import httpx
import asyncio
import argparse
import random
import urllib.parse
import re
from datetime import datetime, timezone
import time
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, AsyncRetrying
from storage import atomic_json

STATE_FILE = Path("data/state/dblp_state.json")

def load_state():
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f).get("seen_keys", []))
        except:
            pass
    return None

def save_state(seen_keys):
    atomic_json(STATE_FILE, {"seen_keys": sorted(seen_keys)})

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]

def get_random_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}

@retry(
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=2, min=2, max=10),
    retry=retry_if_exception_type((httpx.HTTPError, httpx.ReadError)),
    reraise=True
)
def _safe_get(url: str, timeout: float = 30.0) -> httpx.Response:
    time.sleep(random.uniform(2.0, 5.0))
    res = httpx.get(url, headers=get_random_headers(), timeout=timeout, follow_redirects=True)
    res.raise_for_status()
    return res

def fetch_dblp_all(stream_id, year):
    # Fetch all papers for a given year to check for new ones
    # Correct syntax: stream:conf/sp: year:2024: (colons at the end are important for exact match in DBLP)
    url = f"https://dblp.org/search/publ/api?q=stream:{stream_id}:%20year:{year}:&format=json&h=1000"
    try:
        res = _safe_get(url, timeout=30.0)
        data = res.json()
        hits = data.get('result', {}).get('hits', {}).get('hit', [])
        return [h['info'] for h in hits if h.get('info', {}).get('type') == 'Conference and Workshop Papers']
    except Exception as e:
        print(f"[WARN] Error fetching {stream_id} {year} all: {e}")
        raise

def fetch_dblp_random(stream_id, year, limit=5):
    # Fetch a random subset of papers from a specific year
    url_total = f"https://dblp.org/search/publ/api?q=stream:{stream_id}:%20year:{year}:&format=json&h=0"
    try:
        res = _safe_get(url_total, timeout=30.0)
        total = int(res.json().get('result', {}).get('hits', {}).get('@total', 0))
        if total == 0:
            return []
        
        # offset cannot exceed total-limit
        offset = random.randint(0, max(0, total - limit))
        url_data = f"https://dblp.org/search/publ/api?q=stream:{stream_id}:%20year:{year}:&format=json&f={offset}&h={limit}"
        res_data = _safe_get(url_data, timeout=30.0)
        hits = res_data.json().get('result', {}).get('hits', {}).get('hit', [])
        return [h['info'] for h in hits if h.get('info', {}).get('type') == 'Conference and Workshop Papers'][:limit]
    except Exception as e:
        print(f"[WARN] Error fetching {stream_id} {year} random: {e}")
    return []

def fetch_abstract_openalex(title: str) -> str:
    raise DeprecationWarning("Synchronous version is deprecated.")

async def _safe_get_async(client: httpx.AsyncClient, url: str, timeout: float = 30.0) -> httpx.Response:
    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=2, min=2, max=10),
        retry=retry_if_exception_type((httpx.HTTPError, httpx.ReadError)),
        reraise=True
    ):
        with attempt:
            await asyncio.sleep(random.uniform(2.0, 5.0))
            res = await client.get(url, headers=get_random_headers(), timeout=timeout, follow_redirects=True)
            res.raise_for_status()
            return res

class AbstractText(str):
    source_url = None


async def fetch_abstract_openalex_async(client: httpx.AsyncClient, title: str, sem: asyncio.Semaphore, year=None) -> str:
    """Fetch abstract from OpenAlex API based on paper title concurrently."""
    # 净化标题：去除非字母数字字符，仅保留空格，防止 OpenAlex API 400 报错
    clean_title = re.sub(r'[^a-zA-Z0-9\s]', ' ', title)
    clean_title = " ".join(clean_title.split())
    url = f"https://api.openalex.org/works?filter=title.search:{urllib.parse.quote(clean_title)}&select=id,title,publication_year,abstract_inverted_index"
    async with sem:
        try:
            res = await _safe_get_async(client, url, timeout=20.0)
            data = res.json()
            results = data.get("results", [])
            for r in results:
                    normalized = lambda value: "".join(c for c in str(value).casefold() if c.isalnum())
                    if normalized(r.get("title", "")) != normalized(title):
                        continue
                    if year and r.get("publication_year") != int(year):
                        continue
                    idx = r.get("abstract_inverted_index")
                    if idx:
                        # Reconstruct the abstract from the inverted index
                        words = {}
                        for word, positions in idx.items():
                            for pos in positions:
                                words[pos] = word
                        abstract = " ".join(words[i] for i in sorted(words.keys()))
                        result = AbstractText(abstract)
                        result.source_url = r.get("id")
                        return result
        except Exception as e:
            print(f"[WARN] OpenAlex fetch failed for '{title[:30]}...': {e}")
    return ""

async def process_papers_async(papers, source_id, info, now):
    results = []
    sem = asyncio.Semaphore(10) # 限制并发数为10，防止 OpenAlex 拒绝服务
    
    async with httpx.AsyncClient() as client:
        tasks = []
        for i, p in enumerate(papers):
            title = p.get('title', '')
            if isinstance(title, list):
                title = title[0]
            tasks.append(fetch_abstract_openalex_async(client, title, sem, p.get("year")))
            
        print(f"[INFO] 正在并发获取 {len(papers)} 篇论文的摘要...")
        abstracts = await asyncio.gather(*tasks)
        
        for i, p in enumerate(papers):
            results.append(format_item(p, source_id, info, now, abstracts[i]))
            if (i + 1) % 10 == 0 or (i + 1) == len(papers):
                print(f"  -> 已处理 {i + 1}/{len(papers)} 篇")
                
    return results

def format_item(p, source_id, info, now, abstract=""):
    authors_data = p.get('authors', {}).get('author', [])
    authors = []
    if isinstance(authors_data, dict):
        authors = [authors_data.get('text', '')]
    elif isinstance(authors_data, list):
        authors = [a.get('text', '') for a in authors_data]
    
    author_str = ", ".join(authors) if authors else "Unknown"
    title = p.get('title', '')
    year_pub = str(p.get('year', ''))
    published_year = int(year_pub) if year_pub.isdigit() else None
    
    ee = p.get('ee', '')
    if isinstance(ee, list):
        ee = ee[0] if ee else info['url']
    
    return {
        "id": f"paper:{source_id}:{p.get('key', '').replace('/', '_')}",
        "type": "paper",
        "source_info": {
            "source": "top_conferences",
            "source_sub": source_id,
            "source_quality": "primary",
            "native_id": p.get('key', '').replace('/', '_'),
            "source_name": info['name'],
            "source_url": ee or info['url']
        },
        "title": title,
        "summary": abstract[:4000],
        "published_at": None,
        "fetched_at": now.isoformat(),
        "first_seen_at": now.isoformat(),
        "date_precision": "year" if published_year else "unknown",
        "published_year": published_year,
        "is_backfill": bool(published_year and published_year < now.year),
        "abstract_source": getattr(abstract, "source_url", None),
        "authors": authors
    }

def run():
    global STATE_FILE
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="data/raw/top_conferences.json")
    parser.add_argument("--state-file", type=Path, default=STATE_FILE)
    parser.add_argument("--limit-per-conf", type=int, default=20, help="Per-run discovery limit per conference")
    parser.add_argument("--force", action="store_true", help="Force fetch ignoring state")
    args = parser.parse_args()
    if args.limit_per_conf <= 0:
        parser.error("--limit-per-conf must be positive")
    STATE_FILE = args.state_file

    conferences = {
        "ieee_sp": {"stream": "conf/sp", "name": "IEEE S&P", "url": "https://www.ieee-security.org/TC/SP-Index.html"},
        "acm_ccs": {"stream": "conf/ccs", "name": "ACM CCS", "url": "https://www.sigsac.org/ccs.html"},
        "usenix_security": {"stream": "conf/uss", "name": "USENIX Security", "url": "https://www.usenix.org/conferences/byname/106"},
        "ndss": {"stream": "conf/ndss", "name": "NDSS", "url": "https://www.ndss-symposium.org/"}
    }

    # 1. Load state
    seen_keys = load_state() if not args.force else None
    if seen_keys is None:
        seen_keys = set()
    
    results = []
    statuses = []
    now = datetime.now(timezone.utc)
    current_year = now.year
    
    for source_id, info in conferences.items():
        # Step A: Check current year and previous year for ALL papers
        all_recent_papers = []
        errors = []
        for year in (current_year, current_year - 1):
            try:
                all_recent_papers.extend(fetch_dblp_all(info['stream'], year))
            except Exception as exc:
                errors.append({"year": year, "error_type": type(exc).__name__})
        failed_years = [error["year"] for error in errors]
        if len(failed_years) == 2:
            statuses.append({"source_id": source_id, "status": "failed", "item_count": 0,
                             "failed_years": failed_years, "errors": errors})
            continue
        
        new_papers = []
        batch_keys = set()
        for p in all_recent_papers:
            key = p.get('key', '')
            if key and key not in seen_keys and key not in batch_keys:
                new_papers.append(p)
                batch_keys.add(key)
        
        pending_count = len(new_papers)
        new_papers = new_papers[:args.limit_per_conf]
        processed = []
        processing_failed = False
        if len(new_papers) > 0:
            print(f"[OK] Processing {len(new_papers)} of {pending_count} unseen papers for {info['name']}.")
            try:
                processed = asyncio.run(process_papers_async(new_papers, source_id, info, now))
            except Exception as exc:
                processing_failed = True
                errors.append({"phase": "processing", "error_type": type(exc).__name__})
            results.extend(processed)
            emitted_ids = {item["id"] for item in processed}
            emitted_keys = {p["key"] for p in new_papers
                            if f"paper:{source_id}:{p['key'].replace('/', '_')}" in emitted_ids}
            seen_keys.update(emitted_keys)
            pending_count -= len(emitted_keys)
        else:
            print(f"[INFO] No new papers for {info['name']}.")
        status = ("failed" if processing_failed else "partial" if errors or pending_count
                  else "success" if processed else "no_new")
        statuses.append({"source_id": source_id, "status": status,
                         "item_count": len(processed), "pending_count": pending_count,
                         "failed_years": failed_years, "errors": errors})

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    atomic_json(out_path.with_name(out_path.stem + "_status.json"), statuses)
    save_state(seen_keys)
    
    print(f"[OK] Total {len(results)} top conference papers saved to {out_path}")

if __name__ == "__main__":
    run()
