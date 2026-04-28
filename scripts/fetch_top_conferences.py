import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import httpx
import argparse
import random
from datetime import datetime, timezone

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
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"seen_keys": list(seen_keys)}, f)

def fetch_dblp_all(stream_id, year):
    # Fetch all papers for a given year to check for new ones
    url = f"https://dblp.org/search/publ/api?q=stream:{stream_id}:{year}&format=json&h=1000"
    try:
        res = httpx.get(url, timeout=15.0)
        if res.status_code == 200:
            data = res.json()
            hits = data.get('result', {}).get('hits', {}).get('hit', [])
            return [h['info'] for h in hits if h.get('info', {}).get('type') == 'Conference and Workshop Papers']
    except Exception as e:
        print(f"[WARN] Error fetching {stream_id} {year} all: {e}")
    return []

def fetch_dblp_random(stream_id, year, limit=5):
    # Fetch a random subset of papers from a specific year
    url_total = f"https://dblp.org/search/publ/api?q=stream:{stream_id}:{year}&format=json&h=0"
    try:
        res = httpx.get(url_total, timeout=15.0)
        if res.status_code == 200:
            total = int(res.json().get('result', {}).get('hits', {}).get('@total', 0))
            if total == 0:
                return []
            
            # offset cannot exceed total-limit
            offset = random.randint(0, max(0, total - limit))
            url_data = f"https://dblp.org/search/publ/api?q=stream:{stream_id}:{year}&format=json&f={offset}&h={limit}"
            res_data = httpx.get(url_data, timeout=15.0)
            if res_data.status_code == 200:
                hits = res_data.json().get('result', {}).get('hits', {}).get('hit', [])
                return [h['info'] for h in hits if h.get('info', {}).get('type') == 'Conference and Workshop Papers'][:limit]
    except Exception as e:
        print(f"[WARN] Error fetching {stream_id} {year} random: {e}")
    return []

def format_item(p, source_id, info, now):
    authors_data = p.get('authors', {}).get('author', [])
    authors = []
    if isinstance(authors_data, dict):
        authors = [authors_data.get('text', '')]
    elif isinstance(authors_data, list):
        authors = [a.get('text', '') for a in authors_data]
    
    author_str = ", ".join(authors) if authors else "Unknown"
    title = p.get('title', '')
    year_pub = p.get('year', '')
    
    ee = p.get('ee', '')
    if isinstance(ee, list):
        ee = ee[0] if ee else info['url']
    
    return {
        "id": f"paper:{source_id}:{p.get('key', '').replace('/', '_')}",
        "type": "paper",
        "source_info": {
            "source": "top_conferences",
            "source_sub": source_id,
            "native_id": p.get('key', '').replace('/', '_'),
            "source_name": info['name'],
            "source_url": ee or info['url']
        },
        "title": title,
        "summary": f"Authors: {author_str}. Published in {info['name']} {year_pub}.",
        "published_at": now.isoformat(),
        "fetched_at": now.isoformat(),
        "authors": authors
    }

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="data/raw/top_conferences.json")
    parser.add_argument("--limit-per-conf", type=int, default=5, help="Number of random fallback papers per conference")
    args = parser.parse_args()

    conferences = {
        "ieee_sp": {"stream": "conf/sp", "name": "IEEE S&P", "url": "https://www.ieee-security.org/TC/SP-Index.html"},
        "acm_ccs": {"stream": "conf/ccs", "name": "ACM CCS", "url": "https://www.sigsac.org/ccs.html"},
        "usenix_security": {"stream": "conf/uss", "name": "USENIX Security", "url": "https://www.usenix.org/conferences/byname/106"},
        "ndss": {"stream": "conf/ndss", "name": "NDSS", "url": "https://www.ndss-symposium.org/"}
    }

    current_year = datetime.now().year
    
    # 1. Load state
    seen_keys = load_state()
    is_first_run = (seen_keys is None)
    if is_first_run:
        seen_keys = set()
    
    results = []
    now = datetime.now(timezone.utc)
    
    for source_id, info in conferences.items():
        # Step A: Check current year and previous year for ALL papers
        all_recent_papers = []
        all_recent_papers.extend(fetch_dblp_all(info['stream'], current_year))
        all_recent_papers.extend(fetch_dblp_all(info['stream'], current_year - 1))
        
        new_papers = []
        for p in all_recent_papers:
            key = p.get('key', '')
            if key and key not in seen_keys:
                new_papers.append(p)
                seen_keys.add(key)
        
        # If it's the very first run, we don't want to flood with 800+ papers,
        # so we just mark them as seen, and act as if no "new" papers arrived today.
        if is_first_run:
            new_papers = []
            
        if len(new_papers) > 0:
            print(f"[OK] Found {len(new_papers)} NEW papers for {info['name']}! Fetching all of them.")
            for p in new_papers:
                results.append(format_item(p, source_id, info, now))
        else:
            print(f"[INFO] No new papers for {info['name']}. Fetching {args.limit_per_conf} random fallback from past 5 years.")
            # Fallback: pick a random year from the past 5 years
            random_year = random.choice(range(current_year - 5, current_year + 1))
            fallback_papers = fetch_dblp_random(info['stream'], random_year, limit=args.limit_per_conf)
            for p in fallback_papers:
                results.append(format_item(p, source_id, info, now))
                # Note: We do NOT add fallback papers to seen_keys, so they can be randomly picked again.

    # Save the updated state
    save_state(seen_keys)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print(f"[OK] Total {len(results)} top conference papers saved to {out_path}")

if __name__ == "__main__":
    run()
