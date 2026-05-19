#!/bin/bash
set -e
python3 scripts/fetch_arxiv.py --max-results 5
python3 scripts/fetch_top_conferences.py --limit-per-conf 1
