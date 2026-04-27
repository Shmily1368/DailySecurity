# scripts/

Python 3.11 数据管线脚本目录。详见 [docs/ARCHITECTURE.md § 3](../docs/ARCHITECTURE.md)。

Phase 1 仅建立骨架, fetcher / LLM / rank 等脚本将在后续阶段逐步实现。

计划脚本 (待实现):

- `fetch_arxiv.py`
- `fetch_nvd.py`
- `fetch_cisa_kev.py`
- `fetch_epss.py`
- `normalize.py`
- `enrich.py`
- `summarize_with_llm.py`
- `rank_items.py`
- `build_daily_digest.py`
- `validate_data.py`
- `run_pipeline.py`
