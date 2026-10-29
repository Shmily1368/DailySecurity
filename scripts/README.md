# scripts/

Python 3.11 数据管线脚本目录。详见 [docs/ARCHITECTURE.md § 3](../docs/ARCHITECTURE.md)。

当前自动更新入口为 `python scripts/run_pipeline.py`，各来源独立执行并在新目录中处理数据，校验通过后才发布。

运行与故障处理规则见 [PIPELINE_RELIABILITY.md](../docs/PIPELINE_RELIABILITY.md)。离线检查使用 `python scripts/check_pipeline.py`，不会访问来源网站或 LLM API。

主要脚本：

- `fetch_arxiv.py`
- `fetch_nvd.py`
- `fetch_cisa_kev.py`
- `fetch_epss.py`
- `summarize_with_llm.py`
- `rank_items.py`
- `build_daily_digest.py`
- `validate_data.py`
- `run_pipeline.py`
- `check_pipeline.py`
