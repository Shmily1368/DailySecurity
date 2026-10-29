# Cyber Security Daily Radar

每日网络空间安全雷达，聚合安全论文、漏洞、在野利用、厂商公告、威胁情报与检测规则，服务安全工程师、研究员和防御团队。

网站：[dailysecurity.cn](https://www.dailysecurity.cn/) · [本期更新状态](https://www.dailysecurity.cn/health.json)

## 每日更新

GitHub Actions 提前采集并重试，以北京时间 08:37 为目标更新时间。采集、校验、数据提交、静态构建和 Pages 发布属于同一条依赖链，构建固定使用实际数据提交 SHA。GitHub 调度和外部来源可能延迟，网站明确展示最近有效日报及来源状态。

模型可用时生成中文摘要；无密钥、余额不足或请求失败时发布真实来源摘录。来源日期未知时明确标注首次发现或年份，不伪造发表时间。单个来源失败不阻断其他可用来源，全源失败保留上一份有效快照。

原子快照、调度与排障方式见 [每日采集与发布](docs/PIPELINE_RELIABILITY.md)。

## 数据来源与阅读

基础数据来自 arXiv、DBLP/OpenAlex、NVD、CISA KEV、GitHub Advisory、OSV 和 FIRST EPSS，厂商与威胁情报来源通过 `config/sources/` 注册。来源访问失败和布局不可识别都会进入运行诊断。

单漏洞记录聚合并保留 CVE、GHSA/OSV 别名和关联来源。严重度、在野利用、公开 PoC 和修复版本按来源证据分别处理。首页支持本期全文关键词检索，日归档和主题归档静态分页，完整详情按需加载。

本站提供风险摘要、检测信号、防御建议及原始链接；不展示 exploit 代码、攻击步骤或恶意样本。

## 本地运行

需要 Python 3.11、Node.js 20 及 npm。

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cd src
npm ci
npm run dev
```

前端读取 `data/current.json` 指向的权威快照及历史日报。构建期间数据固定，修改数据后重启开发服务。详情解压需要支持 `DecompressionStream` 的现代浏览器，原始链接和静态分页始终可访问。

## 采集与验证

```bash
# 将 .env.example 中需要的变量导出到当前进程；脚本不自动加载 .env
python scripts/run_pipeline.py

# 开发演示才显式使用 --mock；生产工作流拒绝演示数据
python scripts/run_pipeline.py --mock

# 离线验证
python -m pytest scripts/tests -q --tb=short
python scripts/check_pipeline.py
python scripts/publication.py validate
cd src
npm run check
npm run build
cd ..
python scripts/check_site.py
```

可选 GitHub Secrets：`NVD_API_KEY`、`OPENAI_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL`。无模型密钥仍能采集并发布真实摘录。手动更新通过 Actions 中的「Daily Security Radar Update」触发；勾选 `force_refresh` 可绕过当天健康快照的重复执行检查。

## 目录

| 路径 | 用途 |
| --- | --- |
| `scripts/` | 采集、模型摘要、评分、校验、快照与验收 |
| `scripts/tests/` | 禁止外部网络的 Python 回归场景 |
| `schemas/` | 与 Pydantic 同步的数据契约 |
| `config/sources/` | 来源身份、质量和文章布局配置 |
| `data/current.json` | 当前 generation、日期、SHA 和健康状态 |
| `data/generations/` | 当前和上一代日报、索引与状态 |
| `data/daily/` | 历史日报及兼容镜像 |
| `src/` | Astro 静态前端 |
| `.github/workflows/` | 提前采集、重试、固定版本构建与 Pages 发布 |

更多说明：[产品需求](docs/PRD.md)、[架构](docs/ARCHITECTURE.md)、[来源](docs/DATA_SOURCES.md)、[摘要规则](docs/PROMPTS.md)。
