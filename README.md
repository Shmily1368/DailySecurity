# Cyber Security Daily Radar

> 每日自动更新的网络空间安全雷达 —— 聚合 arXiv / CVE / KEV / EPSS / 厂商公告 / 威胁情报, 通过 LLM 生成中文摘要与推荐, 静态部署到 GitHub Pages。

- 面向防御者 (蓝队 / SOC / 安全工程师 / 研究员)
- **不展示 exploit 代码、不提供攻击步骤、不托管恶意样本**
- 详见 [docs/PRD.md](./docs/PRD.md)、[docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)

---

## 项目状态

已接入真实来源并部署至 [dailysecurity.cn](https://www.dailysecurity.cn/)。每日数据更新由 GitHub Actions 执行，Astro 读取日报 JSON 构建静态站点。

构建缓存、来源降级与校验规则见 [构建与数据管线可靠性](./docs/PIPELINE_RELIABILITY.md)。

---

## 目录结构

```
DailySecurity/
├── README.md
├── requirements.txt           # Python 依赖
├── .env.example               # 环境变量示例
├── .gitignore
├── docs/                      # 产品 / 架构 / 数据源 / Prompt 文档
│   ├── PRD.md
│   ├── ARCHITECTURE.md
│   ├── DATA_SOURCES.md
│   └── PROMPTS.md
├── scripts/                   # Python 数据管线 (Phase 2+)
├── schemas/                   # JSON Schema (Phase 2)
├── data/
│   ├── raw/                   # 抓取原始数据 (按日期分目录)
│   ├── processed/             # 中间产物
│   ├── cache/llm/             # LLM 响应缓存
│   └── daily/                 # 前端消费的 daily digest
│       ├── 2026-04-27.json    # MOCK 示例
│       └── index.json
├── src/                       # Astro 前端
│   ├── package.json
│   ├── astro.config.mjs
│   ├── tsconfig.json
│   └── src/
│       ├── pages/index.astro
│       ├── layouts/BaseLayout.astro
│       ├── components/ItemCard.astro
│       └── lib/{data,format}.ts
└── .github/workflows/         # GitHub Actions (Phase 2+)
```

---

## 本地开发

### 1. 准备 Python 环境 (conda)

本项目使用 **conda 环境** `cyber-daily-radar` 统一管理 Python 3.11 + Node.js 20。

```bash
# 创建 conda 环境 (仅首次)
conda create -n cyber-daily-radar python=3.11 -y

# 安装 Node.js 到同一环境 (统一工具链, 避免系统依赖)
conda install -n cyber-daily-radar -c conda-forge nodejs=20 -y

# 激活环境 (之后所有命令都在这个环境下执行)
conda activate cyber-daily-radar

# 安装 Python 依赖
pip install -r requirements.txt
```

### 2. 配置环境变量

```bash
cp .env.example .env
# 将需要的变量导出到 shell；脚本不会自动加载 .env
# 明确需要模拟摘要时使用 --mock，无 key 的生产管线使用原文摘录
```

### 3. 启动前端 (读取已提交日报)

```bash
cd src
npm ci
npm run dev        # 本地开发服务器, 默认 http://localhost:4321
```

构建静态站点:

```bash
cd src
npm run build      # 产物在 src/dist/
npm run preview    # 本地预览构建产物
```

> 前端读取项目根目录的 `data/daily/latest.json` 与历史日期日报。构建期间的数据视为固定快照；修改数据后重启开发服务。

### 4. 数据校验

`scripts/validate_data.py` 用 Pydantic + JSON Schema 双校验所有数据文件。

```bash
# 校验常用目录下所有 JSON (data/raw、data/processed、data/daily)
python scripts/validate_data.py --all

# 校验单个文件 (按路径推断 schema)
python scripts/validate_data.py data/raw/arxiv_latest.json
python scripts/validate_data.py data/processed/mock_digest.json

# 显式指定 schema
python scripts/validate_data.py --schema raw_item data/raw/arxiv_latest.json
python scripts/validate_data.py --schema digest   data/daily/2026-04-27.json

# 只跑一种校验 (pydantic / jsonschema)
python scripts/validate_data.py --only pydantic data/raw/mock_items.json
```

### 5. 抓取数据源

> 各 fetcher 只负责抓取与归一到 `RawItem` (`schemas/raw_item.schema.json`),
> 不调用 LLM、不做排序, 输出结构统一、可被 `validate_data.py` 校验。

#### arXiv cs.CR

```bash
# 抓取 50 条最新论文, 默认输出 data/raw/arxiv_latest.json
python scripts/fetch_arxiv.py

# 自定义条数与输出路径
python scripts/fetch_arxiv.py --max-results 10
python scripts/fetch_arxiv.py --max-results 100 --output data/raw/2026-04-27/arxiv.json

# 抓取后校验
python scripts/validate_data.py data/raw/arxiv_latest.json
```

字段说明:
- `id = "arxiv:<native_id>"` (自动去除 `vN` 版本号)
- `type = "paper"`
- `source_info.source_url` 指向 abs 页, `references[0]` 指向 PDF
- `topics` 取 arXiv 原始分类 (去掉主分类 `cs.CR`)
- 网络失败时使用 tenacity 指数退避重试 3 次

#### NVD CVE

调用 NVD CVE API 2.0, 抓取最近 N 天 (默认 2 天) 发布或修改的 CVE, 归一为 `RawItem`, 输出 `data/raw/nvd_recent.json`。

```bash
# 默认最近 2 天, 输出 data/raw/nvd_recent.json
python scripts/fetch_nvd.py

# 自定义窗口和输出
python scripts/fetch_nvd.py --days 7 --output data/raw/2026-04-27/nvd.json

# 带 API Key 运行 (放宽限速到 50 请求 / 30s)
NVD_API_KEY=your-key python scripts/fetch_nvd.py --days 14

# 抓取后校验
python scripts/validate_data.py data/raw/nvd_recent.json
```

字段说明:
- `id = "nvd:<cveId>"`, `type = "cve"`
- `source_info.source_url` 指向 NVD 详情页
- `risk.cvss_score` / `risk.cvss_vector`: 优先 CVSS v3.1 > v3.0 > v2 的 Primary
- `topics` 含 `cve` + 小写 CWE (如 `cwe-79`)
- `vendors` / `products`: 从 CPE 2.3 URI 解析
- `risk.has_public_exploit` / `risk.exploit_maturity`: 若 NVD references 里带 `Exploit` 标签, 置为 `true` / `poc`
- `risk.exploit_references`: **仅保留 URL + source 标签**, 不下载第三方页面正文
- 限速: 无 key 6.5s / 请求, 有 key 0.7s / 请求; tenacity 4 次指数退避

#### GitHub Advisory Database (GHSA)

调用 GitHub REST `/advisories`, 抓取最近 N 天发布的 advisory, 输出 `data/raw/github_advisory_latest.json`。

```bash
# 匿名访问 (限速 60 请求/小时, 容易 403)
python scripts/fetch_github_advisory.py --days 3

# 推荐: 设置 GITHUB_TOKEN 放宽到 5000 请求/小时
export GITHUB_TOKEN="ghp_xxx"    # 或 github_pat_xxx
python scripts/fetch_github_advisory.py --days 7

# 按 ecosystem / severity 过滤
python scripts/fetch_github_advisory.py --ecosystem pip --severity high

# CI 场景: 无 token 时直接退出 0, 不中断 pipeline
python scripts/fetch_github_advisory.py --skip-if-no-token
```

字段说明:
- `id = "ghsa:<ghsa_id>"`, `type = "advisory"`
- `source_info.source_url` 指向 `github.com/advisories/{ghsa_id}`
- `cves` 含关联 CVE (若有)
- `products` 来自 `vulnerabilities[].package.name`
- `topics` 含 `advisory`、ecosystem 名、`cwe-*`、可选 `severity:{level}`
- `risk.cvss_score` / `risk.cvss_vector` 来自 GHSA cvss 字段
- 翻页: 跟随 `Link: rel="next"`, 硬上限 20 页
- token 配置见 [docs/DATA_SOURCES.md § 5](./docs/DATA_SOURCES.md)

#### OSV.dev

调用 `GET https://api.osv.dev/v1/vulns/{CVE-xxxx}` 按 CVE 反查 OSV 记录 (命中即归一), 输出 `data/raw/osv_latest.json`。

```bash
# 按 CVE 列表查询
python scripts/fetch_osv.py --cve CVE-2024-3094 --cve CVE-2024-21626

# 从文件取 CVE 列表 (每行一个)
python scripts/fetch_osv.py --cve-file cve_list.txt

# 从已有的 NVD 输出自动取最近 CVE (推荐配合 fetch_nvd 的输出)
python scripts/fetch_osv.py --nvd-source data/raw/nvd_recent.json --limit 50

# 直接传 OSV ID
python scripts/fetch_osv.py --osv-id GHSA-jfh8-c2jp-5v3q
```

字段说明:
- `id = "osv:<osv_id>"`, `type = "advisory"`
- 支持的生态: `PyPI` / `npm` / `Maven` / `Go` / `crates.io` / `RubyGems` / `NuGet` / `Packagist` 等 (不做硬白名单)
- 无需 API key; 保守 0.1s / 请求
- 字段映射细节见 [docs/DATA_SOURCES.md § 6](./docs/DATA_SOURCES.md)

#### CISA KEV (Known Exploited Vulnerabilities)

拉取 CISA 官方 KEV JSON feed, 归一为 `RawItem`, 输出 `data/raw/cisa_kev.json`。

```bash
# 默认抓取官方 feed, 输出 data/raw/cisa_kev.json
python scripts/fetch_cisa_kev.py

# 自定义输出路径
python scripts/fetch_cisa_kev.py --output data/raw/2026-04-27/kev.json

# 抓取后校验
python scripts/validate_data.py data/raw/cisa_kev.json
```

字段说明:
- `id = "kev:<cveID>"`, `type = "kev"`
- `source_info.source_url` 指向 NVD 详情页
- `risk.kev_status = "listed"`, `risk.kev_listed = true`, `risk.known_exploited = true`
- `risk.kev_date_added`, `risk.due_date`, `risk.known_ransomware` 原样保留
- `risk.has_public_exploit = true`, `risk.exploit_maturity = "in_the_wild"` (KEV 按定义均已在野)
- `risk.exploit_references` 只包含 CISA KEV Catalog 官方链接 (仅 URL, 不缓存正文)
- **不展示攻击细节**; KEV 统一推荐处置动作写在文件 `meta.recommended_action`: **"优先级置顶处理: 参考厂商公告尽快打补丁, 排查资产暴露面, 验证修复后关闭相关管理端口。"**

#### EPSS (Exploit Prediction Scoring System)

查询 FIRST.org EPSS API, 为一组 CVE 生成评分记录, 输出 `data/raw/epss_scores.json`。

```bash
# 默认: 自动从 data/raw/cisa_kev.json 取最近 30 天 KEV 的 CVE
python scripts/fetch_epss.py

# 显式传入 CVE 列表
python scripts/fetch_epss.py --cve CVE-2024-1234 --cve CVE-2024-5678

# 从文件读取 CVE 列表 (每行一个)
python scripts/fetch_epss.py --cve-file cve_list.txt

# 调整 KEV 回溯窗口或自定义输出
python scripts/fetch_epss.py --kev-days 7 --output data/raw/2026-04-27/epss.json

# 抓取后校验
python scripts/validate_data.py data/raw/epss_scores.json
```

字段说明:
- `id = "epss:<cve>"`, `type = "cve"`
- `risk.epss_score` (0-1), `risk.epss_percentile` (0-1)
- 批量查询, 100 个 CVE / 请求, tenacity 重试

### 6. LLM 摘要 (mock / OpenAI 双模式)

`scripts/summarize_with_llm.py` 读取一个或多个 `data/raw/*.json`, 为每条
`RawItem` 生成 `LlmSummary` 并拼成 `DigestItem`, 输出到
`data/processed/digest_items.json`。

```bash
# Mock 模式 (默认开发期使用, 无需 API Key, 完全本地确定性输出)
python scripts/summarize_with_llm.py \
  --input data/raw/mock_items.json \
  --output data/processed/digest_items.json \
  --mock

# 真实调用 OpenAI (需 OPENAI_API_KEY; 可选 OPENAI_MODEL, 默认 gpt-4o-mini)
export OPENAI_API_KEY=sk-...
python scripts/summarize_with_llm.py \
  --input data/raw/arxiv_latest.json \
  --input data/raw/cisa_kev.json \
  --input data/raw/nvd_recent.json \
  --output data/processed/digest_items.json \
  --limit 30

# 校验输出
python scripts/validate_data.py data/processed/digest_items.json
```

特性:
- `--input` 可重复指定多个原始文件 (会合并)。
- `--mock` 使用 `MockLlmClient`: 按 `RawItem.type` 分派确定性规则, 不消耗 token。
- `--limit N` 限制处理条数, 用于开发 / 快速验证。
- 非 mock 模式调用 OpenAI Chat Completions, 强制 `response_format=json_object`,
  `temperature=0.2`。
- 每条输出用 Pydantic `LlmSummary` + `DigestItem` 双重校验; 单条失败仅 `[WARN]`
  记录并跳过, 不中断整体任务。
- 论文仅提供摘要时强制 `abstract_only`；没有摘要时标注 `metadata_only`。
- Prompt 按 item type 分派 (paper / cve / kev / advisory / threat_report /
  detection_rule), 详情见 [docs/PROMPTS.md](./docs/PROMPTS.md)。

### 7. 生成日报与排序

`scripts/rank_items.py` 会计算各项加分，`scripts/build_daily_digest.py` 负责组装最终的日报：

```bash
# 推荐：在新目录中采集、摘要、校验后发布日报，避免复用旧产物
python scripts/run_pipeline.py

# 从 processed 目录读取数据，生成 data/daily/YYYY-MM-DD.json 和 latest.json
# 仅用于手动处理已准备好的数据；自动更新使用 run_pipeline.py
python scripts/build_daily_digest.py
```

### 8. GitHub Actions 自动更新与部署

本项目已配置完整的 GitHub Actions 工作流，实现每日自动抓取、LLM 分析、构建和 Pages 部署。

#### 如何开启 GitHub Pages
1. 进入仓库 **Settings** -> **Pages**
2. 将 **Source** 设置为 **GitHub Actions**
3. 确保你的 `src/astro.config.mjs` 中正确配置了 `site` 和 `base` (若有需要)

#### 如何配置 GitHub Secrets (可选)
如果需要真实调用 LLM 和提高 NVD API 速率，请在 **Settings** -> **Secrets and variables** -> **Actions** 中添加：
- `OPENAI_API_KEY`: 你的 OpenAI API 密钥。如果不配置，使用本次真实来源数据的原文摘录，并明确说明未生成 LLM 摘要。
- `NVD_API_KEY`: 你的 NVD API 密钥。

#### 如何手动触发 Workflow
1. 进入仓库 **Actions** 页面
2. 左侧点击 **Daily Security Radar Update**
3. 点击右侧的 **Run workflow**
4. （可选）你可以勾选 `Force mock mode` 强制本次运行不调用 LLM API。

> **注：** `daily.yml` 配置每天 UTC 00:37 (北京时间 08:37) 自动运行，实际启动时间可能受 GitHub 调度影响。成功后提交数据到 `main`；`deploy.yml` 通过上游工作流完成事件触发构建和 Pages 发布。

---

## 本地开发与测试

1. 安装依赖：
```bash
pip install -r requirements.txt
cd src && npm install
```

2. 抓取数据（或使用预置 mock 数据）：
```bash
python scripts/fetch_arxiv.py --max-results 10
python scripts/fetch_cisa_kev.py
python scripts/fetch_nvd.py --days 2
python scripts/fetch_vendor_advisories.py --limit-per-source 10
python scripts/fetch_threat_intel.py --limit-per-source 10
```

3. 生成 LLM 摘要：
   你可以设置真实的环境变量，或者直接使用 `--mock` 生成测试摘要：
```bash
# 可选环境变量
export OPENAI_API_KEY="sk-..."
export LLM_BASE_URL="https://api.deepseek.com/v1" # 例如使用 DeepSeek
export LLM_MODEL="deepseek-chat"

# 采集、摘要、校验并发布；显式模拟摘要可增加 --mock
python scripts/run_pipeline.py

# 离线检查，不访问来源网站或 LLM API
python scripts/check_pipeline.py
```

4. 本地预览：
```bash
cd src && npm run dev
```

---

## 自动更新机制 (GitHub Actions)

项目配置了每日自动抓取和部署的工作流 (`.github/workflows/daily.yml` 和 `deploy.yml`)：
- **触发时间**：配置为每天 UTC 00:37 (北京时间 08:37)，实际启动可能延迟。
- **运行内容**：各来源独立采集，仅消费本次产物；新日报通过双重校验后提交。单来源失败允许其他来源继续；没有可用新数据时失败并保留上次日报。部署工作流在上游成功后构建并发布 Pages。
- **环境变量配置**：你需要在 GitHub 仓库的 **Settings -> Secrets and variables -> Actions** 中配置以下 Secret 才能使用真实大模型：
  - `OPENAI_API_KEY` (生成真实模型摘要时需要；无 key 使用明确标注的原文摘录)
  - `LLM_BASE_URL` (选填，如果你不用 OpenAI 官方接口)
  - `LLM_MODEL` (选填，默认为 `gpt-4o-mini`)
  - `NVD_API_KEY` (选填，用于提升 NVD 抓取速率)
- **禁用特定数据源**：
  如果某些数据源抓取频繁失败或不再需要，可修改 `config/sources/vendor_advisories.yml` 或 `threat_intel.yml`，将对应 ID 下的 `enabled: true` 改为 `enabled: false`，下次 Actions 将自动跳过。

---

## 安全红线

本仓库和构建产物都遵循以下红线 (详见 [PRD § 7](./docs/PRD.md)):

- ❌ 不存储 / 不展示 PoC 代码正文、payload、shellcode、完整攻击步骤
- ❌ 不托管恶意样本可执行内容
- ❌ 不生成复现攻击的技术细节、不生成绕过教程
- ✅ CVE 元数据、风险摘要、检测信号、防御建议
- ✅ **Exploit 存在性信号**: `risk.has_public_exploit`、`risk.exploit_maturity`
  (`unreported` / `poc` / `functional` / `weaponized` / `in_the_wild`, 对齐 CVSS Temporal E)
- ✅ **Exploit 外链**: `risk.exploit_references` 仅保留第三方来源 URL + source 标签,
  点击由读者自担风险跳转, 本站不缓存第三方页面正文

---

## 许可

(待定)

### Fetch Vendor Advisories
```bash
PYTHONPATH=. python scripts/fetch_vendor_advisories.py --limit-per-source 5
```

### Fetch Threat Intel
```bash
PYTHONPATH=. python scripts/fetch_threat_intel.py --limit-per-source 5
```
