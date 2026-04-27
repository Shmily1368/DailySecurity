# Cyber Security Daily Radar — 数据源文档

> 文档骨架，各数据源细节待 Phase 2 逐个补齐。
> 配套文档：[PRD.md](./PRD.md)、[ARCHITECTURE.md](./ARCHITECTURE.md)

每个数据源按下列模板记录：

```
- 名称 / source 枚举值
- 官方链接
- 访问方式 (REST / RSS / CSV / Dump)
- 认证方式 (是否需要 Key)
- 频率 / 速率限制
- 增量拉取策略
- 示例响应片段
- 字段 → raw_item 的映射
- 法律 / robots 合规提示
- 安全红线: 是否可能携带 exploit 代码 / PoC, 抓取侧如何过滤
```

---

## MVP 数据源

### 1. arXiv `cs.CR`
- source 枚举: `arxiv`
- 官方链接: https://arxiv.org/list/cs.CR/recent
- 访问方式: RSS / OAI-PMH
- 认证: 无
- 频率: 每日一次
- 增量策略: (待补)
- 字段映射: (待补)
- 安全红线: (待补)

### 2. NVD CVE
- source 枚举: `nvd`
- 官方链接: https://services.nvd.nist.gov/rest/json/cves/2.0
- 访问方式: REST JSON (API 2.0)
- 认证: `NVD_API_KEY` 环境变量, 可选
- 速率限制:
    - 无 Key: **5 请求 / 30s** (代码中 sleep 6.5s)
    - 有 Key: **50 请求 / 30s** (代码中 sleep 0.7s)
- 增量策略: 基于 `lastModStartDate` / `lastModEndDate`, 默认回溯 `--days 2`, 硬上限 120 天
- 分页: `resultsPerPage=2000`, 按 `startIndex` 游标翻页, 直到 `startIndex >= totalResults`
- 重试: tenacity 4 次指数退避 (3s ~ 30s), 429 / 5xx / 网络错误全覆盖
- 实现: [scripts/fetch_nvd.py](../scripts/fetch_nvd.py)
- 字段映射 (NVD 2.0 `vulnerabilities[].cve.*` → `RawItem`):

| RawItem 字段 | NVD 来源 | 备注 |
|---|---|---|
| `id` | `"nvd:" + cve.id` | 统一 ID |
| `type` | 固定 `cve` | |
| `source_info.source` | `nvd` | |
| `source_info.source_sub` | `NIST` | |
| `source_info.source_url` | `https://nvd.nist.gov/vuln/detail/{cveId}` | NVD 详情页 |
| `source_info.native_id` | `cve.id` | |
| `title` / `summary` | `cve.descriptions[lang=en].value` | title 截断 ≤ 180, summary ≤ 4000 |
| `published_at` | `cve.published` | |
| `updated_at` | `cve.lastModified` | |
| `cves` | `[cve.id]` | 单条 CVE, 固定一个元素 |
| `vendors` / `products` | 解析 `configurations[].nodes[].cpeMatch[].criteria` (CPE 2.3 URI 第 3/4 段) | 自动去重 |
| `topics` | `["cve"] + [CWE 前缀小写, 如 "cwe-79"]` | 来自 `weaknesses[].description[lang=en]` |
| `risk.cvss_score` / `risk.cvss_vector` | 优先 `cvssMetricV31 > V30 > V2`; 优先 `type="Primary"` | `baseScore` / `vectorString` |
| `risk.has_public_exploit` / `risk.exploit_maturity` | `references[].tags` 含 `"Exploit"` → `true` / `poc` | **仅作为存在性信号** |
| `risk.exploit_references` | 仅 `{url, source, label}`; 不缓存第三方页面正文 | **红线**: 禁止抓取正文 |
| `references` | `cve.references[].url` 前 20 条 | 去重保序 |
| `lang` | `en` | |

- 健壮性:
    - NVD 结构变化: 所有字段提取函数对 `None` / 类型错误做了 `isinstance` 守护, 单条解析失败只打 warn 不中断
    - 时间字段: 兼容 `2026-04-25T12:34:56.789` 和 `...Z` 结尾
    - CVSS 可能缺失 `Primary`, 回退到列表第一条
- 安全红线:
    - 描述字段可能包含 PoC 片段, **不展示给前端**, 仅留作 LLM 输入; LLM 阶段强制防御者视角 + refusal
    - `references` 中带 `Exploit` 标签的链接: **仅保留 URL + source 标签**, 绝不下载正文 / payload / 攻击步骤
    - 若未来需要展示高亮摘要, 必须走 LLM 经 schema 校验后再上前端

### 3. CISA KEV
- source 枚举: `kev`
- 官方链接: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- 访问方式: 直接下载 JSON
- 认证: 无
- 频率: 每日一次
- 增量策略: 按 `dateAdded` 标记当日新增
- 字段映射: (待补)
- 安全红线: 只含元数据, 低风险

### 4. EPSS
- source 枚举: `epss`
- 官方链接: https://epss.cyentia.com/epss_scores-current.csv.gz
- 访问方式: CSV.gz 直接下载
- 认证: 无
- 频率: 每日一次
- 增量策略: 全量覆盖, 以 `cve` 为 key 关联到其它源
- 字段映射: (待补)
- 安全红线: 仅评分, 无风险

---

## v0.2 数据源

### 5. GitHub Advisory Database (GHSA)
- source 枚举: `ghsa`
- 官方链接: https://github.com/advisories ; API: `GET https://api.github.com/advisories`
- API 版本: `X-GitHub-Api-Version: 2022-11-28`
- 认证: `GITHUB_TOKEN` 环境变量, **可选**
    - 无 token: 匿名访问, 限速 **60 请求 / 小时** (很容易 403, 开发阶段几乎只能拉一次就歇会儿)
    - 有 token: **5000 请求 / 小时**。推荐使用 fine-grained token (只勾 `public_repo` 读权限即可; `/advisories` 是公开端点, 不需要额外权限)
- 查询参数:
    - `published=>=YYYY-MM-DDTHH:MM:SSZ` — 时间窗口
    - `ecosystem` — `actions` / `composer` / `erlang` / `go` / `maven` / `npm` / `nuget` / `pip` / `pub` / `rubygems` / `rust` / `swift`
    - `severity` — `low` / `medium` / `high` / `critical`
    - `per_page` — 最大 100
    - `sort=published, direction=desc`
- 翻页: 跟随 `Link: <...>; rel="next"` header, 本脚本硬上限 20 页
- 重试: tenacity 4 次指数退避; 429 / 5xx 触发重试, 403 (限速) 直接报错给出 reset 时间
- 实现: [scripts/fetch_github_advisory.py](../scripts/fetch_github_advisory.py)
- **token 配置方法**:

    ```bash
    # ~/.zshrc 或者项目根 .env (由 direnv / shell 加载)
    export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxx"

    # 验证
    echo $GITHUB_TOKEN | head -c 4    # 应打印 ghp_ / github_pat_

    # 或 CI 里 (GitHub Actions)
    # env:
    #   GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    ```

    本仓库提供 `--skip-if-no-token` 开关: CI 场景下如果 secret 未注入, 直接退出 0, 不阻塞整个 daily pipeline。

- 字段映射 (GHSA REST → RawItem):

| RawItem 字段 | GHSA 来源 | 备注 |
|---|---|---|
| `id` | `"ghsa:" + ghsa_id` | |
| `type` | 固定 `advisory` | |
| `source_info.source_url` | `html_url` 或 `https://github.com/advisories/{ghsa_id}` | |
| `title` / `summary` | `summary` / `description` | title 截断 180, summary 4000 |
| `published_at` / `updated_at` | `published_at` / `updated_at` | |
| `cves` | `[cve_id]` (存在时) | |
| `products` | `vulnerabilities[].package.name` | |
| `topics` | `["advisory"] + ecosystems + cwes (小写)` + 可选 `severity:{level}` | |
| `risk.cvss_score` / `cvss_vector` | `cvss.score` / `cvss.vector_string` | |
| `references` | `references[].url` 前 20 条 | |

- 安全红线: 不抓取 `references` 里的页面正文; `description` 可能含 PoC 片段, 仅作 LLM 输入, **不直接前端展示**。

### 6. OSV.dev
- source 枚举: `osv`
- 官方链接: https://osv.dev ; API: `https://api.osv.dev/v1/`
- 访问方式: REST JSON, **无需认证**
- 关键端点:
    - `GET /v1/vulns/{osv_id}` — 取单条详情; 支持 `CVE-xxxx` 作为 alias 反查
    - `POST /v1/querybatch` — 批量按包名/版本/commit 查询 (MVP 暂未使用)
- 为什么不用 ZIP bucket? OSV 官方 ZIP dump (`https://osv-vulnerabilities.storage.googleapis.com/{ECOSYSTEM}/all.zip`) 每个生态动辄数百 MB, 不适合每日增量。本 MVP 采用**反查模式**: 从上游 NVD / KEV / GHSA 拿到的 CVE 列表, 逐个 `GET /v1/vulns/{CVE-xxxx}`, 命中即归一。
- 限速: OSV 官方文档未写强限速; 本脚本保守 `time.sleep(0.1)` / 请求
- 重试: tenacity 4 次指数退避
- 实现: [scripts/fetch_osv.py](../scripts/fetch_osv.py)
- 字段映射 (OSV schema 1.x → RawItem):

| RawItem 字段 | OSV 来源 | 备注 |
|---|---|---|
| `id` | `"osv:" + entry.id` | 例如 `osv:GHSA-jfh8-c2jp-5v3q` |
| `type` | 固定 `advisory` | |
| `source_info.source_url` | `https://osv.dev/vulnerability/{id}` | |
| `title` / `summary` | `summary` / `details` | title 截断 180, summary 4000 |
| `published_at` / `updated_at` | `published` / `modified` | |
| `cves` | `aliases` 中 `CVE-*` + 自身 id (如果是 CVE-*) | |
| `products` | `affected[].package.name` 去重 | |
| `topics` | `["advisory"] + ecosystems(小写) + cwes(小写)` | `database_specific.cwe_ids` |
| `risk.cvss_vector` | `severity[].score` (type=CVSS_V4 / V3 / V2 优先级) | **score 字段装的是 vector 字符串**; baseScore 未解析 |
| `references` | `references[].url` 前 20 条 | |

- 支持的生态白名单: 不做硬限制, OSV 返回的 ecosystem 小写后原样进入 `topics`。已知常见值: `PyPI`, `npm`, `Maven`, `Go`, `crates.io`, `RubyGems`, `NuGet`, `Packagist`, `Pub`, `Hex`, `Alpine`, `Debian`, ...
- 安全红线: 不抓取 references 正文; `details` 字段可能含 PoC 片段, 仅作 LLM 输入。

### 7. 重要厂商安全公告
- source 枚举: `vendor`
- 候选: Microsoft MSRC, Cisco PSIRT, Fortinet PSIRT, Apple Security, Red Hat, Google Project Zero
- (待补)

---

## v0.3 数据源

### 8. 安全四大会议
- source 枚举: `conf_paper`
- 会议: USENIX Security / IEEE S&P / ACM CCS / NDSS
- (待补)

### 9. 威胁情报博客
- source 枚举: `ti_blog`
- 候选: Mandiant, Unit 42, Talos, CrowdStrike, SentinelLabs, Volexity
- (待补)

### 10. 检测规则
- source 枚举: `nuclei` / `sigma`
- 原则: 只索引检测规则的元数据与链接, 不索引 exploit 模板文本本体
- (待补)

---

## 字段映射约定

所有数据源的 fetcher 输出必须归一到 `schemas/raw_item.schema.json`。各源通用字段:

| raw_item 字段 | 来源 | 备注 |
|---|---|---|
| `id` | `{source}:{native_id}` | 全局唯一 |
| `source` | 固定枚举 | |
| `native_id` | 源站原始 ID | |
| `title` | 源标题 | 英文原文 |
| `url` | 源详情页 | |
| `published_at` | 源发布时间 | UTC |
| `fetched_at` | 本系统抓取时间 | UTC |
| `raw_text` | 摘要/描述 | 截断 ≤ 4000 字符 |
| `cve_ids` | 关联 CVE | 可选 |
| `lang` | 原文语言 | 默认 `en` |

（各源独有字段见对应章节）
