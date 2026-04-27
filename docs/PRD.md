# Cyber Security Daily Radar — 产品需求文档 (PRD)

- 文档版本：v1.0（MVP 规划）
- 更新日期：2026-04-27
- 文档状态：初稿，待评审
- 适用范围：MVP / v0.2 / v0.3

---

## 1. 产品定位

**Cyber Security Daily Radar** 是一个部署在 GitHub Pages 上的、每日自动更新的**网络空间安全雷达**静态网站。

它的核心价值是：
- **每天一次**，聚合全球范围内最值得关注的安全情报、漏洞、学术论文、检测规则。
- 通过 LLM 自动生成**中文摘要、风险解读、标签、推荐理由**和**排序分数**。
- 以**防御者视角**呈现信息：强调检测、防御、影响面与来源链接；**不提供攻击步骤、不托管 exploit 代码正文 / payload / 恶意样本**；可展示 exploit 存在性信号与第三方来源外链。
- 所有内容以静态 JSON + 静态页面形式输出，**零后端、零数据库**，可被个人、团队自部署与订阅。

一句话定位：

> 给安全从业者的"每日安全早报"——替你读完 arXiv、CVE、KEV、Advisory 与情报博客，只告诉你今天值得关注的事。

---

## 2. 目标用户

核心用户（优先级从高到低）：

1. **蓝队 / SOC / 应急响应人员**
   - 需要第一时间知道：今天哪些漏洞被 KEV 收录、EPSS 分数飙升、哪些产品被爆严重问题。
   - 关心检测信号、IoC、修复建议。
2. **企业安全工程师 / 安全架构师**
   - 关注依赖库漏洞（GitHub Advisory / OSV）、云与开源组件风险。
   - 关注学术界新攻击面与趋势（arXiv、四大会议）。
3. **漏洞研究员 / 红队研究人员（研究向，非攻击向）**
   - 关注最新 CVE、论文、厂商公告。
   - 仅消费摘要与来源，本站**不**提供 PoC。
4. **安全研究方向的学生 / 新人**
   - 每日跟进前沿论文与热点事件，构建知识体系。
5. **技术媒体 / 行业分析师**
   - 快速获取趋势与选题线索。

非目标用户：寻找可直接复用的 exploit 正文、PoC 代码、恶意样本、攻击教学的人——本站只提供存在性信号和第三方来源外链，不托管任何上述内容，也不服务此类需求。

---

## 3. 范围划分

### 3.1 MVP 范围（v0.1）

目标：跑通「抓取 → 清洗 → LLM 摘要 → 排序 → 静态站点 → 每日自动部署」的端到端闭环。

**数据源（MVP 强制）**
- arXiv `cs.CR` 最近一日新增论文
- NVD CVE 最近一日新增/更新
- CISA KEV 全量 + 当日新增高亮
- EPSS 最新分数（关联 CVE）

**功能（MVP 强制）**
- 每日一次 GitHub Actions 自动抓取
- LLM 生成结构化 JSON 摘要（支持 mock 模式，避免开发期烧 API）
- JSON Schema 校验所有输出
- 生成 `data/daily/YYYY-MM-DD.json`
- 前端（Astro）渲染：首页 + 当日详情页 + 历史归档页
- 部署到 GitHub Pages

**明确不在 MVP 的事**
- 不做用户系统、不做登录、不做评论
- 不做全文检索（用浏览器 Ctrl+F 即可）
- 不做邮件/RSS 推送（v0.2 考虑 RSS）
- 不做多语言（MVP 默认中文摘要 + 英文原标题）

### 3.2 v0.2 范围

新增数据源：
- GitHub Advisory Database (GHSA)
- OSV.dev
- 重要厂商安全公告（Microsoft MSRC、Cisco、Fortinet、Apple、Google Project Zero 博客、Red Hat Security）

新增功能：
- **RSS / Atom 订阅**
- **标签页**（按厂商、按类型、按语言生态筛选）
- **搜索（纯前端 client-side，基于 pagefind / lunr）**
- 每日 Top 10 卡片视图
- 暗色模式

### 3.3 v0.3 范围

新增数据源：
- 安全四大会议论文（USENIX Security / IEEE S&P / ACM CCS / NDSS）——按会议程序委员会发布节奏抓取
- 威胁情报博客（Mandiant、Unit 42、Talos、CrowdStrike、SentinelLabs、Volexity、微步在线公开部分等）
- 检测规则来源：Nuclei Templates、Sigma Rules（仅索引检测规则，不索引 exploit）

新增功能：
- **主题周报 / 月报**（LLM 二次聚合）
- **趋势图表**（CVE 数量、EPSS 分布、厂商分布）
- **个人订阅配置**（通过 URL 参数的 client-side 过滤，不做账号）
- 多 LLM 后端支持（OpenAI / 国产 / 本地模型）

---

## 4. 首页栏目设计

首页 `/` 默认展示**今日快照（Today's Radar）**，从上到下的栏目顺序：

1. **顶部 Hero 区**
   - 今日日期 + 一句话「今日安全摘要」（LLM 生成，不超过 80 字）
   - 关键数字：今日 CVE 数 / KEV 新增数 / 论文数 / 最高 EPSS 分
2. **🔥 今日必读 Top 5（Must-Read）**
   - 跨数据源统一排序后的 Top 5，卡片形式
3. **🚨 KEV & 高危漏洞（Exploited in the Wild）**
   - CISA KEV 新增 + EPSS ≥ 0.7 或 CVSS ≥ 9.0 的 CVE
4. **🧬 学术前沿（Research）**
   - arXiv cs.CR 当日；v0.3 起加入四大会议
5. **📦 生态漏洞（Supply Chain & OSS）**
   - GitHub Advisory / OSV —— v0.2 起启用
6. **🏢 厂商公告（Vendor Advisories）**
   - MSRC / Cisco / Fortinet / Apple / Red Hat —— v0.2 起启用
7. **🕵️ 威胁情报（Threat Intel）**
   - 各大 TI 博客 —— v0.3 起启用
8. **🧭 检测规则（Detection Engineering）**
   - Nuclei / Sigma —— v0.3 起启用
9. **📚 历史归档入口**
   - 按日期浏览（日历视图 / 列表视图）

每个栏目右上角提供「查看全部」跳转到该栏目的当日完整列表页。

---

## 5. 数据字段设计

### 5.1 原始数据字段 `raw_item`

统一的抓取侧数据结构（所有 fetcher 输出都归一到此 schema）。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | string | 是 | 全局唯一 ID，建议 `{source}:{native_id}` |
| `source` | enum | 是 | `arxiv` / `nvd` / `kev` / `epss` / `ghsa` / `osv` / `vendor` / `ti_blog` / `nuclei` / `sigma` / `conf_paper` |
| `source_sub` | string | 否 | 厂商名 / 会议名 / 博客名 |
| `native_id` | string | 是 | 源站原始 ID（如 CVE-2026-1234、arXiv:2604.xxxxx） |
| `title` | string | 是 | 原始标题（保留英文） |
| `url` | string | 是 | 来源链接 |
| `published_at` | datetime (UTC) | 是 | 原始发布时间 |
| `updated_at` | datetime (UTC) | 否 | 源站最近更新时间 |
| `fetched_at` | datetime (UTC) | 是 | 本系统抓取时间 |
| `authors` | string[] | 否 | 论文作者 / 博客作者 |
| `raw_text` | string | 否 | 摘要 / 描述原文（截断至 4000 字符） |
| `cve_ids` | string[] | 否 | 关联 CVE |
| `cvss` | object | 否 | `{version, score, vector, severity}` |
| `epss` | object | 否 | `{score, percentile, date}` |
| `kev` | object | 否 | `{date_added, known_ransomware, due_date}` |
| `affected` | object[] | 否 | GHSA/OSV 的受影响包信息 |
| `references` | string[] | 否 | 参考链接 |
| `tags_raw` | string[] | 否 | 源站原始标签 |
| `lang` | string | 是 | 原文语言，默认 `en` |

### 5.2 LLM 摘要字段 `llm_summary`

所有条目经 LLM 处理后产出的**结构化 JSON**（必须通过 schema 校验）。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `summary_zh` | string | 是 | 中文一句话摘要（≤ 120 字） |
| `why_it_matters_zh` | string | 是 | 推荐理由（≤ 150 字），解释"为什么今天值得看" |
| `impact_zh` | string | 否 | 影响面描述（涉及产品/版本/场景） |
| `detection_signals_zh` | string[] | 否 | 检测信号（日志、IoC 类型、行为特征）—— **不含 exploit 代码** |
| `defense_advice_zh` | string[] | 否 | 防御/缓解建议（打补丁、配置、网络分段） |
| `tags` | string[] | 是 | 归一化标签，如 `rce` / `auth-bypass` / `supply-chain` / `linux-kernel` / `ml-security` |
| `category` | enum | 是 | `vuln` / `exploited` / `research` / `advisory` / `threat-intel` / `detection` |
| `severity_hint` | enum | 是 | `critical` / `high` / `medium` / `low` / `info` |
| `novelty_score` | float [0,1] | 是 | LLM 判断的新颖度 |
| `actionability_score` | float [0,1] | 是 | 可操作性（越高越需要今天就响应） |
| `confidence` | float [0,1] | 是 | LLM 自评置信度 |
| `refusal` | bool | 是 | 是否因内容涉及攻击步骤等被拒绝摘要 |
| `refusal_reason` | string | 否 | 拒绝原因（内部用，不对外展示） |

### 5.3 最终展示字段 `digest_item`

首页/栏目页渲染所用结构 = `raw_item` 精简版 + `llm_summary` + `ranking`。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` / `source` / `source_sub` / `title` / `url` / `published_at` | — | 是 | 同 raw_item |
| `cve_ids` / `cvss` / `epss` / `kev` | — | 否 | 同 raw_item |
| `llm` | object | 是 | 嵌入 `llm_summary` |
| `rank_score` | float | 是 | 最终排序分 |
| `rank_reasons` | string[] | 否 | 排序加分项解释（debug 用，可折叠） |
| `shown_in_sections` | string[] | 是 | 该条目出现在哪些首页栏目 |

---

## 6. 推荐排序逻辑

目标：让每天打开首页的人，在前 10 条以内就能看到"今天真正重要的事"。

### 6.1 打分模型（MVP 采用加权线性模型，透明、可解释）

```
rank_score =
    w_kev         * is_kev
  + w_epss        * epss_score                     # 0..1
  + w_cvss        * normalize(cvss_score, 10)      # 0..1
  + w_vendor      * vendor_weight                  # 0..1，来自厂商重要度表
  + w_novelty     * llm.novelty_score              # 0..1
  + w_actionable  * llm.actionability_score        # 0..1
  + w_freshness   * freshness_decay(published_at)  # 1 表示今天
  - p_duplicate   * duplicate_penalty              # 同一 CVE 多源时，次源降权
  - p_refusal     * (1 if llm.refusal else 0)      # 被拒绝的不进前排
```

**MVP 默认权重（可在 `scripts/rank_items.py` 的 YAML/常量里调整）**

| 权重 | 默认值 | 含义 |
|---|---|---|
| w_kev | 3.0 | 进了 KEV 直接最高优先级 |
| w_epss | 2.0 | EPSS 越高越优先 |
| w_cvss | 1.2 | CVSS 兜底 |
| w_vendor | 1.0 | 厂商重要度（Microsoft/Cisco/Fortinet/Apple 等 = 1.0，小众 = 0.3） |
| w_novelty | 1.0 | 新颖度 |
| w_actionable | 1.5 | 可操作性 |
| w_freshness | 0.8 | 新鲜度 |
| p_duplicate | 1.0 | 同一 CVE 在多源出现的次源扣分 |
| p_refusal | 5.0 | 触发安全拒绝的强惩罚 |

### 6.2 栏目内排序

- 各栏目先在本源内按 `rank_score` 排序，再取 Top N。
- **KEV 栏目**强制按 `kev.date_added desc, epss desc` 排序，忽略 LLM 分。
- **论文栏目**额外加 `author_h_index_hint`（v0.3 再做，MVP 不实现）。

### 6.3 去重

- 以 `cve_ids` 为主键聚类：一条 CVE 只展示一次，主源优先级：`kev > nvd > ghsa > osv > vendor > ti_blog`。
- 副源以 "更多来源" 折叠展示。

---

## 7. 安全边界（硬性红线）

本产品面向防御者，**以下内容一律不抓取、不缓存、不展示、不生成**：

1. ❌ 不存储 / 不展示 PoC / exploit 代码**正文**、payload、shellcode、complete 攻击链复现步骤（即便来源是公开仓库，也只保留链接而不镜像正文）。
2. ❌ 不展示恶意样本的可执行内容、不提供样本下载；哈希等元信息可展示。
3. ❌ 不生成复现攻击的技术细节、不生成绕过教程、不复述 "如何利用"。
4. ❌ 不对 exploit-db / GitHub PoC 仓库等做正文爬取或镜像缓存，只保留 URL + 来源标签。
5. ❌ LLM Prompt 中显式禁止产出可操作的攻击指令；若 raw_text 注入诱导，LLM 必须触发 `refusal=true`。

**允许展示**：
- ✅ CVE 编号、受影响版本、CVSS / EPSS / KEV 元数据
- ✅ 风险摘要、业务影响、受影响产品线
- ✅ 检测信号（日志字段、异常行为、IoC 类型描述）
- ✅ 防御与缓解建议（补丁版本、配置、网络策略）
- ✅ 权威来源链接（由用户自己判断是否深入阅读）
- ✅ **Exploit 存在性信号**：`risk.has_public_exploit`、`risk.exploit_maturity` (`unreported` / `poc` / `functional` / `weaponized` / `in_the_wild`，对齐 CVSS Temporal E)
- ✅ **Exploit 外链**：`risk.exploit_references`——仅保存第三方公开来源的 URL + source 标签 + 可选 label，点击由读者自担风险跳转至第三方站点；本站不缓存第三方页面正文

**内容审查流程**：
1. fetcher 层：对源 URL 做黑名单过滤；只写入 `exploit_references` 链接元数据，禁止写入正文 / payload / 步骤。
2. LLM 层：system prompt 中强制防御者视角 + refusal 指令；摘要中可提 "已有公开 PoC，风险上升"，**禁止** 复述 PoC 内容。
3. 校验层：若 `llm.refusal=true` 或 `summary_zh` 命中攻击性关键词（如"执行如下命令"、"payload 如下"、"shellcode"），则从 `digest_item` 中剔除，只保留"已拒绝摘要，请前往来源查看"的占位。

---

## 8. 每日自动更新流程

### 8.1 触发

- GitHub Actions `cron`：每日 UTC 23:00（北京时间次日 07:00）执行。
- 另提供手动触发（`workflow_dispatch`）用于回灌历史。

### 8.2 Pipeline 步骤

```
[1] fetch_*       并行抓取各源 → data/raw/YYYY-MM-DD/*.json
        ↓
[2] normalize     归一化到 raw_item schema → 校验
        ↓
[3] summarize     LLM 调用（支持 mock） → llm_summary → schema 校验
        ↓
[4] rank_items    计算 rank_score、去重、分配 sections
        ↓
[5] build_digest  输出 data/daily/YYYY-MM-DD.json + data/processed/*
        ↓
[6] build_site    Astro 构建静态站点
        ↓
[7] deploy        Push 到 gh-pages 分支 / GitHub Pages artifact
```

### 8.3 容错策略

- 任一数据源失败：跳过该源，记录到 `data/daily/YYYY-MM-DD.errors.json`，**不影响整体发布**。
- LLM 失败/限流：该条目回退为"仅原始标题 + 链接"展示，`llm.summary_zh = null`。
- 当日 pipeline 失败：保留昨日站点不变，在首页顶部显示 banner「今日更新失败，详见 Actions 日志」。

### 8.4 幂等 & 可回放

- 所有 fetcher 支持指定日期参数，可手动补跑某一天。
- `data/raw/` 与 `data/daily/` 全部进 Git，便于复现与回滚。

---

## 9. GitHub Pages 部署方式

### 9.1 仓库结构（复用规则文件中定义的目录）

```
cyber-daily-radar/
  .github/workflows/daily.yml      # 抓取+构建+部署一体流程
  .github/workflows/deploy.yml     # 仅前端构建+部署（手动用）
  scripts/                          # Python 抓取与处理
  schemas/                          # JSON Schema
  data/                             # 所有快照（进 Git）
  src/                              # Astro 前端
  docs/                             # PRD / 架构 / 数据源 / Prompts
```

### 9.2 部署方式

- 使用 **GitHub Actions → Pages artifact → deploy-pages** 官方方案（非 gh-pages 分支）。
- 前端通过 Astro `output: 'static'` 输出到 `dist/`。
- `base` 配置为 `/cyber-daily-radar/`，以适配 Pages 子路径；若绑定自定义域名则改为 `/`。

### 9.3 密钥管理

- `OPENAI_API_KEY` 等敏感信息放 **GitHub Actions Secrets**，不出现在代码或 data 文件里。
- 本地开发使用 `.env`（已 gitignore），并通过 `LLM_MOCK=1` 开启 mock 模式。

### 9.4 成本控制

- LLM 调用前做**去重 + 缓存**：以 `raw_item.id + content_hash` 为 key 写入 `data/cache/llm/`，同一条内容不重复调用。
- 每日 token 预算上限：MVP ≤ 50k input / 20k output，超预算自动降级为仅对 Top N 条目调用 LLM。

---

## 10. 后续可扩展方向

1. **多 LLM 后端**：支持 OpenAI / Anthropic / 国产（豆包、通义、DeepSeek）/ 本地 Ollama，统一通过 adapter 切换。
2. **订阅系统**：RSS / Atom / JSON Feed（v0.2） → 邮件日报（依赖外部发信服务）。
3. **主题周报 / 月报**：基于每日 digest 做二次聚合，输出趋势与重点事件（v0.3）。
4. **可视化仪表盘**：CVE 数量趋势、KEV 增长、厂商分布、EPSS 分布（v0.3+）。
5. **个性化过滤**：基于 URL query 的 client-side 过滤（如 `?tags=linux,container&min_epss=0.5`），无需账号。
6. **多语言**：英文版、日文版摘要（共享排序与抓取层）。
7. **社区化贡献**：允许通过 PR 补充「厂商列表」「TI 博客列表」「标签归一化字典」。
8. **与 SIEM/SOAR 联动**：以 JSON Feed 形式喂给下游自动化系统（仅输出检测相关字段）。
9. **论文深读层**：对四大会议论文生成 1-2 页的"研究员笔记"（v0.3 之后）。
10. **历史检索**：当数据量足够大，再引入 pagefind/lunr 做全站检索。

---

## 11. 验收标准（MVP）

- [ ] 在空仓库 fork 后，仅配置 `OPENAI_API_KEY` 一个 Secret，即可跑通每日 pipeline。
- [ ] `LLM_MOCK=1` 本地跑通全流程，不产生任何外部 API 调用。
- [ ] `data/daily/YYYY-MM-DD.json` 通过 `digest_item.schema.json` 校验。
- [ ] 首页加载 < 2s（GitHub Pages，4G 网络）。
- [ ] 首页 Top 5 人工抽检：KEV 新增必在其中（若当日存在）。
- [ ] 安全红线自动化测试：输入包含"exploit code"的假 raw_item，LLM 输出 `refusal=true` 且不进入 digest。

---

（文档完）
