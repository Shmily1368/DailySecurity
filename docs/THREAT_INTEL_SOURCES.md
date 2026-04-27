# 威胁情报 (Threat Intelligence) 数据源规划

本文档对应 `config/sources/threat_intel.yml`，定义了国内外官方 CERT、安全厂商威胁情报中心、安全实验室和媒体社区的接入计划。

## 1. 核心用途与目标
威胁情报侧重于 APT 攻击、恶意软件、勒索组织、新型 TTP（战术、技术和过程）及规模性安全事件的分析报告。
* **用途**：为蓝队和防御工程师提供高阶攻击趋势、IOCs 提取、内部检测规则校准。
* **可信度 (Source Quality)**：因源而异。官方机构（如 CISA, CNCERT）和顶级实验室（如 Google TAG, Microsoft TI）为 Primary，知名媒体（如 BleepingComputer）和社区（如 FreeBuf）为 Secondary 或 Community。
* **安全策略**：严格（`strict_no_poc`），关注于“谁在打”、“打了谁”、“怎么防御”，而禁止包含绕过技术的教学。

## 2. 来源分类与特点

### 2.1 国际顶级安全实验室与机构 (Global Threat Labs & CERTs)
如 CISA Cybersecurity Advisories, Google TAG, Microsoft TI, Palo Alto Unit 42, Mandiant, CrowdStrike 等。
* **自动化难度**：极低。大部分国际顶尖实验室与安全媒体均提供高质量的 RSS Feed。
* **接入优先级**：**P0**。这是全球最前沿的高阶情报池。

### 2.2 国内国家级 CERT 与漏洞库 (CN Government CERTs & Vuln DBs)
如 CNCERT, CNVD, CNNVD 等。
* **自动化难度**：极高。
  * 国家级网站的反爬虫策略通常极为严苛，部分页面动态加载或有强验证码保护。
  * 报告格式不统一，结构化抽取成本高。
* **规则**：绝不绕过其反爬虫机制。对 CNVD 和 CNNVD 等高敏感源，建议仅按需、低频访问，或在后续阶段作为补充。当前状态：`enabled: false`，`parser: html/mixed`，需谨慎评估。
* **接入优先级**：**P3**。

### 2.3 国内安全厂商威胁情报中心 (CN Threat Intelligence Centers)
如 360CERT 报告、绿盟 NTI、腾讯安全威胁情报中心、微步在线 ThreatBook、奇安信威胁情报中心等。
* **自动化难度**：高。
  * 与厂商公告类似，大量深度 APT 报告通过微信公众号首发。
  * 仅部分（如奇安信博客、360CERT 报告列表）提供网页 HTML 结构化列表。
* **规则**：坚决不碰微信公众号等私域爬虫。优先抓取有官方博客/HTML 列表的来源。对依赖私域或微社区的来源，标记为 `manual_pending` 并写明 `needs verification`。
* **接入优先级**：**P1**。优先接入奇安信、360CERT 官网 HTML 列表。

### 2.4 国内外安全媒体与社区 (Security Media & Communities)
如 FreeBuf, 安全客, 先知社区, 看雪，以及国外的 BleepingComputer, The Hacker News 等。
* **自动化难度**：低 ~ 中。
  * 国外媒体（如 THN, BleepingComputer）和国内部分媒体（如 FreeBuf）均提供 RSS。
  * 社区内容（如先知、看雪）偏向于底层技术研究与实战技巧。
* **风险点**：社区文章通常包含大量具体的攻击 Payload 或利用手法，需要极高的过滤敏感度。
* **接入优先级**：**P2**。优先接入国内外大媒体 RSS 了解宏观事件；对于社区文章，暂时在 `manual_pending` 或 `enabled: false` 中保留观察。

## 3. 后续开发指南

在开发 `scripts/fetch_threat_intel.py` 时：
1. 解析 YAML 配置并过滤 `enabled: true` 的项。
2. 按照 `parser` 类型（`rss` 或 `html`）分别处理。
3. 将抓取的内容统一映射为 `RawItem` 模型，确保 `type` 设置为 `threat_report` 或 `advisory`，并在后续 LLM 处理阶段使用专门的 `THREAT_REPORT_USER_PROMPT` 提取核心情报和防御建议。
## 已实现来源
### 国内：
- **360CERT 安全报告**: 启用 (HTML)
- **CNCERT**: 启用 (HTML)
- **先知社区**: 启用 (HTML)

### 国际：
- **CISA Cybersecurity Advisories**: 启用 (RSS)
- **Microsoft Threat Intelligence**: 启用 (RSS)
- **Palo Alto Unit 42**: 启用 (RSS)
- **Cisco Talos**: 启用 (RSS)
- **SentinelOne**: 启用 (RSS)
- **Sophos**: 启用 (RSS)
- **ESET**: 启用 (RSS)
- **Check Point Research**: 启用 (RSS)

## 保留配置但未启用 (Disabled / Pending)
- 国内：微步在线 ThreatBook、奇安信威胁情报中心、绿盟 NTI、腾讯安全、深信服、安全客、FreeBuf、看雪、CNVD、CNNVD。以及阿里/百度/华为/字节/京东/美团/小米等 SRC 及安全博客。
- 国际：Google TAG, Mandiant, CrowdStrike, Rapid7, Cloudflare, Akamai, Elastic, SANS ISC, BleepingComputer, The Hacker News, SecurityWeek。
- 原因：部分来源没有公开或稳定的接口 (API/RSS)，且 HTML 页面使用了强混淆或前端渲染框架难以直接用 Python `BeautifulSoup` 抓取；部分网站配置了防爬机制。为了不阻塞每日流水线，暂时置为 Disabled，并在 config 内标注为 `manual_pending` 或 `html` 保留不激活。

## 提取的数据字段
每条 `threat_report` 通过正则表达式和启发式匹配提取以下元数据并写入 `RawItem.threat_meta` 之中：
- `threat_actors`: 如 APT28, Lazarus, Volt Typhoon 等
- `malware_families`: 如 LockBit, BlackCat, Cobalt Strike 等
- `attack_techniques`: 如 T1059 (MITRE ATT&CK 技术)
- `iocs_present`: 布尔值，用于指示正文或标题是否包含 IOC 信号，如 "sha256", "indicators of compromise"。

## 后续如何新增国内来源
1. 在 `config/sources/threat_intel.yml` 中新增一个 Source 配置块，并确保 `region: "CN"`，设置 `enabled: true`。
2. 指定 `parser` 优先级为：`api` > `rss` > `html`。
3. 对于动态渲染或反爬严格的源，可在 `scripts/parsers/threat_intel_parsers.py` 中扩充或引入 Selenium / Playwright 等头执行抓取逻辑。
4. 运行单源验证测试：`python scripts/fetch_threat_intel.py --source <新增的id> --limit-per-source 5`。
