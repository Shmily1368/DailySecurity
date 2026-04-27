# 厂商安全公告 (Vendor Advisories) 数据源规划

本文档对应 `config/sources/vendor_advisories.yml`，定义了国内外主要安全厂商、互联网云服务商、硬件产品供应商发布的安全通告接入计划。

## 1. 核心用途与目标
厂商安全公告通常是某个产品出现 0-day 或 N-day 漏洞后，厂商官方发布的第一手缓解、修复或补丁方案。
* **用途**：提供最权威、无损的修复方案和产品受影响版本信息。
* **可信度 (Source Quality)**：极高（Primary）。这是安全事件处置的“Source of Truth”。
* **安全策略**：严格（`strict_no_poc`），只提取漏洞元数据、影响版本和修复补丁，绝不保存漏洞利用代码。

## 2. 来源分类与特点

### 2.1 国际顶级厂商 (Global Product Vendors)
如 Microsoft (MSRC), Cisco, Apple, Google, VMware, Oracle 等。
* **自动化难度**：低 ~ 中。大部分厂商（如 Microsoft, Cisco）提供标准化的 CVRF API 或规范的 RSS 订阅。少数依赖 HTML 表格解析。
* **接入优先级**：**P0**。由于影响全球最广泛的基础设施，必须最先接入。

### 2.2 国内云厂商与大厂 (CN Cloud Providers & Internet Companies)
如 阿里云、腾讯云、字节跳动、华为等。
* **自动化难度**：中 ~ 高。
  * 部分厂商（如阿里云、腾讯云）官网有专门的 HTML 公告列表，可通过爬虫结构化提取。
  * 较多互联网大厂的 SRC (Security Response Center) 平台缺乏通用的公告 RSS，很多高质量通告更倾向于通过微信公众号等私域渠道发布。
* **规则**：坚决不碰微信公众号等私域爬虫，不绕过复杂反爬。对仅有私域渠道的厂商标记为 `manual_pending`。
* **接入优先级**：**P1**。优先接入华为 PSIRT、阿里云、腾讯云的公开 HTML 列表。

### 2.3 国内安全厂商 (CN Security Vendors)
如 360CERT, 绿盟科技, 奇安信, 长亭科技等。
* **自动化难度**：高。
  * 这些厂商发布的通常是关于“他人产品漏洞”的第三方分析与通告，虽然非常快且质量高，但同样极其依赖微信公众号传播。
  * 少数厂商（如 360CERT、绿盟）在官网有固定的 HTML 页面维护预警列表。
* **接入优先级**：**P2**。优先攻克 360CERT 和绿盟的 HTML 解析，其余设为 `manual_pending` 持续观察。

## 3. 后续开发指南

在开发 `scripts/fetch_vendor_advisories.py` 时：
1. 解析 YAML 配置并过滤 `enabled: true` 的项。
2. 按照 `parser` 类型，分派给不同的处理器：
   - `api`: 直接调取接口，映射 JSON。
   - `rss`: 使用 `feedparser` 解析。
   - `html`: 使用 `BeautifulSoup` 或 `lxml` 根据定制的 CSS 选择器抽取。
3. 对带有 `manual_pending` 标记的来源，仅保留在配置内作为知识沉淀，运行时跳过。

## 已实现来源
- **360CERT**: 启用 (HTML 解析)
- **阿里云安全公告**: 启用 (HTML 解析)
- **腾讯云安全公告**: 启用 (HTML 解析)
- **华为 PSIRT**: 启用 (HTML 解析)
- **Microsoft MSRC**: 启用 (API)
- **Cisco PSIRT**: 启用 (RSS)
- **Apple Security Releases**: 启用 (HTML 解析)
- **Google Chrome Releases**: 启用 (RSS)
- **Android Security Bulletin**: 启用 (HTML 解析)
- **GitLab Security Releases**: 启用 (RSS)
- **Fortinet PSIRT**: 启用 (RSS)
- **Palo Alto Security Advisories**: 启用 (RSS)

## 暂未实现/保留为 Disabled 的来源
由于部分网站 URL 变动或暂时没有稳定公开入口，以下来源保留在配置中但未启用 (`enabled: false`)：
- **绿盟科技 NSFOCUS**: 原 HTML 列表页返回 404
- **Atlassian Security Advisories**: 官网 URL 返回 404
- **Ivanti Security Advisories**: 论坛 URL 返回 404
- 以及其它标记为 `manual_pending` 的国内厂商/云厂商 (如奇安信、深信服、百度 SRC 等)，需后续寻找可自动化抓取的入口。

## 输出文件位置
- 数据存储于: `data/raw/vendor_advisories.json`
- 错误日志存储于: `data/raw/vendor_advisories_errors.json`

## 如何新增一个国内厂商来源
1. 在 `config/sources/vendor_advisories.yml` 中新增一个 Source 配置块，并确保 `region: "CN"`。
2. 设置 `enabled: true`。
3. 指定 `parser` (推荐优先寻找 `api` 或 `rss`，如无则使用 `html`)。
4. 若 `html` 默认解析器 (提取链接并生成去重 ID) 不能满足要求，可在 `scripts/parsers/vendor_advisory_parsers.py` 中 `HtmlParser` 增加特化处理函数。
5. 运行测试：`python scripts/fetch_vendor_advisories.py --source <新增的id> --limit-per-source 5`。
