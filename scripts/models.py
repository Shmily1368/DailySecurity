"""
scripts/models.py

Cyber Security Daily Radar 的统一数据模型 (Pydantic v2)。

- RawItem: 抓取侧统一结构, 所有 fetcher 的输出都归一到此。
- DigestItem: 前端消费结构 = 精简 RawItem + LlmSummary + 排序分。
- SourceInfo / RiskSignal / LlmSummary: 组合字段。

与 schemas/raw_item.schema.json、schemas/digest_item.schema.json 保持对齐,
任一改动必须同步更新对方。
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


# ---------------------------------------------------------------------------
# 枚举
# ---------------------------------------------------------------------------


class ItemType(str, Enum):
    """条目类型, 覆盖论文与漏洞情报两大类。"""

    PAPER = "paper"
    CVE = "cve"
    KEV = "kev"
    ADVISORY = "advisory"
    THREAT_REPORT = "threat_report"
    DETECTION_RULE = "detection_rule"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    """LLM 归纳的业务类别, 用于首页分区与过滤。"""

    VULN = "vuln"
    EXPLOITED = "exploited"
    RESEARCH = "research"
    ADVISORY = "advisory"
    THREAT_INTEL = "threat-intel"
    DETECTION = "detection"


class KevStatus(str, Enum):
    """KEV 状态枚举, 比单纯布尔更明确。"""

    LISTED = "listed"
    NOT_LISTED = "not_listed"
    UNKNOWN = "unknown"


class ExploitMaturity(str, Enum):
    """
    Exploit 成熟度, 对齐 CVSS Temporal E (Exploit Code Maturity)。

    注意: 本字段只标注 "存在性与成熟度" 这一风险信号, 严禁在任何字段落地
    PoC 正文 / payload / 攻击步骤。
    """

    UNREPORTED = "unreported"       # 未见公开 PoC
    POC = "poc"                     # 已有概念验证 (通常不可直接武器化)
    FUNCTIONAL = "functional"       # 已有可运行 exploit
    WEAPONIZED = "weaponized"       # 已武器化 / 自动化
    IN_THE_WILD = "in_the_wild"     # 已在野利用


# ---------------------------------------------------------------------------
# 组合模型
# ---------------------------------------------------------------------------


class ExploitRef(BaseModel):
    """
    指向外部 exploit/PoC 资源的链接条目 (仅 URL + 元数据)。

    严格禁止在本模型中落地 PoC 正文、payload、shellcode、攻击步骤。
    只保留原始来源的公开链接, 由读者自行决定是否点击前往第三方站点。
    """

    model_config = ConfigDict(extra="forbid")

    url: HttpUrl = Field(..., description="外链 URL (ExploitDB / GitHub PoC / 博客 等)")
    source: str = Field(..., description="来源标识, 如 exploit-db / github / vendor / cisa")
    label: Optional[str] = Field(
        default=None, description="人类可读标签, 如 'ExploitDB #12345'"
    )


class SourceInfo(BaseModel):
    """数据来源描述。"""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(..., description="源枚举, 如 arxiv / nvd / kev / ghsa / vendor")
    source_sub: Optional[str] = Field(
        default=None, description="子来源, 如厂商名 / 会议名 / 博客名"
    )
    source_name: str = Field(..., description="人类可读来源名")
    source_url: HttpUrl = Field(..., description="原始条目链接")
    native_id: str = Field(..., description="源站原始 ID")


class RiskSignal(BaseModel):
    """漏洞类条目的量化风险信号 (论文类可全空)。"""

    model_config = ConfigDict(extra="forbid")

    # CVSS
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None

    # EPSS
    epss_score: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="EPSS 被利用概率, 0~1"
    )
    epss_percentile: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    # KEV
    kev_status: KevStatus = Field(
        default=KevStatus.UNKNOWN, description="CISA KEV 收录状态"
    )
    kev_listed: bool = Field(
        default=False, description="是否已在 CISA KEV (kev_status == listed 的布尔快照)"
    )
    kev_date_added: Optional[str] = Field(
        default=None, description="CISA KEV 收录日期 (YYYY-MM-DD)"
    )
    due_date: Optional[str] = Field(
        default=None,
        description="CISA KEV 强制修复截止日期 (YYYY-MM-DD), 面向联邦机构但可作为防御优先级参考",
    )
    known_ransomware: Optional[bool] = Field(
        default=None, description="是否已知被勒索软件利用"
    )
    known_exploited: Optional[bool] = Field(
        default=None,
        description="是否已在野利用 (新契约字段, 等价于旧 exploit_in_the_wild)",
    )
    # 兼容字段: 旧 schema 使用 exploit_in_the_wild, 保留以便渐进迁移
    exploit_in_the_wild: Optional[bool] = None

    # Exploit 存在性信号 (只记录是否存在和成熟度, 不落地 PoC 正文)
    has_public_exploit: bool = Field(
        default=False, description="是否已存在公开 exploit / PoC"
    )
    exploit_maturity: ExploitMaturity = Field(
        default=ExploitMaturity.UNREPORTED,
        description="exploit 成熟度 (对齐 CVSS Temporal E)",
    )
    exploit_references: List[ExploitRef] = Field(
        default_factory=list,
        description="指向外部 exploit/PoC 的公开链接 (仅 URL + 元数据, 禁止落地正文)",
    )


class LlmSummary(BaseModel):
    """LLM 产出的结构化摘要。防御者视角, 禁止攻击步骤。"""

    model_config = ConfigDict(extra="forbid")

    summary_zh: str = Field(..., description="一句话中文摘要, <= 120 字")
    why_it_matters_zh: str = Field(..., description="推荐理由, <= 150 字")
    impact_zh: Optional[str] = None
    detection_signals_zh: List[str] = Field(default_factory=list)
    defense_advice_zh: List[str] = Field(default_factory=list)
    recommended_action_zh: Optional[str] = Field(
        default=None, description="一句话行动指引, 给读者今天要做什么"
    )
    tags: List[str] = Field(default_factory=list)
    category: Category = Category.VULN
    severity_hint: Severity = Severity.INFO
    novelty_score: float = Field(..., ge=0.0, le=1.0)
    actionability_score: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    confidence_label: Optional[str] = Field(
        default=None,
        description=(
            "置信度标签, 枚举值: "
            "'abstract_only' / 'metadata_only' / 'with_references' / 'full_text'"
        ),
    )

    # 可选字段：如果存在则使用
    affected_assets: Optional[List[str]] = None
    cves: Optional[List[str]] = None
    limitations: Optional[List[str]] = None
    threat_type: Optional[str] = None
    threat_actors: Optional[List[str]] = None
    malware_families: Optional[List[str]] = None
    affected_industries: Optional[List[str]] = None
    affected_regions: Optional[List[str]] = None
    attack_techniques: Optional[List[str]] = None
    iocs_present: Optional[bool] = None

    refusal: bool = False
    refusal_reason: Optional[str] = None
    prompt_version: Optional[str] = None


# ---------------------------------------------------------------------------
# 主模型
# ---------------------------------------------------------------------------


class ThreatMeta(BaseModel):
    """特定于威胁情报报告的元数据"""
    model_config = ConfigDict(extra="forbid")
    
    malware_families: List[str] = Field(default_factory=list)
    threat_actors: List[str] = Field(default_factory=list)
    affected_industries: List[str] = Field(default_factory=list)
    affected_regions: List[str] = Field(default_factory=list)
    attack_techniques: List[str] = Field(default_factory=list)
    iocs_present: bool = False
    confidence: Optional[float] = None

class RawItem(BaseModel):
    """抓取侧归一结构, 每个 fetcher 必须输出此模型的实例列表。"""

    model_config = ConfigDict(extra="forbid")

    # 身份与类型
    id: str = Field(..., description="全局唯一 ID, 约定为 {source}:{native_id}")
    type: ItemType
    source_info: SourceInfo

    # 正文
    title: str
    summary: Optional[str] = Field(
        default=None, description="源站摘要/描述, 截断 <= 4000 字符"
    )
    raw_text: Optional[str] = Field(
        default=None, description="完整原文 (可选, 仅供内部 LLM 调用)"
    )

    # 时间
    published_at: datetime
    updated_at: Optional[datetime] = None
    fetched_at: datetime

    # 论文侧
    authors: List[str] = Field(default_factory=list)
    affiliations: List[str] = Field(default_factory=list)

    # 漏洞/公告侧
    cves: List[str] = Field(default_factory=list, description="关联 CVE 列表")
    vendors: List[str] = Field(default_factory=list)
    products: List[str] = Field(default_factory=list)
    affected_versions: List[str] = Field(default_factory=list)

    # 通用标签与语言
    topics: List[str] = Field(
        default_factory=list, description="源站原始主题/标签"
    )
    lang: str = "en"

    # 风险信号 (漏洞类必填, 论文类可全空)
    risk: Optional[RiskSignal] = None

    # 情报元数据 (仅针对情报类适用)
    threat_meta: Optional[ThreatMeta] = None

    # 参考链接
    references: List[HttpUrl] = Field(default_factory=list)


class DigestItem(BaseModel):
    """前端消费的最终条目 = 精简 RawItem + LlmSummary + 排序信息。"""

    model_config = ConfigDict(extra="forbid")

    # 身份与类型
    id: str
    type: ItemType

    # 正文
    title: str
    summary: Optional[str] = Field(
        default=None, description="源站原摘要, 可能为空"
    )

    # 来源 (扁平字段便于前端直接渲染)
    source: str
    source_name: str
    source_url: HttpUrl

    # 时间
    published_at: datetime
    updated_at: Optional[datetime] = None

    # 分类字段
    cves: List[str] = Field(default_factory=list)
    vendors: List[str] = Field(default_factory=list)
    products: List[str] = Field(default_factory=list)
    topics: List[str] = Field(default_factory=list)
    authors: List[str] = Field(default_factory=list)

    # 评估字段
    severity: Severity = Severity.INFO
    risk: Optional[RiskSignal] = None
    risk_score: float = Field(
        ..., ge=0.0, description="综合风险分, 来自 CVSS/EPSS/KEV 等"
    )
    recommendation_score: float = Field(
        ..., ge=0.0, description="本系统最终推荐分, 决定首页排序"
    )

    # LLM 字段 (扁平暴露核心字段, 同时保留嵌套 llm_summary)
    llm_summary: LlmSummary
    why_it_matters: str = Field(..., description="等同于 llm_summary.why_it_matters_zh")
    recommended_action: Optional[str] = Field(
        default=None, description="等同于 llm_summary.recommended_action_zh"
    )
    confidence: float = Field(..., ge=0.0, le=1.0)

    # 展示控制
    shown_in_sections: List[str] = Field(default_factory=list)
    rank_reasons: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 辅助: 顶层包装
# ---------------------------------------------------------------------------


class HeroStats(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_count: int = 0
    kev_added: int = 0
    paper_count: int = 0
    advisory_count: int = 0
    max_epss: float = 0.0


class Hero(BaseModel):
    model_config = ConfigDict(extra="forbid")

    one_liner_zh: str
    stats: HeroStats


class DailyDigest(BaseModel):
    """data/processed/mock_digest.json 与 data/daily/<date>.json 的包装结构。"""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "0.2.0"
    date: str
    generated_at: datetime
    is_mock: bool = False
    hero: Hero
    sections: dict[str, List[str]] = Field(default_factory=dict)
    items: List[DigestItem]


__all__ = [
    "ItemType",
    "Severity",
    "Category",
    "KevStatus",
    "ExploitMaturity",
    "ExploitRef",
    "SourceInfo",
    "RiskSignal",
    "LlmSummary",
    "RawItem",
    "DigestItem",
    "HeroStats",
    "Hero",
    "DailyDigest",
]
