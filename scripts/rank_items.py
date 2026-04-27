import re
from models import DigestItem, ItemType

def calculate_scores(item: DigestItem) -> DigestItem:
    """计算风险分数与推荐分数，并填入 rank_reasons。"""
    risk_score = 0.0
    recommendation_score = 0.0
    reasons = []

    # 1. CISA KEV: +10
    if item.risk and (item.risk.kev_listed or str(item.risk.kev_status) == "listed"):
        risk_score += 10.0
        recommendation_score += 10.0
        reasons.append("CISA KEV 已收录 (+10)")

    # 2. EPSS >= 0.9: +6
    if item.risk and item.risk.epss_score is not None and item.risk.epss_score >= 0.9:
        risk_score += 6.0
        recommendation_score += 6.0
        reasons.append(f"EPSS 极高利用概率 ({item.risk.epss_score:.2f}) (+6)")

    # 3. CVSS Critical (>=9.0): +4
    if item.risk and item.risk.cvss_score is not None and item.risk.cvss_score >= 9.0:
        risk_score += 4.0
        recommendation_score += 4.0
        reasons.append(f"CVSS 严重风险 ({item.risk.cvss_score:.1f}) (+4)")

    # 4. 有补丁: +3
    # 通过类型或 LLM 生成的建议字段判断
    has_patch = False
    if item.type == ItemType.ADVISORY:
        has_patch = True
    else:
        text_to_check_patch = (
            str(item.llm_summary.defense_advice_zh) + 
            str(item.llm_summary.recommended_action_zh) + 
            str(item.llm_summary.summary_zh)
        )
        if any(kw in text_to_check_patch for kw in ["补丁", "修复版本", "升级到", "已修复", "更新至", "安全更新"]):
            has_patch = True
            
    if has_patch:
        recommendation_score += 3.0
        reasons.append("有可用补丁/修复方案 (+3)")

    # 5. 影响边界设备/VPN/防火墙/邮件网关: +5
    edge_keywords = ["vpn", "防火墙", "firewall", "网关", "gateway", "边界", "edge", "路由器", "router", "exchange", "网闸", "网关", "gateway", "ivanti", "fortinet", "palo alto", "citrix"]
    text_to_check_edge = (item.title + " " + str(item.summary) + " " + str(item.products)).lower()
    if any(kw in text_to_check_edge for kw in edge_keywords):
        risk_score += 5.0
        recommendation_score += 5.0
        reasons.append("影响边界/网络设备 (+5)")

    # 6. arXiv cs.CR: +2
    if item.type == ItemType.PAPER and item.source == "arxiv" and "cs.CR" in item.topics:
        recommendation_score += 2.0
        reasons.append("来自 arXiv cs.CR (+2)")

    # 7. 论文主题命中 LLM Security、Fuzzing、Supply Chain、Program Analysis、Web Security: +2
    research_keywords = [
        "llm", "large language model", "大语言模型", "大模型",
        "fuzzing", "模糊测试", 
        "supply chain", "供应链", 
        "program analysis", "程序分析", 
        "web security", "web安全", "网页安全"
    ]
    if item.type == ItemType.PAPER:
        text_to_check_research = (item.title + " " + str(item.summary) + " " + str(item.topics)).lower()
        if any(kw in text_to_check_research for kw in research_keywords):
            recommendation_score += 2.0
            reasons.append("命中热门研究主题 (+2)")

    # 8. Source reliability: primary > secondary > community
    # primary: +3, secondary: +2, community: +1
    primary_sources = ["nvd", "kev", "osv", "vendor", "cisa"]
    secondary_sources = ["ghsa", "epss", "github"]
    if item.source.lower() in primary_sources:
        recommendation_score += 3.0
        reasons.append("Primary 数据源 (+3)")
    elif item.source.lower() in secondary_sources:
        recommendation_score += 2.0
        reasons.append("Secondary 数据源 (+2)")
    else:
        recommendation_score += 1.0
        reasons.append("Community 数据源 (+1)")

    # LLM 原生分数作为基底加成 (0~1 之间，不占主导，但能微调排序)
    if item.llm_summary:
        llm_bonus = (item.llm_summary.novelty_score + item.llm_summary.actionability_score) / 2.0
        recommendation_score += llm_bonus
        reasons.append(f"LLM 评分加成 (+{llm_bonus:.1f})")

    # 更新字段
    item.risk_score = round(risk_score, 2)
    item.recommendation_score = round(recommendation_score, 2)
    item.rank_reasons = reasons

    return item

def rank_items(items: list[DigestItem]) -> list[DigestItem]:
    """对一组 DigestItem 计算分数并排序，返回按推荐分数从高到低排列的列表。"""
    scored_items = [calculate_scores(item) for item in items]
    return sorted(scored_items, key=lambda x: x.recommendation_score, reverse=True)
