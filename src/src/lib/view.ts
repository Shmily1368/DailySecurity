import type { DigestItem } from './data';
import { getDetailLocation, getTopicSlug } from './data';

export const TYPE_LABELS = {
    paper: '学术论文', cve: '漏洞预警', kev: '在野利用',
    advisory: '安全公告', threat_report: '威胁情报', detection_rule: '检测规则',
} as const;

export function itemDate(item: DigestItem): string {
    if (item.date_precision === 'year' && item.published_year) return `${item.published_year} 年（仅知年份）`;
    if (item.published_at) return `${item.published_at.slice(0, 10)} 发布`;
    if (item.first_seen_at) return `${item.first_seen_at.slice(0, 10)} 首次发现 · 发布日期未知`;
    return '发布日期未知';
}

export function summaryLabel(item: DigestItem): string {
    switch (item.summary_status) {
        case 'model': return '模型摘要';
        case 'excerpt': return '来源摘录';
        case 'refused': return '摘要未提供';
        case 'mock': return '演示数据';
        default: return '历史摘要 · 未重新核验';
    }
}

export function preview(item: DigestItem, detailUrl?: string) {
    return {
        id: item.id, title: item.title, type: item.type, typeLabel: TYPE_LABELS[item.type],
        date: itemDate(item), severity: item.severity, source: item.source_name,
        url: item.source_url, aliases: item.aliases ?? [], cves: item.cves ?? [],
        sources: [...new Set([item.source_name, ...(item.related_sources ?? []).map(s => s.source_name)])],
        summary: (item.llm_summary?.summary_zh || item.summary || '来源未提供摘要').slice(0, 120),
        summaryLabel: summaryLabel(item),
        topics: [...new Set([...(item.topics ?? []), ...(item.llm_summary?.tags ?? [])])]
            .slice(0, 6).map(topic => ({ topic, slug: getTopicSlug(topic) })),
        detail: detailUrl ?? getDetailLocation(item.id),
    };
}
export type ItemPreview = ReturnType<typeof preview>;

export function searchText(item: DigestItem): string {
    return [item.id, item.title, item.source, item.source_sub, item.source_name,
        item.source_url, ...(item.aliases ?? []), ...(item.cves ?? []),
        ...(item.vendors ?? []), ...(item.products ?? []), ...(item.topics ?? []),
        ...(item.llm_summary?.tags ?? []), item.summary, item.llm_summary?.summary_zh,
        ...(item.related_sources ?? []).flatMap(s => [s.source, s.source_sub, s.source_name, s.native_id, s.source_url])]
        .filter(Boolean).join(' ').normalize('NFKC').toLowerCase();
}
