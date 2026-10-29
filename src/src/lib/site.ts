import { createHash } from 'node:crypto';
import { getLatestDigest, getSnapshot, pickItems, payloadChunk, PAGE_SIZE } from './data';
import { preview, searchText } from './view';
const labels: Record<string, string> = {
    research_ai: 'AI 安全', research_systems: '系统与软件', research_crypto: '密码与隐私',
    research_others: '综合前沿', research_history: '历史研究推荐',
    vuln_exploited: '在野利用', vuln_poc: '公开 PoC', vuln_supply_chain: '供应链与开源',
    vuln_baseline: '常规披露', threat_apt: 'APT', threat_cybercrime: '网络犯罪',
    threat_campaigns: '攻击活动', threat_macro: '宏观情报', vendor_cloud: '云与服务',
    vendor_os: '操作系统与软件', vendor_iot: '物联网',
};
let catalogCache: ReturnType<typeof buildCatalog> | undefined;
function buildCatalog() {
    const digest = getLatestDigest();
    const groupSpecs = [
        ['top_10', '每日精选', null, ''],
        ['research', '学术论文', 'paper', 'research_'],
        ['vuln', '漏洞预警', 'cve,kev', 'vuln_'],
        ['threat', '威胁情报', 'threat_report', 'threat_'],
        ['vendor', '安全公告', 'advisory', 'vendor_'],
        ['detection', '检测规则', 'detection_rule', 'detection_'],
    ] as const;
    const validIds = new Set(digest.items.map(item => item.id));
    const membership = new Map<string, string>();
    for (const [section, ids] of Object.entries(digest.sections)) {
        const group = groupSpecs.find(([, , , prefix]) => prefix && section.startsWith(prefix));
        if (group) for (const id of ids) membership.set(id, group[0]);
    }
    const classify = (item: typeof digest.items[number]) => membership.get(item.id) ??
        groupSpecs.find(([, , types]) => types && types.split(',').includes(item.type))?.[0];
    const groups = groupSpecs.map(([key, label, types, prefix]) => ({
        key, label,
        ids: types ? digest.items.filter(item => classify(item) === key).map(item => item.id) :
            pickItems(digest, digest.sections.top_10 ?? []).map(item => item.id),
        subgroups: prefix ? Object.entries(digest.sections).filter(([section]) => section.startsWith(prefix))
            .map(([key, ids]) => ({ key, label: labels[key] ?? key, ids: ids.filter(id => validIds.has(id)) })) : [],
    }));
    const rows = digest.items.flatMap((_, index) => index % PAGE_SIZE ? [] :
        digest.items.slice(index, index + PAGE_SIZE).map(item => preview(item, payloadChunk(digest.date, index / PAGE_SIZE).url)));
    return { groups, rows };
}
export function getCatalog() { return catalogCache ??= buildCatalog(); }
export type Catalog = ReturnType<typeof getCatalog>;
export function getSearchIndex() {
    return getLatestDigest().items.map(item => ({ id: item.id, text: searchText(item) }));
}
export function getManifest() {
    const digest = getLatestDigest();
    const version = getSnapshot()?.sha256 ?? createHash('sha256').update(JSON.stringify(digest)).digest('hex');
    return {
        date: digest.date, version, generated_at: digest.generated_at,
        checked_at: digest.health?.checked_at ?? null,
        built_at: new Date().toISOString(), commit: process.env.DATA_COMMIT ?? process.env.GITHUB_SHA ?? null,
        status: digest.health?.status ?? 'unknown', item_count: digest.items.length, is_mock: !!digest.is_mock,
        model_count: digest.items.filter(item => item.summary_status === 'model').length,
        excerpt_count: digest.items.filter(item => item.summary_status === 'excerpt').length,
        sources: Object.entries(digest.health?.sources ?? {}).map(([name, row]) => ({
            name, status: row.status, count: typeof row.item_count === 'number' ? row.item_count : 0,
        })),
        catalog: `/edition/${version}/catalog.json`, search: `/edition/${version}/search.json`,
    };
}
