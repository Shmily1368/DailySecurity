/** Build-time access to a verified current generation and legacy daily archives. */
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// src/src/lib/data.ts -> 项目根 (DailySecurity/)
const PROJECT_ROOT = path.resolve(__dirname, '..', '..', '..');
const DAILY_DIR = path.join(PROJECT_ROOT, 'data', 'daily');
const LATEST_DIGEST_PATH = path.join(DAILY_DIR, 'latest.json');

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Category =
    | 'vuln'
    | 'exploited'
    | 'research'
    | 'advisory'
    | 'threat-intel'
    | 'detection';

export type ItemType =
    | 'paper'
    | 'cve'
    | 'kev'
    | 'advisory'
    | 'threat_report'
    | 'detection_rule';

export type ExploitMaturity =
    | 'unreported'
    | 'poc'
    | 'functional'
    | 'weaponized'
    | 'in_the_wild';

export interface ExploitRef {
    url: string;
    source: string;
    label?: string | null;
}

export interface RiskSignal {
    severity?: Severity | null;
    patch_status?: 'available' | 'unknown' | 'unavailable';
    patch_references?: string[];
    cvss_score?: number | null;
    cvss_vector?: string | null;
    epss_score?: number | null;
    epss_percentile?: number | null;
    kev_status?: 'listed' | 'not_listed' | 'unknown';
    kev_listed?: boolean;
    kev_date_added?: string | null;
    due_date?: string | null;
    known_ransomware?: boolean | null;
    known_exploited?: boolean | null;
    exploit_in_the_wild?: boolean | null;

    // Exploit 存在性信号 (仅存在性, 不含 PoC 正文)
    has_public_exploit?: boolean;
    exploit_maturity?: ExploitMaturity;
    exploit_references?: ExploitRef[];
}

export interface LlmSummary {
    summary_zh: string;
    why_it_matters_zh: string;
    impact_zh?: string | null;
    detection_signals_zh?: string[];
    defense_advice_zh?: string[];
    recommended_action_zh?: string | null;
    tags?: string[];
    category?: Category;
    severity_hint?: Severity;
    novelty_score: number;
    actionability_score: number;
    confidence: number;
    confidence_label?: 'abstract_only' | 'metadata_only' | 'with_references' | 'full_text' |
        'source_confirmed' | 'single_source' | 'multi_source' | 'unverified' | null;
    affected_assets?: string[] | null;
    cves?: string[] | null;
    limitations?: string[] | null;
    threat_type?: string | null;
    threat_actors?: string[] | null;
    malware_families?: string[] | null;
    affected_industries?: string[] | null;
    affected_regions?: string[] | null;
    attack_techniques?: string[] | null;
    iocs_present?: boolean | null;
    refusal?: boolean;
    refusal_reason?: string | null;
    prompt_version?: string | null;
}

export interface SourceInfo {
    source: string;
    source_sub?: string | null;
    source_name: string;
    source_url: string;
    native_id: string;
    source_quality?: 'primary' | 'secondary' | 'community' | 'unknown';
    link_kind?: 'article' | 'feed';
}

export interface DigestItem {
    id: string;
    type: ItemType;
    title: string;
    summary?: string | null;

    source: string;
    source_name: string;
    source_url: string;
    source_sub?: string | null;
    source_quality?: SourceInfo['source_quality'];
    aliases?: string[];
    related_sources?: SourceInfo[];
    summary_status?: 'legacy' | 'model' | 'excerpt' | 'refused' | 'mock';

    published_at: string | null;
    updated_at?: string | null;
    fetched_at?: string | null;
    first_seen_at?: string | null;
    date_precision?: 'exact' | 'year' | 'unknown';
    published_year?: number | null;
    is_backfill?: boolean;
    abstract_source?: string | null;

    cves?: string[];
    vendors?: string[];
    products?: string[];
    topics?: string[];
    authors?: string[];

    severity: Severity;
    risk?: RiskSignal | null;
    risk_score: number;
    recommendation_score: number;

    llm_summary: LlmSummary;
    why_it_matters: string;
    recommended_action?: string | null;
    confidence: number;

    shown_in_sections?: string[];
    rank_reasons?: string[];
}

export interface DailyDigest {
    schema_version: string;
    date: string;
    generated_at: string;
    is_mock?: boolean;
    hero: {
        one_liner_zh: string;
        stats: {
            cve_count: number;
            kev_added: number;
            paper_count: number;
            advisory_count?: number;
            max_epss: number;
        };
    };
    sections: Record<string, string[]>;
    items: DigestItem[];
    health?: {
        checked_at?: string;
        status?: string;
        sources?: Record<string, { status: string; count?: number; [key: string]: unknown }>;
        llm?: { groups?: Record<string, unknown>[]; circuit?: Record<string, unknown> | null };
    };
}

interface DailyIndex {
    latest: string;
    dates: string[];
}

export interface TopicEntry {
    topic: string;
    slug: string;
    topics: string[];
}

let topicEntriesCache: TopicEntry[] | null = null;
let topicSlugMapCache: Map<string, string> | null = null;

interface Snapshot {
    generation: string;
    date: string;
    generated_at: string;
    digest: string;
    index: string;
    state: string;
    sha256: string;
}
let snapshotCache: Snapshot | null | undefined;
let latestCache: DailyDigest | undefined;
let dailyIndexCache: DailyIndex | undefined;
const dailyCache = new Map<string, DailyDigest>();

function snapshotPath(relative: string): string {
    const target = fs.realpathSync(path.join(PROJECT_ROOT, 'data', relative));
    const generations = fs.realpathSync(path.join(PROJECT_ROOT, 'data', 'generations')) + path.sep;
    if (!target.startsWith(generations)) throw new Error('Snapshot path escapes generations');
    return target;
}

export function getSnapshot(): Snapshot | null {
    if (snapshotCache !== undefined) return snapshotCache;
    const pointer = path.join(PROJECT_ROOT, 'data', 'current.json');
    if (!fs.existsSync(pointer)) return snapshotCache = null;
    const current = JSON.parse(fs.readFileSync(pointer, 'utf8')) as Snapshot;
    for (const key of ['digest', 'index', 'state'] as const) snapshotPath(current[key]);
    const bytes = fs.readFileSync(snapshotPath(current.digest));
    if (createHash('sha256').update(bytes).digest('hex') !== current.sha256) {
        throw new Error('Current digest checksum mismatch');
    }
    snapshotCache = current;
    return current;
}

export function getLatestDigest(): DailyDigest {
    if (latestCache) return latestCache;
    const snapshot = getSnapshot();
    const raw = fs.readFileSync(snapshot ? snapshotPath(snapshot.digest) : LATEST_DIGEST_PATH, 'utf8');
    latestCache = JSON.parse(raw) as DailyDigest;
    if (snapshot && latestCache.date !== snapshot.date) throw new Error('Snapshot date mismatch');
    return latestCache;
}

export function getDailyIndex(): DailyIndex {
    if (dailyIndexCache) return dailyIndexCache;
    const snapshot = getSnapshot();
    const p = snapshot ? snapshotPath(snapshot.index) : path.join(DAILY_DIR, 'index.json');
    dailyIndexCache = JSON.parse(fs.readFileSync(p, 'utf8')) as DailyIndex;
    if (dailyIndexCache.dates.some(date => !/^\d{4}-\d{2}-\d{2}$/.test(date))) {
        throw new Error('Invalid archive date');
    }
    dailyIndexCache.dates = [...new Set(dailyIndexCache.dates)].sort().reverse();
    return dailyIndexCache;
}

export function getDailyDigest(date: string): DailyDigest {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error('Invalid date');
    if (date === getLatestDigest().date) return getLatestDigest();
    if (dailyCache.has(date)) return dailyCache.get(date)!;
    const p = path.join(DAILY_DIR, `${date}.json`);
    const digest = JSON.parse(fs.readFileSync(p, 'utf8')) as DailyDigest;
    // Avoid retaining 614MB of duplicate history during a build.
    if (dailyCache.size >= 2) dailyCache.delete(dailyCache.keys().next().value!);
    dailyCache.set(date, digest);
    return digest;
}

/** 根据 id 列表在 items 中查出条目, 保持顺序, 跳过找不到的 */
export function pickItems(digest: DailyDigest, ids: string[]): DigestItem[] {
    const map = new Map(digest.items.map((i) => [i.id, i]));
    const out: DigestItem[] = [];
    for (const id of ids) {
        const it = map.get(id);
        if (it) out.push(it);
    }
    return out;
}

/** 提取所有可用的日期列表 */
export function getAllDates(): string[] {
    return getDailyIndex().dates;
}

// 构建期间 data/daily 是固定快照，聚合和索引只需计算一次。
let allItemsCache: DigestItem[] | null = null;
let topicItemsCache: Map<string, DigestItem[]> | null = null;
const detailLocations = new Map<string, string>();
export const PAGE_SIZE = 20;

export function payloadChunk(date: string, page: number): { url: string; body: string } {
    const items = getDailyDigest(date).items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    const body = JSON.stringify(items);
    const hash = createHash('sha256').update(body).digest('hex');
    return { url: `/payload/${date}/${hash}.json.gz`, body };
}

export function getDetailLocation(id: string): string {
    if (!allItemsCache) getAllItems();
    const url = detailLocations.get(id);
    if (!url) throw new Error(`Missing detail payload for ${id}`);
    return url;
}

/** 聚合所有日期的所有条目 (供归档、主题分析用) */
export function getAllItems(): DigestItem[] {
    if (allItemsCache !== null) return allItemsCache;
    const index = getDailyIndex();
    const allItems: DigestItem[] = [];
    const seen = new Set<string>();
    for (const date of index.dates) {
        try {
            const digest = getDailyDigest(date);
            for (let offset = 0; offset < digest.items.length; offset += PAGE_SIZE) {
                const url = payloadChunk(date, offset / PAGE_SIZE).url;
                for (const item of digest.items.slice(offset, offset + PAGE_SIZE)) {
                if (!seen.has(item.id)) {
                    seen.add(item.id);
                    allItems.push(item);
                    detailLocations.set(item.id, url);
                }
                }
            }
        } catch (e) { throw new Error(`Invalid digest for date ${date}`, { cause: e }); }
    }
    // 按照 published_at 倒序
    const time = (i: DigestItem) => Date.parse(i.published_at ?? i.first_seen_at ?? '') || 0;
    allItems.sort((a, b) => time(b) - time(a));
    allItemsCache = allItems;
    return allItemsCache;
}

function getTopicItemsMap(): Map<string, DigestItem[]> {
    if (topicItemsCache !== null) return topicItemsCache;
    const index = new Map<string, DigestItem[]>();
    for (const item of getAllItems()) {
        const topics = new Set([
            ...(item.llm_summary?.tags ?? []),
            ...(item.topics ?? []),
        ].map(topicKey));
        for (const topic of topics) {
            const key = topicKey(topic);
            const related = index.get(key);
            if (related) related.push(item);
            else index.set(key, [item]);
        }
    }
    topicItemsCache = index;
    return topicItemsCache;
}

export function getTopicItems(topic: string): DigestItem[] {
    return getTopicItemsMap().get(topicKey(topic)) ?? [];
}

/** 获取所有主题/标签的列表 */
export function getAllTopics(): string[] {
    return getAllTopicEntries().filter(entry => entry.slug === getTopicSlug(entry.topic))
        .map(entry => entry.topic).sort();
}

function topicKey(topic: string): string { return topic.normalize('NFKC').trim().toLowerCase(); }

function getRawTopics(): string[] {
    return [...new Set(getAllItems().flatMap(item => [
        ...(item.llm_summary?.tags ?? []), ...(item.topics ?? []),
    ]))].sort();
}

function slugifyTopic(topic: string): string {
    const normalized = topic.normalize('NFKC').trim();
    const slug = normalized
        .replace(/\+/g, ' plus ')
        .replace(/[\\/]/g, '-')
        .replace(/[^\p{Letter}\p{Number}._\-\s]/gu, '-')
        .replace(/[\s-]+/g, '-')
        .replace(/^[.-]+|[.-]+$/g, '');
    return slug || 'topic';
}

function buildTopicEntries(): TopicEntry[] {
    const topics = getRawTopics();
    const registryFile = path.join(PROJECT_ROOT, 'config', 'topic-slugs.json');
    const registry = fs.existsSync(registryFile) ? JSON.parse(fs.readFileSync(registryFile, 'utf8')) as {
        legacy: [string, string][]; canonical: [string, string][];
    } : null;
    const slugCounts = new Map<string, number>();
    const legacy = new Map<string, { spellings: Set<string>; topics: Set<string> }>();
    const families = new Map<string, string>();
    for (const topic of topics) {
        if (!families.has(topicKey(topic))) families.set(topicKey(topic), topic);
    }
    const aliases: [string, string][] = registry?.legacy ?? topics.map(topic => {
        const baseSlug = slugifyTopic(topic);
        const currentCount = (slugCounts.get(baseSlug) ?? 0) + 1;
        slugCounts.set(baseSlug, currentCount);
        const slug = currentCount === 1 ? baseSlug : `${baseSlug}-${currentCount}`;
        return [topic, slug];
    });
    for (const [topic, slug] of aliases) {
        const key = topicKey(slug);
        const row = legacy.get(key) ?? { spellings: new Set(), topics: new Set() };
        row.spellings.add(slug);
        row.topics.add(topicKey(topic));
        legacy.set(key, row);
        if (!families.has(topicKey(topic))) families.set(topicKey(topic), topic);
    }
    const entries: TopicEntry[] = [];
    topicSlugMapCache = new Map();
    const stable = new Map(registry?.canonical ?? []);
    const reserved = new Set([...legacy.keys(), ...stable.values()].map(topicKey));
    for (const [key, topic] of families) {
        const base = slugifyTopic(key);
        const candidate = legacy.get(topicKey(base));
        let slug = stable.get(key) ?? base;
        if (!stable.has(key) && (registry || candidate && (candidate.topics.size !== 1 || !candidate.topics.has(key)))) {
            slug = `${base}-${createHash('sha256').update(key).digest('hex').slice(0, 12)}`;
            while (reserved.has(topicKey(slug))) slug += '-x';
        }
        reserved.add(topicKey(slug));
        topicSlugMapCache.set(key, slug);
        entries.push({ topic, slug, topics: [key] });
    }
    const paths = new Map(entries.map(entry => [entry.slug, entry]));
    for (const [folded, row] of legacy) {
        const related = [...row.topics];
        const label = related.map(key => families.get(key) ?? key).join(' / ');
        // Legacy collisions serve the same union at every case variant.
        for (const slug of new Set([...row.spellings, folded])) {
            paths.set(slug, { topic: label, slug, topics: related });
        }
    }
    return [...paths.values()];
}

export function getAllTopicEntries(): TopicEntry[] {
    if (!topicEntriesCache) {
        topicEntriesCache = buildTopicEntries();
    }
    return topicEntriesCache;
}

export function getTopicSlug(topic: string): string {
    if (!topicSlugMapCache) {
        getAllTopicEntries();
    }
    return topicSlugMapCache?.get(topicKey(topic)) ?? slugifyTopic(topicKey(topic));
}

export function getEntryItems(entry: TopicEntry): DigestItem[] {
    return [...new Map(entry.topics.flatMap(getTopicItems).map(item => [item.id, item])).values()];
}
