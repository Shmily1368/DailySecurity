/**
 * 数据访问层: 读取 data/processed/mock_digest.json (Phase 2 mock)
 * 以及 data/daily/*.json (后续管线产物)。
 *
 * 类型与 scripts/models.py / schemas/digest_item.schema.json 保持对齐。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// src/src/lib/data.ts -> 项目根 (DailySecurity/)
const PROJECT_ROOT = path.resolve(__dirname, '..', '..', '..');
const DAILY_DIR = path.join(PROJECT_ROOT, 'data', 'daily');
const PROCESSED_DIR = path.join(PROJECT_ROOT, 'data', 'processed');

// 当前 Phase 2 默认读取的 mock digest
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
    refusal?: boolean;
    refusal_reason?: string | null;
    prompt_version?: string | null;
}

export interface DigestItem {
    id: string;
    type: ItemType;
    title: string;
    summary?: string | null;

    source: string;
    source_name: string;
    source_url: string;

    published_at: string;
    updated_at?: string | null;

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
}

interface DailyIndex {
    latest: string;
    dates: string[];
}

/** 读取最新 digest (data/daily/latest.json)。 */
export function getLatestDigest(): DailyDigest {
    const raw = fs.readFileSync(LATEST_DIGEST_PATH, 'utf-8');
    return JSON.parse(raw) as DailyDigest;
}

export function getDailyIndex(): DailyIndex {
    const p = path.join(DAILY_DIR, 'index.json');
    const raw = fs.readFileSync(p, 'utf-8');
    return JSON.parse(raw) as DailyIndex;
}

export function getDailyDigest(date: string): DailyDigest {
    const p = path.join(DAILY_DIR, `${date}.json`);
    const raw = fs.readFileSync(p, 'utf-8');
    return JSON.parse(raw) as DailyDigest;
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

/** 聚合所有日期的所有条目 (供归档、主题分析用) */
export function getAllItems(): DigestItem[] {
    const index = getDailyIndex();
    const allItems: DigestItem[] = [];
    const seen = new Set<string>();
    for (const date of index.dates) {
        try {
            const digest = getDailyDigest(date);
            for (const item of digest.items) {
                if (!seen.has(item.id)) {
                    seen.add(item.id);
                    allItems.push(item);
                }
            }
        } catch (e) {
            console.warn(`Failed to read digest for date ${date}`);
        }
    }
    // 按照 published_at 倒序
    allItems.sort((a, b) => new Date(b.published_at).getTime() - new Date(a.published_at).getTime());
    return allItems;
}

/** 获取所有主题/标签的列表 */
export function getAllTopics(): string[] {
    const items = getAllItems();
    const topics = new Set<string>();
    for (const item of items) {
        if (item.llm_summary?.tags) {
            item.llm_summary.tags.forEach(t => topics.add(t));
        }
        if (item.topics) {
            item.topics.forEach(t => topics.add(t));
        }
    }
    return Array.from(topics).sort();
}
