/** Integration checks against the real archive; runs independently of Astro rendering. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { getAllItems, getAllTopicEntries, getEntryItems, getTopicItems, getTopicSlug } from '../src/src/lib/data';
import { getCatalog, getSearchIndex } from '../src/src/lib/site';
import { itemDate, preview, searchText } from '../src/src/lib/view';
const entries = getAllTopicEntries();
assert.equal(new Set(entries.map(entry => entry.slug)).size, entries.length, 'Duplicate route');
const folded = new Map<string, string>();
for (const entry of entries) {
    const key = entry.slug.toLowerCase();
    const ids = getEntryItems(entry).map(item => item.id).join('\n');
    if (folded.has(key)) assert.equal(ids, folded.get(key), `Case variants diverge: ${key}`);
    folded.set(key, ids);
}
const all = getAllItems();
const rawTopics = [...new Set(all.flatMap(item => [...(item.topics ?? []), ...(item.llm_summary?.tags ?? [])]))].sort();
const registry = JSON.parse(fs.readFileSync(path.resolve('../config/topic-slugs.json'), 'utf8')) as {
    legacy: [string, string][]; canonical: [string, string][];
};
for (const [topic, slug] of registry.legacy) {
    assert.ok(entries.some(entry => entry.slug === slug), `Old URL lost: ${topic}`);
}
for (const [topic, slug] of registry.canonical) {
    assert.equal(getTopicSlug(topic), slug, `Public URL drifted: ${topic}`);
}
for (const topic of rawTopics) {
    assert.ok(entries.some(entry => entry.slug === getTopicSlug(topic)), `Canonical URL missing: ${topic}`);
    assert.equal(new Set(getTopicItems(topic).map(item => item.id)).size, getTopicItems(topic).length, `Duplicate topic items: ${topic}`);
}
const catalog = getCatalog(), search = getSearchIndex();
const typedIds = catalog.groups.filter(group => group.key !== 'top_10').flatMap(group => group.ids);
assert.equal(typedIds.length, catalog.rows.length);
assert.equal(new Set(typedIds).size, catalog.rows.length, 'Type dispatch loses or repeats items');
assert.equal(search.length, catalog.rows.length);
for (const row of catalog.rows) assert.ok(search.some(index => index.id === row.id));
const sample = all[0];
const enriched = { ...sample, published_at: null, date_precision: 'unknown' as const,
    first_seen_at: '2026-10-29T01:00:00Z', aliases: ['GHSA-test-alias'], cves: ['CVE-2026-987654'],
    products: ['distinct-product'], related_sources: [{ source: 'secondary', source_sub: 'distinct-source',
        source_name: 'Secondary Publisher', source_url: 'https://example.org/advisory', native_id: 'secondary-id' }] };
const text = searchText(enriched);
for (const key of ['ghsa-test-alias', 'cve-2026-987654', 'distinct-product', 'distinct-source', 'secondary-id']) assert.ok(text.includes(key), key);
assert.ok(itemDate(enriched).includes('首次发现'));
assert.ok(itemDate({ ...enriched, date_precision: 'year', published_year: 2022 }).includes('仅知年份'));
assert.ok(preview(enriched).summaryLabel.includes('历史') || enriched.summary_status !== 'legacy');
console.log(JSON.stringify({ items: all.length, topic_paths: entries.length, old_urls: registry.legacy.length,
    current_rows: catalog.rows.length, checks: 'paths, case aliases, unique topic items, type coverage, search fields, date precision' }));
