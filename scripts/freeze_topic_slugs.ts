/** One-time migration of the existing public topic URLs to a persistent registry. */
import fs from 'node:fs';
import path from 'node:path';
import { getAllItems, getTopicSlug } from '../src/src/lib/data';
const file = path.resolve('config/topic-slugs.json');
if (fs.existsSync(file)) throw new Error('The public URL registry must not be regenerated');
const topics = [...new Set(getAllItems().flatMap(item => [...(item.topics ?? []), ...(item.llm_summary?.tags ?? [])]))].sort();
const counts = new Map<string, number>();
const legacy = topics.map(topic => {
    const base = topic.normalize('NFKC').trim().replace(/\+/g, ' plus ').replace(/[\\/]/g, '-')
        .replace(/[^\p{Letter}\p{Number}._\-\s]/gu, '-').replace(/[\s-]+/g, '-').replace(/^[.-]+|[.-]+$/g, '') || 'topic';
    const count = (counts.get(base) ?? 0) + 1; counts.set(base, count);
    return [topic, count === 1 ? base : `${base}-${count}`];
});
const canonical = [...new Map(topics.map(topic => [topic.normalize('NFKC').trim().toLowerCase(), getTopicSlug(topic)])).entries()];
fs.writeFileSync(file, JSON.stringify({ legacy, canonical }, null, 2) + '\n');
console.log(`Frozen ${legacy.length} public aliases and ${canonical.length} canonical topic URLs`);
