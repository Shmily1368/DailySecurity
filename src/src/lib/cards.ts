import type { DigestItem } from './data';
import type { ItemPreview } from './view';

const base = import.meta.env.BASE_URL.replace(/\/$/, '');
function node(tag: string, text?: string, className?: string): HTMLElement {
    const el = document.createElement(tag);
    if (text) el.textContent = text;
    if (className) el.className = className;
    return el;
}
function link(label: string, url: string): HTMLElement {
    try {
        const target = new URL(url, location.href);
        if (!['http:', 'https:'].includes(target.protocol)) return node('span', label);
        const el = node('a', label) as HTMLAnchorElement;
        el.href = target.href;
        if (target.origin !== location.origin) { el.target = '_blank'; el.rel = 'noopener noreferrer'; }
        return el;
    } catch { return node('span', label); }
}
export function renderCard(row: ItemPreview): HTMLElement {
    const card = node('article', undefined, 'item-card');
    card.dataset.itemId = row.id;
    card.dataset.type = row.type;
    card.append(node('div', `${row.typeLabel} · ${row.date} · ${row.severity.toUpperCase()}`, 'item-meta'));
    const title = node('h3'); title.append(link(row.title, row.url)); card.append(title);
    if (row.cves.length) card.append(node('p', row.cves.join(' · '), 'identifiers'));
    card.append(node('p', row.summary, 'item-summary'));
    card.append(node('p', `${row.summaryLabel} · ${row.sources.join(' / ')}`, 'item-meta'));
    const footer = node('div', undefined, 'item-footer'), tags = node('div', undefined, 'item-tags');
    for (const topic of row.topics) tags.append(link('#' + topic.topic, `${base}/topics/${encodeURIComponent(topic.slug)}`));
    const button = node('button', '查看详情', 'detail-button');
    button.dataset.detail = base + row.detail; button.dataset.id = row.id;
    button.setAttribute('aria-expanded', 'false');
    footer.append(tags, button);
    const detail = node('div', undefined, 'item-detail'); detail.hidden = true;
    card.append(footer, detail);
    return card;
}

const payloads = new Map<string, Promise<DigestItem[]>>();
export function bindDetails() {
    document.addEventListener('click', async event => {
        const button = (event.target as Element)?.closest<HTMLButtonElement>('.detail-button');
        if (!button) return;
        const detail = button.closest('.item-card')!.querySelector<HTMLElement>('.item-detail')!;
        if (button.getAttribute('aria-expanded') === 'true') {
            detail.hidden = true; button.setAttribute('aria-expanded', 'false'); button.textContent = '查看详情'; return;
        }
        button.disabled = true; button.textContent = '加载中…';
        try {
            const url = button.dataset.detail!;
            if (!payloads.has(url)) payloads.set(url, fetch(url).then(response => {
                if (!response.ok) throw new Error('Payload unavailable');
                if (!response.body) throw new Error('Missing payload body');
                return new Response(response.body.pipeThrough(new DecompressionStream('gzip'))).json();
            }).catch(error => { payloads.delete(url); throw error; }));
            const item = (await payloads.get(url)!).find(item => item.id === button.dataset.id);
            if (!item) throw new Error('Item not in payload');
            detail.replaceChildren();
            detail.append(node('p', item.llm_summary?.summary_zh || item.summary || '来源未提供摘要'));
            if (item.why_it_matters) detail.append(node('p', '影响与依据：' + item.why_it_matters));
            if (item.recommended_action) detail.append(node('p', '建议：' + item.recommended_action));
            for (const advice of item.llm_summary?.defense_advice_zh ?? []) detail.append(node('p', advice));
            if (item.aliases?.length) detail.append(node('p', '关联标识：' + item.aliases.join(' · ')));
            const sources = node('p', '原始来源：'); sources.append(link(item.source_name, item.source_url)); detail.append(sources);
            for (const source of item.related_sources ?? []) {
                const p = node('p', '关联来源：'); p.append(link(source.source_name + ' · ' + source.native_id, source.source_url)); detail.append(p);
            }
            if (item.risk?.patch_status === 'available') {
                detail.append(node('p', '来源确认存在修复版本'));
                for (const url of item.risk.patch_references ?? []) { const p = node('p'); p.append(link('修复依据', url)); detail.append(p); }
            }
            for (const ref of item.risk?.exploit_references ?? []) {
                const p = node('p'); p.append(link('公开利用线索：' + (ref.label || ref.source), ref.url)); detail.append(p);
            }
            detail.hidden = false; button.setAttribute('aria-expanded', 'true'); button.textContent = '收起详情';
        } catch { button.textContent = '加载失败，点击重试'; }
        finally { button.disabled = false; }
    });
}
