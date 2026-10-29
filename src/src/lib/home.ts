import type { Catalog } from './site';
import { renderCard } from './cards';
const radar = document.querySelector<HTMLElement>('#radar')!;
const input = document.querySelector<HTMLInputElement>('#global-search')!;
const filter = document.querySelector<HTMLSelectElement>('#sub-filter')!;
const list = document.querySelector<HTMLElement>('#items-list')!;
const status = document.querySelector<HTMLElement>('#list-status')!;
const title = document.querySelector<HTMLElement>('#list-title')!;
const info = document.querySelector<HTMLElement>('#page-info')!;
const previous = document.querySelector<HTMLButtonElement>('#previous-page')!;
const next = document.querySelector<HTMLButtonElement>('#next-page')!;
let groupKey = 'top_10', query = '', searchPage = 1, revision = 0;
const selected = new Map<string, string>();
const pages = new Map<string, number>();
let catalog: Promise<Catalog> | undefined;
let searchIndex: Promise<{ id: string; text: string }[]> | undefined;
async function load<T>(url: string): Promise<T> {
    const response = await fetch(url);
    if (!response.ok) throw new Error('Data unavailable'); return response.json();
}
function getCatalog() {
    return catalog ??= load<Catalog>(radar.dataset.catalog!).catch(error => { catalog = undefined; throw error; });
}
function getSearch() {
    return searchIndex ??= load<{ id: string; text: string }[]>(radar.dataset.search!)
        .catch(error => { searchIndex = undefined; throw error; });
}
async function show() {
    const current = ++revision;
    status.textContent = '加载中…';
    previous.disabled = true; next.disabled = true;
    try {
        const data = await getCatalog();
        const group = data.groups.find(group => group.key === groupKey)!;
        let ids = group.ids;
        const key = selected.get(groupKey) ?? groupKey;
        if (query) {
            const tokens = query.normalize('NFKC').toLowerCase().split(/\s+/).filter(Boolean);
            ids = (await getSearch()).filter(row => tokens.every(token => row.text.includes(token))).map(row => row.id);
        } else if (key !== groupKey) ids = group.subgroups.find(group => group.key === key)?.ids ?? group.ids;
        if (current !== revision) return;
        const count = Math.max(1, Math.ceil(ids.length / 20));
        const page = Math.max(1, Math.min(query ? searchPage : pages.get(key) ?? 1, count));
        if (query) searchPage = page; else pages.set(key, page);
        const byId = new Map(data.rows.map(row => [row.id, row]));
        list.replaceChildren(...ids.slice((page - 1) * 20, page * 20).map(id => renderCard(byId.get(id)!)));
        title.textContent = query ? `检索结果：${query}` : group.label;
        status.textContent = ids.length ? '' : '本期暂无匹配内容。';
        info.textContent = `第 ${page} / ${count} 页 · ${ids.length} 条`;
        previous.disabled = page <= 1; next.disabled = page >= count;
        document.querySelector<HTMLElement>('#sub-filter-label')!.hidden = !!query || !group.subgroups.length;
        filter.replaceChildren();
        for (const sub of [{ key: groupKey, label: '全部', ids: group.ids }, ...group.subgroups]) {
            const option = document.createElement('option'); option.value = sub.key;
            option.textContent = `${sub.label}（${sub.ids.length}）`; filter.append(option);
        }
        filter.value = key;
    } catch {
        if (current === revision) status.textContent = '加载失败。请重试或打开本期静态归档。';
    }
}
document.querySelectorAll<HTMLButtonElement>('[data-group]').forEach(button => button.addEventListener('click', () => {
    groupKey = button.dataset.group!; query = ''; input.value = '';
    document.querySelectorAll('[data-group]').forEach(el => el.classList.toggle('active', el === button));
    void show();
}));
filter.addEventListener('change', () => { selected.set(groupKey, filter.value); void show(); });
let debounce: ReturnType<typeof setTimeout>;
input.addEventListener('input', () => {
    clearTimeout(debounce);
    query = input.value.trim(); searchPage = 1; ++revision;
    previous.disabled = true; next.disabled = true;
    debounce = setTimeout(() => void show(), 180);
});
function turn(delta: number) {
    if (delta < 0 ? previous.disabled : next.disabled) return;
    const key = selected.get(groupKey) ?? groupKey;
    if (query) searchPage = Math.max(1, searchPage + delta);
    else pages.set(key, Math.max(1, (pages.get(key) ?? 1) + delta));
    void show();
}
previous.addEventListener('click', () => turn(-1));
next.addEventListener('click', () => turn(1));

const notice = document.querySelector<HTMLElement>('#freshness-notice')!;
const today = new Intl.DateTimeFormat('sv-SE', { timeZone: 'Asia/Shanghai' }).format(new Date());
if (radar.dataset.date! < today) { notice.textContent = `当前展示 ${radar.dataset.date} 最近有效日报，今天的数据尚未发布。`; notice.hidden = false; }
async function checkFreshness() {
    try {
        const health = await load<{ version: string; date: string }>(`${import.meta.env.BASE_URL}health.json?t=${Date.now()}`);
        if (health.version !== radar.dataset.version) {
            notice.replaceChildren(document.createTextNode(`${health.date} 日报已更新。`));
            const reload = document.createElement('button'); reload.textContent = '刷新查看';
            reload.addEventListener('click', () => location.reload()); notice.append(reload); notice.hidden = false;
        }
    } catch { /* Existing verified content stays readable during a temporary network failure. */ }
}
void checkFreshness();
setInterval(() => { if (!document.hidden) void checkFreshness(); }, 120000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) void checkFreshness(); });
