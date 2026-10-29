/** Reproduce search pagination while the real home module awaits its first index. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../src/package.json', import.meta.url));
const ts = require('typescript');
class Element {
    constructor(dataset = {}) {
        Object.assign(this, { dataset, listeners: {}, children: [], disabled: false, hidden: false,
            value: '', textContent: '', classList: { toggle() {} } });
    }
    addEventListener(kind, fn) { this.listeners[kind] = fn; }
    fire(kind) { if (kind !== 'click' || !this.disabled) this.listeners[kind]?.(); }
    replaceChildren(...nodes) { this.children = nodes; }
    append(...nodes) { this.children.push(...nodes); }
}
const elements = Object.fromEntries([
    'radar', 'global-search', 'sub-filter', 'items-list', 'list-status', 'list-title',
    'page-info', 'previous-page', 'next-page', 'sub-filter-label', 'freshness-notice',
].map(id => [id, new Element()]));
elements.radar.dataset = { catalog: '/catalog', search: '/search', date: '2099-01-01', version: 'fixed' };
elements['previous-page'].disabled = elements['next-page'].disabled = true;
const buttons = ['top_10', 'vuln'].map(group => new Element({ group }));
const rows = Array.from({ length: 60 }, (_, index) => ({ id: String(index) }));
const catalog = { rows, groups: [
    { key: 'top_10', label: 'Top', ids: rows.slice(0, 10).map(row => row.id), subgroups: [] },
    { key: 'vuln', label: 'Vuln', ids: rows.map(row => row.id), subgroups: [] },
] };
let resolveSearch, debounce;
const delayedSearch = new Promise(resolve => { resolveSearch = resolve; });
const source = fs.readFileSync(new URL('../src/src/lib/home.ts', import.meta.url), 'utf8').replaceAll('import.meta.env.BASE_URL', "'/'");
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
} }).outputText, {
    document: {
        querySelector: selector => elements[selector.slice(1)], querySelectorAll: () => buttons,
        createElement: () => new Element(), createTextNode: text => ({ textContent: text }), addEventListener() {},
    }, exports: {}, require: () => ({ renderCard: row => ({ id: row.id }) }),
    fetch: async url => ({ ok: true, json: () => url === '/catalog' ? catalog : url === '/search' ? delayedSearch : { version: 'fixed' } }),
    setTimeout: fn => { debounce = fn; return 1; }, clearTimeout: () => { debounce = undefined; },
    setInterval() {}, Intl, Date,
});
const flush = async () => { for (let i = 0; i < 8; ++i) await Promise.resolve(); };
buttons[1].fire('click'); await flush();
elements['next-page'].fire('click'); await flush();
assert.match(elements['page-info'].textContent, /第 2 \/ 3 页/);
elements['global-search'].value = 'match'; elements['global-search'].fire('input');
assert.ok(elements['previous-page'].disabled && elements['next-page'].disabled, 'Disable pagination immediately');
debounce(); await flush();
elements['previous-page'].fire('click'); await flush();
resolveSearch(rows.map(row => ({ id: row.id, text: 'match' }))); await flush();
assert.match(elements['page-info'].textContent, /第 1 \/ 3 页/);
assert.equal(elements['items-list'].children.length, 20);
elements['global-search'].value = ''; elements['global-search'].fire('input'); debounce(); await flush();
assert.match(elements['page-info'].textContent, /第 2 \/ 3 页/);
assert.equal(elements['items-list'].children[0].id, '20');
console.log('Home interaction passed: delayed search, bounded pagination, clear restores page');
