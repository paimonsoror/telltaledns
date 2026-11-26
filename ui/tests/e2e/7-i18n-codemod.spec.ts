// REQ: API-012 (ADR-189) — the migration's codemod (scripts/i18n-codemod.mjs), without a browser: it
// moves text and the attributes a reader sees or hears behind `t()` with the whitespace left outside,
// writes the literal as the browser shows it, binds the file's context once, lists what it cannot
// move safely, renders the same English before and after, and leaves the languages check green.
// The fixture page is made up (tests/i18n-fixtures/codemod/Shop.svelte).
import { expect, test } from '@playwright/test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { compile } from 'svelte/compiler';
import { render } from 'svelte/server';
import * as cm from '../../scripts/i18n-codemod.mjs';
import * as lib from '../../scripts/i18n-lib.mjs';
import { tr } from '../../src/lib/i18n';
import { UI, cleanup, failRules, fails, project, put, run } from './i18n-fixture';

test.afterAll(cleanup);

const SHOP = readFileSync(join(UI, 'tests/i18n-fixtures/codemod/Shop.svelte'), 'utf8');
const temps: string[] = [];
test.afterAll(() => {
  for (const d of temps.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** The page rendered on the server, with English, as text and tags (comments out, entities read). */
async function rendered(code: string): Promise<string> {
  const js = compile(code, { generate: 'server', filename: 'Shop.svelte' }).js.code
    .replace(/from ['"](svelte(?:\/[^'"]*)?)['"]/g, (_, spec) => `from ${JSON.stringify(import.meta.resolve(spec))}`)
    .replace(/import \{ tr \} from ['"][^'"]+['"];/, 'const { tr } = globalThis.__i18aCodemod;');
  const dir = mkdtempSync(join(tmpdir(), 'tt-codemod-'));
  temps.push(dir);
  const file = join(dir, 'Shop.mjs');
  writeFileSync(file, js);
  (globalThis as { __i18aCodemod?: unknown }).__i18aCodemod = { tr };
  const mod = await import(pathToFileURL(file).href);
  const entities: Record<string, string> = { '&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"', '&#39;': "'", '&nbsp;': ' ' };
  return render(mod.default, { props: {} })
    .body.replace(/<!--[\s\S]*?-->/g, '')
    .replace(/&(?:lt|gt|amp|quot|#39|nbsp);/g, (e) => entities[e]);
}

test('api_012 the codemod moves text and attributes behind t()', () => {
  const src = `<script lang="ts">\n  import Icon from './Icon.svelte';\n  let { n = 1 } = $props();\n</script>\n\n<h2>Cached   answers<Icon name="x" /></h2>\n<p>\n  Entries are kept\n  until they expire.\n</p>\n<input placeholder="Search names" title="A &amp; B" aria-label="Find" />\n<select><optgroup label="Recent"><option>All</option></optgroup></select>\n<img alt="Chart" src="/x.png" />\n<div aria-roledescription="heatmap"></div>\n<p>&lt;none&gt;&nbsp;yet</p>\n<Icon title="Close" name="close" />\n`;
  const r = cm.transform('pages/Shop.svelte', src);
  expect(r.code).toBe(
    `<script lang="ts">\n  import Icon from './Icon.svelte';\n  import { tr } from '../lib/i18n';\n  const { t } = tr('shop');\n  let { n = 1 } = $props();\n</script>\n\n<h2>{t('Cached answers')}<Icon name="x" /></h2>\n<p>\n  {t('Entries are kept until they expire.')}\n</p>\n<input placeholder={t('Search names')} title={t('A & B')} aria-label={t('Find')} />\n<select><optgroup label={t('Recent')}><option>{t('All')}</option></optgroup></select>\n<img alt={t('Chart')} src="/x.png" />\n<div aria-roledescription={t('heatmap')}></div>\n<p>{t('<none>\\u00a0yet')}</p>\n<Icon title={t('Close')} name="close" />\n`,
  );
  expect(r.handled.map((h: { kind: string; english: string }) => `${h.kind} ${h.english}`)).toEqual([
    'text Cached answers',
    'text Entries are kept until they expire.',
    'attribute Search names',
    'attribute A & B',
    'attribute Find',
    'attribute Recent',
    'text All',
    'attribute Chart',
    'attribute heatmap',
    'text <none> yet',
    'attribute Close',
  ]);
  expect(r.listed).toEqual([]);
  expect(r.binder).toEqual({ name: 't', context: 'shop', import: '../lib/i18n' });
  // Run again: nothing more to move, and the file stays as it is.
  const again = cm.transform('pages/Shop.svelte', r.code);
  expect(again.handled).toEqual([]);
  expect(again.code).toBe(r.code);
  // No script yet: one is added. A module script stays first. The import follows the file's folder.
  expect(cm.transform('lib/components/Shop.svelte', '<p>Hello</p>\n').code).toBe("<script lang=\"ts\">\n  import { tr } from '../i18n';\n  const { t } = tr('shop');\n</script>\n\n<p>{t('Hello')}</p>\n");
  expect(cm.transform('pages/Shop.svelte', '<script module lang="ts">\n  export const X = 1;\n</script>\n\n<p>Hello</p>\n').code).toBe(
    "<script module lang=\"ts\">\n  export const X = 1;\n</script>\n\n<script lang=\"ts\">\n  import { tr } from '../lib/i18n';\n  const { t } = tr('shop');\n</script>\n\n<p>{t('Hello')}</p>\n",
  );
  // The binder never meets a `t` or `tr` the file already binds.
  const each = cm.transform('App.svelte', '<script lang="ts">\n  const tr = 1;\n</script>\n\n{#each [1] as t}<p>Row</p>{/each}\n');
  expect(each.code).toContain("import { tr as i18nTr } from './lib/i18n';\n  const { t: tx } = i18nTr('app');");
  expect(each.code).toContain("<p>{tx('Row')}</p>");
  // A script with no import gets the binder at its top.
  expect(cm.transform('pages/Shop.svelte', '<script lang="ts">\n  let n = 1;\n</script>\n\n<p>Hi</p>\n').code).toBe(
    "<script lang=\"ts\">\n  import { tr } from '../lib/i18n';\n  const { t } = tr('shop');\n\n  let n = 1;\n</script>\n\n<p>{t('Hi')}</p>\n",
  );
});

test('api_012 the codemod lists what it cannot move safely', () => {
  const src = [
    '<script lang="ts">',
    '  let n = $state(2);',
    "  const tabs = [{ id: 'a', label: 'All rows' }];",
    "  const sections = [{ name: 'Monitor' }];",
    '  const set = new Set(sections.map((s) => s.name));',
    "  const titles: Record<string, string> = { 'Rate limited': 'x' };",
    "  new Map().set('Some label', 1);",
    "  const draw = (c: CanvasRenderingContext2D) => c.fillText('Peak hour', 0, 0);",
    '  const when = new Date().toLocaleString();',
    "  const word = n === 1 ? 'entry' : 'entries';",
    '  const items = [1, 2];',
    "  const many = items.length === 1 ? 'one item' : 'some items';",
    "  if (tabs[0].label === 'All rows') n = 3;",
    "  console.log('Not shown to anyone');",
    '</script>',
    '',
    '<p>{n} rows kept</p>',
    '<p>Read the <a href="/docs">docs</a> first.</p>',
    '<p>Saved{#if n} at noon{/if}.</p>',
    '<span title="Rows: {n}">·</span>',
    '<Stat label="Queries" value={n} variant="wide" />',
    '<pre>Raw   text</pre>',
    '<textarea>Notes here</textarea>',
    '<p>Use &#123;name&#125; here</p>',
    '<p translate="no">example.com</p>',
    "<button>{n > 1 ? 'Delete all' : 'Delete'}</button>",
    '<p>{set.size} {when} {draw}{titles} {word} {many}</p>',
    '',
  ].join('\n');
  const r = cm.transform('pages/Shop.svelte', src);
  // Nothing here is moved, so the file is left as it is.
  expect(r.handled).toEqual([]);
  expect(r.code).toBe(src);
  const got = r.listed.map((l: { class: string; line: number; text: string }) => `${l.line} ${l.class} ${l.text}`);
  expect(got).toEqual([
    "3 identifier All rows",
    "4 identifier Monitor",
    "6 key Rate limited",
    "7 key Some label",
    "8 canvas c.fillText('Peak hour', 0, 0)",
    '9 intl new Date().toLocaleString()',
    "10 plural n === 1 ? 'entry' : 'entries'",
    "12 plural items.length === 1 ? 'one item' : 'some items'",
    '13 identifier All rows',
    '17 expression {n} rows kept',
    '18 inline Read the <a href="/docs">docs</a> first.',
    '19 inline Saved{#if n} at noon{/if}.',
    '20 attribute title="Rows: {n}"',
    '21 prop label="Queries"',
    '22 pre <pre>Raw text</pre>',
    '23 pre <textarea>Notes here</textarea>',
    '24 braces Use {name} here',
    "26 plural n > 1 ? 'Delete all' : 'Delete'",
  ]);
  // A plural ternary says whether the count can be negative: tn() takes "one" for -1, the ternary
  // the plural form.
  const plurals = r.listed.filter((l: { class: string }) => l.class === 'plural') as { count: string; range: string }[];
  expect(plurals.map((p) => [p.count, p.range.split(':')[0]])).toEqual([
    ['n', 'check by hand'],
    ['items.length', 'never negative (a length or size)'],
    ['n', 'check by hand'],
  ]);
  // A .ts file is listed, never edited.
  const ts = cm.transform('lib/labels.ts', "export const LABELS = { blocked: 'Blocked by a list', ok: 'ok' };\n");
  expect(ts.code).toBe("export const LABELS = { blocked: 'Blocked by a list', ok: 'ok' };\n");
  expect(ts.listed.map((l: { class: string; text: string }) => `${l.class} ${l.text}`)).toEqual(['script Blocked by a list']);
});

test('api_012 the codemod lists a sentence that elements with no text split', () => {
  // The DeviceTimeline legend: swatches (spans with no text) between the words of one sentence. The
  // words were moved one by one before (five messages, no listing); now the run is listed whole and
  // the hand writes one message for it.
  const legend =
    '<p class="muted small">Dots above: <span class="key hollow"></span> first contact, <span class="key warn"></span> anomaly, <span class="key bad"></span> blocked burst.</p>\n';
  const r = cm.transform('lib/components/Legend.svelte', legend);
  expect(r.code).toBe(legend);
  expect(r.handled).toEqual([]);
  expect(r.listed.map((l: { class: string; line: number }) => `${l.line} ${l.class}`)).toEqual(['1 split']);
  expect(r.listed[0].text.startsWith('Dots above: <span class="key hollow"></span> first contact, <span class="key warn">')).toBe(true);
  // The same for an icon component, a swatch beside an expression, and an inline image.
  const more = [
    '<p>Saved <Icon name="ok" /> at noon</p>',
    '<p>{n} <span class="dot"></span> rows</p>',
    '<p>Click <img src="/gear.svg" alt="" /> to open the settings</p>',
    '',
  ].join('\n');
  const m = cm.transform('lib/components/Legend.svelte', `<script lang="ts">\n  import Icon from './Icon.svelte';\n  let { n = 2 } = $props();\n</script>\n${more}`);
  expect(m.handled).toEqual([]);
  expect(m.listed.map((l: { class: string; line: number }) => `${l.line} ${l.class}`)).toEqual(['5 split', '6 split', '7 split']);
  // What is not a split: one label beside an icon or a swatch, a line break between two lines, a
  // block between two paragraphs, a sentence with text inside its element (listed as `inline`), and
  // text the page marks as data.
  const fine = [
    '<script lang="ts">',
    "  import Icon from './Icon.svelte';",
    '</script>',
    '<button><Icon name="x" /> Close</button>',
    '<p><span class="key"></span> blocked</p>',
    '<p>Pay now<br />or later</p>',
    '<div>First<div class="bar"></div>Second</div>',
    '<p>Read the <a href="/docs">docs</a> <span class="key"></span> first</p>',
    '<p translate="no">one <span class="key"></span> two</p>',
    '',
  ].join('\n');
  const f = cm.transform('lib/components/Legend.svelte', fine);
  expect(f.listed.map((l: { class: string; line: number }) => `${l.line} ${l.class}`)).toEqual(['8 inline']);
  expect(f.handled.map((h: { english: string }) => h.english)).toEqual(['Close', 'blocked', 'Pay now', 'or later', 'First', 'Second']);
});

test('api_012 the codemod output renders the same english', async () => {
  const r = cm.transform('pages/Shop.svelte', SHOP);
  expect(r.handled.map((h: { english: string }) => h.english)).toEqual([
    'Corner shop',
    'Fresh bread and coffee, every morning.',
    'Prices & offers <today> only',
    'Search the shelves',
    'Bread, milk…',
    'Search by name',
    'Search',
    'Aisle',
    'Food',
    'Bread',
    'Milk',
    'The shop front',
    'shelf map',
    'Open today',
    'Closed for the day',
    'Opening hours',
    'Ask at the till',
    'Pay now',
    'or later',
    'Item',
    'Price',
  ]);
  expect(r.listed.map((l: { class: string }) => l.class)).toEqual(['script', 'plural', 'inline', 'expression', 'inline', 'attribute', 'pre']);
  // The same page on the server, before and after: the same text as the browser shows it, the
  // same attributes. Svelte keeps whitespace inside a text node; the literal holds it collapsed.
  const shown = (html: string) => html.replace(/[ \t\n\r\f]+/g, ' ');
  for (const open of [true, false]) {
    const before = await rendered(SHOP.replace('open = true', `open = ${open}`));
    const after = await rendered(r.code.replace('open = true', `open = ${open}`));
    expect(before).toContain(open ? 'Open today' : 'Closed for the day');
    expect(shown(after)).toBe(shown(before));
    // Only whitespace inside text differs, where the source broke a line or lined words up.
    expect(before).toContain('<h1>Corner   shop</h1>');
    expect(after).toContain('<h1>Corner shop</h1>');
    expect(after.replace(/[ \t\n\r\f]+/g, '')).toBe(before.replace(/[ \t\n\r\f]+/g, ''));
  }
});

test('api_012 the codemod output passes the languages check', () => {
  // The fixture project with the page added, then the codemod's command on it.
  const dir = project((d) => {
    mkdirSync(join(d, 'src/pages'), { recursive: true });
    put(d, 'src/pages/Shop.svelte', SHOP);
  });
  const res = cm.run(dir, ['pages/Shop.svelte'], { write: true });
  expect(res.map((x: { file: string; handled: unknown[] }) => [x.file, x.handled.length])).toEqual([['pages/Shop.svelte', 21]]);
  const after = readFileSync(join(dir, 'src/pages/Shop.svelte'), 'utf8');
  expect(after).toContain("const { t } = tr('shop');");
  const check = run(dir);
  // Nothing fails but the literal text the codemod lists for the hand (a file the baseline does not list holds none)...
  expect(failRules(check).filter((rule) => rule !== 'literal-text')).toEqual([]);
  // ...and that is this page's, at the lines the codemod listed (the move added the import and the context: two lines;
  // a listed script string or plural is no literal text, the lint does not read it as one).
  const shop = check.files.find((f) => f.rel === 'pages/Shop.svelte') as unknown as { usesLayer: boolean; literal: number[]; messages: { ctx: string; english: string }[] };
  expect(fails(check).filter((f) => f.rule === 'literal-text').map((f) => f.file)).toEqual(['src/pages/Shop.svelte']);
  const shift = after.split('\n').length - SHOP.split('\n').length;
  expect(shift).toBe(2);
  expect([...new Set(shop.literal.map((n) => n - shift))]).toEqual(res[0].listed.filter((l: { class: string }) => !['script', 'plural'].includes(l.class)).map((l: { line: number }) => l.line));
  // Every moved text is a message of the file's context, as the check extracts it.
  expect(shop.usesLayer).toBe(true);
  expect(shop.messages.map((m) => `${m.ctx} ${m.english}`).sort()).toEqual(res[0].handled.map((h: { english: string }) => `shop ${h.english}`).sort());
  // A second run moves nothing.
  expect(cm.run(dir, ['pages/Shop.svelte'], { write: true })[0].handled).toEqual([]);
  expect(readFileSync(join(dir, 'src/pages/Shop.svelte'), 'utf8')).toBe(after);
  // Without --write nothing is written.
  const dry = project((d) => put(d, 'src/pages/Shop.svelte', SHOP));
  expect(cm.run(dry, ['pages/Shop.svelte'])[0].handled).toHaveLength(21);
  expect(readFileSync(join(dry, 'src/pages/Shop.svelte'), 'utf8')).toBe(SHOP);
});
