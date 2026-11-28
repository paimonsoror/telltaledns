// REQ: API-012 (ADR-189), API-013 (ADR-190) — what the build's rules share with code that runs them in the
// browser, without a browser: the whole agreement rule apart from the runtime's first-use check, the shipping
// function, the template's slot in the build; and testing a language pack: the template, the check of a
// translated file, the tag, and what a page keeps in its storage. (The pages are 9-devpack.spec.ts.)
import { expect, test, type Browser, type LaunchOptions } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { cleanup, project, put, table, uiCopy, under } from './i18n-fixture';
import { cachingBrowser, resetRestored } from './bfcache';
import * as safe from '../../src/lib/i18n/safe';
import * as added from '../../src/lib/i18n/added';
import { agree } from '../../src/lib/i18n/agree';
import { hash } from '../../src/lib/i18n/ident';
import { load, tr } from '../../src/lib/i18n';
import { installFormat, makeFormat } from '../../src/lib/format';
import { parse, type Catalog } from '../../src/lib/i18n/pairs';
import { MAX_BYTES, MAX_CHARS, MAX_CONTEXTS, MAX_PAIRS, MULTI_SCRIPT, checkPack, decodeFile, markers, shownName, tagInfo, type Tag } from '../../src/lib/i18n/pack';
import { identity, ship } from '../../src/lib/i18n/shipping';
import { forPullRequest, materialize, readTemplate, writeTemplate, type Template } from '../../src/lib/i18n/template';
import { brokenWords, leftoverWords, refusalWords, tagWords, worthWords } from '../../src/lib/devpack/packWords';
import { decide, whenSeen, type Checker, type Deps } from '../../src/lib/devpack/lifecycle';
import { LIFETIME_MS, holds, keptTable, newRecord, notice, readValue, retire, rewrite, type Store } from '../../src/lib/devpack/store';
import { DEVPACK_KEY } from '../../src/lib/i18n/devpack';
import * as lib from '../../scripts/i18n-lib.mjs';
import { agree as agreeBefore } from './rule-934a9fb7/agree';
import * as safeBefore from './rule-934a9fb7/safe';

const UI = resolve(import.meta.dirname, '../..');
const I18N = join(UI, 'src/lib/i18n');
const temps: string[] = [];
test.afterAll(() => {
  cleanup();
  for (const d of temps.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** Runs postbuild on a scratch dist: `index.html` loading `assets/index-e1.js` (whose text is `entry`), the
 * files of `locales` in `assets/locales/`, and the emitted list `emitted`. Returns its status and output. */
function postbuild(entry: string, locales: Record<string, string | Buffer>, emitted: object[]) {
  const dir = mkdtempSync(join(tmpdir(), 'tt-dvp-post-'));
  temps.push(dir);
  const dist = join(dir, 'dist');
  mkdirSync(join(dist, 'assets/locales'), { recursive: true });
  writeFileSync(join(dist, 'index.html'), '<!doctype html><script type="module" crossorigin src="/assets/index-e1.js"></script>');
  writeFileSync(join(dist, 'assets/index-e1.js'), entry);
  for (const [name, body] of Object.entries(locales)) writeFileSync(join(dist, 'assets/locales', name), body);
  mkdirSync(join(dir, 'locales'));
  writeFileSync(join(dir, 'locales/manifest.json'), '{}\n');
  writeFileSync(join(dir, 'emitted.json'), JSON.stringify(emitted));
  const r = spawnSync(process.execPath, [join(UI, 'scripts/postbuild.mjs'), `${dist}/`, `${join(dir, 'locales')}/`, join(dir, 'emitted.json')], { encoding: 'utf8' });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
}

/** The modules of `src/lib/i18n/` that `from` imports, itself included, followed through their own imports. */
function importedFrom(from: string): Set<string> {
  const seen = new Set<string>();
  const visit = (f: string) => {
    if (seen.has(f)) return;
    seen.add(f);
    for (const m of readFileSync(join(I18N, f), 'utf8').matchAll(/from '\.\/([^']+)'/g)) {
      const name = /\.(svelte|json)$/.test(m[1]) ? m[1] : `${m[1].replace(/\.ts$/, '')}.ts`;
      if (existsSync(join(I18N, name)) && name.endsWith('.ts')) visit(name);
    }
  };
  visit(from);
  return seen;
}

test('api_012 the runtime check stays apart from the whole rule', () => {
  // The whole rule is a module of its own; the module the runtime imports holds the readings and the runtime's check.
  expect(Object.hasOwn(safe, 'agree')).toBe(false);
  expect(typeof safe.agreesAtRuntime).toBe('function');
  expect(agree('Keep {n}', 'Qa').fails.map((f) => `${f.rule} ${f.token}`)).toEqual(['placeholders {n}']);
  // No module the runtime loads imports it, so the first load of a page never carries it; nor the digit and
  // added-token rules, which only a catalog the build did not ship needs (it brings them).
  const runtime = importedFrom('index.ts');
  expect(runtime.has('safe.ts')).toBe(true);
  expect([...runtime]).not.toContain('agree.ts');
  expect([...runtime]).not.toContain('added.ts');
});

test('api_012 a catalog the build did not ship is shown only with the rules its code brings', async () => {
  // The code that brings such a catalog (a test pack's boot) gives the runtime the digit and added-token rules, so an
  // English reader's first load does not carry them. Without them nothing of such a catalog is shown, not even a
  // translation that agrees: the conservative direction (review part B of T29.3, finding 3).
  const t = table({ [hash('c', 'Holds')]: 'Qa-holds', [hash('c', 'Wait 7 days')]: 'Qa-wait a week' });
  under({ tag: 'qaa', table: t, extra: undefined }, () => {
    expect(tr('c').t('Holds')).toBe('Holds');
    expect(tr('c').t('Wait 7 days')).toBe('Wait 7 days');
  });
  under({ tag: 'qaa', table: t, extra: added.extraAgrees }, () => {
    expect(tr('c').t('Holds')).toBe('Qa-holds');
    expect(tr('c').t('Wait 7 days')).toBe('Wait 7 days');
  });
  // A catalog the build shipped was held to them by the check: the runtime leaves them out.
  under({ tag: 'qaa', table: t, built: true }, () => expect(tr('c').t('Wait 7 days')).toBe('Qa-wait a week'));
  expect(safe.agreesAtRuntime('Holds', 'Qa-holds')).toBe(false);
  expect(safe.agreesAtRuntime('Holds', 'Qa-holds', 'ltr', { extra: added.extraAgrees })).toBe(true);
  // A page load's choice of a pack carries them (the differential test compares them with the old rule).
  expect((await decide(JSON.stringify(REC), deps())).choice?.extra).toBe(added.extraAgrees);
});

test('api_012 the build admits one template on its own line and the entry holds its name', () => {
  const name = 'template-1a2b3c4d.json';
  const listed = [{ file: name, template: true }];
  const holds = `const T = "/assets/locales/${name}";`;
  // One template, listed, named by the entry chunk: its own line, outside the UI and the languages.
  const ok = postbuild(holds, { [name]: JSON.stringify({ v: 1, contexts: {} }) }, listed);
  expect(ok.out).toMatch(/^template [\d.]+ KiB gzipped \(budget 64\.0 KiB\): assets\/locales\/template-1a2b3c4d\.json, outside the UI and the languages$/m);
  expect(ok.out).toContain('all languages 0.0 KiB gzipped');
  expect(ok.out).toContain('each language at most 80.0 KiB gzipped: 0 file(s) in assets/locales/');
  expect(ok.status, ok.out).toBe(0);
  // The entry chunk does not hold its name: the build's name would not follow the English.
  const unnamed = postbuild('const T = "elsewhere";', { [name]: '{}' }, listed);
  expect(unnamed.status).toBe(1);
  expect(unnamed.out).toContain("the entry chunk does not hold the template's file name (template-1a2b3c4d.json)");
  // Over its budget (incompressible bytes), not listed, listed twice, or listed and missing.
  const big = postbuild(holds, { [name]: randomBytes(70 * 1024) }, listed);
  expect(big.status).toBe(1);
  expect(big.out).toContain('over the 64 KiB the template may take');
  const stray = postbuild(holds, { [name]: '{}' }, []);
  expect(stray.status).toBe(1);
  expect(stray.out).toContain('holds the files the i18n prebuild step emitted');
  const two = postbuild(`${holds} "template-99999999.json"`, { [name]: '{}', 'template-99999999.json': '{}' }, [...listed, { file: 'template-99999999.json', template: true }]);
  expect(two.status).toBe(1);
  expect(two.out).toContain('lists more than one template');
  const gone = postbuild(holds, {}, listed);
  expect(gone.status).toBe(1);
  expect(gone.out).toContain('no file for the template template-1a2b3c4d.json');
  // The URL table has room for the template's address, null until the build writes one.
  const dir = project();
  expect(lib.prebuild(dir)).toBe(1);
  expect(readFileSync(join(dir, 'src/lib/i18n/locales.gen.ts'), 'utf8')).toMatch(/^export const TEMPLATE: string \| null = (null|"\/assets\/locales\/template-[0-9a-f]{8}\.json");$/m);
});

test('api_012 the shipping function is shared and its findings name their pair', () => {
  // The check script ships with the module code in the browser imports.
  expect(lib.ship).toBe(ship);
  const plural = ['{n} file', '{n} files'] as [string, string];
  const entries = new Map([
    [identity('c', plural), { ctx: 'c', english: plural }],
    [identity('c', 'Keep {n}'), { ctx: 'c', english: 'Keep {n}' }],
    [identity('c', 'Open', 'verb'), { ctx: 'c', english: 'Open', note: 'verb' }],
  ]);
  const s = ship({ c: [[plural, { one: 'Qa', other: 'Qa' }], ['Keep {n}', 'Qa'], ['Keep  {n}', 'Qb'], ['Open', 'Qa-open', 'verb'], ['Gone', 'Qa']] }, entries);
  // A plural's form is held to the English of its category; the finding names the pair it came from.
  const fails = s.findings.filter((f) => f.level === 'fail');
  expect(fails.map((f) => [f.rule, f.check ?? '', f.english, JSON.stringify(f.pair), f.note ?? ''])).toEqual([
    ['agreement', 'placeholders', '{n} files', JSON.stringify(plural), ''],
    ['agreement', 'placeholders', 'Keep {n}', '"Keep {n}"', ''],
    ['malformed', '', 'Keep  {n}', '"Keep  {n}"', ''],
  ]);
  expect(s.findings.find((f) => f.level === 'report' && f.token === 'Qa-open')).toMatchObject({ rule: 'agreement-added', check: 'added', pair: 'Open', note: 'verb' });
  expect(Object.values(s.table)).toEqual(['Qa-open']);
  expect([...s.translated]).toEqual([identity('c', 'Open', 'verb')]);
  expect(s.leftovers).toEqual([{ ctx: 'c', english: 'Gone', note: undefined }]);
});

// ---------------------------------------------------------------------------------------------
// API-013: the template

const PLURALS = JSON.parse(readFileSync(join(UI, 'src/locales/plurals.json'), 'utf8')) as Record<string, string[]>;
const code = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** The template of the tree `dir`, as the build writes it. */
function templateOf(dir: string): { json: string; tpl: Template } {
  const json = lib.templateJson(lib.check(dir, { ratchets: false }));
  return { json, tpl: readTemplate(json) };
}
/** `sync <tag>` on `dir`, and the file it wrote. */
function synced(dir: string, tag: string): string {
  lib.sync(dir, tag);
  return readFileSync(join(dir, `src/locales/${tag}.json`), 'utf8');
}
let uiTpl: { dir: string; json: string; tpl: Template } | null = null;
/** A copy of the UI's sources with its template (once per worker). */
function uiTemplate() {
  if (!uiTpl) {
    const dir = uiCopy();
    uiTpl = { dir, ...templateOf(dir) };
  }
  return uiTpl;
}

test('api_013 the template equals what sync writes for a new language', () => {
  const { dir, json, tpl } = uiTemplate();
  // Every message of this build, once.
  expect(tpl.entries.size).toBe(lib.check(dir, { ratchets: false }).entries.size);
  expect(tpl.entries.size).toBeGreaterThan(2000);
  for (const tag of ['de', 'fr', 'ru', 'zh-Hans']) {
    rmSync(join(dir, `src/locales/${tag}.json`), { force: true });
    expect(materialize(tpl, PLURALS[new Intl.Locale(tag).language]), tag).toBe(synced(dir, tag));
  }
  // The same tree gives the same bytes.
  expect(templateOf(dir).json).toBe(json);
  // The notes, sensitive marks, verbatim words, glossary and plural table go with it (the fixture has each).
  const f = templateOf(project()).tpl;
  expect(f.entries.get(identity('cache', 'Holds'))?.info).toEqual({ sensitive: true, text: 'A cache entry count' });
  expect(f.entries.get(identity('cache', 'Choose email or ntfy'))?.verbatim).toEqual(['email', 'ntfy']);
  expect(f.glossary).toEqual(['NXDOMAIN']);
  expect([...f.plurals]).toEqual([['qaa', ['other']]]);
  expect(f.contexts).toEqual([...f.contexts].sort(code));
});

test('api_013 prebuild writes the template the url table names', () => {
  const dir = project();
  lib.prebuild(dir);
  const json = lib.templateJson(lib.check(dir, { ratchets: false }));
  const name = `template-${createHash('sha256').update(json).digest('hex').slice(0, 8)}.json`;
  expect(readFileSync(join(dir, 'public/assets/locales', name), 'utf8')).toBe(json);
  expect(readFileSync(join(dir, 'src/lib/i18n/locales.gen.ts'), 'utf8')).toContain(`export const TEMPLATE: string | null = "/assets/locales/${name}";`);
  expect(JSON.parse(readFileSync(join(dir, 'src/lib/i18n/emitted.gen.json'), 'utf8'))).toContainEqual({ file: name, template: true });
});

test('api_013 plural categories come from the committed table not the engine', () => {
  const { dir, tpl } = uiTemplate();
  const real = Intl.PluralRules;
  let written = '';
  let fromSync = '';
  (Intl as { PluralRules: unknown }).PluralRules = function () {
    throw new Error('the engine was asked for plural rules');
  };
  try {
    rmSync(join(dir, 'src/locales/fr.json'), { force: true });
    written = materialize(tpl, tpl.plurals.get('fr') ?? []);
    fromSync = synced(dir, 'fr');
    templateOf(dir);
  } finally {
    (Intl as { PluralRules: unknown }).PluralRules = real;
  }
  expect(written).toBe(fromSync);
  // French has one, many and other in the committed table: a plural's text has those three.
  expect(tpl.plurals.get('fr')).toEqual(['one', 'many', 'other']);
  const plural = Object.values(parse(written) as Catalog).flat().find((p) => Array.isArray(p[0]));
  expect(Object.keys(plural?.[1] as object)).toEqual(['one', 'many', 'other']);
  // The template carries the committed table itself.
  expect(Object.fromEntries(tpl.plurals)).toEqual(PLURALS);
});

test('api_013 the browser and the script write the same canonical bytes', () => {
  const { dir, tpl } = uiTemplate();
  const cats = tpl.plurals.get('de') ?? [];
  const good = materialize(tpl, cats);
  const cat = parse(good) as Catalog;
  const reversed = Object.fromEntries(Object.entries(cat).reverse().map(([k, v]) => [k, [...v].reverse()]));
  const inputs: Record<string, string> = {
    'shuffled, hand-spaced': JSON.stringify(reversed, null, 3),
    'tabs': JSON.stringify(reversed, null, '\t'),
    'CRLF': good.replace(/\n/g, '\r\n'),
    'one line': JSON.stringify(cat),
  };
  for (const [what, text] of Object.entries(inputs)) {
    put(dir, 'src/locales/de.json', text);
    const fromScript = synced(dir, 'de');
    expect(fromScript, what).toBe(good);
    expect(forPullRequest(parse(text) as Catalog, tpl, cats), what).toBe(fromScript);
  }
  // A byte-order mark: the browser's decoder reads past it, the script refuses the file (as the check does).
  put(dir, 'src/locales/de.json', `\uFEFF${good}`);
  expect(() => lib.sync(dir, 'de')).toThrow();
  expect(forPullRequest(parse(new TextDecoder('utf-8', { fatal: true }).decode(new TextEncoder().encode(`\uFEFF${good}`))) as Catalog, tpl, cats)).toBe(good);
  // The order is by code unit: some context of the UI sorts otherwise under a collator, and the bytes keep code-unit order.
  const differs = Object.values(cat).some((pairs) => {
    const e = pairs.map((p) => JSON.stringify(p[0]));
    return [...e].sort(code).join('\n') !== [...e].sort((a, b) => a.localeCompare(b)).join('\n') && e.join('\n') === [...e].sort(code).join('\n');
  });
  expect(differs, 'a context whose code-unit order is not its collator order').toBe(true);
});

test('api_013 download for a pull request is what sync writes for that file', () => {
  const { dir, tpl } = uiTemplate();
  const cats = tpl.plurals.get('ru') ?? [];
  const all = [...tpl.entries.values()];
  const one = all.find((e) => typeof e.english === 'string' && !e.note);
  const plural = all.find((e) => Array.isArray(e.english));
  if (!one || !plural) throw new Error('the UI has a message and a plural');
  const pack: Catalog = Object.create(null);
  const add = (ctx: string, p: Catalog[string][number]) => (pack[ctx] ??= []).push(p);
  add(one.ctx, [one.english, 'Перевод']);
  add(one.ctx, ['An English this build does not have', 'Старый']);
  // Russian has one, few, many and other: this plural names two of them, and one the language does not have.
  add(plural.ctx, [plural.english, { one: 'один', other: 'много', two: 'два' }]);
  pack['~leftover'] = [['Older English', 'Старое']];
  const text = JSON.stringify(pack, null, 1);
  put(dir, 'src/locales/ru.json', text);
  const fromScript = synced(dir, 'ru');
  expect(forPullRequest(parse(text) as Catalog, tpl, cats)).toBe(fromScript);
  // Translations kept, the missing added empty, left-over pairs moved aside and never pruned.
  const pr = parse(fromScript) as Catalog;
  expect(pr[one.ctx]).toContainEqual([one.english, 'Перевод']);
  expect(pr[plural.ctx]).toContainEqual([plural.english, { one: 'один', few: '', many: '', other: 'много' }]);
  expect(pr['~leftover']).toEqual([['An English this build does not have', 'Старый'], ['Older English', 'Старое']]);
  expect(Object.values(pr).flat().length).toBe(tpl.entries.size + 2);
});

test('api_013 download for a pull request keeps the first of two pairs with one identity', () => {
  // As the build ships it and the card says ("only the first is used"): the first pair of an identity is kept, and a
  // later one is set aside under ~leftover, never dropped. `sync` does the same (review part B of T29.3, finding 1).
  const { dir, tpl } = uiTemplate();
  const fr: Tag = { tag: 'fr', language: 'fr', dir: 'ltr', categories: tpl.plurals.get('fr') ?? [] };
  // A translator pasted the template's empty pair under their own line.
  const text = JSON.stringify({ settings: [['Settings', 'Réglages'], ['Settings', '']] }, null, 2);
  put(dir, 'src/locales/fr.json', text);
  const fromScript = synced(dir, 'fr');
  expect(forPullRequest(parse(text) as Catalog, tpl, fr.categories)).toBe(fromScript);
  const pr = parse(fromScript) as Catalog;
  expect(pr.settings).toContainEqual(['Settings', 'Réglages']);
  expect(pr.settings).not.toContainEqual(['Settings', '']);
  expect(pr['~leftover']).toEqual([['Settings', '']]);
  // The check ships the same first pair, and names the second.
  const c = checkPack(text, false, tpl, fr);
  expect(c.checked?.table[hash('settings', 'Settings')]).toBe('Réglages');
  expect(c.checked?.broken).toContainEqual(expect.objectContaining({ ctx: 'settings', english: 'Settings', rule: 'twice' }));
});

// ---------------------------------------------------------------------------------------------
// API-013: checking a pack

const DE: Tag = { tag: 'de', language: 'de', dir: 'ltr', categories: ['one', 'other'] };
let fx: Template | null = null;
/** The fixture project's template: 9 messages in cache, common and labels (tests/i18n-fixtures/project). */
const fixture = () => (fx ??= templateOf(project()).tpl);
/** A template of these messages alone. */
const tplOf = (entries: { ctx: string; english: string | [string, string]; note?: string }[]) =>
  readTemplate(writeTemplate(entries, { notes: new Map(), verbatim: new Map(), glossary: [], plurals: { de: ['one', 'other'] } }));
/** The check of `pack` (an object, written as JSON) for German, against the fixture's template or `tpl`. */
function checked(pack: object, tpl = fixture()) {
  const r = checkPack(JSON.stringify(pack, null, 2), false, tpl, DE);
  if (r.refused) throw new Error(`refused: ${JSON.stringify(r.refused)}`);
  return r.checked;
}
const refusal = (text: string) => checkPack(text, false, fixture(), DE).refused;

test('api_013 a pack is refused whole for its structure', () => {
  expect(refusal(JSON.stringify({ cache: [['Holds', 'Hält']] }))).toBeUndefined();
  const cases: [string, object][] = [
    // A key twice, at the top level and inside a plural: the second would hide the first.
    ['{"cache": [["Holds", "x"]], "cache": []}', { code: 'duplicate', key: 'cache', line: 1 }],
    ['{"cache": [[["{n} answer", "{n} answers"], {"one": "a", "one": "b"}]]}', { code: 'duplicate', key: 'one', line: 1 }],
    ['{\n  "cache": [\n    ["Holds", "x"],\n  ]\n}', { code: 'json', line: 4, column: 3 }],
    ['{"cache": [["Holds", "x"]]', { code: 'json' }],
    ['{"cache": [[["a", ["b"]], "x"]]}', { code: 'depth' }],
    ['[]', { code: 'shape' }],
    ['{"cache": {}}', { code: 'shape' }],
    [JSON.stringify({ [hash('cache', 'Holds')]: 'Hält' }), { code: 'shape' }],
    ['{"Cache": [["Holds", "x"]]}', { code: 'context', ctx: 'Cache' }],
    ['{"__proto__": [["Holds", "x"]]}', { code: 'context', ctx: '__proto__' }],
    ['{"cache": [["Holds"]]}', { code: 'pair', ctx: 'cache', n: 1, shape: 'pair' }],
    ['{"cache": [["Holds", "x"], ["Holds", 3]]}', { code: 'pair', ctx: 'cache', n: 2, shape: 'text' }],
    ['{"cache": [[["{n} answer", "{n} answers"], "x"]]}', { code: 'pair', ctx: 'cache', n: 1, shape: 'plural-text' }],
    [JSON.stringify({ cache: [['Holds', 'x'.repeat(4001)]] }), { code: 'long', ctx: 'cache', n: 1 }],
    [JSON.stringify({ cache: Array.from({ length: 10_001 }, (_, i) => [`E${i}`, '']) }), { code: 'pairs' }],
    [JSON.stringify(Object.fromEntries(Array.from({ length: 601 }, (_, i) => [`c${i}`, []]))), { code: 'contexts' }],
    ['x'.repeat(MAX_BYTES + 1), { code: 'size' }],
  ];
  for (const [text, want] of cases) {
    const r = refusal(text);
    expect(r, text.slice(0, 60)).toMatchObject(want);
    // In plain words, and nothing was kept: the check stores nothing itself.
    expect(refusalWords(r!)).toMatch(/^This file can't be used: /);
  }
  expect(refusalWords({ code: 'duplicate', key: 'cache', line: 1, column: 29 })).toBe('This file can\'t be used: the key "cache" appears twice (line 1, column 29); the second would hide the first.');
  expect(refusalWords({ code: 'json', line: 41, column: 7 })).toBe("This file can't be used: it isn't valid JSON (line 41, column 7).");
  // The limits are the check's own: each one is its message's count and {max}, the number written as English does.
  expect(refusalWords({ code: 'contexts' })).toContain(`more than ${MAX_CONTEXTS.toLocaleString('en-US')} contexts`);
  expect(refusalWords({ code: 'pairs' })).toContain(`more than ${MAX_PAIRS.toLocaleString('en-US')} pairs`);
  expect(refusalWords({ code: 'long', ctx: 'cache', n: 1 })).toContain(`longer than ${MAX_CHARS.toLocaleString('en-US')} characters`);
  expect(refusalWords({ code: 'size' })).toContain(`larger than ${MAX_BYTES / 1024 / 1024} MiB`);
  // Strict UTF-8; a byte-order mark is read past (and noted: the file is not in the repository's form).
  expect(decodeFile(new Uint8Array([0x7b, 0xff, 0x7d]))).toBeNull();
  expect(decodeFile(new TextEncoder().encode('\uFEFF{}'))).toEqual({ text: '{}', bom: true });
  const bom = checkPack(JSON.stringify({ cache: [['Holds', 'Hält']] }), true, fixture(), DE);
  expect(bom.checked?.canonical).toBe(false);
});

test('api_013 the count of texts that break a rule counts each pair once', () => {
  // The card's "{n} text breaks a rule" and the list's heading count texts (pairs); the list shows every finding. One
  // pair with a changed placeholder and a translated web address is one text with several findings.
  const tpl = tplOf([
    { ctx: 'cache', english: 'Open {name} at https://example.org/help' },
    { ctx: 'cache', english: 'Holds {n}' },
    { ctx: 'cache', english: 'Holds' },
  ]);
  const one = checked({ cache: [['Open {name} at https://example.org/help', 'Öffne {nom} unter https://beispiel.org/hilfe']] }, tpl);
  expect(one.broken.map((b) => b.rule)).toEqual(expect.arrayContaining(['placeholders', 'urls']));
  expect(one.broken.length).toBeGreaterThanOrEqual(2);
  expect(one.brokenTexts).toBe(1);
  // Another pair that breaks a rule is a second text; a pair that agrees is none.
  const two = checked({ cache: [['Open {name} at https://example.org/help', 'Öffne {nom} unter https://beispiel.org/hilfe'], ['Holds {n}', 'Hält'], ['Holds', 'Hält']] }, tpl);
  expect(two.brokenTexts).toBe(2);
  expect(two.broken.length).toBe(one.broken.length + 1);
});

test('api_013 the first of two plurals with one identity decides, whatever its categories', () => {
  // A corrected plural pasted after the old one: the first pair decides for the page as it does for Download for a
  // pull request and `sync` (round 4), and the card says the second is there twice. French uses one, many and other.
  const FR_TAG: Tag = { tag: 'fr', language: 'fr', dir: 'ltr', categories: ['one', 'many', 'other'] };
  const P: [string, string] = ['{n} entry', '{n} entries'];
  const tpl = tplOf([{ ctx: 'cache', english: P }]);
  const old = { one: '{n} entrée', other: '{n} entrées' };
  const fixed = { one: '{n} entrée', many: '{n} d’entrées', other: '{n} entrées' };
  const check = (pairs: unknown[]) => {
    const r = checkPack(JSON.stringify({ cache: pairs }, null, 2), false, tpl, FR_TAG);
    if (r.refused) throw new Error(`refused: ${JSON.stringify(r.refused)}`);
    return r.checked;
  };
  // The old one first: English is shown, the old pair is kept for the pull request, the corrected one set aside.
  const a = check([[P, old], [P, fixed]]);
  expect(a.broken.map((b) => b.rule)).toEqual(['categories', 'twice']);
  expect(a.brokenTexts).toBe(2);
  expect(Object.keys(a.table)).toEqual([]);
  const prA = JSON.parse(a.pr) as Record<string, [unknown, Record<string, string>][]>;
  expect(prA.cache[0][1].one).toBe(old.one);
  expect(prA['~leftover']).toEqual([[P, fixed]]);
  // The corrected one first: it is shown and kept, and the old one is there twice.
  const b = check([[P, fixed], [P, old]]);
  expect(b.broken.map((x) => x.rule)).toEqual(['twice']);
  expect(b.brokenTexts).toBe(1);
  expect(Object.values(b.table)).toEqual([fixed]);
  const prB = JSON.parse(b.pr) as Record<string, [unknown, Record<string, string>][]>;
  expect(prB.cache[0][1]).toEqual(fixed);
  expect(prB['~leftover']).toEqual([[P, old]]);
});

test('api_013 a limit of the check reads as the language writes numbers', () => {
  // The limits of a file are each message's count and {max}, the number formatted for the language: a translator
  // writes the noun in the form that number takes and copies no digit. A German file that keeps {max} passes the
  // check and the runtime, and reads 4.000 Zeichen and 10.000 Paare. With the numbers written in the English, a
  // German 4000 Zeichen or 10000 Paare failed the digit rule (which reads 4,000 as 4 and 000).
  const limits = [...(lib.check(UI, { ratchets: false }).entries as Map<string, { ctx: string; english: string | [string, string]; note?: string }>).values()].filter(
    (e) => e.ctx === 'packWords' && Array.isArray(e.english) && e.english[1].includes('{max}'),
  );
  expect(limits.map((e) => e.english[1])).toEqual([
    "This file can't be used: it has more than {max} contexts.",
    "This file can't be used: it has more than {max} pairs.",
    'This file can\'t be used: pair {n} of "{ctx}" has a text longer than {max} characters.',
  ]);
  const de = [
    { one: 'Diese Datei ist nicht verwendbar: Sie hat mehr als {max} Kontext.', other: 'Diese Datei ist nicht verwendbar: Sie hat mehr als {max} Kontexte.' },
    { one: 'Diese Datei ist nicht verwendbar: Sie hat mehr als {max} Paar.', other: 'Diese Datei ist nicht verwendbar: Sie hat mehr als {max} Paare.' },
    {
      one: 'Diese Datei ist nicht verwendbar: Paar {n} von "{ctx}" hat einen Text, der länger als {max} Zeichen ist.',
      other: 'Diese Datei ist nicht verwendbar: Paar {n} von "{ctx}" hat einen Text, der länger als {max} Zeichen ist.',
    },
  ];
  const c = checked({ packWords: limits.map((e, i) => [e.english, de[i]]) }, tplOf(limits));
  expect(c.broken).toEqual([]);
  expect(Object.keys(c.table)).toHaveLength(3);
  try {
    under({ tag: 'de', table: c.table as never, formatLocale: 'de-DE' }, () => {
      // The formats follow the page's language, as main.ts installs them before the app is drawn.
      installFormat(makeFormat('de-DE', (ctx) => tr(ctx as never)));
      expect(refusalWords({ code: 'contexts' })).toBe('Diese Datei ist nicht verwendbar: Sie hat mehr als 600 Kontexte.');
      expect(refusalWords({ code: 'pairs' })).toBe('Diese Datei ist nicht verwendbar: Sie hat mehr als 10.000 Paare.');
      expect(refusalWords({ code: 'long', ctx: 'cache', n: 2 })).toBe('Diese Datei ist nicht verwendbar: Paar 2 von "cache" hat einen Text, der länger als 4.000 Zeichen ist.');
    });
  } finally {
    // English again, made once English is installed (a format reads whether the text is English when it is made),
    // so later tests of this worker see the formats as before.
    installFormat(makeFormat(undefined, (ctx) => tr(ctx as never)));
  }
  expect(refusalWords({ code: 'pairs' })).toBe(`This file can't be used: it has more than ${MAX_PAIRS.toLocaleString('en-US')} pairs.`);
  // A translator who types the number in place of {max} is told to keep it, whatever way the number is written.
  const typed = checked({ packWords: [[limits[1].english, { one: de[1].one, other: 'Diese Datei ist nicht verwendbar: Sie hat mehr als 10000 Paare.' }]] }, tplOf(limits));
  expect(typed.broken.some((b) => b.rule === 'placeholders' && b.token === '{max}'), JSON.stringify(typed.broken)).toBe(true);
});

test('api_012 a surrogate that is not half of a pair is a forbidden code point', () => {
  // It draws as U+FFFD (review part A of T29.3, nit 10): the check fails it, the runtime shows the English instead,
  // the check screen marks it, and a file's shown name drops it. A pair (one code point) and U+2800 stay allowed.
  expect(safe.forbidden('a\uD800b')).toEqual([{ cp: 'U+D800', at: 1 }]);
  expect(safe.forbidden('a\uDC00')).toEqual([{ cp: 'U+DC00', at: 1 }]);
  expect(safe.forbidden('a\u{1F600}b\u{2800}')).toEqual([]);
  expect(agree('Keep', 'Qa\uD800').fails.map((f) => `${f.rule} ${f.token}`)).toEqual(['code-point U+D800']);
  expect(safe.agreesAtRuntime('Keep', 'Qa\uD800', 'ltr', { extra: added.extraAgrees })).toBe(false);
  expect(safe.agreesAtRuntime('Keep', 'Qa\u{1F600}', 'ltr', { extra: added.extraAgrees })).toBe(true);
  expect(markers('a\uD800b')).toBe('a⟨U+D800⟩b');
  expect(shownName('de\uD800.json')).toBe('de.json');
  expect(checked({ cache: [['Holds', 'Hält\uDFFF']] }).broken.map((b) => `${b.rule} ${b.token}`)).toEqual(['code-point U+DFFF']);
});

test('api_013 pack text in a reason line is marked and limited', () => {
  // A plural form's key is the file's text too (review part A of T29.3, nit 10): longer than a string may be, the
  // file is refused whole, as for a value; a direction override in it shows as a marker in the reason line.
  const plural = ['{n} answer', '{n} answers'];
  expect(refusal(JSON.stringify({ cache: [[plural, { one: 'a', ['o'.repeat(4001)]: 'b', other: 'c' }]] }))).toMatchObject({ code: 'long', ctx: 'cache', n: 1 });
  expect(refusal(JSON.stringify({ cache: [[plural, { one: 'a', ['o'.repeat(4000)]: 'b', other: 'c' }]] }))).toBeUndefined();
  const words = brokenWords({ ctx: 'cache', english: plural as [string, string], rule: 'categories', got: ['one', '\u202Eother'], want: ['one', 'other'] });
  expect(words).toContain('one, ⟨U+202E⟩other');
  expect(words).not.toContain('\u202E');
});

test('api_013 a pack entry that breaks the agreement rule is dropped and named in plain words', () => {
  const c = checked({
    cache: [
      ['Holds', 'Hält'],
      ['Notify by {kind}', 'Benachrichtigen'],
      ['Read https://example.com/docs first.', 'Lies https://evil.example/docs zuerst.'],
      ['Sends mail to smtp://mail.example:587', 'Sendet Mail an smtp://mail.example'],
      ['Choose email or ntfy', 'Wähle E-Mail oder ntfy'],
      ['Kept by <b>{who}</b>', 'Von {who} behalten\u202E'],
    ],
    common: [['Save', 'Sаve']],
  });
  // Only what agrees is in the table; the rest shows English.
  expect(Object.values(c.table)).toEqual(['Hält']);
  expect(c.translated).toBe(1);
  const words = c.broken.map(brokenWords);
  for (const w of [
    'Keep {kind} exactly as it is: it is replaced by a value.',
    'Keep the web address exactly as in the English: https://example.com/docs',
    "This web address isn't in the English: https://evil.example/docs",
    'Keep smtp://mail.example:587 as written.',
    'Keep the number 587.',
    'Keep email untranslated: it is a value people type.',
    'Keep the tag <b> exactly as in the English.',
    "Remove the character U+202E: it is invisible, changes the direction, or can't be shown.",
    'A word mixes Latin letters with Cyrillic or Greek ones that look alike: Sаve',
  ])
    expect(words).toContain(w);
  // Each names its entry and the translation it judged.
  expect(c.broken.find((b) => b.rule === 'code-point')).toMatchObject({ ctx: 'cache', english: 'Kept by <b>{who}</b>', translation: 'Von {who} behalten\u202E', token: 'U+202E' });
  // An entry is not also "missing" when it was dropped.
  expect(c.missing.map((m) => m.english)).toEqual([['{n} answer', '{n} answers'], 'Lists']);
  // Plural categories other than the language's: that entry is dropped, the rest stands.
  const p = checked({ cache: [[['{n} answer', '{n} answers'], { other: '{n} Antworten' }], ['Holds', 'Hält']] });
  expect(p.broken.map(brokenWords)).toEqual(['This language uses one, other; this entry has other.']);
  expect(Object.values(p.table)).toEqual(['Hält']);
});

test('api_013 report-only findings never drop an entry', () => {
  const tpl = tplOf([{ ctx: 'c', english: 'Use the sign-in page' }, { ctx: 'c', english: 'Open the DNS log' }]);
  const c = checked({ c: [['Use the sign-in page', 'Nutze die Anmeldeseite'], ['Open the DNS log', 'Öffne das Protokoll']] }, tpl);
  expect(c.translated).toBe(2);
  expect(c.broken).toEqual([]);
  const words = c.worth.map(worthWords);
  expect(words).toContain('Worth a look: sign-in is not in the translation. Fine if it is an ordinary word.');
  expect(words).toContain('Worth a look: DNS is not in the translation. Keep it if it is a name or an abbreviation.');
  expect(words).toContain('Worth a look: the translation adds Nutze.');
});

test('api_013 a pack pair is current by text never by hash', () => {
  const tpl = tplOf([{ ctx: 'c', english: "Don't stop" }, { ctx: 'c', english: 'Open', note: 'verb' }]);
  // The same text once normalized (a typographic apostrophe, more spaces) is the same message, under its hash.
  const a = checked({ c: [['Don’t   stop', 'Nicht anhalten'], ['Open', 'Öffnen', 'verb']] }, tpl);
  expect(Object.keys(a.table).sort()).toEqual([hash('c', "Don't stop"), hash('c', 'Open', 'verb')].sort());
  // Another note is another message, whatever else it shares.
  const b = checked({ c: [['Open', 'Öffnen', 'adjective']] }, tpl);
  expect(b.translated).toBe(0);
  expect(b.leftovers.map((l) => l.reason)).toEqual(['note']);
  // A file of hashes (what the build ships) is not a pack, and a context named like a hash is no message's.
  expect(checkPack(JSON.stringify({ [hash('c', 'Open', 'verb')]: 'Öffnen' }), false, tpl, DE).refused).toEqual({ code: 'shape' });
  const named = checkPack(JSON.stringify({ [hash('c', 'Open', 'verb')]: [['Open', 'Öffnen', 'verb']] }), false, tpl, DE);
  expect(named.refused?.code === 'context' || named.checked?.translated === 0).toBe(true);
});

test('api_013 a left-over pair says why', () => {
  const c = checked({ cache: [['Holds', 'Hält', 'my own note'], ['Holds now', 'Hält jetzt']], '~leftover': [['Older', 'Älter']] });
  expect(c.leftovers.map((l) => [l.ctx, l.english, l.reason, leftoverWords(l)])).toEqual([
    ['cache', 'Holds', 'note', 'Same English, different note: keep the third item as in the template.'],
    ['cache', 'Holds now', 'gone', "This English isn't in this build: it changed, or it was edited in the file."],
    ['~leftover', 'Older', 'aside', 'Set aside under "~leftover": it is kept there and not used.'],
  ]);
  expect(c.missing).toContainEqual({ ctx: 'cache', english: 'Holds', note: undefined });
  expect(c.translated).toBe(0);
});

test('api_013 pack entries named like object members are data', () => {
  const words = ['constructor', 'toString', 'hasOwnProperty', 'valueOf'];
  const tpl = tplOf([...words.map((w) => ({ ctx: w, english: w })), { ctx: 'c', english: '__proto__' }, { ctx: 'c', english: ['{n} toString', '{n} valueOf'] }]);
  const pack = `{${words.map((w, i) => `"${w}": [["${w}", "${words[(i + 1) % words.length]}"]]`).join(', ')}, "c": [["__proto__", "__proto__ x"], [["{n} toString", "{n} valueOf"], {"__proto__": "{n} a", "constructor": "{n} b"}]]}`;
  const r = checkPack(pack, false, tpl, DE);
  expect(r.refused).toBeUndefined();
  const c = r.checked!;
  expect(c.translated).toBe(5);
  expect(c.table[hash('constructor', 'constructor')]).toBe('toString');
  expect(c.table[hash('c', '__proto__')]).toBe('__proto__ x');
  expect(Object.getPrototypeOf(c.table)).toBeNull();
  // A plural whose categories are named like members is a plural with other categories: dropped, nothing else touched.
  expect(c.broken.map((b) => [b.rule, b.got])).toEqual([['categories', ['__proto__', 'constructor']]]);
  expect(({} as Record<string, unknown>).a).toBeUndefined();
  expect(Object.prototype.toString.call({})).toBe('[object Object]');
  // The runtime reads such a table as data.
  under({ tag: 'de', table: c.table as never }, () => {
    expect(tr('constructor').t('constructor')).toBe('toString');
    expect(tr('valueOf').t('valueOf')).toBe('constructor');
  });
});

test('api_013 coverage counts a plural group once and lists missing and left-over entries', () => {
  const c = checked({ cache: [[['{n} answer', '{n} answers'], { one: '{n} Antwort', other: '{n} Antworten' }], ['Holds', 'Hält'], ['Gone', 'Weg']], common: [['Save', '']] });
  expect([c.total, c.translated]).toEqual([9, 2]);
  expect(c.coverage).toEqual([
    { ctx: 'common', total: 1, translated: 0 },
    { ctx: 'labels', total: 1, translated: 0 },
    { ctx: 'cache', total: 7, translated: 2 },
  ]);
  expect(c.missing).toHaveLength(7);
  expect(c.missing).toContainEqual({ ctx: 'common', english: 'Save', note: undefined });
  expect(c.leftovers).toEqual([{ ctx: 'cache', english: 'Gone', note: undefined, reason: 'gone' }]);
});

test('api_013 the language tag is canonical and known', () => {
  const plurals = new Map(Object.entries(PLURALS));
  const ok = (s: string) => {
    const r = tagInfo(s, plurals);
    return r.ok ? r.value : null;
  };
  const why = (s: string) => {
    const r = tagInfo(s, plurals);
    return r.ok ? null : r.why;
  };
  expect(ok('pt-br')).toEqual({ tag: 'pt-BR', language: 'pt', dir: 'ltr', categories: ['one', 'many', 'other'] });
  expect(ok(' zh-hant ')?.tag).toBe('zh-Hant');
  expect(ok('DE')).toEqual({ tag: 'de', language: 'de', dir: 'ltr', categories: ['one', 'other'] });
  expect([ok('ar')?.dir, ok('he')?.dir, ok('sr-Latn')?.dir]).toEqual(['rtl', 'rtl', 'ltr']);
  for (const s of ['zh', 'sr', 'en', 'en-GB', 'en-XA', 'ar-XB', 'qaa', 'qtz', 'mis', 'mul', 'zxx', 'und', 'x-foo', 'tok', 'iw', '__proto__', 'garbage!!', '', 'de-DE-1996', 'de-u-co-phonebk'])
    expect(ok(s), s).toBeNull();
  expect(why('zh')).toEqual({ code: 'script', language: 'zh', hint: 'zh-Hans' });
  expect(tagWords(why('zh')!)).toBe('This language is written in more than one script: add the script, such as zh-Hans.');
  expect([why('tok')?.code, why('en-GB')?.code, why('en-XA')?.code, why('ar-XB')?.code, why('qaa')?.code, why('und')?.code, why('')?.code]).toEqual(['plurals', 'english', 'english', 'pseudo', 'reserved', 'reserved', 'empty']);
  // The committed table decides, not the engine's alias data: `iw` is refused whether or not the engine reads it as `he`.
  expect(['alias', 'plurals']).toContain(why('iw')?.code);
  expect(tagWords(why('tok')!)).toBe("TelltaleDNS doesn't know the plural forms of this language yet: ask for it to be added.");
  // A tag accepted here is one the repository's check accepts in its manifest; the same languages of several scripts.
  for (const s of ['de', 'fr', 'pt-BR', 'zh-Hans', 'zh-Hant', 'sr-Latn', 'ar', 'ja']) expect(lib.canonicalTagError(ok(s)?.tag ?? s), s).toBeNull();
  expect(MULTI_SCRIPT).toEqual(lib.MULTI_SCRIPT);
});

/** Text of at most `n` units: `unit(i)` for i = 0, 1, 2, … (a shape against the rule). */
const fill = (unit: (i: number) => string, n: number) => {
  let s = '';
  for (let i = 0; s.length + unit(i).length <= n; i++) s += unit(i);
  return s;
};
const letters = (i: number) => [i % 26, ((i / 26) | 0) % 26, ((i / 676) | 0) % 26].map((c) => String.fromCharCode(97 + c)).join('');
/** Shapes against the agreement rule (review part A of T29.3, finding 2): English and translation of `n` units. */
const SHAPES: Record<string, (n: number) => [string, string]> = {
  'distinct tokens a fullwidth colon joins': (n) => [fill((i) => `a_${i} `, n), fill((i) => `x：${i} `, n)],
  'distinct placeholders': (n) => [fill((i) => `{a${i}} `, n), fill((i) => `{b${i}} `, n)],
  'distinct tags': (n) => [fill((i) => `<a${i}>`, n), fill((i) => `<b${i}>`, n)],
  'distinct hyphenated words': (n) => [fill((i) => `ab-${letters(i)} `, n), fill((i) => `w${i} `, n)],
  'a translation alone against a current English': (n) => ['Settings', fill((i) => `w${i} `, n)],
  'the same, its words joined by a fullwidth colon': (n) => ['Settings', fill((i) => `w：${i} `, n)],
};
/** A whole file's check, at most (ms): Node on the test VM took 0.65 s at most for these files (round 3 of
 * T29.3), and 44 s for the first before the rule was made linear. */
const BOUND_MS = 5000;
/** The least time of `k` samples of `reps` calls (ms). */
function cost(f: () => unknown, reps = 10, k = 7) {
  let least = Infinity;
  for (let s = 0; s < k; s++) {
    const t0 = performance.now();
    for (let r = 0; r < reps; r++) f();
    least = Math.min(least, performance.now() - t0);
  }
  return least;
}

test('api_013 the agreement rule stays linear on hostile input', () => {
  // Four times the input costs at most about six times as much, against the same shape at a quarter of the size
  // in the same run: as the browser runs the rule for a pack (no positions) and as the check script does.
  for (const [name, shape] of Object.entries(SHAPES)) {
    const [e1, t1] = shape(1000);
    const [e4, t4] = shape(4000);
    for (const o of [{ positions: false }, {}]) {
      agree(e1, t1, o);
      const ratio = cost(() => agree(e4, t4, o)) / cost(() => agree(e1, t1, o));
      console.log(`DVP_LINEAR ${name}${o.positions === false ? '' : ' (with positions)'}: x${ratio.toFixed(1)} for x4`);
      // The check script places each finding by a search from the start: a term that grows faster on these shapes.
      expect(ratio, `${name}${o.positions === false ? '' : ' (with positions)'}`).toBeLessThan(o.positions === false ? 6 : 10);
    }
  }
});

test('api_013 a whole pack of hostile pairs is checked in a few seconds', () => {
  // A template of 300 messages, and files of about 1 MiB: pairs of a shape whose English is the file's own (left
  // over: never held to the rule), and pairs of the template's own English with the longest translations.
  const entries = Array.from({ length: 300 }, (_, i) => ({ ctx: 'settings', english: `Settings ${i}` }));
  const tpl = readTemplate(writeTemplate(entries, { notes: new Map(), verbatim: new Map(), glossary: [], plurals: { de: ['one', 'other'] } }));
  const file = (english: (i: number) => string, translation: string) => {
    const pairs: [string, string][] = [];
    let size = 20;
    for (let i = 0; ; i++) {
      const p: [string, string] = [english(i), translation];
      size += JSON.stringify(p).length + 2;
      if (size > MAX_BYTES - 64 || i >= 300) break;
      pairs.push(p);
    }
    return JSON.stringify({ settings: pairs });
  };
  const [colonE, colonT] = SHAPES['distinct tokens a fullwidth colon joins'](4000);
  const [placeE, placeT] = SHAPES['distinct placeholders'](4000);
  const files: [string, string][] = [
    ['left over: distinct tokens a fullwidth colon joins', file((i) => `${colonE.slice(0, 3990)} ${i}`, colonT)],
    ['left over: distinct placeholders', file((i) => `${placeE.slice(0, 3990)} ${i}`, placeT)],
    ['current: a translation alone', file((i) => `Settings ${i}`, SHAPES['a translation alone against a current English'](4000)[1])],
    ['current: its words joined by a fullwidth colon', file((i) => `Settings ${i}`, SHAPES['the same, its words joined by a fullwidth colon'](4000)[1])],
    ['current: distinct tokens a fullwidth colon joins', file((i) => `Settings ${i}`, colonT)],
  ];
  for (const [name, text] of files) {
    expect(text.length, name).toBeGreaterThan(1_000_000);
    const t0 = performance.now();
    const r = checkPack(text, false, tpl, DE);
    const card = performance.now() - t0;
    const t1 = performance.now();
    checkPack(text, false, tpl, DE, { full: false });
    const load = performance.now() - t1;
    expect(r.refused, name).toBeUndefined();
    console.log(`DVP_LINEAR file ${name}: ${text.length} characters; the card's check ${(card / 1000).toFixed(2)} s, a page load's ${(load / 1000).toFixed(2)} s`);
    expect(card, name).toBeLessThan(BOUND_MS);
    expect(load, name).toBeLessThan(BOUND_MS);
  }
});

/** A seeded generator (mulberry32): the differential test draws the same pairs on every run. */
function seeded(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
// What a message and its translation are made of, for the differential test: words, placeholders, tags, addresses
// (some written fullwidth), structural tokens, numbers in other digits, the punctuation that joins tokens, code
// spans, and forbidden or joining code points.
const PIECES = [
  'Keep', 'open', 'Einstellungen', 'help', 'email', 'ntfy', 'NXDOMAIN', 'DNSSEC', 'API', 'ab-cd', 'Wi-Fi', 'Сапсеl', 'Dеlеtе', 'Ωmega', 'կօd', '例子.公司', 'x',
  '{n}', '{name}', '{ n }', '{a1}', '{b2}', '<b>', '</b>', '<a>', '</a>', '<br/>',
  'https://a.example/x', 'http://b.lan:8080/p?q=1', 'https://', 'ｈｔｔｐｓ：／／evil', 'https://例子', 'evil.example/login', 'evil.example/a/b',
  'a_b', '[x]', '[[router]]', '/etc/telltale/', 'key=value', '$HOME', 'a|b', '1.1.1.1', '２１．１．１．１５', 'a.example:53', 'DNS：53', 'ｅｖｉｌ．ｈｅｌｐ：８５３',
  '53', '٥٣', '８．８．８．８', '8。8。8。8', '24:00', '5353', '0',
  '：', '。', '．', '＝', ',', '.', ':', '-', '(', ')', '`code`', '`x`', "'ya",
  '\u202E', '\u200B', '\u200D', 'ب\u200Dب', '\u200E', '\uFE0F', '\u00AD', '\u3164', '\u2028',
];
function draw(rand: () => number): { english: string; translation: string; o: object } {
  const pick = () => PIECES[Math.floor(rand() * PIECES.length)];
  const join = () => (rand() < 0.7 ? ' ' : '');
  const words = Array.from({ length: 1 + Math.floor(rand() * 12) }, pick);
  const english = words.reduce((s, w) => s + join() + w, '');
  let tw = [...words];
  const r = rand();
  if (r < 0.25) tw = tw.filter(() => rand() < 0.8);
  else if (r < 0.5) tw = tw.map((w) => (rand() < 0.2 ? pick() : w));
  else if (r < 0.65) tw.splice(Math.floor(rand() * (tw.length + 1)), 0, pick(), pick());
  else if (r < 0.8) tw.sort(() => rand() - 0.5);
  else if (r < 0.9) tw = Array.from({ length: 1 + Math.floor(rand() * 12) }, pick);
  const translation = tw.reduce((s, w) => s + join() + w, '');
  const o = {
    ...(rand() < 0.3 ? { verbatim: ['email', 'ntfy'].filter(() => rand() < 0.5) } : {}),
    ...(rand() < 0.5 ? { glossary: ['NXDOMAIN', 'DNSSEC', 'API'] } : {}),
    ...(rand() < 0.2 ? { dir: 'rtl' as const } : {}),
    ...(rand() < 0.1 ? { exemptDigits: true } : {}),
    ...(rand() < 0.1 ? { exemptAdded: ['24:00', '5353'] } : {}),
    ...(rand() < 0.2 ? { placeholderSubset: true } : {}),
  };
  return { english, translation, o };
}

test('api_012 the agreement rule gives what it gave before it was made linear', () => {
  // The rule as at 934a9fb7 (a copy, byte for byte), against the rule now: every finding the same, in the same
  // order, on a few thousand drawn pairs and on the shapes of finding 2 at several sizes. The runtime's check is
  // given the digit and added-token rules, as a catalog the build did not ship brings them.
  const before = { agree: agreeBefore };
  const beforeSafe = safeBefore;
  const rand = seeded(20261126);
  const cases = Array.from({ length: 3000 }, () => draw(rand));
  for (const shape of Object.values(SHAPES)) for (const n of [40, 300, 1000]) cases.push({ english: shape(n)[0], translation: shape(n)[1], o: {} });
  for (const n of [40, 300, 1000]) cases.push({ english: fill((i) => `a_${i} `, n), translation: fill((i) => `x＝${i} `, n), o: {} }, { english: fill((i) => `a.b${i} `, n), translation: fill((i) => `x.b${i}＝${i} `, n), o: {} });
  // Two behaviours the draw reaches only once each (review part B of T29.3, nit 7). The English's own tokens are
  // taken out longest first: the shorter one first would leave `.c:5` added. A verbatim word is read in the
  // prepared text: fullwidth letters are the word.
  const order = { english: 'a_b a_b.c:5', translation: 'a_b a_b.c:5 z．a_b．c：5', o: {} };
  const verbatim = { english: 'Send email', translation: 'Ｓｅｎｄ ｅｍａｉｌ', o: { verbatim: ['email'] } };
  cases.push(order, verbatim);
  expect(agree(order.english, order.translation).fails.filter((f) => f.rule === 'structural')).toEqual([]);
  expect(agree(verbatim.english, verbatim.translation, verbatim.o).fails.filter((f) => f.rule === 'verbatim')).toEqual([]);
  const noAt = (v: { fails: object[]; reports: object[] }) => JSON.stringify({ fails: v.fails.map((f) => ({ ...f, at: 0 })), reports: v.reports.map((f) => ({ ...f, at: 0 })) });
  let findings = 0;
  for (const { english, translation, o } of cases) {
    const what = JSON.stringify([english.slice(0, 80), translation.slice(0, 80), o]);
    const now = agree(english, translation, o);
    const then = before.agree(english, translation, o);
    expect(JSON.stringify(now), what).toBe(JSON.stringify(then));
    // Without positions: the same findings, only placed nowhere.
    expect(noAt(agree(english, translation, { ...o, positions: false })), what).toBe(noAt(then));
    expect(added.addedStructural(english, translation), what).toEqual(beforeSafe.addedStructural(english, translation));
    const subset = 'placeholderSubset' in o;
    for (const built of [false, true]) expect(safe.agreesAtRuntime(english, translation, 'ltr', { built, subset, extra: added.extraAgrees }), what).toBe(beforeSafe.agreesAtRuntime(english, translation, 'ltr', { built, subset }));
    findings += then.fails.length + then.reports.length;
  }
  // The drawn pairs reach the rule's findings, not only agreement.
  expect(findings).toBeGreaterThan(10_000);
});

test('api_013 no source of the web ui holds a literal direction control or mark, line separator or byte-order mark', () => {
  // Such a character reorders a line in an editor and in a review, and a line separator breaks the test runner's
  // line numbers: a source writes it as an escape (review part B of T29.3, finding 2). Every text file under ui/:
  // the code, the tests, the scripts, the page and the configuration files. Not the language files, which are data
  // the check holds to its own rule (a language written right to left may use the direction marks there).
  const bad = /[\u{061C}\u{200E}\u{200F}\u{2028}\u{2029}\u{202A}-\u{202E}\u{2066}-\u{2069}\u{FEFF}]/u;
  const skip = new Set(['node_modules', '.e2e', 'test-results', 'playwright-report', 'dist', join('src', 'locales'), join('public', 'assets', 'locales')]);
  const found: string[] = [];
  const read = new Set<string>();
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      const rel = p.slice(UI.length + 1).split(sep).join('/');
      if (e.isDirectory()) {
        if (!skip.has(p.slice(UI.length + 1)) && !skip.has(e.name)) walk(p);
      } else if (/\.(ts|svelte|mjs|cjs|js|json|css|html|md|svg|txt|ya?ml)$/.test(e.name)) {
        read.add(rel);
        if (bad.test(readFileSync(p, 'utf8'))) found.push(rel);
      }
    }
  };
  walk(UI);
  expect(found).toEqual([]);
  for (const p of ['index.html', 'vite.config.ts', 'playwright.config.ts', 'package.json', 'scripts/i18n-lib.mjs', 'scripts/postbuild.mjs', 'src/main.ts', 'tests/e2e/9-devpack.spec.ts']) expect(read.has(p), p).toBe(true);
  expect([...read].some((p) => p.startsWith('src/locales/'))).toBe(false);
  // The check itself sees each kind.
  for (const cp of [0x061c, 0x200e, 0x200f, 0x2028, 0x2029, 0x202e, 0x2066, 0x2069, 0xfeff]) expect(bad.test(`a${String.fromCharCode(cp)}b`), cp.toString(16)).toBe(true);
});

test('api_013 a displayed file name loses forbidden code points and is cut to 48', () => {
  expect(shownName('nos\u202Ej.ed')).toBe('nosj.ed');
  expect(shownName('de\u200B.json')).toBe('de.json');
  expect(shownName('a\nb\tc.json')).toBe('abc.json');
  expect(shownName('de.json')).toBe('de.json');
  const cut = shownName(`${'x'.repeat(100)}.json`);
  expect([...cut]).toHaveLength(48);
  expect(cut).toBe(`${'x'.repeat(23)}…${'x'.repeat(19)}.json`);
  // By code point: never half of a pair.
  expect([...shownName('\u{1F600}'.repeat(60))]).toHaveLength(48);
  expect(shownName('\u{1F600}'.repeat(60)).includes('\uFFFD')).toBe(false);
  // Pack text on the check screen: a visible marker for each forbidden code point.
  expect(markers('ab\u202Ecd')).toBe('ab⟨U+202E⟩cd');
  expect(markers('a\u{E0041}b')).toBe('a⟨U+E0041⟩b');
  expect(markers('plain')).toBe('plain');
});

// ---------------------------------------------------------------------------------------------
// API-013: what a page load does with the pack this browser keeps

const NOW = Date.UTC(2026, 10, 26, 12);
const UI_A = '/assets/index-A1.js';
const TPL_URL = '/assets/locales/template-1a2b3c4d.json';
class MemStore implements Store {
  m = new Map<string, string>();
  getItem(k: string) {
    return this.m.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.m.set(k, v);
  }
  removeItem(k: string) {
    this.m.delete(k);
  }
}
/** The fixture's template, with German in its plural table. */
const deJson = () => {
  const f = fixture();
  return writeTemplate(f.entries.values(), { notes: f.notes, verbatim: f.verbatim, glossary: f.glossary, plurals: { de: ['one', 'other'] } });
};
const REC = newRecord({ ui: UI_A, commit: 'c0ffee1', user: 'admin', name: 'de.json', sha: 'a1'.repeat(32), tag: 'de', dir: 'ltr', text: JSON.stringify({ cache: [['Holds', 'Hält']] }) }, NOW - 60_000);
type Fake = { status?: object | null; tpl?: string | null; calls: string[] };
/** Deps of a page load: signed in, the fixture's template, nothing slow (override any). */
function deps(o: Partial<Deps> = {}, fake: Fake = { calls: [] }): Deps {
  const answer = async (url: string): Promise<Response> => {
    fake.calls.push(url);
    if (url === '/api/v1/auth/status') {
      if (fake.status === null) throw new Error('unreachable');
      return Response.json(fake.status ?? { user: { username: 'admin', display: null }, setupRequired: false });
    }
    if (url === TPL_URL) return fake.tpl === null ? new Response('', { status: 500 }) : new Response(fake.tpl ?? deJson());
    return new Response('', { status: 404 });
  };
  return { store: new MemStore(), takeOnce: () => null, fetch: ((u: string) => answer(u)) as typeof fetch, now: () => NOW, ui: UI_A, template: TPL_URL, search: '', hash: '#/', languages: ['de-DE', 'en'], checker: checking(), signal: new AbortController().signal, ...o };
}
/** The checking code as the browser loads it (`recheck.ts`), with another check if given; `loads` counts the loads. */
function checking(check = checkPack, loads = { n: 0 }): () => Promise<Checker> {
  return async () => {
    loads.n++;
    return { readTemplate, tagInfo, checkPack: check };
  };
}
const stored = (s: MemStore) => JSON.parse(s.getItem(DEVPACK_KEY) ?? 'null');
/** A store that holds `v` under the key, as the one a page load read it from. */
const holding = (v: string) => {
  const s = new MemStore();
  s.setItem(DEVPACK_KEY, v);
  return s;
};

test('api_013 a stored pack is cleared on another build after seven days and when damaged', async () => {
  const ok = await decide(JSON.stringify(REC), deps());
  expect(ok.view).toEqual({ kind: 'active', name: 'de.json', sha: REC.sha, tag: 'de' });
  expect(ok.choice).toMatchObject({ tag: 'de', dir: 'ltr', formatLocale: 'de-DE' });
  expect(Object.values(ok.choice?.table ?? {})).toEqual(['Hält']);
  // Another web UI build: removed, and the one key holds the notice.
  const up = holding(JSON.stringify(REC));
  const fake: Fake = { calls: [] };
  expect(await decide(JSON.stringify(REC), deps({ store: up, ui: '/assets/index-B2.js' }, fake))).toEqual({ choice: null, view: { kind: 'notice', gone: 'upgrade', name: 'de.json' }, record: null, notice: { v: 1, gone: 'upgrade', name: 'de.json', at: NOW } });
  expect(stored(up)).toEqual({ v: 1, gone: 'upgrade', name: 'de.json', at: NOW });
  // Seven days after loading; a moment before, it still applies.
  const exp = holding(JSON.stringify(REC));
  expect((await decide(JSON.stringify(REC), deps({ store: exp, now: () => REC.expires }))).view).toEqual({ kind: 'notice', gone: 'expired', name: 'de.json' });
  expect(stored(exp).gone).toBe('expired');
  expect((await decide(JSON.stringify(REC), deps({ now: () => REC.expires - 1 }))).view.kind).toBe('active');
  // A value that is not a record: damaged.
  for (const v of ['{', 'null', '[]', '{"v":2}', JSON.stringify({ ...REC, sha: 'x' }), JSON.stringify({ ...REC, fails: -1 }), JSON.stringify({ ...REC, text: 3 }), JSON.stringify({ ...REC, server: {} }), JSON.stringify({ ...REC, user: 3 }), JSON.stringify({ ...REC, user: undefined })]) {
    const s = holding(v);
    expect((await decide(v, deps({ store: s }, fake))).view, v).toEqual({ kind: 'notice', gone: 'damaged', name: '' });
    expect(stored(s).gone).toBe('damaged');
  }
  // A text that is no longer a pack (refused whole) is damaged too.
  const badText = JSON.stringify({ ...REC, text: '{"cache": [["Holds"]]}' });
  expect((await decide(badText, deps({ store: holding(badText) }))).view).toEqual({ kind: 'notice', gone: 'damaged', name: 'de.json' });
  // A notice stays until dismissed, 7 days at most, then goes by itself; nothing is fetched for one.
  const n = new MemStore();
  n.setItem(DEVPACK_KEY, JSON.stringify(notice('expired', 'de.json', NOW - 1000)));
  expect((await decide(n.getItem(DEVPACK_KEY) ?? '', deps({ store: n }, fake))).view).toEqual({ kind: 'notice', gone: 'expired', name: 'de.json' });
  n.setItem(DEVPACK_KEY, JSON.stringify(notice('expired', 'de.json', NOW - LIFETIME_MS - 1)));
  expect((await decide(n.getItem(DEVPACK_KEY) ?? '', deps({ store: n }, fake))).view).toEqual({ kind: 'none' });
  expect(n.getItem(DEVPACK_KEY)).toBeNull();
  expect(fake.calls).toEqual([]);
});

test('api_013 a kept record whose tag the card could not have stored is damaged', async () => {
  // The card stores a language tag in its canonical form, never one for private use. A kept record with any other tag
  // (with its table, so no check runs) is removed with the notice of a copy that can't be read, as any damaged value.
  const keptAs = (tag: string) => JSON.stringify({ ...REC, tag, checked: { ui: UI_A, sha: REC.sha, table: { deadbeef: 'Hält' } } });
  const canonicalHere = (t: string) => {
    try {
      return Intl.getCanonicalLocales(t)[0] === t;
    } catch {
      return false;
    }
  };
  for (const tag of ['x', 'en_US', '', 'a'.repeat(300), 'i-klingon', 'DE', 'fr-', 'de-x-private']) {
    const s = holding(keptAs(tag));
    const out = await decide(keptAs(tag), deps({ store: s }));
    expect(out.view, `${tag.slice(0, 24)} (canonical on this engine: ${canonicalHere(tag)})`).toEqual({ kind: 'notice', gone: 'damaged', name: '' });
    expect(stored(s).gone).toBe('damaged');
  }
  // The tags the card stores stay records and are shown.
  for (const tag of ['de', 'pt-BR', 'zh-Hant', 'sr-Latn']) expect((await decide(keptAs(tag), deps())).view.kind, tag).toBe('active');
});

test('api_013 a check that throws twice in a row retires the pack', async () => {
  const store = new MemStore();
  store.setItem(DEVPACK_KEY, JSON.stringify(REC));
  const throwing = (() => {
    throw new Error('a fault this file sets off');
  }) as typeof checkPack;
  const first = await decide(store.getItem(DEVPACK_KEY) ?? '', deps({ store, checker: checking(throwing) }));
  expect([first.view.kind, first.choice]).toEqual(['unchecked', null]);
  expect(stored(store).fails).toBe(1);
  const second = await decide(store.getItem(DEVPACK_KEY) ?? '', deps({ store, checker: checking(throwing) }));
  expect(second.view).toEqual({ kind: 'notice', gone: 'failed', name: 'de.json' });
  expect(stored(store).gone).toBe('failed');
  // A template that can't be fetched, read or reached in time is not the file's doing: not counted.
  const s = new MemStore();
  s.setItem(DEVPACK_KEY, JSON.stringify({ ...REC, fails: 1 }));
  const hung = ((_u: string, init?: RequestInit) => new Promise<Response>((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted'))))) as typeof fetch;
  for (const [what, d] of [
    ['an answer 500', deps({ store: s }, { tpl: null, calls: [] })],
    ['a damaged template', deps({ store: s }, { tpl: '{"v": 1, "contexts"', calls: [] })],
    ['an empty answer', deps({ store: s }, { tpl: '', calls: [] })],
    ['no template in the build', deps({ store: s, template: null })],
    ['a server that hangs', deps({ store: s, fetch: hung, signal: AbortSignal.timeout(30) })],
    ['checking code that does not load', deps({ store: s, checker: () => Promise.reject(new Error('404')) })],
  ] as const) {
    expect((await decide(s.getItem(DEVPACK_KEY) ?? '', d)).view.kind, what).toBe('unchecked');
    expect(stored(s).fails, what).toBe(1);
  }
  // A check that passes sets the count back to zero.
  expect((await decide(s.getItem(DEVPACK_KEY) ?? '', deps({ store: s }))).view.kind).toBe('active');
  expect(stored(s).fails).toBe(0);
});

test('api_013 a kept table spares the check while the build and the fingerprint are unchanged', async () => {
  const v = JSON.stringify(REC);
  // A record as Use writes it: the check's table for this build and this file.
  const fresh = await decide(v, deps());
  const table = fresh.choice?.table ?? {};
  const kept = newRecord({ ui: UI_A, commit: 'c0ffee1', user: 'admin', name: 'de.json', sha: REC.sha, tag: 'de', dir: 'ltr', text: REC.text, table }, NOW - 60_000);
  expect(kept.checked).toEqual({ ui: UI_A, sha: REC.sha, table });
  // Kept: no template, no checking code, the same table, the same language.
  const loads = { n: 0 };
  const fake: Fake = { calls: [] };
  const s = new MemStore();
  s.setItem(DEVPACK_KEY, JSON.stringify(kept));
  const fast = await decide(s.getItem(DEVPACK_KEY) ?? '', deps({ store: s, checker: checking(checkPack, loads) }, fake));
  expect([fast.view.kind, fast.checked, loads.n, fake.calls]).toEqual(['active', false, 0, ['/api/v1/auth/status']]);
  expect(fast.choice).toEqual(fresh.choice);
  expect(s.getItem(DEVPACK_KEY)).toBe(JSON.stringify(kept));
  // A table for another build or another file, or one that is not well formed: the file is checked again,
  // and the record keeps the new table, in its one write.
  const odd: [string, object][] = [
    ['another web UI build', { ...kept, checked: { ...kept.checked, ui: '/assets/index-OTHER.js' } }],
    ['another fingerprint', { ...kept, checked: { ...kept.checked, sha: 'b2'.repeat(32) } }],
    ['a key that is no hash', { ...kept, checked: { ...kept.checked, table: { ...table, constructor: 'x' } } }],
    ['a value of the wrong kind', { ...kept, checked: { ...kept.checked, table: { [hash('cache', 'Holds')]: 3 } } }],
    ['plural forms without other', { ...kept, checked: { ...kept.checked, table: { [hash('cache', 'Holds')]: { one: 'x' } } } }],
    ['no table at all', { ...kept, checked: { ui: UI_A, sha: REC.sha } }],
    ['something else', { ...kept, checked: 'yes' }],
  ];
  for (const [what, rec] of odd) {
    const st = holding(JSON.stringify(rec));
    const l = { n: 0 };
    const f: Fake = { calls: [] };
    // The record itself still applies (a damaged kept table is not a damaged record).
    expect('record' in readValue(JSON.stringify(rec)), what).toBe(true);
    const r = await decide(JSON.stringify(rec), deps({ store: st, checker: checking(checkPack, l) }, f));
    expect([r.view.kind, r.checked, l.n, f.calls.includes(TPL_URL)], what).toEqual(['active', true, 1, true]);
    expect(r.choice?.table, what).toEqual(table);
    expect(stored(st).checked, what).toEqual({ ui: UI_A, sha: REC.sha, table });
    expect(stored(st).fails, what).toBe(0);
  }
  // A store that is full keeps the record as it was, and the page still has the pack.
  const full: Store = { getItem: () => null, removeItem: () => undefined, setItem: () => { throw new DOMException('full', 'QuotaExceededError'); } };
  expect((await decide(v, deps({ store: full }))).view.kind).toBe('active');
  // The well-formed tables only.
  expect(keptTable({ [hash('c', 'x')]: 'y', [hash('c', ['a', 'b'])]: { one: 'p', other: 'q' } })).toEqual({ [hash('c', 'x')]: 'y', [hash('c', ['a', 'b'])]: { one: 'p', other: 'q' } });
  for (const t of [null, [], 'x', { ['__proto__']: 'x' }, { ['1234567']: 'x' }, { [hash('c', 'x')]: null }, { [hash('c', 'x')]: ['y'] }]) expect(keptTable(t), JSON.stringify(t)).toBeNull();
  expect(Object.getPrototypeOf(keptTable({}))).toBeNull();
});

test("api_013 a kept record's size for a typical and for the largest pack", () => {
  const { tpl } = uiTemplate();
  const de: Tag = { tag: 'de', language: 'de', dir: 'ltr', categories: ['one', 'other'] };
  const record = (pack: object) => {
    const text = JSON.stringify(pack, null, 2);
    const r = checkPack(text, false, tpl, de);
    if (r.refused) throw new Error(JSON.stringify(r.refused));
    const rec = JSON.stringify(newRecord({ ui: UI_A, commit: 'c0ffee1', user: 'admin', name: 'de.json', sha: 'a1'.repeat(32), tag: 'de', dir: 'ltr', text, table: r.checked.table }, NOW));
    return { text: new TextEncoder().encode(text).length, chars: rec.length, translated: r.checked.translated };
  };
  const all = (pad: string) =>
    Object.fromEntries(tpl.contexts.map((ctx) => [ctx, [...tpl.entries.values()].filter((e) => e.ctx === ctx).map((e) => [e.english, typeof e.english === 'string' ? `${e.english} Ü${pad}` : { one: `${e.english[0]} Ü${pad}`, other: `${e.english[1]} Ü${pad}` }, ...(e.note ? [e.note] : [])])]));
  // Every message of this build translated (about 2,500 pairs).
  const typical = record(all(''));
  // As large as a file may be (1 MiB): each translation padded until the file reaches the limit.
  const room = Math.floor((1024 * 1024 - typical.text) / tpl.entries.size / 1.1);
  const largest = record(all('ü'.repeat(Math.max(0, Math.floor(room / 2)))));
  console.log(`DVP_RECORD typical: ${typical.translated} translated, file ${typical.text} B, record ${typical.chars} characters (${typical.chars * 2} B as UTF-16)`);
  console.log(`DVP_RECORD largest: ${largest.translated} translated, file ${largest.text} B, record ${largest.chars} characters (${largest.chars * 2} B as UTF-16)`);
  expect(typical.translated).toBe(tpl.entries.size);
  expect(largest.text).toBeLessThanOrEqual(1024 * 1024);
  expect(largest.text).toBeGreaterThan(900 * 1024);
  // A record holds the text and, at most, a second copy of the translations: never three times the file.
  expect(largest.chars).toBeLessThan(3 * 1024 * 1024);
});

test('api_013 a page load pauses the pack where someone else may be next', async () => {
  const v = JSON.stringify(REC);
  const paused = async (o: Partial<Deps>, fake: Fake = { calls: [] }) => {
    const r = await decide(v, deps(o, fake));
    return [r.view.kind === 'paused' ? r.view.why : r.view.kind, r.choice === null ? 'usual language' : 'the pack'];
  };
  expect(await paused({}, { status: { user: null, setupRequired: false }, calls: [] })).toEqual(['signed-out', 'usual language']);
  expect(await paused({}, { status: { user: null, setupRequired: true }, calls: [] })).toEqual(['signed-out', 'usual language']);
  expect(await paused({}, { status: { user: { username: 'wall', display: { id: 1 } }, setupRequired: false }, calls: [] })).toEqual(['display', 'usual language']);
  expect(await paused({ hash: '#/display?token=x' })).toEqual(['display', 'usual language']);
  // `?lang=` is this load's language, whatever it is; nothing is requested for the pack.
  const fake: Fake = { calls: [] };
  expect(await paused({ search: '?lang=en' }, fake)).toEqual(['param', 'usual language']);
  expect(fake.calls).toEqual([]);
  // "Show the test pack on this page": this one load, signed out or on a display.
  expect(await paused({ takeOnce: () => '1' }, { status: { user: null, setupRequired: false }, calls: [] })).toEqual(['active', 'the pack']);
  expect(await paused({ takeOnce: () => '1', hash: '#/display?token=x' })).toEqual(['active', 'the pack']);
  // A server that can't be reached: the usual language, and the pack stays.
  expect(await paused({}, { status: null, calls: [] })).toEqual(['unchecked', 'usual language']);
  // Someone other than the user who loaded it: paused, and "Show the test pack on this page" for one load (review
  // part A of T29.3, finding 3); that user gets the pack.
  const bob = { status: { user: { username: 'bob', display: null }, setupRequired: false }, calls: [] };
  expect(await paused({}, bob)).toEqual(['user', 'usual language']);
  expect(await paused({ takeOnce: () => '1' }, { ...bob, calls: [] })).toEqual(['active', 'the pack']);
  expect(await paused({})).toEqual(['active', 'the pack']);
  // The load after the pack left a page because someone went away is paused, whoever the status says is signed
  // in (review part A of T29.3, finding 1: a status that disagrees with the app never makes a reload loop).
  expect(await paused({ takeOnce: () => 'away' })).toEqual(['signed-out', 'usual language']);
  // What the boot needs to follow the user: who was signed in when the load decided, and whether "Show the test
  // pack on this page" lifted a pause.
  const on = await decide(v, deps());
  expect([on.user, on.shown]).toEqual(['admin', false]);
  const out = await decide(v, deps({}, { status: { user: null, setupRequired: false }, calls: [] }));
  expect([out.user, out.paused]).toEqual([null, 'signed-out']);
  const shown = await decide(v, deps({ takeOnce: () => '1' }, { status: { user: null, setupRequired: false }, calls: [] }));
  expect([shown.user, shown.shown, shown.view.kind]).toEqual([null, true, 'active']);
});

test('api_013 the one-load flag is taken whatever the load decides', async () => {
  // "Show the test pack on this page" is for the next load alone: no early return leaves the flag in the tab for a
  // later sign-in page (review part A of T29.3, finding 8).
  const cases: [string, string, Partial<Deps>][] = [
    ['?lang=', JSON.stringify(REC), { search: '?lang=en' }],
    ['a notice', JSON.stringify(notice('expired', 'de.json', NOW - 1000)), {}],
    ['a damaged value', '{', {}],
    ['another web UI build', JSON.stringify(REC), { ui: '/assets/index-B2.js' }],
    ['seven days gone', JSON.stringify(REC), { now: () => REC.expires }],
    ['a page that uses the pack', JSON.stringify(REC), {}],
  ];
  for (const [what, v, o] of cases) {
    let flag: string | null = '1';
    const takeOnce = () => {
      const was = flag;
      flag = null;
      return was;
    };
    await decide(v, deps({ ...o, takeOnce }));
    expect(flag, what).toBeNull();
  }
});

test('api_013 reads of who is signed in that disagree reload a page twice at most in a row', async () => {
  // The boot's rules (`decide`, then `whenSeen` for each report of the app) replayed over every run of four page
  // loads, each with what the pack's read of the status says and what the app reports: nobody, the user who loaded
  // the pack, or another user, on each of three changes of page (the app reports on every one, the same user again).
  // A reload carries its flag to the load it lands on; a load that does nothing ends the run. Reads that disagree in
  // one direction, in turn, or in any mix reload a page twice at most in a row.
  const kept = { ...REC, checked: { ui: UI_A, sha: REC.sha, table: { deadbeef: 'Hält' } } };
  const WHO = [null, 'admin', 'bob'];
  const reads = WHO.flatMap((pack) => WHO.map((app) => ({ pack, app })));
  const status = (u: string | null) => ({ user: u === null ? null : { username: u, display: null }, setupRequired: false });
  /** The reports of one load, as the hook gets them: what each does, up to the first that reloads. */
  const reports = (out: Awaited<ReturnType<typeof decide>>, seq: (string | null)[]) => {
    let last: string | null | undefined;
    for (const who of seq) {
      const act = whenSeen(out, who, { installed: out.choice !== null, last, leaving: false });
      last = who;
      if (act !== 'none') return act;
    }
    return 'none';
  };
  const run = async (seq: { pack: string | null; app: string | null }[]) => {
    let flag: string | null = null;
    const acts: string[] = [];
    for (const load of seq) {
      const was = flag;
      const out = await decide(JSON.stringify(kept), deps({ takeOnce: () => was }, { status: status(load.pack), calls: [] }));
      const act = reports(out, [load.app, load.app, load.app]);
      acts.push(act);
      if (act !== 'away' && act !== 'in') break;
      flag = act;
    }
    return acts;
  };
  let worst: string[] = [];
  for (const a of reads) for (const b of reads) for (const c of reads) for (const d of reads) {
    const acts = await run([a, b, c, d]);
    if (acts.filter((x) => x === 'away' || x === 'in').length > worst.filter((x) => x === 'away' || x === 'in').length) worst = acts;
  }
  expect(worst.filter((x) => x === 'away' || x === 'in').length, JSON.stringify(worst)).toBeLessThanOrEqual(2);
  // In turn: the pack's read says nobody and the app the user, then the other way round: a sign-in reload, a
  // going-away reload, and then nothing.
  const turn = [{ pack: null, app: 'admin' }, { pack: 'admin', app: null }];
  expect(await run([...turn, ...turn])).toEqual(['in', 'away', 'none']);
  // A load after a sign-in reload where the two reads keep disagreeing: changes of page report the same user again,
  // and nothing reloads.
  const held = await decide(JSON.stringify(kept), deps({ takeOnce: () => 'in' }, { status: status(null), calls: [] }));
  expect(reports(held, ['admin', 'admin', 'admin'])).toBe('none');
  // A real sign-out and sign-in still bring the pack back: on the load after the sign-out, the app reports nobody
  // (again on each change of page), and a sign-in after it reloads into the pack.
  const after = await decide(JSON.stringify(kept), deps({ takeOnce: () => 'away' }, { status: status(null), calls: [] }));
  expect(reports(after, [null, null, 'admin'])).toBe('in');
  expect(reports(after, [null, 'bob', null, 'admin'])).toBe('in');
  // While the page leaves for the provider's sign-out it is not reloaded, and a repeat of nobody changes nothing.
  const shown = await decide(JSON.stringify(kept), deps({}, { status: status('admin'), calls: [] }));
  expect(whenSeen(shown, null, { installed: true, last: 'admin', leaving: true })).toBe('leave');
  expect(whenSeen(shown, null, { installed: true, last: 'admin', leaving: false })).toBe('away');
  expect(whenSeen(shown, null, { installed: true, last: null, leaving: false })).toBe('none');
});

test('api_013 the back tests name why the full chromium did not start', async () => {
  // The Back tests' browser (bfcache.ts): when the full Chromium does not start, the suite's own is used, and the skip's
  // reason carries the first line of that error, so a log says why the Back fix was not exercised.
  const fake = { version: () => 'shell' } as unknown as Browser;
  const tried: (string | undefined)[] = [];
  const got = await cachingBrowser({ headless: true }, undefined, async (o) => {
    tried.push(o.channel);
    if (o.channel === 'chromium') throw new Error("browserType.launch: Executable doesn't exist at /ms-playwright/chromium-1254/chrome-linux64/chrome\nLooks like Playwright was just installed or updated.");
    return fake;
  });
  expect(tried).toEqual(['chromium', undefined]);
  expect(got.browser).toBe(fake);
  expect(got.note).toBe("the full Chromium did not start: browserType.launch: Executable doesn't exist at /ms-playwright/chromium-1254/chrome-linux64/chrome; ");
  // A full Chromium named by its path is launched as it is (an error there fails the test), keeping the cache.
  const seen: LaunchOptions[] = [];
  const named = await cachingBrowser({}, '/opt/chrome', async (o) => (seen.push(o), fake));
  expect(named.note).toBe('');
  expect(seen).toEqual([{ ignoreDefaultArgs: ['--disable-back-forward-cache'], executablePath: '/opt/chrome' }]);
});

test('api_013 the back tests fail when the probe cannot forget its own count', async () => {
  // The probe's own restore must not pass for the Back test's: a reset that fails fails the test.
  await expect(resetRestored({ evaluate: () => Promise.reject(new Error('the page is gone')) } as never)).rejects.toThrow('the page is gone');
});

test('api_013 the clock is checked both ways', async () => {
  // A record loaded after now or meant to last longer than seven days, and a notice dated after now, no longer
  // apply, whatever the clock said when they were written (review part A of T29.3, finding 9).
  const view = async (v: object) => (await decide(JSON.stringify(v), deps())).view;
  const expired = { kind: 'notice', gone: 'expired', name: 'de.json' };
  expect(await view({ ...REC, loadedAt: NOW + 60_000, expires: NOW + 60_000 + LIFETIME_MS })).toEqual(expired);
  expect(await view({ ...REC, loadedAt: Date.UTC(2100, 0, 1), expires: Date.UTC(2100, 0, 8) })).toEqual(expired);
  expect(await view({ ...REC, expires: 1e300 })).toEqual(expired);
  expect(await view({ ...REC, expires: REC.loadedAt + LIFETIME_MS + 1 })).toEqual(expired);
  // Loaded a minute ago for seven days, or loaded now: it applies.
  expect((await view(REC)).kind).toBe('active');
  expect((await view({ ...REC, loadedAt: NOW })).kind).toBe('active');
  // A notice dated after now goes by itself, like one 7 days old; one dated now is shown.
  for (const [at, kind] of [[NOW + 60_000, 'none'], [Date.UTC(2100, 0, 1), 'none'], [NOW, 'notice']] as const) {
    const s = new MemStore();
    s.setItem(DEVPACK_KEY, JSON.stringify(notice('expired', 'de.json', at)));
    expect((await decide(s.getItem(DEVPACK_KEY) ?? '', deps({ store: s }))).view.kind, String(at)).toBe(kind);
    expect(s.getItem(DEVPACK_KEY) === null, String(at)).toBe(kind === 'none');
  }
});

test('api_013 a tab writes over or removes only what it read', async () => {
  // Another tab may have loaded a newer pack since this one read the key: neither a page load's notice or new
  // table nor a removal touches it (review part A of T29.3, finding 4).
  const older = REC;
  const newer = newRecord({ ui: UI_A, commit: 'c0ffee1', user: 'admin', name: 'de-2.json', sha: 'b2'.repeat(32), tag: 'de', dir: 'ltr', text: REC.text }, NOW - 1000);
  const s = holding(JSON.stringify(newer));
  expect([holds(s, older), holds(s, newer), holds(s, { ...newer, fails: 1, checked: { ui: UI_A, sha: newer.sha, table: {} } })]).toEqual([false, true, true]);
  expect(rewrite(s, older, { ...older, fails: 1 })).toBe(false);
  expect(retire(s, older, notice('upgrade', 'de.json', NOW))).toBe(true);
  expect(stored(s)).toEqual(newer);
  // A page load that read the older pack: another build, seven days, a check that throws twice, a new table.
  for (const [what, o] of [
    ['another web UI build', { ui: '/assets/index-B2.js' }],
    ['seven days gone', { now: () => older.expires }],
    ['a check that throws', { checker: checking((() => { throw new Error('x'); }) as typeof checkPack) }],
    ['a new table', {}],
  ] as [string, Partial<Deps>][]) {
    await decide(JSON.stringify({ ...older, fails: 1 }), deps({ store: s, ...o }));
    expect(stored(s), what).toEqual(newer);
  }
  // A damaged value read before, or a notice: only that value, or that notice, is taken away.
  const d = holding(JSON.stringify(newer));
  await decide('{', deps({ store: d }));
  expect(stored(d)).toEqual(newer);
  const old = notice('expired', 'de.json', NOW - LIFETIME_MS - 1);
  await decide(JSON.stringify(old), deps({ store: d }));
  expect(stored(d)).toEqual(newer);
  expect(retire(d, notice('expired', 'de.json', NOW))).toBe(true);
  expect(stored(d)).toEqual(newer);
  const n = holding(JSON.stringify(notice('expired', 'de.json', NOW)));
  expect(retire(n, notice('expired', 'de.json', NOW))).toBe(true);
  expect(n.getItem(DEVPACK_KEY)).toBeNull();
});

test('api_013 a notice that cannot be kept never leaves the pack behind', () => {
  // The key is emptied before the notice is written, and the caller reloads only when the key no longer holds the
  // pack, so storage that takes no write cannot make a page reload into the same pack (finding 5).
  const m = new Map<string, string>([[DEVPACK_KEY, JSON.stringify(REC)]]);
  const fails = () => {
    throw new DOMException('read-only', 'QuotaExceededError');
  };
  const readOnly: Store = { getItem: (k) => m.get(k) ?? null, setItem: fails, removeItem: (k) => void m.delete(k) };
  expect(retire(readOnly, REC, notice('upgrade', 'de.json', NOW))).toBe(true);
  expect(m.has(DEVPACK_KEY)).toBe(false);
  // Storage that takes neither a write nor a removal: the key still holds the pack, and retire says so.
  const stuck: Store = { getItem: () => JSON.stringify(REC), setItem: fails, removeItem: fails };
  expect(retire(stuck, REC, notice('upgrade', 'de.json', NOW))).toBe(false);
  // Blocked storage: nothing held, nothing to remove.
  expect(retire(null, REC, notice('upgrade', 'de.json', NOW))).toBe(true);
});

test('api_013 code that never arrives gives the usual language in time', async () => {
  // An import cannot be aborted: the checking code, and the pack's code itself, are given up when the page load's
  // time runs out, so a chunk request that stalls never keeps the page from being drawn (review part A of T29.3,
  // finding 6).
  const never = () => new Promise<never>(() => {});
  const s = holding(JSON.stringify({ ...REC, fails: 1 }));
  const t0 = performance.now();
  const r = await decide(s.getItem(DEVPACK_KEY) ?? '', deps({ store: s, checker: never, signal: AbortSignal.timeout(50) }));
  expect([r.view.kind, r.choice]).toEqual(['unchecked', null]);
  expect(performance.now() - t0).toBeLessThan(2000);
  // Not the file's doing: not counted.
  expect(stored(s).fails).toBe(1);
  // The pack's code: the page load's language is chosen without it, the time a catalog has.
  let given: AbortSignal | undefined;
  const t1 = performance.now();
  const choice = await load({}, { search: '', stored: null, languages: ['de-DE'] }, fetch, 50, (signal) => {
    given = signal;
    return never();
  });
  expect(choice).toEqual({ tag: 'en' });
  expect(performance.now() - t1).toBeLessThan(2000);
  expect(given?.aborted).toBe(true);
});

test('api_013 a pack lookup never throws', () => {
  // A table of every kind of value, under the hashes of messages and plurals, and keys named like members.
  const odd: unknown[] = [1, null, true, [], {}, { one: 'x' }, { other: 3 }, { other: '{n}', one: {} }, { other: null }, 'x'.repeat(100_000), '\uD800', '{n} {n}', '<b>', '%s $1', ''];
  const table: Record<string, unknown> = Object.create(null);
  odd.forEach((v, i) => {
    table[hash('c', `m${i}`)] = v;
    table[hash('c', [`p${i}`, `ps${i}`])] = v;
  });
  for (const k of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) table[k] = { other: 'x' };
  under({ tag: 'de', table: table as never }, () => {
    const { t, tn } = tr('c');
    odd.forEach((_, i) => {
      expect(() => t(`m${i}` as never), `m${i}`).not.toThrow();
      for (const n of [0, 1, 2, 5, -1, 1.5, NaN]) expect(() => tn(`p${i}` as never, `ps${i}` as never, n, { n } as never), `p${i} ${n}`).not.toThrow();
    });
    expect(t('constructor' as never)).toBe('constructor');
    expect(tn('{n} file' as never, '{n} files' as never, 2, { n: 2 } as never)).toBe('2 files');
  });
  // And what a hostile file installs: every message of the template reads without a throw.
  const tpl = readTemplate(deJson());
  const hostile = { cache: [...tpl.entries.values()].filter((e) => e.ctx === 'cache').map((e) => [e.english, typeof e.english === 'string' ? `\u202E${'{x}'.repeat(50)}<b>` : { one: '\uD800', other: '{n}'.repeat(999) }]) };
  const r = checkPack(JSON.stringify(hostile), false, tpl, DE);
  under({ tag: 'de', table: (r.checked?.table ?? {}) as never }, () => {
    for (const e of tpl.entries.values()) {
      const b = tr(e.ctx as never);
      expect(() => (typeof e.english === 'string' ? b.t(e.english as never, {} as never) : b.tn(e.english[0] as never, e.english[1] as never, 3, { n: 3 } as never))).not.toThrow();
    }
  });
});
