// REQ: API-012 (ADR-189) — the languages tool (scripts/i18n.mjs and its library), without a browser,
// against the fixture project (tests/i18n-fixtures/project, with the made-up locale `qaa`) and the UI
// itself: canonical files, contexts, what fails and what is only reported, one recorded mistake per
// FAIL rule, the job summary, what ships, and the committed plural table.
import { expect, test } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fnv1a, hash } from '../../src/lib/i18n/ident';
import { tk, tr } from '../../src/lib/i18n';
import * as lib from '../../scripts/i18n-lib.mjs';
import { FIXTURE, UI, checkUi, cleanup, edit, failRules, fails, manifest, project, put, qaa, run, table, under, type Result } from './i18n-fixture';

test.afterAll(cleanup);

// ---------------------------------------------------------------------------------------------
// The hash the check and the runtime share


/** FNV-1a as ADR-189 specifies it, written out independently of `ident.ts`. */
function reference(context: string, english: string | [string, string], note: string | null): string {
  const norm = (s: string) =>
    s.normalize('NFC').replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/[–—]/g, '-').replace(/…/g, '...').replace(/\u00A0/g, ' ').replace(/\s+/g, ' ').trim();
  const e = typeof english === 'string' ? norm(english) : `${norm(english[0])}\u0005${norm(english[1])}`;
  const s = `${context}\u0004${e}${note ? `\u0004${note}` : ''}`;
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Number((BigInt((h ^ s.charCodeAt(i)) >>> 0) * 16777619n) % 4294967296n);
  return h.toString(16).padStart(8, '0');
}

test('api_012 the runtime and the script hash alike', () => {
  // Published FNV-1a 32-bit vectors.
  expect(fnv1a('')).toBe('811c9dc5');
  expect(fnv1a('a')).toBe('e40c292c');
  const vectors: [string, string | [string, string], string | null, string][] = [
    ['common', 'Save', null, '9a64712d'],
    ['cache', 'Holds', null, 'fca48263'],
    ['cache', 'Café', null, 'd6dab1c2'],
    ['cache', 'Café', null, 'd6dab1c2'],
    ['cache', 'It’s “done” – now…', null, 'ac71917f'],
    ['cache', 'It\'s "done" - now...', null, 'ac71917f'],
    ['cache', '  two\u00A0\u00A0 spaces\n', null, '33bdef96'],
    ['cache', 'two spaces', null, '33bdef96'],
    ['cache', 'Open', 'verb', '2e45320c'],
    ['cache', ['{n} answer', '{n} answers'], null, 'accd9147'],
  ];
  for (const [c, e, n, want] of vectors) {
    expect(hash(c, e, n ?? undefined), JSON.stringify(e)).toBe(want);
    expect(lib.hash(c, e, n ?? undefined), JSON.stringify(e)).toBe(want);
    expect(reference(c, e, n), JSON.stringify(e)).toBe(want);
  }
  expect(hash('cache', 'Open')).not.toBe(hash('cache', 'Open', 'verb'));
  expect(hash('cache', 'Holds')).not.toBe(hash('common', 'Holds'));
  expect(hash('cache', ['a', 'b'])).not.toBe(hash('cache', 'a b'));
});

// ---------------------------------------------------------------------------------------------
// The check script


test('api_012 catalogs are canonical', () => {
  // The UI's own data files.
  expect(fails(checkUi()).filter((f) => ['canonical', 'malformed', 'manifest', 'stray'].includes(f.rule))).toEqual([]);
  // The fixture's locale file is canonical, and writing it again gives the same bytes.
  const text = readFileSync(join(FIXTURE, 'src/locales/qaa.json'), 'utf8');
  expect(lib.serializeCatalog(JSON.parse(text))).toBe(text);
  expect(failRules(run(project()))).toEqual([]);
  const departures: [string, (s: string) => string][] = [
    ['a space inside a pair', (s) => s.replace('["Holds","Qa-holds-zeta"]', '["Holds", "Qa-holds-zeta"]')],
    ['pairs out of order', (s) => s.replace('    ["Choose email or ntfy","Qa-choose email / ntfy"],\n    ["Holds","Qa-holds-zeta"],', '    ["Holds","Qa-holds-zeta"],\n    ["Choose email or ntfy","Qa-choose email / ntfy"],')],
    ['contexts out of order', (s) => `{\n  "common": [\n    ["Save","Qa-save-omega"]\n  ],\n${s.slice(2, s.indexOf('  "common"')).replace(/],\n$/, ']\n')}}\n`],
    ['another indent', (s) => s.replace('\n    ["Holds"', '\n  ["Holds"')],
    ['no final newline', (s) => s.trimEnd()],
    ['a trailing comma', (s) => s.replace('["Save","Qa-save-omega"]\n', '["Save","Qa-save-omega"],\n')],
  ];
  for (const [name, change] of departures) {
    const r = run(project((d) => edit(d, 'src/locales/qaa.json', change)));
    expect(failRules(r).length, name).toBeGreaterThan(0);
    expect(['canonical', 'malformed'], name).toEqual(expect.arrayContaining(failRules(r)));
  }
  // A data file out of order.
  const r = run(project((d) => put(d, 'src/locales/glossary.json', '[\n  "ZZZ",\n  "AAA"\n]\n')));
  expect(failRules(r)).toEqual(['canonical']);
});

test('api_012 a file uses only its own context', () => {
  expect(failRules(run(project((d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("tr('cache')", "tr('labels')")))))).toEqual(['context']);
  expect(failRules(run(project((d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace('<T ctx="cache"', '<T ctx="labels"')))))).toEqual(['context']);
  expect(failRules(run(project((d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace('<T ctx="cache"', '<T ctx="common"')))))).toEqual(['context']);
  // Two files that map to one context name.
  const twin = "import { tr } from './i18n';\n\nexport function f(): string {\n  return tr('cache').t('Twin');\n}\n";
  expect(failRules(run(project((d) => put(d, 'src/lib/cache.ts', twin))))).toEqual(['context-collision']);
  // contexts.json gives the library file its own name.
  const named = "import { tr } from './i18n';\n\nexport function f(): string {\n  return tr('libCache').t('Twin');\n}\n";
  expect(
    failRules(
      run(
        project((d) => {
          put(d, 'src/lib/cache.ts', named);
          put(d, 'src/locales/contexts.json', lib.serializeJson({ 'lib/cache.ts': 'libCache' }));
        }),
      ),
    ),
  ).toEqual([]);
  // A label marked in one file is found in its own context wherever it is shown.
  under({ tag: 'qaa', table: table({ [hash('labels', 'Lists')]: 'Qa-lists' }) }, () => {
    const marked = tr('labels').m('Lists');
    expect(Object.isFrozen(marked)).toBe(true);
    expect(tk(marked)).toBe('Qa-lists');
    expect(tr('other').t('Lists')).toBe('Lists');
  });
});

test('api_012 an english-only change never fails a locale', () => {
  expect(failRules(run(project()))).toEqual([]);
  const changes: [string, (d: string) => void][] = [
    ['reworded', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("t('Holds')", "t('Holds now')"))],
    ['another URL', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace('https://example.com/docs', 'https://example.org/docs'))],
    ['a placeholder removed', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("t('Notify by {kind}', { kind: 'email' })", "t('Notify by mail')"))],
    ['a number changed', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace(':587', ':465'))],
    ['a message deleted', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("<p>{t('Choose email or ntfy')}</p>\n", ''))],
    ['a plural reworded', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("tn('{n} answer', '{n} answers'", "tn('{n} reply', '{n} replies'"))],
    ['a message added', (d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}<p>{t('Brand new')}</p>\n`)],
    ['a sentence reworded', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("msg={'Kept by <b>{who}</b>'}", "msg={'Kept for <b>{who}</b>'}"))],
  ];
  for (const [name, change] of changes) {
    const r = run(project(change));
    expect(fails(r).filter((f) => f.file.startsWith('src/locales/')), name).toEqual([]);
    expect(failRules(r), name).toEqual([]);
  }
});

test('api_012 missing and outdated translations are reported not failed', () => {
  const r = run(project((d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("t('Holds')", "t('Holds today')"))));
  expect(failRules(r)).toEqual([]);
  const missing = r.findings.find((f) => f.rule === 'missing');
  expect(missing?.level).toBe('report');
  expect(missing?.values).toEqual(expect.arrayContaining(['cache: Holds today', 'labels: Lists']));
  const left = r.findings.filter((f) => f.rule === 'left-over');
  expect(left.map((f) => f.level)).toEqual(['report']);
  expect(left[0].values).toEqual(['Holds', 'nearest now: Holds today']);
  // Neither the outdated pair nor anything for the new English is shipped; the rest is.
  const shipped = JSON.parse(r.shipped.qaa.json);
  expect(Object.values(shipped)).not.toContain('Qa-holds-zeta');
  expect(shipped[hash('common', 'Save')]).toBe('Qa-save-omega');
  expect(shipped[hash('cache', ['{n} answer', '{n} answers'])]).toEqual({ other: '{n} qa-answers' });
  expect(r.findings.find((f) => f.rule === 'coverage')?.msg).toMatch(/^"qaa": 7 of 9 messages .*owners: example-owner$/);
  // An empty translation is "not translated yet": missing, not a failure.
  const empty = run(project((d) => qaa(d, (c) => (c.common = [['Save', '']]))));
  expect(failRules(empty)).toEqual([]);
  expect(empty.findings.find((f) => f.rule === 'missing')?.values).toContain('common: Save');
  // sync adds the missing messages and moves the left-over pair aside.
  const dir = project((d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("t('Holds')", "t('Holds today')")));
  lib.sync(dir, 'qaa');
  const synced = JSON.parse(readFileSync(join(dir, 'src/locales/qaa.json'), 'utf8'));
  expect(synced['~leftover']).toEqual([['Holds', 'Qa-holds-zeta']]);
  expect(synced.cache).toContainEqual(['Holds today', '']);
  expect(synced.labels).toEqual([['Lists', '']]);
  expect(failRules(run(dir))).toEqual([]);
  // carry keeps a translation through an English edit that keeps the meaning.
  const carried = project((d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("t('Holds')", "t('Holds now')")));
  expect(lib.carry(carried, 'cache', 'Holds', 'Holds now')).toBe(2); // the locale file and notes.json
  expect(JSON.parse(run(carried).shipped.qaa.json)[hash('cache', 'Holds now')]).toBe('Qa-holds-zeta');
});

test('api_012 sensitive changes and swaps are reported against the previous version', () => {
  const before = readFileSync(join(FIXTURE, 'src/locales/qaa.json'), 'utf8');
  const r = run(
    project((d) => qaa(d, (c) => ((c.cache as [string, string][]).find((p) => p[0] === 'Holds')![1] = 'Qa-save-omega'))),
    { previous: { qaa: before } },
  );
  expect(failRules(r)).toEqual([]);
  expect(r.findings.filter((f) => f.rule === 'sensitive').map((f) => f.values)).toEqual([['Holds']]);
  expect(r.findings.filter((f) => f.rule === 'swap').map((f) => f.values)).toEqual([['Holds', 'Save']]);
  expect(run(project(), { previous: null }).findings.filter((f) => f.rule === 'not-checked')).toHaveLength(1);
  expect(run(project(), { previous: { qaa: before } }).findings.filter((f) => ['sensitive', 'swap', 'not-checked'].includes(f.rule))).toEqual([]);
});

test('api_012 a plural form other than other may hold fewer placeholders', () => {
  const plural = (forms: Record<string, string>) =>
    project((d) => {
      put(d, 'src/locales/plurals.json', lib.serializeJson({ qaa: ['one', 'other'] }));
      qaa(d, (c) => (c.cache[c.cache.length - 1] = [['{n} answer', '{n} answers'], forms]));
    });
  const fine = run(plural({ one: 'Qa one answer', other: '{n} qa-answers' }));
  expect(failRules(fine)).toEqual([]);
  expect(JSON.parse(fine.shipped.qaa.json)[hash('cache', ['{n} answer', '{n} answers'])]).toEqual({ one: 'Qa one answer', other: '{n} qa-answers' });
  // Never a placeholder the English lacks, and `other` keeps every one.
  expect(failRules(run(plural({ one: '{n} {x} qa', other: '{n} qa-answers' })))).toEqual(['agreement']);
  expect(failRules(run(plural({ one: '{n} qa', other: 'qa-answers' })))).toEqual(['agreement']);
});

test('api_012 an added-token exemption in notes.json reports what it lets through', () => {
  const midnight = (exempt: unknown, tx = 'Qa-bis 24:00') =>
    project((d) => {
      edit(d, 'src/pages/Cache.svelte', (s) => `${s}<p>{t('Until midnight')}</p>\n`);
      qaa(d, (c) => c.cache.push(['Until midnight', tx]));
      if (exempt !== undefined) {
        const notes = JSON.parse(readFileSync(join(d, 'src/locales/notes.json'), 'utf8'));
        notes.cache.push(['Until midnight', { exemptAdded: exempt, text: 'a 24-hour time, as the language writes midnight' }]);
        put(d, 'src/locales/notes.json', lib.serializeCatalog(notes, 'data'));
      }
    });
  const plain = run(midnight(undefined));
  expect(failRules(plain)).toEqual(['agreement']);
  expect(fails(plain).map((f) => f.check)).toEqual(['structural']);
  const exempt = run(midnight(['24:00']));
  expect(failRules(exempt)).toEqual([]);
  expect(exempt.findings.filter((f) => f.rule === 'agreement-added').map((f) => f.values?.at(-1))).toContain('24:00');
  expect(JSON.parse(exempt.shipped.qaa.json)[hash('cache', 'Until midnight')]).toBe('Qa-bis 24:00');
  // The exemption names the tokens it allows: another language's added address still fails.
  const other = run(midnight(['24:00'], 'Qa-bis 24:00 8.8.8.8'));
  expect(failRules(other)).toEqual(['agreement']);
  expect(fails(other).map((f) => [f.check, f.values?.at(-1)])).toEqual([['structural', '8.8.8.8']]);
  expect(JSON.parse(other.shipped.qaa.json)[hash('cache', 'Until midnight')]).toBeUndefined();
  // It is a list of tokens: a reason alone, or an empty list, exempts nothing and is malformed.
  for (const bad of ['a 24-hour time', [], [''], true]) expect(failRules(run(midnight(bad))), JSON.stringify(bad)).toEqual(['agreement', 'malformed']);
  // A note has these four fields only.
  const odd = run(
    project((d) => {
      const notes = JSON.parse(readFileSync(join(d, 'src/locales/notes.json'), 'utf8'));
      notes.cache[0][1].exemptEverything = true;
      put(d, 'src/locales/notes.json', lib.serializeCatalog(notes, 'data'));
    }),
  );
  expect(failRules(odd)).toEqual(['malformed']);
});

const random = (n: number, seed: number) => {
  let x = seed;
  return Array.from({ length: n }, () => String.fromCharCode(97 + ((x = (Math.imul(x, 1103515245) + 12345) >>> 0) >>> 8) % 26)).join('');
};
const LONG = "<script lang=\"ts\">\n  import { tr } from '../lib/i18n';\n  const { t } = tr('long');\n</script>\n\n<p>{t('Long')}</p>\n";
const holds = (d: string, tx: string) => qaa(d, (c) => ((c.cache as [string, string][]).find((p) => p[0] === 'Holds')![1] = tx));
/** Gives a language plural rules in the fixture's table, so a manifest case trips only its own rule. */
const withPlurals = (d: string, lang: string, cats: string[]) =>
  put(d, 'src/locales/plurals.json', lib.serializeJson({ ...JSON.parse(readFileSync(join(d, 'src/locales/plurals.json'), 'utf8')), [lang]: cats }));

/** One recorded change per FAIL rule of ADR-189's check, each on its own copy of the fixture; for
 * the agreement rule, also the check inside it that must fail. */
const MISTAKES: [string, string, (d: string) => void, string?][] = [
  ['a top-level t() in a .ts module', 'top-level', (d) => put(d, 'src/lib/top.ts', "import { tr } from './i18n';\n\nconst { t } = tr('top');\nexport const LABEL = t('Top');\n")],
  [
    'a t() at the top of <script module>',
    'top-level',
    (d) => put(d, 'src/pages/Mod.svelte', "<script module lang=\"ts\">\n  import { tr } from '../lib/i18n';\n  const { t } = tr('mod');\n  export const X = t('Module text');\n</script>\n"),
  ],
  ['a non-literal argument', 'non-literal', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("{t('Holds')}", "{t(n > 1 ? 'Holds' : 'Hold')}"))],
  ['a non-literal context', 'non-literal', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("tr('cache')", "tr(String('cache'))"))],
  ['a non-literal <T> message', 'non-literal', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("msg={'Kept by <b>{who}</b>'}", 'msg={who}'))],
  // In a quoted attribute Svelte substitutes {who} itself: the message would never be the literal.
  ['a <T> message Svelte would substitute', 'non-literal', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("msg={'Kept by <b>{who}</b>'}", 'msg="Kept by <b>{who}</b>"'))],
  ['a t() result as an {#each} key', 'misuse', (d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}{#each [1] as x (t('Holds'))}{x}{/each}\n`)],
  ['a t() result in href', 'misuse', (d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}<a href={t('Holds')}>{n}</a>\n`)],
  ['a t() result compared', 'misuse', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace('</script>', "  const same = t('Holds') === 'x';\n</script>"))],
  ['a t() result as a Map key', 'misuse', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace('</script>', "  new Map().set(t('Holds'), 1);\n</script>"))],
  ['a t() result stored', 'misuse', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace('</script>', "  localStorage.setItem('k', t('Holds'));\n</script>"))],
  ['tk() given an object literal', 'non-literal', (d) => edit(d, 'src/lib/labels.ts', (s) => `${s}\nexport function raw(e: string): string {\n  return tk({ c: 'labels', e });\n}\n`)],
  ['tk() given an object literal in a condition', 'non-literal', (d) => edit(d, 'src/lib/labels.ts', (s) => `${s}\nexport function raw(e: string): string {\n  return tk(e ? ({ c: 'labels', e } as never) : LISTS);\n}\n`)],
  ['tk() given a variable made from an object literal', 'non-literal', (d) => edit(d, 'src/lib/labels.ts', (s) => `${s}\nexport function raw(e: string): string {\n  const made = { c: 'labels', e };\n  return tk(<never>made!);\n}\n`)],
  ['a manifest with parent', 'manifest', (d) => manifest(d, (m) => (m.qaa.parent = 'en'))],
  ['a manifest with regions', 'manifest', (d) => manifest(d, (m) => (m.qaa.regions = ['419']))],
  // (A file not on the layer, so only the map's own rule can trip.)
  ['a contexts.json name that is not a name', 'context', (d) => put(d, 'src/locales/contexts.json', lib.serializeJson({ 'pages/Old.svelte': 'Not-a-name' }))],
  ['a manifest entry without owners', 'manifest', (d) => manifest(d, (m) => (m.qaa.owners = []))],
  ['an offered right-to-left language', 'manifest', (d) => manifest(d, (m) => Object.assign(m.qaa, { dir: 'rtl', offered: true }))],
  [
    'a bare zh catalog',
    'manifest',
    (d) => {
      manifest(d, (m) => (m.zh = { dir: 'ltr', offered: false, owners: ['example-owner'], since: '0.9.0' }));
      put(d, 'src/locales/zh.json', '{\n}\n');
      withPlurals(d, 'zh', ['other']);
    },
  ],
  [
    'a regional English catalog',
    'manifest',
    (d) => {
      manifest(d, (m) => (m['en-GB'] = { ...m.qaa }));
      put(d, 'src/locales/en-GB.json', '{\n}\n');
      withPlurals(d, 'en', ['one', 'other']);
    },
  ],
  ['a data file missing', 'manifest', (d) => rmSync(join(d, 'src/locales/glossary.json'))],
  ['a stray file in locales/', 'stray', (d) => put(d, 'src/locales/README.md', 'notes\n')],
  ['a locale context that is not a context name', 'context', (d) => qaa(d, (c) => (c['Bad\n::error title=x::boom'] = [['Holds', 'Qa']]))],
  ['a hash collision', 'hash-collision', (d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}<p>{t('Item wfpmrfbz')}{t('Item xygculea')}</p>\n`)],
  ['a non-canonical locale file', 'canonical', (d) => edit(d, 'src/locales/qaa.json', (s) => s.replace('["Holds","Qa-holds-zeta"]', '["Holds", "Qa-holds-zeta"]'))],
  ['a malformed pair', 'malformed', (d) => qaa(d, (c) => c.cache.push(['Lone']))],
  ['the same English twice in a context', 'malformed', (d) => qaa(d, (c) => c.cache.push(['Holds', 'Qa-holds-again']))],
  ['plural categories other than the language has', 'plural-categories', (d) => qaa(d, (c) => (c.cache[c.cache.length - 1] = [['{n} answer', '{n} answers'], { one: '{n} qa-answer', other: '{n} qa-answers' }]))],
  ['a pair that disagrees with its English', 'agreement', (d) => edit(d, 'src/locales/qaa.json', (s) => s.replace('Qa-read https://example.com/docs.', 'Qa-read https://evil.example/docs.')), 'urls'],
  ['a forbidden code point', 'agreement', (d) => holds(d, 'Qa-holds\u202E-zeta'), 'code-point'],
  ['a tag character', 'agreement', (d) => holds(d, 'Qa-holds\u{E0041}-zeta'), 'code-point'],
  ['an address in fullwidth letters', 'agreement', (d) => holds(d, 'Qa-holds ｈｔｔｐｓ：／／ｅｖｉｌ．ｅｘａｍｐｌｅ'), 'urls'],
  ['an address in capitals', 'agreement', (d) => holds(d, 'Qa-holds HTTPS://evil.example'), 'urls'],
  ['an address the English does not have', 'agreement', (d) => holds(d, 'Qa-holds 8.8.8.8'), 'structural'],
  ['a key twice in a locale file', 'malformed', (d) => edit(d, 'src/locales/qaa.json', (s) => s.replace('  "common": [', '  "cache": [\n  ],\n  "common": ['))],
  ['a language without plural rules in the table', 'manifest', (d) => put(d, 'src/locales/plurals.json', '{\n  "zz": [\n    "other"\n  ]\n}\n')],
  ['a verbatim word renamed', 'agreement', (d) => edit(d, 'src/locales/qaa.json', (s) => s.replace('Qa-choose email / ntfy', 'Qa-choose courriel / ntfy')), 'verbatim'],
  ['a plural whose English forms name different placeholders', 'plural-forms', (d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}<p>{tn('One file', '{n} files', n, { n })}</p>\n`)],
  [
    'more than 40 common messages',
    'common-size',
    (d) =>
      put(
        d,
        'src/lib/many.ts',
        `import { tr } from './i18n';\n\nconst { t: tc } = tr('common');\n\nexport function all(): string[] {\n  return [${Array.from({ length: 40 }, (_, i) => `tc('Action ${i}')`).join(', ')}];\n}\n`,
      ),
  ],
  [
    'a language over its size',
    'size',
    (d) => {
      put(d, 'src/pages/Long.svelte', LONG);
      qaa(d, (c) => (c.long = [['Long', random(170_000, 7)]]));
    },
  ],
  ['literal text in a file that holds none', 'literal-text', (d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}<p>Plain words</p>\n`)],
  [
    // Six languages of about 73 KiB each: each within its 80 KiB, together over 400.
    'all languages over their size',
    'size',
    (d) => {
      const tags = ['qaa', 'qab', 'qac', 'qad', 'qae', 'qaf'];
      const big = random(125_000, 11);
      put(d, 'src/pages/Long.svelte', LONG);
      put(d, 'src/locales/plurals.json', lib.serializeJson(Object.fromEntries(tags.map((t) => [t, ['other']]))));
      manifest(d, (m) => {
        for (const t of tags.slice(1)) m[t] = { ...m.qaa };
      });
      qaa(d, (c) => (c.long = [['Long', big]]));
      for (const t of tags.slice(1)) put(d, `src/locales/${t}.json`, lib.serializeCatalog({ long: [['Long', big]] }));
    },
  ],
  ['an Intl call in a file on the layer', 'intl', (d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace('</script>', '  const f = new Intl.NumberFormat();\n</script>'))],
  // A file whose baseline allows its Intl call moves to the layer and keeps it: only the layer's rule trips.
  ['a file on the layer that keeps its Intl call', 'intl', (d) => edit(d, 'src/pages/Old.svelte', (s) => s.replace('<script lang="ts">\n', "<script lang=\"ts\">\n  import { tr } from '../lib/i18n';\n  const { t } = tr('old');\n"))],
  ['a new physical CSS property', 'physical-css', (d) => edit(d, 'src/pages/Old.svelte', (s) => s.replace('margin-left: 4px;', 'margin-left: 4px;\n    padding-right: 1px;'))],
];

test('api_012 the check sees each mistake it is for', () => {
  // The fixture project and the UI itself pass.
  expect(failRules(run(project()))).toEqual([]);
  expect(fails(checkUi())).toEqual([]);
  // Soft, so a run without one of the rules names every mistake it then misses.
  for (const [name, rule, change, inner] of MISTAKES) {
    const r = run(project(change));
    expect.soft(failRules(r), name).toEqual([rule]);
    if (inner) expect.soft(fails(r).map((f) => f.check), name).toContain(inner);
  }
  // A pair whose English only hashes like a current message is left over: reported, never shipped.
  const r = run(
    project((d) => {
      edit(d, 'src/pages/Cache.svelte', (s) => `${s}<p>{t('Item wfpmrfbz')}</p>\n`);
      qaa(d, (c) => c.cache.push(['Item xygculea', 'Qa-item-sigma']));
    }),
  );
  expect(hash('cache', 'Item wfpmrfbz')).toBe(hash('cache', 'Item xygculea'));
  expect(failRules(r)).toEqual([]);
  expect(r.findings.filter((f) => f.rule === 'left-over').map((f) => f.values?.[0])).toEqual(['Item xygculea']);
  expect(r.shipped.qaa.json).not.toContain('Qa-item-sigma');
});

test('api_012 the tk() lint reads a name where it is declared', () => {
  const scoped = (body: string) => run(project((d) => edit(d, 'src/lib/labels.ts', (s) => `${s}\n${body}`)));
  // A parameter named like another function's object literal is not that object.
  expect(failRules(scoped("export function show(label: typeof LISTS): string {\n  return tk(label);\n}\n\nexport function other(): object {\n  const label = { c: 'labels', e: 'x' };\n  return label;\n}\n"))).toEqual([]);
  // Nor is a variable of an inner block the call cannot see.
  expect(failRules(scoped("export function a(): string {\n  const label = LISTS;\n  {\n    const label = { c: 'labels', e: 'x' };\n    void label;\n  }\n  return tk(label);\n}\n"))).toEqual([]);
  // The nearest declaration counts: an object literal that shadows a module's label still fails.
  expect(failRules(scoped("export function b(): string {\n  const label = { c: 'labels', e: 'x' } as never;\n  return tk(label);\n}\nconst label = LISTS;\nvoid label;\n"))).toEqual(['non-literal']);
});

test('api_012 the shipping step reports structured findings', () => {
  // What the check reports for a locale is built from findings with the token and its place.
  const dir = project((d) => edit(d, 'src/locales/qaa.json', (s) => s.replace('Qa-read https://example.com/docs.', 'Qa-read https://evil.example/docs.')));
  const s = lib.ship(JSON.parse(readFileSync(join(dir, 'src/locales/qaa.json'), 'utf8')), run(dir).entries ?? new Map(), {});
  const urlFindings = s.findings.filter((f: { check?: string }) => f.check === 'urls');
  expect(urlFindings.map((f: { token: string; detail: string }) => [f.token, f.detail])).toEqual([
    ['https://example.com/docs', 'missing'],
    ['https://evil.example/docs', 'added'],
  ]);
});

test('api_012 the job summary prints no catalog value outside a fence', () => {
  const evil = '**Qa** [x](https://evil.example) <img src=x> ``` `x` ````';
  const dir = project((d) => edit(d, 'src/locales/qaa.json', (s) => s.replace('Qa-holds-zeta', evil.replace(/"/g, '\\"'))));
  const r = run(dir, { previous: { qaa: readFileSync(join(FIXTURE, 'src/locales/qaa.json'), 'utf8') } });
  expect(failRules(r)).toEqual(['agreement']);
  const md: string = lib.summaryMarkdown(r);
  expect(md).toContain('evil.example');
  // Remove every fenced block (a fence closes only on a line of the same backticks).
  const outside = md.replace(/^(`{3,})text\n[\s\S]*?\n\1$/gm, '');
  expect(outside).not.toContain('`');
  const cat = JSON.parse(readFileSync(join(dir, 'src/locales/qaa.json'), 'utf8')) as Record<string, [unknown, unknown][]>;
  const values = Object.values(cat).flatMap((pairs) => pairs.flatMap(([e, tx]) => [e, tx].flatMap((v) => (typeof v === 'string' ? [v] : Object.values(v as object)))));
  expect(values).toContain(evil);
  for (const v of values as string[]) for (const piece of [v, ...v.split(/\s+/).filter((w) => w.length >= 5)]) expect(outside, piece).not.toContain(piece);
});

test('api_012 the console report prints no line a file controls', () => {
  const r = run(project((d) => qaa(d, (c) => (c['x\n::error title=t::boom'] = [['Holds', 'Qa']]))));
  expect(failRules(r)).toEqual(['context']);
  const out: string = lib.formatReport(r);
  expect(out.split('\n').filter((l) => /^\s*::/.test(l))).toEqual([]);
  expect(out).toContain('"x\\n::error title=t::boom" is not a context name');
  // Every key a file names is printed the same way: a manifest field, a contexts.json path, a
  // context in <T ctx> and a file's own context.
  const keys = run(
    project((d) => {
      manifest(d, (m) => (m.qaa['f\n::error::k'] = 1));
      put(d, 'src/locales/contexts.json', lib.serializeJson({ 'p\n::error::q': 'pq' }));
      edit(d, 'src/pages/Cache.svelte', (s) => `${s}<T ctx='a"b' msg={'Kept'} />\n`);
      put(d, 'src/pages/Q"t.svelte', "<script lang=\"ts\">\n  import { tr } from '../lib/i18n';\n  const { t } = tr('qt');\n</script>\n\n<p>{t('Q')}</p>\n");
    }),
  );
  const msgs = keys.findings.map((f) => f.msg);
  expect(msgs).toContain('"qaa": unknown field "f\\n::error::k"');
  expect(msgs).toContain('"p\\n::error::q" is not a source file');
  expect(msgs.filter((m) => m.startsWith('<T ctx='))).toEqual(['<T ctx="a\\"b">: a file uses its own context ("cache")']);
  expect(msgs.filter((m) => m.includes("cannot be a file's context"))).toEqual(['"q\\"t" cannot be a file\'s context: add the file to src/locales/contexts.json']);
});

test('api_012 prebuild writes the shipped catalogs and the url table', () => {
  const dir = project();
  expect(lib.prebuild(dir)).toBe(1);
  const out = join(dir, 'public/assets/locales');
  const names = readdirSync(out);
  expect(names).toHaveLength(1);
  expect(names[0]).toMatch(/^qaa-[0-9a-f]{8}\.json$/);
  const shipped = JSON.parse(readFileSync(join(out, names[0]), 'utf8'));
  expect(Object.keys(shipped).every((k) => /^[0-9a-f]{8}$/.test(k))).toBe(true);
  expect(JSON.stringify(shipped)).not.toContain('Holds'); // no English
  const gen = readFileSync(join(dir, 'src/lib/i18n/locales.gen.ts'), 'utf8');
  expect(gen).toContain(`"qaa": { url: "/assets/locales/${names[0]}", dir: "ltr", offered: false }`);
  // No locale: an empty table and no folder.
  manifest(dir, (m) => delete m.qaa);
  rmSync(join(dir, 'src/locales/qaa.json'));
  expect(lib.prebuild(dir)).toBe(0);
  expect(existsSync(out)).toBe(false);
  expect(readFileSync(join(dir, 'src/lib/i18n/locales.gen.ts'), 'utf8')).toContain('Object.assign(Object.create(null), {})');
  // It lists what it wrote, for postbuild.
  const listed = project();
  lib.prebuild(listed);
  const emitted = JSON.parse(readFileSync(join(listed, 'src/lib/i18n/emitted.gen.json'), 'utf8'));
  expect(emitted).toEqual([{ file: readdirSync(join(listed, 'public/assets/locales'))[0], tag: 'qaa' }]);
  // Generation needs only what it ships: a broken ratchet baseline fails the check, never dev or build.
  const broken = project((d) => put(d, 'i18n-baseline.json', '{ "literal": '));
  expect(lib.prebuild(broken)).toBe(1);
  expect(failRules(run(broken))).toEqual(['malformed']);
});

test('api_012 check and sync take plural categories from the committed table', () => {
  // The UI's table: committed, canonical, and with English in it.
  const plurals = JSON.parse(readFileSync(join(UI, 'src/locales/plurals.json'), 'utf8'));
  expect(plurals.en).toEqual(['one', 'other']);
  expect(plurals.ja).toEqual(['other']);
  expect(Object.keys(plurals).length).toBeGreaterThan(100);
  // Neither the check nor sync asks the JavaScript engine.
  const real = Intl.PluralRules;
  const dir = project((d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace("t('Holds')", "t('Holds today')")));
  let r: Result;
  (Intl as { PluralRules: unknown }).PluralRules = function () {
    throw new Error('the engine was asked for plural rules');
  };
  try {
    r = run(dir);
    lib.sync(dir, 'qaa');
  } finally {
    (Intl as { PluralRules: unknown }).PluralRules = real;
  }
  expect(failRules(r)).toEqual([]);
  // The fixture's table says qaa has `other` only, so a plural is written with that category alone.
  expect(JSON.parse(readFileSync(join(dir, 'src/locales/qaa.json'), 'utf8')).cache).toContainEqual([['{n} answer', '{n} answers'], { other: '{n} qa-answers' }]);
  // A language the table lacks is refused, by the check and by sync.
  const missing = project((d) => put(d, 'src/locales/plurals.json', '{\n  "zz": [\n    "other"\n  ]\n}\n'));
  expect(fails(run(missing)).map((f) => f.msg).join('\n')).toContain('ask a maintainer to add the language');
  expect(() => lib.sync(missing, 'qaa')).toThrow('ask a maintainer to add the language');
});

test('api_012 the ui ships no language yet', () => {
  // The made-up locale lives in the fixtures only; the UI's manifest lists no language.
  expect(existsSync(join(UI, 'src/locales/qaa.json'))).toBe(false);
  expect(JSON.parse(readFileSync(join(UI, 'src/locales/manifest.json'), 'utf8'))).toEqual({});
});

test('api_012 the languages tool says which node it needs', () => {
  const r = spawnSync(process.execPath, ['--no-experimental-strip-types', join(UI, 'scripts/i18n.mjs'), 'check'], { encoding: 'utf8' });
  expect(r.status).toBe(2);
  expect(r.stderr).toContain('needs Node 24');
});

test('api_012 npm runs the generation step inside its scripts', () => {
  // Inside the scripts themselves, where `ignore-scripts` cannot skip it, and once: no `pre` script.
  const scripts = JSON.parse(readFileSync(join(UI, 'package.json'), 'utf8')).scripts;
  for (const s of ['dev', 'build', 'check', 'test:e2e']) {
    expect(scripts[s], s).toMatch(/^node scripts\/i18n\.mjs prebuild && /);
    expect(scripts[`pre${s}`], `pre${s}`).toBeUndefined();
  }
});
