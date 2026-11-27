// REQ: API-012 (ADR-189) — the text ratchets (literal text, Intl outside lib/format.ts, physical CSS),
// without a browser: the UI holds to its baseline (i18n-baseline.json), a file the baseline does not
// list holds none of the three, and each rule fails on a fixture made to trip it.
import { expect, test } from '@playwright/test';
import { mkdirSync, readFileSync, renameSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import * as lib from '../../scripts/i18n-lib.mjs';
import { UI, checkUi, cleanup, edit, failRules, fails, project, put, run, uiCopy, type Result } from './i18n-fixture';

test.afterAll(cleanup);

const total = (o: Record<string, number>) => Object.values(o).reduce((a, b) => a + b, 0);

/** What these tests require of a tree, as a list of problems (empty: green). */
function ratchetProblems(root: string, r: Result): string[] {
  const out = fails(r)
    .filter((f) => ['literal-text', 'intl', 'physical-css', 'malformed'].includes(f.rule))
    .map((f) => `${f.rule} ${f.file}: ${f.msg}`);
  const base = JSON.parse(readFileSync(join(root, 'i18n-baseline.json'), 'utf8'));
  // Over the files the baseline lists, Intl calls and physical properties never grow.
  const now = lib.ratchetCounts(root, r.files);
  for (const kind of ['intl', 'physical'] as const) {
    const listed = Object.fromEntries(Object.entries(now[kind] as Record<string, number>).filter(([rel]) => Object.hasOwn(base[kind], rel)));
    if (total(listed) > total(base[kind])) out.push(`${kind}: ${total(listed)}, the baseline's ${total(base[kind])}`);
  }
  return out;
}

test('api_012 only format.ts formats', () => {
  const r = checkUi();
  expect(fails(r).filter((f) => f.rule === 'intl')).toEqual([]);
  expect(ratchetProblems(UI, r)).toEqual([]);
  const base = JSON.parse(readFileSync(join(UI, 'i18n-baseline.json'), 'utf8'));
  const now = lib.ratchetCounts(UI, r.files).intl as Record<string, number>;
  console.log(`Intl/toLocale call sites outside format.ts: ${total(now)} in ${Object.values(now).filter((n) => n > 0).length} files (baseline ${total(base.intl)})`);
  // The end of part A: no file outside format.ts has one, and the baseline allows none anywhere.
  expect(Object.entries(now).filter(([, n]) => n > 0)).toEqual([]);
  expect(Object.entries(base.intl as Record<string, number>).filter(([, n]) => n > 0)).toEqual([]);
  // Growth fails; a file on the layer is at zero; format.ts itself is the place for it.
  expect(failRules(run(project((d) => edit(d, 'src/pages/Old.svelte', (s) => s.replace('</script>', '  const n = (1).toLocaleString();\n</script>')))))).toEqual(['intl']);
  expect(failRules(run(project((d) => edit(d, 'src/lib/labels.ts', (s) => `${s}\nexport const nf = new Intl.NumberFormat();\n`))))).toEqual(['intl']);
  expect(failRules(run(project((d) => put(d, 'src/lib/format.ts', 'export const nf = new Intl.NumberFormat();\n'))))).toEqual([]);
  // A file the baseline does not list (new or moved since) holds none: its call fails.
  const fresh = run(project((d) => put(d, 'src/lib/fresh.ts', 'export const nf = new Intl.NumberFormat();\n')));
  expect(failRules(fresh)).toEqual(['intl']);
  expect(fresh.findings.filter((f) => f.file === 'src/lib/fresh.ts').map((f) => `${f.level} ${f.rule}`)).toEqual(['fail intl']);
  // A file whose baseline allows its call moves to the layer: it must be at zero, growth or not.
  const old = run(project((d) => edit(d, 'src/pages/Old.svelte', (s) => s.replace('<script lang="ts">\n', "<script lang=\"ts\">\n  import { tr } from '../lib/i18n';\n  const { t } = tr('old');\n"))));
  expect(failRules(old)).toEqual(['intl']);
  expect(fails(old).map((f) => f.msg)).toEqual(['a file on the translation layer formats through lib/format.ts only']);
});

test('api_012 migrated files hold no literal text', () => {
  const r = checkUi();
  expect(fails(r).filter((f) => f.rule === 'literal-text')).toEqual([]);
  const counts = lib.ratchetCounts(UI, r.files).literal as Record<string, number>;
  const above = Object.entries(counts).filter(([, n]) => n > 0);
  console.log(`files above 0 (moved to the layer in their own batch): ${above.length}\n${above.map(([f, n]) => `  ${f} ${n}`).join('\n')}`);
  expect(ratchetProblems(UI, r)).toEqual([]);
  // A file at zero fails on any literal text; a file above zero is only printed.
  expect(failRules(run(project((d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}<p>Plain words</p>\n`))))).toEqual(['literal-text']);
  expect(failRules(run(project((d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}<input placeholder="Search" />\n`))))).toEqual(['literal-text']);
  // A file the baseline does not list (new since) holds none either.
  const fresh = run(project((d) => put(d, 'src/pages/New.svelte', '<h1>A new page</h1>\n')));
  expect(failRules(fresh)).toEqual(['literal-text']);
  expect(fresh.findings.filter((f) => f.rule === 'literal-text' && f.file === 'src/pages/New.svelte').map((f) => f.level)).toEqual(['fail']);
  expect(failRules(run(project((d) => edit(d, 'src/pages/Old.svelte', (s) => `${s}\n<p>More words</p>\n`))))).toEqual([]);
  // Data marked translate="no", and text without letters, are not literal text.
  expect(failRules(run(project((d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}<p translate="no">example.com</p>\n<p>· — (42)</p>\n`))))).toEqual([]);
});

test('api_012 a new removed or renamed file leaves the ratchets green', () => {
  const r0 = checkUi();
  expect(ratchetProblems(UI, r0)).toEqual([]);
  // Two small files the test makes in each copy of the UI: one with an Intl call and one with a physical
  // property, both listed in the copy's baseline with their count. What the cases prove (a removed file leaves
  // the ratchets green; a moved file keeps its count only when its baseline entries are renamed) does not
  // depend on which real files still hold one.
  const moved = 'pages/Holds.svelte';
  const removed = 'pages/Edge.svelte';
  const fixture = (d: string) => {
    put(d, `src/${moved}`, '<script lang="ts">\n  const n = (1).toLocaleString();\n</script>\n');
    put(d, `src/${removed}`, '<div></div>\n<style>\n  div {\n    margin-left: 4px;\n  }\n</style>\n');
    const base = JSON.parse(readFileSync(join(d, 'i18n-baseline.json'), 'utf8'));
    base.intl[moved] = 1;
    base.physical[removed] = 1;
    base.literal[moved] = 0;
    base.literal[removed] = 0;
    put(d, 'i18n-baseline.json', `${JSON.stringify(base, null, 2)}\n`);
  };
  const d0 = uiCopy(fixture);
  const r1 = run(d0);
  expect(ratchetProblems(d0, r1), 'the two files').toEqual([]);
  const now = lib.ratchetCounts(d0, r1.files);
  expect([now.intl[moved], now.physical[removed]], 'counted').toEqual([1, 1]);
  const cases: [string, (d: string) => void][] = [
    ['a new file without text', (d) => put(d, 'src/lib/components/Spark.svelte', '<svg viewBox="0 0 8 8"><path d="M0 8 L8 0" /></svg>\n')],
    [`${removed} removed`, (d) => rmSync(join(d, 'src', removed))],
  ];
  for (const [name, change] of cases) {
    const d = uiCopy((x) => {
      fixture(x);
      change(x);
    });
    expect(ratchetProblems(d, run(d)), name).toEqual([]);
  }
  // A moved file that still holds a call keeps its count only when its baseline entries are renamed to the new path.
  const to = `moved/${moved}`;
  const move = (d: string) => {
    mkdirSync(dirname(join(d, 'src', to)), { recursive: true });
    renameSync(join(d, 'src', moved), join(d, 'src', to));
  };
  const unrenamed = uiCopy((x) => {
    fixture(x);
    move(x);
  });
  expect(ratchetProblems(unrenamed, run(unrenamed)), `${moved} moved to another folder`).toEqual([expect.stringContaining(`intl ${`src/${to}`}`)]);
  const renamed = uiCopy((x) => {
    fixture(x);
    move(x);
    const base = JSON.parse(readFileSync(join(x, 'i18n-baseline.json'), 'utf8'));
    for (const kind of ['intl', 'literal', 'physical'] as const) {
      if (Object.hasOwn(base[kind], moved)) {
        base[kind][to] = base[kind][moved];
        delete base[kind][moved];
      }
    }
    put(x, 'i18n-baseline.json', `${JSON.stringify(base, null, 2)}\n`);
  });
  expect(ratchetProblems(renamed, run(renamed)), `${moved} moved, its baseline entries renamed`).toEqual([]);
  // A new file with text fails.
  const d = uiCopy((x) => put(x, 'src/pages/Spare.svelte', '<h1>A new page</h1>\n<p>With words.</p>\n'));
  const r = run(d);
  expect(ratchetProblems(d, r)).toEqual([expect.stringContaining('literal-text src/pages/Spare.svelte')]);
  expect(r.findings.filter((f) => f.file === 'src/pages/Spare.svelte').map((f) => `${f.level} ${f.rule}`)).toEqual(['fail literal-text']);
});

test('api_012 the baseline command lowers counts and never raises one', () => {
  const was = JSON.parse(readFileSync(join(project(), 'i18n-baseline.json'), 'utf8'));
  const d = project((x) => {
    edit(x, 'src/pages/Old.svelte', (s) => s.replace('margin-left: 4px;', 'margin-inline-start: 4px;'));
    edit(x, 'src/pages/Cache.svelte', (s) => `${s}<p>Plain words</p>\n`);
    put(x, 'src/pages/Blank.svelte', '<hr />\n');
    put(x, 'src/pages/Wordy.svelte', '<h1>A new page</h1>\n');
    rmSync(join(x, 'src/lib/labels.ts'));
  });
  const b = lib.baselineOf(d, run(d).files, was);
  // Lowered (Old's physical property), never raised (Cache), a new file at zero listed (Blank), a
  // new file above zero not listed (Wordy), a removed file dropped (labels.ts).
  expect(b.physical).toEqual({ 'pages/Blank.svelte': 0, 'pages/Cache.svelte': 0, 'pages/Old.svelte': 0, 'pages/Wordy.svelte': 0 });
  expect(b.literal).toEqual({ 'pages/Blank.svelte': 0, 'pages/Cache.svelte': 0, 'pages/Old.svelte': 2 });
  // With no baseline before it, every count is written.
  expect(lib.baselineOf(d, run(d).files, null).literal).toEqual({ 'pages/Blank.svelte': 0, 'pages/Cache.svelte': 1, 'pages/Old.svelte': 2, 'pages/Wordy.svelte': 1 });
});

test('api_012 the attributes a reader sees or hears are text', () => {
  expect(lib.TEXT_ATTRS).toEqual(['aria-label', 'title', 'placeholder', 'alt', 'aria-roledescription', 'aria-description', 'aria-valuetext', 'aria-placeholder']);
  for (const text of ['<div aria-roledescription="heatmap"></div>', '<div aria-description="Busy hours"></div>', '<div role="slider" aria-valuetext="Ten minutes"></div>', '<div aria-placeholder="Type a name"></div>', '<select><optgroup label="Lists"></optgroup></select>']) {
    expect(failRules(run(project((d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}${text}\n`)))), text).toEqual(['literal-text']);
  }
  // `label` is text on an <optgroup> only.
  expect(failRules(run(project((d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}<option label="x"></option>\n`))))).toEqual([]);
  // A literal text prop of a component is text too (a label, a title, an empty state, a noun, a summary, a hint, a
  // placeholder); an id, a kind, a tone, a path, a number, a value from the script, or one inside data are not.
  expect(lib.TEXT_PROPS).toEqual(['label', 'title', 'empty', 'noun', 'summary', 'hint', 'placeholder']);
  for (const prop of lib.TEXT_PROPS) expect(failRules(run(project((d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}<Card ${prop}="Nothing yet" />\n`)))), prop).toEqual(['literal-text']);
  for (const ok of ['<Card tone="warn" kind="block" id="top" path="/api/x" color="red" />', '<Card label={name} />', '<Card label="42" />', '<p translate="no"><Card label="Queries" /></p>', '<Card text="Nothing yet" />'])
    expect(failRules(run(project((d) => edit(d, 'src/pages/Cache.svelte', (s) => `${s}${ok}\n`)))), ok).toEqual([]);
});

test('api_012 no new physical css properties', () => {
  const r = checkUi();
  expect(fails(r).filter((f) => f.rule === 'physical-css')).toEqual([]);
  expect(ratchetProblems(UI, r)).toEqual([]);
  const base = JSON.parse(readFileSync(join(UI, 'i18n-baseline.json'), 'utf8'));
  const now = lib.ratchetCounts(UI, r.files).physical as Record<string, number>;
  console.log(`physical CSS properties: ${total(now)} in ${Object.values(now).filter((n) => n > 0).length} files (baseline ${total(base.physical)})`);
  expect(lib.physical('margin-left', '1px')).toBe(true);
  expect(lib.physical('border-top-right-radius', '2px')).toBe(true);
  expect(lib.physical('text-align', 'right')).toBe(true);
  expect(lib.physical('float', 'left')).toBe(true);
  expect(lib.physical('right', '0')).toBe(true);
  expect(lib.physical('text-align', 'start')).toBe(false);
  expect(lib.physical('margin-inline-start', '1px')).toBe(false);
  expect(lib.physical('margin', '0 4px')).toBe(false);
  expect(failRules(run(project((d) => edit(d, 'src/pages/Old.svelte', (s) => s.replace('margin-left: 4px;', 'margin-left: 4px;\n    text-align: right;')))))).toEqual(['physical-css']);
  expect(failRules(run(project((d) => edit(d, 'src/pages/Cache.svelte', (s) => s.replace('<h2>', '<h2 style:margin-right="2px">')))))).toEqual(['physical-css']);
  // (The fixture's baseline lists app.css at zero.)
  expect(failRules(run(project((d) => put(d, 'src/app.css', '.x {\n  text-align: left;\n}\n'))))).toEqual(['physical-css']);
  // A file the baseline does not list holds none.
  const fresh = run(project((d) => put(d, 'src/pages/Fresh.svelte', '<hr />\n<style>\n  hr {\n    margin-left: 1px;\n  }\n</style>\n')));
  expect(failRules(fresh)).toEqual(['physical-css']);
  expect(fresh.findings.filter((f) => f.file === 'src/pages/Fresh.svelte').map((f) => `${f.level} ${f.rule}`)).toEqual(['fail physical-css']);
  expect(failRules(run(project((d) => put(d, 'src/app.css', '.x {\n  margin-inline-start: 1px;\n  text-align: start;\n}\n'))))).toEqual([]);
  expect(failRules(run(project((d) => edit(d, 'src/pages/Old.svelte', (s) => s.replace('margin-left: 4px;', 'margin-inline-start: 4px;')))))).toEqual([]);
});
