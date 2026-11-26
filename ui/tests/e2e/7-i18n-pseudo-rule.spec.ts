// REQ: API-012 (ADR-189) — the whole-page rule of the pseudo-locale page tests (i18n-pseudo-rule.ts)
// held to fixtures, without a browser: a text node, a title, an aria-label, a placeholder, the value of a
// button or an alt that is English fails it, so does a hyphenated word, a one-word label with a colon and
// a short pattern such as `3 behind`, a message beside data (`1 odd` where `odd` is a value), a word that holds
// a value (`username` for `user`, `name`), slash text (`Queries/s`) and the English part of a joined piece
// (`Ĥéļļó · 4.2 q/s`); pseudo text, data marked translate="no", code, text without letters and the data a test
// declares pass. The fixture is a small component rendered on the server under the
// pseudo-locale, read as the page tests read a page (the same text nodes, attributes and marks).
import { expect, test } from '@playwright/test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { compile } from 'svelte/compiler';
import { render } from 'svelte/server';
import { install, tr } from '../../src/lib/i18n';
import { DATA, PSEUDO, collectHtml, collides, hasLetters, isCode, isEnglish, isFormatted, jsonStrings, makeRule, type Read } from './i18n-pseudo-rule';
import { cleanup } from './i18n-fixture';

test.afterAll(cleanup);
const temps: string[] = [];
test.afterAll(() => {
  for (const d of temps.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** A page of every kind of text the rule reads, all through `t()` or marked as data. */
const AFTER = [
  '<script lang="ts">',
  "  import { tr } from '../lib/i18n';",
  "  const { t } = tr('chip');",
  '</script>',
  "<button type=\"button\" title={t('Close this panel')} aria-label={t('Close')}>{t('Save')}</button>",
  "<p>{t('Saved.')}</p>",
  "<p>{t('Canaries:')}</p>",
  "<p>{t('Loading…')}</p>",
  "<p>{t('Git-managed')}</p>",
  "<p>{t('Read-only')}</p>",
  "<p>{t('{n} behind', { n: 3 })}</p>",
  "<input placeholder={t('moved the access point to the hallway')} />",
  "<input type=\"button\" value={t('Apply')} />",
  "<img alt={t('A sparkline')} src=\"x.svg\" />",
  '<p translate="no">laptop</p>',
  '<div translate="no"><span title="hidden">inside</span> <b>mark</b></div>',
  '<code translate="no">ads.example.com</code>',
  '<p><span>12.5</span> <span>—</span> <span>%</span> <span>1,234 · 5</span> <span>3 / 7</span></p>',
  '<p>kids-tv</p>',
  '',
].join('\n');

/** The page as the pseudo-locale draws it, read as the page tests read it. */
async function drawn(source: string): Promise<Read> {
  const js = compile(source, { generate: 'server', filename: 'Chip.svelte' }).js.code
    .replace(/from ['"](svelte(?:\/[^'"]*)?)['"]/g, (_, spec) => `from ${JSON.stringify(import.meta.resolve(spec))}`)
    .replace(/import \{ tr \} from ['"][^'"]+['"];/, 'const { tr } = globalThis.__i18aRule;');
  const dir = mkdtempSync(join(tmpdir(), 'tt-rule-'));
  temps.push(dir);
  writeFileSync(join(dir, 'Chip.mjs'), js);
  (globalThis as { __i18aRule?: unknown }).__i18aRule = { tr };
  const mod = await import(pathToFileURL(join(dir, 'Chip.mjs')).href);
  install({ tag: 'en-XA' });
  try {
    return collectHtml(render(mod.default, { props: {} }).body);
  } finally {
    install({ tag: 'en' });
  }
}

const RULE = makeRule({ data: {}, help: [] });
// `kids-tv` is the one piece of the fixture a test declares: a mock's name that is a hyphenated word.
const DECLARED = ['kids-tv'];
/** What the rule finds on the page after `edit`. */
const found = async (edit: (s: string) => string) => {
  const page = await drawn(edit(AFTER));
  return { page, found: RULE.found(page.text, page.other, DECLARED) };
};

test('api_012 pseudo rule: a word that ends in a full stop or a colon is text, a hyphenated word is text, a token with a separator is code', () => {
  for (const word of ['Saved.', 'Canaries:', 'left.', 'Partial:', 'node:', 'wait:', '/annotations', '/auth/', 'Git-managed', 'Read-only', 'Sign-in.', 'e-mail', 'Add-ons:', 'Git-managed-by']) expect(isCode(word), word).toBe(false);
  // Words joined by a slash are text when a side is a word of two letters or more (`Queries/s`).
  // (A lowercase pair such as `application/json` is judged as text too: it passes as the data of the page that received it.)
  for (const word of ['Queries/s', 'and/or', 'Read/write', 'km/h', 'Allow/Block:', 'application/json']) expect(isCode(word), word).toBe(false);
  // One-letter sides (`q/s`, `a/b`), paths and keys stay code.
  for (const token of ['data-theme-2', '2-digit', 'a/b', 'q/s', 'telltale-support.tar.gz', '--surface-2', 'neighbor_mac', 'node:{}', '/cache/stats', 'ads.example.com', 'n-aaaa1111', 'v0.9.0-edge.437', 'x-1', '10.0.0.1:53', 'a/b/c', 'v1/s', 'on/off1']) expect(isCode(token), token).toBe(true);
  // Text without letters is not text: numbers, signs, units made of signs.
  for (const s of ['12.5', '—', '%', '1,234 · 5', '3 / 7', '99 %', '×', '']) expect(hasLetters(s), s).toBe(false);
  for (const s of ['ms', 'A', '5 s', 'Saved.', 'Ünï', '日本語']) expect(hasLetters(s), s).toBe(true);
});

test('api_012 pseudo rule: the page after its migration holds', async () => {
  const { page, found: f } = await found((s) => s);
  // Every kind of text is on the page the rule reads: five attributes (a title, an aria-label, a placeholder, the
  // value of a button, an alt) and the text nodes with letters (seven of them pseudo text, one a declared name).
  expect(page.other.filter((s) => s)).toHaveLength(5);
  expect(page.other.every((s) => PSEUDO.test(s))).toBe(true);
  const words = page.text.filter((s) => hasLetters(s));
  expect(words.filter((s) => PSEUDO.test(s))).toHaveLength(7);
  expect(words.filter((s) => !PSEUDO.test(s))).toEqual(['kids-tv']);
  // Marked data is not read at all: not its text, not an attribute inside it.
  expect([...page.text, ...page.other].some((s) => ['laptop', 'inside', 'mark', 'hidden', 'ads.example.com'].includes(s))).toBe(false);
  expect(f).toEqual([]);
  // Without the declaration, the hyphenated word is English: a test declares the names its mocks make.
  expect(RULE.found(page.text, page.other)).toEqual(['"kids-tv"']);
});

test('api_012 pseudo rule: a site reverted to its literal english fails it when the English has letters and is no code or date', async () => {
  const cases: [string, string, string, string][] = [
    ['a text node', "{t('Saved.')}", 'Saved.', 'Saved.'],
    ['a one-word label with a colon', "{t('Canaries:')}", 'Canaries:', 'Canaries:'],
    ['a text with an ellipsis', "{t('Loading…')}", 'Loading…', 'Loading…'],
    ['a hyphenated word', "{t('Git-managed')}", 'Git-managed', 'Git-managed'],
    ['another hyphenated word', "{t('Read-only')}", 'Read-only', 'Read-only'],
    ['a pattern with fewer than eight letters', "{t('{n} behind', { n: 3 })}", '{3} behind', '3 behind'],
    ['a one-word label every page has', "{t('Save')}", 'Save', 'Save'],
    ['a placeholder', "placeholder={t('moved the access point to the hallway')}", 'placeholder="moved the access point to the hallway"', 'moved the access point to the hallway'],
    ['a title', "title={t('Close this panel')}", 'title="Close this panel"', 'Close this panel'],
    ['an aria-label', "aria-label={t('Close')}", 'aria-label="Close"', 'Close'],
    ['the value of a button', "value={t('Apply')}", 'value="Apply"', 'Apply'],
    ['an alt', "alt={t('A sparkline')}", 'alt="A sparkline"', 'A sparkline'],
  ];
  for (const [what, from, to, english] of cases) {
    expect(AFTER, what).toContain(from);
    const { page, found: f } = await found((s) => s.replace(from, to));
    expect([...page.text, ...page.other], what).toContain(english);
    expect(f, what).toEqual([JSON.stringify(english)]);
  }
  // The same word twice is found once.
  const twice = await found((s) => s.replace("{t('Saved.')}", 'Saved.').replace("{t('Canaries:')}", 'Saved.'));
  expect(twice.found).toEqual(['"Saved."']);
  // Canvas text is among the pieces the rule reads, as the attributes are.
  expect(RULE.found([], ['Sat', 'Ŝáţ'], DECLARED)).toEqual(['"Sat"']);
});

test('api_012 pseudo rule: data marked, pseudo text, numbers, signs and code pass', async () => {
  // Unmarked, the words of the marked data fail: the mark is what keeps them out.
  const unmarked = await found((s) => s.replace('<p translate="no">laptop</p>', '<p>laptop</p>').replace('<div translate="no">', '<div>'));
  expect(unmarked.found).toEqual(['"laptop"', '"inside"', '"mark"', '"hidden"']);
  for (const ok of [['Ĥéļļó'], ['12.5'], ['—'], ['%'], ['ads.example.com'], ['192.168.1.20:53'], ['/api/v1/rules'], ['']]) expect(RULE.found(ok, []), ok.join()).toEqual([]);
  // A pseudo character anywhere is enough; a text that is English is not. A parameter's text that a
  // message pads with the pseudo-locale's dots passes (the padding is the message's), a lone dot does not.
  expect(RULE.found(['Save', 'Ṡavé'], [])).toEqual(['"Save"']);
  expect(RULE.found(['Applies to the group.·······', 'Applies to the group.·'], [])).toEqual(['"Applies to the group.·"']);
  // A date or a time the browser formats in English is not a message; a word of a date alone is.
  // (and a number the browser formats compactly)
  for (const date of ['06:37 PM', 'Wed, Nov 25', '11/24/2026, 5:00:00 PM', '12:00 AM', 'Tue, Nov 24', '2026-11-26T00:04:50.997Z', '12K', '1.5M']) expect(isFormatted(date) || isCode(date), date).toBe(true);
  for (const word of ['Mon', 'May', 'PM', 'Nov', '5 Mondays and Fridays', 'at 5 PM sharp', '5m 14.4×', 'K', '12 KB']) expect(isFormatted(word), word).toBe(false);
  expect(RULE.found(['Mon', 'Nov 25', '12K'], [])).toEqual(['"Mon"']);
  // A time beside data: the words of a time may stand between values.
  expect(RULE.found(['06:37 PM: first query to example.com', 'PM: first query to example.com'], [], ['first query to example.com'])).toEqual(['"PM: first query to example.com"']);
  // The words of a page the reader does not see: a <noscript> of a page that runs.
  expect((await drawn(AFTER.replace('<p>kids-tv</p>', '<noscript>Needs JavaScript.</noscript><p>kids-tv</p>'))).text.join('|')).not.toContain('JavaScript');
  // What a mock or the server sent: every string value of the JSON, at any depth.
  expect([...jsonStrings({ a: 'one', b: ['two', { c: 'three', n: 4 }], d: null })].sort()).toEqual(['one', 'three', 'two']);
});

test('api_012 pseudo rule: the data of a test excuses a text node and an attribute, shared data a text node only, help only in its panel', () => {
  const note = 'moved the access point to the hallway';
  const rule = makeRule({ data: { Time: { reason: 'a reason' }, Label: { reason: 'a legend', where: /\bu-label\b/ } }, help: ['How it works'] });
  // Shared data may name the place it stands in: every place the text is read at must be one of them.
  expect(rule.found(['Label'], [], [], [], new Map([['Label', ['text of div.u-label']]]))).toEqual([]);
  expect(rule.found(['Label'], [], [], [], new Map([['Label', ['text of div.u-label', 'text of td']]]))).toEqual(['"Label"']);
  expect(rule.found(['Label'], [])).toEqual(['"Label"']);
  expect(rule.found([note], [])).toEqual([`"${note}"`]);
  expect(rule.found([note], [], [note])).toEqual([]);
  expect(rule.found([], [note], new Set([note]))).toEqual([]);
  // A pattern with {} stands for a value that changes (a number in a server's sentence); several values with only
  // signs, numbers and code between them are data; any English word beside them is not.
  expect(rule.found(['configuration 97 applied (ui, 1 section changed)'], [], ['configuration {} applied ({}, {} section{} changed)'])).toEqual([]);
  expect(rule.found(['work-pc (127.0.0.1)', 'unifi · https://192.168.0.1', '@ main,', '· admin'], [], ['work-pc', 'unifi', 'main', 'admin'])).toEqual([]);
  expect(rule.found(['work-pc and the rest', 'Open work-pc'], [], ['work-pc'])).toEqual(['"work-pc and the rest"', '"Open work-pc"']);
  // Shared data: a text node only; the same words as an attribute are the layer's own.
  expect(rule.found(['Time'], [])).toEqual([]);
  expect(rule.found([], ['Time'])).toEqual(['"Time"']);
  expect(rule.found(['Time'], ['Time'])).toEqual(['"Time"']);
  // The help glossary is English in part A, in the help panel and the title of a help button, and nowhere else.
  expect(rule.found([], [], [], ['How it works'])).toEqual([]);
  expect(rule.found(['How it works'], [])).toEqual(['"How it works"']);
  expect(rule.found(['How it works'], [], [], ['How it works'])).toEqual(['"How it works"']);
  expect(rule.found([], [], [], ['A topic nobody wrote'])).toEqual(['"A topic nobody wrote"']);
  // Every entry of the shared table has its reason, and excuses a text node only.
  for (const [text, d] of Object.entries(DATA)) {
    expect(d.reason.length, text).toBeGreaterThan(12);
    const strict = makeRule({ data: DATA, help: [] });
    // at its place, as a text node: excused; as an attribute, or anywhere else: not
    const there = new Map([[text, ['text of div.u-label of a chart']]]);
    expect(strict.found([text], [], [], [], there), text).toEqual([]);
    expect(strict.found([], [text], [], [], there), text).toEqual([JSON.stringify(text)]);
    expect(strict.found([text], [], [], [], new Map([[text, ['text of td']]])), text).toEqual([JSON.stringify(text)]);
  }
});

test('api_012 pseudo rule: a message that is English again is found beside the data of the page', () => {
  const messages = ['{n} odd', 'Queries/s', '{rate} q/s', '{n} rules', 'e.g. kids', 'Sign in with {name}', 'Reason: {reason}', '{n} of {total}'];
  const rule = makeRule({ data: {}, help: [], messages });
  // The page received `odd`, `kids` and `rules` as values: a piece of the UI's own words is still the message.
  expect(rule.found(['1 odd', '3 rules'], [], ['odd', 'rules'])).toEqual(['"1 odd"', '"3 rules"']);
  expect(rule.found([], ['e.g. kids'], ['kids'])).toEqual(['"e.g. kids"']);
  expect(rule.found(['4.2 q/s', 'Queries/s'], [], ['s'])).toEqual(['"4.2 q/s"', '"Queries/s"']);
  // A pattern with a letter of its own (`of`) fits a count.
  expect(rule.found(['3 of 9'], [], ['of'])).toEqual(['"3 of 9"']);
  // Data that no message says stays data, in a text node and in an attribute, alone and beside other data.
  expect(rule.found(['odd', 'work-pc (127.0.0.1)', 'kids · odd'], ['kids'], ['odd', 'kids', 'work-pc'])).toEqual([]);
  // A pattern that fits with no letter of its own is not a message: a count is data.
  expect(rule.found(['3'], [], [])).toEqual([]);
  // Nor is one whose only letters touch a placeholder (`{s}s`, seconds): it would fit every name that ends in `s`.
  expect(makeRule({ data: {}, help: [], messages: ['{s}s', '{m}m', '{n} s'] }).found(['kids', 'homelab'], [], ['kids', 'homelab'])).toEqual([]);
  expect(makeRule({ data: {}, help: [], messages: ['{s}s', '{n} s'] }).found(['5 s'], [], ['s'])).toEqual(['"5 s"']);
  // A short pattern takes one word for each placeholder: `{from} to {to}` is not the text `first query to example.com`.
  const words = makeRule({ data: {}, help: [], messages: ['{from} to {to}', '{n} s', '{n} rules'] });
  expect(words.found(['06:37 AM: first query to example.com'], [], ['first query to example.com'])).toEqual([]);
  expect(words.found(['5 to 9', '5 s', '3 rules'], [], ['first query to example.com'])).toEqual(['"5 to 9"', '"5 s"', '"3 rules"']);
  // A piece that is one value of the data and nothing else is data, though a short message fits it (`by {by}`, `{n} s`).
  const short = makeRule({ data: {}, help: [], messages: ['by {by}', '{n} s'] });
  expect(short.found(['by hand', 'every 5 s', 'Ĥéļļó · by hand'], [], ['by hand', 'every 5 s'])).toEqual([]);
  expect(short.found(['by hand', 'by hand today'], [], ['hand'])).toEqual(['"by hand"', '"by hand today"']);
  // Without the messages the rule cannot tell, and the data hides it: the page tests give it the layer's messages.
  expect(makeRule({ data: {}, help: [] }).found(['1 odd', '3 rules'], [], ['odd', 'rules'])).toEqual([]);
});

test('api_012 pseudo rule: a value of the data counts as whole words only', () => {
  const rule = makeRule({ data: {}, help: [] });
  // `user` and `name` are values; `username` is a word of the UI's own.
  expect(rule.found([], ['username'], ['user', 'name'])).toEqual(['"username"']);
  expect(rule.found(['users', 'user2', 'rename'], [], ['user', 'name'])).toEqual(['"users"', '"user2"', '"rename"']);
  // Each value is a whole word beside signs, numbers and spaces; and a value that begins or ends with a sign needs no boundary there.
  expect(rule.found(['user name', 'user, name', '(user)', 'user-name', 'user2 user', '· user'], [], ['user', 'name', 'user2'])).toEqual([]);
  expect(rule.found(['Done user'], [], ['user'])).toEqual(['"Done user"']);
  expect(rule.found(['@main,'], [], ['@main'])).toEqual([]);
});

test('api_012 pseudo rule: a message with a placeholder that code joined to pseudo text in English is found', async () => {
  // `{[t('Close'), '4.2 q/s'].join(' · ')}` draws one text node with pseudo text in front and English behind it.
  const rule = makeRule({ data: {}, help: [], messages: ['{rate} q/s', 'Close'] });
  const joined = async (parts: string) => {
    const page = await drawn(AFTER.replace('<p>kids-tv</p>', `<p>kids-tv</p><p>{[${parts}].join(' · ')}</p>`));
    return { page, found: rule.found(page.text, page.other, DECLARED) };
  };
  const english = await joined("t('Close'), '4.2 q/s'");
  expect(english.page.text.filter((s) => s.endsWith(' · 4.2 q/s') && PSEUDO.test(s))).toHaveLength(1);
  expect(english.found).toHaveLength(1);
  expect(english.found[0]).toContain(' · 4.2 q/s');
  // Not held: a part that is a single word or a sentence is not told from a word of the server's (`primary`, `block`).
  expect(RULE.found(['Ĥéļļó · moved to the hallway'], [])).toEqual([]);
  // The same with a part that is data, a part without letters and a part that is code: all pass.
  for (const parts of ["t('Close'), 'kids-tv'", "t('Close'), '4.2'", "t('Close'), '/cache/stats'", "'kids-tv', t('Save'), '12K'"]) expect((await joined(parts)).found, parts).toEqual([]);
  // A message with a placeholder gone back to English as a part is found, also when its words are data.
  const rules = makeRule({ data: {}, help: [], messages: ['{n} rules', '{n} odd', '{since} · up {uptime}'] });
  expect(rules.found(['block · 3 rules · off', 'Ĥéļļó · 3 rules'], [], ['block', 'off', 'rules'])).toEqual(['"block · 3 rules · off"', '"Ĥéļļó · 3 rules"']);
  expect(rules.found(['block · ŕúļéş · off', 'Ĥéļļó · ŵöŕļď', 'kids · odd'], [], ['block', 'off', 'kids', 'odd'])).toEqual([]);
  // A message that holds the separator itself is found whole, also when its words are data.
  expect(rules.found(['3d · up 2h'], [], ['3d', 'up', '2h'])).toEqual(['"3d · up 2h"']);
  // A server's sentence that holds the separator is one piece of data.
  expect(rules.found(['audit · admin · drill'], [], ['audit · admin · drill'])).toEqual([]);
});

test('api_012 pseudo rule: a test may declare only what no message says', () => {
  const messages = ['this node', 'none', 'Reason: {reason}', '{n} behind', '{n} of {total}', 'Sign in with {name}', 'Open {a}{b}{c}{d} at {e}: open this query now'];
  // A message's own English hides a reverted site.
  expect(collides('this node', messages)).toBe('this node');
  expect(collides('none', messages)).toBe('none');
  // A pattern counts when it has eight letters of its own (a shorter one would fit any name).
  expect(collides('Sign in with Keycloak', messages)).toBe('Sign in with {name}');
  expect(collides('Reason: moved', messages)).toBeUndefined();
  expect(collides('3 behind', messages)).toBeUndefined();
  expect(collides('4 of 9', messages)).toBeUndefined();
  // Names are fine.
  for (const name of ['homelab', 'pi', 'laptop', 'kids-tv', 'ops-bot', 'grafana', 'This node of mine']) expect(collides(name, messages), name).toBeUndefined();
});

test('api_012 pseudo rule: a long text is judged in linear time', () => {
  // A pattern with adjacent placeholders, and a text of many short pieces: as a regular expression of lazy
  // gaps it took seconds on the few thousand characters of the dashboard's list of changes, and never ends
  // on this one.
  const hot = ['Open {a}{b}{c}{d} at {e}: open this query now'];
  const long = `Open ${Array.from({ length: 3000 }, (_, i) => `at ${i}: a`).join(' ')}`;
  expect(long.length).toBeGreaterThan(20_000);
  expect(collides(long, hot)).toBe(undefined);
  expect(collides(`${long}: open this query now`, hot)).toBe(hot[0]);
});

test('api_012 pseudo rule: a text fits an English with placeholders as the lazy pattern said', () => {
  const escape = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const lazy = (s: string) => new RegExp(`^${s.split('{}').map(escape).join('[\\s\\S]*?')}$`);
  const english = ['Saved.', '{} items', 'Open {}', '{}{} x {}', 'a {} b {} c', '{}', 'a{}b', '{}a{}', 'x {}{}', 'a{}a', 'Hello {} and {}!'];
  const texts = ['', 'Saved.', 'Saved. ', ' 5 items', 'items', 'Open', 'Open ', 'Open it', ' x ', 'q x z', 'x  x ', 'a b c', 'a  b  c', 'a b b c', 'ab', 'aXb', 'a', 'aa', 'aXa', 'Hello 1 and 2!', 'Hello and !', 'Hello 1 and 2', 'Hello and  and !', 'line\nbreak items', 'items items'];
  for (const s of english) for (const t of texts) expect(isEnglish(s, t), `${JSON.stringify(s)} / ${JSON.stringify(t)}`).toBe(lazy(s).test(t));
});
