// REQ: API-012 (ADR-189) — languages in the web UI, the layer itself, without a browser: messages,
// plurals, matching, the agreement rule, the pseudo-locale, the runtime's tables, the catalog step,
// the pair files and the formats. The languages tool is 7-i18n-check.spec.ts, the ratchets
// 7-i18n-ratchets.spec.ts, the pages 8-i18n-pages.spec.ts.
import { expect, test } from '@playwright/test';
import { interpolate, parts, plural } from '../../src/lib/i18n/message';
import { candidates, canonical, match, type Request } from '../../src/lib/i18n/match';
import { agreesAtRuntime as runtimeCheck, codePoints, schemes, tokens, urls } from '../../src/lib/i18n/safe';
import { extraAgrees } from '../../src/lib/i18n/added';
import { agree } from '../../src/lib/i18n/agree';
import { LOWER, UPPER, pseudo } from '../../src/lib/i18n/pseudo';
import { hash } from '../../src/lib/i18n/ident';
import { PairFileError, merge, parse, shapeError, shapeProblem, skeleton } from '../../src/lib/i18n/pairs';
import { catalogRuntime, install, load, parseCatalog, tk, tr, type Choice } from '../../src/lib/i18n';
import * as fmt from '../../src/lib/format';
import { makeFormat } from '../../src/lib/format';

/** The runtime's check of a catalog the build did not ship, with the digit and added-token rules that the code
 * bringing such a catalog gives it (ADR-190). */
const agreesAtRuntime = (english: string, translation: string, dir: 'ltr' | 'rtl' = 'ltr', o: { subset?: boolean } = {}) => runtimeCheck(english, translation, dir, { ...o, extra: extraAgrees });

/** Runs `body` with `c` installed, then English again; a catalog the build did not ship gets those two rules,
 * unless `c` names its own `extra`. */
function under(c: Choice, body: () => void) {
  install(c.built || 'extra' in c ? c : { ...c, extra: extraAgrees });
  try {
    body();
  } finally {
    install({ tag: 'en' });
  }
}
const table = (o: object) => parseCatalog(JSON.stringify(o));

// ---------------------------------------------------------------------------------------------
// Messages


test('api_012 interpolation is single pass and own-property only', () => {
  expect(interpolate('Hello {name}', { name: '{name}' })).toBe('Hello {name}');
  expect(interpolate('{a} and {b}', { a: '{b}', b: 'x' })).toBe('{b} and x');
  expect(interpolate('Hi {who}', { who: '<b>x</b>' })).toBe('Hi <b>x</b>');
  expect(interpolate('{constructor} {toString} {__proto__} {hasOwnProperty}', {})).toBe('{constructor} {toString} {__proto__} {hasOwnProperty}');
  expect(interpolate('{inherited}', Object.create({ inherited: 'no' }))).toBe('{inherited}');
  expect(interpolate('{v} $1', { v: '$& $1' })).toBe('$& $1 $1');
  expect(interpolate('{missing}', { other: 1 })).toBe('{missing}');
  expect(interpolate('no params {x}')).toBe('no params {x}');
});

test('api_012 a nullish parameter renders as empty', () => {
  expect(interpolate('[{v}]', { v: undefined })).toBe('[]');
  expect(interpolate('[{v}]', { v: null })).toBe('[]');
  expect(interpolate('[{v}]', { v: 0 })).toBe('[0]');
  expect(interpolate('[{v}]', { v: false })).toBe('[false]');
  expect(interpolate('[{v}]', { v: '' })).toBe('[]');
  const { t, tn } = tr('fixture');
  expect(t('[{v}]', { v: undefined })).toBe('[]');
  expect(tn('{n} row ({v})', '{n} rows ({v})', 2, { n: 2, v: null })).toBe('2 rows ()');
});

test('api_012 message markup becomes text and named snippets only', () => {
  const tags = ['b', 'a', 'br'];
  expect(parts('Muted by <b>{who}</b>: ok', { who: '<i>x</i>' }, tags)).toEqual([{ text: 'Muted by ' }, { tag: 'b', text: '<i>x</i>' }, { text: ': ok' }]);
  expect(parts('<img src=x onerror=alert(1)>', null, tags)).toEqual([{ text: '<img src=x onerror=alert(1)>' }]);
  expect(parts('<script>alert(1)</script>', null, tags)).toEqual([{ text: '<script>alert(1)</script>' }]);
  expect(parts('unclosed <b>bold', null, tags)).toEqual([{ text: 'unclosed <b>bold' }]);
  expect(parts('<a href="https://evil.example">link</a>', null, tags)).toEqual([{ text: '<a href="https://evil.example">link</a>' }]);
  expect(parts('line<br/>next', null, tags)).toEqual([{ text: 'line' }, { tag: 'br', text: '' }, { text: 'next' }]);
  // A tag the caller has no snippet for stays text; a parameter never becomes a tag.
  expect(parts('<b>x</b>', null, [])).toEqual([{ text: '<b>x</b>' }]);
  expect(parts('{x}', { x: '<b>y</b>' }, ['b'])).toEqual([{ text: '<b>y</b>' }]);
  // No nesting: the outer tag stays text.
  expect(parts('<b><a>x</a></b>', null, tags)).toEqual([{ text: '<b>' }, { tag: 'a', text: 'x' }, { text: '</b>' }]);
});

test('api_012 english plurals come from the catalog language', () => {
  // What the browser's own rules would say: French 0 is "one", Russian 2 is "few", Japanese 1 is "other".
  expect(new Intl.PluralRules('fr').select(0)).toBe('one');
  expect(new Intl.PluralRules('ru').select(2)).toBe('few');
  expect(new Intl.PluralRules('ja').select(1)).toBe('other');
  // English: there is no browser input at all.
  const { tn } = tr('fixture');
  expect([0, 1, 2].map((n) => tn('{n} answer', '{n} answers', n, { n }))).toEqual(['0 answers', '1 answer', '2 answers']);
  for (const browser of ['fr', 'ja', 'ru']) {
    // A page in the browser's language whose catalog lacks the message: English text, English rules.
    under({ tag: browser, table: table({}), formatLocale: `${browser}-XX` }, () => {
      const { tn: tb } = tr('fixture');
      expect([0, 1, 2].map((n) => tb('{n} answer', '{n} answers', n, { n })), browser).toEqual(['0 answers', '1 answer', '2 answers']);
    });
    const f = catalogRuntime(browser, table({}), 'ltr', browser).forms('fixture', '{n} answer', '{n} answers');
    expect(f.lang).toBe('en');
    expect([0, 1, 2].map((n) => plural(f.lang, f.forms, n))).toEqual(['{n} answers', '{n} answer', '{n} answers']);
  }
  // The pseudo-locale is English text: English rules.
  under({ tag: 'en-XA' }, () => expect(tr('fixture').tn('{n} answer', '{n} answers', 1, { n: 1 })).toBe(pseudo('{n} answer').replace('{n}', '1')));
});

test('api_012 a missing plural category falls back within the catalog', () => {
  const k = hash('c', ['{n} file', '{n} files']);
  under({ tag: 'ru', table: table({ [k]: { one: '{n} файл', other: '{n} файлов' } }), formatLocale: 'ru-RU' }, () => {
    const { tn } = tr('c');
    expect(tn('{n} file', '{n} files', 1, { n: 1 })).toBe('1 файл');
    // Russian 3 is "few" and 5 is "many": the catalog has neither, so its own "other", never English.
    expect(tn('{n} file', '{n} files', 3, { n: 3 })).toBe('3 файлов');
    expect(tn('{n} file', '{n} files', 5, { n: 5 })).toBe('5 файлов');
  });
  // A plural without "other" is not a catalog entry: English.
  under({ tag: 'ru', table: table({ [k]: { one: '{n} файл' } }) }, () => expect(tr('c').tn('{n} file', '{n} files', 3, { n: 3 })).toBe('3 files'));
});

// ---------------------------------------------------------------------------------------------
// Matching


test('api_012 locale matching follows the request order and scripts', () => {
  const offered = { 'zh-Hans': { offered: true } };
  const browser = (...tags: string[]): Request[] => tags.map((tag) => ({ tag, source: 'browser' as const }));
  expect(match(browser('zh-TW', 'zh', 'en-US', 'en'), offered)).toBe('en');
  expect(match(browser('zh-HK', 'zh'), offered)).toBe('en');
  expect(match(browser('zh', 'zh-TW'), offered)).toBe('zh-Hans');
  expect(match(browser('zh-TW', 'zh-CN', 'en'), offered)).toBe('zh-Hans');
  expect(match(browser('zh-SG'), offered)).toBe('zh-Hans');
  expect(match(browser('de-DE', 'en-US', 'zh-CN'), offered)).toBe('en');
  expect(match(browser('not a tag', '__proto__', 'constructor', 'toString', ''), offered)).toBe('en');
  expect(match([], offered)).toBe('en');
  expect(candidates('zh', ['zh-TW'])).toEqual(['zh', 'zh-Hant-TW', 'zh-Hant']);
  expect(candidates('zh')).toEqual(['zh', 'zh-Hans-CN', 'zh-Hans']);
  expect(canonical('zh-hant-tw')).toBe('zh-Hant-TW');
  expect(canonical('__proto__')).toBeNull();
  // A catalog that is not offered is reached through ?lang= only.
  const hidden = { 'zh-Hans': { offered: false } };
  expect(match(browser('zh-CN'), hidden)).toBe('en');
  expect(match([{ tag: 'zh-CN', source: 'stored' }], hidden)).toBe('en');
  expect(match([{ tag: 'zh-CN', source: 'param' }], hidden)).toBe('zh-Hans');
  // ?lang= comes first, then the stored choice, then the browser.
  const two = { 'zh-Hans': { offered: true }, 'fr-FR': { offered: true } };
  expect(match([{ tag: 'fr-FR', source: 'param' }, { tag: 'zh-CN', source: 'stored' }], two)).toBe('fr-FR');
  // The pseudo-locale only from ?lang=.
  expect(match([{ tag: 'en-XA', source: 'param' }], offered)).toBe('en-XA');
  expect(match([{ tag: 'en-XA', source: 'browser' }, { tag: 'zh-CN', source: 'browser' }], offered)).toBe('en');
  // A catalog whose tag names no script is taken only for a request of its likely script: a `yue`
  // catalog (Traditional) is not taken for `yue-CN` (Simplified), and no list of languages decides it.
  const yue = { yue: { offered: true } };
  expect(match(browser('yue-CN'), yue)).toBe('en');
  expect(match(browser('yue-Hans'), yue)).toBe('en');
  expect(match(browser('yue-HK'), yue)).toBe('yue');
  expect(match(browser('yue'), yue)).toBe('yue');
  expect(match(browser('yue-CN', 'yue'), yue)).toBe('en');
  expect(match([{ tag: 'yue-CN', source: 'param' }], yue)).toBe('en');
  const sr = { 'sr-Latn': { offered: true } };
  expect(match(browser('sr'), sr)).toBe('en');
  expect(match(browser('sr-Latn-RS'), sr)).toBe('sr-Latn');
});

// ---------------------------------------------------------------------------------------------
// The agreement rule


const failed = (en: string, tx: string, o?: object) => [...new Set(agree(en, tx, o).fails.map((f) => f.rule))];

test('api_012 url and token extraction', () => {
  // A CJK full stop after a URL, and text right after it.
  expect(urls('打开https://192.168.1.1。然后登录')).toEqual(['https://192.168.1.1']);
  expect(failed('Open https://192.168.1.1.', '打开https://192.168.1.1。然后登录')).toEqual([]);
  // A fullwidth parenthesis ends the URL: here a bare scheme.
  expect(urls('见 https://（DNS…')).toEqual(['https://']);
  // A fullwidth colon does not glue two tokens.
  expect(tokens('OPNsense：https://x.example/a')).toEqual(['OPNsense', 'https://x.example/a']);
  // Fullwidth letters and dots in an address are caught.
  expect(failed('See https://example.com/x', '见 https://ｅｖｉｌ．ｃｏｍ/x')).toContain('urls');
  expect(failed('See https://example.com/x', '见 https://ｅｖｉｌ.com/x')).toContain('urls');
  // An address in capitals is an address.
  expect(urls('见 HTTPS://Evil.example/x')).toEqual(['HTTPS://Evil.example/x']);
  expect(failed("Open your router's page", '打开 HTTPS://evil.example')).toContain('urls');
  expect(failed('See HTTPS://a.example', '见 HTTPS://a.example')).toEqual([]);
  // A fullwidth scheme (its colon and slashes too) counts as one, though no URL can be read from it.
  expect(schemes('打开 ｈｔｔｐｓ：／／ｅｖｉｌ．ｅｘａｍｐｌｅ')).toBe(1);
  // (The folded reading also finds the added `://` as a structural token.)
  expect(failed("Open your router's page", '打开 ｈｔｔｐｓ：／／ｅｖｉｌ．ｅｘａｍｐｌｅ')).toEqual(['urls', 'structural']);
  expect(failed('Open https://a.example', '打开 https://a.example 或 ｆｔｐ：／／ｂ')).toEqual(['urls', 'structural']);
  expect(agreesAtRuntime("Open your router's page", '打开 ｈｔｔｐｓ：／／ｅｖｉｌ．ｅｘａｍｐｌｅ')).toBe(false);
  expect(agreesAtRuntime("Open your router's page", '打开 HTTPS://evil.example')).toBe(false);
  // A scheme with a host and port, and its number, must stay.
  expect(failed('Use smtp://host:587 to send', '用邮件服务器发送')).toEqual(['structural', 'digits']);
  // A verbatim word renamed fails; kept as a word (also between CJK letters) it passes.
  expect(failed('Send by email', '通过电子邮件发送', { verbatim: ['email'] })).toEqual(['verbatim']);
  expect(failed('Send by email', '通过email发送', { verbatim: ['email'] })).toEqual([]);
  expect(failed('Send by email', '通过 emails 发送', { verbatim: ['email'] })).toEqual(['verbatim']);
  // A hyphenated word and a short acronym translated: reported, not failed.
  const v = agree('Use the UI to sign-in', '使用界面登录');
  expect(v.fails).toEqual([]);
  expect(v.reports.map((r) => r.rule).sort()).toEqual(['capitals', 'hyphenated']);
  // A token the translation adds is reported.
  expect(agree('Holds', '保存 DNS').reports.map((r) => r.rule)).toEqual(['added']);
  // A Latin word with one Cyrillic letter fails.
  expect(failed('Password', 'Pаssword')).toEqual(['mixed-script']);
  // A glossary term is structural.
  expect(failed('NXDOMAIN answers', '否定回答', { glossary: ['NXDOMAIN'] })).toEqual(['structural']);
  expect(failed('NXDOMAIN answers', 'NXDOMAIN 回答', { glossary: ['NXDOMAIN'] })).toEqual([]);
  // A bare scheme followed by a letter of another script is an address in that script.
  expect(urls('其他：https://例子.公司 网址。')).toEqual(['https://例子']);
  expect(urls('sent only over https://.')).toEqual(['https://']);
  expect(failed('Others: the https:// URL.', '其他：https://例子.公司 网址。')).toEqual(['urls']);
  expect(agreesAtRuntime('Others: the https:// URL.', '其他：https://例子.公司 网址。')).toBe(false);
  expect(failed('Others: the https:// URL.', '其他：https:// 网址。')).toEqual([]);
  // Without a scheme, a `.` between two letters of another script is reported (the language's owner
  // reads it); an ideographic full stop is not.
  expect(agree('Visit the site', '访问 例子.公司').reports.map((r) => `${r.rule} ${r.token}`)).toEqual(['added 例子.公司']);
  expect(agree('Done. Next', '完成。下一步').reports).toEqual([]);
  // A suffix after an address (Turkish) is not part of it.
  expect(urls("Konu https://ntfy.sh/my-topic'e gider")).toEqual(['https://ntfy.sh/my-topic']);
  expect(failed('Topic https://ntfy.sh/my-topic', "Konu https://ntfy.sh/my-topic'e gider")).toEqual([]);
  expect(failed('Topic https://ntfy.sh/my-topic', "Konu https://ntfy.sh/my-topic'ın")).toEqual([]);
  expect(failed('Topic https://ntfy.sh/my-topic', "Konu https://ntfy.sh/my-topic'e/x")).toEqual(['urls']);
});

test('api_012 forbidden code points', () => {
  const named: Record<string, string> = {
    'U+202A': '\u202A', 'U+202E': '\u202E', 'U+2066': '\u2066', 'U+2069': '\u2069', 'U+200B': '\u200B', 'U+2060': '\u2060',
    'U+2064': '\u2064', 'U+FEFF': '\uFEFF', 'U+00AD': '\u00AD', 'U+0000': '\u0000', 'U+0009': '\t', 'U+001F': '\u001F',
    'U+007F': '\u007F', 'U+0080': '\u0080', 'U+009F': '\u009F',
  };
  for (const [name, c] of Object.entries(named)) expect(codePoints(`a${c}b`), name).toEqual([name]);
  // Every other format character, the line and paragraph separators, the invisible fillers and
  // selectors, and the tag characters.
  const more: Record<string, string> = {
    'U+2028': '\u{2028}', 'U+2029': '\u{2029}', 'U+180E': '\u180E', 'U+034F': '\u034F', 'U+FE00': '\uFE00', 'U+FE0F': '\uFE0F',
    'U+115F': '\u115F', 'U+1160': '\u1160', 'U+3164': '\u3164', 'U+FFA0': '\uFFA0', 'U+206A': '\u206A', 'U+206F': '\u206F',
    'U+E0000': '\u{E0000}', 'U+E0001': '\u{E0001}', 'U+E0041': '\u{E0041}', 'U+E007F': '\u{E007F}', 'U+0600': '\u0600', 'U+2061': '\u2061',
  };
  for (const [name, c] of Object.entries(more)) expect(codePoints(`a${c}b`), name).toEqual([name]);
  expect(agreesAtRuntime('Hello', 'Hel\u{E0041}lo')).toBe(false);
  // Every default-ignorable code point: the supplementary and the Mongolian variation selectors too.
  for (const [name, c] of Object.entries({ 'U+E0100': '\u{E0100}', 'U+E01EF': '\u{E01EF}', 'U+180B': '\u180B', 'U+180D': '\u180D', 'U+180F': '\u180F' })) {
    expect(codePoints(`Qa-holds${c.repeat(3)}`), name).toEqual([name, name, name]);
  }
  expect(codePoints('a\nb')).toEqual([]);
  // U+200C/U+200D between letters of a script that needs them; nowhere else.
  expect(codePoints('می\u200Cخواهم')).toEqual([]);
  expect(codePoints('क्\u200Dष')).toEqual([]);
  expect(codePoints('ab\u200Ccd')).toEqual(['U+200C']);
  expect(codePoints('\u200Cمی')).toEqual(['U+200C']);
  expect(codePoints('a\u200Db')).toEqual(['U+200D']);
  // U+200E, U+200F and U+061C right to left only.
  for (const c of ['\u200E', '\u200F', '\u061C']) {
    expect(codePoints(`a${c}b`)).toHaveLength(1);
    expect(codePoints(`a${c}b`, 'rtl')).toEqual([]);
  }
  expect(failed('Hello', 'Hel\u202Elo')).toEqual(['code-point']);
  expect(agreesAtRuntime('Hello', 'Hel\u200Blo')).toBe(false);
});

test('api_012 findings name the rule the token and its place', () => {
  const v = agree('See https://a.example/docs and {n} items', 'Qa {n} https://b.example/docs Pаss\u202E');
  const pick = (rule: string) => v.fails.filter((f) => f.rule === rule).map(({ token, at, detail }) => ({ token, at, detail }));
  expect(pick('urls')).toEqual([
    { token: 'https://a.example/docs', at: -1, detail: 'missing' },
    { token: 'https://b.example/docs', at: 7, detail: 'added' },
  ]);
  expect(pick('structural')).toEqual([
    { token: 'https://a.example/docs', at: -1, detail: 'missing' },
    { token: 'https://b.example/docs', at: 7, detail: 'added' },
  ]);
  expect(pick('mixed-script')).toEqual([{ token: 'Pаss', at: 30, detail: 'mixes Latin with Cyrillic or Greek letters' }]);
  expect(pick('code-point')).toEqual([{ token: 'U+202E', at: 34, detail: 'forbidden' }]);
  // The browser's first-use check is a separate yes or no on the same rules.
  expect(agreesAtRuntime('See https://a.example/docs and {n} items', 'Qa {n} https://b.example/docs Pаss\u202E')).toBe(false);
});

test('api_012 a translation keeps the placeholders tags urls and tokens of english', () => {
  expect(failed('{n} rows', '{n} 行')).toEqual([]);
  expect(failed('{n} rows', '行')).toEqual(['placeholders']);
  expect(failed('{n} rows', '{n} {m} 行')).toEqual(['placeholders']);
  expect(failed('{n} rows', '{N} 行')).toEqual(['placeholders']);
  expect(failed('Muted by <b>{who}</b>', '静音 <b>{who}</b>')).toEqual([]);
  expect(failed('Muted by <b>{who}</b>', '静音 {who}')).toEqual(['tags']);
  expect(failed('Muted by <b>{who}</b>', '静音 <i>{who}</i>')).toEqual(['tags']);
  expect(failed('See https://a.example/docs', '见 https://a.example/docs')).toEqual([]);
  expect(failed('See https://a.example/docs', '见 https://b.example/docs')).toEqual(['urls', 'structural']);
  expect(failed('See the docs', '见 https://evil.example')).toEqual(['urls', 'structural']);
  expect(failed('Set upstream=1.1.1.1', '设置上游')).toEqual(['structural', 'digits']);
  expect(failed('Path /etc/telltale/ here', '路径 /etc/telltale/')).toEqual([]);
  expect(failed('Path /etc/telltale/ here', '路径')).toEqual(['structural']);
  expect(failed('Code [x] here', '代码 [x]')).toEqual([]);
  expect(failed('a|b and $HOME and x_y', 'ab')).toEqual(['structural']);
  expect(failed('localhost:8053', '本机')).toEqual(['structural', 'digits']);
  expect(failed('Run `telltale ctl` now', '现在运行 `telltale ctl`')).toEqual([]);
  expect(failed('Run `telltale ctl` now', '现在运行 `telltale-ctl`')).toEqual(['code']);
  expect(failed('Wait 7 days', '等待七天')).toEqual(['digits']);
  expect(failed('Wait 7 days', '等待七天', { exemptDigits: true })).toEqual([]);
  expect(failed('Port 53 and 53', 'port 53')).toEqual(['digits']);
  // The browser applies the same rules, without the data-file ones (verbatim, glossary).
  expect(agreesAtRuntime('Send by email', '通过电子邮件发送')).toBe(true);
  expect(agreesAtRuntime('See https://a.example', '见 https://b.example')).toBe(false);
  expect(agreesAtRuntime('{n} rows', '行')).toBe(false);
  expect(agreesAtRuntime('Set upstream=1.1.1.1', '设置 upstream=1.1.1.1')).toBe(true);
});

test('api_012 a translation adds no address port path or setting', () => {
  const en = "Set your router's DNS to this server";
  expect(failed(en, '把路由器的 DNS 设为本服务器')).toEqual([]);
  // An address, a host and port, a path, a setting: none of them is in the English.
  for (const added of ['8.8.8.8', '1.1.1.1:53', 'dns.example:853', '/etc/resolv.conf/', 'upstream=8.8.8.8', '$HOME', 'a|b', 'tls://dns.example']) {
    const tx = `把路由器的 DNS 设为 ${added}`;
    const f = agree(en, tx).fails.filter((x) => x.rule === 'structural');
    expect(f.map((x) => x.detail), added).toContain('added');
    expect(agreesAtRuntime(en, tx), added).toBe(false);
  }
  // Words, acronyms, numbers and the other tokens a translation adds are only reported.
  for (const added of ['DNS', 'IPv6', 'rate_limited', '[x]', '53', 'Wi-Fi']) {
    const v = agree('Holds', `保存 ${added}`);
    expect(v.fails, added).toEqual([]);
    expect(v.reports.map((r) => r.rule), added).toEqual(['added']);
    expect(agreesAtRuntime('Holds', `保存 ${added}`), added).toBe(true);
  }
  // An address that is in the English may be repeated.
  expect(failed('Use 1.1.1.1', '用 1.1.1.1（1.1.1.1）')).toEqual([]);
  // In fullwidth or ideographic punctuation too: the folded reading sees them.
  for (const added of ['８．８．８．８', '8。8。8。8', 'ｄｎｓ．ｅｘａｍｐｌｅ：８５３', '／etc／resolv．conf／', 'upstream＝1.1.1.1', '＄HOME', 'a｜b']) {
    const tx = `把路由器的 DNS 设为 ${added}`;
    expect(failed(en, tx), added).toEqual(['structural']);
    expect(agreesAtRuntime(en, tx), added).toBe(false);
  }
  // There, a fullwidth colon after a word is no host and port, and `：` or `。` joining addresses
  // and words the English has adds nothing; an English `8` hides nothing.
  expect(failed('Holds', '保存 DNS：53')).toEqual([]);
  expect(agreesAtRuntime('Holds', '保存 DNS：53')).toBe(true);
  const joined = ['Network application: https://controller:8443. OPNsense: https://opnsense.lan.', '经典 Network 应用：https://controller:8443。OPNsense：https://opnsense.lan。'];
  expect(failed(joined[0], joined[1])).toEqual([]);
  expect(agreesAtRuntime(joined[0], joined[1])).toBe(true);
  expect(failed('Wait 8 hours', '等待 8 小时 ８．８．８．８')).toEqual(['structural']);
  // Only the English's addresses are taken out, each where it stands whole: an address built from
  // its words, a port added to its host, and an address around its own are still added.
  for (const [english, tx] of [
    ['Ask for help', '求助 ｅｖｉｌ．ｈｅｌｐ：８５３'],
    ['Open example.com', '打开 example.com：53'],
    ['Use 1.1.1.1', '用 1.1.1.1，不用 ２１．１．１．１５'],
  ]) {
    expect(agree(english, tx).fails.map((f) => `${f.rule} ${f.detail}`), tx).toEqual(['structural added']);
    expect(agreesAtRuntime(english, tx), tx).toBe(false);
  }
});

test('api_012 a maintainer may exempt an entry from the added-token rule', () => {
  // Honest translations that add a time, a ratio, a date pattern, a list, a grouped number, a
  // setting or a price fail, each naming its token; an exemption in notes.json reports them instead.
  for (const [en, tx, token] of [
    ['Until midnight', 'Bis 24:00', '24:00'],
    ['Widescreen', 'Breitbild 16:9', '16:9'],
    ['Date format', 'Datumsformat TT/MM/JJJJ', 'TT/MM/JJJJ'],
    ['Day, week, month', 'Tag/Woche/Monat', 'Tag/Woche/Monat'],
    ['A billion', '1.000.000.000', '1.000.000.000'],
    ['Set it', 'Setze a=b', 'a=b'],
    ['Price', 'Preis $5', '$5'],
  ]) {
    expect(agree(en, tx).fails.map((f) => `${f.rule} ${f.token} ${f.detail}`), tx).toEqual([`structural ${token} added`]);
    const v = agree(en, tx, { exemptAdded: [token] });
    expect(v.fails, tx).toEqual([]);
    expect(v.reports.map((r) => r.token), tx).toContain(token);
    // The exemption names its tokens: any other the translation adds still fails.
    expect(agree(en, `${tx} 8.8.8.8`, { exemptAdded: [token] }).fails.map((f) => `${f.rule} ${f.token} ${f.detail}`), tx).toEqual(['structural 8.8.8.8 added']);
    expect(failed(en, tx, { exemptAdded: ['00:00'] }), tx).toEqual(['structural']);
  }
  // An exemption covers added tokens only: an address the English has must stay.
  expect(failed('See https://a.example', '见 https://b.example', { exemptAdded: ['https://b.example'] })).toEqual(['urls', 'structural']);
});

test('api_012 the agreement rule takes linear time on any text', () => {
  // A translator's text is read in the check and in the browser: no pattern may backtrack over a
  // long run. Each of these takes minutes with a quadratic pattern and milliseconds without one.
  const n = 200_000;
  const texts = ['a'.repeat(n), `a${'.'.repeat(n)}b`, `https://a${'.'.repeat(n)}b`, `${'a'.repeat(n)}:`, `x${'1'.repeat(n)}`, `{${'a'.repeat(n)}`, `<b>${'a'.repeat(n)}`, `/${'a'.repeat(n)}`, `\`${'a'.repeat(n)}`, 'a:'.repeat(n / 2)];
  // The folded reading, the address in another script and the suffix after an address.
  texts.push('８'.repeat(n), '例'.repeat(n), `https://${'例'.repeat(n)}`, '例.'.repeat(n / 2), "a'".repeat(n / 2), `https://a${"'a".repeat(n / 2)}`, '．'.repeat(n), `.${'a'.repeat(n)}`);
  // Many short tokens in each reading: each is looked up, never searched for in a list.
  texts.push('a．b '.repeat(2 * n / 5), 'x1．y '.repeat(n / 3));
  const start = performance.now();
  for (const tx of texts) {
    agree('Holds https://a.example', tx);
    agreesAtRuntime('Holds https://a.example', tx);
  }
  expect(performance.now() - start).toBeLessThan(10_000);
});

test('api_012 plural forms other than other may leave out placeholders', () => {
  const en: [string, string] = ['{n} file', '{n} files'];
  const ar = { zero: 'لا ملفات', one: 'ملف واحد', two: 'ملفان', few: '{n} ملفات', many: '{n} ملفًا', other: '{n} ملف' };
  // The check: `other` keeps every placeholder; another form may hold fewer, never one more.
  expect(failed(en[0], ar.one, { placeholderSubset: true })).toEqual([]);
  expect(failed(en[1], ar.two, { placeholderSubset: true })).toEqual([]);
  expect(failed(en[1], '{n} {x} ملف', { placeholderSubset: true })).toEqual(['placeholders']);
  expect(failed(en[1], 'ملف')).toEqual(['placeholders']);
  // Everything else still holds in such a form: a URL, a token, a number.
  expect(failed('Wait {n} day for https://a.example', 'انتظر https://b.example', { placeholderSubset: true })).toEqual(['urls', 'structural']);
  // The browser shows such a catalog, and drops one whose `other` or another form breaks the rule.
  const k = hash('c', en);
  under({ tag: 'ar', table: table({ [k]: ar }) }, () => {
    const { tn } = tr('c');
    expect([0, 1, 2, 3, 11, 100].map((n) => tn(en[0], en[1], n, { n }))).toEqual(['لا ملفات', 'ملف واحد', 'ملفان', '3 ملفات', '11 ملفًا', '100 ملف']);
  });
  for (const broken of [{ ...ar, other: 'ملف' }, { ...ar, two: '{n} {x} ملفان' }]) {
    under({ tag: 'ar', table: table({ [k]: broken }) }, () => expect(tr('c').tn(en[0], en[1], 2, { n: 2 })).toBe('2 files'));
  }
});

test('api_012 pseudo text keeps placeholders and tags and accents every letter', () => {
  expect(LOWER).toHaveLength(26);
  expect(UPPER).toHaveLength(26);
  expect([...LOWER, ...UPPER].every((c) => c.charCodeAt(0) > 127)).toBe(true);
  const p = pseudo('Muted by <b>{who}</b>: 3 rows');
  expect(p).toContain('<b>{who}</b>');
  expect(p).toContain('3');
  expect(p.replace(/<\/?b>|\{who\}/g, '')).not.toMatch(/[A-Za-z]/);
  const plain = 'Holds the answers';
  expect(pseudo(plain).length).toBeGreaterThanOrEqual(Math.ceil(plain.length * 1.3));
  expect(pseudo('')).toBe('');
  under({ tag: 'en-XA' }, () => expect(tr('fixture').t('Hello {name}', { name: 'Ada' })).toBe(pseudo('Hello {name}').replace('{name}', 'Ada')));
});

// ---------------------------------------------------------------------------------------------
// The runtime and its tables


test('api_012 catalog entries named like object members are data', () => {
  const parsed = parseCatalog(
    '{"__proto__": {"polluted": "yes"}, "constructor": "c", "toString": "t", "0123abcd": "ok", "0123abce": {"other": "x", "__proto__": "y", "constructor": "z"}}',
  ) as Record<string, unknown>;
  expect(Object.getPrototypeOf(parsed)).toBeNull();
  expect(Object.keys(parsed)).toEqual(['0123abcd', '0123abce']);
  expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  expect(Object.getPrototypeOf(parsed['0123abce'])).toBeNull();
  expect(Object.keys(parsed['0123abce'] as object)).toEqual(['other']);
  expect(Object.keys(parseCatalog('not json'))).toEqual([]);
  expect(Object.keys(parseCatalog('[1, 2]'))).toEqual([]);
  const t3 = table({ [hash('c', 'constructor')]: 'Qa-constructor', [hash('c', '__proto__')]: 'Qa __proto__', [hash('__proto__', 'x')]: 'Qa-x' });
  under({ tag: 'qaa', table: t3 }, () => {
    const { t } = tr('c');
    expect(t('constructor')).toBe('Qa-constructor');
    expect(t('__proto__')).toBe('Qa __proto__');
    expect(t('toString')).toBe('toString');
    expect(t('hasOwnProperty')).toBe('hasOwnProperty');
    expect(t('valueOf')).toBe('valueOf');
    expect(tk({ c: 'c', e: 'constructor' })).toBe('Qa-constructor');
    expect(tr('__proto__').t('x')).toBe('Qa-x');
    expect(tr('constructor').t('toString')).toBe('toString');
  });
});

test('api_012 the runtime drops a translation that differs from current english', () => {
  const en = {
    url: 'Read https://example.com/docs first',
    token: 'Set upstream=1.1.1.1',
    placeholder: 'Hello {name}',
    digits: 'Wait 7 days',
    tag: 'Kept by <b>{who}</b>',
    ok: 'Holds',
  };
  const entries = {
    [hash('c', en.url)]: 'Qa-read https://evil.example/docs',
    [hash('c', en.token)]: 'Qa-set upstream',
    [hash('c', en.placeholder)]: 'Qa-hello',
    [hash('c', en.digits)]: 'Qa-wait days',
    [hash('c', en.tag)]: 'Qa-kept {who}',
    [hash('c', en.ok)]: 'Qa-holds',
    [hash('c', ['{n} answer', '{n} answers'])]: { other: 'Qa answers' },
  };
  under({ tag: 'qaa', table: table(entries) }, () => {
    const { t, tn } = tr('c');
    expect(t('Read https://example.com/docs first')).toBe(en.url);
    expect(t('Set upstream=1.1.1.1')).toBe(en.token);
    expect(t('Hello {name}', { name: 'Ada' })).toBe('Hello Ada');
    expect(t('Wait 7 days')).toBe(en.digits);
    expect(t('Kept by <b>{who}</b>', { who: 'x' })).toBe('Kept by <b>x</b>');
    expect(tn('{n} answer', '{n} answers', 2, { n: 2 })).toBe('2 answers');
    // An agreeing translation is shown, and found again however the English is spaced or quoted.
    expect(t('Holds')).toBe('Qa-holds');
    expect(t(' Holds ')).toBe('Qa-holds');
    // A translation made from older English matches nothing: English.
    expect(t('Holds now')).toBe('Holds now');
  });
});

test('api_012 the catalog step falls back to english', async () => {
  const locales = Object.assign(Object.create(null), { 'zh-Hans': { url: '/assets/locales/zh-Hans-00000000.json', dir: 'ltr', offered: true } });
  const src = (languages: string[], search = '') => ({ search, stored: null, languages });
  const body = JSON.stringify({ [hash('c', 'Holds')]: '保存' });
  const ok = (async () => new Response(body, { status: 200 })) as typeof fetch;
  const asked: string[] = [];
  const spy = (async (url: string) => (asked.push(url), new Response(body))) as typeof fetch;
  // English needs no request.
  expect(await load(locales, src(['en-US']), spy)).toEqual({ tag: 'en' });
  expect(await load(locales, src(['de-DE']), spy)).toEqual({ tag: 'en' });
  expect(asked).toEqual([]);
  expect(await load(locales, src(['en-US'], '?lang=en-XA'), spy)).toEqual({ tag: 'en-XA' });
  // A catalog: its table, its direction, and the browser's variant of its language for formats.
  const zh = await load(locales, src(['zh-CN', 'en']), ok);
  expect(zh.tag).toBe('zh-Hans');
  expect(zh.formatLocale).toBe('zh-CN');
  under(zh, () => expect(tr('c').t('Holds')).toBe('保存'));
  // A failed, refused or late catalog request: English.
  expect(await load(locales, src(['zh-CN']), (async () => new Response('', { status: 404 })) as typeof fetch)).toEqual({ tag: 'en' });
  expect(await load(locales, src(['zh-CN']), (async () => Promise.reject(new Error('offline'))) as typeof fetch)).toEqual({ tag: 'en' });
  const never = ((_u: string, init?: RequestInit) =>
    new Promise((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted'))))) as typeof fetch;
  expect(await load(locales, src(['zh-CN']), never, 20)).toEqual({ tag: 'en' });
  // A catalog that does not parse, or holds no entry, is English: never a page tagged zh-Hans that
  // shows only English text in Chinese formats.
  for (const text of ['not json', '{}', '[]', '{"constructor": "x"}']) {
    expect(await load(locales, src(['zh-CN']), (async () => new Response(text)) as typeof fetch), text).toEqual({ tag: 'en' });
  }
  for (const empty of [undefined, table({}), table({ toString: 'x' })]) expect(install({ tag: 'zh-Hans', table: empty }).lang).toBe('en');
  install({ tag: 'en' });
  // A provider is asked first; nothing, or a failure, goes on as before.
  expect(await load(locales, src(['en-US']), spy, 4000, () => ({ tag: 'en-XA' }))).toEqual({ tag: 'en-XA', built: false });
  expect(await load(locales, src(['en-US']), spy, 4000, () => null)).toEqual({ tag: 'en' });
  expect(
    await load(locales, src(['en-US']), spy, 4000, () => {
      throw new Error('broken');
    }),
  ).toEqual({ tag: 'en' });
  expect(asked).toEqual([]);
});

test('api_012 the browser re-checks digits and added tokens only where the build did not ship the catalog', async () => {
  // Pairs a maintainer exempted from the digit rule and from the added-token rule: the build ships
  // them, and the browser shows them.
  const entries = {
    [hash('c', 'Wait 7 days')]: 'Qa-wait a week',
    [hash('c', 'Until midnight')]: 'Qa-bis 24:00',
    [hash('c', 'Read https://a.example')]: 'Qa-read https://b.example',
  };
  const locales = Object.assign(Object.create(null), { qaa: { url: '/assets/locales/qaa-00000000.json', dir: 'ltr', offered: true } });
  const built = await load(locales, { search: '', stored: null, languages: ['qaa'] }, (async () => new Response(JSON.stringify(entries))) as typeof fetch);
  expect(built.built).toBe(true);
  under(built, () => {
    expect(tr('c').t('Wait 7 days')).toBe('Qa-wait a week');
    expect(tr('c').t('Until midnight')).toBe('Qa-bis 24:00');
    // Every other rule still holds in the browser.
    expect(tr('c').t('Read https://a.example')).toBe('Read https://a.example');
  });
  // The same table from anywhere else (a provider) is held to both rules, even when the provider
  // says it is built.
  for (const provided of [{ tag: 'qaa', table: table(entries) }, { tag: 'qaa', table: table(entries), built: true }]) {
    const other = await load(locales, { search: '', stored: null, languages: [] }, fetch, 4000, () => provided);
    expect(other.built).toBe(false);
    under(other, () => {
      expect(tr('c').t('Wait 7 days')).toBe('Wait 7 days');
      expect(tr('c').t('Until midnight')).toBe('Until midnight');
    });
  }
});

// ---------------------------------------------------------------------------------------------
// The pair files


test('api_012 the pair-file parser refuses what json would lose', () => {
  expect(parse('{"a": [1, "x", null, true]}')).toEqual({ a: [1, 'x', null, true] });
  const refused = (text: string, limits?: { bytes: number; depth: number }) => {
    try {
      parse(text, limits);
      return null;
    } catch (e) {
      expect(e).toBeInstanceOf(PairFileError);
      return (e as Error).message;
    }
  };
  expect(refused('{"a": [], "a": []}')).toContain('the key "a" twice');
  expect(refused('{"c": [[["one", "other"], {"other": "x", "other": "y"}]]}')).toContain('the key "other" twice');
  expect(refused('[[[[[1]]]]]')).toContain('nesting deeper than 4');
  expect(refused('{"a": 1}', { bytes: 4, depth: 4 })).toContain('over 4 characters');
  expect(refused('{"a": 1} x')).toContain('text after the end');
  expect(refused('{"a": "\u0001"}')).toContain('a malformed string');
  expect(refused('{"a": 1,}')).toContain('a key that is not a string');
  const proto = parse('{"__proto__": {"x": 1}}') as Record<string, unknown>;
  expect(Object.getPrototypeOf(proto)).toBe(Object.prototype);
  expect(Object.keys(proto)).toEqual(['__proto__']);
  expect(({} as Record<string, unknown>).x).toBeUndefined();
  // sync is extract -> skeleton -> merge: the same functions run on a skeleton alone.
  const skel = skeleton([{ ctx: 'c', english: 'Holds' }, { ctx: 'c', english: ['{n} file', '{n} files'] }, { ctx: 'c', english: 'Open', note: 'verb' }], ['one', 'few', 'other']);
  expect(skel).toEqual({ c: [['Holds', ''], [['{n} file', '{n} files'], { one: '', few: '', other: '' }], ['Open', '', 'verb']] });
  const key = (ctx: string, e: unknown, n?: string) => `${ctx}|${JSON.stringify(e)}|${n ?? ''}`;
  const merged = merge({ c: [['Holds', 'Qa'], ['Gone', 'Qa-gone']], '~leftover': [['Older', 'Qa-older']] }, skel, key);
  expect(merged.c).toEqual([['Holds', 'Qa'], [['{n} file', '{n} files'], { one: '', few: '', other: '' }], ['Open', '', 'verb']]);
  expect(merged['~leftover']).toEqual([['Older', 'Qa-older'], ['Gone', 'Qa-gone']]);
  expect(merge({ c: [['Gone', 'x']] }, skel, key, { prune: true })['~leftover']).toBeUndefined();
  // A context named like an object member (a file called Constructor.svelte) is just a context.
  for (const ctx of ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__']) {
    const s = skeleton([{ ctx, english: 'Holds' }], ['other']);
    expect(Object.keys(s), ctx).toEqual([ctx]);
    const m = merge(parse(`{"${ctx}": [["Holds", "Qa"]]}`) as never, s, key);
    expect(m[ctx], ctx).toEqual([['Holds', 'Qa']]);
  }
});

// A page that checks a file says why in its own words: the parser's refusal carries its reason (and the
// repeated key), and a pair's shape problem is a code. The check keeps its wording.
test('api_012 a pair-file refusal and a shape problem name their reason', () => {
  const why = (text: string, limits?: { bytes: number; depth: number }) => {
    try {
      parse(text, limits);
      return null;
    } catch (e) {
      expect(e).toBeInstanceOf(PairFileError);
      const x = e as PairFileError;
      return { reason: x.reason, key: x.key, at: x.at };
    }
  };
  expect(why('{"a": [], "a": []}')).toEqual({ reason: 'duplicate', key: 'a', at: 10 });
  expect(why('{"c": [[["one", "other"], {"other": "x", "other": "y"}]]}')).toMatchObject({ reason: 'duplicate', key: 'other' });
  expect(why('[[[[[1]]]]]')).toEqual({ reason: 'depth', key: undefined, at: 4 });
  expect(why('{"a": 1}', { bytes: 4, depth: 4 })).toMatchObject({ reason: 'size' });
  for (const text of ['{"a": 1} x', '{"a": 1,}', '{"a": "\u0001"}', '{"a": [1, 2', '']) expect(why(text)?.reason, JSON.stringify(text)).toBe('syntax');
  const cats = ['one', 'other'];
  const cases: [unknown, string | null, string | null][] = [
    [['Holds', 'Qa'], null, null],
    [['Holds'], 'pair', 'a pair is [english, translation] or [english, translation, note]'],
    [['Holds', 'Qa', 'n', 'x'], 'pair', 'a pair is [english, translation] or [english, translation, note]'],
    ['Holds', 'pair', 'a pair is [english, translation] or [english, translation, note]'],
    [['Holds', 'Qa', ''], 'note', 'a note is a non-empty string'],
    [['Holds', 'Qa', 3], 'note', 'a note is a non-empty string'],
    [['', 'Qa'], 'english', 'the English is empty'],
    [['Holds', 3], 'text', 'the translation of a message is a string'],
    [[['a'], { one: '', other: '' }], 'plural-english', 'the English of a plural is [one, other]'],
    [[['a', ''], { one: '', other: '' }], 'plural-english', 'the English of a plural is [one, other]'],
    [[['a', 'b'], 'x'], 'plural-text', 'the translation of a plural is an object of strings'],
    [[['a', 'b'], { one: 1, other: '' }], 'plural-text', 'the translation of a plural is an object of strings'],
    [[['a', 'b'], { other: '' }], 'categories', 'plural categories ["other"]; this language has ["one","other"]'],
    [[['a', 'b'], { one: '', other: '' }], null, null],
  ];
  for (const [p, code, words] of cases) {
    expect(shapeProblem(p, cats, 'c')?.code ?? null, JSON.stringify(p)).toBe(code);
    expect(shapeError(p, cats, 'c'), JSON.stringify(p)).toBe(words);
  }
  expect(shapeProblem([['a', 'b'], { other: '' }], cats, 'c')).toEqual({ code: 'categories', got: ['other'], want: ['one', 'other'] });
  expect(shapeProblem([['a', 'b'], { other: '' }], cats, '~leftover')).toBeNull();
});

// ---------------------------------------------------------------------------------------------
// The formats


/** `ui/src/lib/format.ts` as it was before the factory, with the locale as a parameter where it
 * used the browser default (`undefined`, or `[]` in the `toLocale*` calls). */
function frozen(locale: string | undefined) {
  const at = locale ?? [];
  const nf = new Intl.NumberFormat(locale);
  const compact = new Intl.NumberFormat(locale, { notation: 'compact', maximumFractionDigits: 1 });
  const num = (n: number | undefined | null) => (n == null ? '–' : nf.format(n));
  const rate2 = new Intl.NumberFormat(locale, { maximumFractionDigits: 2 });
  const rate1 = new Intl.NumberFormat(locale, { maximumFractionDigits: 1 });
  const rate0 = new Intl.NumberFormat(locale, { maximumFractionDigits: 0 });
  const rate = (n: number | undefined | null) => (n == null ? '–' : (n < 10 ? rate2 : n < 100 ? rate1 : rate0).format(n));
  const short = (n: number | undefined | null) => (n == null ? '–' : n < 10_000 ? nf.format(n) : compact.format(n));
  const pct = (n: number | undefined | null, digits = 1) => (n == null || Number.isNaN(n) ? '–' : `${n.toFixed(digits)}%`);
  function ms(n: number | undefined | null): string {
    if (n == null) return '–';
    if (n === 0) return '0 ms';
    if (n < 1) return `${(n * 1000).toFixed(0)} µs`;
    if (n < 10) return `${n.toFixed(2)} ms`;
    if (n < 1000) return `${n.toFixed(0)} ms`;
    return `${(n / 1000).toFixed(2)} s`;
  }
  function bytes(n: number | undefined | null): string {
    if (n == null) return '–';
    const u = ['B', 'KiB', 'MiB', 'GiB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) {
      n /= 1024;
      i++;
    }
    return `${i ? n.toFixed(1) : n} ${u[i]}`;
  }
  function duration(secs: number): string {
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    if (d) return `${d}d ${h}h`;
    if (h) return `${h}h ${m}m`;
    if (m) return `${m}m`;
    return `${Math.floor(secs)}s`;
  }
  function ago(unix: number | undefined | null): string {
    if (!unix) return 'never';
    const diff = Date.now() / 1000 - unix;
    const s = duration(Math.abs(diff));
    return diff >= 0 ? `${s} ago` : `in ${s}`;
  }
  function clock(unixSeconds: number, withSeconds = false): string {
    return new Date(unixSeconds * 1000).toLocaleTimeString(at, { hour: '2-digit', minute: '2-digit', second: withSeconds ? '2-digit' : undefined });
  }
  function dateTime(unixSeconds: number): string {
    return new Date(unixSeconds * 1000).toLocaleString(locale);
  }
  function logTime(rfc3339: string): string {
    const d = new Date(rfc3339);
    const t = d.toLocaleTimeString(at, { hour12: false });
    return `${t}.${String(d.getMilliseconds()).padStart(3, '0')}`;
  }
  function logDate(rfc3339: string): string {
    return new Date(rfc3339).toLocaleDateString(locale);
  }
  function endsAt(rfc3339: string | null | undefined): string {
    if (!rfc3339) return '';
    const d = new Date(rfc3339);
    const time = d.toLocaleTimeString(at, { hour: '2-digit', minute: '2-digit' });
    return d.toDateString() === new Date().toDateString() ? time : `${d.toLocaleDateString(at, { weekday: 'short' })} ${time}`;
  }
  return { num, rate, short, pct, ms, bytes, duration, ago, clock, dateTime, logTime, logDate, endsAt };
}

test('api_012 english formats match the frozen functions', () => {
  // A fixed clock, so `ago` and `endsAt` see the same "now" in both.
  const NOW = Date.UTC(2026, 10, 24, 12, 34, 56, 789);
  const Real = Date;
  class Fixed extends Real {
    constructor(...a: ConstructorParameters<typeof Date>) {
      if (a.length) super(...a);
      else super(NOW);
    }
    static now() {
      return NOW;
    }
  }
  globalThis.Date = Fixed as DateConstructor;
  try {
    const numbers = [undefined, null, 0, 0.0004, 0.5, 1, 9.999, 10, 12.345, 99.95, 100, 999.4, 1000, 1234.5, 9999, 10_000, 123_456, 1e7, -5, -0.25, Number.NaN];
    const seconds = [0, 1, 59, 60, 61, 3599, 3600, 3661, 86_399, 86_400, 90_061, 1e6];
    const unix = [undefined, null, 0, NOW / 1000 - 30, NOW / 1000 - 3600, NOW / 1000 - 86_400 * 3, NOW / 1000 + 120, NOW / 1000 + 90_061];
    const times = ['2026-11-24T12:00:00.007Z', '2026-11-24T23:59:59.999Z', '2026-11-20T03:04:05.060Z', '2025-01-01T00:00:00Z'];
    for (const locale of [undefined, 'en-US', 'de-DE', 'fr-FR']) {
      const want = frozen(locale);
      // The module's own functions (the default instance, before and without install) for the browser
      // default; and the instance the runtime installs, with English, for each locale.
      const instances: [string, ReturnType<typeof makeFormat>][] = [['the runtime instance', makeFormat(locale, (ctx) => tr(ctx))]];
      if (locale === undefined) instances.push(['the exports', fmt]);
      for (const [name, got] of instances) {
        const tag = `${locale ?? 'default'} ${name}`;
        for (const n of numbers) {
          expect(got.num(n), `${tag} num ${n}`).toBe(want.num(n));
          expect(got.rate(n), `${tag} rate ${n}`).toBe(want.rate(n));
          expect(got.short(n), `${tag} short ${n}`).toBe(want.short(n));
          for (const d of [undefined, 0, 1, 2]) expect(got.pct(n, d), `${tag} pct ${n} ${d}`).toBe(want.pct(n, d));
          expect(got.ms(n), `${tag} ms ${n}`).toBe(want.ms(n));
          expect(got.bytes(n), `${tag} bytes ${n}`).toBe(want.bytes(n));
        }
        for (const b of [1023, 1024, 1536, 1_048_576, 5e9, 1e13, 1e16]) expect(got.bytes(b), `${tag} bytes ${b}`).toBe(want.bytes(b));
        for (const s of seconds) expect(got.duration(s), `${tag} duration ${s}`).toBe(want.duration(s));
        for (const u of unix) expect(got.ago(u), `${tag} ago ${u}`).toBe(want.ago(u));
        for (const u of [NOW / 1000, NOW / 1000 - 40_000]) {
          expect(got.clock(u), `${tag} clock ${u}`).toBe(want.clock(u));
          expect(got.clock(u, true), `${tag} clock ${u} s`).toBe(want.clock(u, true));
          expect(got.dateTime(u), `${tag} dateTime ${u}`).toBe(want.dateTime(u));
        }
        for (const t of times) {
          expect(got.logTime(t), `${tag} logTime ${t}`).toBe(want.logTime(t));
          expect(got.logDate(t), `${tag} logDate ${t}`).toBe(want.logDate(t));
          expect(got.endsAt(t), `${tag} endsAt ${t}`).toBe(want.endsAt(t));
        }
        for (const t of [null, undefined, '']) expect(got.endsAt(t), `${tag} endsAt ${t}`).toBe(want.endsAt(t));
      }
    }
  } finally {
    globalThis.Date = Real;
  }
});

test('api_012 formats moved into format.ts keep their english', () => {
  // The expressions other files held (A1b: lib/dash/smooth.ts, SmoothChart.svelte, Stat.svelte,
  // lib/heatmap.ts; A1c: Chart.svelte, whose axis date is A1b's monthDay expression,
  // DeviceTimeline.svelte, BudgetAttribution.svelte; A1d: Kpi.svelte, Tabs.svelte, and the counts of
  // RolloutPanel.svelte and SimulationCard.svelte (`toLocaleString()`), LatencyHeatmap.svelte's axis
  // date (A1b's monthDay expression), NodeCompare.svelte's weekday and time, SimulationCard.svelte's
  // window start; A1e: Traffic.svelte's "updated" time), copied as they were, with the locale as a
  // parameter where they used `[]` (or nothing).
  const old = (locale: string | undefined) => {
    const at = locale ?? [];
    return {
      trafficUpdated: (d: Date) => d.toLocaleTimeString(locale),
      monthDay: (t: number) => new Date(t * 1000).toLocaleDateString(at, { month: 'short', day: 'numeric' }),
      weekdayDate: (t: number) => new Date(t * 1000).toLocaleDateString(at, { weekday: 'short', month: 'short', day: 'numeric' }),
      clock: (t: number, withSec: boolean) => new Date(t * 1000).toLocaleTimeString(at, { hour: '2-digit', minute: '2-digit', second: withSec ? '2-digit' : undefined }),
      whole: (p: number) => Math.round(p).toLocaleString(locale),
      timelineHm: (t: number) => new Date(t * 1000).toLocaleTimeString(at, { hour: '2-digit', minute: '2-digit' }),
      timelineDay: (t: number) => new Date(t * 1000).toLocaleDateString(at, { weekday: 'short', day: 'numeric', month: 'short' }),
      budgetSince: (s: string) => new Date(s).toLocaleDateString(locale),
      nodeSince: (s: string) => new Date(s).toLocaleString(at, { weekday: 'short', hour: '2-digit', minute: '2-digit' }),
      simulationFrom: (s: string) => new Date(s).toLocaleString(locale),
      count: (n: number) => n.toLocaleString(locale),
    };
  };
  const at = [Date.UTC(2026, 10, 24, 12, 34, 56) / 1000, Date.UTC(2026, 0, 1, 0, 0, 0) / 1000, Date.UTC(2025, 6, 4, 23, 59, 59) / 1000];
  for (const locale of [undefined, 'en-US', 'de-DE', 'fr-FR']) {
    const want = old(locale);
    const instances: [string, ReturnType<typeof makeFormat>][] = [['the runtime instance', makeFormat(locale, (ctx) => tr(ctx))]];
    if (locale === undefined) instances.push(['the exports', fmt]);
    for (const [name, got] of instances) {
      const tag = `${locale ?? 'default'} ${name}`;
      for (const t of at) {
        expect(got.monthDay(t), `${tag} monthDay ${t}`).toBe(want.monthDay(t));
        expect(got.weekdayDate(t), `${tag} weekdayDate ${t}`).toBe(want.weekdayDate(t));
        for (const s of [false, true]) expect(got.clock(t, s), `${tag} clock ${t} ${s}`).toBe(want.clock(t, s));
        expect(got.clock(t), `${tag} timeline time ${t}`).toBe(want.timelineHm(t));
        expect(got.weekdayDate(t), `${tag} timeline day ${t}`).toBe(want.timelineDay(t));
        const rfc = new Date(t * 1000).toISOString();
        expect(got.logDate(rfc), `${tag} budget since ${rfc}`).toBe(want.budgetSince(rfc));
        expect(got.weekdayTime(rfc), `${tag} node odd since ${rfc}`).toBe(want.nodeSince(rfc));
        expect(got.dateTime(Date.parse(rfc) / 1000), `${tag} simulation window ${rfc}`).toBe(want.simulationFrom(rfc));
        expect(got.timeOfDay(new Date(t * 1000 + 789)), `${tag} traffic map updated ${t}`).toBe(want.trafficUpdated(new Date(t * 1000 + 789)));
      }
      for (const p of [100, 100.4, 999.5, 1234.4, 98_765.6]) expect(got.num(Math.round(p)), `${tag} whole ${p}`).toBe(want.whole(p));
      for (const n of [0, 7, 999, 1000, 1234, 1_234_567, 12_345_678]) expect(got.num(n), `${tag} count ${n}`).toBe(want.count(n));
    }
  }
});
