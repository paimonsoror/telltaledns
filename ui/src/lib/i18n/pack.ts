// REQ: API-013 (ADR-190) — checking a translated pair file in the browser with the build's own
// rules: the shared parser, the shipping function and the whole agreement rule, run against the
// build's template. A file outside the format or the limits is refused whole (nothing is kept); an
// entry that breaks the agreement rule, or has other plural categories than its language, is
// dropped and English is shown; report-only findings drop nothing; left-over pairs say why. Text
// decides what is current, never a hash. Also the language tag a translator types (and, from
// `names.ts`, how a file name and a pack's text are shown inert). Pure, apart from `Intl` (canonical
// tags, scripts).
import { englishKey } from './ident.ts';
import { LEFTOVER, PairFileError, parse, serialize, shapeProblem, type Catalog, type Pair } from './pairs.ts';
import { identity, ship } from './shipping.ts';
import { forPullRequest, type Template } from './template.ts';

export { languageName, markers, shownName } from './names.ts';

/** The limits of a pack: the file's bytes, its pairs and contexts, and the length of one string. */
export const MAX_BYTES = 1024 * 1024;
export const MAX_PAIRS = 10_000;
export const MAX_CONTEXTS = 600;
export const MAX_CHARS = 4000;
const CONTEXT = /^[a-z][A-Za-z0-9]{0,63}$/;
/** Languages written in more than one script (as the check script has them): a tag names the script. */
export const MULTI_SCRIPT = ['az', 'bs', 'ha', 'kk', 'ks', 'ku', 'mn', 'pa', 'sd', 'sr', 'uz', 'zh'];
/** Scripts written right to left. */
const RTL = ['Arab', 'Hebr', 'Thaa', 'Syrc', 'Nkoo', 'Adlm', 'Rohg'];
const SHAPE = /^[a-z]{2,3}(-[A-Z][a-z]{3})?(-(?:[A-Z]{2}|\d{3}))?$/;

export type Tag = { readonly tag: string; readonly language: string; readonly dir: 'ltr' | 'rtl'; readonly categories: readonly string[] };
/** A tag refused: `syntax` (not a tag), `english`, `pseudo` (en-XA, ar-XB), `reserved` (qaa-qtz,
 * mis, mul, zxx, und, private use), `shape` (variants, extensions), `alias` (a tag the engine
 * rewrites to another language: `hint`), `plurals` (not in the committed table), `script` (a
 * language of several scripts named without one: `hint`). */
export type TagRefusal = {
  readonly code: 'empty' | 'syntax' | 'english' | 'pseudo' | 'reserved' | 'shape' | 'alias' | 'plurals' | 'script';
  readonly language?: string;
  readonly hint?: string;
};

/** The canonical form of a typed tag, and its language's direction and plural categories (from the
 * committed table the template carries, never from the engine), or why it is refused. */
export function tagInfo(input: string, plurals: ReadonlyMap<string, readonly string[]>): { ok: true; value: Tag } | { ok: false; why: TagRefusal } {
  const no = (why: TagRefusal) => ({ ok: false as const, why });
  const typed = input.trim();
  if (!typed) return no({ code: 'empty' });
  let tag: string | undefined;
  try {
    [tag] = Intl.getCanonicalLocales(typed);
  } catch {
    return no({ code: 'syntax' });
  }
  if (!tag) return no({ code: 'syntax' });
  if (/(^|-)x-/i.test(tag)) return no({ code: 'reserved' });
  const loc = new Intl.Locale(tag);
  const language = loc.language;
  // The language as typed: alias data differs between engines (`iw` is `he` in some), so the
  // committed table, not the engine, decides which language a file is.
  const asTyped = typed.split('-')[0].toLowerCase();
  const reserved = (l: string) => /^q[a-t][a-z]$/.test(l) || ['mis', 'mul', 'zxx', 'und', 'root'].includes(l);
  if (language === 'en') return no({ code: 'english' });
  if (['XA', 'XB', 'XC'].includes(loc.region ?? '')) return no({ code: 'pseudo' });
  if (reserved(language) || reserved(asTyped)) return no({ code: 'reserved', language: asTyped });
  if (!SHAPE.test(tag)) return no({ code: 'shape' });
  if (asTyped !== language) return no({ code: 'alias', language, hint: tag });
  const categories = plurals.get(language);
  if (!categories) return no({ code: 'plurals', language });
  if (MULTI_SCRIPT.includes(language) && !loc.script) return no({ code: 'script', language, hint: `${language}-${new Intl.Locale(language).maximize().script ?? ''}` });
  const script = loc.maximize().script ?? '';
  return { ok: true, value: { tag, language, dir: RTL.includes(script) ? 'rtl' : 'ltr', categories } };
}

/** Strict UTF-8 (null when the bytes are not), and whether a byte-order mark led. */
export function decodeFile(bytes: Uint8Array): { text: string; bom: boolean } | null {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
  const bom = text.startsWith('\uFEFF');
  return { text: bom ? text.slice(1) : text, bom };
}

/** Why a file is refused whole. `json`, `duplicate`: where (line and column, from 1). */
export type Refusal =
  | { readonly code: 'size' | 'utf8' | 'depth' | 'shape' | 'pairs' | 'contexts' }
  | { readonly code: 'json'; readonly line: number; readonly column: number }
  | { readonly code: 'duplicate'; readonly key: string; readonly line: number; readonly column: number }
  | { readonly code: 'context'; readonly ctx: string }
  | { readonly code: 'long'; readonly ctx: string; readonly n: number }
  | { readonly code: 'pair'; readonly ctx: string; readonly n: number; readonly shape: string };

/** An entry dropped (English is shown): `rule` is the agreement rule that failed (`placeholders`,
 * `urls`, `code-point`, …, with its token and the form's English and translation), `twice` (the same
 * English and note again in one context), or `categories` (other plural categories than the language's). */
export type Broken = {
  readonly ctx: string;
  readonly english: Pair[0];
  readonly note?: string;
  readonly rule: string;
  readonly token?: string;
  /** `missing`, `added`, … (the agreement rule's own word). */
  readonly detail?: string;
  readonly form?: string;
  readonly translation?: string;
  readonly got?: readonly string[];
  readonly want?: readonly string[];
};
/** A report-only finding (the entry is kept): `hyphenated`, `capitals` or `added`, with its token. */
export type Worth = { readonly ctx: string; readonly english: Pair[0]; readonly note?: string; readonly rule: string; readonly token: string };
/** A pair that is not used: `note` (the same English as a current entry, another third item),
 * `gone` (English this build does not have), `aside` (under `~leftover`). */
export type Leftover = { readonly ctx: string; readonly english: Pair[0]; readonly note?: string; readonly reason: 'note' | 'gone' | 'aside' };
export type Coverage = { readonly ctx: string; readonly total: number; readonly translated: number };
export type Checked = {
  /** What a page shows: hash -> translation (or plural forms), null prototype. */
  readonly table: Readonly<Record<string, string | Readonly<Record<string, string>>>>;
  readonly total: number;
  readonly translated: number;
  /** Every finding that drops an entry: one text of the file can have several. */
  readonly broken: readonly Broken[];
  /** How many texts of the file (pairs) break a rule: a pair with several findings counts once. */
  readonly brokenTexts: number;
  readonly worth: readonly Worth[];
  readonly missing: readonly { readonly ctx: string; readonly english: Pair[0]; readonly note?: string }[];
  readonly leftovers: readonly Leftover[];
  /** Per context of the template, lowest share first. */
  readonly coverage: readonly Coverage[];
  /** Whether the file is already in the repository's exact form. */
  readonly canonical: boolean;
  /** What `sync <tag>` writes for this file at this build ("Download for a pull request"). */
  readonly pr: string;
};

const code = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const noteOf = (p: Pair) => (typeof p[2] === 'string' && p[2] !== '' ? p[2] : undefined);
// A string over the limit anywhere in a pair: its English, its translation, its note, a plural form or a
// plural form's key.
const longer = (x: unknown): boolean =>
  typeof x === 'string'
    ? x.length > MAX_CHARS
    : Array.isArray(x)
      ? x.some(longer)
      : !!x && typeof x === 'object' && (Object.keys(x).some(longer) || Object.values(x).some(longer));
function where(text: string, at: number) {
  let line = 1;
  let start = 0;
  for (let i = 0; i < at && i < text.length; i++)
    if (text.charCodeAt(i) === 10) {
      line++;
      start = i + 1;
    }
  return { line, column: at - start + 1 };
}

/** Checks the text of a pack (`bom`: a byte-order mark led it) for the language `tag` against the
 * template. `full: false` (a page load) stops at the table. */
export function checkPack(text: string, bom: boolean, tpl: Template, tag: Tag, { full = true } = {}): { refused: Refusal } | { refused?: undefined; checked: Checked } {
  let raw: unknown;
  try {
    raw = parse(text, { bytes: MAX_BYTES, depth: 4 });
  } catch (e) {
    if (!(e instanceof PairFileError)) throw e;
    if (e.reason === 'size' || e.reason === 'depth') return { refused: { code: e.reason } };
    const { line, column } = where(text, e.at);
    return { refused: e.reason === 'duplicate' ? { code: 'duplicate', key: e.key ?? '', line, column } : { code: 'json', line, column } };
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !Object.values(raw).every((v) => Array.isArray(v))) return { refused: { code: 'shape' } };
  const cat = raw as Catalog;
  const names = Object.keys(cat);
  if (names.length > MAX_CONTEXTS) return { refused: { code: 'contexts' } };
  let count = 0;
  for (const ctx of names) {
    if (ctx !== LEFTOVER && !CONTEXT.test(ctx)) return { refused: { code: 'context', ctx } };
    count += cat[ctx].length;
  }
  if (count > MAX_PAIRS) return { refused: { code: 'pairs' } };
  const sameEnglish = new Set([...tpl.entries.values()].map((e) => `${e.ctx}\u0004${englishKey(e.english)}`));
  const reason = (ctx: string, english: Pair[0]) => (sameEnglish.has(`${ctx}\u0004${englishKey(english as string)}`) ? 'note' : 'gone');
  const broken: Broken[] = [];
  const leftovers: Leftover[] = [];
  const failed = new Set<string>();
  const kept: Catalog = Object.create(null);
  for (const ctx of names) {
    const list: Pair[] = [];
    // A plural's identity met before in this context: the later pair is set aside, as `sync` and Download for a pull
    // request do ("twice"), and the first decides, whether or not it has the language's categories. So the shipping
    // function never meets a repeated plural here, and never takes a later one for the first.
    const plurals = new Set<string>();
    for (let i = 0; i < cat[ctx].length; i++) {
      const p: unknown = cat[ctx][i];
      const problem = shapeProblem(p, tag.categories, ctx);
      if (problem && problem.code !== 'categories') return { refused: { code: 'pair', ctx, n: i + 1, shape: problem.code } };
      if (longer(p)) return { refused: { code: 'long', ctx, n: i + 1 } };
      const pair = p as Pair;
      const plural = ctx !== LEFTOVER && Array.isArray(pair[0]);
      const id = plural || problem?.code === 'categories' ? identity(ctx, pair[0], noteOf(pair)) : '';
      if (plural) {
        if (plurals.has(id)) {
          broken.push({ ctx, english: pair[0], note: noteOf(pair), rule: 'twice' });
          continue;
        }
        plurals.add(id);
      }
      if (problem?.code !== 'categories') {
        list.push(pair);
        continue;
      }
      if (!tpl.entries.has(id)) leftovers.push({ ctx, english: pair[0], note: noteOf(pair), reason: reason(ctx, pair[0]) });
      else {
        failed.add(id);
        broken.push({ ctx, english: pair[0], note: noteOf(pair), rule: 'categories', got: problem.got, want: problem.want });
      }
    }
    kept[ctx] = list;
  }
  // Only current pairs are held to the agreement rule (what it finds in the others is never shown), so every
  // English it reads is the build's own; nothing here shows where a finding is.
  const s = ship(kept, tpl.entries, { verbatim: tpl.verbatim, notes: tpl.notes, glossary: tpl.glossary, dir: tag.dir, currentOnly: true, positions: false });
  const table = Object.assign(Object.create(null), s.table) as Checked['table'];
  const base = { table, total: tpl.entries.size, translated: s.translated.size };
  if (!full) return { checked: { ...base, broken: [], brokenTexts: 0, worth: [], missing: [], leftovers: [], coverage: [], canonical: true, pr: '' } };
  const worth: Worth[] = [];
  // A pair's findings come together: its identity is read once.
  let last: (typeof s.findings)[number] | undefined;
  let id = '';
  for (const f of s.findings) {
    if (!last || f.ctx !== last.ctx || f.pair !== last.pair || f.note !== last.note) id = identity(f.ctx, f.pair, f.note);
    last = f;
    const current = tpl.entries.has(id);
    if (f.level === 'fail' && f.rule === 'malformed') broken.push({ ctx: f.ctx, english: f.pair, note: f.note, rule: 'twice' });
    else if (f.level === 'fail' && current) {
      failed.add(id);
      broken.push({ ctx: f.ctx, english: f.pair, note: f.note, rule: f.check ?? 'agreement', token: f.token, detail: f.detail, form: typeof f.english === 'string' ? f.english : undefined, translation: f.translation });
    } else if (f.level === 'report' && current) worth.push({ ctx: f.ctx, english: f.pair, note: f.note, rule: f.check ?? '', token: f.token ?? '' });
  }
  const missing = [...tpl.entries]
    .filter(([id]) => !s.translated.has(id) && !failed.has(id))
    .map(([, e]) => ({ ctx: e.ctx, english: e.english as Pair[0], note: e.note }));
  for (const l of s.leftovers) leftovers.push({ ...l, reason: reason(l.ctx, l.english) });
  if (Object.hasOwn(cat, LEFTOVER)) for (const p of cat[LEFTOVER]) leftovers.push({ ctx: LEFTOVER, english: p[0], note: noteOf(p), reason: 'aside' });
  const per = new Map<string, { ctx: string; total: number; translated: number }>(tpl.contexts.map((ctx) => [ctx, { ctx, total: 0, translated: 0 }]));
  for (const [id, e] of tpl.entries) {
    const c = per.get(e.ctx);
    if (!c) continue;
    c.total++;
    if (s.translated.has(id)) c.translated++;
  }
  const share = (c: Coverage) => (c.total ? c.translated / c.total : 1);
  const coverage = [...per.values()].sort((a, b) => share(a) - share(b) || code(a.ctx, b.ctx));
  // The texts that break a rule: each current pair that failed (`failed`, by identity, once whatever its findings),
  // and each later pair of an identity the file repeats (one finding each).
  const brokenTexts = failed.size + broken.filter((b) => b.rule === 'twice').length;
  return { checked: { ...base, broken, brokenTexts, worth, missing, leftovers, coverage, canonical: !bom && serialize(cat) === text, pr: forPullRequest(cat, tpl, tag.categories) } };
}
