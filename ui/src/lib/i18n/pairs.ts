// REQ: API-012 (ADR-189) — the pair files (`src/locales/<tag>.json`, and the catalog-shaped notes,
// verbatim and baseline files): a strict parser, the one canonical serialization, and the merge
// that `sync` runs (extract -> skeleton -> merge). Pure and with no imports, so the check script and
// a page can share it. Order is by UTF-16 code unit (`<`), never by a collator.

/** context -> pairs. A pair is `[english, translation]` or `[english, translation, note]`; a plural
 * is `[[one, other], { category: text }]`. */
export type Pair = [string | [string, string], unknown, string?];
export type Catalog = Record<string, Pair[]>;

export const CATEGORIES = ['zero', 'one', 'two', 'few', 'many', 'other'] as const;
export const LEFTOVER = '~leftover';

export const LIMITS = { bytes: 4 * 1024 * 1024, depth: 4 } as const;

/** Thrown by `parse`, with the offset where the text stops being acceptable. */
export class PairFileError extends Error {
  readonly at: number;
  constructor(message: string, at: number) {
    super(`${message} at offset ${at}`);
    this.at = at;
  }
}

/** JSON as `JSON.parse` reads it, but refusing what would be lost silently: a key twice in one
 * object (at any depth), nesting deeper than `depth` containers, and text over `bytes` UTF-16 units. */
export function parse(text: string, limits: { bytes: number; depth: number } = LIMITS): unknown {
  if (text.length > limits.bytes) throw new PairFileError(`over ${limits.bytes} characters`, limits.bytes);
  let i = 0;
  const ws = () => {
    while (i < text.length && ' \t\n\r'.includes(text[i])) i++;
  };
  const str = (): string => {
    const start = i;
    i++;
    while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
    if (i >= text.length) throw new PairFileError('an unterminated string', start);
    i++;
    try {
      return JSON.parse(text.slice(start, i)) as string;
    } catch {
      throw new PairFileError('a malformed string', start);
    }
  };
  const value = (depth: number): unknown => {
    ws();
    const c = text[i];
    if (c === '{' || c === '[') {
      if (depth >= limits.depth) throw new PairFileError(`nesting deeper than ${limits.depth}`, i);
      const open = i++;
      const obj = c === '{';
      const out: Record<string, unknown> | unknown[] = obj ? Object.create(null) : [];
      ws();
      if (text[i] === (obj ? '}' : ']')) {
        i++;
        return obj ? Object.assign({}, out) : out;
      }
      for (;;) {
        ws();
        if (obj) {
          if (text[i] !== '"') throw new PairFileError('a key that is not a string', i);
          const at = i;
          const k = str();
          if (Object.hasOwn(out, k)) throw new PairFileError(`the key ${JSON.stringify(k)} twice`, at);
          ws();
          if (text[i++] !== ':') throw new PairFileError('a missing colon', i - 1);
          (out as Record<string, unknown>)[k] = value(depth + 1);
        } else (out as unknown[]).push(value(depth + 1));
        ws();
        const sep = text[i++];
        if (sep === ',') continue;
        if (sep === (obj ? '}' : ']')) break;
        throw new PairFileError(`an unclosed ${obj ? 'object' : 'array'} (opened at ${open})`, i - 1);
      }
      // A plain object for callers (keys were checked on the null-prototype copy).
      return obj ? Object.fromEntries(Object.entries(out)) : out;
    }
    if (c === '"') return str();
    const m = /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/.exec(text.slice(i, i + 64));
    if (!m) throw new PairFileError('an unexpected character', i);
    i += m[0].length;
    return JSON.parse(m[0]);
  };
  const v = value(0);
  ws();
  if (i !== text.length) throw new PairFileError('text after the end', i);
  return v;
}

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const englishOf = (p: Pair) => (Array.isArray(p[0]) ? `${p[0][0]}\u0005${p[0][1]}` : p[0]);
const noteOf = (p: Pair) => (typeof p[2] === 'string' ? p[2] : '');
const order = (a: Pair, b: Pair) => cmp(englishOf(a), englishOf(b)) || cmp(noteOf(a), noteOf(b)) || cmp(JSON.stringify(a[1]), JSON.stringify(b[1]));
const sortKeys = (v: unknown): unknown =>
  Array.isArray(v)
    ? v.map(sortKeys)
    : v && typeof v === 'object'
      ? Object.fromEntries(
          Object.keys(v)
            .sort(cmp)
            .map((k) => [k, sortKeys((v as Record<string, unknown>)[k])]),
        )
      : v;
const categoriesInOrder = (v: unknown) =>
  v && typeof v === 'object' && !Array.isArray(v)
    ? Object.fromEntries(CATEGORIES.filter((c) => Object.hasOwn(v, c)).map((c) => [c, (v as Record<string, unknown>)[c]]))
    : v;

/** The canonical bytes: contexts by code unit; one pair per line, by English, then note; plural
 * categories in the order zero, one, two, few, many, other (`locale`), or a data value's keys
 * sorted (`data`: notes, verbatim, baseline). */
export function serialize(cat: Catalog, kind: 'locale' | 'data' = 'locale'): string {
  const contexts = Object.keys(cat).sort(cmp);
  let out = '{\n';
  contexts.forEach((c, ci) => {
    const pairs = [...cat[c]].sort(order);
    out += `  ${JSON.stringify(c)}: [\n`;
    pairs.forEach((p, pi) => {
      const q = [p[0], kind === 'locale' ? categoriesInOrder(p[1]) : sortKeys(p[1]), ...p.slice(2)];
      out += `    ${JSON.stringify(q)}${pi < pairs.length - 1 ? ',' : ''}\n`;
    });
    out += `  ]${ci < contexts.length - 1 ? ',' : ''}\n`;
  });
  return `${out}}\n`;
}

/** What a pair must look like; `categories` are the language's plural categories. Null when fine. */
export function shapeError(p: unknown, categories: readonly string[], section: string): string | null {
  if (!Array.isArray(p) || p.length < 2 || p.length > 3) return 'a pair is [english, translation] or [english, translation, note]';
  if (p.length === 3 && (typeof p[2] !== 'string' || p[2] === '')) return 'a note is a non-empty string';
  if (typeof p[0] === 'string') {
    if (p[0] === '') return 'the English is empty';
    if (typeof p[1] !== 'string') return 'the translation of a message is a string';
    return null;
  }
  if (!Array.isArray(p[0]) || p[0].length !== 2 || !p[0].every((s) => typeof s === 'string' && s)) return 'the English of a plural is [one, other]';
  const v = p[1];
  if (!v || typeof v !== 'object' || Array.isArray(v) || !Object.values(v).every((s) => typeof s === 'string')) return 'the translation of a plural is an object of strings';
  const got = Object.keys(v).sort(cmp);
  if (section !== LEFTOVER && (got.length !== categories.length || !categories.every((c) => got.includes(c))))
    return `plural categories ${JSON.stringify(got)}; this language has ${JSON.stringify(categories)}`;
  return null;
}

/** An English message of the source: its context, English and note. */
export type Entry = { readonly ctx: string; readonly english: string | readonly [string, string]; readonly note?: string };

/** A pair file with every entry and nothing translated: `[english, ""]`, or the language's plural
 * categories with empty text. */
export function skeleton(entries: Iterable<Entry>, categories: readonly string[]): Catalog {
  // Null prototype: a context may be called `constructor` or `toString`.
  const out: Catalog = Object.create(null);
  for (const e of entries) {
    const english = Array.isArray(e.english) ? ([e.english[0], e.english[1]] as [string, string]) : (e.english as string);
    const tx = Array.isArray(e.english) ? Object.fromEntries(categories.map((c) => [c, ''])) : '';
    const pair: Pair = e.note ? [english, tx, e.note] : [english, tx];
    (out[e.ctx] ??= []).push(pair);
  }
  return out;
}

/** `sync`: the skeleton, with each translation of `existing` whose identity (`key`) is still there
 * carried over; every other pair of `existing` moved to `~leftover` (or dropped with `prune`). */
export function merge(existing: Catalog, skel: Catalog, key: (ctx: string, english: Pair[0], note?: string) => string, { prune = false } = {}): Catalog {
  const have = new Map<string, Pair>();
  const left: Pair[] = [...(Object.hasOwn(existing, LEFTOVER) ? existing[LEFTOVER] : [])];
  for (const [ctx, pairs] of Object.entries(existing)) {
    if (ctx === LEFTOVER) continue;
    for (const p of pairs) have.set(key(ctx, p[0], noteOf(p) || undefined), p);
  }
  const used = new Set<string>();
  const out: Catalog = Object.create(null);
  for (const [ctx, pairs] of Object.entries(skel)) {
    for (const s of pairs) {
      const k = key(ctx, s[0], noteOf(s) || undefined);
      const old = have.get(k);
      used.add(k);
      // The English as the source writes it now; the translation as the translator left it (a
      // plural's text per category of the skeleton).
      let tx = old ? old[1] : s[1];
      if (old && Array.isArray(s[0]) && s[1] && typeof s[1] === 'object' && tx && typeof tx === 'object' && !Array.isArray(tx)) {
        const was = tx as Record<string, unknown>;
        tx = Object.fromEntries(Object.keys(s[1] as object).map((c) => [c, typeof was[c] === 'string' ? was[c] : '']));
      }
      (out[ctx] ??= []).push(s.length === 3 ? [s[0], tx, s[2]] : [s[0], tx]);
    }
  }
  for (const [k, p] of have) if (!used.has(k)) left.push(p);
  if (!prune && left.length) out[LEFTOVER] = left;
  return out;
}
