// REQ: API-012 (ADR-189) — what a message does with its parameters, its markup and its count. Pure:
// no runtime state, no Svelte, no Vite syntax, so the tests and `format.ts` can import it.

/** A parameter value. A nullish value renders as empty (as Svelte renders `{x}`); any other value
 * through `String()`. Numbers are formatted by the caller (`num()`), never here. */
export type Param = string | number | boolean | null | undefined;
export type Params = Readonly<Record<string, Param>>;

/** A message marked in one file and rendered in another: it carries its context. Never a key,
 * never compared: code that needs an identifier keeps one beside it. */
export type Msg = Readonly<{ c: string; e: string; n?: string }>;

/** A string literal type only: `t(label)` with a variable of type `string` does not compile. */
type Lit<S extends string> = string extends S ? never : S;
/** The `{name}`s of a literal. */
type Names<S extends string> = S extends `${string}{${infer N}}${infer R}` ? N | Names<R> : never;
/** Exactly the parameters a literal names (none: no parameter object), then an optional note. */
type Args<S extends string> = [Names<S>] extends [never]
  ? [params?: null, note?: string]
  : [params: { readonly [K in Names<S>]: Param }, note?: string];

/** What `tr(context)` returns, and what `format.ts` receives from `bind('format')`. */
export interface Binder {
  /** Whether the text is English (or the pseudo-locale computed from it): formats keep their
   * English forms exactly. */
  readonly english: boolean;
  t<S extends string>(english: Lit<S>, ...rest: Args<S>): string;
  tn<O extends string, P extends string>(one: Lit<O>, other: Lit<P>, count: number, ...rest: Args<O | P>): string;
  m<S extends string>(english: Lit<S>, note?: string): Msg;
}

const PLACEHOLDER = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

/** One pass over `text`: a `{name}` whose name is an own property of `params` is replaced by its
 * value; any other `{...}` stays as it is. A value is never scanned again. */
export function interpolate(text: string, params?: Params | null): string {
  if (!params) return text;
  return text.replace(PLACEHOLDER, (whole: string, name: string) => {
    if (!Object.hasOwn(params, name)) return whole;
    const v = params[name];
    return v == null ? '' : String(v);
  });
}

/** The placeholder names of a message. */
export function placeholders(text: string): string[] {
  return [...text.matchAll(PLACEHOLDER)].map((m) => m[1]);
}

/** A piece of a message: text, or the text inside a named tag (`<b>…</b>`, or empty for `<br/>`). */
export type Part = { text: string; tag?: string };

const TAG = /<([a-z][a-z0-9]*)>([^<]*)<\/\1>|<([a-z][a-z0-9]*)\/>/g;

/** Splits a message on `<name>text</name>` and `<name/>` whose name is in `tags` (the caller's
 * snippets), substitutes inside each piece, and leaves everything else as text: an unknown tag,
 * a tag with an attribute, an unclosed or nested tag. Nothing in a message ever becomes markup. */
export function parts(text: string, params?: Params | null, tags: readonly string[] = []): Part[] {
  const out: Part[] = [];
  let last = 0;
  for (const m of text.matchAll(TAG)) {
    const name = m[1] ?? m[3];
    if (!tags.includes(name)) continue;
    if (m.index > last) out.push({ text: interpolate(text.slice(last, m.index), params) });
    out.push({ tag: name, text: m[1] === undefined ? '' : interpolate(m[2], params) });
    last = m.index + m[0].length;
  }
  if (last < text.length || out.length === 0) out.push({ text: interpolate(text.slice(last), params) });
  return out;
}

/** CLDR plural categories, in the order a catalog lists them. */
export const CATEGORIES = ['zero', 'one', 'two', 'few', 'many', 'other'] as const;
export type Category = (typeof CATEGORIES)[number];
export type Forms = Readonly<Partial<Record<Category, string>>>;

const rules = new Map<string, Intl.PluralRules>();

/** The plural category of `n` in `lang`, the language of the catalog the forms came from (`en` for
 * English text, also for an English fallback inside a translated page): never the browser's
 * language, never the format locale. */
export function category(lang: string, n: number): Category {
  let r = rules.get(lang);
  if (!r) {
    r = new Intl.PluralRules(lang);
    rules.set(lang, r);
  }
  return r.select(n) as Category;
}

/** The form of `forms` (all from one catalog, in `lang`) for `n`. A category the catalog lacks
 * falls back to that catalog's `other`; languages are never mixed within one message. */
export function plural(lang: string, forms: Forms, n: number): string | undefined {
  const c = category(lang, n);
  return Object.hasOwn(forms, c) ? forms[c] : forms.other;
}
