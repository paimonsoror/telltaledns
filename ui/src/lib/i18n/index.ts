// REQ: API-012 (ADR-189) — the translation layer. English is the key: `t('Holds')` returns the
// literal (after substitution) while English is active, with no lookup and no table. Another
// language is a data file fetched before the page is drawn; a translation is found by the hash of
// (context, normalized English, note) and shown only if it agrees with the English literal it
// replaces (`safe.ts`); otherwise English is shown. `t()` is a plain function: no reactive state.
import { hash } from './ident';
import { PSEUDO, formatLocale, match, type Request } from './match';
import { CATEGORIES, interpolate, plural, type Binder, type Forms, type Msg, type Params } from './message';
import { pseudo } from './pseudo';
import { agreesAtRuntime, type Extra } from './safe';

export type { Binder, Msg, Param, Params } from './message';

/** The build's table of catalogs (`locales.gen.ts`, made by `scripts/i18n.mjs prebuild`). The same
 * file exports `TEMPLATE`, the address of the build's one pair-file template (null without one). */
export type LocaleTable = Readonly<Record<string, { readonly url: string; readonly dir: 'ltr' | 'rtl'; readonly offered: boolean }>>;

/** A shipped catalog: hash -> translation, or plural forms by category. Null prototype. */
export type Table = Readonly<Record<string, string | Forms>>;

/** The language of a page load, as data: English (`en`), the pseudo-locale (`en-XA`), or a catalog
 * with its table. `install()` turns it into the runtime. */
export type Choice = {
  readonly tag: string;
  readonly table?: Table;
  readonly dir?: 'ltr' | 'rtl';
  /** The locale formats use with a catalog (default: the tag). Never used with English. */
  readonly formatLocale?: string;
  /** A catalog the build shipped: the check held each pair to the digit and added-token rules
   * (with a maintainer's exemptions), so the browser does not re-check those two. Set only by
   * `load()` for a catalog of the build's table; anything else is re-checked in full. */
  readonly built?: boolean;
  /** For a catalog the build did not ship: the digit and added-token rules, which the code that brought it
   * gives (`extraAgrees`, `added.ts`). Without them, no translation of such a catalog is shown. */
  readonly extra?: Extra;
};

/** One language for the life of the page. */
export interface Runtime {
  /** `<html lang>`. */
  readonly lang: string;
  readonly dir: 'ltr' | 'rtl';
  /** The locale formats use: `undefined` (the browser default) with English. */
  readonly formatLocale: string | undefined;
  /** Whether the text is English or computed from it (formats keep their English forms). */
  readonly english: boolean;
  /** The text of a message (before substitution). */
  text(context: string, english: string, note?: string): string;
  /** The forms of a plural message and the language whose plural rules pick among them. */
  forms(context: string, one: string, other: string, note?: string): { lang: string; forms: Forms };
}

export const ENGLISH: Runtime = Object.freeze({
  lang: 'en',
  dir: 'ltr',
  formatLocale: undefined,
  english: true,
  text: (_c: string, english: string) => english,
  forms: (_c: string, one: string, other: string) => ({ lang: 'en', forms: { one, other } }),
});

export const PSEUDO_RUNTIME: Runtime = Object.freeze({
  lang: PSEUDO,
  dir: 'ltr',
  formatLocale: undefined,
  english: true,
  text: (_c: string, english: string) => pseudo(english),
  // English plural rules: the text is English, whatever the browser's language.
  forms: (_c: string, one: string, other: string) => ({ lang: 'en', forms: { one: pseudo(one), other: pseudo(other) } }),
});

/** Parses a shipped catalog into a null-prototype table: 8-hex keys only, a string or an object of
 * plural categories (with `other`) as values; anything else is dropped. */
export function parseCatalog(json: string): Table {
  const table: Record<string, string | Forms> = Object.create(null);
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return table;
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return table;
  for (const [k, v] of Object.entries(raw)) {
    if (!/^[0-9a-f]{8}$/.test(k)) continue;
    if (typeof v === 'string') table[k] = v;
    else if (v && typeof v === 'object' && !Array.isArray(v)) {
      const forms: Record<string, string> = Object.create(null);
      for (const [c, s] of Object.entries(v)) if ((CATEGORIES as readonly string[]).includes(c) && typeof s === 'string') forms[c] = s;
      if (Object.hasOwn(forms, 'other')) table[k] = Object.freeze(forms);
    }
  }
  return Object.freeze(table);
}

/** A translated runtime. Each message is looked up once per context and checked against the
 * English literal it would replace; one that disagrees is never shown. `built`, `extra`: see `Choice`. */
export function catalogRuntime(tag: string, table: Table, dir: 'ltr' | 'rtl', locale: string, built = false, extra?: Extra): Runtime {
  const texts = new Map<string, Map<string, string>>();
  const plurals = new Map<string, Map<string, { lang: string; forms: Forms }>>();
  const memo = <V>(m: Map<string, Map<string, V>>, context: string, id: string, make: () => V): V => {
    let byContext = m.get(context);
    if (!byContext) m.set(context, (byContext = new Map()));
    let v = byContext.get(id);
    if (v === undefined) byContext.set(id, (v = make()));
    return v;
  };
  const NOTE = '\u0004';
  return Object.freeze({
    lang: tag,
    dir,
    formatLocale: locale,
    english: false,
    text: (context: string, english: string, note?: string) =>
      memo(texts, context, english + NOTE + (note ?? ''), () => {
        const k = hash(context, english, note);
        const v = Object.hasOwn(table, k) ? table[k] : undefined;
        return typeof v === 'string' && v !== '' && agreesAtRuntime(english, v, dir, { built, extra }) ? v : english;
      }),
    forms: (context: string, one: string, other: string, note?: string) =>
      memo(plurals, context, one + NOTE + other + NOTE + (note ?? ''), () => {
        const k = hash(context, [one, other], note);
        const v = Object.hasOwn(table, k) ? table[k] : undefined;
        if (v && typeof v === 'object') {
          // Each form against the English form of its category, or English `other`; a form other
          // than `other` may leave out placeholders (a dual or a "one" that names no number).
          const ok = Object.entries(v).every(([c, s]) => typeof s === 'string' && s !== '' && agreesAtRuntime(c === 'one' ? one : other, s, dir, { subset: c !== 'other', built, extra }));
          if (ok) return { lang: tag, forms: v };
        }
        return { lang: 'en', forms: { one, other } };
      }),
  });
}

let current: Runtime = ENGLISH;
let installed = false;
let early = 0;

function runtime(): Runtime {
  if (!installed) early++;
  return current;
}

/** The runtime of a choice. A catalog with no entry (none given, empty, or unreadable) is English:
 * never a page tagged with another language that shows only English text. */
export function runtimeOf(c: Choice): Runtime {
  if (c.tag === PSEUDO) return PSEUDO_RUNTIME;
  if (c.tag === 'en' || !c.table || !Object.keys(c.table).length) return ENGLISH;
  return catalogRuntime(c.tag, c.table, c.dir ?? 'ltr', c.formatLocale ?? c.tag, c.built, c.extra);
}

/** Called before the app mounts (and again only to fall back to English). */
export function install(c: Choice): Runtime {
  current = runtimeOf(c);
  installed = true;
  return current;
}

/** How many messages were read before `install()` (a page test reads it under `?lang=en-XA`). */
export function earlyCalls(): number {
  return early;
}

/** The text of a message in the installed language (for `<T>`). */
export function lookup(context: string, english: string, note?: string): string {
  return runtime().text(context, english, note);
}

/** The messages of one context: the file's own (`tr('anomalies')`), or `tr('common')`. */
export function tr<C extends string>(context: string extends C ? never : C): Binder {
  // The literal and placeholder types are on `Binder`; the check script holds every call to them.
  const t = (english: string, params?: Params | null, note?: string) => interpolate(runtime().text(context, english, note), params);
  const tn = (one: string, other: string, count: number, params?: Params | null, note?: string) => {
    const f = runtime().forms(context, one, other, note);
    return interpolate(plural(f.lang, f.forms, count) ?? other, params);
  };
  const m = (english: string, note?: string): Msg => Object.freeze(note ? { c: context, e: english, n: note } : { c: context, e: english });
  return {
    get english() {
      return current.english;
    },
    t,
    tn,
    m,
  } as Binder;
}

/** Translates a message marked with `m()` in the context it carries. */
export function tk(msg: Msg, params?: Params | null): string {
  return interpolate(runtime().text(msg.c, msg.e, msg.n), params);
}

/** The entry of a table keyed by the server's words, when the key is the table's own and else `undefined`
 * (`constructor` and `__proto__` are never entries). */
export function own<V>(table: Readonly<Record<string, V>>, key: string | null | undefined): V | undefined {
  return key != null && Object.hasOwn(table, key) ? table[key] : undefined;
}

/** Where the request comes from: the page's own address, the stored choice and the browser. */
export type Sources = { readonly search: string; readonly stored: string | null; readonly languages: readonly string[] };

/** A source consulted before the build's catalogs (a test language pack): a choice, or null to go on. Given
 * the page load's signal, which ends with the time a catalog has. */
export type Provider = (signal: AbortSignal) => Choice | null | Promise<Choice | null>;

const EN: Choice = Object.freeze({ tag: 'en' });

/** The language of this page load: `?lang=` (this load only), the stored choice, then the browser's
 * languages in order. A provider and a catalog have 4 s together, then the page is English; so does any
 * failure. */
export async function load(locales: LocaleTable, src: Sources, fetcher: typeof fetch, timeoutMs = 4000, provider?: Provider): Promise<Choice> {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), timeoutMs);
  try {
    if (provider) {
      try {
        // Never `built`: only a catalog of the build's table skips the digit and added-token rules. Given up
        // when the time runs out (an import cannot be aborted).
        const c = await Promise.race([provider(abort.signal), new Promise<never>((_, no) => abort.signal.addEventListener('abort', no))]);
        if (c) return { ...c, built: false };
      } catch {
        // A provider that fails is skipped.
      }
    }
    const requests: Request[] = [];
    const param = new URLSearchParams(src.search).get('lang');
    if (param) requests.push({ tag: param, source: 'param' });
    if (src.stored) requests.push({ tag: src.stored, source: 'stored' });
    for (const l of src.languages) requests.push({ tag: l, source: 'browser' });
    const pick = match(requests, locales);
    if (pick === PSEUDO) return { tag: PSEUDO };
    if (pick === 'en' || !Object.hasOwn(locales, pick)) return EN;
    const entry = locales[pick];
    const res = await fetcher(entry.url, { signal: abort.signal, credentials: 'same-origin' });
    if (!res.ok) return EN;
    const table = parseCatalog(await res.text());
    if (!Object.keys(table).length) return EN;
    return { tag: pick, table, dir: entry.dir, formatLocale: formatLocale(pick, src.languages), built: true };
  } catch {
    return EN;
  } finally {
    clearTimeout(timer);
  }
}
