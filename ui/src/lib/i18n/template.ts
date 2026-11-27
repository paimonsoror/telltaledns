// REQ: API-013 (ADR-190) — the build's pair-file template: every message of this build (its context,
// English and note, from the same extraction `sync` uses), what `src/locales/notes.json` says of it
// and the words `verbatim.json` keeps, the glossary, and a copy of the committed plural table.
// `prebuild` writes it as `assets/locales/template-<sha8>.json`; a page reads it to write a new
// language's file, or the repository's form of a translated one, with the very functions `sync`
// runs (extract -> skeleton -> merge -> serialize), so the bytes are the same. Pure; its imports name
// their files (`.ts`), as Node's own type stripping needs.
import type { English } from './ident.ts';
import { merge, serialize, skeleton, type Catalog } from './pairs.ts';
import { identity, type ShipEntry } from './shipping.ts';

/** What `notes.json` says of a message: the translator's note, whether it is sensitive (its pull
 * request carries a back-translation), and a maintainer's exemptions. */
export type NoteValue = {
  readonly text?: string;
  readonly sensitive?: boolean;
  readonly exemptDigits?: unknown;
  readonly exemptAdded?: readonly string[];
};

/** One message of the template. `note` is the third item of its pair (the English's own note). */
export type TemplateEntry = ShipEntry & { readonly info?: NoteValue; readonly verbatim?: readonly string[] };

export type Template = {
  /** Every message, by identity (context, normalized English, note). */
  readonly entries: ReadonlyMap<string, TemplateEntry>;
  /** The contexts, in code-unit order. */
  readonly contexts: readonly string[];
  readonly glossary: readonly string[];
  /** Canonical language -> plural categories (zero, one, two, few, many, other order). */
  readonly plurals: ReadonlyMap<string, readonly string[]>;
  /** By identity, for the shipping function. */
  readonly notes: ReadonlyMap<string, NoteValue>;
  readonly verbatim: ReadonlyMap<string, readonly string[]>;
};

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const order = (e: { english: English; note?: string }) => `${JSON.stringify(e.english)}\u0000${e.note ?? ''}`;

/** The template's bytes: `{"v":1,"glossary":[…],"plurals":{…},"contexts":{"<ctx>":[[english, note?,
 * info?, verbatim?], …]}}`, contexts and entries in code-unit order, trailing empty items left out
 * (an empty note is `""`, a missing info `null`, when a later item follows). */
export function writeTemplate(
  entries: Iterable<ShipEntry>,
  data: { notes: ReadonlyMap<string, unknown>; verbatim: ReadonlyMap<string, unknown>; glossary: readonly string[]; plurals: Readonly<Record<string, readonly string[]>> },
): string {
  const by = new Map<string, ShipEntry[]>();
  for (const e of entries) by.set(e.ctx, [...(by.get(e.ctx) ?? []), e]);
  // Null prototype: a context is data, whatever its name.
  const contexts: Record<string, unknown[]> = Object.create(null);
  for (const ctx of [...by.keys()].sort(cmp)) {
    const list = [...(by.get(ctx) ?? [])].sort((a, b) => cmp(order(a), order(b)));
    contexts[ctx] = list.map((e) => {
      const id = identity(e.ctx, e.english, e.note);
      const item: unknown[] = [e.english, e.note ?? '', data.notes.get(id) ?? null, data.verbatim.get(id) ?? null];
      while (item.length > 1 && (item[item.length - 1] === null || item[item.length - 1] === '')) item.pop();
      return item;
    });
  }
  const plurals = Object.fromEntries(Object.keys(data.plurals).sort(cmp).map((k) => [k, data.plurals[k]]));
  return JSON.stringify({ v: 1, glossary: [...data.glossary], plurals, contexts });
}

const isEnglish = (x: unknown): x is English => (typeof x === 'string' && x !== '') || (Array.isArray(x) && x.length === 2 && x.every((s) => typeof s === 'string' && s !== ''));
const strings = (x: unknown): x is string[] => Array.isArray(x) && x.every((s) => typeof s === 'string');

/** Reads a template (as `writeTemplate` wrote it); throws on anything else. Context names and
 * keys are data: everything is kept in maps. */
export function readTemplate(json: string): Template {
  const raw: unknown = JSON.parse(json);
  if (!raw || typeof raw !== 'object' || (raw as { v?: unknown }).v !== 1) throw new Error('not a template');
  const t = raw as { glossary?: unknown; plurals?: unknown; contexts?: unknown };
  if (!strings(t.glossary) || !t.plurals || typeof t.plurals !== 'object' || !t.contexts || typeof t.contexts !== 'object') throw new Error('not a template');
  const plurals = new Map<string, readonly string[]>();
  for (const [k, v] of Object.entries(t.plurals)) if (strings(v)) plurals.set(k, v);
  const entries = new Map<string, TemplateEntry>();
  const notes = new Map<string, NoteValue>();
  const verbatim = new Map<string, readonly string[]>();
  const contexts: string[] = [];
  for (const [ctx, list] of Object.entries(t.contexts)) {
    if (!Array.isArray(list)) throw new Error('not a template');
    contexts.push(ctx);
    for (const item of list) {
      if (!Array.isArray(item) || !isEnglish(item[0])) throw new Error('not a template');
      const english: English = typeof item[0] === 'string' ? item[0] : [item[0][0], item[0][1]];
      const note = typeof item[1] === 'string' && item[1] !== '' ? item[1] : undefined;
      const info = item[2] && typeof item[2] === 'object' && !Array.isArray(item[2]) ? (item[2] as NoteValue) : undefined;
      const words = strings(item[3]) ? item[3] : undefined;
      const id = identity(ctx, english, note);
      entries.set(id, { ctx, english, note, info, verbatim: words });
      if (info) notes.set(id, info);
      if (words) verbatim.set(id, words);
    }
  }
  return { entries, contexts: contexts.sort(cmp), glossary: t.glossary, plurals, notes, verbatim };
}

/** A pair file with every message of the template and nothing translated, for `categories`. */
const skeletonOf = (tpl: Template, categories: readonly string[]): Catalog => skeleton(tpl.entries.values(), categories);

/** What `node scripts/i18n.mjs sync <tag>` writes for a new language at this build. */
export function materialize(tpl: Template, categories: readonly string[]): string {
  return serialize(merge(Object.create(null) as Catalog, skeletonOf(tpl, categories), identity));
}

/** What `node scripts/i18n.mjs sync <tag>` writes for the file `cat` at this build: the canonical
 * form, every missing message added empty, left-over pairs under `~leftover`, translations kept. */
export function forPullRequest(cat: Catalog, tpl: Template, categories: readonly string[]): string {
  return serialize(merge(cat, skeletonOf(tpl, categories), identity));
}
