// REQ: API-012 (ADR-189) — what the build ships of a locale file, as one pure function that the check
// script (`scripts/i18n-lib.mjs`) and code in the browser share: every pair is checked against its own
// English half, and a pair that agrees and whose identity (context, normalized English, note) is in the
// source now, compared as text, ships under the hash of that source entry. Pure; its imports name
// their files (`.ts`), as Node's own type stripping needs.
import { agree } from './agree.ts';
import { englishKey, hash, type English } from './ident.ts';
import { CATEGORIES, LEFTOVER, type Catalog, type Pair } from './pairs.ts';

/** The identity of a message: its context, normalized English and note, compared as text. */
export const identity = (ctx: string, english: English | Pair[0], note?: string) => `${ctx}\u0004${englishKey(english as English)}\u0004${note ?? ''}`;

const pairNote = (p: Pair) => (typeof p[2] === 'string' ? p[2] : '');
const canonValue = (v: unknown) =>
  v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(CATEGORIES.filter((c) => Object.hasOwn(v, c)).map((c) => [c, (v as Record<string, unknown>)[c]])) : v;

/** A message of the source, as the shipping function reads it. */
export type ShipEntry = { readonly ctx: string; readonly english: English; readonly note?: string };

/** One finding: `check` is the agreement rule that failed (a `fail` of rule `agreement`) or reported
 * (rule `agreement-<check>`), with its token and place; `english` is the English the translation was
 * held to (a plural's form), `pair` and `note` the pair's own English half and note. */
export type ShipFinding = {
  readonly level: 'fail' | 'report';
  readonly rule: string;
  readonly ctx: string;
  readonly english: string | readonly [string, string];
  readonly pair: Pair[0];
  readonly note?: string;
  readonly translation?: string;
  readonly check?: string;
  readonly token?: string;
  readonly at?: number;
  readonly detail: string;
};

export type ShipOptions = {
  readonly verbatim?: ReadonlyMap<string, unknown>;
  readonly notes?: ReadonlyMap<string, unknown>;
  readonly glossary?: readonly string[];
  readonly dir?: 'ltr' | 'rtl';
  /** Only pairs whose identity is in the source now are held to the agreement rule; the others are left
   * over without it, and without findings (a pair file checked in the browser, which shows neither). */
  readonly currentOnly?: boolean;
  /** `false`: findings say nowhere where they are (`at`: -1), for a caller that never shows it. */
  readonly positions?: boolean;
};

type NoteValue = { exemptDigits?: unknown; exemptAdded?: unknown };

/**
 * What one locale file ships. Every pair is checked against its own English half (so a change to
 * the English in the source alone can never make a locale fail); a pair that agrees and whose
 * identity (context, normalized English, note) is in the source now, compared as text, ships under
 * the hash of that source entry. Returns the table (hash -> translation), the identities translated,
 * the pairs left over, and the findings.
 */
export function ship(cat: Catalog, entries: ReadonlyMap<string, ShipEntry>, { verbatim = new Map(), notes = new Map(), glossary = [], dir = 'ltr', currentOnly = false, positions }: ShipOptions = {}) {
  const findings: ShipFinding[] = [];
  const table: Record<string, unknown> = {};
  const translated = new Set<string>();
  const leftovers: { ctx: string; english: Pair[0]; note?: string }[] = [];
  const seen = new Set<string>();
  for (const [ctx, pairs] of Object.entries(cat)) {
    if (ctx === LEFTOVER) continue;
    for (const p of pairs) {
      const note = pairNote(p) || undefined;
      const id = identity(ctx, p[0], note);
      if (seen.has(id)) {
        findings.push({ level: 'fail', rule: 'malformed', ctx, english: p[0], pair: p[0], note, detail: 'the same English twice' });
        continue;
      }
      seen.add(id);
      const empty = typeof p[1] === 'string' ? p[1] === '' : Object.values(p[1] as object).every((x) => x === '');
      if (empty) continue;
      const e = entries.get(id);
      if (!e && currentOnly) {
        leftovers.push({ ctx, english: p[0], note });
        continue;
      }
      // A maintainer's exemptions (notes.json, reviewed): the digit rule, and the tokens the
      // added-token rule allows (then reported instead).
      const n = notes.get(id) as NoteValue | undefined;
      const ea = n?.exemptAdded;
      const opts = { verbatim: (verbatim.get(id) ?? []) as string[], glossary, dir, exemptDigits: !!n?.exemptDigits, exemptAdded: Array.isArray(ea) ? (ea as string[]) : undefined, positions };
      // A plural form against the English form of its category (`one`), else English `other`; a
      // form other than `other` may leave out placeholders (a dual, or a "one" that names no number).
      const forms: [string, string, boolean][] =
        typeof p[1] === 'string' ? [[p[0] as string, p[1], false]] : Object.entries(p[1] as Record<string, string>).map(([c, x]) => [c === 'one' ? p[0][0] : p[0][1], x, c !== 'other']);
      let ok = true;
      for (const [en, tx, subset] of forms) {
        if (tx === '') {
          ok = false;
          continue;
        }
        const v = agree(en, tx, { ...opts, placeholderSubset: subset });
        for (const x of v.fails) findings.push({ level: 'fail', rule: 'agreement', ctx, english: en, pair: p[0], note, translation: tx, check: x.rule, token: x.token, at: x.at, detail: x.detail });
        for (const x of v.reports) findings.push({ level: 'report', rule: `agreement-${x.rule}`, ctx, english: en, pair: p[0], note, check: x.rule, token: x.token, at: x.at, detail: x.detail });
        if (v.fails.length) ok = false;
      }
      if (!e) {
        leftovers.push({ ctx, english: p[0], note });
        continue;
      }
      if (ok) {
        table[hash(e.ctx, e.english, e.note)] = typeof p[1] === 'string' ? p[1] : canonValue(p[1]);
        translated.add(id);
      }
    }
  }
  return { table, translated, leftovers, findings };
}
