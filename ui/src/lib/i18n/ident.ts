// REQ: API-012 (ADR-189) — the identity of an English message: its context, its English text
// normalized, and an optional note. A translation file pairs English with a translation; the
// shipped file is keyed by `hash()` of this identity. One module for the runtime, the check script
// (`scripts/i18n.mjs`) and the tests, so the three hash alike. It imports nothing.

/** For identity only (the screen shows the literal): NFC; typographic quotes, dashes and the
 * ellipsis folded to ASCII; a no-break space as a space; runs of whitespace to one space; trimmed. */
export function normalize(s: string): string {
  return s
    .normalize('NFC')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/\u2026/g, '...')
    .replace(/\u00A0/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Joins the two English forms of a plural message in its identity. */
export const PLURAL_JOIN = '\u0005';
const FIELD = '\u0004';

/** English of a message: one form, or the `one` and `other` forms of a plural. */
export type English = string | readonly [string, string];

/** The English half of an identity, normalized. */
export function englishKey(e: English): string {
  return typeof e === 'string' ? normalize(e) : normalize(e[0]) + PLURAL_JOIN + normalize(e[1]);
}

/** FNV-1a, 32 bits, over UTF-16 code units, as 8 hex digits. Synchronous and available without a
 * secure context. It is a lookup index, not a security control: the check fails any collision
 * among current English entries, and "current" is always decided by text, never by this hash. */
export function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

/** The key of (context, English, note) in a shipped catalog. */
export function hash(context: string, english: English, note?: string): string {
  return fnv1a(context + FIELD + englishKey(english) + (note ? FIELD + note : ''));
}
