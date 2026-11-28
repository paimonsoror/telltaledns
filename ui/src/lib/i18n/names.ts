// REQ: API-013 (ADR-190) — how a test language pack's name and text are shown: the language's name (for
// display only), a file name without forbidden code points and cut to 48 characters, and pack text with
// each forbidden code point as a visible marker. Small, so the banner needs nothing of the check. Pure,
// apart from `Intl.DisplayNames`. Its imports name their files (`.ts`), as Node's own type stripping needs.
import { forbidden } from './safe.ts';

/** The name of a language in a language (`de` in `en`: German), for display only; it decides nothing. */
export function languageName(tag: string, inLanguage: string): string | undefined {
  try {
    return new Intl.DisplayNames([inLanguage], { type: 'language' }).of(tag) ?? undefined;
  } catch {
    return undefined;
  }
}

/** A file's name as the page shows it: without forbidden code points or controls, at most 48
 * characters (`…` in the middle). The fingerprint, not the name, is the file's identity. */
export function shownName(name: string): string {
  const drop = new Set(forbidden(name).map((f) => f.at));
  let clean = '';
  for (let i = 0; i < name.length; ) {
    const ch = String.fromCodePoint(name.codePointAt(i) ?? 0);
    if (!drop.has(i) && !/[\u0000-\u001f]/.test(ch)) clean += ch;
    i += ch.length;
  }
  const chars = [...clean];
  return chars.length <= 48 ? clean : `${chars.slice(0, 23).join('')}…${chars.slice(-24).join('')}`;
}

/** A pack's text as the check screen shows it: each forbidden code point as a visible marker
 * (`⟨U+202E⟩`), so a direction override cannot reorder the rest of the line. */
export function markers(s: string, dir: 'ltr' | 'rtl' = 'ltr'): string {
  let out = '';
  let last = 0;
  for (const f of forbidden(s, dir)) {
    out += `${s.slice(last, f.at)}⟨${f.cp}⟩`;
    last = f.at + ((s.codePointAt(f.at) ?? 0) > 0xffff ? 2 : 1);
  }
  return out + s.slice(last);
}
