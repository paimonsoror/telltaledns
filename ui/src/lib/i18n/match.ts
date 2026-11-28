// REQ: API-012 (ADR-189) — which catalog a reader gets. Requests come in order (`?lang=`, the stored
// choice, then the browser's languages); each is matched to a catalog of the same language AND
// script, so a reader of Traditional Chinese is never given Simplified text. Pure.

/** Where a request came from. Only `param` (`?lang=`) reaches a catalog that is not offered, or the
 * pseudo-locale. */
export type Source = 'param' | 'stored' | 'browser';
export type Request = { readonly tag: string; readonly source: Source };
export type Offered = { readonly offered: boolean };

/** The pseudo-locale (accented, longer English), reachable only with `?lang=en-XA`. */
export const PSEUDO = 'en-XA';

/** The canonical form of a BCP 47 tag, or null for anything that is not one. */
export function canonical(tag: string): string | null {
  try {
    const [c] = Intl.getCanonicalLocales(tag);
    return c ?? null;
  } catch {
    return null;
  }
}

/** The catalog tags a request can match, most specific first: the tag itself; its likely
 * language-script-region, then language-script; then the bare language, which matches only a
 * catalog whose tag is exactly that language. A bare-language request takes the script of an
 * earlier, more specific request of the same language (`[zh-TW, zh]`: `zh` means Traditional);
 * without one, the script its likely subtags give. */
export function candidates(tag: string, earlier: readonly string[] = []): string[] {
  const loc = new Intl.Locale(tag);
  const max = scripted(tag, earlier).maximize();
  const out = [loc.toString()];
  if (max.script && max.region) out.push(`${max.language}-${max.script}-${max.region}`);
  if (max.script) out.push(`${max.language}-${max.script}`);
  out.push(loc.language);
  return [...new Set(out)];
}

/** A request with the script it means: a bare language takes the script of an earlier request of
 * the same language. */
function scripted(tag: string, earlier: readonly string[]): Intl.Locale {
  const loc = new Intl.Locale(tag);
  if (!loc.script && !loc.region) {
    for (const e of earlier) {
      const prev = new Intl.Locale(e).maximize();
      if (prev.language === loc.language && prev.script) return new Intl.Locale(loc.language, { script: prev.script });
    }
  }
  return loc;
}

/** The tag to use: a catalog of `locales`, `en`, or the pseudo-locale. The first request with an
 * offered match wins; English matches English at once; nothing matched means English. A catalog is
 * taken only if its likely script is the request's (a `yue` catalog, Traditional, is not taken for
 * `yue-CN`), whether or not the catalog's tag names a script. */
export function match(requests: readonly Request[], locales: Readonly<Record<string, Offered>>): string {
  const earlier: string[] = [];
  for (const r of requests) {
    const tag = canonical(r.tag);
    if (!tag) continue;
    if (tag === PSEUDO && r.source === 'param') return PSEUDO;
    if (new Intl.Locale(tag).language === 'en') return 'en';
    const want = scripted(tag, earlier).maximize().script;
    for (const c of candidates(tag, earlier)) {
      if (Object.hasOwn(locales, c) && (locales[c].offered || r.source === 'param') && new Intl.Locale(c).maximize().script === want) return c;
    }
    earlier.push(tag);
  }
  return 'en';
}

/** The locale formats use with a catalog: the first browser language of the catalog's language
 * and script, else the catalog tag. (With English, formats use the browser default, `undefined`.) */
export function formatLocale(catalog: string, languages: readonly string[]): string {
  const want = new Intl.Locale(catalog).maximize();
  for (const l of languages) {
    const tag = canonical(l);
    if (!tag) continue;
    const got = new Intl.Locale(tag).maximize();
    if (got.language === want.language && got.script === want.script) return tag;
  }
  return catalog;
}
