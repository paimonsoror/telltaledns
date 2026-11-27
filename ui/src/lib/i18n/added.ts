// REQ: API-012 (ADR-189), API-013 (ADR-190) — the two rules the browser holds only a catalog the build did
// not ship to (a test language pack): a translation adds no address, port, path or setting the English does
// not have, in either reading, and keeps every number of the English. The check script applies them to every
// pair (`agree.ts`); the runtime gets them from the code that brought such a catalog (`extraAgrees`, which the
// pack's boot gives its choice), so an English reader's first load never carries them. Pure; its imports
// name their files (`.ts`), as Node's own type stripping needs.
import { ADDED, HOST_PORT, PLACEHOLDER, prepare, structural, tokens, unique } from './safe.ts';

// In the folded reading only a dotted host counts as a host and port: a fullwidth colon there may just
// follow a word (`DNS：53`).
const DOTTED_HOST_PORT = /\.[A-Za-z0-9-]+:\d/;

/** Whether a token a translation adds is an address, a port, a path or a setting (`also`: the
 * host-and-port pattern of that reading). */
export const isAdded = (token: string, also = HOST_PORT) => also.test(token) || ADDED.some((re) => re.test(token));

/** `w` as a whole word: not inside a longer run of letters, digits or `_`. */
export const whole = (w: string, flags?: string) => new RegExp(`(?<![A-Za-z0-9_])${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9_])`, flags);

/** The tokens a translation adds that are an address, a port, a path or a setting: in the prepared
 * reading, then in the folded one. There a token the first reading already judged is left out, and
 * a token is judged without the English's own addresses in it, each where it stands whole, since
 * `：` and `。` also join those (`https://a.example。OPNsense：https://b.lan`). The English's words
 * stay in (`ｅｖｉｌ．ｈｅｌｐ：８５３` when the English says "help"), and so do its numbers and
 * an address inside a longer one (`２１．１．１．１５` when it says `1.1.1.1`). */
export function addedStructural(english: string, translation: string): string[] {
  // Sets, so a long translation is read in linear time; each of the English's own patterns is built once
  // and applied only to a token that holds it.
  const te = new Set(tokens(english));
  const tt = tokens(translation);
  const ts = new Set(tt);
  const fe = new Set(tokens(english, true));
  const own = unique([...te, ...fe])
    .filter((e) => structural(e))
    .sort((a, b) => b.length - a.length)
    .map((e) => [e, whole(e, 'g')] as const);
  const rest = (t: string) => own.reduce((s, [e, re]) => (s.includes(e) ? s.replace(re, ' ') : s), t);
  // Taking the English's own out (each as a whole word, for a space) never makes a token added: it is read
  // only for a token that is added as it stands.
  return unique([...tt.filter((t) => !te.has(t) && isAdded(t)), ...tokens(translation, true).filter((t) => !fe.has(t) && !ts.has(t) && isAdded(t, DOTTED_HOST_PORT) && isAdded(rest(t), DOTTED_HOST_PORT))]);
}

export const digits = (s: string): string[] => prepare(s).replace(PLACEHOLDER, ' ').match(/\d+/g) ?? [];

/** The members of multiset `a` that `b` lacks. */
export function missingFrom(a: readonly string[], b: readonly string[]): string[] {
  const left = new Map<string, number>();
  for (const v of b) left.set(v, (left.get(v) ?? 0) + 1);
  const out: string[] = [];
  for (const v of a) {
    const n = left.get(v) ?? 0;
    if (n > 0) left.set(v, n - 1);
    else out.push(v);
  }
  return out;
}

/** The two rules as the runtime asks them (`agreesAtRuntime`'s `extra`): true when the translation adds no
 * address, port, path or setting and keeps every number of the English. */
export const extraAgrees = (english: string, translation: string): boolean => !addedStructural(english, translation).length && !missingFrom(digits(english), digits(translation)).length;
