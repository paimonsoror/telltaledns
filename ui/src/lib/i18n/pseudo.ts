// REQ: API-012 (ADR-189) — the pseudo-locale `en-XA`: English with every ASCII letter accented and
// about 35% longer, computed in the browser (`?lang=en-XA` only; never listed, never stored). Text
// that bypassed the translation layer stays plain ASCII and stands out; placeholders and tags are
// left intact so the message still works. Pure; no imports.

/** a-z and A-Z, in order: one non-ASCII letter each. */
export const LOWER = [...'áƀçðéƒĝĥíĵķļɱñóþǫŕšţúṽŵẋýž'];
export const UPPER = [...'ÁƁÇÐÉƑĜĤÍĴĶĻṀÑÓÞǪŔŠŢÚṼŴẊÝŽ'];
const KEEP = /\{[A-Za-z_][A-Za-z0-9_]*\}|<\/?[a-z][a-z0-9]*\/?>/g;

function accent(s: string): string {
  let out = '';
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    if (c >= 97 && c <= 122) out += LOWER[c - 97];
    else if (c >= 65 && c <= 90) out += UPPER[c - 65];
    else out += ch;
  }
  return out;
}

/** `Holds {n}` -> `Ĥóļðš {n}·····`. */
export function pseudo(s: string): string {
  let out = '';
  let last = 0;
  let letters = 0;
  for (const m of s.matchAll(KEEP)) {
    const text = s.slice(last, m.index);
    letters += text.length;
    out += accent(text) + m[0];
    last = m.index + m[0].length;
  }
  const tail = s.slice(last);
  letters += tail.length;
  out += accent(tail);
  return letters ? out + '·'.repeat(Math.ceil(letters * 0.35)) : out;
}
