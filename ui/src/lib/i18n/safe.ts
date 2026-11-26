// REQ: API-012 (ADR-189) — a translation must agree with its English: the same placeholders, tags
// and web addresses; every structural token, number and `verbatim` word of the English, and no
// address, port, path or setting the English does not have; no direction overrides, invisible
// characters or words that mix scripts. The check script applies all of it (`agree`, findings with
// the token and its position); the browser re-checks what needs no data file (`agreesAtRuntime`, a
// yes or no that stops at the first problem) the first time it shows a translation, and shows
// English instead when they disagree. Pure; no imports.

/** One problem: the rule, the token concerned, and where it is in the translation (-1: absent). */
export type Finding = { readonly rule: string; readonly token: string; readonly at: number; readonly detail: string };
export type Verdict = { readonly fails: Finding[]; readonly reports: Finding[] };
export type AgreeOptions = {
  /** Words of this entry a reader types as they are (`email`, `ntfy`): each must stay, as a word. */
  readonly verbatim?: readonly string[];
  /** Terms that are structural wherever they appear (`NXDOMAIN`, `DNSSEC`, record types). */
  readonly glossary?: readonly string[];
  /** The locale's direction: U+200E, U+200F and U+061C are allowed only right to left. */
  readonly dir?: 'ltr' | 'rtl';
  /** A maintainer's exemption from the digit rule (notes file), with its reason. */
  readonly exemptDigits?: boolean;
  /** A maintainer's exemption from the added-token rule (notes file): the tokens a translation of
   * this message may add (a time, ratio, date pattern or price: `["24:00"]`), each reported, not
   * failed. Any other added token still fails. */
  readonly exemptAdded?: readonly string[];
  /** A plural form other than `other`: it may leave out some of the English placeholders. */
  readonly placeholderSubset?: boolean;
};

// CJK and fullwidth punctuation become spaces BEFORE NFKC, so `：` cannot glue two tokens.
const CJK_PUNCTUATION = /[\u3000-\u303F\uFF01-\uFF0F\uFF1A-\uFF20\uFF3B-\uFF40\uFF5B-\uFF65]/g;

/** Both texts are prepared the same way before URLs, tokens and digits are read. */
export function prepare(s: string): string {
  return s.replace(CJK_PUNCTUATION, ' ').normalize('NFKC');
}

/** The second reading of the added-token rule: the punctuation kept, folded to ASCII (NFKC, and the
 * ideographic full stop to `.`), so `８．８．８．８` and `8。8。8。8` read as `8.8.8.8`. */
const fold = (s: string) => s.normalize('NFKC').replace(/\u3002/g, '.');

const PLACEHOLDER = /\{[A-Za-z_][A-Za-z0-9_]*\}/g;
const TAG = /<\/?[a-z][a-z0-9]*\/?>/g;
// Every pattern below runs on a translator's text, in the check and in the browser: none of them
// backtracks over an unbounded run, so any text is read in linear time.
// `https?://` in any case and zero or more RFC 3986 characters; trailing `. , ; : ! ? )` are not part of it.
const URL = /https?:\/\/[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]*/gi;
// Any `scheme://` (counted as the `://` after a scheme character), on the text with its
// compatibility characters folded (NFKC) but its punctuation kept, so `ｈｔｔｐｓ：／／` counts as one.
const SCHEME = /[a-z0-9+.-]:\/\//gi;
const TOKEN = /[A-Za-z0-9._:/[\]=$|-]+/g;
// Structural by pattern, wherever they appear. A translation may not add one of these (but may add
// `_` or `[x]`, and words and acronyms, which are only reported), in either reading.
const ADDED = [
  /:\/\//, // a scheme
  /\/[A-Za-z0-9._-]+\//, // a /x/ path
  /=/,
  /\$/,
  /\|/,
  /\b\d{1,3}(?:\.\d{1,3}){3}\b/, // an IPv4 address
];
// A host and port. In the folded reading only a dotted host counts: a fullwidth colon there may
// just follow a word (`DNS：53`).
const HOST_PORT = /[A-Za-z0-9-]:\d/;
const DOTTED_HOST_PORT = /\.[A-Za-z0-9-]+:\d/;
/** `s` without the characters of `chars` at either end (a loop: no regex backtracking). */
function trim(s: string, chars: string): string {
  let a = 0;
  let b = s.length;
  while (a < b && chars.includes(s[a])) a++;
  while (b > a && chars.includes(s[b - 1])) b--;
  return s.slice(a, b);
}
const STRUCTURAL = [...ADDED, HOST_PORT, /\[[^\]\s]+\]/, /_/];
const CODE_SPAN = /`[^`]+`/g;
// Letters, digits and marks (sticky): the host of a bare scheme written in another script.
const SCRIPT_RUN = /[\p{L}\p{N}\p{M}]+/uy;

/** The web addresses of a text, after preparation. A bare `https://` is one; followed by a letter
 * or digit of another script (`https://例子`), that run is part of it. */
export function urls(s: string): string[] {
  const p = prepare(s);
  return [...p.matchAll(URL)].map((m) => {
    let u = m[0];
    // Trailing `. , ; : ! ? )` are sentence punctuation, and an apostrophe and letters after the
    // address a suffix (Turkish `…/konu'ya`): neither is part of it.
    let end = u.length;
    while (end && '.,;:!?)'.includes(u[end - 1])) end--;
    u = u.slice(0, end).replace(/'[A-Za-z]*$/, '');
    if (u === m[0] && /^https?:\/\/$/i.test(u)) {
      SCRIPT_RUN.lastIndex = m.index + u.length;
      u += SCRIPT_RUN.exec(p)?.[0] ?? '';
    }
    return u;
  });
}

/** How many `scheme://` a text holds, in any case or width. */
export function schemes(s: string): number {
  return s.normalize('NFKC').match(SCHEME)?.length ?? 0;
}

/** The ASCII tokens of a text, after preparation (or folded), with placeholders and tags taken out. */
export function tokens(s: string, folded = false): string[] {
  const text = (folded ? fold(s) : prepare(s)).replace(PLACEHOLDER, ' ').replace(TAG, ' ');
  const out: string[] = [];
  for (const m of text.matchAll(TOKEN)) {
    // Sentence punctuation around a token is not part of it (a slash is: `/etc/telltale/` is a path).
    const t = trim(m[0], '.:-|=');
    if (t) out.push(t);
  }
  return out;
}

/** Whether a token must survive translation unchanged. */
export function structural(token: string, glossary: readonly string[] = []): boolean {
  return glossary.includes(token) || STRUCTURAL.some((re) => re.test(token));
}

/** Whether a token a translation adds is an address, a port, a path or a setting (`also`: the
 * host-and-port pattern of that reading). */
const isAdded = (token: string, also = HOST_PORT) => also.test(token) || ADDED.some((re) => re.test(token));

/** `w` as a whole word: not inside a longer run of letters, digits or `_`. */
const whole = (w: string, flags?: string) => new RegExp(`(?<![A-Za-z0-9_])${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9_])`, flags);

/** The tokens a translation adds that are an address, a port, a path or a setting: in the prepared
 * reading, then in the folded one. There a token the first reading already judged is left out, and
 * a token is judged without the English's own addresses in it, each where it stands whole, since
 * `：` and `。` also join those (`https://a.example。OPNsense：https://b.lan`). The English's words
 * stay in (`ｅｖｉｌ．ｈｅｌｐ：８５３` when the English says "help"), and so do its numbers and
 * an address inside a longer one (`２１．１．１．１５` when it says `1.1.1.1`). */
export function addedStructural(english: string, translation: string): string[] {
  // Sets, so a long translation is read in linear time.
  const te = new Set(tokens(english));
  const tt = tokens(translation);
  const ts = new Set(tt);
  const fe = new Set(tokens(english, true));
  const own = unique([...te, ...fe])
    .filter((e) => structural(e))
    .sort((a, b) => b.length - a.length);
  const rest = (t: string) => own.reduce((s, e) => s.replace(whole(e, 'g'), ' '), t);
  return unique([...tt.filter((t) => !te.has(t) && isAdded(t)), ...tokens(translation, true).filter((t) => !fe.has(t) && !ts.has(t) && isAdded(rest(t), DOTTED_HOST_PORT))]);
}

// A `.` between two letters of other scripts: an address the ASCII readings cannot see (`例子.公司`).
const WORD_RUN = /[\p{L}\p{N}\p{M}.]+/gu;
const SCRIPT_DOT = /(?![\x00-\x7F])\p{L}\.(?![\x00-\x7F])\p{L}/u;
const scriptDots = (s: string) => (s.normalize('NFKC').match(WORD_RUN) ?? []).filter((w) => SCRIPT_DOT.test(w));

const digits = (s: string): string[] => prepare(s).replace(PLACEHOLDER, ' ').match(/\d+/g) ?? [];
const all = (s: string, re: RegExp): string[] => s.match(re) ?? [];

/** The members of multiset `a` that `b` lacks. */
function missingFrom(a: readonly string[], b: readonly string[]): string[] {
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
const unique = (xs: readonly string[]) => [...new Set(xs)];
const sameSet = (a: readonly string[], b: readonly string[]) => {
  const x = new Set(a);
  const y = new Set(b);
  return x.size === y.size && [...x].every((v) => y.has(v));
};

// Forbidden code points: every format character (bidi controls and isolates, zero-width and
// invisible characters, the soft hyphen, tag characters), every default-ignorable code point (the
// invisible fillers, and every variation selector: U+FE00-FE0F, U+E0100-E01EF, the Mongolian ones),
// C0 controls but the newline, DEL and C1 controls, and the line and paragraph separators.
const FORBIDDEN = /[\p{Cf}\p{DI}\u0000-\u0009\u000B-\u001F\u007F-\u009F\u{2028}\u{2029}]/u;
// The joiners are allowed only between two letters of the scripts whose words need them (Arabic,
// and the Indic scripts from Devanagari to Sinhala); the marks only in right-to-left text.
const JOINERS = /[\u200C\u200D]/u;
const JOINING_LETTER = /[\p{Script=Arabic}\u0900-\u0DFF]/u;
const LETTER = /[\p{L}\p{M}]/u;
const MARKS = /[\u200E\u200F\u061C]/u;
const WORD = /[\p{L}\p{M}]+/gu;
const LATIN = /\p{Script=Latin}/u;
const CYRILLIC_OR_GREEK = /[\p{Script=Cyrillic}\p{Script=Greek}]/u;

const hex = (c: string) => `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`;

/** The forbidden code points of a translation, with their offsets. */
export function forbidden(s: string, dir: 'ltr' | 'rtl' = 'ltr'): { cp: string; at: number }[] {
  const out: { cp: string; at: number }[] = [];
  const chars = [...s];
  let at = 0;
  const joins = (x: string | undefined) => !!x && JOINING_LETTER.test(x) && LETTER.test(x);
  chars.forEach((c, i) => {
    const bad = JOINERS.test(c) ? !(joins(chars[i - 1]) && joins(chars[i + 1])) : MARKS.test(c) ? dir !== 'rtl' : FORBIDDEN.test(c);
    if (bad) out.push({ cp: hex(c), at });
    at += c.length;
  });
  return out;
}

/** The forbidden code points of a translation, as `U+XXXX` (empty when it has none). */
export function codePoints(s: string, dir: 'ltr' | 'rtl' = 'ltr'): string[] {
  return forbidden(s, dir).map((f) => f.cp);
}

/** Words of a translation that mix Latin letters with Cyrillic or Greek ones, with their offsets. */
export function mixedScript(s: string): { word: string; at: number }[] {
  return [...s.matchAll(WORD)].filter((m) => LATIN.test(m[0]) && CYRILLIC_OR_GREEK.test(m[0])).map((m) => ({ word: m[0], at: m.index }));
}

/** Everything that fails, one finding per token. */
function failures(english: string, translation: string, o: AgreeOptions): Finding[] {
  const fails: Finding[] = [];
  const add = (rule: string, token: string, detail: string, at = translation.indexOf(token)) => fails.push({ rule, token, at, detail });
  // The same set, both directions (only "added" counts for a plural form that may hold a subset).
  const both = (rule: string, e: string[], t: string[], subset = false) => {
    if (!subset) for (const x of unique(e)) if (!t.includes(x)) add(rule, x, 'missing', -1);
    for (const x of unique(t)) if (!e.includes(x)) add(rule, x, 'added');
  };
  both('placeholders', all(english, PLACEHOLDER), all(translation, PLACEHOLDER), o.placeholderSubset);
  both('tags', all(english, TAG), all(translation, TAG));
  both('urls', urls(english), urls(translation));
  const se = schemes(english);
  const st = schemes(translation);
  if (st > se) add('urls', `${st} schemes`, `added: the English has ${se}`, -1);
  const te = tokens(english);
  const tt = tokens(translation);
  for (const x of unique(te.filter((t) => structural(t, o.glossary)))) if (!tt.includes(x)) add('structural', x, 'missing', -1);
  for (const x of addedStructural(english, translation)) if (!o.exemptAdded?.includes(x)) add('structural', x, 'added');
  if (!o.exemptDigits) for (const x of missingFrom(digits(english), digits(translation))) add('digits', x, 'missing', -1);
  const prepared = prepare(translation);
  for (const w of o.verbatim ?? []) if (!whole(w).test(prepared)) add('verbatim', w, 'missing', -1);
  for (const m of mixedScript(translation)) add('mixed-script', m.word, 'mixes Latin with Cyrillic or Greek letters', m.at);
  both('code', all(english, CODE_SPAN), all(translation, CODE_SPAN));
  for (const f of forbidden(translation, o.dir)) add('code-point', f.cp, 'forbidden', f.at);
  return fails;
}

const HYPHENATED = /^[A-Za-z]+(?:-[A-Za-z]+)+$/;
const CAPITALS = /^[A-Z]{2,}$/;

/** The whole rule, for the check script: FAIL findings and REPORT findings. */
export function agree(english: string, translation: string, o: AgreeOptions = {}): Verdict {
  const fails = failures(english, translation, o);
  const reports: Finding[] = [];
  const glossary = o.glossary ?? [];
  const te = tokens(english);
  const tt = tokens(translation);
  const report = (rule: string, xs: string[], detail: string) => {
    for (const x of unique(xs)) reports.push({ rule, token: x, at: translation.indexOf(x), detail });
  };
  report('hyphenated', te.filter((t) => HYPHENATED.test(t) && !tt.includes(t)), 'translated');
  report('capitals', te.filter((t) => CAPITALS.test(t) && !glossary.includes(t) && !tt.includes(t)), 'translated');
  // Added tokens that are not structural (and those a maintainer's exemption allows), and a `.`
  // between letters of another script, which may be an address the rule cannot read.
  const dots = scriptDots(english);
  const exempt = o.exemptAdded ? addedStructural(english, translation).filter((x) => o.exemptAdded?.includes(x)) : [];
  report('added', [...tt.filter((t) => !te.includes(t) && !isAdded(t)), ...exempt, ...scriptDots(translation).filter((w) => !dots.includes(w))], 'added');
  return { fails, reports };
}

/** What the browser checks before it shows a translation: the same rules without the data files
 * (`verbatim`, glossary), as a yes or no that stops at the first problem. `built` for a catalog
 * the build shipped: the check held it to the digit and added-token rules, with a maintainer's
 * exemptions, so those two are left out; anything else is held to them. `subset` for a plural form
 * other than `other`. */
export function agreesAtRuntime(english: string, translation: string, dir: 'ltr' | 'rtl' = 'ltr', o: { subset?: boolean; built?: boolean } = {}): boolean {
  const pe = all(english, PLACEHOLDER);
  const pt = all(translation, PLACEHOLDER);
  if (o.subset ? pt.some((p) => !pe.includes(p)) : !sameSet(pe, pt)) return false;
  if (!sameSet(all(english, TAG), all(translation, TAG))) return false;
  if (!sameSet(urls(english), urls(translation)) || schemes(translation) > schemes(english)) return false;
  const te = tokens(english);
  const tt = tokens(translation);
  if (te.some((t) => structural(t) && !tt.includes(t))) return false;
  if (!o.built && (addedStructural(english, translation).length || missingFrom(digits(english), digits(translation)).length)) return false;
  if (!sameSet(all(english, CODE_SPAN), all(translation, CODE_SPAN))) return false;
  return mixedScript(translation).length === 0 && forbidden(translation, dir).length === 0;
}
