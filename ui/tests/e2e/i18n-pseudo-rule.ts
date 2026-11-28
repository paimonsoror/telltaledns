// REQ: API-012 (ADR-189) — the whole-page rule of the pseudo-locale page tests (8-i18n-pseudo.spec.ts),
// as functions of data, so a test without a browser can hold it to fixtures (7-i18n-pseudo-rule.spec.ts).
//
// On a page under the pseudo-locale, every piece of visible text (the text nodes outside
// translate="no", the attributes a reader sees or hears, and the canvas text) carries a pseudo
// character, or has no letters, or is code (a path, a key, a host name, a format), or is a formatted
// date or time, or is data of the test: the names and values its mocks and the server sent, and
// what it typed, each checked never to be the English of a message. Nothing depends on where a text
// came from, or on which file wrote it.
import { LOWER, UPPER } from '../../src/lib/i18n/pseudo';

/** A pseudo character: the accented letters the pseudo-locale draws every ASCII letter with. */
export const PSEUDO = new RegExp(`[${[...LOWER, ...UPPER].join('')}]`);
/** The dots the pseudo-locale pads a message with (a third of its letters): a message that wraps a
 * parameter (`<b>What this will do:</b> {impact}`) leaves them after the parameter's text. */
const PADDING = /·{3,}$/;
export const hasPseudo = (s: string): boolean => PSEUDO.test(s) || PADDING.test(s);

const LETTER = /\p{L}/u;
/** Whether a text has letters at all: numbers, units without letters and signs are not text. */
export const hasLetters = (s: string): boolean => LETTER.test(s);

/** A path, a key, a host name or a format: one token with a separator between two other characters
 * (`a/b`, `data-theme`, `2-digit`, `ads.example.com`). A word with a full stop or a colon after it
 * (`Saved.`, `Canaries:`) is text, so the stop and the colon at the end do not count. */
const CODE = /^\S*[^\s.:][./:_=-][^\s.:]\S*$/;
/** Letters, a hyphen between two letters, and nothing else: a word (`Git-managed`, `Read-only`). */
const HYPHENATED_WORD = /^\p{L}+(?:-\p{L}+)+$/u;
/** Letters and slashes and nothing else (`Queries/s`, `and/or`, `q/s`). */
const SLASHED_WORDS = /^\p{L}+(?:\/\p{L}+)+$/u;
export const isCode = (s: string): boolean => {
  const word = s.replace(/[.:]+$/, '');
  if (!CODE.test(word) || HYPHENATED_WORD.test(word)) return false;
  // Words joined by a slash are text when a side is a word of two letters or more (`Queries/s`); `a/b` and `q/s`
  // have none, and read as code (a unit like `q/s` cannot be told from a path).
  return !(SLASHED_WORDS.test(word) && word.split('/').some((w) => [...w].length >= 2));
};

/** The words a date or a time formatted in English by the browser (the suite pins en-US) is made of. */
const DATE_WORDS = new Set(
  'AM PM am pm UTC GMT Jan Feb Mar Apr Jun Jul Aug Sep Sept Oct Nov Dec January February March April May June July August September October November December Mon Tue Tues Wed Thu Thur Thurs Fri Sat Sun Monday Tuesday Wednesday Thursday Friday Saturday Sunday'.split(' '),
);
/** A date or a time formatted by `lib/format.ts` (`06:37 PM`, `Wed, Nov 25`, `11/24/2026, 5:00:00 PM`): it
 * has a digit and no word but those of a date. A word alone (`Mon`, `May`) is a message, not a date. A number
 * the browser formats compactly (`12K`, `1.5M`) is not a message either. */
export const isFormatted = (s: string): boolean =>
  (/\d/.test(s) && s.split(/[^\p{L}]+/u).filter(Boolean).every((w) => DATE_WORDS.has(w))) || /^-?[\d.,]+[KMBT]$/.test(s);

/** Whether a text is the English `s` with `{}` for a placeholder: the whole text, a placeholder is any
 * text (also none). The pieces between the placeholders are looked for in order, the first at the
 * start and the last at the end: in linear time, however long the text (a pattern of `[\s\S]*?` gaps
 * took seconds on the few thousand characters of the dashboard's list of changes). */
export function isEnglish(s: string, text: string): boolean {
  return fits(s.split('{}'), text);
}
function fits(parts: readonly string[], text: string): boolean {
  if (parts.length === 1) return text === parts[0];
  const first = parts[0];
  const last = parts[parts.length - 1];
  if (!text.startsWith(first) || !text.endsWith(last) || first.length + last.length > text.length) return false;
  const end = text.length - last.length;
  let at = first.length;
  for (let i = 1; i < parts.length - 1; i++) {
    const p = parts[i];
    if (p === '') continue;
    const k = text.indexOf(p, at);
    if (k < 0 || k + p.length > end) return false;
    at = k + p.length;
  }
  return true;
}

const letterCount = (s: string) => (s.replace(/\{\}/g, '').match(/\p{L}/gu) ?? []).length;
/** The letters of a pattern that no placeholder touches: `{n} odd` has three, `{s}s` none (the placeholder could take that
 * letter too, and the pattern would fit any word that ends in it). */
const freeLetters = (s: string) => {
  const c = [...s.replace(/\{\}/g, '\u0000')];
  return c.filter((ch, i) => LETTER.test(ch) && c[i - 1] !== '\u0000' && c[i + 1] !== '\u0000').length;
};

const WORD_CHAR = /[\p{L}\p{N}]/u;
/** Where `value` stands in `piece` as whole words: not inside a longer word or number (`name` is not in
 * `username`). A value that starts or ends with a sign needs no boundary on that side. */
function wholeAt(piece: string, value: string): number[] {
  const out: number[] = [];
  const first = WORD_CHAR.test(value[0] ?? '');
  const last = WORD_CHAR.test(value[value.length - 1] ?? '');
  for (let i = piece.indexOf(value); i >= 0; i = piece.indexOf(value, i + 1)) {
    if (first && i > 0 && WORD_CHAR.test(piece[i - 1])) continue;
    const end = i + value.length;
    if (last && end < piece.length && WORD_CHAR.test(piece[end])) continue;
    out.push(i);
  }
  return out;
}

/** Whether a piece is made of the test's own data: one value (or a pattern with `{}`), or several of them
 * with only signs, numbers and code between (`work-pc (127.0.0.1)`, `unifi · https://192.168.0.1`). A value
 * counts as whole words only. */
export function covered(piece: string, own: Iterable<string>): boolean {
  const values = [...own].filter((v) => v.length >= 2 && (v.includes('{}') ? isEnglish(v, piece) : wholeAt(piece, v).length > 0));
  if (values.some((v) => v.includes('{}') || v === piece)) return true;
  let rest = piece;
  for (const v of values.sort((a, b) => b.length - a.length)) {
    for (const i of wholeAt(rest, v).reverse()) rest = `${rest.slice(0, i)}${' '.repeat(v.length)}${rest.slice(i + v.length)}`;
  }
  // What is left between the values: signs, numbers, code, and (beside a number) the words of a time (`06:37 PM: …`).
  const clock = /\d/.test(piece);
  return rest.split(/\s+/).every((word) => !hasLetters(word) || isCode(word) || (clock && DATE_WORDS.has(word.replace(/[^\p{L}]/gu, ''))));
}

/** Whether a piece is one value of the test's data, whole (or fits a pattern of its own with `{}`): the data and nothing
 * else, which no message can be hiding behind (`by hand`, the value of a field, is not the message `by {by}`). */
export const isWhole = (piece: string, own: Iterable<string>): boolean => [...own].some((v) => v.length >= 2 && (v.includes('{}') ? isEnglish(v, piece) : v === piece));

export type Datum = {
  /** Why the text is data and the UI cannot mark it. */
  reason: string;
  /** Where it may stand: every place the text is read at must match (a place reads like `text of div.u-label`). */
  where?: RegExp;
};

/** Values the real server shows that the UI cannot mark as data, and that read like English: one entry
 * each, with the reason and the place, as a text node only (an attribute with the same text is the layer's
 * own). Keep it empty where an element can carry `translate="no"` instead. */
export const DATA: Readonly<Record<string, Datum>> = {
  // The name of the built-in group, which the legend of a chart that draws one series per group shows: uPlot
  // writes a series' label as text of its own, which cannot carry the mark.
  default: { reason: "the server's built-in group, as the label of a series in a uPlot legend (lib/components/Chart.svelte)", where: /\bu-label\b/ },
};

export type RuleInput = {
  /** Shared data: see DATA. Text nodes only, at the places they name. */
  data: Readonly<Record<string, Datum>>;
  /** English the help panel shows from docs/help/topics.json (ADR-189: help stays English in part A). Only in the help panel. */
  help: readonly string[];
  /** The English of the layer's messages (`{name}` for a placeholder). With them, a piece that is a message's English, or fits
   * a message that has a letter of its own, is that message gone back to English, whatever data it also shows. */
  messages?: readonly string[];
};

export type Rule = {
  /** The pieces of the page that are English (empty: the rule holds). `text` the text nodes, `other`
   * the attributes a reader sees or hears and the canvas text, `own` the test's data (values, or patterns
   * with `{}`), `help` the pieces inside the help panel and the titles of help buttons. */
  found(text: readonly string[], other: readonly string[], own?: Iterable<string>, help?: readonly string[], places?: ReadonlyMap<string, readonly string[]>): string[];
};

/** The separator code puts between the parts of a piece it builds (`3 rules · off`). */
const JOIN = ' · ';

export function makeRule({ data, help, messages }: RuleInput): Rule {
  const helpSet = new Set(help);
  // A message of the layer that a piece is, or fits with a letter of its own (one word for each placeholder).
  const messageOf = messages ? makeCollides(messages, 1, true) : () => undefined;
  return {
    found(text, other, own = [], inHelp = [], places) {
      const ownList = [...own];
      const found: string[] = [];
      /** A part of a piece that code joined: a message with a placeholder gone back to English (`4.2 q/s`, `3 rules`), which no
       * data of the test says whole. A part that is a single word (`primary`, `block`: the server's, or a message's) is not told apart. */
      const englishPart = (s: string) => !hasPseudo(s) && hasLetters(s) && !isCode(s) && !isFormatted(s) && !isWhole(s, ownList) && (messageOf(s) ?? '').includes('{');
      for (const p of new Set([...text, ...other, ...inHelp])) {
        if (!hasLetters(p) || isCode(p) || isFormatted(p)) continue;
        // One pseudo character excuses a piece, but not a message with a placeholder that code joined to it in English
        // (`you · 4.2 q/s`).
        if (p.includes(JOIN) && p.split(JOIN).some(englishPart)) {
          found.push(JSON.stringify(p));
          continue;
        }
        if (hasPseudo(p)) continue;
        const elsewhere = text.includes(p) || other.includes(p);
        // Shared data: as a text node only (an attribute or canvas text is the page's own), at the places it names.
        const d = Object.hasOwn(data, p) ? data[p] : undefined;
        const at = places?.get(p) ?? [];
        if (d && text.includes(p) && !other.includes(p) && (!d.where || (at.length > 0 && at.every((w) => d.where?.test(w))))) continue;
        // The help glossary: English in part A, where the help panel shows it (and nowhere else).
        if (helpSet.has(p) && !elsewhere) continue;
        // The test's own data: its mocks' and the server's names and values, in a text node or an attribute. A piece that is
        // a message's English, or fits a message, is that message gone back to English, whatever data it also holds; a piece
        // that is one value of the data and nothing else is data.
        if (isWhole(p, ownList) || (!messageOf(p) && covered(p, ownList))) continue;
        found.push(JSON.stringify(p));
      }
      return found;
    },
  };
}

/** The English message a data string would hide, if any: a test may take as data only what no message
 * says. `messages` are the English of the layer's messages, with `{name}` for a placeholder; a pattern
 * with a placeholder counts when it has eight letters of its own (a shorter one would fit any name). */
export function collides(value: string, messages: readonly string[], minLetters = 8, free = false): string | undefined {
  return messages.find((m) => {
    const s = m.replace(/\{[A-Za-z_][A-Za-z0-9_]*\}/g, '{}');
    if (!s.includes('{}')) return s === value || (value.includes('{}') && isEnglish(value, s));
    const own = free ? freeLetters(s) : letterCount(s);
    // A pattern read for a piece takes one word for each placeholder (`{n} odd` fits `1 odd`, not `first query to odd`).
    const fits = free ? fitsWords(s, value) : isEnglish(s, value);
    return (own >= minLetters && fits) || (value.includes('{}') && isEnglish(value, s));
  });
}

/** Whether a text is the English `s` (placeholders `{}`) with one word, or none, for each placeholder. */
function fitsWords(s: string, text: string): boolean {
  if (text.length > 400) return false;
  return new RegExp(`^${s.split('{}').map((x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('\\S*')}$`, 'u').test(text);
}

/** `collides` for many values: one lookup for the messages without a placeholder, and the answer kept. A value of the
 * data is held to patterns with eight letters of their own; a piece of a page, to patterns with one letter that no
 * placeholder touches (`minLetters` 1, `free`). */
export function makeCollides(messages: readonly string[], minLetters = 8, free = false): (value: string) => string | undefined {
  const exact = new Set(messages.filter((m) => !/\{[A-Za-z_][A-Za-z0-9_]*\}/.test(m)));
  const patterns = messages.filter((m) => /\{[A-Za-z_][A-Za-z0-9_]*\}/.test(m));
  const known = new Map<string, string | undefined>();
  return (value) => {
    if (known.has(value)) return known.get(value);
    const hit = exact.has(value) ? value : collides(value, patterns, minLetters, free);
    known.set(value, hit);
    return hit;
  };
}

/** Every string value of a JSON document (what a mock or the server sent, what a test typed). */
export function jsonStrings(v: unknown, out: Set<string> = new Set()): Set<string> {
  if (typeof v === 'string') out.add(v);
  else if (Array.isArray(v)) for (const x of v) jsonStrings(x, out);
  else if (v && typeof v === 'object') for (const x of Object.values(v)) jsonStrings(x, out);
  return out;
}

/** The attributes a reader sees or hears. */
export const ATTRS = ['aria-label', 'title', 'placeholder', 'alt', 'aria-roledescription', 'aria-description', 'aria-valuetext', 'aria-placeholder'];

export type Read = { text: string[]; other: string[]; help: string[]; at: [string, string][] };

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
const decode = (s: string) => s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-z]+);/g, (whole, e: string) => (e[0] === '#' ? String.fromCodePoint(e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : (ENTITIES[e] ?? whole)));

/** What `readPage` reads, from the HTML of a page rendered on the server (the fixtures of the rule, with no
 * browser): the same text nodes, attributes and `translate="no"` subtrees, from the markup. */
export function collectHtml(html: string): Read {
  const text: string[] = [];
  const other: string[] = [];
  const at: [string, string][] = [];
  const stack: { name: string; no: boolean }[] = [];
  const tidy = (s: string) => s.replace(/\s+/g, ' ').trim();
  for (const m of html.matchAll(/<!--[\s\S]*?-->|<\/([a-zA-Z][^\s>]*)\s*>|<([a-zA-Z][^\s/>]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>|[^<]+/g)) {
    if (m[0].startsWith('<!--')) continue;
    if (m[1] !== undefined) {
      const name = m[1].toLowerCase();
      const i = stack.map((e) => e.name).lastIndexOf(name);
      if (i >= 0) stack.length = i;
    } else if (m[2] !== undefined) {
      const name = m[2].toLowerCase();
      const attrs = new Map<string, string>();
      for (const a of m[3].matchAll(/([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) attrs.set(a[1].toLowerCase(), decode(a[2] ?? a[3] ?? a[4] ?? ''));
      const no = (stack.at(-1)?.no ?? false) || attrs.get('translate') === 'no' || name === 'script' || name === 'style' || name === 'noscript';
      if (!no) {
        const read = (k: string) => {
          const s = tidy(attrs.get(k) ?? '');
          other.push(s);
          at.push([s, `${k} of ${name}`]);
        };
        for (const a of ATTRS) if (attrs.has(a)) read(a);
        if (name === 'optgroup' && attrs.has('label')) read('label');
        if (name === 'input' && ['button', 'submit', 'reset'].includes(attrs.get('type') ?? '') && attrs.has('value')) read('value');
      }
      if (!VOID.has(name) && !m[0].endsWith('/>')) stack.push({ name, no });
    } else if (!(stack.at(-1)?.no ?? false)) {
      const s = tidy(decode(m[0]));
      if (s) {
        text.push(s);
        at.push([s, `text of ${stack.at(-1)?.name ?? 'the page'}`]);
      }
    }
  }
  return { text, other, help: [], at };
}

/** Run in the page (it takes no argument and uses nothing outside itself): every text node outside
 * translate="no", the attributes a reader sees or hears (and the `label` of an optgroup and the `value`
 * of a button), and the canvas text the init script of `watch` collected; `at` names where each was first
 * seen. What sits in the help panel (and the title of a help button) is returned in `help` instead. */
export function readPage(): Read {
  const ATTR_LIST = ['aria-label', 'title', 'placeholder', 'alt', 'aria-roledescription', 'aria-description', 'aria-valuetext', 'aria-placeholder'];
  const text: string[] = [];
  const other: string[] = [];
  const help: string[] = [];
  const at: [string, string][] = [];
  const seen = new Set<string>();
  // The reader does not see a <noscript> of a page that runs.
  const free = (el: Element) => !el.closest('[translate="no"], script, style, noscript');
  const tidy = (s: string) => s.replace(/\s+/g, ' ').trim();
  const where = (el: Element | null, what: string) => {
    if (!el) return what;
    const id = el.closest('[data-testid]')?.getAttribute('data-testid');
    const cls = typeof el.className === 'string' && el.className.trim() ? `.${el.className.trim().split(/\s+/).join('.')}` : '';
    return `${what} of ${el.localName}${cls}${id ? ` in [data-testid=${id}]` : ''}`;
  };
  const note = (s: string, el: Element | null, what: string) => {
    const place = where(el, what);
    if (seen.has(`${s}\u0000${place}`)) return;
    seen.add(`${s}\u0000${place}`);
    at.push([s, place]);
  };
  // The help panel (English data in part A): what is inside it, and what else its own drawer holds (the topic's title,
  // the close button). A drawer that only holds another drawer with a help panel (a "?" button renders its drawer
  // inline) is not help: the closest drawer of the element must be the panel's own.
  const panels = [...document.querySelectorAll('[data-testid="help-panel"]')];
  const helpDrawers = new Set(panels.map((p) => p.closest('.drawer')).filter((d): d is Element => d !== null));
  const inHelp = (el: Element) => {
    if (panels.some((p) => p.contains(el))) return true;
    const drawer = el.closest('.drawer');
    return drawer !== null && helpDrawers.has(drawer);
  };
  const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
  for (let n: Node | null = walk.currentNode; n; n = walk.nextNode()) {
    if (n.nodeType === Node.TEXT_NODE) {
      const s = tidy(n.textContent ?? '');
      if (n.parentElement && free(n.parentElement) && s) {
        (inHelp(n.parentElement) ? help : text).push(s);
        note(s, n.parentElement, 'text');
      }
    } else if (n instanceof Element && free(n)) {
      const read = (name: string) => {
        const s = tidy(n.getAttribute(name) ?? '');
        // The title of a help button, and every attribute inside the help drawer (its label is the topic's title).
        (inHelp(n) || (name === 'title' && n.matches('button[data-help]')) ? help : other).push(s);
        note(s, n, name);
      };
      for (const a of ATTR_LIST) if (n.hasAttribute(a)) read(a);
      if (n.localName === 'optgroup' && n.hasAttribute('label')) read('label');
      if (n.localName === 'input' && ['button', 'submit', 'reset'].includes((n as HTMLInputElement).type) && n.hasAttribute('value')) read('value');
    }
  }
  const canvas: string[] = (window as unknown as { __i18aCanvas?: string[] }).__i18aCanvas ?? [];
  for (const c of canvas) {
    const s = tidy(c);
    other.push(s);
    note(s, null, 'canvas text');
  }
  return { text, other, help, at };
}
