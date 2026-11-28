// REQ: API-012 (ADR-189) — the whole agreement rule, as the check script applies it: every finding,
// FAIL and REPORT, with the token and where it is in the translation. A module of its own, apart
// from the runtime's first-use check (`agreesAtRuntime` in `safe.ts`), so code loaded later can run
// the build's rule without the page's first load carrying it. Pure; it imports the readings of
// `safe.ts` and the digit and added-token rules of `added.ts` only, by their file names (`.ts`), as
// Node's own type stripping needs (the check script imports this module).
import { addedStructural, digits, isAdded, missingFrom, whole } from './added.ts';
import {
  CODE_SPAN,
  PLACEHOLDER,
  TAG,
  all,
  forbidden,
  mixedScript,
  prepare,
  schemes,
  structural,
  tokens,
  unique,
  urls,
  type AgreeOptions,
  type Finding,
  type Verdict,
} from './safe.ts';

export type { AgreeOptions, Finding, Verdict } from './safe.ts';

/** Where a finding's token first is in the translation (a search from the start, so it is skipped for a
 * caller that never shows it). */
const where = (translation: string, token: string, o: AgreeOptions) => (o.positions === false ? -1 : translation.indexOf(token));

/** Everything that fails, one finding per token. */
function failures(english: string, translation: string, o: AgreeOptions): Finding[] {
  const fails: Finding[] = [];
  const add = (rule: string, token: string, detail: string, at = where(translation, token, o)) => fails.push({ rule, token, at, detail });
  // The same set, both directions (only "added" counts for a plural form that may hold a subset). Sets
  // throughout, so a long text is read in linear time.
  const both = (rule: string, e: string[], t: string[], subset = false) => {
    const es = new Set(e);
    const ts = new Set(t);
    if (!subset) for (const x of es) if (!ts.has(x)) add(rule, x, 'missing', -1);
    for (const x of ts) if (!es.has(x)) add(rule, x, 'added');
  };
  both('placeholders', all(english, PLACEHOLDER), all(translation, PLACEHOLDER), o.placeholderSubset);
  both('tags', all(english, TAG), all(translation, TAG));
  both('urls', urls(english), urls(translation));
  const se = schemes(english);
  const st = schemes(translation);
  if (st > se) add('urls', `${st} schemes`, `added: the English has ${se}`, -1);
  const te = tokens(english);
  const tt = new Set(tokens(translation));
  for (const x of unique(te.filter((t) => structural(t, o.glossary)))) if (!tt.has(x)) add('structural', x, 'missing', -1);
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
// A `.` between two letters of other scripts: an address the ASCII readings cannot see (`例子.公司`).
const WORD_RUN = /[\p{L}\p{N}\p{M}.]+/gu;
const SCRIPT_DOT = /(?![\x00-\x7F])\p{L}\.(?![\x00-\x7F])\p{L}/u;
const scriptDots = (s: string) => (s.normalize('NFKC').match(WORD_RUN) ?? []).filter((w) => SCRIPT_DOT.test(w));

/** The whole rule, for the check script: FAIL findings and REPORT findings. */
export function agree(english: string, translation: string, o: AgreeOptions = {}): Verdict {
  const fails = failures(english, translation, o);
  const reports: Finding[] = [];
  const glossary = o.glossary ?? [];
  const te = tokens(english);
  const tt = tokens(translation);
  const tes = new Set(te);
  const tts = new Set(tt);
  const report = (rule: string, xs: string[], detail: string) => {
    for (const x of unique(xs)) reports.push({ rule, token: x, at: where(translation, x, o), detail });
  };
  report('hyphenated', te.filter((t) => HYPHENATED.test(t) && !tts.has(t)), 'translated');
  report('capitals', te.filter((t) => CAPITALS.test(t) && !glossary.includes(t) && !tts.has(t)), 'translated');
  // Added tokens that are not structural (and those a maintainer's exemption allows), and a `.`
  // between letters of another script, which may be an address the rule cannot read.
  const dots = new Set(scriptDots(english));
  const exempt = o.exemptAdded ? addedStructural(english, translation).filter((x) => o.exemptAdded?.includes(x)) : [];
  report('added', [...tt.filter((t) => !tes.has(t) && !isAdded(t)), ...exempt, ...scriptDots(translation).filter((w) => !dots.has(w))], 'added');
  return { fails, reports };
}
