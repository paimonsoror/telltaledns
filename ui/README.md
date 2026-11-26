# TelltaleDNS web UI

Changing the design? Read [DESIGN-HANDOFF.md](DESIGN-HANDOFF.md) first (constraints, design
system, test contract, backlog).

Svelte 5 + Vite + TypeScript + uPlot, no CSS framework (`spec/07` §3, ADR-009, ADR-030). The
build output (`dist/`) is embedded in the binary by `telltale-api` (`rust-embed`) and served at
`/` on the API listener.

```sh
npm ci
npm run dev        # http://localhost:5173, proxies /api to a server on 127.0.0.1:8053 (TELLTALE_API=...)
npm run check      # svelte-check (types, a11y)
npm run check:i18n # messages, contexts, locale files and the text ratchets (ADR-189)
npm run build      # dist/ + .gz files; fails over the budgets: the UI with English 400 KiB
                   # gzipped (everything outside assets/locales/), each language 80, all of them 400
npm run types      # regenerate src/lib/api-types.ts from ../docs/api/openapi.json (CI checks it's current)
```

`dev`, `check`, `build` and `test:e2e` first run `node scripts/i18n.mjs prebuild`, which writes
`src/lib/i18n/locales.gen.ts`, `src/lib/i18n/emitted.gen.json` and `public/assets/locales/` (all
git-ignored): a fresh checkout needs no extra step. `scripts/i18n.mjs` needs Node 24 (as CI and the
Dockerfile use; 22.18 and later also work), which strips TypeScript types: the tool imports the
runtime's own modules.

Then rebuild the binary (`cargo build -p telltale`) to embed `dist/`. A binary built without
`dist/` still works and says the UI is missing.

## End-to-end tests

```sh
cargo build -p telltale && npm run build
npx playwright install --with-deps --only-shell chromium
npm run test:e2e             # starts the real binary (tests/e2e/server.mjs) on 127.0.0.1:18054
SHOTS=1 npm run test:e2e     # also refreshes the site's screenshots (../site/assets/shots/)
                             # and saves every page to .shots/ for design review
```

## Dashboard screenshots

The README's and the site's dashboard pictures come from a made-up home network, so no real
network ever shows up in them. `tests/demo/run.sh` starts two stub upstreams and a fresh server
with `tests/demo/demo.toml`, sends about 14 minutes of synthetic traffic from invented devices,
and then writes `../docs/images/dashboard-*.jpg` and `../site/assets/shots/dashboard-*.jpg`:

```sh
npm run build && cargo build -p telltale     # the binary embeds the UI
tests/demo/run.sh            # or `tests/demo/run.sh 60` for a quick look
```

## Rules

- The UI uses only the public API (`src/lib/api.ts`), like scripts and agents do.
- Strict CSP (`script-src 'self'; style-src 'self'`): no inline scripts, no `style="..."`
  attributes, no `{@html}`. Set dynamic styles with `style:prop={...}` (applied through the
  CSSOM, which CSP allows). The suite fails on any CSP violation.
- Every chart gets a table view; every page works at 360 px.
- Filters and tabs live in the URL hash (`#/queries?client=...`).

## Languages

The UI's text goes through a small layer of its own (`src/lib/i18n/`, `spec/11` ADR-189, API-012).
English is the key: the English stays in the source, and with English active `t()` returns it
unchanged. Every other language is a data file fetched before the page is drawn; a translation is
shown only if it agrees with the English it replaces, otherwise English is. No language is offered
yet; `?lang=en-XA` shows the pseudo-locale (accented, longer English) for one page load.

**Add a string.** In the file that shows it, bind the file's context (its name in lower camel case:
`pages/Cache.svelte` is `cache`; `src/locales/contexts.json` renames a file whose name another
file already has) and write the English as a literal:

```svelte
<script lang="ts">
  import { tr } from '../lib/i18n';
  import T from '../lib/i18n/T.svelte';
  const { t, tn } = tr('cache');
  const { t: tc } = tr('common'); // bare actions shared by every file (at most 40)
</script>

<h2>{t('Holds')}</h2>
<p>{t('{n} entries of {max}', { n: num(count), max: num(limit) })}</p>
<p>{tn('{n} answer', '{n} answers', n, { n: num(n) })}</p>
<T ctx="cache" msg={'Kept by <b>{who}</b>'} params={{ who }}>{#snippet b(text)}<b>{text}</b>{/snippet}</T>
```

- Literals only: the check reads them from the syntax tree. `t('Open', undefined, 'verb')` separates
  two meanings of the same English in one file.
- A sentence is one message. Markup inside it goes through `<T>`, whose `msg` is an expression
  (`msg={'…'}`): in a quoted attribute Svelte would replace `{who}` itself.
- `tn()` only where the English has two forms; the form follows the language of the text, never the
  browser's. Numbers are formatted by the caller (`num()`), dates and times by `lib/format.ts`,
  the only place that calls `Intl`.
- A `t()` result is text to show: never a key, a comparison operand, a stored value, a URL or part of
  a request. Keep an identifier beside it.
- Nothing translates at the top level of a `.ts` module or `<script module>` (it would run before
  the language is loaded): mark a label there with `m('Lists')` and show it with `tk(label)`.
- Names, addresses and code shown as data get `translate="no"`.

`npm run check:i18n` fails on a non-literal message, a context that is not the file's or `common`,
two files with one context, a hash collision, a translated text misused as above, literal text in a
file `i18n-baseline.json` holds at zero (in the markup, or in an attribute a reader sees or hears:
`aria-label`, `title`, `placeholder`, `alt`, `aria-roledescription`, `aria-description`,
`aria-valuetext`, `aria-placeholder`, and `label` on `<optgroup>`), a new `Intl` call outside
`lib/format.ts`, and a new physical CSS property (`margin-left`, `text-align: right`; use logical
ones). It reports, and never fails on, missing, outdated and left-over translations. A change to
English alone never fails a language. A file `i18n-baseline.json` does not list (one added or moved
since) holds none of the three: literal text, an `Intl` call or a physical property in it fails, and a
moved file that still holds some keeps its counts only if its entries in `i18n-baseline.json` are
renamed to the new path by hand. After removing text, an `Intl` call or a physical property,
`node scripts/i18n.mjs baseline` lowers that file's count (it never raises one, and lists a new file
only at zero). Every file holds no literal text and no `Intl` call outside `lib/format.ts`; the
physical CSS properties of the files that have them are kept at their counts and are converted
with the right-to-left work.

**The pseudo-locale tests** (`tests/e2e/8-i18n-pseudo.spec.ts`, the rule in
`tests/e2e/i18n-pseudo-rule.ts`) read every page under `?lang=en-XA`: each text node outside
`translate="no"`, each attribute a reader sees or hears, the value of a button and the canvas text
must carry a pseudo character, have no letters, be code, be a formatted date, time or compact number,
or be data of the test (a name or value its mocks or the server sent). A name or value the page
shows as it was given and that is also the English of a message (`default`, `admin`, a status word)
needs `translate="no"` on the element that shows it. Two excuses are kept to the place they name: the
help glossary (`docs/help/topics.json`, English in part A) only inside the help panel and the drawer
that holds it, and the shared table in `i18n-pseudo-rule.ts` (`DATA`: the series label that uPlot writes
itself in a chart legend) only as a text node at its place. A piece that is a message's English, or fits
one that has a letter of its own (one word for each placeholder), fails even beside data (`1 odd` where
`odd` is a value); a value counts as whole words; and a message with a placeholder that code joined to
pseudo text with ` · ` in English (`you · 4.2 q/s`) fails too.

**Moving a file to the layer** (part A): `node scripts/i18n-codemod.mjs <file under src/>` (or
`--all`) prints, per file, what it can move and what it leaves for the hand; `--write` rewrites the
file. Each template text and each attribute a reader sees or hears becomes `t('…')` (the text as
the browser shows it), and the file gets its `tr()` line. It lists, with the line, and never edits:
a sentence with an expression, an inline element or a block inside, words cut by an element with no
text (a colour key, an icon: class `split`; one message for the whole run), `<pre>`, script strings, plural
ternaries (`tn()` takes the `one` form for -1), labels used as keys, canvas text and `Intl` calls.

**Add a language.** A maintainer adds the tag to `src/locales/manifest.json` (`owners`: the GitHub
logins of the people who answer for its content; `dir`; `offered: false` until a release turns it
on; `since`), and the language to `src/locales/plurals.json` if it is not there (`node
scripts/i18n.mjs plurals` writes it from CLDR; review the diff). A tag names the script where the
language has several (`zh-Hans`, `sr-Latn`); there is no `en-*` catalog (English is built in). The
translator then runs `node scripts/i18n.mjs sync <tag>`, fills in the empty translations of
`src/locales/<tag>.json` (pairs of English and translation; a plural lists the language's
categories), and opens a pull request with that one file. A plural form other than `other` may
leave out `{n}`, but in some languages it is used for more than one number: Russian, Ukrainian and
Croatian `one` also for 21, 31 or 101, Latvian `zero` also for 10 to 20. Keep `{n}` in those forms.
After an English edit that keeps the meaning, a maintainer runs `node scripts/i18n.mjs carry
<context> --from "<old>" --to "<new>"`; otherwise the old pair is reported as left over and English
is shown until the language's owner confirms the new text.

**Exemptions.** A translation that adds a time, a ratio, a date pattern, a list joined by slashes,
a grouped number or a price (`24:00`, `16:9`, `TT/MM/JJJJ`, `1.000.000.000`, `$5`) fails as an added
structural token, naming it. A maintainer may then allow that token for that message in
`src/locales/notes.json`: `exemptAdded` lists the tokens a translation may add (`"exemptAdded":
["24:00"]`, with the reason in `text`), and any other token it adds still fails. A translation that
writes a number in words is exempted with `exemptDigits` (the reason as the value). The check
reports the allowed tokens instead, and the reviewer reads them. The browser does not re-check the
two rules for a catalog the build shipped, and does for any other.

**Review a catalog pull request by structure.** You do not need to read the language:

1. The pull request changes that language's file only (and its owners in the manifest, if the
   owner says so).
2. `npm run check:i18n` is green: every translation keeps the placeholders, tags and web addresses
   of its English, every structural token (a URL, a path, `[x]`, `=`, `_`, `$`, `|`, a host and port,
   an IP address, a glossary term), every number, and every word `src/locales/verbatim.json` lists
   for it; it adds no address, port, path or setting (also written with fullwidth or ideographic
   punctuation, `８．８．８．８`); and it has no direction overrides, invisible characters or words
   that mix scripts. The added-token lines of the report name no address.
   An address written in the language's own script shows only as an added-token line (`例子.公司`,
   for its `.` between two letters of that script; after a bare `https://` it fails), and with an
   ideographic full stop (`例子。公司`) not at all. Digits of another script (`٨٫٨٫٨٫٨`) and an
   address with spaces in it (`8 . 8 . 8 . 8`) are not seen either: the language's owner reads the
   text for these.
3. The job summary's **sensitive** lines (messages `src/locales/notes.json` marks sensitive: the
   pull request carries a back-translation of each) and **swap** lines (a new translation equal to
   another message's old one) are explained.
4. The language's owner has approved it.