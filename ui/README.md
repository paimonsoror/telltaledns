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
npm run build      # dist/ + .gz files; fails over the 400 KiB gzipped budget
npm run types      # regenerate src/lib/api-types.ts from ../docs/api/openapi.json (CI checks it's current)
```

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

## Languages

The UI speaks English and Simplified Chinese (ADR-185). The switch is the globe button in the
header (also on the sign-in pages); it names the language it goes to and is kept in this browser.
`?lang=zh-CN` or `?lang=en` on any URL does the same, and a browser whose first language is
Chinese opens in Chinese.

Text lives in `src/lib/i18n/messages/<language>/<area>.ts`, one file per area, and `src/lib/i18n/`
has the `t()`/`tn()` functions. The English catalog is the source of truth: `MessageKey` comes from
it, so an unknown key is a type error, and `npm run check:i18n` fails when a language is missing a
key, adds one, repeats one, leaves a value empty, or has different `{placeholders}`. To add a
string:

1. Add `'area.what.it.says': 'The English text'` to `messages/en/<area>.ts` (the English must be
   the exact text users see today: the Playwright suite asserts English labels).
2. Add the same key with the Chinese text to `messages/zh-CN/<area>.ts`.
3. Use `{t('area.what.it.says')}` in the markup (alias the import as `tr` if the file already has a
   `t`), or `t('area.key', { name })` with `{name}` in the string. Counts use `tn('area.key', n)`
   with `area.key.one` and `area.key.other` in both languages.
4. Strings built in `<script>` must be `$derived` or a function called from the markup, so they
   follow a language change without a reload.

Nothing that belongs to the server is translated: API values, configuration keys, status and
enum identifiers, DNS/RFC terms, `code` snippets, and people's names. The help glossary is
`../docs/help/topics.json` plus `../docs/help/topics.zh-CN.json`; `npm run check:help` checks both
against the `?` buttons.

## Rules

- The UI uses only the public API (`src/lib/api.ts`), like scripts and agents do.
- Strict CSP (`script-src 'self'; style-src 'self'`): no inline scripts, no `style="..."`
  attributes, no `{@html}`. Set dynamic styles with `style:prop={...}` (applied through the
  CSSOM, which CSP allows). The suite fails on any CSP violation.
- Every chart gets a table view; every page works at 360 px.
- Filters and tabs live in the URL hash (`#/queries?client=...`).