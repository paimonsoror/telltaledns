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

## Rules

- The UI uses only the public API (`src/lib/api.ts`), like scripts and agents do.
- Strict CSP (`script-src 'self'; style-src 'self'`): no inline scripts, no `style="..."`
  attributes, no `{@html}`. Set dynamic styles with `style:prop={...}` (applied through the
  CSSOM, which CSP allows). The suite fails on any CSP violation.
- Every chart gets a table view; every page works at 360 px.
- Filters and tabs live in the URL hash (`#/queries?client=...`).