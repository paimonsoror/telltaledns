# TelltaleDNS web UI — design handoff

For a frontend designer/engineer agent improving the UI. You start with no context: read this
whole file before you change anything. It describes what exists, why, the rules that keep the
product working, and where design work is most welcome.

Status: MVP shipped 2026-10-04 (roadmap T3.9, ADR-030). About 60 KiB gzipped. 8 Playwright
end-to-end tests pass against the real server binary.

---

## 1. Product context

**TelltaleDNS** is a DNS resolver for homes and homelabs that filters ads and trackers (like
Pi-hole or AdGuard Home), encrypts upstream traffic, and *explains* every decision. It runs on a
Raspberry Pi or in Kubernetes. Its tagline: "See every question. Answer on your terms."

**Who uses the UI:** the person who runs the home network (technical, often on a phone
while troubleshooting "why doesn't this site load?"), plus family members with a `viewer`
account. The typical visits:

1. *Something is broken*: find the query in the log, press **Why?**, see which list blocked it.
2. *Glance*: is it working, how much is blocked, is an upstream down?
3. *Admin*: create users and API tokens, enroll two-factor sign-in.

**What it should feel like:** a calm, precise instrument panel (closer to Grafana or Linear
than to a consumer app). Dense but readable. Numbers are first-class (tabular figures, units
always shown). It shouldn't feel playful or marketing-like.

**Owner priorities (from `AGENTS.md`, for tie-breaks):** performance > lightweight footprint >
observability > Kubernetes + Pi deployability > clustering/HA > protocol breadth > UI polish.
So: polish is welcome, but **never at the cost of bundle size, runtime speed, or correctness**.
The UI is served by the DNS server itself, often from a Raspberry Pi.

---

## 2. Hard constraints (breaking these breaks the product or CI)

| # | Rule | Why / what enforces it |
|---|---|---|
| 1 | **Stack: Svelte 5 (runes), Vite, TypeScript, uPlot.** No UI framework, no CSS framework (no Tailwind, Bootstrap, component libraries), no CSS-in-JS runtime. | `spec/07` §3, ADR-009. Owner decision. |
| 2 | **Bundle ≤ 400 KiB gzipped in total** (JS + CSS + HTML + assets). | `npm run build` fails above it (`scripts/postbuild.mjs`). Currently ~60 KiB: keep plenty of headroom. Any new dependency needs a one-line justification in the commit. |
| 3 | **Strict CSP.** The server sends `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. So: **no inline `<script>`, no `style="..."` attributes (static or dynamic), no `{@html}`, no external fonts/CDNs/images, no `eval`**. Dynamic styles **must** use Svelte's `style:prop={value}` directive (applied via CSSOM, which CSP allows). Scoped `<style>` blocks in `.svelte` files are fine (Vite emits them to a CSS file). | `crates/telltale-api/src/ui.rs`. The e2e suite fails on any console error, so CSP violations fail CI. Fonts must be system fonts or self-hosted files in `public/` (count them in the budget). |
| 4 | **The UI uses only the public REST API** (`/api/v1/*`) through `src/lib/api.ts`. No new server endpoints are created for the UI alone. | The API is the product's contract for scripts and AI agents too (AGT-001..005). If you need data the API doesn't have, write it down as a request (§10); don't fake it. |
| 5 | **`src/lib/api-types.ts` is generated, never hand-edited.** Run `npm run types` (from `../docs/api/openapi.json`). | CI fails if it's stale. |
| 6 | **Hash routing** (`#/queries?client=…`). The server only serves `/`, `/assets/*`, `/favicon.svg`. Don't switch to history routing or add paths outside `public/`/`assets`. | `ui.rs` serves `index.html` only at `/`. |
| 7 | **Works at 360 px wide** with no horizontal page scroll (tables may scroll inside their own `.table-wrap`). | Tested (`works at phone width (360 px)`). |
| 8 | **Light and dark themes** from the same tokens; follows the system unless the user picks one (`data-theme` on `<html>`, remembered in `localStorage` with try/catch). | `app.css` `:root` tokens. |
| 9 | **Every chart has a table view** (the "Table" toggle in `Chart.svelte`). | `spec/07` §3 UX rule; tested. |
| 10 | **Accessibility basics:** real `<label>`s or `aria-label` on every input, buttons are `<button>`, dialogs have `role="dialog"`, `aria-modal`, Escape closes, `aria-current="page"` in nav, `aria-pressed`/`aria-selected` on toggles/tabs. `npm run check` (svelte-check a11y) must report **0 errors and 0 warnings**. | CI runs `npm run check`. |
| 11 | **Don't break the e2e selectors** (§7) without updating the tests in the same change. | CI `ui` job. |
| 12 | **Text uses Svelte's escaped bindings only.** Data (domain names, list lines, usernames) is untrusted. | Security (`spec/08` §6). |
| 13 | **No analytics, trackers, telemetry, or external requests** from the UI. | It's a privacy product. |

---

## 3. Running it

```sh
cd ui
npm ci
npm run dev            # http://localhost:5173, proxies /api and /metrics to TELLTALE_API (default http://127.0.0.1:8053)
npm run check          # svelte-check: types + a11y (must be clean)
npm run build          # dist/ + .gz files + size budget report
npm run types          # regenerate src/lib/api-types.ts after API changes
```

A server for `npm run dev`: from the repo root, `cargo build -p telltale` then run
`node ui/tests/e2e/server.mjs` (starts a throwaway server on `127.0.0.1:18054` with an inline
blocklist and a local record; then run dev with `TELLTALE_API=http://127.0.0.1:18054`). The
setup token is in `ui/.e2e/data/setup-token`. Generate traffic with
`dig @127.0.0.1 -p 15354 ads.e2e.test` (blocked) or `nas.e2e.test` (local record).

**Embedding:** release builds compile `ui/dist` into the binary (`cargo build -p telltale`
after `npm run build`). Debug builds read `ui/dist` from disk at request time, so with a debug
server running, `npm run build` plus a page reload is enough.

**End-to-end tests:**
```sh
cargo build -p telltale && npm run build
npx playwright install --with-deps --only-shell chromium   # once
npm run test:e2e                  # 8 tests; starts the real binary
SHOTS=1 npm run test:e2e          # also writes screenshots to test-results/shots/{page}-{light,dark}.png
```
On the owner's WSL machine (no sudo): Node is in `~/.local/node/bin`, and Chromium needs
`LD_LIBRARY_PATH=$HOME/.local/pwlibs/root/usr/lib/x86_64-linux-gnu`.

Use the screenshots to review your work visually in both themes before finishing.

---

## 4. Architecture and files

```
ui/
  index.html                 # shell: no inline script/style (CSP)
  vite.config.ts             # dev proxy, build to dist/, assetsInlineLimit 0
  scripts/postbuild.mjs      # gzip + 400 KiB budget gate
  public/favicon.svg
  src/
    main.ts                  # mounts App, imports app.css
    app.css                  # design tokens (light/dark) + global primitives (.card, .badge, tables, buttons, forms)
    App.svelte               # auth gate (loading / setup / login / app), header, nav, page switch, theme toggle
    lib/
      api.ts                 # typed fetch client; CSRF header; ApiError (problem+json); signed-out hook
      api-types.ts           # GENERATED from docs/api/openapi.json — do not edit
      session.svelte.ts      # $state session: loaded, setupRequired, user; refreshSession, signedIn, signOut, can(role)
      router.svelte.ts       # hash router: route.path, route.params (URLSearchParams); href(), navigate()
      poll.ts                # poll(fn, ms): runs while the tab is visible; returns stop()
      format.ts              # num, short, pct, ms (µs/ms/s), bytes, duration, ago, clock, dateTime, logTime
      components/
        Chart.svelte         # uPlot wrapper: stacked option, responsive width, theme-aware, Table toggle
        Kpi.svelte           # KPI tile (label, value, sub, tone)
        Drawer.svelte        # right-side dialog (Escape/backdrop close)
        ErrorNote.svelte     # renders ApiError detail + hint (role=alert)
        StatusBadge.svelte   # status/rcode/state → toned badge
        ExplainView.svelte   # renders an Explanation (client, block, matching rules ★, route)
        Logo.svelte
    pages/
      AuthShell.svelte, Login.svelte, Setup.svelte
      Dashboard.svelte, Queries.svelte, Explain.svelte, Clients.svelte, Groups.svelte,
      Lists.svelte, Upstreams.svelte, LocalDns.svelte, Settings.svelte
  tests/e2e/
    server.mjs               # starts the real binary with a test config
    dns.ts                   # sends UDP DNS queries
    1-ui.spec.ts             # the suite (serial, shared page)
    2-shots.spec.ts          # screenshots when SHOTS=1
```

**Patterns in use (keep them consistent):**
- Svelte 5 runes only (`$state`, `$derived`, `$effect`, `$props`). Typed state as
  `let x = $state<T | null>(null)` (the generic form; the annotated form narrows wrongly).
- Data loading: in `$effect`, either one-shot `api.x().then(...).catch(e => error = e)` or
  `return poll(load, ms)` for live pages (dashboard 15 s, 5 s at the 15-min range; lists 15 s;
  upstreams 10 s; query log 3 s only when "Auto-refresh" is on).
- Errors: every page shows `<ErrorNote {error} />`; `ApiError` carries `code`, `detail`, `hint`.
- Pages that read URL params must re-sync form state in an `$effect` on `route.params`
  (navigating between `#/queries?...` URLs does **not** remount the page; see `Queries.svelte`).
- Settings tabs come from `?tab=`, falling back to `account` when the tab isn't allowed.
- Role-based UI: `can('admin')` etc. The server enforces roles; the UI only hides what can't work.

**Server side you should know about (don't change without the owner):**
`crates/telltale-api/src/ui.rs` serves `dist/` with the CSP above, `X-Frame-Options: DENY`,
`nosniff`, `no-referrer`; `assets/*` are cached `immutable` (hashed names), `index.html`
`no-cache`; `.gz` variants are served when accepted.

---

## 5. Design system as it is today

**Tokens** (`src/app.css`, `:root`, redefined for dark under `prefers-color-scheme` and
`[data-theme='dark']`; keep all three blocks in sync):

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | `#f5f7fa` | `#0e151c` | page |
| `--surface` / `--surface-2` | `#fff` / `#eef2f6` | `#151f29` / `#1c2834` | cards / hovers, bars, code |
| `--border` | `#d9e0e8` | `#2a3846` | borders, grid lines |
| `--text` / `--muted` | `#17212b` / `#5b6b7b` | `#e4eaf0` / `#93a3b3` | text |
| `--brand` | `#123044` | `#0b1a25` | header bar |
| `--accent` / `--accent-text` | `#1f8f74` / `#fff` | `#2fb594` / `#06231b` | primary buttons, active states |
| `--link` | `#11698e` | `#6cc3e6` | links |
| `--ok` `--warn` `--bad` `--info` | green/amber/red/blue | lighter variants | badges, KPI tones, notices |
| `--s-cached` `--s-forwarded` `--s-blocked` `--s-local` `--s-other` | | | **status colors, used by charts (by CSS variable name)** |
| `--radius` 10px, `--gap` 16px, `--shadow`, `--mono` | | | |

Typography: system UI font stack, 14px base, 12–12.5px for labels/meta, 20px `h1`, 15px `h2`,
tabular numerals for numbers; monospace for domains, IPs, list lines, tokens.

**Primitives** (global classes): `.page` (grid with gap), `.page-head`, `.row`, `.grid-2`,
`.grid-3` (auto-fit responsive), `.card`, `.card-head`, `.muted`, `.small`, `.spacer`,
buttons (`button`, `.primary`, `.danger`, `.link`), `.seg` (segmented control using
`aria-pressed`), forms (`label.field`, `form.stack`), tables (`.table-wrap`, `th.num`/`td.num`,
`td.name`), `.badge` with tones `ok|bad|warn|info`, `.notice` with tones, `.empty`, `.sr-only`.

**Layout:** sticky dark header (brand, node name, theme toggle, user + role, Sign out); 200 px
left nav; content padded 20 px. Under 760 px: nav becomes a slide-over opened by **Menu** (☰),
node and user hide, content padding 12 px.

**Status semantics (consistent everywhere):**
`blocked` → bad/red, `cached` → ok/green, `forwarded` → info/blue, `local` → purple,
`stale`/`half_open`/`pending`/`NXDOMAIN` → warn, `servfail`/`refused`/`failed`/breaker `open` → bad.
Status names come from the API: `cached, forwarded, stale, local, special, blocked, refused,
rate_limited, malformed, servfail, dropped`.

---

## 6. Pages: purpose, data, current state

All data is from `/api/v1` (see `docs/api/openapi.json`; every operation has a description).
JSON is camelCase; units are in field names (`totalMs`, `ttlSeconds`, `*UnixSeconds`).

| Page (route) | API calls | What it shows now | Known weaknesses / ideas |
|---|---|---|---|
| **Setup** (gate when `setupRequired`) | `GET /auth/status`, `POST /auth/setup` | token + admin username + password ×2 | Plain; could explain where to find the token for Docker/K8s/Pi installs. |
| **Sign in** (gate) | `POST /auth/login` (401 `totp_required` → code step; recovery code alternative) | 1–2 step form | Fine; lockout (429) message is just the API detail. |
| **Dashboard** `#/` | `stats/summary`, `stats/timeseries` (second/minute/hour steps), `stats/top` ×3, `upstreams`, `stats/latency?by=stage|path` | range segmented control (15 min, 1 h, 24 h, 48 h, 7 d, 30 d); 6 KPI tiles; stacked "Queries by status" chart; "Where time goes" table; upstream share bars with breaker badge; "Upstream exchanges" chart; Top domains/blocked/clients lists linking into the query log | Biggest design opportunity. KPI tiles lack trend/sparkline and comparison to the previous period. "Where time goes" is a raw table (spec wants a stage breakdown chart). Upstream panel could show latency sparklines. Top lists' counts are "this hour" while the range control suggests otherwise (label it more clearly). Missing "nodes up" tile (cluster arrives later; don't fake it). |
| **Query log** `#/queries` | `GET /queries` (filters: `name`+`match`, `client`, `status` csv, `qtype`, `rcode`, `minLatencyMs`, `from`; cursor paging 100 rows), `GET /explain` | filter form + status chips (in URL), table with time/client/name/type/status+rcode/rule/time-taken bar, **Why?** drawer, "Older" pager, Auto-refresh toggle | Spec wants a virtualized table and a live tail (SSE arrives in T3.7; polling for now). Row density and scanning could improve (sticky header, hover row, copy-name action, clearer rule column). Filters take a lot of vertical space on phones (consider a collapsible filter bar with chips summarizing active filters). |
| **Explain** `#/explain` | `GET /explain?name&client&qtype` | form + `ExplainView` | Could link from anywhere a domain appears. |
| **Clients** `#/clients` | `GET /clients`, `stats/top?kind=clients&limit=100` | "Seen this hour" + configured devices | Spec wants per-client profile pages (traffic, top domains via `stats/top?kind=domains&client=IP`, latency): this is buildable now with existing API. |
| **Groups** `#/groups` | `GET /groups` | table | Read-only until the config API exists. |
| **Lists** `#/lists` | `GET /lists`, `GET /system/info` | table: state, names used, lines, size, checked/changed | Could visualize contribution (names used vs lines) and highlight failing/stale lists. |
| **Upstreams** `#/upstreams` | `GET /upstreams`, `stats/latency?by=upstream` | table: endpoint, groups, breaker, requests, failures %, smoothed, p50, p99 | Spec wants sparklines (could use `stats/timeseries` upstream totals; per-upstream series don't exist in the API yet). |
| **Local DNS** `#/local-dns` | none | explanatory note + example | Waits for the config API. |
| **Settings** `#/settings?tab=` | `auth/me`, `auth/password`, `auth/totp/*`, `tokens`, `users`, `system/info` | tabs: Account (password, two-factor), API tokens (create once, revoke), Users (admin: role, 2FA reset, Basic opt-in, disable, two-click delete), System | TOTP shows an `otpauth://` link + key (no QR library, by budget choice; a tiny dependency-free QR encoder would be acceptable if < ~8 KiB gz). |

---

## 7. Test contract: selectors you must keep (or update the tests in the same change)

`tests/e2e/1-ui.spec.ts` relies on these **accessible names and selectors**. Renaming visible
text, labels, or roles below breaks CI.

- **Headings:** `Welcome to TelltaleDNS`, `Dashboard`, `Query log`, `Sign in`, `Settings`.
- **Labels (inputs):** `Setup token`, `Admin username`, `Password (at least 10 characters)`,
  `Repeat password`, `Username`, `Password`, `Name` (query log and explain), `Token name`.
  Note: in Settings → Users, the add-user inputs are `aria-label="Username"` / `"Password"`.
- **Buttons:** `Create admin and sign in`, `Sign in`, `Sign out`, `Table` (chart toggle),
  `Why?`, the status chip `local` (exact), `Explain`, `Create token`, `Revoke`, `Add` (exact),
  `Menu` (mobile nav).
- **Links:** top-list entries are links whose name is the domain (`ads.e2e.test`); nav link
  `Dashboard`.
- **Roles:** `dialog` (the Why? drawer; Escape closes it), `alert` (ErrorNote; must contain the
  API's `wrong username or password`), `tab` with `aria-selected` for `Account`, `API tokens`,
  `Users` (absent for viewers).
- **CSS hooks:** `table.log tbody tr` (query rows; a row contains the status text and list
  name), `.table-view table` (chart table view), `.explain` (ExplainView root), `code.token`
  (the newly created token), `main`, `main table`.
- **Texts:** `Queries by status` (chart title), `No tokens yet.`.
- **Behaviors:** URL gets `status=local` after pressing the chip; after sign-in the current hash
  route is kept; a viewer opening `?tab=users` lands on Account; no horizontal overflow at
  360 px; no console errors at all.

If you restructure a page, prefer keeping these names and adding new ones. If a change truly
needs different names, update the spec file in the same commit and run the suite.

---

## 8. How to make changes safely

1. Read `AGENTS.md` (repo root). Relevant rules: spec-driven, requirement IDs in comments
   (`// REQ: API-005`), no new runtime dependency without justification, docs updated, and
   **don't silently invent behavior**: record design decisions that change conventions as a
   new ADR in `spec/11-decisions.md` with status `Proposed`.
2. Keep changes incremental (one page or one component system per commit), each one green.
3. Before finishing every change:
   ```sh
   npm run check              # 0 errors, 0 warnings
   npm run build              # under budget; note the new size in your report
   cargo build -p telltale && npm run test:e2e        # all pass
   SHOTS=1 npm run test:e2e   # look at the light and dark screenshots
   ```
   Also check 360 px by eye (Chrome devtools or a Playwright viewport).
4. If you change user-visible behavior, update `docs/running.md` (section "Web UI") and, if it's
   a headline feature, `site/how-it-works.html` (then `python3 site/build.py --check`).
5. Commit messages: `feat(ui): ... [API-005]` with the trailers the owner requires (see the most
   recent commits in `git log` and copy their `Co-Authored-By` / `Claude-Session` format).
6. Never commit `ui/dist`, `ui/.e2e`, `ui/test-results`, `ui/node_modules` (gitignored).

**Things not to change** (ask the owner first): the API client contract and generated types,
the routing scheme, the server's CSP and caching (`ui.rs`), the stack, the status vocabulary and
color semantics (they match Grafana and the docs), the auth flow (cookie + `X-CSRF-Token` sent
by `api.ts` on every non-GET; tokens are shown once).

---

## 9. Where design help is most valuable (suggested backlog, in priority order)

1. **Dashboard visual hierarchy:** KPI tiles with sparklines and deltas vs. the previous period
   (fetch `stats/summary` for the previous window); a proper "where time goes" stage chart;
   clearer "this hour" vs. range labeling; upstream health panel with mini bars.
2. **Query log ergonomics:** compact/comfortable density toggle, sticky table header, filter
   bar that collapses on phones into active-filter chips, better empty states, a row detail
   view (all fields from `QueryRow`), copy actions, keyboard navigation (j/k, Enter = Why?).
   Consider windowed rendering for 1,000+ loaded rows (stay dependency-free).
3. **Explain readability:** make the deciding rule unmistakable, group rules by tier, show
   "why not blocked" just as clearly as "why blocked".
4. **Client profile page** `#/clients/<ip>`: built from existing endpoints (top domains for a
   client, query log filtered by client, latency by client is *not* in the API yet).
5. **Consistent component set:** page header with actions, empty state, skeleton loading,
   toast for success messages (currently inline notices), confirm pattern (currently two-click
   arm for user delete).
6. **Polish:** focus styles, motion (respect `prefers-reduced-motion`; transitions must not
   inject `<style>` at runtime; CSS transitions in stylesheets are fine), iconography (inline
   SVG components only; no icon fonts from CDNs), print-free.

**Out of scope for the UI agent** (needs backend work first; list them as requests instead):
editing lists/groups/upstreams/local records and allow/block quick actions (configuration API),
live tail (SSE, T3.7), OIDC sign-in (T3.6), audit log (T3.8), cluster page and scope selector
(M5), analytics (new domains, DGA, anomalies), per-upstream time series, past-hour top lists.

---

## 10. API facts that matter for design

- `GET /stats/timeseries?step=second|minute|hour|day&from=-1h`: omits empty buckets (the
  dashboard fills gaps, see `dense()` in `Dashboard.svelte`). Second = last 15 min; minute =
  48 h live + 7 days stored; hour = 400 days; day = forever.
- `GET /stats/top?kind=domains|blocked|nxdomain|clients&limit=&hour=current|previous&client=`:
  per-hour Space-Saving sketches; `count` is an upper bound, `errorBound` the slack.
- `GET /stats/latency?by=path|qtype|upstream|stage&hour=`: p50/p90/p99/p999/max in ms (no p95).
- `GET /stats/summary?from=`: totals over a range, plus this hour's active clients and latency.
- `GET /queries`: newest first, `nextCursor` for older pages, `scanned` stats.
- `GET /explain`: `outcome` is `refused|special|local|blocked|allowed|resolved`; `filter.rules`
  in precedence order with `winner` and `enabled`.
- Errors: RFC 9457 problem+json with `code` (`unauthorized`, `totp_required`, `forbidden`,
  `csrf_rejected`, `conflict`, `rate_limited`, `invalid_parameter`, `not_found`,
  `unavailable`, `internal`, `unsupported_scope`) and an actionable `hint`. Show the hint.
- Auth: `GET /auth/status` (public) tells the UI whether setup is required and who is signed
  in, including the CSRF token. A 401 on a data call means the session ended: `api.ts` calls
  the signed-out hook and the app shows Sign in.
- Roles: `viewer` < `operator` < `admin`; `/users` is admin-only (403 otherwise).

If you need something the API doesn't offer, add it to a "UI requests" list in your final
report (endpoint, fields, why) rather than working around it.
