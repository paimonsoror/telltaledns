# UI visual refresh: design notes (T6.8)

Owner request 2026-10-04: make the UI look more modern and less like a hard-edged classic admin
panel, **keeping the current color scheme**. The reference was a commercial admin-dashboard
template, so it isn't stored here. We borrow these general patterns from it, not its assets or code:

## Shell
- **Sidebar:** a darker sidebar with small upper-case section labels (e.g. *Monitor*, *Filtering*,
  *Settings*), each item an icon plus a label, and count badges as small rounded pills (e.g.
  anomalies, lists with errors). The active item is a filled rounded pill, not an underline. The
  sidebar collapses to icons on medium widths and becomes a drawer on phones (as today).
- **Top bar:** light and borderless. It holds the menu toggle, search (names or clients, opening
  the query log), the theme toggle, an alerts bell with a count, and the user menu with avatar
  initials and role.
- **Page header:** the title on the left and breadcrumbs on the right.

## Surfaces
- A light grey canvas with white cards (dark mode: two steps of our dark surface). Cards have about
  10 px radius, a soft shadow, and no hard 1 px borders.
- **Card header:** the title with a short accent bar to its left, and actions ("View all",
  "Export") as soft tinted pill buttons on the right, with a hairline divider under the header.
- More space between and inside cards. Medium-weight headings and big tabular figures for numbers.

## Data
- **KPI tiles:** label, big number, and the change against the previous period (green up or red
  down arrow, consistent meaning per metric: more blocking isn't "bad"). Some tiles get an inline
  sparkline, others a rounded accent icon square.
- **Charts:** rounded bar ends, smooth lines, light gridlines, and a dot legend above the plot.
  Bars and lines can mix (e.g. queries as bars, p90 latency as a line).
- **Donut** with the total in the center and a breakdown grid below it (e.g. answers by status,
  queries by protocol).
- **Small radial progress rings** for ratios (cache hit rate, blocked share).
- **Tables:** roomier rows, icons in the first column (client type, list source), inline
  progress bars for shares, and no zebra stripes.

## Constraints
- Our color tokens stay; only shape, depth, spacing, and type change, all in the shared tokens
  and components so light and dark follow.
- WCAG AA contrast in both themes. Charts keep their table views (the existing "Table" toggle).
- Bundle ≤ 400 KiB gzipped. No new UI framework or chart library unless one is measured to
  fit; the current Svelte components get restyled.
- The shots suite regenerates before/after screenshots of every page, and the site uses them.

## What shipped (2026-10-05)
- **Pass 1:** the shell (sectioned dark sidebar, top bar with search, avatar and role), shared
  tokens (12 px radius, soft shadow, borderless cards, accent-bar titles, pill controls, roomier
  tables), and KPI tiles with changes against the previous period and sparklines.
- **Pass 2:**
  - charts with smooth lines, gradient fills, rounded bars (upstream exchanges), light gridlines,
    and a dot legend above the plot;
  - an "Answers by status" donut with a breakdown grid;
  - progress rings on the Blocked and Cache hits tiles;
  - inline share bars in the Lists and Upstreams tables (`ShareBar`);
  - group cards with the title bar in the group's color;
  - sidebar count badges (anomalies in the last day, lists failing to download).
- **Contrast:** text on tinted chips, pills, and the active nav pill uses `--accent-strong`,
  `--ok-strong`, `--bad-strong`, and `--warn-strong` (dark mode keeps its colors), so every
  pair is at least 4.5:1 in both themes. That also fixes the light-theme "ok" and "warn"
  badges, which were below AA before the refresh.
- **Not done:**
  - breadcrumbs, because every page is one level deep;
  - an alerts bell, because the sidebar badges cover it;
  - icons in table first columns.
- **Review:** `SHOTS=1 npx playwright test` writes the site pictures to `site/assets/shots/` and
  every other page (plus a phone view) to `ui/.shots/`, which is git-ignored.
