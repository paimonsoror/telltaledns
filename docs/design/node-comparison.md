# Node odd-one-out comparison: design notes (T14.2)

**Requirement:** OBS-028 (new). **ADR:** ADR-128 (new, Proposed). **Spec section:** add `07` §3 row
*Cluster → Compare* and a paragraph in `06` §8.3. **Owner request:** 2026-10-16 ("something seems odd
with that node").

## 1. What it is, in one paragraph
A side-by-side of every node over the same window — answered, SERVFAIL ratio, slow ratio, cache
from-cache share, upstream failure share, p50/p99, q/s — with the node that deviates from the others
marked, the hour it started deviating named, and the statistics honest about small denominators. It
turns "the Pi looks worse" into either "it has the same bad count on a tenth of the traffic" or "it
really is failing more, since 15:00".

## 2. Non-goals
- Replacing the Cluster page's membership/sync view; this is a *statistics* comparison.
- Any machine learning. Robust statistics only (median and MAD), deterministic, explainable.
- Comparing nodes across different windows.

## 3. Data (decision)
Everything exists:
- Per-node buckets: `GET /stats/timeseries?scope=node:<id>` (minute for ≤ 48 h, hour beyond); the
  primary holds pods' minutes in `shipped_minute`, replicas answer for themselves via federation.
- Per-node latency percentiles: `hour_latency` (`p50..max` per key per hour) via `GET /stats/latency`.
- Node list: `GET /api/v1/cluster` (`nodeId`, `site`, `pod`, `thisNode`, heartbeat).

No new storage. One new federated read that fans out and **computes on the entry node**:
`Read::NodeCompare` → per node: the sums over the window and the per-bucket series for the ratios.

### Deviation score (decision)
For each metric *m* and node *i*, `x_i` is the window ratio (e.g. SERVFAIL / answered). With *n* nodes:
- `n ≥ 3`: robust z = (x_i − median) / (1.4826 × MAD), with MAD floored at the metric's floor
  (ratios: 0.0005; latency µs: 10 % of median). Flag `|z| ≥ 3` as *odd*.
- `n = 2` (the owner's cluster): no median is meaningful. Compare the **Wilson 95 % intervals** of the
  two ratios; flag *odd* only when they don't overlap. For latency compare p99s with the 10 % floor.
- Always attach the evidence: `observed`, `others` (median or the other node), `spread`, `answered`.
  Say "same bad count, smaller base" when `bad_i ≈ bad_others` and `answered_i < answered_others / 3`.
- **Since when:** walk the per-bucket ratio series backwards from `to`; the first bucket where the
  node's cumulative-from-there ratio stops being odd marks `oddSince`. One pass, O(buckets).

## 4. API (decision)
`GET /api/v1/cluster/compare?from&to&step=minute|hour` (default last 24 h, hour step beyond 48 h).
```json
{
  "from": "...", "to": "...", "nodes": [
    { "nodeId": "528c…", "label": "pi", "answered": 38068, "qps": 0.44,
      "servfailPct": 0.008, "slowPct": 0.003, "fromCachePct": 63.1, "upstreamFailPct": 1.9,
      "p50Us": 32, "p99Us": 86000, "series": { "start": [...], "servfailPct": [...], "slowPct": [...] } }
  ],
  "findings": [
    { "metric": "servfailPct", "nodeId": "528c…", "level": "note",
      "observed": 0.008, "others": 0.005, "spread": 0.0005, "oddSince": null,
      "detail": "same bad count as the pods (15 vs 14) on a tenth of the traffic" }
  ],
  "missingNodes": []
}
```
`level` ∈ `odd` | `note` (small-denominator explanation) — never "error". MCP `compare_nodes(window)`.
Metric: none new (Prometheus users do this with `by (node)` already; add a Grafana row, §6).

## 5. UI (decision)
- Cluster page, new tab **Compare** (TabPanel; a tab never hides trouble — ADR-121: the tab label
  carries a dot when any finding is `odd`).
- Top: a **small-multiples grid** — one row per metric, one cell per node, each cell a sparkline of the
  ratio with the window's value as the big number. The odd cell has an outlined border in the
  `--s-warn` token and a one-line finding under it; a `note` cell gets the grey "smaller base" line.
- Window picker (1 h, 6 h, 24 h, 7 d, 30 d) shared with the dashboard's `remembered()` pattern.
- "Open in dashboard" per node sets `dashboard.scope = node:<id>`.
- Table view: the same numbers as a table with intervals shown (`0.008 % (0.004–0.02)`).
- Phone: one metric at a time, nodes as cards.

## 6. Grafana
New row *Nodes*: time series of `servfail` and `slow` ratios `by (node)`, and a table of window ratios
`by (node)` with the smallest `answered` highlighted via a threshold on count, not ratio.

## 7. Acceptance criteria
1. Fixture, 3 nodes × 24 h: node C has 2 % SERVFAIL from 15:00, A and B 0.05 % → one `odd` finding
   on C, `oddSince = 15:00`; before 15:00 the same fixture yields no finding.
2. Fixture, 2 nodes: Pi 15 bad / 38k, pods 14 bad / 300k → no `odd`, one `note` with the "same bad
   count… smaller base" detail; Pi 150 bad / 38k → `odd` (intervals don't overlap).
3. Deterministic: the same fixture twice gives byte-identical JSON (fixed float formatting).
4. A missing node → `missingNodes`, findings computed over the rest; with one node reporting, no
   findings and the UI says "one node; nothing to compare".
5. Playwright `obs_028 node compare`: the tab shows the dot, the odd cell is outlined, table view works.
6. Docs: `running.md` *Cluster* → "Compare nodes"; site page; demo screenshot; OpenAPI/MCP regenerated.

## 8. Open
- Should an `odd` finding also become a health reason (`node_deviates`, degraded) and an alert rule?
  Default **no** (it is a lens, not a condition) until the owner has watched it for a week.

## 9. Decided at the start of the task (owner: accept all defaults, 2026-10-16)
Recorded in ADR-128:
- **No new federated read.** The entry node reads each node's buckets through the existing scoped
  timeseries read (`node:<id>`), all at once, and computes there; older peers answer it too.
- **p50/p99 from the latency histograms** (OBS-030, minute and hour buckets) rather than
  `hour_latency`; a node with under 100 answers isn't compared on latency; `partial` when a node
  has answers but no histograms (an older build).
- **Leave-one-out with three or more nodes:** a node is measured against the median and MAD of the
  *other* nodes, and is odd only when, besides |z| ≥ 3, its own Wilson interval leaves out that
  median (so a handful of answers can't make it odd).
- **Two nodes:** odd needs non-overlapping Wilson intervals *and* the same floored threshold
  (|Δ| ≥ 3 × 1.4826 × 0.0005, 0.22 percentage points), and only the worse node is odd (higher
  SERVFAIL, slow, upstream failure share, or latency; lower from-cache share). Without the floor the
  §7 AC 2 first case (15 / 38k vs 14 / 300k) would be odd: those intervals don't overlap.
- **The note:** not odd, higher than the others, a bad count "about the same" (within 3, or a third
  of the larger) on under a third of the others' base. SERVFAIL, slow, and upstream failures only.
- **Since when:** the change point of the node's cumulative excess over the others' pooled rate,
  bucket by bucket (the latest minimum of the running sum), kept only when the node is still odd
  from there; absent when the excess runs through the whole window, and for latency. (Walking back
  until the suffix stops being odd would land on the window's start whenever the window is odd.)
- Witness nodes aren't listed (they don't answer DNS); a standalone node is one node, "nothing to
  compare". Sparklines carry at most 240 points (buckets summed into spans). Agents read it with
  `analytics:read`; MCP `compare_nodes(window)`. The Cluster page reads it every 60 s on every tab so
  the **Compare** tab's count can say "1 odd". Not a health reason or an alert (§8's default).
