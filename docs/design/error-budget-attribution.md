# Error-budget attribution ("Who spent my budget?"): design notes (T14.1)

**Requirement:** OBS-027 (new). **ADR:** ADR-127 (new, Proposed). **Spec section:** add `06` §8.3.
**Owner request:** 2026-10-16, after asking why the Pi had overspent its budget and getting the
answer from a script instead of the product.

## 1. What it is, in one paragraph
The Service level card (OBS-016) says *how much* budget is left and *how fast* it burns. It never says
*who* spent it, *on what*, or *when*. Attribution adds a drill-down: for each objective, the bad
answers over the budget window broken down by client, name, path/status, response code, upstream,
node, and hour, plus a timeline of the budget's consumption across the window. Opening it answers
today's question in one click: "10 of 15 bad answers are one PTR name from one laptop; the rest of the
deficit is from before 10-13".

## 2. Non-goals
- Changing what counts as bad (`telltale_api::slo::tally` stays the one definition).
- Root-causing upstream failures (that is the upstream truth checks, OBS-019).
- A per-query SLO log. Attribution is counts over bounded top-K, not a second query log.

## 3. Data (decision)
Two layers, because the window (30 d) outlives the query log (7 d on the Pi):

1. **Exact timeline from buckets.** `TimeBucket.by_rcode["SERVFAIL"]` and `TimeBucket.slow` per hour
   over `window_days` (hour buckets, `Step::Hour`, federated per node). This gives "budget spent per
   day/hour, per node" for the whole window with nothing new stored.
2. **Attribution from new hourly top lists.** The aggregator keeps, per hour, Space-Saving top-K
   sketches (`telltale_telemetry::topk`, reuse) of **bad answers only**, keyed four ways, and flushes
   them into `hour_top` with new `kind` strings:
   - `servfail_name`, `servfail_client`, `slow_name`, `slow_client` — 32 entries each (20 reported).
   - Keys for names follow the privacy level the way `domains` does (hash at ≥ 1; no `*_client` rows
     at ≥ 2). Probe names (`Record::is_probe`) and excluded queries never reach this point already.
   - Cost: only bad events touch the sketches (0.04 % of traffic on the Pi); four 32-entry Space-Saving
     tables per hour. Include the number in the bench report.
   **Path/status** and **rcode** dimensions: the buckets have `by_status` and `by_rcode` as marginals
   but don't cross status with "bad", so add two small joint counters to `TimeBucket`:
   `servfail_by_status: BTreeMap<String,u32>` and `slow_by_status: BTreeMap<String,u32>` (≤ 12 keys
   each, `#[serde(default)]`, stored in the tagged section with `slow`; T14.6 adds `status_rcode`,
   which gives the rcode split of every status — share the serialization code).
   **Upstream** (decision, owner 2026-10-16): exact, not a top list — upstream cardinality is bounded
   by configuration, so two more maps on `TimeBucket` in the same section:
   `servfail_by_upstream: BTreeMap<String,u32>` and `slow_by_upstream: BTreeMap<String,u32>`, keyed by
   the upstream name the event already carries (the one `telltale_upstream_requests_total{upstream}`
   uses). A bad answer with no upstream on the event (a cache-served SERVFAIL whose background refresh
   isn't attributed, a local or special answer that was slow) counts under `none`. One map increment
   per *bad* event only; exact over the whole 400-day window; no error bound. For the availability
   objective this is the dimension that turns the view into an action (ADR-098's DoT handshake
   failures, the old AXFR SERVFAILs were both upstream stories). The Upstreams page's
   per-upstream health (`api.upstreams`) stays where it is; the attribution links to it.

Why hour_top and not the query log? The log answers "which rows" for 7 days; attribution needs
"which keys" for 30. Space-Saving is what the top lists already use, it is bounded, and older builds
ignore unknown kinds. The query log is still linked from every row (see §5) for the rows it has.

## 4. API (decision)
`GET /api/v1/stats/slo/attribution?objective=availability|latency&from&to&scope&limit`
(default window: the objective's `window_days`; `limit` ≤ 20; federated `Read::SloAttribution`).
Response (units in names, AGT-001):
```json
{
  "objective": "availability", "from": "...", "to": "...",
  "budget": { "allowedBad": 1140, "bad": 412, "remainingPct": 63.9, "answered": 1140000 },
  "timeline": [ { "start": "...", "answered": 38000, "bad": 15, "budgetSpentPct": 1.3, "node": "pi" } ],
  "byClient": [ { "key": "192.168.10.185", "name": "PaimonLaptop", "bad": 13, "sharePct": 86.7 } ],
  "byName":   [ { "key": "247.73.85.170.in-addr.arpa", "bad": 10, "sharePct": 66.7 } ],
  "byStatus": [ { "key": "refreshed", "bad": 8 }, { "key": "forwarded", "bad": 4 }, { "key": "servfail", "bad": 3 } ],
  "byUpstream": [ { "key": "quad9-2", "bad": 3, "exact": true }, { "key": "none", "bad": 12, "exact": true } ],
  "byRcode":  [ ... ],  "byNode": [ ... ],
  "coverage": { "topListsFromHours": 720, "approximate": true },
  "missingNodes": []
}
```
`timeline` is per node per hour (or per day when the window > 7 d; the client decides the grain by
`step=hour|day`). `sharePct` is of the window's bad answers. `coverage.approximate` is true because
Space-Saving counts carry an error bound (`hour_top.error`); surface the bound as `errorMax` on each
row rather than hiding it. `byStatus`, `byRcode`, `byUpstream`, `byNode`, and `timeline` are exact
(`exact: true`); only `byClient` and `byName` are approximate.

MCP tool `slo_attribution(objective, window, scope)` — thin wrapper, same caps; tool description says
"shows who and what consumed the error budget; counts are approximate top lists".

Metrics: none new (Prometheus already has `telltale_responses_total{rcode}` and the latency
histogram; per-name/per-client series are deliberately not exported — cardinality).

## 5. UI (decision)
- The `SloCard` (Advanced view, Dashboard) gets a *Who spent it?* link per objective →
  `#/analyze?tab=budget&objective=…` (Analyze page, new tab; it is already the "why" page).
- Layout, top to bottom: (1) a **budget burn-down** line over the window (remaining % per hour/day,
  one line per node, markers from T14.7 overlaid when present); (2) five **bar lists** in a wrapping
  grid, stacked on phones: clients, names, upstreams, status, rcode — bars sized by share; the two
  approximate lists show the error bound as a faint extension, the exact ones don't; an upstream row
  links to that upstream's drawer on the Upstreams page; (3) **nodes** as small multiples of the same
  burn-down.
- Every client/name row links to the Query log with the filters that reproduce it where the log still
  has the rows: `#/queries?client=…&rcode=SERVFAIL&from=…` (availability) or `&minMs=250` (latency).
  Rows whose hours are older than the log's retention show the link disabled with the tooltip
  "older than the query log keeps".
- Copy for the empty state (budget untouched): "Nothing spent this window." For the
  small-denominator case (answered < 10 × allowedBad): a one-line note "this node answers few queries,
  so one failure moves its ratio a lot" — same wording T14.2 uses.
- Table view for every list (spec `07` §3). Help topic `slo-attribution`.

## 6. Grafana
Add to the *Service level* row: a stat "bad answers by rcode (window)" and a bar gauge by `node`;
nothing per name/client (not exported).

## 7. Acceptance criteria
1. Replay fixture: 10,000 answered queries over 48 h where client A asks name X 10 times → SERVFAIL
   (status `refreshed`), client B gets 3 SERVFAILs on three names, and 2 answers exceed 250 ms. The
   availability attribution reports `byClient` A 10 (76.9 %), B 3; `byName` X 10; `byStatus`
   refreshed 10, …; `budget.bad` 13; the latency attribution reports 2 bad. `timeline` sums equal the
   bucket SERVFAIL totals exactly.
   Upstream: in the same fixture 3 of B's SERVFAILs came from `quad9-2` and A's 10 were cache-served
   with no upstream on the event → `byUpstream` is `quad9-2: 3, none: 10`, both `exact: true`, and the
   sum equals `budget.bad`.
2. A node on the previous build (no `servfail_*` kinds, no joint counters) in the cluster: the read
   still answers for that node's timeline from `by_rcode`/`slow`, lists it under `coverage` as
   `partialNodes`, and never errors.
3. Privacy level 1: `byName` keys are hashes and the UI shows "N names (hidden by privacy level)";
   level 2: no `byClient`; level 3: only `timeline`.
4. Federation: a three-node fixture where one node is down → `missingNodes` names it, the other two
   are summed; the guard test for `Federated` coverage passes.
5. `make bench-smoke` within budget; the aggregator micro-bench shows the sketches are touched only
   on bad events (assert via a counter in the test build).
6. Playwright `obs_027 budget attribution`: the card link opens the tab; a bar row's link opens the
   Query log pre-filtered; table view toggles.
7. OpenAPI and MCP JSON regenerated; `docs/running.md` *Service level* section gains "Who spent it?";
   site monitoring page updated; demo screenshot.

## 8. Open
- Whether a `refreshed` answer that is SERVFAIL should be cached at all is a *separate* correctness
  question (today's finding). Don't fix it in this task; report it.

## 9. Decided at the start of the task (owner, 2026-10-16)
1. `slow_by_rcode` is added to the bucket's bad-answer maps, so the latency objective has an
   exact rcode split (availability's is SERVFAIL by definition).
2. A resolver pod that isn't live counts from the primary's shipped minutes (7 days) under its own
   name, and is listed in `coverage.partialNodes` (its client and name lists went with it).
3. The current hour, and the previous one until it's stored, come from the aggregator's memory.
4. Statuses are stored by label (`refreshed`, `forwarded`, ...), upstreams by name.
