# Query flow (Sankey): design notes (T14.6)

**Requirement:** OBS-032 (new). **ADR:** ADR-132 (new, Proposed). **Spec section:** `07` §3 row
*Flow*; `06` §3 note on the joint counters. **Owner request:** 2026-10-16.

## 1. What it is, in one paragraph
One diagram of where queries go: **groups → decision → upstream → outcome**, with band width the
count and a red tint where the outcome is SERVFAIL. The upstream stage is only entered by statuses
that asked one (`forwarded`, `refreshed`, `stale` when a refresh ran); the rest skip it. Decision is the recorded status (`cached`, `refreshed`,
`stale`, `blocked`, `local`, `special`, `forwarded`, `refused`, `ratelimited`, `servfail`, ...);
outcome is the response code. Toggle to one device. It is the Dynatrace service-flow picture for a
resolver: "63 % from cache, 4 % blocked, 2 % of forwarded answers fail" as a shape.

## 2. Non-goals
- Any join the buckets don't have. A Sankey never splits a band proportionally; every link is a
  counter that was incremented for exactly that pair (§3).
- Per-name flows (the treemap and the heatmap own names).
- A dependency on `d3-sankey`. Three fixed stages make the layout trivial (§5).

## 3. Data (decision)
`TimeBucket` has `by_group`, `by_status`, `by_rcode`, `blocked_by_group` — marginals, not joints. Add
two bounded joint maps, updated by the aggregator per drained event (two map increments), serialized
in the tagged section with `slow`, `#[serde(default)]`:
- `group_status: BTreeMap<String, u32>` keyed `"<group>/<status>"` — ≤ groups × ~12 statuses.
- `status_rcode: BTreeMap<String, u32>` keyed `"<status>/<rcode>"` — ≤ ~12 × 6.
- `status_upstream: BTreeMap<String, u32>` keyed `"<status>/<upstream>"` and
  `upstream_rcode: BTreeMap<String, u32>` keyed `"<upstream>/<rcode>"` — upstream cardinality is
  bounded by configuration; events without an upstream on them don't touch these maps (**decision,
  owner 2026-10-16:** stage 4 is in v1; it uses the same event field T14.1's `servfail_by_upstream`
  reads, so land T14.1 first and share the accessor).
Hour buckets sum them. Four maps, at most ~100 keys in total on a two-upstream network. `by_group` is "empty for buckets read from rollups" today (model comment) —
**decision:** persist `group_status` in rollups so the flow works beyond 48 h; the Dashboard's
*traffic by group* chart may then also read it (report that as a follow-up, don't change the chart in
this task). Keys use the group's name as the event records it; the UI maps renamed groups by name only.

For the **device** toggle: a device's flow over the window needs per-client joints, which don't exist
and won't. **Decision:** device mode reads the query log for that client (`GET /queries?client=…`
with the existing column reader; bloom-prunable by `client_ref`), bounded to the last 24 h and 200k
rows, and labels the diagram "from the query log, last 24 h". Cluster mode is always from buckets.

## 4. API (decision)
`GET /api/v1/stats/flow?from&to&scope&client=` →
```json
{ "from": "...", "to": "...", "source": "buckets|querylog",
  "stages": ["group", "status", "upstream", "rcode"],
  "nodes": [ { "stage": 0, "id": "kids", "label": "Kids", "count": 12000 }, { "stage": 1, "id": "cached", ... }, { "stage": 2, "id": "quad9-1", ... } ],
  "links": [ { "from": "kids", "to": "cached", "count": 8000 }, { "from": "cached", "to": "NOERROR", "count": 7900 },
             { "from": "forwarded", "to": "quad9-1", "count": 1200 }, { "from": "quad9-1", "to": "SERVFAIL", "count": 40 } ],
  "truncated": false, "missingNodes": [] }
```
Counts are exact (bucket sums). A link may skip a stage: statuses that asked no upstream link
straight from stage 1 to stage 3 (from `status_rcode`); statuses that did go through stage 2
(`status_upstream` then `upstream_rcode`). Statuses that never reach an rcode (`dropped`) end at
stage 1 and are listed in `nodes` with no outgoing link; the UI draws them as a dead end. Federated `Read::Flow`
summing links by key. Privacy: no names involved; at ≥ 2 the `client` parameter is refused.
MCP `query_flow(window, scope, client?)` — thin wrapper. Metrics: none new.

## 5. UI (decision)
- New page **Flow** in the Monitor section (`#/flow`), icon `flow`, after Heatmap. Window picker
  (1 h, 24 h, 7 d, 30 d), scope (as the dashboard), device picker (`ClientChip`), and a *hide < 0.5 %*
  toggle (default on) that folds small links into an "other" node per stage.
- `ui/src/lib/sankey.ts`: pure layout. Four columns at fixed x; within a column, nodes stacked by
  count desc with a 6 px gap; link heights proportional to count; a link is a filled path of two cubic
  Béziers between its source and target offsets. A stage-skipping link (status → rcode) is drawn
  through an invisible pass-through slot in column 3 so it never crosses the upstream nodes. Order links at each node by the other end's position
  to minimise crossings (sorting, no iteration). Unit-test the layout (heights sum, offsets monotonic).
- SVG. Node colours: stage 1 uses the existing status tokens (`--s-cached`, `--s-blocked`, ...); stage
  0 a neutral ink; stage 2 `NOERROR` neutral, `NXDOMAIN` muted, `SERVFAIL`/`REFUSED` `--s-error`.
  Links take the source node's colour at 35 % opacity; a link into `SERVFAIL` is tinted `--s-error`.
  Hover a link: "Kids → cached: 8,000 (66.7 % of Kids)"; hover a node: its in/out totals. Click
  `blocked` → Lists page; an upstream node → its drawer on the Upstreams page; a group → Groups; an
  rcode → Query log filtered.
- Labels inside the band when it is ≥ 14 px tall, otherwise beside the node; small nodes get a
  leader line. Phone: stages become rows (top-to-bottom flow), same layout code with axes swapped.
- Table view: the links table (from, to, count, share). Change markers don't apply (no time axis).
- Live mode (toggle): the 1 h window refreshes every 10 s; animate band heights with a 300 ms CSS
  transition unless `prefers-reduced-motion`.

## 6. Grafana
No Sankey in core Grafana; add nothing. `docs/monitoring` can mention the community Sankey panel over
`telltale_queries_total{status}` / `telltale_responses_total{rcode}` as marginals only.

## 7. Acceptance criteria
1. Fixture: 1,000 events over two groups and two upstreams → `group_status` and `status_rcode` sums
   each equal 1,000; `status_upstream` and `upstream_rcode` sums each equal the forwarded-path count;
   `links` out of every stage-0 node equal `by_group`; every stage-1 and stage-2 node's in equals its
   out plus dead-ends (`dropped`); 40 SERVFAILs from `quad9-1` appear as exactly that link. Old-build buckets (no joints) → `source: "buckets"`, `partialNodes` listed,
   the diagram draws what it has.
2. Device mode: a client with 300 rows yesterday → `source: "querylog"`, link sums 300; a client with
   250k rows → `truncated: true` and the UI says so.
3. Layout test: for random inputs, column heights equal the total, no overlapping nodes, link offsets
   within their nodes.
4. Bench: two map increments per event, four on the forwarded path (BTreeMaps with ≤ ~100 keys in
   total) within the aggregator budget;
   `make bench-smoke` green; minute-bucket size growth reported.
5. Playwright `obs_032 flow`: the page renders 4 stages; hovering a link shows the share; clicking
   `blocked` navigates to Lists; phone layout stacks; table view; both themes.
6. Docs: `running.md` *Flow*; site monitoring page; help topic `flow`; OpenAPI/MCP regenerated.

## 8. Open
Nothing. (The upstream stage was decided in on 2026-10-16.)

## 9. Decided at the start of the task (owner: accept all defaults, 2026-10-16)
Recorded in ADR-132: `status_rcode` counts only answers that asked no upstream (so every link stays
an exact counter); minute buckets only; `partial` without naming the node; device mode through vqlog
(its own row cap sets `truncated`); `client` refused at privacy level 2; the layout's invariants
checked by Playwright on the drawn SVG; the traffic-by-group chart left as it is (follow-up).
