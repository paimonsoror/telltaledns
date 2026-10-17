# Latency heatmap with exemplars: design notes (T14.4)

**Requirement:** OBS-030 (new). **ADR:** ADR-130 (new, Proposed). **Spec section:** `06` §5.1
(exemplars) gains a paragraph; `07` §3 row *Latency heatmap*. **Owner request:** 2026-10-16.

## 1. What it is, in one paragraph
A histogram-over-time heatmap of query latency — x is time, y is the latency bucket (50 µs … 5 s, the
same bounds as `telltale_query_duration_seconds`), colour is how many answers landed there — per
path (cache, blocked, local, upstream) and per upstream, with **exemplar dots**: a click opens the
trace lookup (`#/queries?trace=`) for a real query from that cell. The Pi's 77 ms forwarded PTR is a
lonely dot in the right band; a DoT cold-start tail (ADR-098) is a stripe you can see, not a p99 you
have to believe.

## 2. Non-goals
- Replacing the percentile charts ("Where does time go?", `hour_latency`).
- Storing per-query latencies; this is buckets of counts plus a bounded exemplar ring.

## 3. Data (decision)
Today the UI has percentiles per hour (`hour_latency`) and the Prometheus histogram per scrape; the
telemetry thread already keeps one exemplar per (path, bucket) slot, replaced at most once a second
(OBS-017). Two additions, both on the telemetry thread:

1. **Per-minute latency histogram in `TimeBucket`:** `latency_hist: BTreeMap<String, [u32; 14]>` keyed
   by path (`cache`, `blocked`, `local`, `upstream`; plus `upstream:<name>` for the per-upstream
   variant, bounded by the configured upstreams) over the **14 classic bounds** the Prometheus
   exporter uses (reuse its constant; the SLO threshold is one of them, OBS-016). Updated by the
   aggregator per drained event (one index computation, one increment). Serialized in the tagged
   section with `slow` and `#[serde(default)]`. Size: 4 paths × 14 × 4 B = 224 B per minute bucket;
   48 h in memory ≈ 650 KB; hour buckets sum minutes. Measure the aggregator's per-event cost in the
   bench (expected: tens of ns).
2. **Exemplar ring:** keep the last 512 exemplars (trace ID, `ts_us`, latency µs, path, upstream,
   bucket index) in a ring on the telemetry thread, fed by the same sink that fills the OpenMetrics
   slots, sampling at most one per (path, bucket) per second as now. The ring is the API's source;
   nothing is persisted (exemplars are a live aid; the trace lookup works for anything the log holds).

## 4. API (decision)
- `GET /api/v1/stats/latency/heatmap?from&to&step=minute|hour&by=path|upstream&scope` →
  `{ "bounds_us": [50, 100, ...], "starts": [...], "series": { "cache": [[...14 counts], ...], "upstream": [...] }, "missingNodes": [] }`.
  Federated `Read::LatencyHeatmap`, summed per cell. Window ≤ 48 h at minute step, ≤ 400 d at hour.
- `GET /api/v1/stats/latency/exemplars?from&to&path&scope` → up to 512 `{ "traceId", "time", "latencyUs", "path", "upstream" }`
  per node (federated, concatenated, newest first, cap 2,048 total). Scope `querylog:read` (a trace
  ID resolves to a row).
- MCP: extend `latency_breakdown` with `histogram: true` (returns the per-path arrays for the window);
  no exemplar tool (IDs are for humans clicking; agents use `search_queries` with `trace`).
- Metrics: none new; `telltale_query_duration_seconds` is already the Prometheus side of this.

## 5. UI (decision)
- Dashboard (Advanced view) *Where does time go?* card gets a **Heatmap** tab next to the percentile
  chart; the Upstreams page gets the per-upstream variant in each upstream's drawer.
- Canvas (`ui/src/lib/latency-heatmap.ts`): columns = time steps, rows = 14 buckets (log scale labels
  `50 µs, 100 µs, …, 250 ms, 1 s, 5 s`), colour = count with a square-root ramp on `--hm-ink`; the SLO
  threshold row (250 ms) drawn as a dashed line; exemplars as small dots placed at their exact
  (time, latency) position, with the dot's colour the path's series token. Hover: "15:04 · 10–25 ms ·
  312 answers (upstream)"; hover on a dot: latency and client (if allowed); click → `#/queries?trace=`.
- Path toggle chips (cache / blocked / local / upstream / all); when "all", stack as a sum.
- Change markers (T14.7) overlaid. Table view: bounds × time counts.
- `prefers-reduced-motion`: no fade-in on refresh.

## 6. Grafana
*Latency* row: add Grafana's heatmap panel over
`sum by (le) (rate(telltale_query_duration_seconds_bucket[1m]))` with exemplars enabled (note in
`docs/monitoring`: Prometheus needs `--enable-feature=exemplar-storage`; the homelab's doesn't have it,
the owner's call). Per path with a variable.

## 7. Acceptance criteria
1. Fixture: 1,000 events, 900 at 40 µs (cache), 90 at 30 ms (upstream), 10 at 400 ms (upstream) → the
   minute bucket's `latency_hist` has 900 in the `cache` 50 µs bound, 90 in `upstream` 50 ms, 10 in
   `upstream` 500 ms; `slow` (OBS-016) still equals 10 (same threshold, same count — assert equality).
2. Hour aggregation of 60 minutes equals the element-wise sum; a bucket from an older build (no
   section) reads as all zeros, and the API marks `partialNodes`.
3. Exemplar ring: 2,000 events in a second produce ≤ 14 × 4 exemplars; the API returns them newest
   first; a returned trace ID resolves through `GET /queries?trace=`.
4. Bench: aggregator per-event cost increase < 50 ns on the VM; `make bench-smoke` green.
5. Playwright `obs_030 latency heatmap`: tab shows the grid; a dot click navigates to the trace; the
   threshold line is drawn; table view; both themes.
6. Docs (`running.md` *Where does time go?*, Upstreams), site monitoring page, Grafana panel,
   OpenAPI/MCP regenerated.

## 8. Open
- Per-client latency heatmap (for "why is the TV slow?") would need `latency_hist` per client — no.
  Offer the device timeline (T14.8) with a latency lane instead; ask the owner if they want more.

## 9. Decided at the start of the task (owner: accept all defaults, 2026-10-16)
Recorded in ADR-130: the real 16 bounds plus overflow (17 rows); the histogram's own paths
(`synthesized` holds blocked answers); minute buckets only, not seconds; a federated read says
`partial` without naming the node; the Upstreams page gets a card with a picker (no drawer exists);
no per-client heatmap (§8; T14.8's latency lane); the per-event cost measured with the counts off
and on.
