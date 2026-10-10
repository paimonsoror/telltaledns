# Change simulation: design notes (T13.1)

**Requirement:** OBS-024 (and the impact estimate AGT-002 promised). **ADR:** ADR-115. **Task:** T13.1 in `spec/10`.
**Owner request:** 2026-10-09, from the capability review. **Spec section:** `06` §7.3.

This document is opinionated on purpose. Where it says *decision*, build it that way; if you find a reason
not to, amend ADR-115 and say why in the task report. Where it says *open*, ask the owner.

## 1. What it is, in one paragraph
A dry run today answers "what changes?" (the diff, validation). Simulation answers "what would it have
done?": it takes the configuration the dry run computed, decides every query in the query log over a
window again under that configuration, and reports the differences from what was actually decided:
queries that would now be blocked, queries that would now be allowed, queries whose route (upstream
group) or answer (local record, rewrite, AAAA filter) would change — by device and by name, with the
deciding list. It never asks an upstream, never touches the cache, and never runs on the query path.

## 2. Non-goals
- Latency, cache hit rate, DNSSEC outcomes, rate limiting, upstream behaviour. The simulation is about
  **decisions**, which is what a filtering change affects. Say so in the help text.
- Predicting names nobody has asked yet. The estimate is about the past; the response says "over the
  last 24 h these N queries would have changed", not "this will block N per day".
- A second query-log format or a long-lived "simulation store". Results are computed and returned.

## 3. The three doors (decision)
1. **Dry runs.** Every mutation that already supports `?dryRun=true` (devices, records, forwards, quick
   rules, lists, groups, upstreams, schedules, exclusions, alerts…) accepts `&simulate=<window>`
   (`24h`, `7d`, or `from=…&to=…`). The response gains `impact` (§6). Without `simulate`, nothing
   changes. Mutations whose kind can't affect a decision (alerts, users, tokens, exclusions) answer
   `impact: { applicable: false }` rather than 400, so clients can send it blindly.
2. **Whole configuration.** `POST /api/v1/simulate` with `{ config: <shared configuration as JSON>,
   window }` — the shape `telltale_config::shared::shared_part` produces, which is also what a Git
   commit's `telltale/shared.toml` becomes. `telltale config simulate shared.toml --window 24h
   [--node URL --token …]` wraps it. This is the GitOps door: test a commit before pushing.
3. **MCP.** `simulate_change(kind, …, window)` where `kind` ∈ `block_domain | allow_domain | add_list |
   assign_client | update_group` with the same parameters as the matching `plan_*` tool. It calls the
   dry-run door and returns `impact` alone. Separately, every `plan_*` tool that can affect decisions
   takes an optional `simulate` (a window such as `"24h"`); **plans simulate only on request** (owner
   decision 2026-10-09: save compute and bandwidth) — or always, when the toggle
   `[simulate] plans_by_default` is on. If the node answers `simulation_busy` or the window is empty,
   the plan is created without `impact` and its text says "impact not estimated: <reason>". The tool
   descriptions tell agents the parameter exists ("pass simulate: \"24h\" to see what it would have
   done to yesterday's queries").

Why not one new `POST /api/v1/simulate` with a union body of every change kind? Because the dry-run
endpoints already validate and merge each kind; duplicating that in a second body shape is how two
code paths drift. The whole-configuration door exists for the case the dry-run doors can't express.

## 4. Engine (decision)
New module `crates/telltale/src/simulate.rs`. Inputs: the dry run's **merged configuration** (`Config`,
after the managed-entry merge; the dry-run handlers already have it) and the window. Steps:

1. **Candidate policy.** Build the candidate `Policy`/`ClientTable`/router exactly as a reload would
   (`pipeline::build_policy`-equivalent; refactor the reload path so the construction is a function of
   `&Config` + the current snapshot, with no side effects). Quick rules, schedules (evaluated at each
   event's timestamp, not now), block modes, group masks, routes, local records, rewrites, AAAA filter.
2. **Candidate filter.**
   - If the candidate's `[[list]]` set (URLs/paths/inline, `kind`, `match`, `mode`, enabled) equals the
     serving one: reuse the serving `FilterState`'s snapshot; recompute per-group/per-client masks for
     the candidate groups.
   - Else: compile **only the lists that differ or are new** (`telltale_filter::compile` with the
     fetcher's stored sources; a new URL list is fetched through the existing `check_list` path first —
     the dry run for `plan_add_list`/`PUT /lists` already downloads to validate) into a **side
     snapshot** in a temp dir under `<data_dir>/snapshots/sim-<id>/`, one thread, `SCHED_IDLE`, the
     compiler's memory cap. Removed lists are handled by masks (their IDs leave the mask), not by
     recompiling.
   - Decision function: `decide_merged(name, ctx)` runs `Matcher::matches` on the serving snapshot
     (with candidate masks) and on the side snapshot, then picks by the existing precedence (exact >
     deepest suffix > regex > lowest list ID; shadow lists excluded; `$denyallow`, `$dnstype`,
     `$client` honoured by each matcher). `$badfilter` across the two snapshots is not honoured; add
     `notes: ["badfilter_cross_snapshot"]` when the side snapshot contains any `$badfilter` rule.
   - Property test: for 10k random names × 3 clients, `decide_merged` with (serving = lists A, side =
     list B) equals `decide` on a full compile of A ∪ B, in both lookup modes, excluding `$badfilter`.
3. **Replay.** Read the query log newest first over the window with the column reader
   (`telltale_store::qlog::search` with a projection: `ts`, `client`, `group`, `qname`, `qtype`,
   `status`, `rule_list`, `upstream_group`), in blocks. For each row: identify the client under the
   candidate table (the event carries the address; MAC/client-ID identification can't be redone — use
   the event's recorded group when the address alone can't identify, and note `identity_from_event`),
   evaluate schedules at the row's time, run `decide_merged`, local data, rewrites, AAAA filter, and
   the route. Compare with the recorded status/route. **Skip** rows with status `special`, `refused`,
   `ratelimited`, `dropped`, probes, and excluded names (they never reach the filter).
4. **Aggregate.** Counters per outcome class; `SpaceSaving` top names per class (capacity 256, report
   20) with the deciding list; per-device counts (bounded 4,096 devices, then "other"); per-group
   counts. Fixed ordering on output (count desc, then name) so results are byte-identical across runs.

**Bounds:** a `tokio::sync::Semaphore(1)` per node → `409 simulation_busy` with `retryAfterSecs`.
`[simulate] max_secs` (20) checked between blocks; `max_rows` (2,000,000) newest first; both set
`partial: true` and `rows` to what was read. Window ≤ 7 d (422 otherwise). Everything runs in
`spawn_blocking` on the idle-priority pool the query-log search already uses.

**Privacy.** At `[telemetry.qlog] privacy_level ≥ 1` names in the log are hashed, so a change that
depends on names can't be replayed: answer `impact: { available: false, reason: "privacy_level" }`.
A device-only change (moving a device between groups whose lists are identical) only needs the
address and the recorded status; allow it at level 1, not at 2+ (clients hidden).

## 5. Cluster (decision)
Each node holds its own log, plus (a controller) the shipped logs of resolver pods under
`qlog-nodes/<id>/`. Run the simulation **where the rows are**: the entry node fans out an RPC
`sim.run { config_blob_hash | inline config, window, lists_to_compile }` to every node in scope that
reports a local or receiving log (a new heartbeat bit, `has_qlog`), with deadline `max_secs + 5`, and
merges the aggregates (sum counters, merge Space-Saving, merge per-device maps) like other federated
reads (`federation.rs`). `missingNodes` as usual. Ship-mode nodes don't run it (no rows). The side
snapshot compiles on every participating node (each compiles the same small list set; cheaper than
shipping blobs for a preview). `scope=node:local` keeps it local.

## 6. Output
```jsonc
"impact": {
  "available": true, "applicable": true,
  "window": { "from": "...", "to": "..." }, "rows": 183204, "partial": false,
  "newlyBlocked":  { "queries": 412, "devices": 3, "topNames": [ { "name": "ads.example", "queries": 300, "devices": 2, "list": "hagezi-pro" } ] },
  "newlyAllowed":  { "queries": 7,   "devices": 1, "topNames": [ { "name": "cdn.example", "queries": 7, "devices": 1, "list": "oisd (was blocking)" } ] },
  "changedRoute":  { "queries": 0,   "devices": 0, "topNames": [] },
  "changedAnswer": { "queries": 0,   "devices": 0, "topNames": [] },
  "unchanged": 182785,
  "byDevice": [ { "client": "192.168.2.40", "name": "living-room-tv", "newlyBlocked": 300, "newlyAllowed": 0 } ],
  "byGroup":  [ { "group": "iot", "newlyBlocked": 400, "newlyAllowed": 0 } ],
  "notes": [],
  "missingNodes": []
}
```
Names follow the query log's privacy rules exactly as `GET /queries` returns them. Units in field
names where they apply (AGT-001).

## 7. UI
- `ChangePreview` gets a **"What would this have done?"** button (not automatic: it can take seconds on
  a Pi). It shows a compact impact card: the four counters as tiles, top names with a link to the
  query log filtered by name and window, by-device chips (the existing `ClientChip`), and the notes.
  "Partial" and "unavailable" states are explicit sentences, never empty tables.
- Lists → Add list: the same button after the list validates.
- Agent changes (plans inbox): plan cards show `impact` when present.
- Help topic `simulate` (what it is, what it isn't, why it can take a while, privacy levels).
- Site: the monitoring page gets a short section; the agents page lists `simulate_change`.

## 8. Config
```toml
[simulate]            # shared; a one-of section managed like [exclusions] (ADR-111)
enabled = true
plans_by_default = false   # agents' plans simulate only when they ask, unless this is on
max_secs = 20
max_rows = 2_000_000
default_window = "24h"
```
`enabled = false` makes every door answer `available: false, reason: "disabled"`. Validation: 1 ≤
`max_secs` ≤ 300, `max_rows` ≥ 1,000, `default_window` ≤ 7 d.

**Settings → System → Change simulation** edits it like the rate limit and exclusions: the toggles and
bounds, a plain-language preview, Revert to the file, and under a GitOps authority the TOML to commit.
`PUT`/`DELETE /api/v1/simulate-settings/default` with dry run, `If-Match`, idempotency, audit
`simulate.put`; agent scope `config:write:simulate`; MCP `plan_set_simulate_settings` is **not** added
(an agent shouldn't turn on its own default-simulation; a human does).

Shared rather than node-local on purpose: the toggles are one place to look and GitOps-manageable; the
bounds suit a Pi and a pod alike. A node that can't meet `max_secs` reports `partial`, which is fine.

## 9. Metrics, audit, scopes
- `telltale_simulations_total{outcome="ok|partial|busy|unavailable|error"}`,
  `telltale_simulation_duration_seconds` (histogram), `telltale_simulation_rows_total`.
- Not audited (a dry run isn't). Scopes: `querylog:read` plus the write scope of the change (as for
  `check_list`/`check_upstream`); the whole-configuration door needs `config:read` + `querylog:read`.
- Rate: the semaphore is the rate limit; agents hitting `busy` get `retryAfterSecs`.

## 10. Performance budget
- Query path: untouched (no new state in `Pipeline`; the candidate is built beside it). `make
  bench-smoke` before and after must match.
- Telemetry thread: untouched.
- Replay cost: a decision is ~1 µs; reading rows from the column store is the bound. Target: 2M rows
  in ≤ 20 s on a Pi 4 at idle priority (the T3.2 numbers suggest ~1–2 s for a column scan of 50M
  rows; the per-row decide dominates). Measure on the build VM and the Pi and record in the task.
- Memory: side snapshot ≤ the compiler cap (`[filter] compile_memory`); aggregates bounded (§4.4).

## 11. Tests (map to the AC in `spec/10`)
- Unit (`crates/telltale/tests/simulate.rs`): block/allow/route/zero cases over a synthetic log;
  `decide_merged` property test; bounds (`busy`, `max_rows`, `max_secs`); privacy levels;
  determinism (two runs, byte-equal JSON); skipping special/refused/probe/excluded rows.
- Cluster e2e step: simulation on the replica includes the primary's rows and a ship-mode node's rows
  on the controller; `missingNodes` for a stopped node.
- Playwright: a quick block rule's preview shows the count of queries the test made; the MCP e2e
  plan carries `impact`.
- Bench: `make bench-smoke` unchanged.

## 12. Implementation order
1. Refactor: candidate `Policy`/router construction as a pure function of `&Config` + snapshot.
2. `decide_merged` + property test (no I/O yet).
3. Replay over the query log + aggregation + bounds + determinism tests.
4. `simulate=` on the dry-run handlers (one shared helper), `impact` type in `telltale-api::model`,
   OpenAPI regenerated, `applicable: false` for kinds that can't affect decisions.
5. `POST /api/v1/simulate` + `telltale config simulate`.
6. RPC `sim.run`, `has_qlog` heartbeat bit, federation merge, e2e step.
7. MCP `simulate_change`; `simulate` on the `plan_*` tools; `plans_by_default`; graceful degradation.
8. `[simulate]` as a managed one-of section + Settings → System editor + API + audit.
9. UI button and card; help topic; docs; site. Tick the task.

## 13. Decisions taken with the owner (2026-10-09)
- Plans simulate **only on request** (`simulate` parameter), with `plans_by_default` as the toggle in
  Settings. Rationale: compute and bandwidth on a Pi.
- Window maximum 7 days (not raised; longer windows add cost, not insight, for a preview).
