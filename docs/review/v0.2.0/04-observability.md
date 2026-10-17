# Pass 04: telemetry, storage, observability (v0.2.0)

Reviewed at tag `v0.2.0` (commit 338db09) in `~/telltale-review`. `main` has changed one
in-scope file since the tag (`crates/telltale/src/http.rs`, +110 lines: new metrics appended
to `render`); the patches here touch `render_telemetry`, `render_exported`, and the test
module, which that change doesn't, so they should apply to `main` with at most an offset.
Nothing touched the Pi or the homelab; the experiments ran against a local debug build with a
loopback stub upstream.

## Summary

This is the strongest area reviewed so far. The capture path does what the spec promises
(wait-free per-thread rings, whole-record pushes, drops counted, counters that never drop,
no allocation after a thread's first event, all of it tested), the query-log format is
built to survive the SD card (self-describing blocks, a footer that is only an accelerator,
a checksum per section, every length checked, a fuzz target), and every consumer behind the
aggregator (query log, live tail, sinks, anomaly engine, rollups) has its own bounded buffer
with drops that reach `/metrics`. I found no way for telemetry, storage, or a sink to delay
an answer.

Top three points:

1. **Event time is anchored to the wall clock once, at start** (04-01, high). `Hub::ts_us`
   is `epoch + monotonic elapsed`, and the epoch is read when the hub is created. A Pi has
   no RTC: it boots on the clock it shut down with and sets it from NTP only after DNS
   works, which is after TelltaleDNS started. From that step on, every event, query-log
   row, and anomaly window carries the old offset, the rollup writer never sees another
   completed minute (the minutes it looks for are stamped hours away), and the dashboard's
   "last 15 minutes" is empty, until a restart. The patch re-anchors the epoch on the
   aggregator thread when the two clocks differ by a second or more (one clock read per
   25 ms drain; the query path still reads one atomic) and exports how often it happened.
2. **`/metrics` repeats a label set once per Tokio worker** (04-02, medium, verified: eight
   `telltale_telemetry_dropped_total{ring="telltale-rt"}` samples in one scrape). Prometheus
   keeps the first and silently drops the rest, so the chart's `TelltaleDNSTelemetryDropping`
   alert only sees one worker's drops. The patch sums rings by thread name.
3. **Blocks that no list decided are attributed to a list** (04-03, medium).
   `telltale_blocked_total{list}` keys on `Rule::list`, which is a hash reference for quick
   rules, a schedule reference for schedules, and `0` for rebinding-protection blocks, so a
   bedtime schedule or an answer-address refusal shows up as a block by whatever list has
   that number (always list #0 for rebinding). The patch keys those kinds separately.

Also worth the owner's attention: the privacy levels apply to the query log, tail, and
sinks but not to the in-memory analytics the API serves (04-04), and level 1's "hidden"
names are an unsalted hash that confirms any guessed domain (04-05). The rest is low.

Not reported, as the README asks: the v1.0 gate's memory and cold-start numbers, and the
ADR-026 decision that `QueryEvent.upstream` stays 0 (though see 04-07 for what it does to
the API's filters).

## Strengths

- **The capture path is what the spec asks for, and it's proven.** A thread's ring is a
  byte ring written with `push_entire_slice`, so a record is in or out, never torn
  (`crates/telltale-telemetry/src/ring.rs:101-122`); the thread-local lookup can't panic
  on re-entry (`:104`); after the first event nothing allocates
  (`events_tests.rs:216-228`, with `allocation_counter`); and 100k events/s from four
  producers drop nothing (`events_tests.rs:337-375`). Counters live in cache-line-aligned
  per-thread slots with relaxed atomics and are summed on scrape (`lib.rs:197-306`), so
  the "counters never drop" promise holds by construction.
- **The query-log format is designed for power loss.** Every block carries the dictionary
  entries it introduces, so a part cut short by a crash is read by walking block headers
  (`crates/telltale-store/src/qlog/reader.rs:385-405`); the footer is a faster path to the
  same headers and is ignored if its trailer doesn't account for the file exactly
  (`reader.rs:347-383`). Block headers are sanity-checked before anything is allocated
  (`format.rs:168-196`), every section is checksummed before it's decompressed
  (`reader.rs:287-294`), decompression is capped (`reader.rs:16-18`), and there is a fuzz
  target plus `obs_003_unfinished_and_damaged_segments_are_still_readable`.
- **A slow disk costs rows, never answers, and never corrupts a part.** The builder hands
  sealed blocks to the writer through an 8-deep channel; when it's full the block is
  dropped, counted, and a new part starts, because a later block must never reference a
  dictionary entry only the dropped block introduced (`writer.rs:262-271`). That is the
  kind of invariant that is easy to miss and was not.
- **Search reads as little as it can.** A finished part's name filter rules out an exact
  name after one small read (`search.rs:515-520`); blocks are pruned by time, status and
  RCODE masks, max latency, and blooms keyed by content hashes (`search.rs:753-774`); the
  dictionary is decoded in bulk and indexed in place (`reader.rs:60-76`); output rows
  resolve their names from only the dictionary blocks that hold them (`reader.rs:194-240`);
  and the parallel path merges results in segment order, stops the pool when the page is
  full, and survives a panicking worker (`search.rs:344-422`). API and CLI searches run at
  idle priority (`api_backend.rs:382-385`, `qlog_cli.rs:109-114`).
- **Rollups are idempotent and forward-compatible.** Minutes are upserted and the hours
  and days above them recomputed in one transaction (`rollup.rs:262-295`), so re-flushing
  the last three minutes for late events is harmless; the encoding carries its column
  counts so an older build reads newer rows (`rollup.rs:81-194`, tested for version 1);
  groups are stored by name so a group table change doesn't shuffle history (T6.16).
  Minutes from before a restart are never overwritten by a partial view
  (`crates/telltale/src/rollups.rs:59-65`).
- **The live tail is free when nobody watches** (one `receiver_count` load per event,
  `tail.rs:97`), capped at 16 subscribers, rate-limited per subscriber with the skipped
  count sent inline (`tail.rs:302-358`), and it applies the query-log privacy level.
- **Sinks and alerts are bounded and visible.** Each sink has its own channel and thread;
  a full channel drops and counts (`sinks.rs:225-231`), the drop is logged once a minute
  (`:234-245`) and exported as `telltale_sink_dropped_total{sink}` (`http.rs:555-570`);
  the webhook spill is capped, compacted, and tested (`sinks.rs:572-698`). Alerts fire once
  per subject after `for_secs` and clear once (`alerts.rs:52-118`, tested); a failing
  destination is logged and recorded for the status API, never queued.
- **The anomaly engine keeps its promises.** Fixed-size per-device state with a measured
  byte budget (`anomaly.rs:627-639`), event-time windows, FNV and plain IEEE arithmetic,
  and a golden-file test for byte-identical findings (`anomaly_tests.rs:185`); findings
  carry observed, baseline, spread, threshold, and samples; state is saved atomically
  (`crates/telltale/src/anomaly.rs:122-136`).
- **An operator can diagnose the three incidents the brief names.** An upstream failing:
  breaker state and EWMA per upstream plus the `TelltaleDNSAllUpstreamsDown` rule. A disk
  filling: `telltale_data_filesystem_bytes`, `telltale_data_bytes{kind="qlog"}`,
  `telltale_qlog_write_errors_total` with the last error kept for the status API, and
  `TelltaleDNSDataDiskLow`. A slow sink: `telltale_sink_dropped_total` and the throttled
  warning. Host metrics a node can't read are left out rather than reported as zero
  (`host.rs:217-234`), so alerts don't fire on them.
- **The Grafana dashboard only uses metrics that exist**: every `telltale_*` name in
  `deploy/grafana/build.py` is rendered by the binary (checked by script, 0 missing).
- **Cluster percentiles are merged exactly**, from each node's recorded values rather than
  by averaging percentiles (`agg.rs:289-306`, `clu_002_latency_histograms_merge_exactly`).

## Measurements

| What | Result |
|---|---|
| `/metrics` after 4,800 UDP queries (unique names, loopback stub upstream) and 8 TCP queries, debug build | `telltale_telemetry_events_total{ring="telltale-rt"}` and `_dropped_total{ring="telltale-rt"}` each appear **8 times** (one per Tokio worker); 0 other duplicate label sets (04-02) |
| Query-log writer, 400k rows, 1,000 distinct names (debug build, WSL) | 1 part, 1.4 MB (3.5 B/row), 0.6 s |
| Query-log writer, 400k rows, every name unique | 25 parts, 6.6 MB (16.4 B/row), 1.4 s, 0 dropped |
| Query-log writer, 1.6M unique names in one hour (~450 unique qps) | 98 parts, 26 MB, 5.3 s, 0 dropped; exact-name search 23 ms (name filter: 1 dictionary read); substring search 1.2 s (98 dictionaries); `list_segments` 0.16 ms; retention pass 0.27 ms (04-06) |
| Dashboard metric names vs. exported names | all 36 `telltale_*` names in `deploy/grafana/build.py` are exported |
| Each patch, applied alone to v0.2.0: `cargo test -p telltale-telemetry --lib`, `cargo test -p telltale --bin telltale obs_005` / `ops_003` / `obs_007`, `cargo clippy -p telltale-telemetry -p telltale --all-targets -- -D warnings` | all pass, all clean (details in each finding's Patch row) |

Debug-build timings are only relative; the part counts and read counts are what matter.
No `bench.py sustain` run: it needs the release build (over 10 minutes here) and the
question it answers (0 drops at 50k qps) was measured for ADR-026 and the v1 gate.

## Findings

### 04-01 Event time is anchored to the wall clock once; a clock step after start mis-times everything until a restart

| Field | Content |
|---|---|
| Severity | **high** |
| Category | correctness, reliability (Pi deployability) |
| Where | `crates/telltale-telemetry/src/ring.rs:63-83` (`Hub::new` reads `SystemTime` once into `epoch_us`; `ts_us` is `epoch_us + (Instant − epoch_at)`); `crates/telltale/src/pipeline.rs:2109`, `:1907`, `:1945` (every query and upstream event is stamped through it); `crates/telltale/src/rollups.rs:57-96` (the writer flushes minutes in `[flushed_to − 180 s, now)` by the **system** clock); `crates/telltale-store/src/qlog/writer.rs:163-167` (segment hour from the event time); `crates/telltale/src/anomaly.rs:156` (engine windows from event time) |
| Evidence | **verified by reading**, the mechanism is unambiguous: `Instant` (CLOCK_MONOTONIC) does not move on `settimeofday`, and `epoch_us` is never updated. The consequences follow: (1) after a forward step of Δ, every event is stamped Δ in the past; the rollup task's window is `[now − 180 s, now)` by the system clock, so no in-memory minute ever lands in it again and `rollups.db` stops growing; the API's `step=second/minute` windows are empty for "now"; query-log rows go to the segment for the hour Δ ago (search by time misses them); anomaly hours close Δ late. (2) After a backward step of Δ, events are stamped Δ in the future: the API's "last 15 minutes" (by the system clock) is empty until the clock catches up, and the minutes reach `rollups.db` Δ late under the wrong start times. **When it happens:** a Raspberry Pi has no RTC; `fake-hwclock` restores the last shutdown time at boot and `systemd-timesyncd` steps the clock on its first sync, which needs DNS, which is this service (the unit only orders after `network-online.target`, `deploy/systemd/telltale.service:5-6`). A power cut on the Pi at 192.168.3.2 is exactly this sequence. Also any VM or laptop resumed from suspend (CLOCK_MONOTONIC stops during suspend). The pass-01 and -03 reports didn't touch time. **To confirm live:** start the debug binary, `date -s "+2 hours"` (or `sudo timedatectl set-time`), send queries, and watch `GET /api/v1/stats/timeseries?step=second` stay empty and `rollups.db`'s `MAX(start)` stop; the patch's unit test shows the re-anchoring instead, since the clock can't be stepped on this machine. |
| Impact | Every Pi that loses power: from the NTP sync onward (minutes after boot), the dashboard shows no traffic, long-range history stops accruing, the query log files hours in the wrong place, anomaly baselines learn the wrong hour of day, and it looks like telemetry is broken, until the operator restarts the service. Kubernetes nodes are unaffected (their clocks are set before pods start). |
| Recommendation | Re-anchor the epoch when the system clock and the epoch-derived time differ by a second or more: the aggregator thread already wakes every 25 ms, so one `SystemTime::now()` there costs nothing, and `epoch_us` becomes an `AtomicU64` read with `Relaxed` on the query path (no measurable change: it was a plain load). Slewing never triggers it (NTP frequency corrections apply to CLOCK_MONOTONIC too; only steps differ). Count the steps and export them (`telltale_clock_steps_total`, `telltale_clock_last_step_seconds`) so an operator can explain a gap. Alternative: `CLOCK_BOOTTIME`-based `Instant` would cover suspend but not NTP steps, so it doesn't replace this. Separately worth doing in the Pi install docs: `After=time-sync.target` can't be used (it would wait for DNS that this service provides), so say that the first minutes after a cold boot may be mis-timed on builds without this fix. |
| Patch | `patches/04-01-event-clock-follows-clock-steps.patch` (`ring.rs`, `http.rs`, `docs/running.md`, test `obs_001_event_time_follows_a_clock_step`). **Verified:** `cargo test -p telltale-telemetry --lib` (26 pass, the new test included: a 2 h step forward and back moves the epoch, a 0.5 s difference doesn't), `cargo test -p telltale --bin telltale obs_005` passes, `cargo clippy -p telltale-telemetry -p telltale --all-targets -- -D warnings` clean. The query-path cost is one relaxed atomic load in place of a plain one; I did not re-run `bench-smoke` for that (release build > 10 min here), so the implementing agent should, per rule 4. |
| Effort | S |
| References | OBS-001, OBS-004, ADR-026 (the epoch design), ADR-031 (rollups), `spec/06` §2–3 |

### 04-02 `/metrics` repeats the ring label set once per Tokio worker; Prometheus keeps only the first

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | observability, correctness |
| Where | `crates/telltale-telemetry/src/ring.rs:124-145` (a ring is named after its thread); `crates/telltale/src/main.rs:1206-1209` (every Tokio worker is `telltale-rt`); `crates/telltale/src/http.rs:601-628` (one sample per ring, no folding); `deploy/helm/telltale/templates/monitoring.yaml:64-69` (`TelltaleDNSTelemetryDropping` sums `rate(telltale_telemetry_dropped_total)`) |
| Evidence | **verified.** Debug build, loopback stub upstream, 4,800 unique-name UDP queries (so every answer completes on a Tokio thread) plus 8 TCP queries: the scrape contains `telltale_telemetry_events_total{ring="telltale-rt"}` eight times with values 3268, 3420, 2918, 2, 2, 2, 2, 2, and `telltale_telemetry_dropped_total{ring="telltale-rt"}` eight times (`~/.cache/tt/rv04_metrics.txt`). Prometheus treats a repeated label set in one scrape as a duplicate sample: it ingests the first and drops the rest ("duplicate sample for timestamp", counted, not an error for the scrape). So the chart alert, the dashboard's drop panel, and OTLP export see one worker's counters out of eight. `promtool check metrics` would flag it; it isn't installed here. |
| Impact | Drops on seven of eight Tokio workers are invisible to Prometheus; the one that is visible is whichever thread registered first. The UDP workers (`udp-<port>-<n>`) are unaffected. Nobody notices until they look for drops that the API's own counters show and Prometheus doesn't. |
| Recommendation | Fold `ring_stats()` by thread name before rendering (one series per name, summed), which keeps the per-UDP-worker series ADR-026 wanted and gives Tokio one. Alternatives: number the rings (`telltale-rt-3`) for per-thread detail nobody needs in Prometheus, or name Tokio's threads uniquely at the runtime builder (Tokio has no per-worker name hook; a counter in `thread_name_fn` would do but is further from the problem). Also worth a test that no label set repeats in a full render. |
| Patch | `patches/04-02-ring-series-per-thread-name.patch` (`http.rs`, `docs/running.md`, test `obs_005_ring_series_are_unique_per_thread_name`). **Verified:** the test alone fails on v0.2.0 (three `ring="twin"` samples); with the fix `cargo test -p telltale --bin telltale obs_005` (2) and `ops_003` (7) pass and `cargo clippy -p telltale --all-targets -- -D warnings` is clean. |
| Effort | S |
| References | OBS-002, OBS-005, ADR-026, Prometheus exposition format (a series may appear once per scrape) |

### 04-03 `telltale_blocked_total{list}` attributes quick-rule, schedule, and answer-address blocks to a filter list

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | correctness (observability) |
| Where | `crates/telltale-telemetry/src/export.rs:89-99` (`blocked` keyed by `(group, rule.list)` for every rule kind); `crates/telltale/src/http.rs:1034-1046` (`list` label = `lists[rule.list]`); what `Rule::list` holds per kind: `crates/telltale/src/pipeline.rs:2062-2074` (quick rule: `quick_ref(id)`, a 16-bit FNV hash), `:1495-1499` (schedule: its reference), `:1580-1586` (answer address: `0`); compare `api_backend.rs:262-310` (`rule_labels`, which the API and sinks use, does switch on the kind) |
| Evidence | **verified by reading** (the three constructors above) and by the patch's test, which on v0.2.0 shows the four kinds with `list = 3` all landing in key `(1, 3)`. In particular every rebinding-protection or blocked-range refusal (FLT-015) counts as a block by list #0, the first list in the snapshot, whatever it is. |
| Impact | The Grafana "blocks by list" panel and anyone alerting on a list's block rate get credit assigned to the wrong list: a kids' bedtime schedule inflates whichever list shares its hash, and rebinding protection always inflates list #0. The API's query log and sinks label these correctly, so the two disagree. Bounded in size (4,096 pairs) so it isn't a cardinality issue. |
| Recommendation | Key `blocked` by what decided: the list ID for list rules (domain, modifier, regex, CNAME), and three reserved keys for quick rules, schedules, and answer addresses, rendered as `list="quick"`, `"schedule"`, `"answer_ip"` (and `"none"` for a block without a rule, today `"unknown"`). Per-quick-rule series would be unbounded and are not wanted. |
| Patch | `patches/04-03-blocked-total-keyed-by-decider.patch` (`export.rs`, `http.rs`, `docs/running.md`, test `obs_005_blocks_are_keyed_by_what_decided`). **Verified:** `cargo test -p telltale-telemetry --lib` (26 pass), `cargo test -p telltale --bin telltale obs_005` passes, clippy clean for both crates. The test references the new keys, so it doesn't compile on v0.2.0 unpatched; the collision is shown by the constructors cited above. The dashboard's "blocks by list" panel needs no change (the new label values just appear). |
| Effort | S |
| References | OBS-005, FLT-013 (attribution), FLT-010 (schedules), FLT-015 (answer addresses), ADR-067 (quick rule references) |

### 04-04 Privacy levels 1 and 2 don't reach the in-memory analytics the API serves

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | security (privacy), docs |
| Where | Applied: `crates/telltale-store/src/qlog/writer.rs:183-201` (query log), `crates/telltale/src/tail.rs:100-109` (tail), `crates/telltale/src/sinks.rs:146-155` (sinks), `crates/telltale/src/anomaly.rs:51` (engine off at 3 only). Not applied: `crates/telltale-telemetry/src/agg.rs` (no notion of privacy: top domains, top clients, per-client domains, per-client histograms, `recent` client windows all keep full names and addresses); served by `crates/telltale/src/api_backend.rs:758-785` (`top`, including `top_client_domains` for one address), `:1193-1214` (`anomalies`: client address and name, domain, `detail` with sample names), `:1425-1448` (`new_domains`: address and registrable domain), `clients`; the anomaly engine's NXDOMAIN samples are full query names (`anomaly.rs:696-703`), not eTLD+1 |
| Evidence | **verified by reading.** `Aggregates::record` and the `Hour` trackers take the wire name and client address as emitted; nothing between the ring and the API applies `privacy_level`. The docs describe the levels only under the query log (`docs/running.md:1656`, `:1661`: "`2` also drops client addresses"), and `spec/06` §7.1 says findings should honor the level ("at levels that hide domains, findings show eTLD+1 only, or counts only"). |
| Impact | An operator who sets `privacy_level = 2` because they must not keep per-device records (a shared house, a small office) still gets per-device top domains, a per-client page, first-seen domains per device, and anomaly findings naming the device, through the API, MCP tools, and the UI. Someone comparing with Pi-hole's levels (where 2 hides clients everywhere) will assume otherwise. The query log, the part that persists, is handled correctly. |
| Recommendation | A decision first (question 1 below). The conservative reading of the spec: at level 1 replace names with the same hashed form the log uses before they reach `Aggregates` and the anomaly engine (eTLD+1 findings then become hashes; the engine could stay off at ≥ 1 as it is at 3); at level 2 also zero the client address before `Aggregates::record`, which turns per-client analytics into one "all clients" bucket and would also disable the masked-IP detector (OPS-003) and per-device alerts: that is what "hide clients" means. One place does it: the aggregator thread, before `agg.record` and the sinks, so the writer's and tail's own hashing becomes a no-op. Whatever is chosen, say in the docs which views each level affects. |
| Patch | none (the behaviour needs the owner's decision; the change is mechanical once made) |
| Effort | M |
| References | OBS-003, OBS-004, OBS-009, OBS-013, OPS-003, `spec/06` §4 (privacy levels), §7.1 ("honors the client's privacy level"), ADR-027, ADR-043 |

### 04-05 Privacy level 1 hides names with an unsalted hash, so any guessed name can be confirmed

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | security (privacy) |
| Where | `crates/telltale-store/src/qlog/writer.rs:300-313` (`hidden_name`: `blake3(name)`, first 8 bytes, one label); used by the writer (`:193-196`), the tail (`tail.rs:106`), and the sinks (`sinks.rs:152`) |
| Evidence | **verified by reading.** The hash has no key or per-installation salt, so `h<hex>` for `facebook.com` is the same on every TelltaleDNS install. Anyone holding a level-1 log (a backup, a shipped segment, a sink's file) can hash a list of a few million common domains and read back which were queried, when, and by whom (clients are still stored at level 1). The spec calls level 1 "hide domains (stored as hash)", so a hash is intended; the docs say the names "can't be read" (`docs/running.md:1661`), which is true only for names nobody can guess. |
| Impact | Level 1 protects against a casual reader, not against anyone who wants to know whether a given domain was visited. For a home resolver that's most of the threat. |
| Recommendation | Key the hash with a random per-installation secret (32 bytes in `<data_dir>`, created once, mode 0600; `blake3::keyed_hash`), used by the writer, tail, and sinks. Grouping is unchanged within one node. Two things to decide: in a cluster, shipped level-1 logs would then not group with the primary's (a cluster-wide secret distributed like the cluster certificate solves it), and the docs should state what level 1 does and doesn't protect against. An alternative with no key is to store nothing for names at level 1 (Pi-hole's behaviour: a constant "hidden"), losing the grouping. |
| Patch | none (needs the cluster decision; S once decided, plus a test that two installs hash differently) |
| Effort | S–M |
| References | OBS-003, `spec/06` §4 privacy levels, ADR-027 |

### 04-06 A unique-name flood splits the hour's query log into many parts, one per 16,384 names

| Field | Content |
|---|---|
| Severity | low |
| Category | performance, footprint |
| Where | `crates/telltale-store/src/qlog/writer.rs:29-35` (`MAX_DICT = 16,384`, down from ADR-027's 65,536), `:179-182` (a new part when the dictionary is full), `:414-423` (`create` scans part numbers from 0 with `exists()` each time); `search.rs:536-553` (a name or client predicate reads every candidate part's dictionary) |
| Evidence | **verified (measured, debug build).** 1.6M rows of unique names in one hour (about 450 unique queries/s, what a random-subdomain attack or a misbehaving scanner on the LAN produces) wrote 98 parts, 26 MB, with 0 rows dropped and the writer keeping up. An exact-name search still cost one dictionary read (the per-part name filters work); a substring search read all 98 dictionaries (1.2 s in a debug build); listing and a retention pass over 98 files took under 0.3 ms. The same rows with 1,000 distinct names: 1 part. At 5,000 unique qps the hour would hold about 1,100 files and a day 26,000, which `list_segments` (every search, every retention pass, every `estimate`) and the retention `metadata` loop then walk; `create`'s scan is quadratic in parts per hour (about 600k `stat` calls for that day) but still small. |
| Impact | Under a sustained unique-name flood the log stays correct and bounded in memory, which is the point of the cap; the cost moves to file count and to name-predicate searches over that period, which get slower linearly. No DNS impact. A Pi with a slow SD card would feel the directory growth first. |
| Recommendation | Nothing urgent. Cheap improvements when nearby: remember the last part number per hour in the writer instead of scanning from 0; and consider rotating on `MAX_DICT` only after a part has at least N blocks or M seconds, so a short burst doesn't split the hour. Document the behaviour next to `retention_bytes`. |
| Patch | none |
| Effort | S |
| References | OBS-003, ADR-027, NFR-002 (the reason for the cap, T10.2) |

### 04-07 The `upstream` filter of the query log, live tail, and vqlog can never match

| Field | Content |
|---|---|
| Severity | low |
| Category | correctness, docs |
| Where | `crates/telltale/src/pipeline.rs:2120` (`upstream: 0` on every query event, per ADR-026); filters: `crates/telltale-store/src/qlog/search.rs:49`, `:710-713`; `crates/telltale/src/tail.rs:221`, `:234`; `crates/telltale/src/api_backend.rs:366`; documented as a filter in `docs/running.md:1878` and the OpenAPI document |
| Evidence | **verified by reading.** The event's `upstream` is always 0, so `?upstream=1` returns nothing and `?upstream=0` everything. Per-upstream analytics correctly come from `UpstreamEvent`s instead. |
| Impact | A documented filter that silently returns an empty page; an agent using the API would conclude the upstream answered nothing. |
| Recommendation | Either attribute the answering upstream on the event (the group resolver knows which member won; the singleflight sharing ADR-026 mentions means coalesced clients would all carry the winner, which is fine), or remove the parameter from the API and docs until it does. The first is the useful one for "which upstream is slow for this client". |
| Patch | none (attribution needs a small change in the upstream group's return value; a design choice for the pipeline) |
| Effort | S–M |
| References | OBS-001, OBS-008, AGT-012, ADR-026 |

### 04-08 dnstap's writer connects and writes without timeouts

| Field | Content |
|---|---|
| Severity | low |
| Category | reliability |
| Where | `crates/telltale/src/dnstap.rs:194-218` (`connect`: `TcpStream::connect` with no timeout, read timeout only), `:297` (`write_all` with no write timeout) |
| Evidence | **verified by reading.** A reader that accepts the handshake and then stops reading (a hung `fstrm_capture`, a Vector sink with a full buffer) lets the socket buffer fill, after which `write_all` blocks the dnstap thread for good: the queue fills, every copy is dropped, and because the thread never returns to its loop it never logs or reconnects. A blackholed TCP address blocks `connect` for the kernel's SYN retry time (about two minutes) on every retry. Only the dnstap thread is affected; DNS and the rest of telemetry are not. |
| Impact | dnstap stops silently after a reader stall; the operator sees nothing in the log (the "can't reach the reader" warning needs a failed connect) and the drop counter isn't exported. |
| Recommendation | Set a write timeout on both socket kinds and use `connect_timeout` for TCP (5 s, like syslog's TCP sink in `sinks.rs:379-380`), so a stalled reader surfaces as a reconnect with its warning. Export `Tap::dropped` as `telltale_dnstap_dropped_total` while there. |
| Patch | `patches/04-04-dnstap-io-timeouts.patch` (timeouts only; the metric is a few more lines in `http.rs` once the owner wants it). **Verified:** builds, `cargo test -p telltale --bin telltale obs_007` (2, including the Frame Streams handshake over a Unix socket) passes, clippy clean. No new test: a stalled reader needs a socket whose buffer is full, which the existing tests don't model. |
| Effort | S |
| References | OBS-007, ADR-077 |

### 04-09 Sinks format every event on the aggregator thread

| Field | Content |
|---|---|
| Severity | low |
| Category | performance |
| Where | `crates/telltale/src/sinks.rs:197-232` (`record`: for every event with any sink configured, `row()` resolves the device name through `policy.clients.identify`, clones the schedule names (`:168`), builds a `QueryRow`, serializes it to JSON, then clones the string once per additional sink) |
| Evidence | **suspected.** The work is bounded and allocation-light, but it runs on the one thread that drains every ring every 25 ms; `identify` walks the client table per event and `schedules.load().names.clone()` allocates per event. At 40k qps a few microseconds per event is a tenth of the aggregator's time; it adds up with the anomaly engine and the query-log builder on the same thread. To confirm: `bench.py sustain --rate 50000` with and without a file sink, watching `telltale_telemetry_dropped_total` (needs the release build). |
| Impact | On a loaded Pi with a sink configured, ring drops start earlier than without one. The design is right (one format, many sinks); only the thread is debatable. |
| Recommendation | Measure first. If it shows, hand sinks the raw `(QueryEvent, name)` through one channel and format on the sinks' own thread (device naming included), or at least drop the per-event schedule-name clone (`&schedules.names` is enough; `load()` holds the `Arc`). |
| Patch | none |
| Effort | S (the clone) / M (moving the formatting) |
| References | OBS-002, OBS-010, ADR-072 |

### 04-10 One-off alerts can repeat after the engine forgets 5,000 subjects at once

| Field | Content |
|---|---|
| Severity | low |
| Category | correctness |
| Where | `crates/telltale/src/alerts.rs:74-77` (`sent_once.clear()` once the set passes 5,000 entries) |
| Evidence | **verified by reading.** Anomaly, new-device, update, and plan-pending subjects are deduplicated by this set. When it is cleared, every subject still observed in the next evaluation (anomalies from the last hour, a pending plan, the available version) is sent again. Rare on a home network (5,000 one-off subjects), so low. |
| Impact | A burst of duplicate notifications once in a long while, on the busiest networks. |
| Recommendation | Keep the newest subjects instead of none: a `VecDeque` alongside the set, popping the oldest past the cap; or drop subjects whose window is older than an hour, since observations are limited to the last hour anyway. |
| Patch | none |
| Effort | S |
| References | OBS-010 |

### 04-11 An hour's stored top lists are lost if the process restarts within a minute of the hour closing

| Field | Content |
|---|---|
| Severity | low |
| Category | correctness (history across restarts) |
| Where | `crates/telltale/src/rollups.rs:63-65` (`extras_for` starts at the hour before start, so that hour's extras are never written by this process), `:91-94` (extras are written only for `previous_hour_start()`, at the next minute tick after the hour rolls, which happens on the first event of the new hour) |
| Evidence | **verified by reading.** Hour H's `hour_top`/`hour_latency` rows are written by the process that is running at the first minute tick after an event of hour H+1 arrives. A restart (upgrade, crash, pod reschedule) between H+1:00:00 and that tick means no process ever writes them: the new one deliberately skips them, assuming its predecessor did. The replay (T6.16) refills memory for the UI, so the loss is only visible in the stored history. |
| Impact | Occasional gaps in the stored per-hour top lists and latency summaries, exactly around restarts. Counts (minutes, hours, days) are unaffected. |
| Recommendation | After the startup replay finishes, write the previous hour's extras if `hour_top` has no rows for it (one `SELECT COUNT(*)`), instead of skipping unconditionally. |
| Patch | none |
| Effort | S |
| References | OBS-004, ADR-031, T6.16 |

## Questions for the owner

1. **What should `privacy_level` 1 and 2 mean for live analytics** (04-04)? Options: (a) the
   levels only govern what is stored and exported (today; document it), (b) they govern
   everything the API shows, which at level 2 removes per-device analytics, the masked-IP
   detector, and device anomaly alerts, (c) a separate knob for analytics. Pi-hole's levels
   are (b); the spec's §7.1 reads like (b) for findings.
2. **A per-installation or per-cluster salt for level 1's hashed names** (04-05): shipped
   logs from replicas would need the primary's key to group together. Is a cluster-wide
   secret (distributed like the cluster certificate) acceptable, or should level 1 simply
   store nothing for names?
3. **Should `QueryEvent.upstream` be attributed** (04-07), or should the `upstream` filter
   leave the API until it is? The former is cheap and makes "which upstream is slow for this
   client" answerable from the log.
4. **Is `telltale_dnstap_dropped_total` wanted** (04-08)? The counter exists; it just isn't
   rendered.

## Not reviewed

- `vqlog` beyond its limits and the search it compiles to (`vqlog.rs:440-549`): the
  language, `or` groups, and rollup-backed windows (ADR-082, ADR-089) belong with the API
  and agents in pass 06. `state.db` (users, tokens, audit) is pass 06 too; I noted only that
  the audit table is append-only by trigger (`state.rs:68-71`) and has no retention, which
  that pass should weigh.
- Federated reads across nodes, shipped query logs (CLU-007, `ship.rs`), and the cluster
  metrics in `http.rs:204-434`: pass 05.
- OTLP against a real collector, syslog over TLS against a real collector, and SMTP against
  a real provider: only the unit tests and CI's scripted servers (ADR-085) were read.
- The Grafana dashboard panel by panel: only that every metric it uses exists.
- `bench.py sustain` and the memory probe (`memprobe.py`): they need the release build.
- The web UI's use of these endpoints: pass 08.
- Line numbers refer to the v0.2.0 worktree; `main` has only appended to `http.rs::render`.
