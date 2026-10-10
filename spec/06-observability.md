# 06 — Observability and Analytics

Monitoring is a primary product pillar. The design principle: **capture everything cheaply on the hot path, aggregate off the hot path, store compactly, and query fast.**

## 1. QueryEvent (OBS-001)
Fixed-size, `Copy`, ~128 bytes, written into a per-worker ring buffer.
| Field | Type | Notes |
|---|---|---|
| `ts_us` | u64 | Wall-clock microseconds (start of processing) |
| `node_id` | u16 | Cluster node |
| `proto` | u8 | udp/tcp/dot/doh/doh3/doq |
| `client_ip` | [u8;16] | v4-mapped |
| `client_ref` | u32 | Resolved client ID (0 = unknown) |
| `group_ids` | [u16;2] | Primary group(s) |
| `qname` | interned u32 (+ inline 64-byte copy into the ring slot for the interner) | Interned by the aggregator, not on the hot path |
| `qtype`, `qclass` | u16, u16 | |
| `rcode` | u8 | |
| `status` | u8 | `allowed_forwarded`, `cached`, `stale`, `prefetch`, `local`, `rewritten`, `blocked_list`, `blocked_regex`, `blocked_cname`, `blocked_ip`, `blocked_schedule`, `blocked_service`, `rate_limited`, `refused`, `servfail_upstream`, `bogus`, `paused`, `malformed` |
| `rule` | (u16 list_id, u32 rule_idx) | For block/allow attribution |
| `upstream_id` | u16 | 0 if none |
| `upstream_attempts` | u8 | |
| `t_total_us` | u32 | Receive → send |
| `t_filter_us`, `t_cache_us`, `t_upstream_us`, `t_dnssec_us`, `t_queue_us` | u32 each | Stage breakdown |
| `resp_size` | u16 | |
| `answer_count` | u8 | |
| `min_answer_ttl` | u32 | |
| `dnssec` | u8 | secure/insecure/bogus/indeterminate/off |
| `ede` | u16 | |
| `flags` | u16 | DO, CD, AD, TC, ECS-present, prefetched, coalesced |

Upstream transactions additionally emit `UpstreamEvent { ts, upstream_id, latency_us, outcome, protocol, conn_reused }` for upstream analytics independent of client queries (prefetch, health checks).

## 2. Hot-path capture (OBS-002)
- Each worker owns an SPSC ring (`rtrb`, default 65,536 slots ≈ 8 MiB per worker; configurable; reduced automatically when the memory budget is small).
- Push is wait-free. If full, `telemetry_dropped_total{worker}` is incremented and the event is discarded. **Counters/histograms never drop**: they are updated by the worker itself in thread-local, cache-line-padded counters that the aggregator sums. Only the *detailed event* can drop.
- One **aggregator thread** drains all rings every ≤ 50 ms (or at a ring high-watermark). It:
  1. Interns qnames and client keys (FxHash map; the dictionary is per hour-segment).
  2. Updates the **live window**: per-second buckets for 15 min and per-minute buckets for 48 h (counts by status/qtype/rcode/proto/upstream/group).
  3. Updates **Space-Saving top-K** (K=1000, reporting top 100) for domains, blocked domains, clients, NXDOMAIN domains, and per-client domains (bounded LRU of clients).
  4. Records **HDR histograms** (1 µs–60 s, 3 significant digits) for total latency by `{status-class, proto}`, per upstream, per client (top 256 clients + "other"), per qtype, and per stage.
  5. Appends to the query-log store (§4).
  6. Fans out to exporters (§5) and live-tail subscribers (§6), each through its own bounded queue (a drop on a slow consumer is counted per consumer).

## 3. Rollups
- Minute rollups are flushed to SQLite `rollup_minute` (kept 7 days), then aggregated into `rollup_hour` (kept 400 days) and `rollup_day` (kept forever; tiny). Top-K and serialized HDR histograms are stored per hour.
- All dashboard queries beyond 15 minutes read rollups, never raw logs. So "last 30 days" charts render in < 100 ms on a Pi.

## 4. Query-log store (OBS-003)
A custom, append-only columnar segment format optimized for "filter by time, client, domain substring, status" on low-end storage.
- **Segment = one hour per node:** `qlog/YYYY/MM/DD/HH-<node>.seg`.
- **Layout:**
  - header (magic `VQLG`, version, node, hour)
  - N **blocks** of up to 8192 rows; each column is encoded separately:
    - delta + varint for `ts`
    - dictionary IDs (bit-packed) for qname/client
    - run-length encoding for status/qtype/rcode/upstream
    - frame-of-reference for latencies
  - then zstd level 3 per column chunk
  - **block index** (min/max ts, per-column min/max, a 1 KiB bloom filter over qname_id and client_ref)
  - **segment dictionary** (qname strings, client keys) + footer
- **Write path:** the aggregator builds the current block in memory and flushes when it has 8192 rows or is 10 s old. An fsync on each flush is configurable. **SD-card friendly:** ~1 write per 10 s, sequential. The in-progress block is not durable; a crash loses ≤ 10 s of *detail* (rollups are flushed every minute). This is a documented trade-off.
- **Search:**
  1. Select segments by time.
  2. Resolve predicates against the **dictionary first**. A domain substring/glob/regex is evaluated against unique names (orders of magnitude fewer than rows) to produce an ID set.
  3. Prune blocks with the block index + bloom filter.
  4. Decode only the needed columns, filter, and stream results newest-first with cursor pagination.
  5. Parallelize segments across a small thread pool (1 thread on Pi by default).
- **Retention (OBS-003):** by days (default 30) **and** by bytes (default 2 GiB; oldest segments deleted first). Expected compressed size is ~10–20 bytes/row, so 50M rows ≈ 0.5–1 GiB.
- **Privacy levels** (Pi-hole parity): `0` full; `1` hide domains (stored as hash); `2` hide domains + clients; `3` anonymous (no per-query log, aggregates only). Configurable per group.
- **Escape hatch:** `telltale ctl qlog export --from --to --format parquet|csv|jsonl` for offline analysis (Parquet behind a feature flag).

### 4.1 Exclusions (OBS-022, ADR-111)
`[exclusions]` (`enabled`, `names`, `clients`) is shared configuration. The aggregator thread checks each drained query against it (once per drain it takes the current set; per event: a hash lookup per name suffix, a scan of the client networks) and drops matches before the analytics and every sink: query log, live tail, anomalies, event sinks, shadow/over-blocking, exemplars and traces. `Metrics` (hot-path counters) still counts them; `telltale_queries_excluded_total` counts the drops. The startup replay of the query log skips them too. Set at start and on every reload (a replica's included). Managed as a one-of kind like `[ratelimit]` (`PUT/DELETE /api/v1/exclusions/default`, scope `config:write:exclusions`, MCP `plan_set_exclusions`, Settings → System); under a GitOps authority the write is refused and the TOML to commit is shown.

## 5. Exporters (OBS-005..007, OBS-010)
### Prometheus `/metrics` (default port 9153; also on the API port)
| Metric | Type | Labels |
|---|---|---|
| `telltale_queries_total` | counter | `node, proto, status, qtype` (qtype bucketed to the top 12 + `other`) |
| `telltale_responses_total` | counter | `node, rcode` |
| `telltale_query_duration_seconds` | histogram (native or classic buckets 50µs…5s) | `node, path` (`cache`, `blocked`, `local`, `upstream`) |
| `telltale_stage_duration_seconds` | histogram | `node, stage` |
| `telltale_upstream_requests_total` | counter | `node, upstream, outcome` |
| `telltale_upstream_duration_seconds` | histogram | `node, upstream, protocol` |
| `telltale_upstream_breaker_state` | gauge | `node, upstream` |
| `telltale_cache_entries`, `telltale_cache_bytes`, `telltale_cache_hits_total`, `telltale_cache_misses_total`, `telltale_cache_stale_served_total`, `telltale_cache_prefetch_total`, `telltale_cache_evictions_total` | | `node` |
| `telltale_filter_rules`, `telltale_filter_snapshot_version`, `telltale_filter_compile_seconds`, `telltale_list_entries{list}` | | |
| `telltale_blocked_total` | counter | `node, group, list` (cardinality bounded by #lists) |
| `telltale_client_queries_total` | counter | `node, client` **opt-in**, top-N capped (default off; N=100) |
| `telltale_telemetry_dropped_total`, `telltale_qlog_write_seconds`, `telltale_qlog_bytes` | | `node` |
| `telltale_cluster_snapshot_lag`, `telltale_cluster_peer_up`, `telltale_cluster_role` | gauge | `node, peer` |
| `telltale_ratelimited_total`, `telltale_dnssec_validation_total{result}` | counter | |

### Others
- **OTLP (P1):** the same metric set via OTLP/HTTP; optional QueryEvent export as OTel logs.
- **dnstap (P1):** CLIENT_QUERY/CLIENT_RESPONSE and FORWARDER_QUERY/RESPONSE messages over Frame Streams (Unix or TCP), with sampling.
- **Sinks (P1):** JSON-lines file (rotated), syslog RFC 5424 (UDP/TCP/TLS), and batched HTTP webhook (e.g., Loki, Elastic, Splunk HEC) with retry and a disk spill cap.
- **Grafana:** ship `deploy/grafana/telltale-dashboard.json` built on the Prometheus metrics.

### 5.1 Exemplars and traces (OBS-017, ADR-110)
- **Trace ID** (`event::trace_id`): 16 bytes = the query's start (`ts_us`, 8 bytes big-endian) ‖ the first 8 bytes of a BLAKE3 hash, keyed with the cluster's privacy key (OBS-003), of `ts_us` and the query-log row's `client`, `qtype`, and `name` text after the privacy level. Any node can recompute it from a returned row, the start time narrows the search to one microsecond, and without the key a guessed name can't be checked against an ID.
- **Exemplars:** a telemetry-thread sink keeps, per `telltale_query_duration_seconds` (path, bucket), the latest query's trace ID, latency, and time, replacing a slot at most once a second (one bucket lookup and a comparison per event otherwise). `/metrics` answers OpenMetrics 1.0 when `Accept` asks for `application/openmetrics-text` (and `[telemetry.metrics] exemplars`, default on): the 0.0.4 exposition converted (counter families without `_total`, `unknown` for a counter without it, HELP escaped, `# EOF`) with ` # {trace_id="…"} <seconds> <timestamp>` on each bucket that has one.
- **Traces:** with `[telemetry.otlp] endpoint` and `traces_sample_every` (1 in N) or `traces_slow_ms`, the sink queues the chosen events (≤ 4,096; more dropped, counted) as the privacy level keeps them; a task sends them every 5 s, ≤ 512 per request, as OTLP/HTTP JSON to `<endpoint>/v1/traces`: a SERVER span (`DNS <qtype>`, the query's attributes) and, when `t_upstream_us > 0`, a CLIENT child span for the upstream wait placed at the query's end. `telltale_traces_total{result}`.
- **Lookup:** `GET /api/v1/queries?trace=<32 hex>` searches `[ts, ts+1)` and keeps rows whose recomputed ID matches (after federation, so older nodes still answer); the UI's `#/queries?trace=`; MCP `search_queries` `trace`.

## 6. Live tail (OBS-008)
`GET /api/v1/queries/stream` (SSE) or `/ws`. Server-side filters: client, group, status set, qname glob, upstream, min latency, node(s). Rate-capped per subscriber (default 500 events/s, with drop counts sent inline).

## 7. Analytics (OBS-009, OBS-011)
| Analytic | Method | Output |
|---|---|---|
| Per-client profile | Rollups + top-K per client | qps, block %, top domains, qtype mix, protocols used, upstream latency seen, first/last seen, device name |
| First-seen domains | Per-client cuckoo filter of eTLD+1 seen in the last 30 days (bounded memory, ~1–2 B/entry) | "New domains this hour" feed per client; optional alert |
| NXDOMAIN storm | Per-client sliding window; alert if NXDOMAIN rate > X/min and > Y% of queries | Malware/misconfig indicator |
| DGA likelihood | Shannon entropy + consonant-run + bigram log-likelihood (bigram table shipped as data) on the left-most significant label; scored off the hot path for first-seen names only | Score 0–1 stored on the event; "suspicious domains" view |
| Rate anomaly | EWMA + MAD of per-client qpm vs. same-hour-of-week baseline | Spike alerts (OBS-013) |
| Per-domain volume anomaly | Per client, top-K eTLD+1 by query count (Space-Saving) with an EWMA + MAD baseline per tracked pair; also flags names re-queried far faster than their TTL allows | "TV → telemetry.vendor.example: 4,100 q/h, baseline 120 ± 40" (OBS-013) |
| Behavior drift | Per-client learned domain set (the cuckoo filter above) + daily count of new eTLD+1 vs. that device's own baseline; share of queries to domains outside its set | "Smart plug contacted 37 new domains today (usual: 0–1)" (OBS-013) |
| Beaconing | Per-(client, eTLD+1) inter-arrival histogram over log-spaced bins; flags a dominant period with low jitter that persists across ≥ N windows | Phone-home / C2 candidates with period and regularity (OBS-013) |
| List effectiveness | Hits per list, unique contribution, overlap matrix | Prune recommendations |
| Upstream health | HDR per upstream; breaker history | SLO view, "fastest upstream for you" |
| Latency explainer | Stage breakdown percentiles | "Where does time go?" chart (cache vs upstream vs DNSSEC) |
| Cache efficiency | Hit ratio, stale-served, prefetch success, eviction reasons | Sizing recommendations |

### 7.2 Shadow lists and over-blocking suspects (OBS-018, ADR-109)
- **Shadow lists:** `[[list]] mode = "shadow"` (block lists only) are compiled into the snapshot, but `FilterState` leaves them out of every enforcing mask; per group it keeps `shadow_group_masks` (the group's lists including its shadow ones) and `shadow_ids`. A telemetry-thread sink re-decides each answered query (`cached`, `forwarded`, `stale`, no allow rule) with the group's shadow mask; a block whose list is a shadow list is counted per list: queries, devices (≤ 4,096), Space-Saving top names (256 tracked, 20 reported), last hit. Nothing runs while no list is in shadow mode.
- **Over-blocking suspects:** the same sink remembers recent blocks per (device, name) (≤ 8,192): 10 blocked queries within 60 s is a retry burst (once per burst); the same device getting the name answered normally within 10 min of its last block is `allowed_after_block`. Suspects are kept per name (≤ 512, least recent evicted) with the deciding lists and devices (≤ 64); ranked by allowed × 10 + bursts.
- Names per the privacy level (hashed at 1+), devices not counted at 2+. Since start, per node; `GET /api/v1/analytics/shadow-lists` and `/analytics/overblocking` merge every node's (`federation::merge_shadow`, `merge_overblocking`); MCP `shadow_lists`, `overblocking_suspects`; `telltale_list_shadow_hits_total{list}`; the Lists page; explain's `shadow` flag.

### 7.3 Change simulation (OBS-024, ADR-115)
- **Doors:** `simulate=<window>` on any dry run (`?dryRun=true&simulate=24h`; `true` for `[simulate] default_window`; `simulateUntil` moves the end back) adds `simulation` (ADR-115 amendment: `impact` was already the dry run's sentence); `POST /api/v1/simulate` takes a whole candidate shared configuration (`telltale config simulate`, `telltale ctl simulate`); MCP `simulate_change`. Plans simulate only when the agent asks (`simulate` on a `plan_*` tool, default `auto`: only when `[simulate] plans_by_default` is on); a busy node gives the plan without it and a `note`. The UI's preview is a button.
- **Engine** (`crates/telltale/src/simulate.rs`): both sides are decided by the same steps (access, special names, local data and zones, quick rules and schedules at each row's time, list `$dnsrewrite`, the filter, the AAAA filter, group rewrites and safe search, the route): the configuration in effect against the serving snapshot, and the candidate against the serving snapshot with its stale lists masked out plus a side snapshot of only the changed lists (one background thread, compiler memory cap, removed afterwards), merged by the matcher's precedence (`Matcher::decide_ranked`, `Ranked::merge`). Re-deciding the configuration in effect, rather than reading the recorded status, keeps pauses, CNAME-target blocks, and list updates since out of the difference. Rate-limited, malformed, and dropped rows count as unchanged (refused ones are replayed: no upstream, or `allowed_networks`, decided again). Devices are identified by address; one identified by MAC or client ID keeps its logged group (`identity_from_event`). No upstream, cache, DNSSEC, or latency.
- **Output** `simulation`: `available`/`reason`, `applicable`, `from`, `to`, `rows`, `partial`, `newlyBlocked`, `newlyAllowed`, `changedRoute`, `changedAnswer` (queries, devices, top 20 names with the deciding list), `unchanged`, `undetermined`, `byDevice` (top 50), `byGroup`, `notes`, `missingNodes`. Deterministic ordering (count, then name).
- **Bounds:** one at a time per node (`409 simulation_busy`, `Retry-After`), `[simulate] max_secs` (20), `max_rows` (2,000,000), window ≤ 7 d (`422 simulation_window`). Privacy level 1: only changes to `[[client]]` (counted unchanged when the new groups decide alike, else `undetermined`); level ≥ 2 or a name-dependent change at 1: `available: false, reason: privacy_level`. `[simulate]` (`enabled`, `plans_by_default`, `max_secs`, `max_rows`, `default_window`) is a shared one-of section: Settings → System → *Change simulation*, `PUT`/`DELETE /api/v1/simulate-settings/default` (agent scope `config:write:simulate`; no MCP tool), GitOps-aware (ADR-111 pattern). Every reachable node replays its own log and the logs shipped to it (RPC `sim.run` with both configurations' shared parts, deadline `max_secs + 30`); the entry node sums them; unreachable or older nodes are `missingNodes`. `telltale_simulations_total{outcome}`, `telltale_simulation_duration_seconds`, `telltale_simulation_rows_total`. Not audited; agents need `querylog:read` (plus the change's write scope, or `config:read` for a whole configuration).
- Design: `docs/design/change-simulation.md`.

### 7.4 Device identification (OBS-025, ADR-117)
- **Inputs per device:** MAC vendor (`presets/oui.bin`, from the neighbor table, EDNS MAC, or router leases), announced names (mDNS, router DHCP), and the registrable domains it talks to (the aggregator's per-client top domains; a query-log top-K at idle priority for devices it doesn't hold).
- **Scoring** against `presets/devices.toml` (+ `[identify] signatures_file`): `0.6 × domains + 0.25 × vendor + 0.15 × hostname`; `likely` ≥ 0.6, `possibly` ≥ 0.35, else `unknown` with the vendor. Evidence always attached. Deterministic (f32, fixed ordering).
- **Runs** every 10 minutes in a background task over devices seen in the last day (`max_clients`, 1,024); results in memory and `<data_dir>/devices.json`; off at privacy level ≥ 1. `[[client]] kind` overrides; `[[group]] device_classes` turns a class into a group suggestion. Never changes a decision.
- **Surfaces:** `identity` on `GET /api/v1/clients`, `GET /api/v1/clients/identities` (every device seen), `GET /api/v1/clients/{id}/identity` (with evidence), the Clients page (sentence, evidence, the suggested group), the naming form's suggestion and "What it is" (`kind`), the Advanced dashboard's "Devices by type", new-device alerts and anomaly findings, MCP `identify_device` and `get_client_profile.identity`, `plan_assign_client` `kind`, `telltale_devices_by_class{class}`, `telltale_identify_runs_total`, `telltale_identify_duration_seconds`. Federated reads keep the highest confidence per device (`identify::merge`).
- **Details (ADR-117, amended):** vendor words match whole words; a tie with another kind of device is `possibly`, not `likely`; a pass also runs when the API asks for identities older than 15 seconds; a private (locally administered) MAC has no vendor.
- Design: `docs/design/device-identification.md`.

### 7.1 Anomaly engine rules (OBS-013, ADR-019)
- **Deterministic:** fixed-math streaming statistics only (counts, EWMA, median absolute deviation, histogram periodicity); no trained models. Time comes from event timestamps, never the wall clock, so replaying the same events yields the same alerts. Golden tests replay recorded fixtures.
- **Explainable:** every finding carries its evidence: metric, observed value, baseline (center ± spread), threshold, window, and sample query-log links. The UI and `find_anomalies` (MCP) show the numbers, not just a score.
- **Learn first:** each device needs a minimum learning period (default 7 days) before it can alert; new devices only appear in the "new client" feed until then. Baselines adapt slowly (EWMA half-life of days), so a sustained change becomes the new normal unless it was alerted on and left unacknowledged.
- **Bounded and off the hot path:** runs in the telemetry aggregator on QueryEvents, never in workers; per-client state is fixed-size (top-K, sketches, cuckoo filter); memory is capped globally, and the coldest clients' state is evicted first and counted.
- **Alert-only:** findings go to the anomalies view, alert rules (§8), and MCP. Acting on one (e.g. moving a device to a "quarantine" group) is always an explicit, audited user or agent action through the plan/apply flow; the engine itself never blocks.
- **Cluster-wide, and acknowledgeable (OBS-014, ADR-103):** each node learns from the queries it answers; the anomalies view and alert rules read every node's findings, merged by a stable finding ID. Acknowledging a finding (operator, or an agent with `ops:anomalies`) marks it seen on every node: it stops counting as new in the badge and alerts, and stays listed with who acknowledged it. The primary keeps the set and publishes it with each configuration version.
- **Tunable, with per-device opt-out:** sensitivity per group (low / normal / high maps to MAD multipliers), allowlists for known-chatty domains (OS connectivity checks, NTP), mute per device or finding. Honors the client's privacy level: at levels that hide domains, findings show eTLD+1 only, or counts only.

**Client naming:** sources merged in priority order: user-assigned name → DHCP lease (the router's, through the UniFi/OPNsense API; TelltaleDNS runs no DHCP server, ADR-091) → reverse PTR via the conditional-forwarding upstream → mDNS/NetBIOS (P2) → IP. MAC vendor lookup via a shipped OUI table.

## 8. Alerts (OBS-010)
Rule examples: upstream breaker open > 1 min; node missing from cluster > 2 min; snapshot lag > 3 versions; NXDOMAIN storm; new client seen; device anomaly (OBS-013: rate spike, domain volume, drift, beaconing); list fetch failing for > 48 h; qlog disk > 90% of budget. Destinations: webhook, ntfy, Gotify, SMTP, Slack-compatible webhook. Alerts are evaluated on the primary only, using federated data.

### 8.2 Service-level objectives (OBS-016, ADR-105)
Two objectives over every node's answers (`[slo]`, on by default): **availability**, the share of responses (any RCODE) that aren't SERVFAIL (target 99.9%), and **latency**, the share of timed queries (all but `dropped`) answered within `latency_ms` (99% within 250 ms; the threshold must be a bucket bound of `telltale_query_duration_seconds`, so Prometheus computes the same SLI). Dropped queries have no answer and count for neither.
- **Data:** the aggregator counts answers slower than the threshold in every time bucket (`slow`, stored in the rollups as a tagged section older builds skip). The status is worked out from the (federated) minute buckets of the last 6 hours and the hour buckets of the window, so it costs nothing on the query path.
- **Budget and burn:** budget = (1 − target) × answers over `window_days` (default 30); burn rate over a window = bad share ÷ (1 − target). Shown over 5m, 30m, 1h, 6h, 3d.
- **Warnings (multi-window, multi-burn-rate):** `fast` 14.4× over 1h and 5m; `slow` 6× over 6h and 30m; `ticket` 1× over 3d and 6h (shown only). A pair needs ≥ 50 answers in its short window and ≥ 10 bad answers in its long one (quiet networks). `fast`/`slow` add a degraded health reason (`slo_burn`) and fire `slo_burn` alert rules.
- **Surfaces:** `GET /api/v1/stats/slo`, MCP `slo_status`, the dashboard's Service level card (Advanced view only; owner 2026-10-09), `telltale_slo_objective_ratio{slo}` and `telltale_slo_latency_threshold_seconds`, the Helm chart's recording rules (`telltale:slo_<objective>_errors:ratio_rate<window>`) and burn-rate alerts (same windows and minimums), `deploy/prometheus/telltale-slo-rules.yaml` for non-Kubernetes Prometheus, and the Grafana dashboard's Service level row.

## 9. Synthetic probes (OBS-020, ADR-107)
Every `[probe] interval_secs` (30) a background task on each node asks each of its DNS listeners `probe.telltale.invalid` A through the listener's own protocol (the upstream client: UDP, TCP, DoT, DoH, DoH3, DoQ; wildcard binds on loopback; certificate checks off, since it connects by IP; dnstap's forwarder observer off), plus each `[probe] targets` entry (by IP). Any well-formed answer is a success; the special-name handling answers NXDOMAIN without an upstream. PROXY-protocol listeners are skipped. Each TLS listener's certificate file is read for `notAfter`.
- The telemetry thread drops records for `probe.telltale.invalid` before the analytics, the query log, the tail, and the sinks (`Record::is_probe`); the counters still count them.
- Results per target: ok, latency, error, failures in a row, last success, certificate expiry and days left. Health: 2 failures in a row → degraded `probe_failing`; every listener failing → `not_serving` (severe, softened when other nodes serve); certificate < `cert_warn_days` → degraded `cert_expiring`, expired → severe `cert_expired`. Alert rules `probe_failing`, `cert_expiring` (`threshold` in days).
- `GET /api/v1/system/probes` (federated, `Read::Probes`), MCP `probe_status`, Settings → System, `telltale_probe_success`, `telltale_probe_duration_seconds`, `telltale_probe_failures_total`, `telltale_listener_cert_expiry_timestamp_seconds`.

### 8.1 Health level (OBS-015, ADR-104)
One word for the whole deployment, from the same signals as the alert rules but with no rules configured: `severe` (an upstream group with no upstream answering, no node serving, SERVFAIL ≥ 25% of the last 5 minutes), `degraded` (one upstream down, a node unreachable, not serving, or behind for a minute, a list failing, any query rate-limited in the last 5 minutes, SERVFAIL ≥ 5%, a data disk > 90%, an objective burning its error budget fast or slow per §8.2), else `healthy`. Every node reports its own conditions (federated); the answering node adds the cluster's. Each reason carries a stable code, its node, a summary, and a UI link. Device anomalies don't count. Served at `GET /api/v1/system/health`, by the MCP tool `health`, and as the UI's health icon.
