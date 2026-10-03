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

### 7.1 Anomaly engine rules (OBS-013, ADR-019)
- **Deterministic:** fixed-math streaming statistics only (counts, EWMA, median absolute deviation, histogram periodicity); no trained models. Time comes from event timestamps, never the wall clock, so replaying the same events yields the same alerts. Golden tests replay recorded fixtures.
- **Explainable:** every finding carries its evidence: metric, observed value, baseline (center ± spread), threshold, window, and sample query-log links. The UI and `find_anomalies` (MCP) show the numbers, not just a score.
- **Learn first:** each device needs a minimum learning period (default 7 days) before it can alert; new devices only appear in the "new client" feed until then. Baselines adapt slowly (EWMA half-life of days), so a sustained change becomes the new normal unless it was alerted on and left unacknowledged.
- **Bounded and off the hot path:** runs in the telemetry aggregator on QueryEvents, never in workers; per-client state is fixed-size (top-K, sketches, cuckoo filter); memory is capped globally, and the coldest clients' state is evicted first and counted.
- **Alert-only:** findings go to the anomalies view, alert rules (§8), and MCP. Acting on one (e.g. moving a device to a "quarantine" group) is always an explicit, audited user or agent action through the plan/apply flow; the engine itself never blocks.
- **Tunable, with per-device opt-out:** sensitivity per group (low / normal / high maps to MAD multipliers), allowlists for known-chatty domains (OS connectivity checks, NTP), mute per device or finding. Honors the client's privacy level: at levels that hide domains, findings show eTLD+1 only, or counts only.

**Client naming:** sources merged in priority order: user-assigned name → DHCP lease (own DHCP or an imported dnsmasq/ISC/Kea lease file, or the UniFi/OPNsense API as a P2 integration) → reverse PTR via the conditional-forwarding upstream → mDNS/NetBIOS (P2) → IP. MAC vendor lookup via a shipped OUI table.

## 8. Alerts (OBS-010)
Rule examples: upstream breaker open > 1 min; node missing from cluster > 2 min; snapshot lag > 3 versions; NXDOMAIN storm; new client seen; device anomaly (OBS-013: rate spike, domain volume, drift, beaconing); list fetch failing for > 48 h; qlog disk > 90% of budget. Destinations: webhook, ntfy, Gotify, SMTP, Slack-compatible webhook. Alerts are evaluated on the primary only, using federated data.
