# Pass 04: telemetry, storage, observability

**Output:** `docs/review/v0.2.0/04-observability.md` (+ `patches/04-*`)

## Scope
Seeing what the resolver does: per-query events, metrics, the query log, rollups, the live
tail, analytics (vqlog), anomaly detection, alerts, and exports.

- `crates/telltale-telemetry/` (event rings `ring.rs`, aggregator `agg.rs`, top-K, anomaly
  detection, DGA scoring, Prometheus rendering)
- `crates/telltale-store/` (the columnar query log `qlog/`, rollups, `state/` = state.db)
- `crates/telltale/src/`: `http.rs` (metrics endpoint), `tail.rs`, `rollups.rs`,
  `qlog_cli.rs`, `vqlog.rs`, `alerts.rs`, `anomaly.rs`, `smtp.rs`, `sinks.rs`, `otlp.rs`,
  `dnstap.rs`, `cache_history.rs`, `host/`
- `deploy/grafana/`, the chart's ServiceMonitor and PrometheusRule

## Read first
1. `spec/06-observability.md`; ADR-019, ADR-026, ADR-027, ADR-031, ADR-043, ADR-072,
   ADR-073, ADR-076, ADR-077, ADR-082, ADR-085, ADR-089.
2. `ring.rs` (how events leave the hot path) → `agg.rs` → `crates/telltale-store/src/qlog/`
   (`writer.rs`, `search.rs`).

## Look for
- **Never blocking DNS:** bounded queues everywhere, drops counted and exported (OBS-002),
  nothing on the query path waits for disk, network, or a slow sink.
- **Accuracy:** counters that can drift (e.g. "failure" in upstream metrics mixes causes),
  histograms and percentiles (merging across cluster nodes), rollups across restarts,
  time zones and hour boundaries, retention by age and size.
- **Query log:** format robustness (corrupt segments, partial writes, power loss on a Pi SD
  card), search performance and correctness, privacy levels, the dictionary cap per part
  (16,384 names since 0.2.0).
- **Cardinality and footprint:** label sets in Prometheus output, memory of top-K and
  anomaly state, per-client data growth.
- **Alerts and sinks:** retries, backoff, secrets in logs, email/webhook failure modes.
- **Operator experience:** are the metrics and logs enough to diagnose a real incident
  (try: an upstream failing, a disk filling, a slow sink)?

## Threat surface
Log injection, secrets or client data leaking into logs, exports, or metrics labels;
unbounded memory from attacker-chosen names (unique-name floods).

## Useful
```sh
cargo test -p telltale-telemetry; cargo test -p telltale-store
python3 bench/bench.py sustain --rate 50000 --duration 30     # telemetry loss under load
bash deploy/sinks-e2e.sh                                       # if prerequisites are present
```
