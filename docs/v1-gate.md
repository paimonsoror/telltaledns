# The v1.0 release gate

Where TelltaleDNS stands against the v1.0 release gate (`spec/10` M6, `spec/00` §5). 0.1.0 is
the first stable release; 1.0 waits until every row below passes on the reference hardware.
This page records each target, the latest measurement, how it was taken, and the status.

**Last run:** 2026-10-07, `python3 bench/gate.py` at 60a2c30 (0.2.0 development), results in
`bench/results/20261007T140130Z-gate.json` (not committed; reproduce with the same command).

## How it was measured

- **Host:** the development laptop (AMD Ryzen 5 5500U, WSL2, 4 cores / 8 threads, 7.6 GiB).
  The server ran on CPUs 0–3 (two physical cores, `taskset`) with 4 workers; dnsperf ran on
  CPUs 4–7 (the other two). They don't share a core, but they do share caches, memory
  bandwidth, and WSL's scheduler.
- **These are dev-host numbers.** The gate needs the load generator on separate hardware and
  the 4-core reference machine (`spec/09` §2–3). Throughput here is conservative (two
  physical cores, not four). Tail latency is not trustworthy here: WSL's scheduling puts
  millisecond spikes into the client's measurements.
- **Lists:** the first 1,000,000 and 2,000,000 unique names of the fixed bench snapshot
  (`bench/lists/`: HaGeZi Pro and TIF, OISD big, AdGuard DNS, StevenBlack), as plain lists.

## Performance and footprint (`spec/00` §5)

| Target | Gate | Measured | Status |
|---|---|---|---|
| Cache-hit throughput, 4-core x86-64 | ≥ 150k qps at < 1 % loss | 170.6k qps, 0 % loss (median of 3; 2 physical cores) | ✅ pass (dev host) |
| Cache-hit throughput, Raspberry Pi 4 | ≥ 25k qps | not measured | ⏳ needs a Pi 4 that isn't serving the home network |
| Added latency, cache hit (p99 at 50 % load) | ≤ 250 µs | p50 101 µs, **p99 4.2 ms** | ❌ unproven: needs a separate load generator |
| Added latency, blocked answer (p99 at 50 % load) | ≤ 250 µs | p50 125 µs, **p99 2.0 ms** | ❌ unproven: same |
| Idle RSS, no lists | ≤ 20 MiB | 18.8 MiB with the shipped binary (v0.1.0, musl); 25.2 MiB with the bench build, which carries more code | ✅ pass (shipped binary) |
| RSS, 1M blocked names + 100k cache entries + telemetry | ≤ 64 MiB | **84.2 MiB** after T10.2 so far (was 130.4; bench build, `bench/memprobe.py`) | ❌ fail |
| Compressed container image | ≤ 15 MiB per arch | amd64 11.1, arm64 10.6, arm/v7 11.0 MiB (`:latest` = 0.1.0) | ✅ pass |
| List recompile, 2M names, Pi 4 | ≤ 8 s, p99 regression ≤ 10 % during the compile | this host: 2.0 s first compile, 3.1 s recompile. Pi 4 (2026-10-03): 6.4 s on 2 threads, **11.6 s on 1 thread (the recompile default)**. p99 under a recompile: within noise on the homelab (T2.7) | ❌ the Pi recompile misses |
| Cold start to serving, snapshot on disk | ≤ 500 ms | **565 ms** until blocking works (53 ms until it answers). A cluster replica in CI: ≤ 500 ms | ❌ fail (by 65 ms) |
| Query-log search, 30 days / 50M rows, Pi 4 | ≤ 2 s | every query in the suite under 2 s (T3.2, 2026-10-03) | ✅ pass (re-run before 1.0) |
| Config propagation, primary → all nodes incl. a cross-site Pi | ≤ 5 s p95 | under 5 s on loopback in CI (single samples) | ⏳ cross-site p95 not measured |
| DNS availability with the primary down | 100 % | 100 % of a steady load while the primary is killed (CI, `deploy/cluster/e2e.sh`) | ✅ pass |
| Primary failover with a witness | writes back ≤ 30 s | elected within 30 s, 100 % DNS answered (CI, `deploy/cluster/failover-e2e.sh`) | ✅ pass |
| Telemetry loss under sustained load | 0 % for counters and histograms | 0 dropped; 2,475,363 events for 2,475,363 queries at 75 % of max | ✅ pass |

On the live Pi 4 (2.7M blocked names from the cluster's lists, a small cache), the process
used 82 MiB (97 MiB peak) on 2026-10-07 before the T10.2 work and 49.6 MiB (68 MiB peak) after
it (edge 185). The project's earlier "about 60 MB" figure was out of date; the published
figure is now about 50 MB.

## The rest of the gate

| Item | Status |
|---|---|
| All P0 requirements pass | ⏳ not yet checked requirement by requirement |
| Comparative benchmark report published | ⏳ owner decision needed: the project doesn't compare itself with other resolvers in public text |
| Security review of sign-in, the cluster, and the parsers | ⏳ not started |

## Next

Tracked as M10 in `spec/10-roadmap-and-tasks.md`: find where the memory goes (idle, and with
1M names), make the recompile meet 8 s on a Pi 4, bring the cold start under 500 ms, measure
latency and Pi throughput on separate hardware, measure cross-site propagation, the
requirement-by-requirement check, and the security review.
