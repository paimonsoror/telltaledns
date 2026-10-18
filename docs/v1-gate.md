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
| Idle RSS, no lists | ≤ 20 MiB | 13.7 MiB 40 s after start, 16.1 MiB after 3 min (the shipped musl build, T10.2, `bench/memprobe.py`; 22.7 MiB before) | ✅ pass |
| RSS, 1M blocked names + 100k cache entries + telemetry | ≤ 64 MiB | 60.0 MiB 40 s after the fill, 60.9 MiB after 3 min; peak 97.5 MiB during the compile (the shipped musl build; 71.4 MiB and a 170 MiB peak before T10.2's last step, 130.4 MiB at its start) | ✅ pass |
| Compressed container image | ≤ 15 MiB per arch | amd64 11.1, arm64 10.6, arm/v7 11.0 MiB (`:latest` = 0.1.0) | ✅ pass |
| List recompile, 2M names, Pi 4 | ≤ 8 s, p99 regression ≤ 10 % during the compile | Pi 4 (2026-10-17, the gate's 2M names, `compile_bench`, bench build): **11.8 s on 1 thread** (the recompile default; 14.2 s before T10.3's parser fast path), 9.7 s on 2 threads; building the FST alone takes 8.1 s on one Pi core. p99 under a recompile on 4 cores (VM, `bench.py swap --server-cpus 0-3`): 44 → 49.5 µs on 1 thread, 40.5 → 54 µs on 2 | ❌ the Pi recompile misses: one thread can't build the FST inside 8 s |
| Cold start to serving, snapshot on disk | ≤ 500 ms | 52 ms until a blocked name is answered blocked over DNS, 1M names (median of 5, the shipped build, `bench/coldstart.py`); the lookup index follows at about 0.5 s, blocking through the FST walk until then. A cluster replica in CI: ≤ 500 ms | ✅ pass |
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
| All P0 requirements pass | ⚠️ checked (T10.6, `docs/v1-requirements.md`, kept current by CI): all 73 have tests or evidence, 66 with named tests. **Open:** NFR-005's `cargo-auditable` builds, CycloneDX SBOM, cosign-signed images, and reproducibility check (T10.10) |
| Comparative benchmark report published | ✅ decided (owner, 2026-10-17): TelltaleDNS publishes its own numbers and the exact method (hardware, load, corpus) so anyone can reproduce or compare them; no side-by-side with other resolvers |
| Security review of sign-in, the cluster, and the parsers | ✅ done (T10.7, `docs/security-review.md`): 17 findings fixed with regression tests (2 high, in the cluster channel); accepted items and missing fuzz targets listed there |

## Next

Tracked as M10 in `spec/10-roadmap-and-tasks.md`: make the recompile meet 8 s on a Pi 4, measure
latency and Pi throughput on separate hardware, measure cross-site propagation, and the
supply-chain items NFR-005 still lacks (T10.10).
