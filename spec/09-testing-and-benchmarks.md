# 09 — Testing, Conformance, Benchmarks

## 1. Test pyramid
| Layer | Tooling | Scope |
|---|---|---|
| Unit | `cargo test`, `proptest` | Parser round-trips; TTL patching; FST walk; rule precedence table; strategy selection; epoch/fencing state machine |
| Golden | `insta` snapshots | List parsing of real-world lists (vendored fixtures: StevenBlack, HaGeZi Pro, OISD small, an AdGuard DNS filter, Pi-hole regex samples) → canonical compiled-rule dumps |
| Integration | In-process server + `hickory-client`; `testcontainers` for upstream fakes | Full pipeline per transport (UDP/TCP/DoT/DoH/DoQ); serve-stale; prefetch; DNSSEC (with a local signed zone via Knot in a container); CNAME inspection; schedules with a mocked clock |
| Conformance | `dnsperf`-independent checks: **DNS Flag Day** EDNS compliance checker (`ednscomp`-style), RFC 8914 EDE presence, `kdig`-driven scripts | Protocol correctness |
| Fuzz (NFR-004) | `cargo-fuzz` (libFuzzer) | Wire parser, response patcher, each list parser, rule compiler, snapshot loader (malformed manifests/blobs), API JSON |
| Allocation (NFR-002) | Counting global allocator in a test build | Asserts zero allocations across 100k cache hits and 100k blocked answers after warmup |
| Cluster | `telltale-sim`: a deterministic simulation of N nodes with a virtual network and clock (turmoil-style) + a docker-compose chaos suite (toxiproxy) | §12.10 matrix; linearizable change log check (no two primaries accept writes in the same epoch) |
| E2E UI | Playwright | Login/2FA; pause; list add; explain; cluster promote |
| Helm | `helm lint`, `kubeconform`, `ct install` on kind (amd64) and k3d (arm64 runner) | Chart renders; pods ready; DNS answers through the LB; ServiceMonitor scraped |

## 2. Performance harness (NFR-001) — `bench/`
- **Tools:** `dnsperf` and `resperf` (DNS-OARC), `flamethrower` for DoH/DoT, and `kdig` for spot checks. Collect results as JSON.
- **Corpora** (generated, committed with seeds):
  1. `cache-hot`: 10k names, Zipf s=1.0, after warmup (cache-hit path).
  2. `blocked`: names drawn 100% from the loaded blocklists.
  3. `realistic-home`: a 24 h replay with a mix (~65% cache hit, 15–25% blocked, the rest misses), derived from anonymized real distributions (domains replaced with synthetic ones of matching length/label distribution).
  4. `miss-heavy`: unique random subdomains of a local authoritative fake (measures the upstream path with a local NSD/Knot upstream at fixed 0 ms and 20 ms netem delay).
- **Lists:** fixed snapshot of HaGeZi Pro + OISD big + StevenBlack (~1–1.5M unique domains) + 500 regexes, versioned in `bench/lists/` (as a downloadable artifact, not in git).
- **Metrics captured:** qps at < 1% loss (resperf ramp), latency percentiles at 25/50/75% of max, RSS (idle/peak via cgroup `memory.peak`), CPU %, list compile time, cold-start time, image size.
- **Hardware matrix:** x86-64 4-core (CI self-hosted or a fixed cloud instance type), Raspberry Pi 4 4 GB (self-hosted runner), Pi Zero 2 W (manual, per release).
- **Regression gate:** on every PR, the `cache-hot` and `blocked` runs on x86 must stay within 5% of `main` (the machine is noisy, so 3 runs and take the median). Nightly runs everything.

## 3. Comparative benchmark (analysis §5)
`bench/compare/` brings up **Pi-hole (latest v6 image)**, **Technitium (latest image)**, and **TelltaleDNS** on the same host with:
- the same lists (Pi-hole adlists, Technitium block-list URLs, TelltaleDNS lists, all served from a local HTTP fixture server),
- the same upstream (local Knot/NSD fake),
- logging at each product's default and with "full query logging" enabled.

It runs the corpora and produces `bench/compare/report.md` (tables + charts): throughput, p50/p99 latency, RSS, CPU, list-update duration, and query-latency impact during a list update.

**Rule:** the README and the executive summary may only cite numbers produced by this harness, with hardware and versions listed.

## 4. CI pipeline
fmt → clippy (`-D warnings`, pedantic subset) → test (linux x86_64 + aarch64 via QEMU for unit tests) → cargo-deny → build images (multi-arch) → integration + helm on kind → bench gate → SBOM + sign (release only). Nightly: fuzz (30 min per target), full bench, cluster chaos suite, comparative bench (weekly).
