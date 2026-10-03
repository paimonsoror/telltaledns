# bench/ — performance harness (NFR-001, `spec/09` §2)

```sh
make bench-smoke                 # cache-hot + miss-heavy, one run each (~40 s)
make bench-full                  # every available corpus, 3 runs, 25/50/75% load points
bench/run.sh smoke --baseline bench/results/<main>.json   # fail on > 5% regression
python3 bench/bench.py compare base.json new.json         # compare two result files
bench/run.sh smoke --target 192.0.2.53:53                 # bench any running DNS server
```

Requires `dnsperf` (DNS-OARC, `apt install dnsperf`) and Python 3.10+ (standard library only).

## What a run does
1. Generates the corpora with `corpus.py` from fixed seeds into `bench/corpora/` (git-ignored;
   the same seed always yields the same file, and its SHA-256 is recorded in the results).
2. Starts `stub_upstream.py` on `127.0.0.1:5301`: a fake authoritative server that answers
   A/AAAA with deterministic addresses from the RFC 2544/5180 benchmarking ranges (TTL 3600)
   and everything else with NODATA + SOA. `--upstream-delay-ms 20` stands in for netem.
3. Starts `telltale run` (the `bench-fast` profile, thin LTO) on `127.0.0.1:5300` with 4
   workers and waits for `/readyz`.
4. For each corpus: a warmup run, a saturating dnsperf run (throughput), then fixed-rate runs at
   a share of that maximum (latency; `00 §5` gates p99 at 50% load). Saturated latency is
   mostly queueing inside dnsperf and the socket buffers, so don't read it as server latency.
5. Writes `bench/results/<UTC timestamp>-<mode>.json` and fails on > 1% loss or, with
   `--baseline`, on a qps drop or p99@50% rise beyond `--tolerance` (default 5%).

## Corpora
| Corpus | Status | Shape |
|---|---|---|
| `cache-hot` | ready | 10k names, Zipf s=1.0, 62% A / 30% AAAA / 8% HTTPS |
| `miss-heavy` | ready | unique names, each sent once at a fixed 2000 qps (upstream path latency) |
| `blocked` | needs lists | names sampled from `bench/lists/*.txt` (plain or hosts format) |
| `realistic-home` | needs lists | home mix: Zipf cache-hot names, blocked names, and unique misses |

`bench/lists/` holds the fixed blocklist snapshot (HaGeZi Pro + OISD big + StevenBlack). It's a
downloaded artifact, not in git.

## Swap under load (T2.7)
`bench.py swap` checks that a filter recompile doesn't disturb queries. It starts the server with the lists in `bench/lists/*.txt` plus a small `swap.txt`, then runs the `realistic-home` corpus at a fixed rate (`--rate`, default 20k qps) in pairs of windows: a quiet one, and one where a recompile is triggered `--at` seconds in. The order alternates each round to cancel drift. `--trigger list` (default) rewrites `swap.txt` and sends `SIGUSR1`; `--trigger reload` adds an inline list and sends `SIGHUP`. It fails if the median p99 over rounds rises more than `--max-regression` (10%), or on any lost query, SERVFAIL, or server exit. The server log is saved as `swap-server.log` in `--out`. `--compile-threads` overrides `[filter] compile_threads`.

```sh
python3 bench/bench.py swap --rounds 10 --rate 20000
```
Run it on a machine with spare cores (the homelab, not the Pi). Quiet-window p99 varies a lot between rounds on a shared host, so use at least 8 rounds.

## Results JSON (schema 1)
Top level: `mode`, `started`, `git` (rev, dirty), `host` (cpu, cores, arch, kernel), `tools`,
`params`, `server` (version, workers, `ready_ms`, `idle_rss_kib`, `peak_rss_kib`), `runs[]`, and
`summary` (per-corpus medians). Each run has `qps`, `sent/completed/lost`, `loss_pct`, `rcodes`,
`latency_us` (avg/min/max/stddev/p50/p90/p99/p999, from dnsperf's latency histogram, upper bucket
edge), server `rss_kib`/`peak_rss_kib`/`cpu_pct`, and `at_load.{25,50,75}`.

## Reading the numbers
Running dnsperf on the same machine as the server shares CPUs and caches. Those numbers are fine
for comparing commits on one machine. Release gates (`00 §5`) need the load generator on separate
hardware, as in the `09` hardware matrix. Only numbers from this harness may be quoted in the
README or the site (`09` §3).

Not yet: `resperf` ramp for max qps at < 1% loss, cgroup `memory.peak`, `flamethrower` for DoT/DoH,
the `compare/` stack (Pi-hole, Technitium), and the Pi 4 runner.
