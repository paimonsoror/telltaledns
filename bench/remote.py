"""REQ: NFR-001 (T10.5) — the latency gates (`spec/00` §5: p99 ≤ 250 µs at 50 % load, cache hit
and blocked answer) with the load generator on another machine.

  python3 bench/remote.py --target 192.168.5.2:15300 --metrics http://192.168.5.2:19153/metrics

The server must already run with the blocked names of `--names` (default 1M, the first unique
names of bench/lists, as `gate.py` writes them) and an upstream that answers anything. For each
corpus (cache-hot, then blocked) this finds the saturating rate (median of 3 runs), then runs at
half of it and reads two latencies:

  - the server's own: `telltale_query_duration_seconds` (receive → answer ready), the delta of
    two scrapes around the run, for the path the corpus takes. The gate is met when at least
    99 % of those queries fall in the 250 µs bucket. This is the "added latency" figure.
  - end to end: dnsperf's p99, which includes the network between the machines.
"""

import argparse
import re
import statistics
import sys
import tempfile
import pathlib
import random
import time
import urllib.request

import bench
import corpus
import gate


def histogram(url):
    """Cumulative `telltale_query_duration_seconds` buckets: {path: [(le, count), ...]}."""
    with urllib.request.urlopen(url, timeout=5) as r:
        body = r.read().decode()
    out = {}
    for path, le, n in re.findall(
        r'^telltale_query_duration_seconds_bucket\{path="(\w+)",le="([^"]+)"\} (\d+)', body, re.M
    ):
        out.setdefault(path, []).append((float("inf") if le == "+Inf" else float(le), int(n)))
    return out


def server_latency(before, after):
    """Per path: queries in the window, the share within 250 µs, and the p99 bucket bound."""
    res = {}
    for path, buckets in after.items():
        prev = dict(before.get(path, []))
        delta = [(le, n - prev.get(le, 0)) for le, n in buckets]
        total = delta[-1][1] if delta else 0
        if total <= 0:
            continue
        within = next(n for le, n in delta if abs(le - 0.00025) < 1e-9)
        p99 = next(le for le, n in delta if n >= 0.99 * total)
        res[path] = {"queries": total, "within_250us_pct": round(100 * within / total, 3),
                     "p99_bucket_us": None if p99 == float("inf") else round(p99 * 1e6)}
    return res


def run(datafile, args, label):
    target = (args.host, args.port)
    common = dict(threads=args.threads, clients=args.clients, outstanding=args.outstanding)
    bench.dnsperf(target, datafile, 5, **common)  # warm the cache
    runs = [bench.parse_dnsperf(bench.dnsperf(target, datafile, args.duration, **common)) for _ in range(3)]
    qps = statistics.median(r["qps"] for r in runs)
    before = histogram(args.metrics)
    half = bench.parse_dnsperf(bench.dnsperf(target, datafile, args.duration, **common, max_qps=int(qps / 2)))
    time.sleep(1)
    lat = server_latency(before, histogram(args.metrics))
    print(f"{label}: max {qps:,.0f} qps (loss up to {max(r['loss_pct'] for r in runs)} %); at 50 %: "
          f"{half['qps']:,.0f} qps, loss {half['loss_pct']} %, end-to-end p50 {half['latency_us']['p50']} µs, "
          f"p99 {half['latency_us']['p99']} µs; server {lat}")
    return {"max_qps": round(qps), "at_50": half, "server": lat}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="host:port of the server's UDP listener")
    ap.add_argument("--metrics", required=True, help="its /metrics URL")
    ap.add_argument("--names", type=int, default=1_000_000)
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--outstanding", type=int, default=200)
    ap.add_argument("--duration", type=int, default=20)
    args = ap.parse_args()
    args.host, port = args.target.rsplit(":", 1)
    args.port = int(port)

    hot, _ = corpus.generate("cache-hot", bench.HERE / "corpora")
    names = gate.blocked_names(args.names)
    rng = random.Random(0x7E1A)
    tmp = tempfile.TemporaryDirectory(prefix="telltale-remote-")
    blocked = gate.write_lines(pathlib.Path(tmp.name) / "blocked.corpus",
                               [f"{rng.choice(names)} A" for _ in range(200_000)])
    print(f"target {args.target}; index built: {bench.metric(args.metrics, 'telltale_filter_lookup_index_bytes')}")
    results = {"cache_hit": run(hot, args, "cache hit"), "blocked": run(blocked, args, "blocked")}
    print(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
