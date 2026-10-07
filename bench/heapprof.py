"""REQ: NFR-002 (T10.2) — which code holds the heap after a burst of unique names.

  cargo build --profile bench-fast -p telltale --features dhat-heap   # with symbols, see below
  python3 bench/heapprof.py --bin target/bench-fast/telltale --fill 100000

Runs a `dhat-heap` build (no lists, so the compile's peak doesn't dominate) against the stub
upstream, sends `--fill` unique names at `--rate`, waits, stops the server cleanly so dhat
writes `dhat-heap.json`, and prints the allocation sites holding the most bytes at the heap's
peak (which, without lists, is right after the fill), grouped by their first TelltaleDNS frames.
Build with symbols: `CARGO_PROFILE_BENCH_FAST_STRIP=false CARGO_PROFILE_BENCH_FAST_DEBUG=1`.
"""

import argparse
import collections
import json
import os
import pathlib
import re
import sys
import tempfile
import time

import bench
import gate


def frames(ftbl, idxs, depth):
    """The first `depth` frames in TelltaleDNS code, shortened."""
    out = []
    for i in idxs:
        f = ftbl[i]
        if "telltale" not in f or "dhat" in f:
            continue
        m = re.search(r": (.*?) \((.*?)\)$", f)
        fn, loc = (m.group(1), m.group(2)) if m else (f, "")
        fn = re.sub(r"<[^<>]*>", "", re.sub(r"<[^<>]*>", "", fn))  # drop generics
        loc = re.sub(r".*/crates/", "", loc)
        out.append(f"{fn} ({loc})")
        if len(out) == depth:
            break
    return out or ["(no TelltaleDNS frame)"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=str(bench.ROOT / "target/bench-fast/telltale"))
    ap.add_argument("--server-cpus", default="0-3")
    ap.add_argument("--client-cpus", default="4-7")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--outstanding", type=int, default=200)
    ap.add_argument("--fill", type=int, default=100_000)
    ap.add_argument("--rate", type=int, default=5_000)
    ap.add_argument("--extra", default="", help="TOML appended to the config (`\\n` between lines)")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--depth", type=int, default=3)
    args = ap.parse_args()

    tmp = tempfile.TemporaryDirectory(prefix="telltale-heap-")
    gate.pinned_dnsperf(args.client_cpus, tmp.name)
    d = pathlib.Path(tmp.name) / "run"
    d.mkdir()
    miss, _ = gate.corpus.generate("miss-heavy", bench.HERE / "corpora")
    fill = gate.write_lines(d / "fill.corpus", miss.read_text().splitlines()[:args.fill])
    st = gate.Stack(args, d)
    if args.extra:
        st.cfg.write_text(st.cfg.read_text() + "\n" + args.extra.replace("\\n", "\n") + "\n")
    os.chdir(d)  # dhat writes dhat-heap.json into the server's working directory
    try:
        st.start()
        time.sleep(2)
        seconds = args.fill // args.rate + 30
        gate.perf(fill, seconds, args, max_qps=args.rate, once=True)
        time.sleep(3)
        rss = st.rss_mib()
        print(f"after {args.fill:,} names: RSS {rss[0]} MiB (peak {rss[1]})", file=sys.stderr)
    finally:
        st.close()
    out = d / "dhat-heap.json"
    for _ in range(100):
        if out.exists() and out.stat().st_size > 0:
            break
        time.sleep(0.2)
    data = json.loads(out.read_text())
    ftbl, pps = data["ftbl"], data["pps"]
    total = sum(p["gb"] for p in pps)
    print(f"heap at its peak: {total / 1048576:.1f} MiB in {sum(p['gbk'] for p in pps):,} blocks")
    groups = collections.defaultdict(lambda: [0, 0])
    for p in pps:
        if p["gb"]:
            key = " <- ".join(frames(ftbl, p["fs"], args.depth))
            groups[key][0] += p["gb"]
            groups[key][1] += p["gbk"]
    for key, (b, k) in sorted(groups.items(), key=lambda kv: -kv[1][0])[:args.top]:
        print(f"{b / 1048576:7.2f} MiB {k:9,} blocks  {key}")
    tmp.cleanup()


if __name__ == "__main__":
    sys.exit(main())
