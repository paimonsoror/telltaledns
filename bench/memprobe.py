"""REQ: NFR-002 (T10.2) — where the server's memory goes, for the RSS gates in `spec/00` §5.

  python3 bench/memprobe.py                 # idle without lists, then 1M names + 100k entries
  python3 bench/memprobe.py --names 0       # idle only

Starts the stub upstream and a server the way `gate.py` does, and at each stage prints RSS split
by mapping (from /proc/<pid>/smaps: anonymous heap, thread stacks, the mapped list snapshot,
the binary's own pages) next to the server's counters (cache bytes and entries, lookup index
bytes), so a number in the gate table can be traced to what holds it.
"""

import argparse
import collections
import os
import pathlib
import re
import sys
import tempfile
import time

import bench
import gate

URL = gate.URL


def smaps(pid):
    """RSS and anonymous KiB per mapping kind."""
    out = collections.defaultdict(lambda: [0, 0, 0])  # rss, anon, count
    kind = None
    for line in pathlib.Path(f"/proc/{pid}/smaps").read_text().splitlines():
        m = re.match(r"^[0-9a-f]+-[0-9a-f]+ \S+ \S+ \S+ \d+\s*(.*)$", line)
        if m:
            path = m.group(1).strip()
            if not path:
                kind = "anon (heap, allocator arenas)"
            elif path.startswith("[stack"):
                kind = "main stack"
            elif path.startswith("["):
                kind = path
            elif "telltale" in path and ("/target/" in path or "/rel/" in path):
                kind = "binary (text, rodata, embedded UI)"
            elif path.endswith((".snap", ".fst", ".idx")) or "/filter/" in path or "snapshot" in path:
                kind = f"mapped: {pathlib.Path(path).name}"
            else:
                kind = f"file: {pathlib.Path(path).name}"
            out[kind][2] += 1
            continue
        if kind and line.startswith("Rss:"):
            out[kind][0] += int(line.split()[1])
        elif kind and line.startswith("Anonymous:"):
            out[kind][1] += int(line.split()[1])
    return out


def threads(pid):
    names = collections.Counter()
    for t in pathlib.Path(f"/proc/{pid}/task").iterdir():
        try:
            names[re.sub(r"\d+$", "N", (t / "comm").read_text().strip())] += 1
        except OSError:
            pass
    return names


def counters():
    m = lambda n: bench.metric_sum(f"{URL}/metrics", n)  # noqa: E731
    return {"cache_bytes": m("telltale_cache_bytes"), "cache_entries": m("telltale_cache_entries"),
            "index_bytes": m("telltale_filter_lookup_index_bytes"), "rules": m("telltale_filter_rules")}


def report(stage, pid):
    total = bench.proc_stats(pid) or {}
    print(f"\n== {stage}: RSS {total.get('rss_kib', 0) / 1024:.1f} MiB (peak {total.get('hwm_kib', 0) / 1024:.1f})")
    rows = sorted(smaps(pid).items(), key=lambda kv: -kv[1][0])
    for kind, (rss, anon, n) in rows:
        if rss >= 256:
            print(f"  {rss / 1024:7.1f} MiB  (anon {anon / 1024:6.1f})  {n:4d} maps  {kind}")
    c = counters()
    print("  counters: " + ", ".join(f"{k}={v / 1048576:.1f} MiB" if k.endswith("bytes") and v else f"{k}={v}"
                                     for k, v in c.items()))
    print("  threads: " + ", ".join(f"{n}x{k}" for k, n in threads(pid).most_common()))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=str(bench.ROOT / "target/bench-fast/telltale"))
    ap.add_argument("--server-cpus", default="0-3")
    ap.add_argument("--client-cpus", default="4-7")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--names", type=int, default=1_000_000)
    ap.add_argument("--fill", type=int, default=100_000)
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--outstanding", type=int, default=200)
    ap.add_argument("--duration", type=int, default=20)
    ap.add_argument("--extra", default="", help="TOML appended to the server config (e.g. to turn a feature off)")
    ap.add_argument("--settle", type=int, default=30, help="seconds to wait before a last sample")
    args = ap.parse_args()
    tmp = tempfile.TemporaryDirectory(prefix="telltale-mem-")
    gate.pinned_dnsperf(args.client_cpus, tmp.name)

    d = pathlib.Path(tmp.name) / "plain"
    d.mkdir()
    st = gate.Stack(args, d)
    try:
        st.start()
        time.sleep(5)
        report("idle, no lists", st.server.pid)
    finally:
        st.close()
    if not args.names:
        return

    d = pathlib.Path(tmp.name) / "lists"
    d.mkdir()
    lst = gate.write_lines(d / "names.txt", gate.blocked_names(args.names))
    miss, _ = gate.corpus.generate("miss-heavy", bench.HERE / "corpora")
    fill = gate.write_lines(d / "fill.corpus", miss.read_text().splitlines()[:args.fill])
    st = gate.Stack(args, d, lst)
    if args.extra:
        # `--extra` takes `\n` (two characters) between lines, so it fits on a command line.
        st.cfg.write_text(st.cfg.read_text() + "\n" + args.extra.replace("\\n", "\n") + "\n")
    try:
        st.start()
        bench.wait_filter(f"{URL}/metrics", st.server)
        time.sleep(6)
        report(f"{args.names:,} names, compiled, empty cache", st.server.pid)
        gate.perf(fill, 30, args, max_qps=20_000, once=True)
        time.sleep(3)
        report(f"+ {args.fill:,} cache fills", st.server.pid)
        if args.settle:
            time.sleep(args.settle)
            report(f"{args.settle} s later", st.server.pid)
    finally:
        st.close()
        tmp.cleanup()


if __name__ == "__main__":
    sys.exit(main())
