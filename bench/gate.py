"""REQ: NFR-001, OBS-002 (`spec/00` §5) — the v1.0 release gates this machine can measure.

  python3 bench/gate.py                      # server on CPUs 0-3, dnsperf on 4-7
  python3 bench/gate.py --server-cpus 0-3 --client-cpus 4-7 --duration 20

Starts the stub upstream and a telltale server (`bench-fast` build) pinned to `--server-cpus`,
drives it with dnsperf pinned to `--client-cpus`, and measures:

  1. idle RSS without lists, and start-to-ready;
  2. cache-hit throughput (median of 3 saturating runs) and p99 at 50 % of it;
  3. telemetry loss: drops and missing events over a fixed-rate run at 75 %;
  4. with 1,000,000 blocked names: blocked-answer p99 at 50 % of the blocked maximum, RSS with
     100,000 cache entries and telemetry on, and cold start with the snapshot on disk;
  5. with 2,000,000 names: first compile and a recompile (the default thread counts);
  6. the published image's compressed size per platform.

Writes `bench/results/<UTC>-gate.json` and prints a Markdown table (target, measured, status).
Gates that need other hardware (a Pi 4, the 4-core reference machine, a cluster) are listed
as not measured here; `docs/v1-gate.md` tracks them. Pinning the server and the load generator
to separate cores keeps them from sharing a core, but they still share the machine's caches
and memory bandwidth: these are dev-host numbers, not reference-hardware numbers (`09` §3).
"""

import argparse
import datetime
import json
import os
import pathlib
import random
import signal
import statistics
import subprocess
import sys
import tempfile
import time

import bench
import corpus

HERE = bench.HERE
ROOT = bench.ROOT
URL = f"http://127.0.0.1:{bench.METRICS_PORT}"
TARGET = ("127.0.0.1", bench.DNS_PORT)
MIB = 1024


def pinned_dnsperf(cpus, tmp):
    """dnsperf on its own cores: a wrapper first on PATH (bench.dnsperf runs `dnsperf`)."""
    real = subprocess.run(["sh", "-c", "command -v dnsperf"], capture_output=True, text=True).stdout.strip()
    shim = pathlib.Path(tmp) / "bin"
    shim.mkdir()
    (shim / "dnsperf").write_text(f'#!/bin/sh\nexec taskset -c {cpus} {real} "$@"\n')
    (shim / "dnsperf").chmod(0o755)
    os.environ["PATH"] = f"{shim}:{os.environ['PATH']}"


def blocked_names(n):
    """The first `n` unique names of the bench lists (deterministic: sorted files, file order)."""
    seen, out = set(), []
    for name in corpus.blocked_names(HERE / "lists"):
        if name not in seen:
            seen.add(name)
            out.append(name)
            if len(out) == n:
                break
    if len(out) < n:
        sys.exit(f"bench/lists/ has only {len(out)} unique names; {n} needed")
    return out


class Stack:
    """The stub upstream and a pinned server with one optional plain-names list."""

    def __init__(self, args, data_dir, names_file=None):
        self.args, self.data_dir = args, pathlib.Path(data_dir)
        self.cfg = self.data_dir / "telltale.toml"
        lists = [names_file] if names_file else []
        self.cfg.write_text(bench.server_config(args.workers, data_dir, f"udp://127.0.0.1:{bench.STUB_PORT}", lists))
        self.stub = subprocess.Popen([sys.executable, str(HERE / "stub_upstream.py"), "--port", str(bench.STUB_PORT)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        bench.wait_port(bench.STUB_PORT)
        self.server = None

    def start(self):
        log = open(self.data_dir / "server.log", "a")
        t0 = time.monotonic()
        self.server = subprocess.Popen(["taskset", "-c", self.args.server_cpus, str(self.args.bin), "run", "-c",
                                        str(self.cfg)], stdout=log, stderr=subprocess.STDOUT,
                                       env=dict(os.environ, RUST_LOG="warn"))
        ready = bench.wait_ready(f"{URL}/readyz", self.server)
        return t0, ready

    def stop_server(self):
        bench.stop(self.server, "telltale")

    def close(self):
        self.stop_server()
        bench.stop(self.stub, "stub upstream")

    def rss_mib(self):
        s = bench.proc_stats(self.server.pid) or {}
        return round((s.get("rss_kib") or 0) / MIB, 1), round((s.get("hwm_kib") or 0) / MIB, 1)


def perf(datafile, seconds, args, **kw):
    return bench.measure(TARGET, datafile, seconds, threads=args.threads, clients=args.clients,
                         outstanding=args.outstanding, **kw)


def max_and_p99(datafile, args, label):
    """Median of 3 saturating runs, then p99 at 50 % of that rate."""
    perf(datafile, 5, args)  # warm the cache
    runs = [perf(datafile, args.duration, args) for _ in range(3)]
    qps = statistics.median(r["qps"] for r in runs)
    loss = max(r["loss_pct"] for r in runs)
    half = perf(datafile, args.duration, args, max_qps=int(qps / 2))
    print(f"{label}: {qps:,.0f} qps (max loss {loss}%), p99 at 50% {half['latency_us']['p99']} µs", file=sys.stderr)
    return {"qps": round(qps), "loss_pct": loss, "runs_qps": [round(r["qps"]) for r in runs],
            "p99_at_50_us": half["latency_us"]["p99"], "p50_at_50_us": half["latency_us"]["p50"],
            "loss_at_50_pct": half["loss_pct"]}


def telemetry_loss(datafile, rate, args):
    """OBS-002: counters and events under fixed-rate load; drops must stay 0."""
    names = ("telltale_telemetry_events_total", "telltale_telemetry_dropped_total", "telltale_queries_total")
    before = [bench.metric_sum(f"{URL}/metrics", n) or 0 for n in names]
    run = perf(datafile, args.duration, args, max_qps=rate)
    time.sleep(0.5)
    after = [bench.metric_sum(f"{URL}/metrics", n) or 0 for n in names]
    events, dropped, queries = (a - b for a, b in zip(after, before))
    return {"rate": rate, "qps": round(run["qps"]), "loss_pct": run["loss_pct"], "queries": queries,
            "events": events, "dropped": dropped}


def write_lines(path, lines):
    path.write_text("\n".join(lines) + "\n")
    return path


def gate_size(tag):
    proc = subprocess.run([sys.executable, str(ROOT / "deploy/image/size.py"), "--remote", tag],
                          capture_output=True, text=True, timeout=120)
    return (proc.stdout + proc.stderr).strip()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=str(ROOT / "target/bench-fast/telltale"))
    ap.add_argument("--server-cpus", default="0-3")
    ap.add_argument("--client-cpus", default="4-7")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--outstanding", type=int, default=200)
    ap.add_argument("--duration", type=int, default=20, help="seconds per measured run")
    ap.add_argument("--image", default="ghcr.io/paimonsoror/telltale:latest")
    ap.add_argument("--out", default=str(HERE / "results"))
    args = ap.parse_args()

    tmp = tempfile.TemporaryDirectory(prefix="telltale-gate-")
    pinned_dnsperf(args.client_cpus, tmp.name)
    corpora = HERE / "corpora"
    hot, _ = corpus.generate("cache-hot", corpora)
    miss, _ = corpus.generate("miss-heavy", corpora)
    r = {"schema": 1, "mode": "gate", "started": datetime.datetime.now(datetime.timezone.utc).isoformat(),
         "git": bench.git_info(), "host": bench.host_info(), "bin": bench.tool_version([args.bin, "--version"]),
         "params": {k: getattr(args, k) for k in ("server_cpus", "client_cpus", "workers", "threads", "clients",
                                                    "outstanding", "duration")}}

    # 1-3: no lists.
    d = pathlib.Path(tmp.name) / "plain"
    d.mkdir()
    st = Stack(args, d)
    try:
        t0, ready = st.start()
        r["ready_ms_no_lists"] = round((ready - t0) * 1000, 1)
        time.sleep(5)
        r["idle_rss_mib"] = st.rss_mib()[0]
        print(f"idle RSS {r['idle_rss_mib']} MiB, ready in {r['ready_ms_no_lists']} ms", file=sys.stderr)
        r["cache_hit"] = max_and_p99(hot, args, "cache-hit")
        r["telemetry"] = telemetry_loss(hot, int(r["cache_hit"]["qps"] * 0.75), args)
        print(f"telemetry: {r['telemetry']}", file=sys.stderr)
    finally:
        st.close()

    # 4: 1M blocked names.
    d = pathlib.Path(tmp.name) / "1m"
    d.mkdir()
    names = blocked_names(1_000_000)
    lst = write_lines(d / "million.txt", names)
    rng = random.Random(0x7E1A)
    blocked = write_lines(d / "blocked.corpus", [f"{rng.choice(names)} A" for _ in range(200_000)])
    fill = write_lines(d / "fill.corpus", miss.read_text().splitlines()[:100_000])
    st = Stack(args, d, lst)
    try:
        t0, ready = st.start()
        filt = bench.wait_filter(f"{URL}/metrics", st.server)
        r["compile_1m_s"] = bench.metric(f"{URL}/metrics", "telltale_filter_compile_seconds")
        r["blocked"] = max_and_p99(blocked, args, "blocked")
        perf(fill, 30, args, max_qps=20_000, once=True)
        entries = bench.metric_sum(f"{URL}/metrics", "telltale_cache_entries")
        time.sleep(3)
        rss, hwm = st.rss_mib()
        r["rss_1m_100k"] = {"rss_mib": rss, "peak_mib": hwm, "cache_entries": entries}
        print(f"1M names + {entries} cache entries: RSS {rss} MiB (peak {hwm})", file=sys.stderr)
        # Cold start with the compiled snapshot on disk: until blocked names are answered.
        st.stop_server()
        t0, ready = st.start()
        filt = bench.wait_filter(f"{URL}/metrics", st.server)
        r["cold_start_snapshot_ms"] = {"ready_ms": round((ready - t0) * 1000, 1),
                                       "filter_ms": round((filt - t0) * 1000, 1),
                                       "compile_s": bench.metric(f"{URL}/metrics", "telltale_filter_compile_seconds")}
        print(f"cold start with snapshot: {r['cold_start_snapshot_ms']}", file=sys.stderr)
    finally:
        st.close()

    # 5: 2M names, first compile and a recompile (default threads).
    d = pathlib.Path(tmp.name) / "2m"
    d.mkdir()
    lst = write_lines(d / "two-million.txt", blocked_names(2_000_000))
    st = Stack(args, d, lst)
    try:
        st.start()
        bench.wait_filter(f"{URL}/metrics", st.server)
        first = bench.metric(f"{URL}/metrics", "telltale_filter_compile_seconds")
        v0 = bench.metric(f"{URL}/metrics", "telltale_filter_snapshot_version") or 0
        with open(lst, "a") as f:
            f.write("gate-recompile.example\n")
        st.server.send_signal(signal.SIGUSR1)
        deadline = time.monotonic() + 300
        while (bench.metric(f"{URL}/metrics", "telltale_filter_snapshot_version") or 0) <= v0:
            if time.monotonic() > deadline:
                raise RuntimeError("recompile didn't finish in 300 s")
            time.sleep(0.5)
        r["compile_2m_s"] = {"first": first,
                             "recompile": bench.metric(f"{URL}/metrics", "telltale_filter_compile_seconds")}
        print(f"2M names: {r['compile_2m_s']}", file=sys.stderr)
    finally:
        st.close()
        tmp.cleanup()

    r["image_size"] = gate_size(args.image)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{datetime.datetime.now(datetime.timezone.utc):%Y%m%dT%H%M%SZ}-gate.json"
    path.write_text(json.dumps(r, indent=2) + "\n")
    print(report(r))
    print(f"\nwrote {path}", file=sys.stderr)


def report(r):
    ch, bl, tel = r["cache_hit"], r["blocked"], r["telemetry"]
    rss = r["rss_1m_100k"]
    cold = r["cold_start_snapshot_ms"]
    rows = [
        ("Cache-hit throughput, 4-core x86-64", "≥ 150k qps at < 1 % loss",
         f"{ch['qps']:,} qps, loss ≤ {ch['loss_pct']} %", ch["qps"] >= 150_000 and ch["loss_pct"] < 1),
        ("Added latency, cache hit (p99 at 50 % load)", "≤ 250 µs", f"{ch['p99_at_50_us']} µs", ch["p99_at_50_us"] <= 250),
        ("Added latency, blocked answer (p99 at 50 % load)", "≤ 250 µs", f"{bl['p99_at_50_us']} µs",
         bl["p99_at_50_us"] <= 250),
        ("Idle RSS, no lists", "≤ 20 MiB", f"{r['idle_rss_mib']} MiB", r["idle_rss_mib"] <= 20),
        ("RSS, 1M blocked names + 100k cache entries + telemetry", "≤ 64 MiB",
         f"{rss['rss_mib']} MiB ({rss['cache_entries']:.0f} entries; compile peak {rss['peak_mib']} MiB)",
         rss["rss_mib"] <= 64),
        ("Cold start to serving, snapshot on disk", "≤ 500 ms",
         f"{cold['filter_ms']} ms to blocking ({cold['ready_ms']} ms to ready)", cold["filter_ms"] <= 500),
        ("Telemetry loss at 75 % of max", "0 %",
         f"{tel['dropped']:.0f} dropped, {tel['events']:.0f} events for {tel['queries']:.0f} queries",
         tel["dropped"] == 0 and tel["events"] >= tel["queries"]),
        ("List compile, 2M names (this host, not a Pi 4)", "≤ 8 s on a Pi 4",
         f"first {r['compile_2m_s']['first']} s, recompile {r['compile_2m_s']['recompile']} s", None),
    ]
    lines = ["| Gate | Target | Measured | Status |", "|---|---|---|---|"]
    for name, target, got, ok in rows:
        status = "info" if ok is None else ("pass" if ok else "**fail**")
        lines.append(f"| {name} | {target} | {got} | {status} |")
    lines.append(f"\nImage size ({'see output'}):\n```\n{r['image_size']}\n```")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
