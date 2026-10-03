#!/usr/bin/env python3
"""TelltaleDNS performance harness (spec/09 §2, NFR-001).

  bench.py run smoke            quick gate: cache-hot + miss-heavy, one run each
  bench.py run full             every available corpus, 3 runs each, medians reported
  bench.py run smoke --target 192.0.2.53:53     bench any external DNS server instead
  bench.py compare base.json new.json           regression gate (default ±5%)

By default the harness starts the stub upstream (stub_upstream.py) and a telltale server
on loopback, drives it with dnsperf, and writes results JSON to bench/results/.
"""

import argparse
import datetime
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request

import corpus

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
SCHEMA = 1

# Ports for the local stack; chosen to avoid :53 so the harness never needs root.
DNS_PORT = 5300
STUB_PORT = 5301
METRICS_PORT = 9153

MODES = {
    # REQ: NFR-001 — `make bench-smoke` (AGENTS.md rule 4): short, single run, fails on errors.
    "smoke": {"corpora": ["cache-hot", "miss-heavy"], "duration": 8, "runs": 1, "warmup": 2, "load_points": [50]},
    # Nightly / release: every corpus whose inputs are present, median of 3 (09 §2 regression gate).
    "full": {"corpora": ["cache-hot", "miss-heavy", "blocked"], "duration": 30, "runs": 3, "warmup": 5,
             "load_points": [25, 50, 75]},
}

# miss-heavy measures latency through the upstream path, not throughput: the Python stub
# would saturate long before the server, so the offered load is fixed.
MISS_QPS = 2000

# Saturated (closed-loop) runs measure throughput; their latency is mostly queueing. Latency
# gates (00 §5: p99 ≤ 250 µs at 50% of max) come from fixed-rate runs at these percentages of
# the measured max qps.

# Gate thresholds for a single smoke run on loopback. Loss on cache hits means something is
# broken, not slow.
MAX_LOSS_PCT = {"cache-hot": 1.0, "miss-heavy": 1.0, "blocked": 1.0}


# ---------------------------------------------------------------------------- dnsperf

STAT_RE = {
    "sent": re.compile(r"Queries sent:\s+(\d+)"),
    "completed": re.compile(r"Queries completed:\s+(\d+)"),
    "lost": re.compile(r"Queries lost:\s+(\d+)"),
    "qps": re.compile(r"Queries per second:\s+([\d.]+)"),
    "avg": re.compile(r"Average Latency \(s\):\s+([\d.]+) \(min ([\d.]+), max ([\d.]+)\)"),
    "stddev": re.compile(r"Latency StdDev \(s\):\s+([\d.]+)"),
    "rcodes": re.compile(r"Response codes:\s+(.*)"),
}
BUCKET_RE = re.compile(r"^\s+([\d.]+) - ([\d.]+):\s+(\d+)\s*$", re.M)


def parse_dnsperf(out: str) -> dict:
    def grab(key, group=1, cast=float):
        m = STAT_RE[key].search(out)
        if not m:
            raise RuntimeError(f"dnsperf output has no '{key}' line:\n{out[-2000:]}")
        return cast(m.group(group))

    sent, completed, lost = grab("sent", cast=int), grab("completed", cast=int), grab("lost", cast=int)
    rcodes = {}
    m = STAT_RE["rcodes"].search(out)
    if m:
        for code, n in re.findall(r"(\w+) (\d+) \(", m.group(1)):
            rcodes[code] = int(n)
    # Percentiles from dnsperf's latency histogram, reported at each bucket's upper edge.
    buckets = [(float(hi), int(n)) for _, hi, n in BUCKET_RE.findall(out)]
    total = sum(n for _, n in buckets)
    pct = {}
    for name, q in (("p50", 0.50), ("p90", 0.90), ("p99", 0.99), ("p999", 0.999)):
        if not total:
            break
        acc, target = 0, q * total
        for hi, n in buckets:
            acc += n
            if acc >= target:
                pct[name] = round(hi * 1e6, 1)
                break
    return {
        "qps": grab("qps"),
        "sent": sent,
        "completed": completed,
        "lost": lost,
        "loss_pct": round(100.0 * lost / sent, 4) if sent else 100.0,
        "rcodes": rcodes,
        "latency_us": {
            "avg": round(grab("avg") * 1e6, 1),
            "min": round(grab("avg", 2) * 1e6, 1),
            "max": round(grab("avg", 3) * 1e6, 1),
            "stddev": round(grab("stddev") * 1e6, 1),
            **pct,
        },
    }


def dnsperf(target, datafile, seconds, *, threads, clients, outstanding, max_qps=None, once=False):
    host, port = target
    cmd = [
        "dnsperf", "-s", host, "-p", str(port), "-d", str(datafile), "-l", str(seconds),
        "-T", str(threads), "-c", str(clients), "-q", str(outstanding), "-t", "2",
        "-O", "latency-histogram", "-O", "suppress=timeout,unexpected",
    ]
    if max_qps:
        cmd += ["-Q", str(max_qps)]
    if once:
        cmd += ["-n", "1"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 30)
    if proc.returncode != 0:
        raise RuntimeError(f"dnsperf exited {proc.returncode}:\n{proc.stderr or proc.stdout}")
    return proc.stdout


# ---------------------------------------------------------------------------- processes


def proc_stats(pid):
    """RSS/HWM in KiB and CPU seconds for a local server process (Linux /proc)."""
    try:
        status = pathlib.Path(f"/proc/{pid}/status").read_text()
        stat = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except OSError:
        return None
    kib = {k: int(v.split()[0]) for k, v in re.findall(r"^(VmRSS|VmHWM):\s+(.*)$", status, re.M)}
    ticks = os.sysconf("SC_CLK_TCK")
    return {"rss_kib": kib.get("VmRSS"), "hwm_kib": kib.get("VmHWM"), "cpu_s": (int(stat[11]) + int(stat[12])) / ticks}


def stop(proc, name):
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        print(f"warning: {name} ignored SIGTERM, killing", file=sys.stderr)
        proc.kill()
        proc.wait(timeout=5)


def wait_ready(url, proc, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"server exited with {proc.returncode} before becoming ready")
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    return time.monotonic()
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"server not ready at {url} after {timeout}s")


def wait_port(port, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


def server_config(workers, data_dir, upstream):
    return f"""# Generated by bench/bench.py — loopback-only bench stack.
config_version = 1

[node]
workers = {workers}
data_dir = "{data_dir}"

[[listen]]
proto = "udp"
addr = "127.0.0.1:{DNS_PORT}"

[[listen]]
proto = "tcp"
addr = "127.0.0.1:{DNS_PORT}"

[[upstream]]
name = "stub"
url = "{upstream}"

[[upstream_group]]
name = "default"
members = ["stub"]

[telemetry.metrics]
listen = "127.0.0.1:{METRICS_PORT}"
"""


# ---------------------------------------------------------------------------- run


def git_info():
    def git(*args):
        r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None

    return {"rev": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain", "--untracked-files=no"))}


def host_info():
    cpu = None
    try:
        m = re.search(r"^model name\s*:\s*(.*)$", pathlib.Path("/proc/cpuinfo").read_text(), re.M)
        cpu = m.group(1) if m else None
    except OSError:
        pass
    return {"cpu": cpu, "cores": os.cpu_count(), "arch": platform.machine(), "kernel": platform.release(), "os": platform.platform()}


def tool_version(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"\d+\.\d+(\.\d+)?", r.stdout + r.stderr)
    return m.group(0) if m else None


def summarize(runs):
    """Median of each numeric metric per corpus (09 §2: noisy machine, take the median)."""
    out = {}
    for name in dict.fromkeys(r["corpus"] for r in runs):
        rs = [r for r in runs if r["corpus"] == name]
        med = lambda xs: round(statistics.median(xs), 1)  # noqa: E731
        out[name] = {
            "runs": len(rs),
            "qps": med([r["qps"] for r in rs]),
            "loss_pct": max(r["loss_pct"] for r in rs),
            "latency_us": {k: med([r["latency_us"][k] for r in rs if k in r["latency_us"]])
                           for k in rs[0]["latency_us"]},
        }
        for pct in rs[0].get("at_load", {}):
            ats = [r["at_load"][pct] for r in rs if pct in r.get("at_load", {})]
            out[name].setdefault("at_load", {})[pct] = {
                "offered_qps": med([a["offered_qps"] for a in ats]),
                "loss_pct": max(a["loss_pct"] for a in ats),
                "latency_us": {k: med([a["latency_us"][k] for a in ats if k in a["latency_us"]])
                               for k in ats[0]["latency_us"]},
            }
        cpu = [r["server"]["cpu_pct"] for r in rs if r.get("server")]
        if cpu:
            out[name]["server_cpu_pct"] = med(cpu)
    return out


def cmd_run(args):
    mode = dict(MODES[args.mode])
    corpora = args.corpus or mode["corpora"]
    duration = args.duration or mode["duration"]
    runs = args.runs or mode["runs"]

    if not shutil.which("dnsperf"):
        sys.exit("dnsperf not found (apt install dnsperf)")

    corpus_dir = HERE / "corpora"
    files = {}
    for name in corpora:
        if name == "blocked" and not any((HERE / "lists").glob("*.txt")):
            print("skip blocked: no lists in bench/lists/ (fetched artifact, see bench/README.md)", file=sys.stderr)
            continue
        path, digest = corpus.generate(name, corpus_dir, HERE / "lists")
        files[name] = {"path": path, "sha256": digest, "seed": corpus.CORPORA[name]["seed"]}

    result = {
        "schema": SCHEMA,
        "mode": args.mode,
        "started": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "git": git_info(),
        "host": host_info(),
        "tools": {"dnsperf": tool_version(["dnsperf", "-h"])},
        "params": {"duration_s": duration, "runs": runs, "warmup_s": mode["warmup"], "threads": args.threads,
                   "clients": args.clients, "outstanding": args.outstanding, "miss_qps": MISS_QPS},
        "server": {},
        "runs": [],
    }

    stub = server = None
    tmp = tempfile.TemporaryDirectory(prefix="telltale-bench-")
    try:
        if args.target:
            host, _, port = args.target.rpartition(":")
            target = (host or "127.0.0.1", int(port or 53))
            result["server"] = {"external": args.target}
        else:
            binary = pathlib.Path(args.bin)
            if not binary.is_file():
                sys.exit(f"server binary {binary} not found (make bench-smoke builds it)")
            stub = subprocess.Popen([sys.executable, str(HERE / "stub_upstream.py"), "--port", str(STUB_PORT),
                                     "--delay-ms", str(args.upstream_delay_ms)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_port(STUB_PORT)
            cfg = pathlib.Path(tmp.name) / "telltale.toml"
            cfg.write_text(server_config(args.workers, tmp.name, f"udp://127.0.0.1:{STUB_PORT}"))
            log = open(pathlib.Path(tmp.name) / "server.log", "w")
            env = dict(os.environ, RUST_LOG=os.environ.get("RUST_LOG", "warn"))
            t0 = time.monotonic()
            server = subprocess.Popen([str(binary), "run", "-c", str(cfg)], stdout=log, stderr=subprocess.STDOUT, env=env)
            ready_at = wait_ready(f"http://127.0.0.1:{METRICS_PORT}/readyz", server)
            time.sleep(1.0)  # let worker threads settle before sampling idle RSS
            idle = proc_stats(server.pid) or {}
            result["server"] = {
                "bin": str(binary),
                "version": tool_version([str(binary), "--version"]),
                "workers": args.workers,
                "upstream_delay_ms": args.upstream_delay_ms,
                "ready_ms": round((ready_at - t0) * 1000, 1),
                "idle_rss_kib": idle.get("rss_kib"),
            }
            target = ("127.0.0.1", DNS_PORT)

        for name, meta in files.items():
            for i in range(runs):
                miss = name == "miss-heavy"
                common = dict(threads=args.threads, clients=args.clients, outstanding=args.outstanding)
                if not miss and mode["warmup"]:
                    dnsperf(target, meta["path"], mode["warmup"], **common)
                before = proc_stats(server.pid) if server else None
                # miss-heavy: run each name at most once so every query is a real miss.
                out = dnsperf(target, meta["path"], duration, **common,
                              max_qps=MISS_QPS if miss else None, once=miss)
                after = proc_stats(server.pid) if server else None
                run = {"corpus": name, "run": i + 1, "seed": meta["seed"], "corpus_sha256": meta["sha256"],
                       **parse_dnsperf(out)}
                if before and after:
                    run["server"] = {
                        "rss_kib": after["rss_kib"],
                        "peak_rss_kib": after["hwm_kib"],
                        "cpu_pct": round(100.0 * (after["cpu_s"] - before["cpu_s"]) / duration, 1),
                    }
                # Fixed-rate latency at a share of the measured max (throughput corpora only).
                for pct in [] if miss else mode["load_points"]:
                    offered = max(1, int(run["qps"] * pct / 100))
                    at = parse_dnsperf(dnsperf(target, meta["path"], duration, **common, max_qps=offered))
                    run.setdefault("at_load", {})[str(pct)] = {"offered_qps": offered, "qps": at["qps"],
                                                               "loss_pct": at["loss_pct"], "latency_us": at["latency_us"]}
                result["runs"].append(run)
                lat = run["latency_us"]
                print(f"{name:<11} run {i + 1}/{runs}: {run['qps']:>10.0f} qps  loss {run['loss_pct']:.2f}%  "
                      f"p50 {lat.get('p50', '-')} µs  p99 {lat.get('p99', '-')} µs", file=sys.stderr)
                for pct, at in run.get("at_load", {}).items():
                    al = at["latency_us"]
                    print(f"{'':<11}   @{pct:>3}%: {at['qps']:>10.0f} qps  loss {at['loss_pct']:.2f}%  "
                          f"p50 {al.get('p50', '-')} µs  p99 {al.get('p99', '-')} µs", file=sys.stderr)
                if server and server.poll() is not None:
                    raise RuntimeError(f"server exited with {server.returncode} during {name}")
        if server:
            final = proc_stats(server.pid) or {}
            result["server"]["peak_rss_kib"] = final.get("hwm_kib")
    finally:
        stop(server, "telltale")
        stop(stub, "stub upstream")
        if server and server.returncode not in (0, None):
            print(f"telltale exited with {server.returncode}; log:", file=sys.stderr)
            print((pathlib.Path(tmp.name) / "server.log").read_text()[-4000:], file=sys.stderr)
        tmp.cleanup()

    result["summary"] = summarize(result["runs"])
    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = result["started"].replace(":", "").replace("-", "").replace("+0000", "Z")
    path = out_dir / f"{stamp}-{args.mode}.json"
    path.write_text(json.dumps(result, indent=2) + "\n")
    print(f"results: {path}", file=sys.stderr)

    failures = [f"{name}: loss {s['loss_pct']}% > {MAX_LOSS_PCT[name]}%"
                for name, s in result["summary"].items() if s["loss_pct"] > MAX_LOSS_PCT[name]]
    if args.baseline:
        failures += compare(json.loads(pathlib.Path(args.baseline).read_text()), result, args.tolerance)
    for f in failures:
        print(f"FAIL {f}", file=sys.stderr)
    return 1 if failures else 0


# ---------------------------------------------------------------------------- compare


def compare(base, new, tolerance_pct):
    """Regression gate (09 §2): qps must not drop and p99 must not rise by more than the tolerance."""
    failures = []
    for name, b in base.get("summary", {}).items():
        n = new.get("summary", {}).get(name)
        if not n:
            continue
        rows = [("qps", b["qps"], n["qps"], -1)]
        # Gate latency on the 50%-load point when both sides have it (saturated p99 is queueing noise).
        b50, n50 = b.get("at_load", {}).get("50"), n.get("at_load", {}).get("50")
        if b50 and n50:
            rows.append(("p99@50%", b50["latency_us"].get("p99"), n50["latency_us"].get("p99"), 1))
        else:
            rows.append(("p99 µs", b["latency_us"].get("p99"), n["latency_us"].get("p99"), 1))
        for label, old, cur, worse_sign in rows:
            if not old or cur is None:
                continue
            delta = 100.0 * (cur - old) / old
            flag = "REGRESSION" if delta * worse_sign > tolerance_pct else "ok"
            print(f"{name:<11} {label:<8} {old:>12.1f} → {cur:>12.1f}  ({delta:+.1f}%)  {flag}", file=sys.stderr)
            if flag != "ok":
                failures.append(f"{name} {label} {delta:+.1f}% (tolerance {tolerance_pct}%)")
    return failures


def cmd_compare(args):
    base = json.loads(pathlib.Path(args.base).read_text())
    new = json.loads(pathlib.Path(args.new).read_text())
    failures = compare(base, new, args.tolerance)
    for f in failures:
        print(f"FAIL {f}", file=sys.stderr)
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run a benchmark mode")
    r.add_argument("mode", choices=sorted(MODES))
    r.add_argument("--bin", default=str(ROOT / "target/bench-fast/telltale"), help="telltale binary")
    r.add_argument("--target", help="bench an already-running server at HOST:PORT instead")
    r.add_argument("--corpus", action="append", choices=sorted(corpus.CORPORA), help="override the mode's corpora")
    r.add_argument("--duration", type=int, help="seconds per measured run")
    r.add_argument("--runs", type=int, help="runs per corpus (median is reported)")
    r.add_argument("--workers", type=int, default=4, help="server workers (09 §2: 4-core profile)")
    r.add_argument("--threads", type=int, default=2, help="dnsperf threads")
    r.add_argument("--clients", type=int, default=8, help="dnsperf client sockets")
    r.add_argument("--outstanding", type=int, default=200, help="dnsperf max in-flight queries")
    r.add_argument("--upstream-delay-ms", type=float, default=0.0, help="stub upstream delay (0 and 20 in 09 §2)")
    r.add_argument("--baseline", help="results JSON to gate against")
    r.add_argument("--tolerance", type=float, default=5.0, help="regression tolerance in percent")
    r.add_argument("--out", default=str(HERE / "results"))
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("compare", help="compare two results files")
    c.add_argument("base")
    c.add_argument("new")
    c.add_argument("--tolerance", type=float, default=5.0)
    c.set_defaults(func=cmd_compare)

    args = ap.parse_args()
    try:
        sys.exit(args.func(args))
    except RuntimeError as e:
        sys.exit(f"bench: {e}")


if __name__ == "__main__":
    main()
