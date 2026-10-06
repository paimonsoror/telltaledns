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
import base64
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
import struct
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
# T9.13 — encrypted listeners for the `transports` mode (a throwaway self-signed certificate).
DOT_PORT = 5853
DOH_PORT = 5443

MODES = {
    # REQ: NFR-001 — `make bench-smoke` (AGENTS.md rule 4): short, single run, fails on errors.
    "smoke": {"corpora": ["cache-hot", "miss-heavy"], "duration": 8, "runs": 1, "warmup": 2, "load_points": [50]},
    # Nightly / release: every corpus whose inputs are present, median of 3 (09 §2 regression gate).
    "full": {"corpora": ["cache-hot", "miss-heavy", "blocked"], "duration": 30, "runs": 3, "warmup": 5,
             "load_points": [25, 50, 75]},
    # T9.13 — the same cache hits over each transport: what TCP framing, TLS, and HTTP/2 cost.
    "transports": {"corpora": ["cache-hot"], "duration": 10, "runs": 1, "warmup": 3, "load_points": [50],
                   "transports": ["udp", "tcp", "dot", "doh"]},
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
    # Percentiles from dnsperf's latency histogram, reported at each bucket's upper edge. Over
    # TCP, DoT, and DoH a second one (connection latency) follows: it isn't counted (T9.13).
    answers = out.split("Connection Statistics")[0]
    buckets = [(float(hi), int(n)) for _, hi, n in BUCKET_RE.findall(answers)]
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
            "avg": round(grab("avg") * 1e6, 1),  # the first match: answers
            "min": round(grab("avg", 2) * 1e6, 1),
            "max": round(grab("avg", 3) * 1e6, 1),
            "stddev": round(grab("stddev") * 1e6, 1),
            **pct,
        },
    }


def dnsperf(target, datafile, seconds, *, threads, clients, outstanding, max_qps=None, once=False,
            transport="udp"):
    host, port = target
    cmd = [
        "dnsperf", "-s", host, "-p", str(port), "-d", str(datafile), "-l", str(seconds),
        "-T", str(threads), "-c", str(clients), "-q", str(outstanding), "-t", "2",
        "-O", "latency-histogram", "-O", "suppress=timeout,unexpected",
    ]
    # T9.13 — TCP, DoT, or DoH (dnsperf doesn't verify the certificate).
    if transport != "udp":
        cmd += ["-m", transport]
    if transport == "doh":
        cmd += ["-O", f"doh-uri=https://{host}:{port}/dns-query", "-O", "doh-method=POST"]
    if max_qps:
        cmd += ["-Q", str(max_qps)]
    if once:
        cmd += ["-n", "1"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 30)
    if proc.returncode != 0:
        raise RuntimeError(f"dnsperf exited {proc.returncode}:\n{proc.stderr or proc.stdout}")
    return proc.stdout


# ---------------------------------------------------------------------------- h2load (DoH)

# T9.13 — dnsperf's DoH client tops out at a few dozen queries a second here (about 40 ms each,
# even one at a time; curl gets 175 µs from the same listener), so DoH load comes from h2load
# (nghttp2), with the corpus as RFC 8484 GET URLs.
H2LOAD = os.environ.get("H2LOAD") or shutil.which("h2load")
QTYPES = {"A": 1, "AAAA": 28, "HTTPS": 65, "CNAME": 5, "PTR": 12, "TXT": 16, "SRV": 33, "MX": 15, "NS": 2}


def doh_uris(datafile, port, out, limit=50_000):
    """The corpus as `https://127.0.0.1:PORT/dns-query?dns=…` lines (query ID 0, RD set)."""
    lines = []
    for line in pathlib.Path(datafile).read_text().splitlines()[:limit]:
        parts = line.split()
        if len(parts) != 2 or parts[1] not in QTYPES:
            continue
        wire = b"".join(bytes([len(lbl)]) + lbl.encode() for lbl in parts[0].strip(".").split(".")) + b"\0"
        msg = struct.pack(">HHHHHH", 0, 0x0100, 1, 0, 0, 0) + wire + struct.pack(">HH", QTYPES[parts[1]], 1)
        b64 = base64.urlsafe_b64encode(msg).decode().rstrip("=")
        lines.append(f"https://127.0.0.1:{port}/dns-query?dns={b64}")
    pathlib.Path(out).write_text("\n".join(lines) + "\n")
    return out


H2_REQ_RE = re.compile(r"requests: (\d+) total, \d+ started, (\d+) done, (\d+) succeeded, (\d+) failed, (\d+) errored")
H2_RPS_RE = re.compile(r"finished in ([\d.]+)(m?s), ([\d.]+) req/s")


def h2load(target, uris, seconds, *, clients, outstanding, max_qps=None, **_):
    """One DoH run, in dnsperf's result shape (no rcodes: h2load sees HTTP, not DNS)."""
    host, port = target
    log = pathlib.Path(uris).with_suffix(".log")
    log.unlink(missing_ok=True)
    streams = max(1, outstanding // max(1, clients))
    cmd = [H2LOAD, "-i", str(uris), "-D", str(seconds), "-c", str(clients), "-m", str(streams), "-t", "2",
           "--log-file", str(log)]
    if max_qps:
        cmd += ["--rps", str(max(1, max_qps // clients))]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 60)
    m, r = H2_REQ_RE.search(proc.stdout), H2_RPS_RE.search(proc.stdout)
    if proc.returncode != 0 or not m or not r:
        raise RuntimeError(f"h2load exited {proc.returncode}:\n{proc.stdout[-1500:]}{proc.stderr[-500:]}")
    total, succeeded = int(m.group(1)), int(m.group(3))
    durs = sorted(int(f[2]) for f in (l.split("\t") for l in log.read_text().splitlines()) if len(f) >= 3 and f[1] == "200")
    pct = {}
    for name, q in (("p50", 0.50), ("p90", 0.90), ("p99", 0.99), ("p999", 0.999)):
        if durs:
            pct[name] = float(durs[min(len(durs) - 1, int(q * len(durs)))])
    avg = statistics.fmean(durs) if durs else 0.0
    return {
        "qps": float(r.group(3)),
        "sent": total,
        "completed": succeeded,
        "lost": total - succeeded,
        "loss_pct": round(100.0 * (total - succeeded) / total, 4) if total else 100.0,
        "rcodes": {},
        "latency_us": {"avg": round(avg, 1), "min": float(durs[0]) if durs else 0.0,
                       "max": float(durs[-1]) if durs else 0.0,
                       "stddev": round(statistics.pstdev(durs), 1) if len(durs) > 1 else 0.0, **pct},
    }


def measure(target, datafile, seconds, *, transport="udp", **kw):
    """One run as a result dict: dnsperf, or h2load for DoH."""
    if transport == "doh":
        uris = doh_uris(datafile, target[1], pathlib.Path(tempfile.gettempdir()) / f"tt-doh-{os.getpid()}.uris")
        kw.pop("threads", None)
        kw.pop("once", None)
        return h2load(target, uris, seconds, **kw)
    return parse_dnsperf(dnsperf(target, datafile, seconds, transport=transport, **kw))


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


def wait_filter(url, proc, timeout=300.0):
    """With lists configured: wait until the snapshot is compiled and its hash index is
    built, so blocked-path numbers measure the steady state."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"server exited with {proc.returncode} while compiling lists")
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                body = r.read().decode()
            m = re.search(r"^telltale_filter_lookup_index_bytes (\d+)", body, re.M)
            if m and int(m.group(1)) > 0:
                return time.monotonic()
        except OSError:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"filter not ready after {timeout}s")


def wait_port(port, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


def tls_cert(dir_):
    """T9.13 — a throwaway self-signed certificate for the encrypted listeners."""
    cert, key = pathlib.Path(dir_) / "cert.pem", pathlib.Path(dir_) / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    return cert, key


def server_config(workers, data_dir, upstream, lists=(), compile_threads=0, quick_rules=0, tls=None):
    list_cfg = "".join(f'\n[[list]]\nname = "{p.stem}"\npath = "{p}"\n' for p in lists)
    if compile_threads:
        list_cfg = f"\n[filter]\ncompile_threads = {compile_threads}\n" + list_cfg
    # T6.12 (ADR-067): quick rules that never match the corpora, so every query pays the
    # lookup (one probe per label of its name) without short-circuiting on a match.
    for i in range(quick_rules):
        scope = (f'devices = ["192.0.2.{i % 250 + 1}"]' if i % 3 == 0
                 else 'groups = ["default"]' if i % 3 == 1 else "")
        action = "allow" if i % 2 else "block"
        list_cfg += f'\n[[rule]]\nid = "bench-{i}"\naction = "{action}"\ndomain = "r{i}.bench.invalid"\n{scope}\n'

    encrypted = ""
    if tls:
        cert, key = tls
        for proto, port in (("dot", DOT_PORT), ("doh", DOH_PORT)):
            encrypted += (f'\n[[listen]]\nproto = "{proto}"\naddr = "127.0.0.1:{port}"\n'
                          f'tls = {{ cert = "{cert}", key = "{key}" }}\n')
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
{encrypted}
[[upstream]]
name = "stub"
url = "{upstream}"

[[upstream_group]]
name = "default"
members = ["stub"]

[telemetry.metrics]
listen = "127.0.0.1:{METRICS_PORT}"
{list_cfg}"""


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
    transports = args.transport or mode.get("transports", ["udp"])
    if "doh" in transports and not H2LOAD:
        print("skip doh: h2load not found (apt install nghttp2-client, or set H2LOAD)", file=sys.stderr)
        transports = [t for t in transports if t != "doh"]
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
                   "clients": args.clients, "outstanding": args.outstanding, "miss_qps": MISS_QPS,
                   "quick_rules": args.quick_rules, "transports": transports},
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
            # The blocked corpus needs the lists loaded; then every corpus runs with them.
            lists = sorted((HERE / "lists").glob("*.txt")) if "blocked" in files else []
            tls = tls_cert(tmp.name) if {"dot", "doh"} & set(transports) else None
            cfg.write_text(server_config(args.workers, tmp.name, f"udp://127.0.0.1:{STUB_PORT}", lists,
                                         quick_rules=args.quick_rules, tls=tls))
            log = open(pathlib.Path(tmp.name) / "server.log", "w")
            env = dict(os.environ, RUST_LOG=os.environ.get("RUST_LOG", "warn"))
            t0 = time.monotonic()
            server = subprocess.Popen([str(binary), "run", "-c", str(cfg)], stdout=log, stderr=subprocess.STDOUT, env=env)
            ready_at = wait_ready(f"http://127.0.0.1:{METRICS_PORT}/readyz", server)
            filter_s = None
            if lists:
                filter_s = round(wait_filter(f"http://127.0.0.1:{METRICS_PORT}/metrics", server) - ready_at, 1)
                print(f"filter ready {filter_s}s after start ({len(lists)} lists)", file=sys.stderr)
            # Let worker threads settle before sampling idle RSS. With lists, also wait out the
            # 2 s grace before swapped-out matchers are freed (ADR-023) and the allocator's
            # purge of the compile's memory: sampled earlier, a transient compile peak
            # (~110 MiB on the homelab) passed for idle RSS.
            time.sleep(6.0 if lists else 1.0)
            idle = proc_stats(server.pid) or {}
            result["server"] = {
                "bin": str(binary),
                "version": tool_version([str(binary), "--version"]),
                "workers": args.workers,
                "upstream_delay_ms": args.upstream_delay_ms,
                "ready_ms": round((ready_at - t0) * 1000, 1),
                "idle_rss_kib": idle.get("rss_kib"),
                "lists": [p.name for p in lists],
                "filter_ready_s": filter_s,
            }
            target = ("127.0.0.1", DNS_PORT)

        plain = target
        for (name, meta), transport in [(f, t) for f in files.items() for t in transports]:
            # T9.13 — one label per corpus and transport ("cache-hot", "cache-hot/dot").
            label = name if transport == "udp" else f"{name}/{transport}"
            port = {"dot": DOT_PORT, "doh": DOH_PORT}.get(transport)
            target = (plain[0], port) if port and not args.target else plain
            for i in range(runs):
                miss = name == "miss-heavy"
                common = dict(threads=args.threads, clients=args.clients, outstanding=args.outstanding,
                              transport=transport)
                if not miss and mode["warmup"]:
                    measure(target, meta["path"], mode["warmup"], **common)
                before = proc_stats(server.pid) if server else None
                # miss-heavy: run each name at most once so every query is a real miss.
                res = measure(target, meta["path"], duration, **common,
                              max_qps=MISS_QPS if miss else None, once=miss)
                after = proc_stats(server.pid) if server else None
                run = {"corpus": label, "transport": transport, "run": i + 1, "seed": meta["seed"], "corpus_sha256": meta["sha256"],
                       **res}
                if before and after:
                    run["server"] = {
                        "rss_kib": after["rss_kib"],
                        "peak_rss_kib": after["hwm_kib"],
                        "cpu_pct": round(100.0 * (after["cpu_s"] - before["cpu_s"]) / duration, 1),
                    }
                # Fixed-rate latency at a share of the measured max (throughput corpora only).
                for pct in [] if miss else mode["load_points"]:
                    offered = max(1, int(run["qps"] * pct / 100))
                    at = measure(target, meta["path"], duration, **common, max_qps=offered)
                    run.setdefault("at_load", {})[str(pct)] = {"offered_qps": offered, "qps": at["qps"],
                                                               "loss_pct": at["loss_pct"], "latency_us": at["latency_us"]}
                result["runs"].append(run)
                lat = run["latency_us"]
                print(f"{label:<15} run {i + 1}/{runs}: {run['qps']:>10.0f} qps  loss {run['loss_pct']:.2f}%  "
                      f"p50 {lat.get('p50', '-')} µs  p99 {lat.get('p99', '-')} µs", file=sys.stderr)
                for pct, at in run.get("at_load", {}).items():
                    al = at["latency_us"]
                    print(f"{'':<15}   @{pct:>3}%: {at['qps']:>10.0f} qps  loss {at['loss_pct']:.2f}%  "
                          f"p50 {al.get('p50', '-')} µs  p99 {al.get('p99', '-')} µs", file=sys.stderr)
                if server and server.poll() is not None:
                    raise RuntimeError(f"server exited with {server.returncode} during {label}")
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

    failures = [f"{name}: loss {s['loss_pct']}% > {MAX_LOSS_PCT.get(name.split('/')[0], 1.0)}%"
                for name, s in result["summary"].items()
                if s["loss_pct"] > MAX_LOSS_PCT.get(name.split("/")[0], 1.0)]
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


# ---------------------------------------------------------------------------- swap


def metric(url, name):
    """One unlabeled gauge from /metrics, or None."""
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            body = r.read().decode()
    except OSError:
        return None
    m = re.search(rf"^{name} ([0-9.e+-]+)$", body, re.M)
    return float(m.group(1)) if m else None


def metric_sum(url, name):
    """Sum of every series of a (labeled) counter from /metrics, or None."""
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            body = r.read().decode()
    except OSError:
        return None
    vals = re.findall(rf"^{name}(?:{{[^}}]*}})? ([0-9.e+-]+)$", body, re.M)
    return sum(float(v) for v in vals) if vals else None


def cmd_sustain(args):
    """REQ: T3.1 AC — sustained fixed-rate load with telemetry on: the event drop counter must
    stay 0 (OBS-002), no query may be lost, and every answered query must leave an event."""
    if not shutil.which("dnsperf"):
        sys.exit("dnsperf not found")
    lists = sorted((HERE / "lists").glob("*.txt")) if args.corpus in ("blocked", "realistic-home") else []
    path, digest = corpus.generate(args.corpus, HERE / "corpora", HERE / "lists")
    tmp = tempfile.TemporaryDirectory(prefix="telltale-sustain-")
    cfg = pathlib.Path(tmp.name) / "telltale.toml"
    cfg.write_text(server_config(args.workers, tmp.name, f"udp://127.0.0.1:{STUB_PORT}", lists))
    url = f"http://127.0.0.1:{METRICS_PORT}/metrics"
    target = ("127.0.0.1", DNS_PORT)
    common = dict(threads=args.threads, clients=args.clients, outstanding=args.outstanding)
    stub = server = None
    try:
        stub = subprocess.Popen([sys.executable, str(HERE / "stub_upstream.py"), "--port", str(STUB_PORT)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_port(STUB_PORT)
        log = open(pathlib.Path(tmp.name) / "server.log", "w")
        server = subprocess.Popen([str(args.bin), "run", "-c", str(cfg)], stdout=log, stderr=subprocess.STDOUT,
                                  env=dict(os.environ, RUST_LOG="warn"))
        wait_ready(f"http://127.0.0.1:{METRICS_PORT}/readyz", server)
        if lists:
            wait_filter(url, server)
        dnsperf(target, path, 5, **common, max_qps=args.rate)  # warm the cache
        before = (metric_sum(url, "telltale_telemetry_events_total") or 0,
                  metric_sum(url, "telltale_telemetry_dropped_total") or 0,
                  metric_sum(url, "telltale_queries_total") or 0)
        run = parse_dnsperf(dnsperf(target, path, args.duration, **common, max_qps=args.rate))
        time.sleep(0.5)  # let deferred answers and the aggregator catch up
        after = (metric_sum(url, "telltale_telemetry_events_total") or 0,
                 metric_sum(url, "telltale_telemetry_dropped_total") or 0,
                 metric_sum(url, "telltale_queries_total") or 0)
        stats = proc_stats(server.pid) or {}
        if server.poll() is not None:
            raise RuntimeError(f"server exited with {server.returncode}")
    finally:
        stop(server, "telltale")
        stop(stub, "stub upstream")
        tmp.cleanup()
    events, dropped, queries = (a - b for a, b in zip(after, before))
    summary = {"corpus": args.corpus, "corpus_sha256": digest, "rate": args.rate, "duration": args.duration,
               "qps": run.get("qps"), "loss_pct": run.get("loss_pct"), "latency_us": run.get("latency_us"),
               "queries": queries, "events": events, "dropped": dropped,
               "rss_kib": stats.get("rss_kib"), "peak_rss_kib": stats.get("hwm_kib")}
    print(json.dumps(summary), file=sys.stdout)
    ok = dropped == 0 and (run.get("loss_pct") or 0) == 0 and events >= queries
    print(f"sustained {run.get('qps', 0):.0f} qps for {args.duration} s: {queries:.0f} queries, "
          f"{events:.0f} events (incl. upstream), {dropped:.0f} dropped, loss {run.get('loss_pct')}%; "
          f"RSS {stats.get('rss_kib', 0) // 1024} MiB -> {'PASS' if ok else 'FAIL'}", file=sys.stderr)
    return 0 if ok else 1


def cmd_swap(args):
    """REQ: T2.7 AC — recompile and swap the filter during a realistic-home run: p99 must not
    regress by more than 10% and no query may fail. Each round runs the same fixed-rate load
    twice, once quiet and once with a full recompile + index swap triggered mid-run (a config
    change plus SIGHUP), alternating which comes first."""
    if not shutil.which("dnsperf"):
        sys.exit("dnsperf not found")
    lists = sorted((HERE / "lists").glob("*.txt"))
    if not lists:
        sys.exit("swap needs lists in bench/lists/")
    path, digest = corpus.generate("realistic-home", HERE / "corpora", HERE / "lists")
    tmp = tempfile.TemporaryDirectory(prefix="telltale-swap-")
    cfg = pathlib.Path(tmp.name) / "telltale.toml"
    # A small path list the "list" trigger rewrites: a list update, as the fetcher would see.
    swap_list = pathlib.Path(tmp.name) / "swap.txt"
    swap_list.write_text("||swap-initial.example^\n")
    base_cfg = server_config(args.workers, tmp.name, f"udp://127.0.0.1:{STUB_PORT}", [*lists, swap_list],
                             args.compile_threads)
    cfg.write_text(base_cfg)
    metrics_url = f"http://127.0.0.1:{METRICS_PORT}/metrics"
    target = ("127.0.0.1", DNS_PORT)
    common = dict(threads=args.threads, clients=args.clients, outstanding=args.outstanding)
    stub = server = None
    rounds = []
    try:
        stub = subprocess.Popen([sys.executable, str(HERE / "stub_upstream.py"), "--port", str(STUB_PORT)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_port(STUB_PORT)
        log = open(pathlib.Path(tmp.name) / "server.log", "w")
        server = subprocess.Popen([str(args.bin), "run", "-c", str(cfg)], stdout=log, stderr=subprocess.STDOUT,
                                  env=dict(os.environ, RUST_LOG="warn"))
        wait_ready(f"http://127.0.0.1:{METRICS_PORT}/readyz", server)
        t = wait_filter(metrics_url, server)
        print(f"filter ready; warming up", file=sys.stderr)
        dnsperf(target, path, args.duration, **common, max_qps=args.rate)
        for i in range(args.rounds):
            order = ["quiet", "swap"] if i % 2 == 0 else ["swap", "quiet"]
            result = {}
            for kind in order:
                if kind == "quiet":
                    out = dnsperf(target, path, args.duration, **common, max_qps=args.rate)
                    result["quiet"] = parse_dnsperf(out)
                    continue
                v0 = metric(metrics_url, "telltale_filter_snapshot_version") or 0
                cmd = ["dnsperf", "-s", target[0], "-p", str(target[1]), "-d", str(path), "-l", str(args.duration),
                       "-T", str(args.threads), "-c", str(args.clients), "-q", str(args.outstanding), "-t", "2",
                       "-Q", str(args.rate), "-O", "latency-histogram", "-O", "suppress=timeout,unexpected"]
                load = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                time.sleep(args.at)
                t0 = time.monotonic()
                if args.trigger == "list":
                    # New list content + "refresh lists now": full recompile + swap.
                    swap_list.write_text(f"||swap{i}.example^\n")
                    server.send_signal(signal.SIGUSR1)
                else:
                    # A new inline list in the config + reload: the same, plus a config reload.
                    cfg.write_text(base_cfg + f'\n[[list]]\nname = "swap-{i}"\nrules = ["||swap{i}.example^"]\n')
                    server.send_signal(signal.SIGHUP)
                swapped = indexed = None
                while load.poll() is None:
                    v = metric(metrics_url, "telltale_filter_snapshot_version") or 0
                    if swapped is None and v > v0:
                        swapped = round(time.monotonic() - t0, 2)
                    if swapped is not None and indexed is None and (metric(metrics_url, "telltale_filter_lookup_index_bytes") or 0) > 0:
                        indexed = round(time.monotonic() - t0, 2)
                    time.sleep(0.1)
                stdout, _ = load.communicate()
                r = parse_dnsperf(stdout)
                r["swap_after_s"] = swapped
                r["indexed_after_s"] = indexed
                result["swap"] = r
                if swapped is None:
                    raise RuntimeError("the snapshot didn't change during the run; raise --duration")
            rounds.append(result)
            if server.poll() is not None:
                raise RuntimeError(f"server exited with {server.returncode} during round {i + 1}")
            if result["quiet"]["completed"] == 0 or result["swap"]["completed"] == 0:
                raise RuntimeError(f"server stopped answering in round {i + 1}")
            q, s = result["quiet"], result["swap"]
            print(f"round {i + 1}: quiet p99 {q['latency_us'].get('p99')} µs, swap p99 {s['latency_us'].get('p99')} µs "
                  f"(swap at +{s['swap_after_s']}s, indexed +{s['indexed_after_s']}s); loss {q['loss_pct']}% / {s['loss_pct']}%; "
                  f"rcodes {s['rcodes']}", file=sys.stderr)
    finally:
        alive = server is not None and server.poll() is None
        stop(server, "telltale")
        stop(stub, "stub upstream")
        # Keep the server log with the results: it's the evidence when something goes wrong.
        out_dir = pathlib.Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path = pathlib.Path(tmp.name) / "server.log"
        if log_path.exists():
            text = log_path.read_text(errors="replace")
            (out_dir / "swap-server.log").write_text(text)
            if not alive or "panicked" in text:
                print(f"server log (alive at end: {alive}):\n{text[-3000:]}", file=sys.stderr)
        tmp.cleanup()
    med = lambda xs: statistics.median(xs)  # noqa: E731
    q99 = med([r["quiet"]["latency_us"]["p99"] for r in rounds])
    s99 = med([r["swap"]["latency_us"]["p99"] for r in rounds])
    q50 = med([r["quiet"]["latency_us"]["p50"] for r in rounds])
    s50 = med([r["swap"]["latency_us"]["p50"] for r in rounds])
    lost = sum(r[k]["lost"] for r in rounds for k in ("quiet", "swap"))
    servfail = sum(r["swap"]["rcodes"].get("SERVFAIL", 0) for r in rounds)
    regress = 100.0 * (s99 - q99) / q99 if q99 else 0.0
    summary = {"corpus_sha256": digest, "trigger": args.trigger, "rate": args.rate, "duration_s": args.duration, "rounds": rounds,
               "p50_us": {"quiet": q50, "swap": s50}, "p99_us": {"quiet": q99, "swap": s99},
               "p99_regression_pct": round(regress, 1), "lost": lost, "servfail_during_swap": servfail,
               "host": host_info(), "git": git_info()}
    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (out_dir / f"{stamp}-swap.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"median p50 {q50} → {s50} µs; median p99 {q99} → {s99} µs ({regress:+.1f}%); lost {lost}; "
          f"SERVFAIL during swaps {servfail}", file=sys.stderr)
    ok = regress <= args.max_regression and lost == 0 and servfail == 0
    print("PASS" if ok else "FAIL", file=sys.stderr)
    return 0 if ok else 1


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
    r.add_argument("--quick-rules", type=int, default=0, help="load this many non-matching quick rules (T6.12)")
    r.add_argument("--transport", action="append", choices=["udp", "tcp", "dot", "doh"],
                   help="query over these transports (T9.13; default: the mode's, else udp)")
    r.add_argument("--out", default=str(HERE / "results"))
    r.set_defaults(func=cmd_run)

    w = sub.add_parser("swap", help="T2.7: recompile + swap the filter under realistic-home load")
    w.add_argument("--bin", default=str(ROOT / "target/bench-fast/telltale"))
    w.add_argument("--rate", type=int, default=20_000, help="fixed query rate (qps)")
    w.add_argument("--duration", type=int, default=20, help="seconds per run")
    w.add_argument("--at", type=float, default=4.0, help="seconds into the swap run to trigger the recompile")
    w.add_argument("--trigger", choices=["list", "reload"], default="list",
                   help="list = list content changes (SIGUSR1); reload = config change (SIGHUP)")
    w.add_argument("--compile-threads", type=int, default=0, help="[filter] compile_threads (0 = auto)")
    w.add_argument("--rounds", type=int, default=4)
    w.add_argument("--workers", type=int, default=4)
    w.add_argument("--threads", type=int, default=2)
    w.add_argument("--clients", type=int, default=8)
    w.add_argument("--outstanding", type=int, default=200)
    w.add_argument("--max-regression", type=float, default=10.0, help="allowed p99 regression (%%)")
    w.add_argument("--out", default=str(HERE / "results"))
    w.set_defaults(func=cmd_swap)

    s = sub.add_parser("sustain", help="T3.1: fixed-rate load; telemetry must drop nothing")
    s.add_argument("--bin", default=str(ROOT / "target/bench-fast/telltale"))
    s.add_argument("--corpus", choices=sorted(corpus.CORPORA), default="cache-hot")
    s.add_argument("--rate", type=int, default=100_000, help="fixed query rate (qps)")
    s.add_argument("--duration", type=int, default=60, help="seconds")
    s.add_argument("--workers", type=int, default=4)
    s.add_argument("--threads", type=int, default=4)
    s.add_argument("--clients", type=int, default=16)
    s.add_argument("--outstanding", type=int, default=500)
    s.set_defaults(func=cmd_sustain)

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
