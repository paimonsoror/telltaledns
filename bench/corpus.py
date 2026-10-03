#!/usr/bin/env python3
"""Deterministic query-corpus generator for dnsperf (spec/09 §2).

Each corpus is defined by a name and a seed below, so the same command always produces
byte-identical files; the runner records each file's SHA-256 in the results JSON.

  cache-hot   10k names, Zipf s=1.0, after warmup (cache-hit path)
  miss-heavy  unique random subdomains (every query misses the cache)
  blocked     names drawn 100% from the blocklists in bench/lists/ (needs --lists)

realistic-home (24 h replay mix) needs blocking and the query-log distributions, so it
lands with the filter tasks (T2.x).
"""

import argparse
import bisect
import hashlib
import itertools
import pathlib
import random
import sys

# REQ: NFR-001 — corpora are reproducible from these seeds.
CORPORA = {
    "cache-hot": {"seed": 0x7E11, "names": 10_000, "zipf_s": 1.0, "queries": 200_000},
    "miss-heavy": {"seed": 0x7E12, "queries": 500_000},
    "blocked": {"seed": 0x7E13, "queries": 200_000},
}

TLDS = [("com", 60), ("net", 12), ("org", 8), ("io", 5), ("de", 5), ("co.uk", 4), ("app", 3), ("tv", 3)]
ALPHABET = "abcdefghijklmnopqrstuvwxyz"
# Rough label-length distribution of popular registrable domains (5–12 chars dominate).
LABEL_LEN = [(3, 3), (4, 6), (5, 10), (6, 12), (7, 13), (8, 12), (9, 10), (10, 9), (11, 7), (12, 6), (14, 6), (18, 6)]
SUBDOMAINS = [("", 45), ("www", 20), ("api", 6), ("cdn", 6), ("static", 4), ("img", 4), ("m", 3), ("mail", 3), ("app", 3), ("edge", 3), ("telemetry", 3)]


def weighted(rng, table):
    return rng.choices([v for v, _ in table], weights=[w for _, w in table])[0]


def label(rng):
    return "".join(rng.choice(ALPHABET) for _ in range(weighted(rng, LABEL_LEN)))


def domain(rng):
    sub = weighted(rng, SUBDOMAINS)
    name = f"{label(rng)}.{weighted(rng, TLDS)}"
    return f"{sub}.{name}" if sub else name


def qtype(rng):
    # Home traffic is mostly A/AAAA with a few HTTPS lookups from modern browsers.
    return rng.choices(["A", "AAAA", "HTTPS"], weights=[62, 30, 8])[0]


def cache_hot(spec):
    rng = random.Random(spec["seed"])
    names = list(dict.fromkeys(domain(rng) for _ in range(spec["names"] * 2)))[: spec["names"]]
    types = [qtype(rng) for _ in names]
    # Zipf over ranks: P(k) ∝ 1/k^s.
    cdf = list(itertools.accumulate(1.0 / (k ** spec["zipf_s"]) for k in range(1, len(names) + 1)))
    total = cdf[-1]
    for _ in range(spec["queries"]):
        i = bisect.bisect_left(cdf, rng.random() * total)
        yield f"{names[i]} {types[i]}"


def miss_heavy(spec):
    rng = random.Random(spec["seed"])
    parents = [domain(rng) for _ in range(1000)]
    for n in range(spec["queries"]):
        # The counter keeps every name unique across the whole file.
        yield f"m{n:x}{label(rng)}.{rng.choice(parents)} A"


def blocked(spec, lists):
    files = sorted(lists.glob("*.txt")) if lists else []
    names = []
    for f in files:
        for line in f.read_text(errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "!")):
                # Accept plain-domain and hosts-format lines.
                names.append(line.split()[-1])
    if not names:
        sys.exit(f"blocked corpus needs domain lists (*.txt) in {lists}")
    rng = random.Random(spec["seed"])
    for _ in range(spec["queries"]):
        yield f"{rng.choice(names)} A"


def generate(name, out_dir, lists=None):
    spec = CORPORA[name]
    gen = blocked(spec, lists) if name == "blocked" else {"cache-hot": cache_hot, "miss-heavy": miss_heavy}[name](spec)
    path = out_dir / f"{name}.txt"
    out_dir.mkdir(parents=True, exist_ok=True)
    data = ("\n".join(gen) + "\n").encode()
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("corpora", nargs="*", default=["cache-hot", "miss-heavy"], choices=sorted(CORPORA))
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path(__file__).parent / "corpora")
    ap.add_argument("--lists", type=pathlib.Path, default=pathlib.Path(__file__).parent / "lists")
    args = ap.parse_args()
    for name in args.corpora:
        path, digest = generate(name, args.out, args.lists)
        print(f"{name}: {path} sha256={digest}")


if __name__ == "__main__":
    main()
