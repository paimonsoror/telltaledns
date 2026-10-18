"""REQ: NFR-001 (T10.4) — cold start with the compiled snapshot on disk, the gate in `spec/00` §5.

  python3 bench/coldstart.py --bin target/release/telltale     # 1M names, 5 restarts

Starts the stub upstream and a server with `--names` blocked names the way `gate.py` does,
waits for the first compile, then restarts the server `--runs` times and prints, for each:
when `/readyz` answered, when a blocked name was first answered as blocked over DNS (the
gate figure; polled every 5 ms), and when the lookup index was built (blocking works before
it, through the FST walk).
"""

import argparse
import pathlib
import statistics
import sys
import tempfile

import bench
import gate


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=str(bench.ROOT / "target/bench-fast/telltale"))
    ap.add_argument("--server-cpus", default="0-3")
    ap.add_argument("--client-cpus", default="4-7")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--outstanding", type=int, default=200)
    ap.add_argument("--duration", type=int, default=20)
    ap.add_argument("--names", type=int, default=1_000_000)
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()

    tmp = tempfile.TemporaryDirectory(prefix="telltale-cold-")
    d = pathlib.Path(tmp.name)
    names = gate.blocked_names(args.names)
    lst = gate.write_lines(d / "names.txt", names)
    st = gate.Stack(args, d, lst)
    rows = []
    try:
        st.start()
        bench.wait_filter(f"{gate.URL}/metrics", st.server)
        for i in range(args.runs):
            st.stop_server()
            t0, ready = st.start()
            blk = gate.wait_blocked(names[i::997], st.server)
            idx = bench.wait_filter(f"{gate.URL}/metrics", st.server)
            row = [round((t - t0) * 1000, 1) for t in (ready, blk, idx)]
            rows.append(row)
            print(f"run {i + 1}: ready {row[0]} ms, blocking {row[1]} ms, index {row[2]} ms", file=sys.stderr)
        # The detector itself: names not on the lists must never count as blocked.
        try:
            gate.wait_blocked([f"not-listed-{n}.example.net" for n in range(200)], st.server, timeout=2)
            sys.exit("a name not on the lists was answered as blocked: the detector is wrong")
        except RuntimeError:
            print("check: names not on the lists get the upstream's answer", file=sys.stderr)
    finally:
        st.close()
        tmp.cleanup()
    med = [statistics.median(c) for c in zip(*rows)]
    print(f"median: ready {med[0]} ms, blocking {med[1]} ms (gate ≤ 500), index {med[2]} ms")
    return 0 if med[1] <= 500 else 1


if __name__ == "__main__":
    sys.exit(main())
