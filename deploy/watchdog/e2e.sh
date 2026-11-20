#!/usr/bin/env bash
# REQ: OPS-012 (ADR-163, GitHub issue #7) — the watchdog on a real process. The binary is built with
# `--features wedge-test` (never in a release build): `TT_WEDGE_AFTER_SECS=6` blocks every
# runtime worker six seconds after start, as a deadlock would, while the UDP workers keep answering.
#   1. before the wedge, DNS answers;
#   2. with `[watchdog] stall_secs = 20` the process writes its dump and exits with status 70 within
#      about 40 s (a supervising loop here plays systemd);
#   3. exactly one dump exists, private (0640 in a 0750 directory), saying the runtime did not run a
#      task, with the thread table, a stack of raw addresses for the blocked workers, the
#      executable's mappings, and the restart is recorded;
#   4. when the binary has symbols (a debug build), the blocked workers' stacks resolve to the
#      function the wedge sits in, with `addr2line`;
#   5. the next run (not wedged) says in its log that the previous one was restarted by the
#      watchdog, answers DNS, and reports the watchdog's metrics.
# Usage: deploy/watchdog/e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
SUP_PID= N_PID=
cleanup() {
  for p in $SUP_PID $N_PID; do kill "$p" 2>/dev/null && wait "$p" 2>/dev/null || true; done
  [ "${KEEP:-}" = 1 ] || rm -rf "$E"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  [ -f "$E/node.log" ] && { echo "--- node log"; tail -30 "$E/node.log"; }
  [ -d "$E/data/watchdog" ] && { echo "--- watchdog dir"; ls -l "$E/data/watchdog"; }
  [ "${KEEP:-}" = 1 ] && echo "files kept in $E"
  exit 1
}

mkdir -p "$E/data"
cat > "$E/t.toml" <<EOF
[node]
name = "wd"
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25901"
[api]
listen = "127.0.0.1:28901"
[telemetry.metrics]
listen = "127.0.0.1:29901"
[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"
[[upstream_group]]
name = "default"
members = ["nowhere"]
[[record]]
name = "a.wd.test"
type = "A"
value = "10.0.0.1"
[watchdog]
stall_secs = 20
EOF

cat > "$E/q.py" <<'PY'
import socket, struct, sys, random
def query(port, name, timeout=0.5):
    qid = random.randrange(65536)
    q = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    q += b''.join(bytes([len(l)]) + l.encode() for l in name.split('.')) + b'\0' + struct.pack('>HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        s.sendto(q, ('127.0.0.1', port)); r, _ = s.recvfrom(4096)
    except OSError:
        return None
    finally:
        s.close()
    return '.'.join(str(b) for b in r[-4:]) if struct.unpack('>H', r[6:8])[0] else ''
a = query(int(sys.argv[1]), sys.argv[2]); print(a if a is not None else 'TIMEOUT')
PY
q() { python3 "$E/q.py" "$@"; }

# The node, wedged six seconds after it starts; this script is its supervisor (it reads the exit status).
TT_WEDGE_AFTER_SECS=6 "$B" run -c "$E/t.toml" >> "$E/node.log" 2>&1 & SUP_PID=$!

# 1. DNS answers before the wedge.
for _ in $(seq 60); do [ "$(q 25901 a.wd.test)" = 10.0.0.1 ] && break; sleep 0.1; done
[ "$(q 25901 a.wd.test)" = 10.0.0.1 ] || fail "the node didn't answer before the wedge"

# 2. The watchdog ends the process with status 70.
for _ in $(seq 120); do kill -0 "$SUP_PID" 2>/dev/null || break; sleep 1; done
kill -0 "$SUP_PID" 2>/dev/null && fail "the process was still running 120 s after the wedge: the watchdog didn't act"
set +e; wait "$SUP_PID"; RC=$?; set -e; SUP_PID=
[ "$RC" = 70 ] || fail "the process exited with $RC, not 70"
echo "ok: exit 70"

# 3. One private dump with the evidence.
D="$E/data/watchdog"
[ "$(ls "$D"/hang-*.txt 2>/dev/null | wc -l)" = 1 ] || fail "expected exactly one dump"
F=$(ls "$D"/hang-*.txt)
[ "$(stat -c %a "$F")" = 640 ] || fail "the dump is mode $(stat -c %a "$F"), not 640"
[ "$(stat -c %a "$D")" = 750 ] || fail "the directory is mode $(stat -c %a "$D"), not 750"
grep -q "runtime: the runtime did not run a task for" "$F" || fail "the dump doesn't say the runtime stalled"
grep -q "exits with status 70" "$F" || fail "the dump doesn't say it restarts"
grep -qE "^== threads \([0-9]+\)" "$F" || fail "no thread table"
grep -q " telltale-rt " "$F" || fail "no runtime worker in the thread table"
grep -qE "^telltale-rt \([0-9]+\): 0x[0-9a-f]+" "$F" || fail "no stack for a runtime worker"
grep -q "== executable mappings" "$F" && grep -qE "r-xp" "$F" || fail "no executable mapping"
grep -q "== log, last" "$F" || fail "no log"
grep -qE "^runtime workers: [0-9]+, tasks alive: [0-9]+, waiting in the global queue: [0-9]+" "$F" || fail "no runtime numbers"
[ "$(wc -l < "$D/restarts")" = 1 ] || fail "the restart wasn't recorded once"
echo "ok: the dump has the reason, threads, stacks, mappings, and log"

# 4. Symbols (a debug build): the blocked workers sit in the wedge's function.
nm "$B" > "$E/nm.txt" 2>/dev/null || true
if grep -q wedge_here "$E/nm.txt" && command -v addr2line >/dev/null; then
  type=$(readelf -h "$B" | awk '/Type:/ {print $2}')
  base=0
  if [ "$type" = DYN ]; then
    m=$(awk '/r-xp|r--p/ && /\/telltale/ {print; exit}' "$F")
    start=$(echo "$m" | awk '{print $1}' | cut -d- -f1); off=$(echo "$m" | awk '{print $3}')
    base=$(( 16#$start - 16#$off ))
  fi
  addrs=$(grep -E "^telltale-rt \(" "$F" | grep -oE "0x[0-9a-f]+" | while read -r a; do printf '0x%x\n' $(( a - 1 - base )); done)
  # shellcheck disable=SC2086
  names=$(addr2line -f -C -e "$B" $addrs | tr '\n' ' ')
  echo "$names" | grep -q wedge_here || fail "no worker stack resolves to wedge_here: $names"
  echo "ok: the workers' stacks resolve to wedge_here"
else
  echo "skip: this binary has no symbols, so the stacks are not resolved"
fi

# 5. The next run says why it was restarted, answers, and reports the watchdog.
"$B" run -c "$E/t.toml" >> "$E/node2.log" 2>&1 & N_PID=$!
for _ in $(seq 60); do [ "$(q 25901 a.wd.test)" = 10.0.0.1 ] && break; sleep 0.2; done
[ "$(q 25901 a.wd.test)" = 10.0.0.1 ] || fail "the restarted node doesn't answer"
grep -q "the previous run was restarted by the watchdog" "$E/node2.log" || { cp "$E/node2.log" "$E/node.log"; fail "the log doesn't say the previous run was restarted by the watchdog"; }
for _ in $(seq 40); do
  M=$(curl -sf http://127.0.0.1:29901/metrics) || M=
  echo "$M" | grep -q '^telltale_watchdog_check_age_seconds{check="runtime"}' && break
  sleep 0.5
done
[ -n "$M" ] || fail "no metrics"
echo "$M" | grep -q '^telltale_watchdog_enabled 1' || fail "telltale_watchdog_enabled isn't 1"
echo "$M" | grep -q '^telltale_watchdog_check_age_seconds{check="runtime"}' || fail "no runtime check age"
echo "$M" | grep -qE '^telltale_watchdog_last_action_timestamp_seconds [1-9]' || fail "no last action time"
echo "ok: the next run says why, answers, and reports"
echo "PASS"
