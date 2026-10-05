#!/usr/bin/env bash
# REQ: CLU-003, CLU-004 — T5.2/T5.3 acceptance on two real processes (a primary and a replica):
#   1. the replica takes the primary's configuration and lists (and drops its own);
#   2. an edit on the primary reaches the replica within 5 s;
#   3. killing the primary leaves the replica answering 100% of a steady query load;
#   4. the replica, restarted with the primary down, answers within 500 ms of starting.
# Usage: deploy/cluster/e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P_PID= R_PID=
cleanup() {
  [ -n "$P_PID" ] && kill "$P_PID" 2>/dev/null || true
  [ -n "$R_PID" ] && kill "$R_PID" 2>/dev/null || true
  [ "${KEEP:-}" = 1 ] || rm -rf "$E"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- primary log"; tail -30 "$E/p.log" || true; echo "--- replica log"; tail -30 "$E/r.log" || true; exit 1; }

node_config() { # name dns-port api-port metrics-port cluster-port record list-rule
  cat <<EOF
[node]
name = "$1"
data_dir = "$E/$1"
[[listen]]
proto = "udp"
addr = "127.0.0.1:$2"
[api]
listen = "127.0.0.1:$3"
[telemetry.metrics]
listen = "127.0.0.1:$4"
[cluster]
listen = "127.0.0.1:$5"
[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"
[[upstream_group]]
name = "default"
members = ["nowhere"]
[[list]]
name = "$1-block"
rules = ["$7"]
[[record]]
name = "$6"
type = "A"
value = "10.0.0.1"
EOF
}
mkdir -p "$E/p" "$E/r"
node_config p 25301 28001 29001 28441 a.p.test '||ads.p.test^' > "$E/p.toml"
node_config r 25302 28002 29002 28442 own.r.test '||ads.r.test^' > "$E/r.toml"

# One A query over UDP; prints the first answer address (empty if none) — no dig needed.
cat > "$E/q.py" <<'PY'
import socket, struct, sys, time, random
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
    an = struct.unpack('>H', r[6:8])[0]
    if an == 0:
        return ''
    return '.'.join(str(b) for b in r[-4:])
mode = sys.argv[1]
if mode == 'one':
    a = query(int(sys.argv[2]), sys.argv[3]); print(a if a is not None else 'TIMEOUT')
elif mode == 'load':  # port name seconds rate -> answered/sent
    port, name, secs, rate = int(sys.argv[2]), sys.argv[3], float(sys.argv[4]), int(sys.argv[5])
    sent = ok = 0; end = time.time() + secs
    while time.time() < end:
        sent += 1; ok += query(port, name) == '10.0.0.1'; time.sleep(1 / rate)
    print(f'{ok} {sent}')
elif mode == 'first':  # port name timeout_s since -> seconds from `since` (Unix) to the first good answer
    port, name, limit, t0 = int(sys.argv[2]), sys.argv[3], float(sys.argv[4]), float(sys.argv[5])
    while time.time() - t0 < limit:
        if query(port, name, 0.05) == '10.0.0.1':
            print(f'{time.time() - t0:.3f}'); break
    else:
        print('never')
PY
q() { python3 "$E/q.py" one "$@"; }

"$B" cluster init --name e2e --advertise https://127.0.0.1:28441 -c "$E/p.toml" >/dev/null
"$B" run -c "$E/p.toml" > "$E/p.log" 2>&1 & P_PID=$!
for _ in $(seq 50); do [ "$(q 25301 a.p.test)" = 10.0.0.1 ] && break; sleep 0.1; done
T=$("$B" cluster token create --ttl 10m -c "$E/p.toml" 2>/dev/null)
"$B" cluster join "$T" --site r -c "$E/r.toml" >/dev/null
"$B" run -c "$E/r.toml" > "$E/r.log" 2>&1 & R_PID=$!

echo "== 1. the replica follows the primary"
for _ in $(seq 100); do [ "$(q 25302 a.p.test)" = 10.0.0.1 ] && break; sleep 0.1; done
[ "$(q 25302 a.p.test)" = 10.0.0.1 ] || fail "replica doesn't serve the primary's record"
[ "$(q 25302 own.r.test)" != 10.0.0.1 ] || fail "replica still serves its own record"
for _ in $(seq 50); do [ "$(q 25302 ads.p.test)" = 0.0.0.0 ] && break; sleep 0.1; done
[ "$(q 25302 ads.p.test)" = 0.0.0.0 ] || fail "replica doesn't block with the primary's list"
echo "ok"

echo "== 2. an edit on the primary propagates"
cat >> "$E/p.toml" <<EOF
[[record]]
name = "b.p.test"
type = "A"
value = "10.0.0.1"
EOF
t0=$(date +%s.%N); kill -HUP "$P_PID"
for _ in $(seq 100); do [ "$(q 25302 b.p.test)" = 10.0.0.1 ] && break; sleep 0.05; done
[ "$(q 25302 b.p.test)" = 10.0.0.1 ] || fail "edit didn't reach the replica in 5 s"
echo "ok: $(python3 -c "print(f'{$(date +%s.%N) - $t0:.2f}')") s"

echo "== 3. killing the primary: the replica keeps answering (CLU-004)"
python3 "$E/q.py" load 25302 a.p.test 6 200 > "$E/load.txt" &
LOAD=$!
sleep 2; kill -9 "$P_PID"; P_PID=
wait "$LOAD"
read -r ok sent < "$E/load.txt"
echo "answered $ok of $sent"
[ "$ok" = "$sent" ] || fail "the replica dropped answers while the primary died"

echo "== 4. replica cold start without the primary (≤ 500 ms)"
kill "$R_PID"; wait "$R_PID" 2>/dev/null || true; R_PID=
start=$(date +%s.%N)
"$B" run -c "$E/r.toml" > "$E/r2.log" 2>&1 & R_PID=$!
first=$(python3 "$E/q.py" first 25302 b.p.test 5 "$start")
echo "first answer ${first} s after launching the process"
[ "$first" != never ] || fail "the replica never answered"
python3 -c "import sys; sys.exit(0 if float('$first') <= 0.5 else 1)" || fail "cold start took ${first} s (> 0.5)"
for _ in $(seq 40); do [ "$(q 25302 ads.p.test)" = 0.0.0.0 ] && break; sleep 0.05; done
[ "$(q 25302 ads.p.test)" = 0.0.0.0 ] || fail "the replica forgot the primary's list after a restart"
echo "PASS"
