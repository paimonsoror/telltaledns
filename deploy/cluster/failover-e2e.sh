#!/usr/bin/env bash
# REQ: CLU-005 — T5.4b acceptance on real processes (ADR-056): two eligible nodes and a
# witness in automatic failover.
#   1. the primary holds a lease granted by a majority (itself + replica + witness);
#   2. kill -9 the primary: the replica is elected within 30 s, and DNS answers 100% of a
#      steady query load throughout;
#   3. the old primary comes back, sees the newer epoch, and follows (it never publishes in
#      its old epoch again).
# Usage: deploy/cluster/failover-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P_PID= R_PID= W_PID= LOAD=
cleanup() {
  for p in $P_PID $R_PID $W_PID $LOAD; do kill "$p" 2>/dev/null && wait "$p" 2>/dev/null || true; done
  [ "${KEEP:-}" = 1 ] || rm -rf "$E"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  # Annotations are readable without a token (job logs aren't).
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  for n in p r w p2; do [ -f "$E/$n.log" ] && { echo "--- $n log"; tail -25 "$E/$n.log"; }; done
  [ "${KEEP:-}" = 1 ] && echo "logs kept in $E"
  exit 1
}

node_config() { # name dns-port api-port metrics-port cluster-port
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
[[record]]
name = "a.fo.test"
type = "A"
value = "10.0.0.1"
EOF
}
mkdir -p "$E/p" "$E/r" "$E/w"
node_config p 25401 28101 29101 28541 > "$E/p.toml"
node_config r 25402 28102 29102 28542 > "$E/r.toml"
# A witness needs only its data directory and cluster port.
cat > "$E/w.toml" <<EOF
[node]
name = "w"
data_dir = "$E/w"
[cluster]
listen = "127.0.0.1:28543"
EOF

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
    return '.'.join(str(b) for b in r[-4:]) if struct.unpack('>H', r[6:8])[0] else ''
if sys.argv[1] == 'one':
    a = query(int(sys.argv[2]), sys.argv[3]); print(a if a is not None else 'TIMEOUT')
else:  # load port name seconds rate
    port, name, secs, rate = int(sys.argv[2]), sys.argv[3], float(sys.argv[4]), int(sys.argv[5])
    sent = ok = 0; end = time.time() + secs
    while time.time() < end:
        sent += 1; ok += query(port, name, 0.3) == '10.0.0.1'; time.sleep(1 / rate)
    print(ok, sent)
PY
q() { python3 "$E/q.py" one "$@"; }
metric() { # metrics-port name -> value (empty if unreachable)
  curl -s --max-time 2 "http://127.0.0.1:$1/metrics" | awk -v n="$2" '$1 == n {print $2}'
}
wait_metric() { # port name value seconds
  for _ in $(seq $(( $4 * 4 ))); do [ "$(metric "$1" "$2")" = "$3" ] && return 0; sleep 0.25; done
  return 1
}

"$B" cluster init --name fo --advertise https://127.0.0.1:28541 -c "$E/p.toml" >/dev/null
"$B" cluster set-failover auto -c "$E/p.toml" >/dev/null
T=$("$B" cluster token create --ttl 10m -c "$E/p.toml" 2>/dev/null)
"$B" run -c "$E/p.toml" > "$E/p.log" 2>&1 & P_PID=$!
for _ in $(seq 50); do [ "$(q 25401 a.fo.test)" = 10.0.0.1 ] && break; sleep 0.1; done
join() { # retries until the primary's cluster port is up
  for _ in $(seq 40); do "$B" cluster join "$T" "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done
  fail "couldn't join: $*"
}
join --site r --eligible --advertise https://127.0.0.1:28542 -c "$E/r.toml"
join --site w --witness --advertise https://127.0.0.1:28543 -c "$E/w.toml"
"$B" run -c "$E/r.toml" > "$E/r.log" 2>&1 & R_PID=$!
"$B" cluster witness -c "$E/w.toml" > "$E/w.log" 2>&1 & W_PID=$!

echo "== 1. the primary holds a majority lease"
wait_metric 29101 telltale_cluster_failover_auto 1 30 || fail "automatic failover never turned on at the primary"
wait_metric 29102 telltale_cluster_failover_auto 1 30 || fail "automatic failover never turned on at the replica"
wait_metric 29101 telltale_cluster_lease_held 1 30 || fail "the primary never held a lease"
[ "$(metric 29102 telltale_cluster_primary)" = 0 ] || fail "the replica thinks it's primary"
# The replica must hold the cluster key to be able to win.
for _ in $(seq 40); do [ -f "$E/r/cluster/ca.key" ] && break; sleep 0.25; done
[ -f "$E/r/cluster/ca.key" ] || fail "the eligible replica never received the cluster key"
echo "ok (epoch $(metric 29101 telltale_cluster_epoch))"

echo "== 2. kill the primary: the replica is elected, DNS never stops"
python3 "$E/q.py" load 25402 a.fo.test 40 50 > "$E/load.txt" & LOAD=$!
sleep 2
t0=$(date +%s)
kill -9 "$P_PID"; wait "$P_PID" 2>/dev/null || true; P_PID=
wait_metric 29102 telltale_cluster_lease_held 1 40 || fail "the replica wasn't elected within 40 s"
took=$(( $(date +%s) - t0 ))
[ "$took" -le 30 ] || fail "election took $took s (more than 30)"
epoch=$(metric 29102 telltale_cluster_epoch)
[ "$epoch" -ge 2 ] || fail "the new primary's epoch is $epoch"
wait "$LOAD"; LOAD=
read -r ok sent < "$E/load.txt"
[ "$ok" = "$sent" ] || fail "DNS dropped answers during failover: $ok of $sent"
grep -q "elected" "$E/r.log" || fail "the replica's log doesn't record its election"
echo "ok (elected after ${took} s, epoch $epoch; $ok of $sent queries answered)"

echo "== 3. the old primary returns and follows"
"$B" run -c "$E/p.toml" > "$E/p2.log" 2>&1 & P_PID=$!
wait_metric 29101 telltale_cluster_primary 0 30 || fail "the old primary didn't step down"
wait_metric 29101 telltale_cluster_epoch "$epoch" 30 || fail "the old primary didn't adopt epoch $epoch"
[ "$(metric 29102 telltale_cluster_lease_held)" = 1 ] || fail "the new primary lost its lease when the old one returned"
[ "$(q 25401 a.fo.test)" = 10.0.0.1 ] || fail "the old primary doesn't answer after rejoining"
echo "ok"
echo PASS
