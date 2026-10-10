#!/usr/bin/env bash
# REQ: CLU-005 — T5.4b acceptance on real processes (ADR-056): two eligible nodes and a
# witness in automatic failover.
#   1. the primary holds a lease granted by a majority (itself + replica + witness);
#   2. kill -9 the primary: the replica is elected within 30 s, and DNS answers 100% of a
#      steady query load throughout;
#   3. the old primary comes back, sees the newer epoch, and follows (it never publishes in
#      its old epoch again).
# REQ: OPS-010 (T13.4, ADR-118) — maintenance and elections:
#   4. with the only other eligible node in maintenance (asked on the primary, done on that
#      node), killing the primary elects nobody until maintenance ends, then that node;
#   5. maintenance on the primary hands over: the replica is elected within the lease window,
#      DNS on the old primary answers 100% throughout, and the old primary follows;
#   6. with handover = false the primary stays primary, and the answer says to promote first.
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
T=$("$B" cluster token create --ttl 10m --eligible --witness -c "$E/p.toml" 2>/dev/null)
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

# An admin, made on the primary; users reach every node (T9.1), for the maintenance steps.
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
curl -sf -c "$E/pjar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$(cat "$E/p/setup-token")\",\"username\":\"admin\",\"password\":\"e2e-password-123\"}" \
  http://127.0.0.1:28101/api/v1/auth/setup >/dev/null || fail "couldn't set up the admin"
login() { # api-port jar -> CSRF token (retries while users replicate)
  for _ in $(seq 60); do
    t=$(curl -sf -c "$2" -H 'content-type: application/json' -d '{"username":"admin","password":"e2e-password-123"}' \
      "http://127.0.0.1:$1/api/v1/auth/login" 2>/dev/null | field 'd["csrfToken"]' 2>/dev/null) && [ -n "$t" ] && { echo "$t"; return 0; }
    sleep 0.5
  done
  return 1
}
maint() { # api-port jar csrf method node [json] -> HTTP status; the body in m.json
  curl -s -o "$E/m.json" -w '%{http_code}' --max-time 20 -b "$2" -X "$4" -H "x-csrf-token: $3" \
    -H 'content-type: application/json' ${6:+-d "$6"} "http://127.0.0.1:$1/api/v1/nodes/$5/maintenance"
}
# A node's ID (requests name a node by its ID, site, or pod).
node_id() { "$B" cluster status -c "$E/$1.toml" | awk '$1 == "node" {print $2; exit}'; }

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

echo "== 4. a node in maintenance isn't elected (OPS-010)"
sleep 6   # p just restarted: let its streams to r settle (a heartbeat or so)
RCSRF=$(login 28102 "$E/rjar") || fail "the admin can't sign in on the new primary"
P_ID=$(node_id p)
code=$(maint 28102 "$E/rjar" "$RCSRF" POST "$P_ID" '{"forSecs":600,"reason":"e2e: keep p out"}')
[ "$code" = 200 ] || fail "maintenance for p through the primary answered $code: $(cat "$E/m.json")"
grep -q '"handover":"not_needed"' "$E/m.json" || fail "a replica needs no handover: $(cat "$E/m.json")"
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:29101/readyz)" = 503 ] || fail "p is still ready in maintenance"
kill -9 "$R_PID"; wait "$R_PID" 2>/dev/null || true; R_PID=
for _ in $(seq 40); do
  [ "$(metric 29101 telltale_cluster_lease_held)" = 0 ] || fail "p was elected while in maintenance"
  [ "$(q 25401 a.fo.test)" = 10.0.0.1 ] || fail "p stopped answering DNS"
  sleep 1
done
PCSRF=$(login 28101 "$E/pjar") || fail "the admin can't sign in on p"
code=$(maint 28101 "$E/pjar" "$PCSRF" DELETE local)
[ "$code" = 200 ] || fail "ending p's maintenance answered $code: $(cat "$E/m.json")"
t0=$(date +%s)
wait_metric 29101 telltale_cluster_lease_held 1 40 || fail "p wasn't elected after its maintenance ended"
echo "ok (nobody elected for 40 s; p elected $(( $(date +%s) - t0 )) s after its maintenance ended)"

echo "== 5. maintenance on the primary hands over (OPS-010)"
"$B" run -c "$E/r.toml" > "$E/r2.log" 2>&1 & R_PID=$!
wait_metric 29102 telltale_cluster_primary 0 30 || fail "r didn't follow after restarting"
for _ in $(seq 60); do [ "$(metric 29102 telltale_cluster_failover_auto)" = 1 ] && break; sleep 0.5; done
for _ in $(seq 60); do [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:29102/readyz)" = 200 ] && break; sleep 0.5; done
sleep 6   # a heartbeat or two: p sees r connected and eligible
python3 "$E/q.py" load 25401 a.fo.test 40 50 > "$E/load2.txt" & LOAD=$!
sleep 2
t0=$(date +%s)
code=$(maint 28101 "$E/pjar" "$PCSRF" POST local '{"forSecs":600,"reason":"e2e: hand over"}')
[ "$code" = 200 ] || fail "maintenance on the primary answered $code: $(cat "$E/m.json")"
grep -q '"handover":"started"' "$E/m.json" || fail "the primary didn't start a handover: $(cat "$E/m.json")"
wait_metric 29102 telltale_cluster_lease_held 1 40 || fail "r wasn't elected after the handover started"
took=$(( $(date +%s) - t0 ))
[ "$took" -le 30 ] || fail "the handover took $took s (more than the lease window and a round)"
wait_metric 29101 telltale_cluster_primary 0 30 || fail "the old primary didn't follow"
wait "$LOAD"; LOAD=
read -r ok sent < "$E/load2.txt"
[ "$ok" = "$sent" ] || fail "DNS on the old primary dropped answers during the handover: $ok of $sent"
code=$(maint 28101 "$E/pjar" "$PCSRF" DELETE local)
[ "$code" = 200 ] || fail "ending the old primary's maintenance answered $code"
[ "$(metric 29102 telltale_cluster_lease_held)" = 1 ] || fail "r lost its lease when p's maintenance ended"
echo "ok (r elected after ${took} s; $ok of $sent queries to p answered)"

echo "== 6. handover = false: the primary stays primary (OPS-010)"
RCSRF=$(login 28102 "$E/rjar") || fail "the admin can't sign in on r"
code=$(maint 28102 "$E/rjar" "$RCSRF" POST local '{"forSecs":120,"reason":"e2e: stay","handover":false}')
[ "$code" = 200 ] || fail "maintenance with handover=false answered $code"
grep -q '"handover":"declined"' "$E/m.json" && grep -q 'promote another node first' "$E/m.json" \
  || fail "no note to promote first: $(cat "$E/m.json")"
for _ in $(seq 20); do
  [ "$(metric 29102 telltale_cluster_lease_held)" = 1 ] || fail "the primary lost its lease with handover=false"
  sleep 1
done
code=$(maint 28102 "$E/rjar" "$RCSRF" DELETE local)
[ "$code" = 200 ] || fail "ending r's maintenance answered $code"
echo "ok"
echo PASS
