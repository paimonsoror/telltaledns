#!/usr/bin/env bash
# REQ: CLU-010 — rolling upgrade with live traffic: an older build (N-1) and this build (N)
# in one cluster, both ways round, while a client with two DNS servers keeps querying.
#   1. both nodes on N-1; the replica follows;
#   2. the replica upgraded to N follows the N-1 primary (an edit reaches it);
#   3. the primary upgraded to N; the N replica follows;
#   4. the replica back on N-1 follows the N primary (an edit reaches it);
#   5. REQ: CLU-013 — a staged rollout with an N-1 replica: a canary on N gets the change first;
#      the N-1 replica, though its site is named a canary too, is only ever sent stable versions
#      (it gets the change after the bake);
#   and the client never fails a query (it tries the other server when one doesn't answer).
# Usage: deploy/cluster/upgrade-e2e.sh <old telltale> [new telltale (default target/debug)]
set -euo pipefail
OLD=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
NEW=${2:-target/debug/telltale}
NEW=$(cd "$(dirname "$NEW")" && pwd)/$(basename "$NEW")
E=$(mktemp -d)
P_PID= R_PID= C_PID= LOAD=
cleanup() {
  for p in $P_PID $R_PID $C_PID $LOAD; do kill "$p" 2>/dev/null && wait "$p" 2>/dev/null || true; done
  [ "${KEEP:-}" = 1 ] || rm -rf "$E"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  # Annotations are readable without a token (job logs aren't).
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  for f in "$E"/*.log; do echo "--- $(basename "$f")"; tail -15 "$f"; done
  exit 1
}
echo "old: $("$OLD" --version)   new: $("$NEW" --version)"

node_config() { # name dns-port metrics-port cluster-port value
  cat <<EOF
[node]
name = "$1"
data_dir = "$E/$1"
[[listen]]
proto = "udp"
addr = "127.0.0.1:$2"
[telemetry.metrics]
listen = "127.0.0.1:$3"
[api]
listen = "127.0.0.1:$(( $3 + 100 ))"
[cluster]
listen = "127.0.0.1:$4"
[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"
[[upstream_group]]
name = "default"
members = ["nowhere"]
[[record]]
name = "up.test"
type = "A"
value = "$5"
EOF
}
mkdir -p "$E/p" "$E/r" "$E/c"
node_config p 25501 29201 28641 10.0.0.1 > "$E/p.toml"
node_config r 25502 29202 28642 10.0.0.1 > "$E/r.toml"
node_config c 25503 29203 28643 10.0.0.1 > "$E/c.toml"

cat > "$E/q.py" <<'PY'
import os, socket, struct, sys, time, random
def query(port, name, timeout):
    q = struct.pack('>HHHHHH', random.randrange(65536), 0x0100, 1, 0, 0, 0)
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
    a = query(int(sys.argv[2]), sys.argv[3], 0.5); print(a if a is not None else 'TIMEOUT')
else:  # load primary-port replica-port stop-file: like a client with two DNS servers
    p, r, stop = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    sent = ok = 0
    while not os.path.exists(stop):
        sent += 1
        first, second = (p, r) if sent % 2 else (r, p)
        a = query(first, 'up.test', 0.4)
        if not a:
            a = query(second, 'up.test', 0.4)
        ok += bool(a)
        time.sleep(0.02)
    print(ok, sent)
PY
q() { python3 "$E/q.py" one "$@"; }
wait_answer() { # port value seconds
  for _ in $(seq $(( $3 * 10 ))); do [ "$(q "$1" up.test)" = "$2" ] && return 0; sleep 0.1; done
  return 1
}
start_p() { "$1" run -c "$E/p.toml" >> "$E/p.log" 2>&1 & P_PID=$!; }
start_r() { "$1" run -c "$E/r.toml" >> "$E/r.log" 2>&1 & R_PID=$!; }
stop_p() { kill "$P_PID"; wait "$P_PID" 2>/dev/null || true; P_PID=; }
stop_r() { kill "$R_PID"; wait "$R_PID" 2>/dev/null || true; R_PID=; }
edit() { # value: change the record on the primary and reload it
  sed -i "s/^value = \".*\"/value = \"$1\"/" "$E/p.toml"
  kill -HUP "$P_PID"
}

echo "== 1. both on N-1"
"$OLD" cluster init --name up --advertise https://127.0.0.1:28641 -c "$E/p.toml" >/dev/null
start_p "$OLD"
wait_answer 25501 10.0.0.1 10 || fail "the old primary never answered"
# The token decides eligibility (05-01): ask for an eligible one. Builds from before that
# change have no --eligible here and took the joiner's word for it.
T=$("$OLD" cluster token create --eligible --ttl 10m -c "$E/p.toml" 2>/dev/null ||
    "$OLD" cluster token create --ttl 10m -c "$E/p.toml" 2>/dev/null)
# DNS answers a moment before the cluster port listens: retry the join briefly.
joined=
for _ in $(seq 50); do
  if "$OLD" cluster join "$T" --site r --eligible --advertise https://127.0.0.1:28642 -c "$E/r.toml" >/dev/null 2>&1; then
    joined=1; break
  fi
  sleep 0.2
done
[ -n "$joined" ] || fail "the replica couldn't join the old primary"
start_r "$OLD"
wait_answer 25502 10.0.0.1 15 || fail "the old replica never followed"
python3 "$E/q.py" load 25501 25502 "$E/stop" > "$E/load.txt" & LOAD=$!
echo ok

echo "== 2. replica on N follows the N-1 primary"
stop_r; start_r "$NEW"
wait_answer 25502 10.0.0.1 10 || fail "the new replica doesn't answer"
edit 10.0.0.2
wait_answer 25502 10.0.0.2 15 || fail "an edit on the N-1 primary didn't reach the N replica"
echo ok

echo "== 3. primary on N"
stop_p; start_p "$NEW"
wait_answer 25501 10.0.0.2 10 || fail "the new primary doesn't answer"
edit 10.0.0.3
wait_answer 25502 10.0.0.3 15 || fail "an edit on the N primary didn't reach the N replica"
echo ok

echo "== 4. replica back on N-1 follows the N primary"
stop_r; start_r "$OLD"
wait_answer 25502 10.0.0.3 10 || fail "the old replica doesn't answer"
edit 10.0.0.4
wait_answer 25502 10.0.0.4 15 || fail "an edit on the N primary didn't reach the N-1 replica"
echo ok

echo "== 5. a staged rollout: the N-1 replica gets stable versions only (CLU-013)"
T=$("$NEW" cluster token create --ttl 10m -c "$E/p.toml" 2>/dev/null)
"$NEW" cluster join "$T" --site canary -c "$E/c.toml" >/dev/null || fail "the canary couldn't join"
"$NEW" run -c "$E/c.toml" >> "$E/c.log" 2>&1 & C_PID=$!
wait_answer 25503 10.0.0.4 15 || fail "the canary never synced"
sleep 6   # a heartbeat: the primary knows the canary takes part in rollouts
# The N-1 replica's site is named too: it must still never be sent a canary version.
printf '\n[cluster.rollout]\ncanaries = ["site:canary", "site:r"]\nbake_secs = 20\n' >> "$E/p.toml"
kill -HUP "$P_PID"
sleep 3   # the settings change is published at once
edit 10.0.0.5
wait_answer 25503 10.0.0.5 10 || fail "the N canary didn't get the change first"
for _ in 1 2 3; do
  [ "$(q 25502 up.test)" = 10.0.0.4 ] || fail "the N-1 replica got the canary version"
  sleep 3
done
wait_answer 25502 10.0.0.5 40 || fail "the N-1 replica never got the version after the bake"
grep -q "canary node" "$E/p.log" || fail "the primary didn't stage the change"
echo ok

touch "$E/stop"; wait "$LOAD"; LOAD=
read -r ok sent < "$E/load.txt"
echo "client with two servers: $ok of $sent queries answered"
[ "$ok" = "$sent" ] || fail "queries failed during the rolling upgrade"
echo PASS
