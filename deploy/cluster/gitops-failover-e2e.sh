#!/usr/bin/env bash
# REQ: CLU-005 (ADR-154, GitHub issue #3) — a Git-managed node takes over from an emergency
# primary under automatic failover, on real processes. Three eligible nodes, the GitOps
# authority, `failover = auto`: g is Git-managed, n1 and n2 are not.
#   1. g is the primary and holds a lease granted by a majority;
#   2. kill -9 g: one of n1/n2 is elected and becomes an emergency primary (it coordinates on
#      the last version);
#   3. g comes back as a replica; about a minute after it sees the emergency primary up it asks
#      it to hand over, and g, not the other non-Git node, is elected (the hold-back), as the
#      primary rather than an emergency one, with DNS on the emergency primary answered
#      throughout.
# Usage: deploy/cluster/gitops-failover-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
G_PID= N1_PID= N2_PID= LOAD=
cleanup() {
  for p in $G_PID $N1_PID $N2_PID $LOAD; do kill "$p" 2>/dev/null && wait "$p" 2>/dev/null || true; done
  [ "${KEEP:-}" = 1 ] || rm -rf "$E"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  # Annotations are readable without a token (job logs aren't).
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  for n in g g2 n1 n1b n2 n2b; do [ -f "$E/$n.log" ] && { echo "--- $n log"; tail -25 "$E/$n.log"; }; done
  [ "${KEEP:-}" = 1 ] && echo "logs kept in $E"
  exit 1
}

# name dns-port api-port metrics-port cluster-port [extra [cluster] lines]
node_config() {
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
${6:-}
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
mkdir -p "$E/g" "$E/n1" "$E/n2"
# g's own configuration comes from Git (the marker is what makes a node Git-managed; no
# repository is needed to test who holds the role).
node_config g 25601 28201 29201 28641 'config_source = "gitops"' > "$E/g.toml"
node_config n1 25602 28202 29202 28642 > "$E/n1.toml"
node_config n2 25603 28203 29203 28643 > "$E/n2.toml"

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
# BEGIN epoch-report — REQ: CLU-005. deploy/systemd/portwait-test.sh runs this block, with `metric`
# above, against a port nothing listens on.
# This script runs under `set -euo pipefail` and `metric` returns curl's status, so a bare
# `epoch=$(metric ...)` ended the run with no FAIL line and no log dump when a node's metrics
# couldn't be read at that moment. These say so and go on.
epoch_of() { # metrics-port -> the node's cluster epoch; nothing (and a note) when it can't be read
  local e
  e=$(metric "$1" telltale_cluster_epoch || true)
  [ -n "$e" ] || echo "note: couldn't read the epoch on :$1" >&2
  printf '%s' "$e"
}
epoch_advance() { # before after -> how far the epoch moved; ? when either is unknown
  if [ -n "$1" ] && [ -n "$2" ]; then echo $(( $2 - $1 )); else echo '?'; fi
}
# END epoch-report

"$B" cluster init --name gf --advertise https://127.0.0.1:28641 --config-authority gitops -c "$E/g.toml" >/dev/null
"$B" cluster set-failover auto -c "$E/g.toml" >/dev/null
T=$("$B" cluster token create --ttl 20m --eligible -c "$E/g.toml" 2>/dev/null)
"$B" run -c "$E/g.toml" > "$E/g.log" 2>&1 & G_PID=$!
for _ in $(seq 50); do [ "$(q 25601 a.fo.test)" = 10.0.0.1 ] && break; sleep 0.1; done
join() { # retries until the primary's cluster port is up
  for _ in $(seq 40); do "$B" cluster join "$T" "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done
  fail "couldn't join: $*"
}
join --site n1 --eligible --advertise https://127.0.0.1:28642 -c "$E/n1.toml"
join --site n2 --eligible --advertise https://127.0.0.1:28643 -c "$E/n2.toml"
"$B" run -c "$E/n1.toml" > "$E/n1.log" 2>&1 & N1_PID=$!
"$B" run -c "$E/n2.toml" > "$E/n2.log" 2>&1 & N2_PID=$!

echo "== 1. g, the Git-managed node, is the primary and holds a lease"
for port in 29201 29202 29203; do
  wait_metric $port telltale_cluster_failover_auto 1 40 || fail "automatic failover never turned on at :$port"
done
wait_metric 29201 telltale_cluster_lease_held 1 40 || fail "g never held a lease"
for n in n1 n2; do
  for _ in $(seq 60); do [ -f "$E/$n/cluster/ca.key" ] && break; sleep 0.25; done
  [ -f "$E/$n/cluster/ca.key" ] || fail "$n never received the cluster key"
done
echo "ok (epoch $(metric 29201 telltale_cluster_epoch))"

echo "== 2. kill g: a node that isn't Git-managed becomes the emergency primary"
epoch_before=$(epoch_of 29201)
t0=$(date +%s)
kill -9 "$G_PID"; wait "$G_PID" 2>/dev/null || true; G_PID=
EMERG=; OTHER=; EMERG_MET=; OTHER_MET=; EMERG_DNS=
for _ in $(seq 240); do
  if [ "$(metric 29202 telltale_cluster_lease_held)" = 1 ]; then
    EMERG=n1; OTHER=n2; EMERG_MET=29202; OTHER_MET=29203; EMERG_DNS=25602; break
  fi
  if [ "$(metric 29203 telltale_cluster_lease_held)" = 1 ]; then
    EMERG=n2; OTHER=n1; EMERG_MET=29203; OTHER_MET=29202; EMERG_DNS=25603; break
  fi
  sleep 0.25
done
[ -n "$EMERG" ] || fail "nobody was elected within 60 s of g's death"
took=$(( $(date +%s) - t0 ))
epoch=$(epoch_of "$EMERG_MET")
# REQ: CLU-005 — spec/12 §10: after the primary is killed, a new primary within 30 s. One election
# round takes about one lease (15 s) and moves the epoch by one. When both candidates ask at once,
# the one whose node ID sorts after the other's gives way (ADR-178), so the vote doesn't split; a
# split round would cost another lease (31 to 35 s, seen before ADR-178 in 12 of 79 CI runs), which
# already passes the spec's 30 s. This limit tolerates one such round and no more: a third round
# (about 50 s) fails the step on purpose, with how far the epoch moved in the message, because it
# is a finding about the election (spec/12 §5), not noise in the test. Widening it would hide it.
advanced=$(epoch_advance "$epoch_before" "$epoch")
[ "$took" -le 45 ] || fail "the election took $took s: the epoch advanced $advanced time(s), from ${epoch_before:-?} to ${epoch:-?} (a round takes about 15 s and moves it by one; a second round means the candidates split the vote, and spec/12 §10 allows 30 s in all)"
[ "${epoch:-0}" -ge 2 ] || fail "the new primary's epoch is '${epoch}' (its metrics couldn't be read, or it is below 2)"
grep 'elected primary' "$E/$EMERG.log" | grep -q 'role.*Emergency' || fail "$EMERG wasn't made an emergency primary: $(grep 'elected primary' "$E/$EMERG.log" | tail -1)"
[ "$(q "$EMERG_DNS" a.fo.test)" = 10.0.0.1 ] || fail "$EMERG doesn't answer DNS"
echo "ok ($EMERG elected after ${took} s as an emergency primary, epoch $epoch: the epoch advanced $advanced time(s) from ${epoch_before:-?})"

echo "== 3. g returns; it asks the emergency primary to hand over and is elected"
"$B" run -c "$E/g.toml" > "$E/g2.log" 2>&1 & G_PID=$!
wait_metric 29201 telltale_cluster_primary 0 40 || fail "g didn't follow the emergency primary after restarting"
t1=$(date +%s)
# TAKEOVER_AFTER (60 s) plus the 10 s checks, once g has applied the emergency primary's version.
for _ in $(seq 360); do
  grep -q "asked the emergency primary to hand over" "$E/g2.log" && break
  sleep 0.5
done
grep -q "asked the emergency primary to hand over" "$E/g2.log" \
  || fail "g never asked for a handover: $(grep -i 'takeover\|hand over' "$E/g2.log" | tail -3)"
asked=$(( $(date +%s) - t1 ))
python3 "$E/q.py" load "$EMERG_DNS" a.fo.test 40 25 > "$E/load.txt" & LOAD=$!
wait_metric 29201 telltale_cluster_lease_held 1 60 || fail "g wasn't elected after it asked (the other node holds: $(metric "$OTHER_MET" telltale_cluster_lease_held))"
took=$(( $(date +%s) - t1 - asked ))
[ "$took" -le 40 ] || fail "g's election took $took s after the ask"
wait_metric "$EMERG_MET" telltale_cluster_primary 0 30 || fail "the emergency primary didn't step down"
[ "$(metric "$OTHER_MET" telltale_cluster_primary)" = 0 ] || fail "$OTHER became primary instead of g (the hold-back failed)"
[ "$(metric "$OTHER_MET" telltale_cluster_lease_held)" = 0 ] || fail "$OTHER holds a lease"
epoch2=$(epoch_of 29201)
[ "${epoch2:-0}" -gt "$epoch" ] || fail "g's epoch '${epoch2:-unreadable}' isn't newer than $epoch"
grep 'elected primary' "$E/g2.log" | grep -q 'role.*Primary' || fail "g wasn't made the primary: $(grep 'elected primary' "$E/g2.log" | tail -1)"
wait "$LOAD"; LOAD=
read -r ok sent < "$E/load.txt"
[ "$ok" = "$sent" ] || fail "DNS on $EMERG dropped answers during the handover: $ok of $sent"
for p in 25601 25602 25603; do [ "$(q $p a.fo.test)" = 10.0.0.1 ] || fail "a node doesn't answer DNS on :$p"; done
echo "ok (g asked after ${asked} s, elected ${took} s later, epoch $epoch2; $ok of $sent queries to $EMERG answered)"
echo PASS
