#!/usr/bin/env bash
# REQ: CLU-013 — T13.2 acceptance on real processes (ADR-116): a primary, a canary replica
# (site `canary`, eligible), and a plain replica (site `plain`).
#   1. with no canaries set (the default), a change reaches every node at once;
#   2. setting canaries is published at once (a change to the rollout settings isn't staged);
#   3. ordering: a change reaches the canary and the primary first, the plain replica only after
#      the bake, and the version's outcome is `canary_promoted`;
#   4. the guard: under load, a change that makes the canary SERVFAIL fails the bake, the cluster
#      is pinned to the version before it, the plain replica never runs the bad version, and the
#      canary and the primary serve the good one again;
#   5. while pinned, configuration changes answer 409 `cluster_pinned` with the diff (a dry run
#      still works); metrics and health say pinned;
#   6. unpin and fix: the fix supersedes the bad version and is promoted;
#   7. pin an older version by hand: every node serves it, as a newer version number;
#   8. failover keeps the pin: the canary replica promoted after the primary stops stays pinned,
#      and unpinning it works.
# Usage: deploy/cluster/rollout-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P_PID= C_PID= R_PID= U_PID= LOAD_C= LOAD_P= LOAD_R=
cleanup() {
  for p in $P_PID $C_PID $R_PID $U_PID $LOAD_C $LOAD_P $LOAD_R; do kill "$p" 2>/dev/null && wait "$p" 2>/dev/null || true; done
  [ "${KEEP:-}" = 1 ] || rm -rf "$E"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  for n in p c r c2; do [ -f "$E/$n.log" ] && { echo "--- $n log"; tail -30 "$E/$n.log"; }; done
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
name = "stub"
url = "udp://127.0.0.1:25690"
[[upstream_group]]
name = "default"
members = ["stub"]
[[record]]
name = "a.ro.test"
type = "A"
value = "10.0.0.1"
EOF
}
mkdir -p "$E/p" "$E/c" "$E/r"
node_config p 25601 28601 29601 28641 > "$E/p.toml"
node_config c 25602 28602 29602 28642 > "$E/c.toml"
node_config r 25603 28603 29603 28643 > "$E/r.toml"

cat > "$E/q.py" <<'PY'
import socket, struct, sys, time, random
def query(port, name, timeout=0.5):
    """The first A record, '' for none, 'SERVFAIL', or None on timeout."""
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
    if r[3] & 0x0f == 2:
        return 'SERVFAIL'
    return '.'.join(str(b) for b in r[-4:]) if struct.unpack('>H', r[6:8])[0] else ''
if sys.argv[1] == 'one':
    a = query(int(sys.argv[2]), sys.argv[3]); print(a if a is not None else 'TIMEOUT')
elif sys.argv[1] == 'load':  # port seconds rate: random names under up.test (cache misses)
    port, secs, rate = int(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4])
    sent = servfail = lost = 0; end = time.time() + secs
    while time.time() < end:
        sent += 1
        a = query(port, 'x%d.up.test' % random.randrange(10**9), 1.0)
        servfail += a == 'SERVFAIL'
        lost += a is None
        time.sleep(1 / rate)
    print(servfail, sent, lost)
else:  # stub: an upstream answering A 10.9.9.9 for names under up.test, NXDOMAIN otherwise
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', int(sys.argv[2])))
    while True:
        q, addr = s.recvfrom(4096)
        i, labels = 12, []
        while q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode(errors='replace').lower()); i += 1 + q[i]
        qd = q[12:i + 5]
        if labels[-2:] == ['up', 'test']:
            r = q[:2] + b'\x81\x80' + struct.pack('>HHHH', 1, 1, 0, 0) + qd
            r += b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 30, 4) + bytes([10, 9, 9, 9])
        else:
            r = q[:2] + b'\x81\x83' + struct.pack('>HHHH', 1, 0, 0, 0) + qd
        s.sendto(r, addr)
PY
python3 "$E/q.py" stub 25690 & U_PID=$!
q() { python3 "$E/q.py" one "$@"; }
metric() { curl -s --max-time 2 "http://127.0.0.1:$1/metrics" | awk -v n="$2" '$1 == n {print $2}'; }
wait_answer() { # port name want seconds
  for _ in $(seq $(( $4 * 4 ))); do [ "$(q "$1" "$2")" = "$3" ] && return 0; sleep 0.25; done
  return 1
}
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

"$B" cluster init --name ro --advertise https://127.0.0.1:28641 -c "$E/p.toml" >/dev/null
TE=$("$B" cluster token create --ttl 10m --eligible -c "$E/p.toml" 2>/dev/null)
TP=$("$B" cluster token create --ttl 10m -c "$E/p.toml" 2>/dev/null)
"$B" run -c "$E/p.toml" > "$E/p.log" 2>&1 & P_PID=$!
wait_answer 25601 a.ro.test 10.0.0.1 10 || fail "the primary doesn't answer"
join() { # token args...
  local t=$1; shift
  for _ in $(seq 40); do "$B" cluster join "$t" "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done
  fail "couldn't join: $*"
}
join "$TE" --site canary --eligible --advertise https://127.0.0.1:28642 -c "$E/c.toml"
join "$TP" --site plain -c "$E/r.toml"
"$B" run -c "$E/c.toml" > "$E/c.log" 2>&1 & C_PID=$!
"$B" run -c "$E/r.toml" > "$E/r.log" 2>&1 & R_PID=$!

# The setup token is written once the API is up.
for _ in $(seq 60); do [ -s "$E/p/setup-token" ] && break; sleep 0.25; done
curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$(cat "$E/p/setup-token")\",\"username\":\"admin\",\"password\":\"e2e-password-123\"}" \
  http://127.0.0.1:28601/api/v1/auth/setup >/dev/null || fail "couldn't set up the admin"
login() { # api-port jar -> CSRF token
  for _ in $(seq 60); do
    t=$(curl -sf -c "$2" -H 'content-type: application/json' -d '{"username":"admin","password":"e2e-password-123"}' \
      "http://127.0.0.1:$1/api/v1/auth/login" 2>/dev/null | field 'd["csrfToken"]' 2>/dev/null) && [ -n "$t" ] && { echo "$t"; return 0; }
    sleep 0.5
  done
  return 1
}
CSRF=$(login 28601 "$E/jar") || fail "the admin can't sign in"
API=28601 JAR="$E/jar"
api() { # method path [json] -> HTTP status; the body in out.json
  curl -s -o "$E/out.json" -w '%{http_code}' --max-time 20 -b "$JAR" -X "$1" -H "x-csrf-token: $CSRF" \
    -H 'content-type: application/json' ${3:+-d "$3"} "http://127.0.0.1:$API/api/v1$2"
}
status() { api GET /cluster/rollout >/dev/null; field "$1" < "$E/out.json"; }
record() { api PUT "/records/$1" "{\"records\":[{\"type\":\"A\",\"value\":\"$2\"}]}"; }
wait_answer 25602 a.ro.test 10.0.0.1 20 || fail "the canary replica never synced"
wait_answer 25603 a.ro.test 10.0.0.1 20 || fail "the plain replica never synced"
sleep 6   # a heartbeat or so: the primary sees both replicas, and they take part in rollouts

echo "== 1. no canaries (the default): a change reaches every node at once"
[ "$(status 'd["stage"]')" = none ] || fail "a rollout without canaries: $(cat "$E/out.json")"
code=$(record b.ro.test 10.0.0.5)
[ "$code" = 200 ] || fail "the record change answered $code: $(cat "$E/out.json")"
[ "$(q 25603 d.ro.test)" = "" ] || fail "d.ro.test answers before it exists"
wait_answer 25603 b.ro.test 10.0.0.5 10 || fail "the plain replica didn't get the change at once"
wait_answer 25602 b.ro.test 10.0.0.5 10 || fail "the canary replica didn't get the change"
echo ok

echo "== 2. setting canaries is published at once"
code=$(api PUT /cluster/rollout-settings/default '{"canaries":["site:canary"],"bake_secs":20}')
[ "$code" = 200 ] || fail "the rollout settings answered $code: $(cat "$E/out.json")"
for _ in $(seq 40); do [ "$(status 'd["canaries"]')" = "['site:canary']" ] && break; sleep 0.25; done
[ "$(status 'd["canaries"]')" = "['site:canary']" ] || fail "the canaries didn't take: $(cat "$E/out.json")"
sleep 1
[ "$(status 'd["stage"]')" = none ] || fail "the settings change was staged: $(cat "$E/out.json")"
S1=$(status 'd["stable"]')
echo "ok (stable $S1)"

echo "== 3. ordering: canary and primary first, the rest after the bake"
code=$(record d.ro.test 10.0.0.2)
[ "$code" = 200 ] || fail "the record change answered $code: $(cat "$E/out.json")"
wait_answer 25602 d.ro.test 10.0.0.2 10 || fail "the canary didn't get the change"
[ "$(q 25601 d.ro.test)" = 10.0.0.2 ] || fail "the primary doesn't run the change"
[ "$(status 'd["stage"]')" = canary ] || fail "no rollout in progress: $(cat "$E/out.json")"
V3=$(status 'd["version"]')
for _ in 1 2 3; do
  [ "$(q 25603 d.ro.test)" = "" ] || fail "the plain replica got the change during the bake"
  sleep 3
done
wait_answer 25603 d.ro.test 10.0.0.2 40 || fail "the plain replica never got the change after the bake"
[ "$(status 'd["stage"]')" = none ] || fail "still baking after promotion"
api GET /cluster/versions >/dev/null
python3 - "$E/out.json" "$V3" <<'PY' || fail "version $V3 isn't canary_promoted: $(cat "$E/out.json")"
import json, sys
v = {i['version']: i for i in json.load(open(sys.argv[1]))['items']}
sys.exit(0 if v.get(sys.argv[2], {}).get('outcome') == 'canary_promoted' else 1)
PY
echo "ok (version $V3 promoted after the bake)"

echo "== 4. the guard fails a bad version and pins the cluster"
wait_answer 25601 ok.up.test 10.9.9.9 5 || fail "the stub upstream doesn't answer through the primary"
python3 "$E/q.py" load 25602 60 30 > "$E/load_c.txt" & LOAD_C=$!
python3 "$E/q.py" load 25601 60 30 > "$E/load_p.txt" & LOAD_P=$!
python3 "$E/q.py" load 25603 60 30 > "$E/load_r.txt" & LOAD_R=$!
sleep 25   # a bake's worth of good answers before the change
S4=$(status 'd["stable"]')
code=$(api PUT /upstreams/stub '{"url":"udp://127.0.0.1:9"}')
[ "$code" = 200 ] || fail "breaking the upstream answered $code: $(cat "$E/out.json")"
for _ in $(seq 20); do [ "$(status 'd["stage"]')" = canary ] && break; sleep 0.25; done
BAD=$(status 'd.get("version") or ""')
[ -n "$BAD" ] || fail "the bad change wasn't staged: $(cat "$E/out.json")"
t_bad=$(date +%s)
for _ in $(seq 120); do [ "$(status 'd["stage"]')" = pinned ] && break; sleep 0.5; done
[ "$(status 'd["stage"]')" = pinned ] || fail "the guard didn't pin: $(cat "$E/out.json")"
took=$(( $(date +%s) - t_bad ))
[ "$took" -lt 20 ] || fail "the guard pinned after $took s, not before the 20 s bake ended"
[ "$(status 'd["pinned"]["to"]')" = "$S4" ] || fail "pinned to the wrong version: $(cat "$E/out.json")"
[ "$(status 'd["pinned"]["by"]')" = "the guard" ] || fail "not pinned by the guard"
echo "  pinned: $(status 'd["pinned"]["reason"]')"
wait_answer 25602 y.up.test 10.9.9.9 15 || fail "the canary doesn't serve the good version again"
wait_answer 25601 z.up.test 10.9.9.9 15 || fail "the primary doesn't serve the good version again"
[ "$(q 25603 w.up.test)" = 10.9.9.9 ] || fail "the plain replica ran the bad version"
wait "$LOAD_C" "$LOAD_P" "$LOAD_R" 2>/dev/null || true; LOAD_C= LOAD_P= LOAD_R=
read -r sf_r sent_r lost_r < "$E/load_r.txt"
read -r sf_c sent_c lost_c < "$E/load_c.txt"
[ "$sf_r" = 0 ] || fail "the plain replica answered SERVFAIL $sf_r times of $sent_r"
[ "$lost_r" = 0 ] && [ "$lost_c" = 0 ] || fail "lost queries: plain replica $lost_r of $sent_r, canary $lost_c of $sent_c"
[ "$(metric 29601 'telltale_cluster_rollouts_total{outcome="failed"}')" = 1 ] || fail "the failure wasn't counted once"
grep -q "rollout failed" "$E/p.log" || fail "the primary's log doesn't say the rollout failed"
echo "ok (version $BAD failed after $took s; pinned to $S4; canary SERVFAIL $sf_c of $sent_c, 0 lost)"

echo "== 5. while pinned, changes wait: 409 cluster_pinned with the diff"
code=$(record c.ro.test 10.0.0.7)
[ "$code" = 409 ] || fail "a change while pinned answered $code"
[ "$(field 'd["code"]' < "$E/out.json")" = cluster_pinned ] || fail "not cluster_pinned: $(cat "$E/out.json")"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if any('upstream' in o['path'] for o in d.get('diff',[])) else 1)" "$E/out.json" \
  || fail "the diff doesn't name the upstream change: $(cat "$E/out.json")"
code=$(api PUT "/records/c.ro.test?dryRun=true" '{"records":[{"type":"A","value":"10.0.0.7"}]}')
[ "$code" = 200 ] || fail "a dry run while pinned answered $code"
[ "$(metric 29601 telltale_cluster_pinned)" = 1 ] || fail "telltale_cluster_pinned isn't 1"
api GET /system/health >/dev/null
grep -q cluster_pinned "$E/out.json" || fail "health doesn't say pinned: $(cat "$E/out.json")"
echo ok

echo "== 6. unpin and fix: the fix supersedes the bad version"
fixed=
for _ in 1 2 3; do
  code=$(api DELETE /cluster/pin)
  [ "$code" = 200 ] || fail "unpinning answered $code: $(cat "$E/out.json")"
  code=$(api PUT /upstreams/stub '{"url":"udp://127.0.0.1:25690"}')
  [ "$code" = 200 ] && { fixed=1; break; }
  sleep 2
done
[ -n "$fixed" ] || fail "couldn't fix the upstream after unpinning"
for _ in $(seq 120); do [ "$(status 'd["stage"]')" = none ] && break; sleep 0.5; done
[ "$(status 'd["stage"]')" = none ] || fail "the fix wasn't promoted: $(cat "$E/out.json")"
wait_answer 25603 v.up.test 10.9.9.9 10 || fail "the plain replica doesn't resolve after the fix"
wait_answer 25602 u.up.test 10.9.9.9 10 || fail "the canary doesn't resolve after the fix"
api GET /cluster/versions >/dev/null
grep -q canary_failed "$E/out.json" && grep -q superseded "$E/out.json" \
  || fail "the versions don't list both attempts: $(cat "$E/out.json")"
echo ok

echo "== 7. pin an older version by hand"
seq_r=$(metric 29603 telltale_cluster_config_seq)
code=$(api POST "/cluster/versions/$S1/pin?dryRun=true" '{"reason":"e2e: back to the start"}')
[ "$code" = 200 ] || fail "a dry-run pin answered $code: $(cat "$E/out.json")"
[ "$(field 'd["dryRun"]' < "$E/out.json")" = True ] || fail "not a dry run"
code=$(api POST "/cluster/versions/$S1/pin" '{"reason":"e2e: back to the start"}')
[ "$code" = 200 ] || fail "pinning $S1 answered $code: $(cat "$E/out.json")"
for port in 25601 25602 25603; do
  wait_answer "$port" d.ro.test "" 15 || fail "node on $port doesn't serve version $S1"
  [ "$(q "$port" b.ro.test)" = 10.0.0.5 ] || fail "node on $port lost b.ro.test from version $S1"
done
api GET "/explain?name=d.ro.test" >/dev/null
grep -q 10.0.0.2 "$E/out.json" && fail "the primary's explain still shows the newer record: $(cat "$E/out.json")"
seq_r2=$(metric 29603 telltale_cluster_config_seq)
[ "$seq_r2" -gt "$seq_r" ] || fail "the pin went backwards on the plain replica: $seq_r -> $seq_r2"
code=$(api POST /cluster/versions/9.9999/pin '{"reason":"nope"}')
[ "$code" = 404 ] || fail "pinning an unknown version answered $code"
echo "ok (every node serves $S1, as version $seq_r2)"

echo "== 8. failover keeps the pin"
kill "$P_PID"; wait "$P_PID" 2>/dev/null || true; P_PID=
kill "$C_PID"; wait "$C_PID" 2>/dev/null || true; C_PID=
"$B" cluster promote -c "$E/c.toml" >/dev/null || fail "promotion refused"
"$B" run -c "$E/c.toml" > "$E/c2.log" 2>&1 & C_PID=$!
wait_answer 25602 b.ro.test 10.0.0.5 20 || fail "the promoted node doesn't answer"
[ "$(q 25602 d.ro.test)" = "" ] || fail "the promoted node doesn't serve the pinned version"
API=28602 JAR="$E/jar2"
CSRF=$(login 28602 "$E/jar2") || fail "the admin can't sign in on the promoted node"
for _ in $(seq 40); do [ "$(status 'd["stage"]')" = pinned ] && break; sleep 0.5; done
[ "$(status 'd["stage"]')" = pinned ] || fail "the promoted node isn't pinned: $(cat "$E/out.json")"
[ "$(status 'd["fromPrimary"]')" = True ] || fail "the promoted node doesn't publish"
code=$(record c.ro.test 10.0.0.7)
[ "$code" = 409 ] || fail "a change on the promoted, pinned node answered $code"
code=$(api DELETE /cluster/pin)
[ "$code" = 200 ] || fail "unpinning on the promoted node answered $code: $(cat "$E/out.json")"
for _ in $(seq 40); do [ "$(status 'd["stage"]')" != pinned ] && break; sleep 0.5; done
[ "$(status 'd["stage"]')" != pinned ] || fail "still pinned after unpinning"
code=$(record c.ro.test 10.0.0.7)
[ "$code" = 200 ] || fail "a change after unpinning answered $code: $(cat "$E/out.json")"
wait_answer 25602 c.ro.test 10.0.0.7 30 || fail "the change after unpinning didn't apply"
echo ok
echo PASS
