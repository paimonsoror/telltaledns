#!/usr/bin/env bash
# REQ: CLU-003, CLU-004 — T5.2/T5.3 acceptance on two real processes (a primary and a replica):
#   1. the replica takes the primary's configuration and lists (and drops its own);
#   2. an edit on the primary reaches the replica within 5 s;
#   3. killing the primary leaves the replica answering 100% of a steady query load;
#   4. the replica, restarted with the primary down, answers within 500 ms of starting;
#   5. failover (ADR-051): the eligible replica got the cluster key, is promoted while the
#      primary is down, and serves the last version it had; the old primary comes back, steps
#      down, follows the new primary, and keeps its unseen edit under Conflicts.
# Plus CLU-002 (T5.6): the primary's stats and query log include the replica's queries;
# (T5.7): a change made on the replica's API is forwarded to the primary, reaches both
# nodes, and the primary's audit log names the user and the entry node; (T9.1): users and
# tokens made on the primary work on the replica, and changing them there is refused; (T5.8): the
# replica's query log, in ship mode, ends up on the primary and is still searchable.
# Usage: deploy/cluster/e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P_PID= R_PID=
cleanup() {
  # Wait for both to exit: the listeners use SO_REUSEPORT, so a node still draining would
  # share its ports with the next run's (flaked locally when runs followed each other).
  [ -n "$P_PID" ] && kill "$P_PID" 2>/dev/null && wait "$P_PID" 2>/dev/null || true
  [ -n "$R_PID" ] && kill "$R_PID" 2>/dev/null && wait "$R_PID" 2>/dev/null || true
  [ "${KEEP:-}" = 1 ] || rm -rf "$E"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  # Annotations are readable without a token (job logs aren't).
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  echo "--- primary log"; tail -30 "$E/p.log" || true
  echo "--- replica log"; tail -30 "$E/r.log" || true
  if [ "${KEEP:-}" = 1 ]; then echo "logs kept in $E"; fi
  exit 1
}

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
[telemetry.qlog]
enabled = true
flush_interval_secs = 1
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
# The replica ships its query log to the primary (CLU-007).
cat >> "$E/r.toml" <<EOF
[telemetry]
mode = "ship"
[telemetry.ship]
interval_secs = 10
EOF
# A record that stays on the replica (CLU-006).
cat >> "$E/r.toml" <<EOF
[[record]]
name = "mine.r.test"
type = "A"
value = "10.0.0.1"
node_only = true
EOF

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
"$B" cluster join "$T" --site r --eligible --advertise https://127.0.0.1:28442 -c "$E/r.toml" >/dev/null
"$B" run -c "$E/r.toml" > "$E/r.log" 2>&1 & R_PID=$!

echo "== 1. the replica follows the primary"
for _ in $(seq 100); do [ "$(q 25302 a.p.test)" = 10.0.0.1 ] && break; sleep 0.1; done
[ "$(q 25302 a.p.test)" = 10.0.0.1 ] || fail "replica doesn't serve the primary's record"
[ "$(q 25302 own.r.test)" != 10.0.0.1 ] || fail "replica still serves its own record"
[ "$(q 25302 mine.r.test)" = 10.0.0.1 ] || fail "replica lost its node-only record (CLU-006)"
[ "$(q 25301 mine.r.test)" != 10.0.0.1 ] || fail "a node-only record reached the primary"
for _ in $(seq 50); do [ "$(q 25302 ads.p.test)" = 0.0.0.0 ] && break; sleep 0.1; done
[ "$(q 25302 ads.p.test)" = 0.0.0.0 ] || fail "replica doesn't block with the primary's list"
echo "ok"

echo "== cache-warm hints (CLU-011)"
# The primary answered a.p.test while starting: the replica warms its cache with it.
for _ in $(seq 150); do grep -q "cache warm: resolving" "$E/r.log" && break; sleep 0.1; done
grep -q "cache warm: resolving the cluster's hot names" "$E/r.log" ||
  fail "the replica didn't take the primary's hot names to warm its cache"
echo "ok"

echo "== federated reads (CLU-002)"
for i in $(seq 5); do q 25302 "fed$i.r.test" >/dev/null; done
API=http://127.0.0.1:28001
ST=$(cat "$E/p/setup-token")
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
PCSRF=$(curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$ST\",\"username\":\"admin\",\"password\":\"e2e-password-123\"}" \
  "$API/api/v1/auth/setup" | field 'd["csrfToken"]') || fail "couldn't set up the primary's admin"
get() { curl -sf -b "$E/jar" "$API$1"; }
found=""
for _ in $(seq 30); do
  found=$(get '/api/v1/queries?name=fed1.r.test' | field '" ".join(r.get("node","") for r in d["items"])')
  [ -n "$found" ] && break; sleep 0.5
done
[ "$found" = r ] || fail "the primary's query log doesn't show the replica's query (got '$found')"
[ "$(get '/api/v1/queries?name=fed1.r.test&scope=node:local' | field 'len(d["items"])')" = 0 ] \
  || fail "scope=node:local returned another node's rows"
both=$(get '/api/v1/stats/summary' | field 'd["queries"]')
own=$(get '/api/v1/stats/summary?scope=node:local' | field 'd["queries"]')
[ "$both" -gt "$own" ] || fail "cluster totals ($both) don't exceed this node's ($own)"
echo "ok (cluster $both queries, primary alone $own)"

# REQ: AGT-011, CLU-002 (T7.3) — a read scoped to a site or a node reads only those nodes.
echo "== scoped reads (AGT-011)"
for s in site:r node:r; do
  [ "$(get "/api/v1/queries?name=fed1.r.test&scope=$s" | field 'len(d["items"])')" -ge 1 ] \
    || fail "scope=$s missed the replica's query"
done
site_r=$(get '/api/v1/stats/summary?scope=site:r' | field 'd["queries"]')
{ [ "$site_r" -gt 0 ] && [ "$site_r" -lt "$both" ]; } || fail "site:r totals ($site_r) aren't a part of the cluster's ($both)"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$E/jar" "$API/api/v1/stats/summary?scope=site:nowhere")
[ "$code" = 400 ] || fail "an unknown site answered $code"
echo "ok (site r: $site_r of $both)"

# REQ: OBS-008, CLU-002 (T9.2) — the primary's live tail shows the replica's queries, labelled,
# and latency percentiles cover both nodes (exact histogram merge).
echo "== cluster-wide live tail and latency (T9.2)"
curl -sN --max-time 8 -b "$E/jar" "$API/api/v1/queries/stream?name=tail.r.test" > "$E/tail.txt" &
TAILP=$!
sleep 2.5
for _ in $(seq 3); do q 25302 tail.r.test >/dev/null; sleep 0.3; done
wait "$TAILP" 2>/dev/null || true
grep -q 'tail.r.test' "$E/tail.txt" || fail "the primary's live tail didn't show the replica's query"
grep -q '"node":"r"' "$E/tail.txt" || fail "the replica's rows in the tail don't name it ($(head -c 300 "$E/tail.txt"))"
lat_all=$(get '/api/v1/stats/latency?by=path' | field 'sum(r["count"] for r in d["items"])')
lat_own=$(get '/api/v1/stats/latency?by=path&scope=node:local' | field 'sum(r["count"] for r in d["items"])')
[ "$lat_all" -gt "$lat_own" ] || fail "cluster latency counts ($lat_all) don't exceed this node's ($lat_own)"
echo "ok (tail labelled; latency over $lat_all queries, $lat_own here)"

# REQ: CLU-003, API-003 (T9.1, ADR-045) — the primary's users and tokens reach the replica.
echo "== users and tokens replicate (T9.1)"
RAPI=http://127.0.0.1:28002
CSRF=""
for _ in $(seq 60); do
  CSRF=$(curl -sf -c "$E/rjar" -H 'content-type: application/json' \
    -d '{"username":"admin","password":"e2e-password-123"}' "$RAPI/api/v1/auth/login" 2>/dev/null \
    | field 'd["csrfToken"]' 2>/dev/null) && [ -n "$CSRF" ] && break
  sleep 0.5
done
[ -n "$CSRF" ] || fail "the primary's admin can't sign in on the replica"
TOKEN=$(curl -sf -b "$E/jar" -H "x-csrf-token: $PCSRF" -H 'content-type: application/json' \
  -d '{"name":"e2e-replicated"}' "$API/api/v1/tokens" | field 'd["token"]') || fail "couldn't make a token on the primary"
code=000
for _ in $(seq 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $TOKEN" "$RAPI/api/v1/system/info")
  [ "$code" = 200 ] && break; sleep 0.5
done
[ "$code" = 200 ] || fail "a token made on the primary doesn't work on the replica ($code)"
code=$(curl -s -o "$E/user.json" -w '%{http_code}' -b "$E/rjar" -H "x-csrf-token: $CSRF" \
  -H 'content-type: application/json' -d '{"username":"carol","password":"e2e-password-456","role":"viewer"}' \
  "$RAPI/api/v1/users")
{ [ "$code" = 409 ] && grep -q 'managed on the cluster' "$E/user.json"; } \
  || fail "making a user on the replica wasn't refused ($code: $(cat "$E/user.json"))"
echo "ok (sign-in and a token work on the replica; user changes there are refused)"

echo "== write forwarding (CLU-002)"
code=$(curl -s -o "$E/fwd.json" -w '%{http_code}' -b "$E/rjar" -X PUT -H "x-csrf-token: $CSRF" \
  -H 'content-type: application/json' -d '{"records":[{"type":"A","value":"10.0.0.1"}]}' \
  "$RAPI/api/v1/records/fwd.e2e.test")
[ "$code" = 200 ] || fail "a write on the replica wasn't forwarded ($code: $(cat "$E/fwd.json"))"
for _ in $(seq 50); do [ "$(q 25302 fwd.e2e.test)" = 10.0.0.1 ] && break; sleep 0.1; done
[ "$(q 25301 fwd.e2e.test)" = 10.0.0.1 ] || fail "the forwarded record isn't on the primary"
[ "$(q 25302 fwd.e2e.test)" = 10.0.0.1 ] || fail "the forwarded record didn't come back to the replica"
get '/api/v1/audit' | grep -q 'admin via r' || fail "the primary's audit log doesn't name the user and entry node"
echo "ok"

echo "== quick rules made on the replica apply on every node (T6.12, ADR-067)"
code=$(curl -s -o "$E/rule.json" -w '%{http_code}' -b "$E/rjar" -X PUT -H "x-csrf-token: $CSRF" \
  -H 'content-type: application/json' -d '{"action":"block","domain":"qr1.e2e.test","note":"cluster e2e"}' \
  "$RAPI/api/v1/rules/e2e-cluster")
[ "$code" = 200 ] || fail "a quick rule on the replica wasn't forwarded ($code: $(cat "$E/rule.json"))"
for _ in $(seq 50); do [ "$(q 25302 x.qr1.e2e.test)" = 0.0.0.0 ] && break; sleep 0.1; done
[ "$(q 25301 x.qr1.e2e.test)" = 0.0.0.0 ] || fail "the quick rule doesn't block on the primary"
[ "$(q 25302 x.qr1.e2e.test)" = 0.0.0.0 ] || fail "the quick rule doesn't block on the replica"
listed=$(curl -sf -b "$E/rjar" "$RAPI/api/v1/rules" | field '" ".join(r["id"] for r in d["items"])')
[ "$listed" = e2e-cluster ] || fail "the replica's GET /api/v1/rules doesn't list the rule (got '$listed')"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$E/rjar" -X DELETE -H "x-csrf-token: $CSRF" \
  "$RAPI/api/v1/rules/e2e-cluster")
[ "$code" = 200 ] || fail "removing the quick rule through the replica answered $code"
for _ in $(seq 50); do [ "$(q 25302 x.qr1.e2e.test)" != 0.0.0.0 ] && break; sleep 0.1; done
[ "$(q 25301 x.qr1.e2e.test)" != 0.0.0.0 ] || fail "the removed quick rule still blocks on the primary"
[ "$(q 25302 x.qr1.e2e.test)" != 0.0.0.0 ] || fail "the removed quick rule still blocks on the replica"
echo "ok"

echo "== the Cache page lists every node's cache (T6.15)"
# The federated backend once lacked this read: the table came back empty on clustered nodes.
nodes=$(curl -sf -b "$E/rjar" "$RAPI/api/v1/cache/entries?limit=5" | field 'len([n for n in d["items"] if n.get("makeup") is not None and not n.get("error")])')
[ "$nodes" = 2 ] || fail "GET /api/v1/cache/entries on the replica listed $nodes nodes' caches, not 2"
names=$(curl -sf -b "$E/rjar" "$RAPI/api/v1/cache/entries?limit=5" | field '" ".join(sorted(str(n.get("node")) for n in d["items"]))')
echo "ok ($names)"

echo "== query-log ship mode (CLU-007)"
q 25302 ship1.r.test >/dev/null
# A part closes after interval_secs (on the next query), then the shipper delivers it. Wait
# for the part holding ship1 (an earlier part may already have arrived).
shipped="" node=""
for i in $(seq 60); do
  q 25302 "tick$i.r.test" >/dev/null
  node=$(get '/api/v1/queries?name=ship1.r.test&scope=node:local' | field '" ".join(r.get("node","") for r in d["items"])')
  [ "$node" = r ] && break; sleep 1
done
shipped=$(curl -s http://127.0.0.1:29001/metrics | awk '/^telltale_qlog_received_segments_total/ {print $2}')
[ "${shipped:-0}" -gt 0 ] || fail "the primary never received the replica's query log"
ls "$E/p/qlog-nodes/"*/ >/dev/null 2>&1 || fail "no shipped query log under the primary's qlog-nodes"
[ "$node" = r ] || fail "the primary's own search doesn't show the shipped row as the replica's (got '$node')"
# REQ: CLU-007 (T9.3) — and its per-minute counts (dashboard history that outlives the node).
minutes=0
for _ in $(seq 90); do
  minutes=$(python3 -c "import sqlite3; print(sqlite3.connect('$E/p/rollups.db').execute('SELECT count(*) FROM shipped_minute').fetchone()[0])" 2>/dev/null || echo 0)
  [ "${minutes:-0}" -gt 0 ] && break; sleep 1
done
[ "${minutes:-0}" -gt 0 ] || fail "the replica's per-minute counts never reached the primary"
echo "ok ($shipped parts and $minutes minutes received)"

# The cluster's settings travel too: a new authority on the primary reaches the replica.
"$B" cluster set-authority gitops -c "$E/p.toml" >/dev/null
kill "$P_PID"; wait "$P_PID" 2>/dev/null || true
"$B" run -c "$E/p.toml" > "$E/p1b.log" 2>&1 & P_PID=$!
for _ in $(seq 100); do grep -q '"gitops"' "$E/r/cluster/cluster.json" && break; sleep 0.1; done
grep -q '"config_authority": "gitops"' "$E/r/cluster/cluster.json" || fail "the replica didn't learn the new config authority"
"$B" cluster set-authority api -c "$E/p.toml" >/dev/null
kill "$P_PID"; wait "$P_PID" 2>/dev/null || true
"$B" run -c "$E/p.toml" > "$E/p1c.log" 2>&1 & P_PID=$!
for _ in $(seq 100); do grep -q '"config_authority": "api"' "$E/r/cluster/cluster.json" && break; sleep 0.1; done
for _ in $(seq 50); do [ "$(q 25301 a.p.test)" = 10.0.0.1 ] && break; sleep 0.1; done
echo "ok: authority propagates"

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
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -b "$E/rjar" -X DELETE \
  -H "x-csrf-token: $CSRF" "$RAPI/api/v1/records/fwd.e2e.test")
[ "$code" = 503 ] || fail "a write on the replica with the primary down answered $code, not 503"
echo "a write with the primary down: 503, as expected"

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
echo "== 5. failover: promote the replica, fence the old primary (ADR-051)"
[ -f "$E/r/cluster/ca.key" ] || fail "the eligible replica never received the cluster key"
# The old primary comes back and publishes an edit the replica never sees.
"$B" run -c "$E/p.toml" > "$E/p2.log" 2>&1 & P_PID=$!
for _ in $(seq 50); do [ "$(q 25301 a.p.test)" = 10.0.0.1 ] && break; sleep 0.1; done
kill "$R_PID"; wait "$R_PID" 2>/dev/null || true; R_PID=
cat >> "$E/p.toml" <<EOF
[[record]]
name = "c.p.test"
type = "A"
value = "10.0.0.1"
EOF
pubseq() { python3 -c "import json;print(json.load(open('$E/p/cluster/published.json'))['seq'])" 2>/dev/null || echo 0; }
before=$(pubseq)
kill -HUP "$P_PID"
for _ in $(seq 50); do [ "$(q 25301 c.p.test)" = 10.0.0.1 ] && break; sleep 0.1; done
[ "$(q 25301 c.p.test)" = 10.0.0.1 ] || fail "the primary didn't apply its own edit"
# Wait until the edit is actually published (a slow runner can take longer than a second):
# only a published version the replica never saw is an orphan.
for _ in $(seq 150); do [ "$(pubseq)" -gt "$before" ] && break; sleep 0.1; done
[ "$(pubseq)" -gt "$before" ] || fail "the primary never published its edit (seq still $before)"
kill "$P_PID"; wait "$P_PID" 2>/dev/null || true; P_PID=
# Promote the replica while the primary is down.
"$B" cluster promote -c "$E/r.toml" | head -1
"$B" run -c "$E/r.toml" > "$E/r3.log" 2>&1 & R_PID=$!
for _ in $(seq 50); do [ "$(q 25302 b.p.test)" = 10.0.0.1 ] && break; sleep 0.1; done
[ "$(q 25302 b.p.test)" = 10.0.0.1 ] || fail "the promoted node lost the cluster's configuration"
[ "$(q 25302 c.p.test)" != 10.0.0.1 ] || fail "the promoted node has an edit it never received"
"$B" cluster status -c "$E/r.toml" | grep -q 'role       primary' || fail "the replica isn't primary after promotion"
# The old primary returns: it must step down and follow, keeping its edit as a conflict.
"$B" run -c "$E/p.toml" > "$E/p3.log" 2>&1 & P_PID=$!
# Up to 30 s: on a slow CI runner the step-down (and the conflict record) can take a while.
for _ in $(seq 300); do ls "$E/p/cluster/conflicts/" 2>/dev/null | grep -q '\.json$' && break; sleep 0.1; done
for _ in $(seq 50); do [ "$(q 25301 c.p.test)" != 10.0.0.1 ] && break; sleep 0.1; done
[ "$(q 25301 c.p.test)" != 10.0.0.1 ] || fail "the old primary still serves its orphaned edit"
[ "$(q 25301 b.p.test)" = 10.0.0.1 ] || fail "the old primary doesn't serve the cluster's configuration"
"$B" cluster status -c "$E/p.toml" | grep -q 'role       replica' || fail "the old primary didn't step down"
ls "$E/p/cluster/conflicts/" 2>/dev/null | grep -q '^1-.*[0-9]\.json$' || {
  echo "conflicts dir: $(ls -la "$E/p/cluster/conflicts/" 2>&1 | tr '\n' ' ')"
  grep -iE 'conflict|stepping down|epoch|orphan' "$E/p3.log" | tail -15
  # Annotations are public (job logs aren't): what each side did, for the next failure.
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::warning title=old primary (p3)::$(grep -iE 'cluster|applied|sync|manifest|published|stepping|orphan|conflict|epoch|error|warn' "$E/p3.log" | tail -14 | cut -c28-200 | tr '\n' '|')"
    echo "::warning title=new primary (r3)::$(grep -iE 'cluster|applied|sync|manifest|published|promot|epoch|error|warn' "$E/r3.log" | tail -14 | cut -c28-200 | tr '\n' '|')"
    echo "::warning title=old primary files::published=$(tr -d '\n ' < "$E/p/cluster/published.json" 2>/dev/null | cut -c1-160) applied=$(python3 -c "import json;m=json.load(open('$E/p/cluster/applied.json'));print(m.get('epoch'),m.get('seq'),m.get('base'))" 2>/dev/null)"
  fi
  fail "no conflict recorded for the orphaned version (conflicts: $(ls "$E/p/cluster/conflicts/" 2>&1 | tr '\n' ' '); log: $(grep -iE 'conflict|stepping down' "$E/p3.log" | tail -3 | cut -c1-160 | tr '\n' '|'))"
}
grep -q '"record"' "$E/p/cluster/conflicts/"1-*[0-9].json || fail "the conflict doesn't name the changed setting"
grep -h 'stepping down\|kept under Conflicts' "$E/p3.log" | cut -c1-140
echo "ok"
echo "PASS"
