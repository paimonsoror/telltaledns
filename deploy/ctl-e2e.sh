#!/usr/bin/env bash
# REQ: API-008 — T7.25 acceptance: `telltale ctl` against a running node with an API token:
# status, block (and the name is blocked in DNS), rules, unrule, pause/resume, flush, lists,
# queries, raw get, --json, and a clear error for a bad token. Needs python3, dig, curl.
# Usage: deploy/ctl-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
cd "$(dirname "$0")/.."
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P=
cleanup() {
  local rc=$?
  [ -n "$P" ] && kill "$P" 2>/dev/null && { wait "$P" 2>/dev/null || true; }
  rm -rf "$E"
  exit "$rc"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  [ -f "$E/node.log" ] && tail -15 "$E/node.log"
  exit 1
}
trap 'fail "line $LINENO: \`$BASH_COMMAND\` failed"' ERR
API=http://127.0.0.1:26991
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

cat > "$E/telltale.toml" <<EOF
[node]
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25991"
[api]
listen = "127.0.0.1:26991"
[telemetry.metrics]
listen = "127.0.0.1:27991"
[telemetry.qlog]
flush_interval_secs = 1
[[record]]
name = "nas.ctl.test"
type = "A"
value = "10.0.0.8"
[[list]]
name = "ads"
rules = ["ads.ctl.test"]
EOF
"$B" run -c "$E/telltale.toml" > "$E/node.log" 2>&1 & P=$!
for _ in $(seq 100); do curl -s -o /dev/null "$API/api/v1/auth/status" && break; sleep 0.1; done
ST=$(cat "$E/data/setup-token")
CSRF=$(curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$ST\",\"username\":\"admin\",\"password\":\"ctl-e2e-pass-1\"}" \
  "$API/api/v1/auth/setup" | field 'd["csrfToken"]')
export TELLTALE_TOKEN
TELLTALE_TOKEN=$(curl -sf -b "$E/jar" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -d '{"name":"ctl-e2e","scope":"write"}' "$API/api/v1/tokens" | field 'd["token"]')
ctl() { "$B" ctl --url "$API" "$@"; }

ctl status | grep -q "^TelltaleDNS" || fail "status"
echo "status: ok"

# Block a name now: DNS blocks it, the rule is listed, and it can be removed.
dig +short -p 25991 @127.0.0.1 safe.ctl.test >/dev/null || true
ctl block safe.ctl.test --note "ctl e2e" | grep -q "^done" || fail "block"
for _ in $(seq 20); do [[ $(dig +time=1 -p 25991 @127.0.0.1 safe.ctl.test) == *"EDE: 15"* ]] && break; sleep 0.2; done
[[ $(dig +time=1 -p 25991 @127.0.0.1 safe.ctl.test) == *"EDE: 15"* ]] || fail "the blocked name still resolves"
ctl rules | grep -q "block-safe-ctl-test" || fail "rules"
ctl rules --json | python3 -c 'import sys, json; assert json.load(sys.stdin)["items"][0]["domain"] == "safe.ctl.test"' || fail "rules --json"
ctl unrule block-safe-ctl-test | grep -q removed || fail "unrule"
echo "block/rules/unrule: ok"

ctl pause --minutes 5 | grep -q "paused" || fail "pause"
ctl get blocking | python3 -c 'import sys, json; d = json.load(sys.stdin); assert d["items"][0]["pauses"], d' || fail "paused state"
ctl resume | grep -q "resumed" || fail "resume"
ctl flush | grep -q "^flushed" || fail "flush"
ctl lists | grep -qE "^ads +block" || fail "lists"
echo "pause/resume/flush/lists: ok"

dig +short -p 25991 @127.0.0.1 nas.ctl.test >/dev/null
sleep 2 # the query log flushes every second here
ctl queries --name nas.ctl.test | grep -q "nas.ctl.test" || fail "queries"
ctl get stats/summary from=-1h | python3 -c 'import sys, json; assert json.load(sys.stdin)["queries"] >= 1' || fail "raw get"
echo "queries/get: ok"

if TELLTALE_TOKEN=nope ctl status 2> "$E/err"; then fail "a bad token was accepted"; fi
grep -q "HTTP 401" "$E/err" || fail "bad token: $(cat "$E/err")"
echo "ctl-e2e: ok"
