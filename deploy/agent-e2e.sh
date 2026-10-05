#!/usr/bin/env bash
# REQ: AGT-002, AGT-004, AGT-005, AGT-009 — T6.5 acceptance on a running node:
#   1. an admin creates an agent token with write scopes; the agent reads what its scopes allow
#      and is refused the rest (the query log, users, tokens, backups);
#   2. every mutation (devices, local names, forwarded domains: put and delete) has a dry run
#      that reports an impact and changes nothing; a change without a reason is refused;
#   3. a real change is attributed `agent:<token> (owner: admin) via <client>` with its reason;
#   4. `[agents] enabled = false` and a reload refuse the agent and not the admin.
# Usage: deploy/agent-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
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
command -v dig >/dev/null || { echo "needs dig"; exit 2; }
API=http://127.0.0.1:26991
q() { dig +short +time=1 +tries=2 -p 25991 @127.0.0.1 "$@"; }
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

write_config() { # agents enabled?
  cat > "$E/telltale.toml" <<EOF
[node]
name = "agent-e2e"
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25991"
[api]
listen = "127.0.0.1:26991"
[telemetry.metrics]
listen = "127.0.0.1:27991"
[agents]
enabled = $1
EOF
}
write_config true
"$B" run -c "$E/telltale.toml" > "$E/node.log" 2>&1 & P=$!
for _ in $(seq 100); do curl -s -o /dev/null "$API/api/v1/auth/status" && break; sleep 0.1; done

echo "== 1. an agent token and its scopes"
ST=$(cat "$E/data/setup-token")
CSRF=$(curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$ST\",\"username\":\"admin\",\"password\":\"agent-e2e-pass-1\"}" \
  "$API/api/v1/auth/setup" | field 'd["csrfToken"]')
AGENT=$(curl -sf -b "$E/jar" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
  -d '{"name":"helper","kind":"agent","scopes":["analytics:read","config:read","config:write:*"]}' \
  "$API/api/v1/tokens" | field 'd["token"]') || fail "creating an agent token"
code() { # method path [body] [reason]
  local args=(-s -o "$E/out.json" -w '%{http_code}' -X "$1" -H "authorization: Bearer $AGENT"
    -H 'x-telltale-client: agent-e2e/1.0' -H 'content-type: application/json')
  [ -n "${3:-}" ] && args+=(-d "$3")
  [ -n "${4:-}" ] && args+=(-H "x-telltale-reason: $4")
  curl "${args[@]}" "$API$2"
}
[ "$(code GET /api/v1/stats/summary)" = 200 ] || fail "the agent can't read statistics"
[ "$(code GET /api/v1/clients)" = 200 ] || fail "the agent can't read devices"
for p in /api/v1/queries /api/v1/users /api/v1/tokens /api/v1/backup /api/v1/audit; do
  [ "$(code GET "$p")" = 403 ] || fail "the agent wasn't refused $p ($(cat "$E/out.json"))"
done
echo ok

echo "== 2. a dry run for every change"
dry() { # method path body
  local c; c=$(code "$1" "$2?dryRun=true" "$3" "trying it")
  [ "$c" = 200 ] || fail "dry run of $1 $2: $c $(cat "$E/out.json")"
  [ "$(field 'd["applied"]' < "$E/out.json")" = False ] || fail "dry run of $1 $2 says applied"
  [ -n "$(field 'd.get("impact","")' < "$E/out.json")" ] || fail "dry run of $1 $2 has no impact"
}
dry PUT /api/v1/clients/tv '{"match":["192.168.1.40"]}'
dry PUT /api/v1/records/nas.agent.test '{"records":[{"type":"A","value":"10.9.9.9"}]}'
dry PUT /api/v1/forwards/corp.agent.test '{"servers":["10.0.0.53"]}'
[ -z "$(q nas.agent.test)" ] || fail "a dry run changed DNS"
[ "$(code GET /api/v1/clients)" = 200 ] && ! grep -q '"tv"' "$E/out.json" || fail "a dry run added a device"
[ "$(code PUT /api/v1/records/nas.agent.test '{"records":[{"type":"A","value":"10.9.9.9"}]}')" = 400 ] \
  || fail "a change without a reason wasn't refused"
echo ok

echo "== 3. a real change, attributed"
[ "$(code PUT /api/v1/records/nas.agent.test '{"records":[{"type":"A","value":"10.9.9.9"}]}' 'the NAS moved')" = 200 ] \
  || fail "the agent's change: $(cat "$E/out.json")"
for _ in $(seq 50); do [ "$(q nas.agent.test)" = 10.9.9.9 ] && break; sleep 0.1; done
[ "$(q nas.agent.test)" = 10.9.9.9 ] || fail "the agent's name doesn't answer"
[ "$(code PUT /api/v1/clients/tv '{"match":["192.168.1.40"]}' 'name the TV')" = 200 ] || fail "adding a device: $(cat "$E/out.json")"
[ "$(code PUT /api/v1/forwards/corp.agent.test '{"servers":["10.0.0.53"]}' 'office VPN')" = 200 ] || fail "adding a forward: $(cat "$E/out.json")"
dry DELETE /api/v1/records/nas.agent.test ''
dry DELETE /api/v1/clients/tv ''
dry DELETE /api/v1/forwards/corp.agent.test ''
[ "$(q nas.agent.test)" = 10.9.9.9 ] || fail "a dry-run delete removed the name"
code GET /api/v1/clients >/dev/null; grep -q '"tv"' "$E/out.json" || fail "a dry-run delete removed the device"
audit=$(curl -sf -b "$E/jar" "$API/api/v1/audit")
echo "$audit" | grep -q 'agent:helper (owner: admin) via agent-e2e/1.0' || fail "no agent attribution: $(echo "$audit" | head -c 400)"
echo "$audit" | grep -q 'the NAS moved' || fail "the reason isn't in the audit log"
echo ok

echo "== 4. the kill switch"
write_config false
kill -HUP "$P"
for _ in $(seq 50); do [ "$(code GET /api/v1/stats/summary)" = 403 ] && break; sleep 0.1; done
[ "$(code GET /api/v1/stats/summary)" = 403 ] || fail "[agents] enabled = false didn't stop the agent"
curl -sf -b "$E/jar" "$API/api/v1/stats/summary" >/dev/null || fail "the kill switch stopped the admin too"
echo PASS
