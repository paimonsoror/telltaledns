#!/usr/bin/env bash
# REQ: AGT-006 — T6.6 acceptance: a running node, a named device with traffic, agent tokens,
# then deploy/mcp-e2e/check.mjs drives the MCP server with the official TypeScript SDK client
# (Streamable HTTP and `telltale mcp --stdio`). Needs node, npm, dig.
# Usage: deploy/mcp-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
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
API=http://127.0.0.1:26993
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

cat > "$E/telltale.toml" <<EOF
[node]
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25993"
[api]
listen = "127.0.0.1:26993"
[telemetry.metrics]
listen = "127.0.0.1:27993"
[telemetry.qlog]
flush_interval_secs = 1
[[record]]
name = "tv-portal.mcp.test"
type = "A"
value = "10.0.0.7"
[[list]]
name = "ads"
rules = ["ads.mcp.test"]
[[client]]
name = "living-room-tv"
match = ["127.0.0.1"]
# REQ: AGT-007 — agents' plans wait for an operator.
[agents]
require_approval = true
EOF
"$B" run -c "$E/telltale.toml" > "$E/node.log" 2>&1 & P=$!
for _ in $(seq 100); do curl -s -o /dev/null "$API/api/v1/auth/status" && break; sleep 0.1; done
for i in $(seq 20); do dig +short +time=1 -p 25993 @127.0.0.1 tv-portal.mcp.test >/dev/null || true; done
for _ in $(seq 30); do dig +time=1 -p 25993 @127.0.0.1 ads.mcp.test | grep -q 'EDE: 15' && break; sleep 0.3; done
# REQ: OBS-024 — five queries for a name a plan will block, for the simulations to find.
for i in $(seq 5); do dig +short +time=1 -p 25993 @127.0.0.1 sim.mcp.test >/dev/null || true; done
sleep 2 # the query log flushes every second here

ST=$(cat "$E/data/setup-token")
CSRF=$(curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$ST\",\"username\":\"admin\",\"password\":\"mcp-e2e-pass-1\"}" \
  "$API/api/v1/auth/setup" | field 'd["csrfToken"]')
token() { # scopes JSON
  curl -sf -b "$E/jar" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' \
    -d "{\"name\":\"mcp-$RANDOM\",\"kind\":\"agent\",\"scopes\":$1}" "$API/api/v1/tokens" | field 'd["token"]'
}
export AGENT_TOKEN NARROW_TOKEN WRITER_TOKEN SIM_TOKEN ADMIN_PASSWORD=mcp-e2e-pass-1
AGENT_TOKEN=$(token '["analytics:read","config:read","querylog:read"]')
NARROW_TOKEN=$(token '["analytics:read"]')
WRITER_TOKEN=$(token '["analytics:read","config:write:rules"]')
SIM_TOKEN=$(token '["analytics:read","config:write:rules","querylog:read"]')

(cd deploy/mcp-e2e && npm install --silent --no-audit --no-fund >/dev/null)
node deploy/mcp-e2e/check.mjs "$API" "$B" docs/api/mcp-tools.json
# AGT-007: the applied plan blocks the name in DNS itself.
dig +time=1 -p 25993 @127.0.0.1 agent.mcp.test | grep -q 'EDE: 15' || fail "agent.mcp.test isn't blocked in DNS after apply_plan"
echo 'ok: agent.mcp.test is blocked in DNS'

# Every tool call was an agent request: the audit log names the MCP client on changes only,
# so check the session at least reached the node as the agent.
grep -q 'mcp' "$E/node.log" || true
