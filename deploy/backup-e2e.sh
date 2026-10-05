#!/usr/bin/env bash
# REQ: API-007 — T6.7 acceptance: a backup taken from a running node restores onto a fresh
# one, which then answers and signs in the same way.
#   1. node A: a first admin, a name added through the API, some queries (statistics);
#   2. `telltale backup create` while A runs; `backup show` checks it;
#   3. stop A; `backup restore` into a new data directory and config directory;
#   4. node B from the restored files: the API-made name answers, the admin signs in with
#      the same password, A's sessions don't carry over, and the audit log came along;
#   5. restoring again without --force is refused; a damaged archive is refused.
# Usage: deploy/backup-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P=
cleanup() { [ -n "$P" ] && kill "$P" 2>/dev/null && wait "$P" 2>/dev/null; rm -rf "$E"; }
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  for f in "$E"/*.log; do [ -f "$f" ] && { echo "--- $(basename "$f")"; tail -15 "$f"; }; done
  exit 1
}
command -v dig >/dev/null || { echo "needs dig"; exit 2; }
API=http://127.0.0.1:26981
q() { dig +short +time=1 +tries=2 -p 25981 @127.0.0.1 "$@"; }
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
start() { # config files...
  "$B" run "$@" > "$E/node.log" 2>&1 & P=$!
  for _ in $(seq 100); do curl -s -o /dev/null "$API/api/v1/auth/status" && return 0; sleep 0.1; done
  fail "the node didn't start"
}
stop() { kill "$P"; wait "$P" 2>/dev/null || true; P=; }

mkdir -p "$E/a/etc"
cat > "$E/a/etc/telltale.toml" <<EOF
[node]
name = "node-a"
data_dir = "$E/a/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25981"
[api]
listen = "127.0.0.1:26981"
[telemetry.metrics]
listen = "127.0.0.1:27981"
[[record]]
name = "from-file.backup.test"
type = "A"
value = "10.1.0.1"
EOF

echo "== 1. node A"
start -c "$E/a/etc/telltale.toml"
ST=$(cat "$E/a/data/setup-token")
CSRF=$(curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$ST\",\"username\":\"admin\",\"password\":\"backup-e2e-pass-1\"}" \
  "$API/api/v1/auth/setup" | field 'd["csrfToken"]') || fail "admin setup"
code=$(curl -s -o "$E/put.json" -w '%{http_code}' -b "$E/jar" -X PUT -H "x-csrf-token: $CSRF" \
  -H 'content-type: application/json' -d '{"records":[{"type":"A","value":"10.1.0.2"}]}' \
  "$API/api/v1/records/from-api.backup.test")
[ "$code" = 200 ] || fail "adding a name through the API ($code: $(cat "$E/put.json"))"
for _ in $(seq 50); do [ "$(q from-api.backup.test)" = 10.1.0.2 ] && break; sleep 0.1; done
[ "$(q from-api.backup.test)" = 10.1.0.2 ] || fail "A doesn't answer the API-made name"

echo "== 2. backup while A runs (the API download, then the CLI)"
hdrs=$(curl -sf -D - -o "$E/api.ttbk" -b "$E/jar" "$API/api/v1/backup") || fail "the API backup download"
echo "$hdrs" | grep -qi 'content-disposition: attachment; filename="telltale-node-a-' \
  || fail "the download isn't named as an attachment: $hdrs"
"$B" backup show "$E/api.ttbk" | grep -q 'data/state.db' || fail "the API backup doesn't check out"
"$B" backup create -c "$E/a/etc/telltale.toml" -o "$E/a.ttbk" 2> "$E/create.log" || fail "backup create"
cat "$E/create.log"
"$B" backup show "$E/a.ttbk" > "$E/show.txt" || fail "backup show"
grep -q 'config/telltale.toml' "$E/show.txt" && grep -q 'data/state.db' "$E/show.txt" \
  || fail "the backup lacks the config or state.db: $(cat "$E/show.txt")"
[ "$(stat -c %a "$E/a.ttbk")" = 600 ] || fail "the backup isn't owner-only"

echo "== 3. stop A, restore elsewhere"
stop
"$B" backup restore "$E/a.ttbk" --data-dir "$E/b/data" --config-dir "$E/b/etc" 2> "$E/restore.log" \
  || fail "restore: $(cat "$E/restore.log")"
cat "$E/restore.log"
cmp -s "$E/a/etc/telltale.toml" "$E/b/etc/telltale.toml" || fail "the config file differs"
grep -q 'data_dir' "$E/restore.log" || fail "restore didn't say the config names another data_dir"

echo "== 4. node B from the restored files"
printf '[node]\ndata_dir = "%s"\n' "$E/b/data" > "$E/b/etc/local.toml"
start -c "$E/b/etc/telltale.toml" -c "$E/b/etc/local.toml"
for _ in $(seq 50); do [ "$(q from-api.backup.test)" = 10.1.0.2 ] && break; sleep 0.1; done
[ "$(q from-api.backup.test)" = 10.1.0.2 ] || fail "B doesn't answer the API-made name"
[ "$(q from-file.backup.test)" = 10.1.0.1 ] || fail "B doesn't answer the file's name"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$E/jar" "$API/api/v1/auth/me")
[ "$code" = 401 ] || fail "A's session still works on B ($code)"
curl -sf -c "$E/jar2" -H 'content-type: application/json' \
  -d '{"username":"admin","password":"backup-e2e-pass-1"}' "$API/api/v1/auth/login" >/dev/null \
  || fail "the admin can't sign in on B"
audit=$(curl -sf -b "$E/jar2" "$API/api/v1/audit")
echo "$audit" | grep -q 'from-api.backup.test' || fail "the audit log didn't come along"
echo "$audit" | grep -q 'backup.create' || fail "the API download isn't in the audit log"
[ -e "$E/b/data/setup-token" ] && fail "B asks for first-run setup again"
stop

echo "== 5. refusals"
"$B" backup restore "$E/a.ttbk" --data-dir "$E/b/data" --config-dir "$E/b/etc" 2>/dev/null \
  && fail "restoring over existing files without --force worked"
python3 - "$E/a.ttbk" "$E/bad.ttbk" <<'PY'
import sys
b = bytearray(open(sys.argv[1], 'rb').read()); b[len(b) // 2] ^= 0x55
open(sys.argv[2], 'wb').write(b)
PY
"$B" backup show "$E/bad.ttbk" >/dev/null 2>&1 && fail "a damaged backup was accepted"
"$B" backup restore "$E/bad.ttbk" --data-dir "$E/c/data" --config-dir "$E/c/etc" 2>/dev/null \
  && fail "a damaged backup was restored"
[ -e "$E/c/data/state.db" ] && fail "a damaged backup left files behind"
echo PASS
