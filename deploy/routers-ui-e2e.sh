#!/usr/bin/env bash
# REQ: T8.2, API-002 (ADR-181) — a router added through the API, as the UI does: its API key is
# saved to a new private file under <data_dir>/secrets/ (never stored, listed, or audited), the
# router is read without a restart, credential files outside secrets/ are refused, a change to
# another field keeps the key but a new address needs it again, a refused change writes
# nothing, a new key switches files, and a delete removes the router and only the files the
# API wrote.
# Needs python3, curl.
# Usage: deploy/routers-ui-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
cd "$(dirname "$0")/.."
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P=
H=
cleanup() {
  local rc=$?
  for p in $P $H; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
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
KEY=ui-pasted-key-0123456789
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

cat > "$E/fake.py" <<'EOF'
import http.server, json, sys
KEY = sys.argv[1]
class UniFi(http.server.BaseHTTPRequestHandler):
    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.headers.get("x-api-key") != KEY:
            return self.reply(401, {"meta": {"rc": "error"}})
        if self.path == "/proxy/network/api/s/default/stat/sta":
            return self.reply(200, {"meta": {"rc": "ok"}, "data": [
                {"mac": "02:00:00:00:01:01", "ip": "192.168.7.20", "name": "Hall tablet"}]})
        self.reply(404, {})
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("127.0.0.1", 26984), UniFi).serve_forever()
EOF
python3 "$E/fake.py" "$KEY" & H=$!
for _ in $(seq 50); do curl -s -o /dev/null http://127.0.0.1:26984/ && break; sleep 0.1; done

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
EOF
"$B" run -c "$E/telltale.toml" > "$E/node.log" 2>&1 & P=$!
for _ in $(seq 100); do curl -s -o /dev/null "$API/api/v1/auth/status" && break; sleep 0.1; done
ST=$(cat "$E/data/setup-token")
CSRF=$(curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$ST\",\"username\":\"admin\",\"password\":\"routers-ui-e2e-pass-1\"}" \
  "$API/api/v1/auth/setup" | field 'd["csrfToken"]')
put() { curl -s -o "$E/out" -w '%{http_code}' -X PUT -b "$E/jar" -H "x-csrf-token: $CSRF" -H 'content-type: application/json' -d "$2" "$API/api/v1/routers/$1"; }

keyfile() { curl -sf -b "$E/jar" "$API/api/v1/config/entries?kind=router" | python3 -c '
import json, sys
items = [x for x in json.load(sys.stdin)["items"] if x["name"] == "udm"]
print(items[0]["definition"].get("api_key_file", "") if items else "")'; }

# Credential files outside secrets/ are refused, pasted or not (the poll would send them).
for body in "{\"type\":\"unifi\",\"url\":\"http://127.0.0.1:26984\",\"api_key\":\"$KEY\",\"api_key_file\":\"$E/elsewhere\"}" \
            "{\"type\":\"unifi\",\"url\":\"http://127.0.0.1:26984\",\"api_key_file\":\"$E/telltale.toml\"}"; do
  code=$(put udm "$body")
  [ "$code" = 422 ] || fail "a credential file outside secrets/ wasn't refused ($code): $(cat "$E/out")"
done
[ ! -e "$E/elsewhere" ] || fail "the key was written outside secrets/"

# Added with a pasted key: a new file under secrets/, 0600, read without a restart.
code=$(put udm "{\"type\":\"unifi\",\"url\":\"http://127.0.0.1:26984\",\"api_key\":\"$KEY\",\"offline_days\":0}")
[ "$code" = 200 ] || fail "PUT /routers/udm: $code $(cat "$E/out")"
F=$(keyfile)
case "$F" in "$E/data/secrets/router-udm.api_key."*) ;; *) fail "the key file is $F" ;; esac
[ "$(cat "$F")" = "$KEY" ] || fail "the key file's content"
[ "$(stat -c %a "$F")" = 600 ] || fail "the key file is $(stat -c %a "$F"), not 600"
[ "$(stat -c %a "$E/data/secrets")" = 700 ] || fail "the secrets directory isn't 700"
for _ in $(seq 50); do grep -q 'router="udm".*devices read\|router=udm.*devices read' "$E/node.log" && break; sleep 0.2; done
curl -sf -b "$E/jar" "$API/api/v1/dhcp/leases" | python3 -c '
import json, sys
items = {x["ip"]: x for x in json.load(sys.stdin)["items"]}
assert items["192.168.7.20"]["hostname"] == "Hall tablet", items
' || fail "the router added through the API wasn't read"
echo "added: key saved to a new file under secrets/ (0600), router read without a restart"

# The key is nowhere the API can show it.
curl -sf -b "$E/jar" "$API/api/v1/config/entries?kind=router" > "$E/entries"
curl -sf -b "$E/jar" "$API/api/v1/audit" > "$E/audit"
! grep -q "$KEY" "$E/entries" "$E/audit" "$E/node.log" || fail "the key shows up in the API or the log"

# Changing another field keeps the key; a new address needs it again.
code=$(put udm '{"type":"unifi","url":"http://127.0.0.1:26984","interval_secs":60,"offline_days":0}')
[ "$code" = 200 ] || fail "PUT without the key: $code $(cat "$E/out")"
[ "$(keyfile)" = "$F" ] || fail "the key file changed"
code=$(put udm '{"type":"unifi","url":"http://127.0.0.2:26984","offline_days":0}')
[ "$code" = 422 ] && grep -q "enter it again" "$E/out" || fail "a new address reused the saved key ($code): $(cat "$E/out")"
echo "changed: the key is kept, never shown, and not sent to a new address"

# A stale If-Match leaves the key in use alone and writes nothing.
before=$(ls "$E/data/secrets")
code=$(curl -s -o "$E/out" -w '%{http_code}' -X PUT -b "$E/jar" -H "x-csrf-token: $CSRF" -H 'if-match: "1"' \
  -H 'content-type: application/json' -d '{"type":"unifi","url":"http://127.0.0.1:26984","api_key":"other-key","offline_days":0}' \
  "$API/api/v1/routers/udm")
[ "$code" = 412 ] || fail "stale If-Match: $code $(cat "$E/out")"
[ "$(ls "$E/data/secrets")" = "$before" ] || fail "a refused change left a file: $(ls "$E/data/secrets")"
[ "$(cat "$F")" = "$KEY" ] || fail "a refused change replaced the key"

# A new key goes to a new file; the old one is removed once the change applies.
code=$(put udm "{\"type\":\"unifi\",\"url\":\"http://127.0.0.1:26984\",\"api_key\":\"$KEY\",\"offline_days\":0}")
[ "$code" = 200 ] || fail "PUT with a new key: $code $(cat "$E/out")"
F2=$(keyfile)
[ "$F2" != "$F" ] && [ -f "$F2" ] && [ ! -e "$F" ] || fail "the key wasn't switched to a new file ($F -> $F2)"
echo "replaced: a new file, the old one removed after the change applied; a refused change touched nothing"

# Deleting it removes the router, its names, and the key file it wrote, and nothing else.
echo keep > "$E/data/secrets/mine"
code=$(curl -s -o "$E/out" -w '%{http_code}' -X DELETE -b "$E/jar" -H "x-csrf-token: $CSRF" "$API/api/v1/routers/udm")
[ "$code" = 200 ] || fail "DELETE: $code $(cat "$E/out")"
[ ! -e "$F2" ] || fail "the key file is still there"
[ -f "$E/data/secrets/mine" ] || fail "a file the API didn't write was removed"
for _ in $(seq 50); do
  curl -sf -b "$E/jar" "$API/api/v1/dhcp/leases" | grep -q 192.168.7.20 || break
  sleep 0.2
done
! curl -sf -b "$E/jar" "$API/api/v1/dhcp/leases" | grep -q 192.168.7.20 || fail "the deleted router's names are still listed"
echo "deleted: router, names, and key file gone"
echo "routers-ui-e2e: ok"
