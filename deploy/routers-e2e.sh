#!/usr/bin/env bash
# REQ: T8.2, T8.3 — router integrations against fake UniFi OS and OPNsense APIs, and mDNS: a UniFi login
# (cookie) and its client list, OPNsense leases with an API key, the leases in the API, and a
# device named from the router in the query log. Needs python3, dig, curl.
# Usage: deploy/routers-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
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
API=http://127.0.0.1:26992
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

cat > "$E/fake.py" <<'EOF'
import base64, http.server, json, sys, threading
class UniFi(http.server.BaseHTTPRequestHandler):
    def reply(self, code, obj, headers=()):
        body = json.dumps(obj).encode()
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        creds = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/api/auth/login" and creds.get("username") == "telltale" and creds.get("password") == "s3cret":
            self.reply(200, {}, [("set-cookie", "TOKEN=abc123; Path=/; HttpOnly"), ("x-csrf-token", "x")])
        else:
            self.reply(401, {"error": "bad login"})
    def do_GET(self):
        if self.path == "/proxy/network/api/s/default/stat/sta" and "TOKEN=abc123" in (self.headers.get("cookie") or ""):
            self.reply(200, {"meta": {"rc": "ok"}, "data": [
                {"mac": "02:00:00:00:00:01", "ip": "127.0.0.1", "hostname": "laptop-77", "name": "Desk laptop"},
                {"mac": "02:00:00:00:00:02", "ip": "192.168.1.31", "hostname": "roku"}]})
        else:
            self.reply(401, {"meta": {"rc": "error", "msg": "api.err.LoginRequired"}})
    def log_message(self, *a):
        pass
class OPN(UniFi):
    def do_GET(self):
        ok = self.headers.get("authorization") == "Basic " + base64.b64encode(b"key1:secret1").decode()
        if not ok:
            return self.reply(401, {"status": 401})
        if self.path == "/api/dnsmasq/leases/search":
            return self.reply(404, {})
        if self.path == "/api/kea/leases4/search":
            return self.reply(200, {"rows": [{"address": "192.168.1.40", "hwaddr": "02:00:00:00:00:03", "hostname": "printer"}]})
        self.reply(404, {})
s1 = http.server.ThreadingHTTPServer(("127.0.0.1", 26981), UniFi)
s2 = http.server.ThreadingHTTPServer(("127.0.0.1", 26982), OPN)
threading.Thread(target=s1.serve_forever, daemon=True).start()
s2.serve_forever()
EOF
python3 "$E/fake.py" & H=$!
for _ in $(seq 50); do curl -s -o /dev/null http://127.0.0.1:26982/ && break; sleep 0.1; done
echo -n s3cret > "$E/unifi-pass"
echo -n key1 > "$E/opn-key"
echo -n secret1 > "$E/opn-secret"

cat > "$E/telltale.toml" <<EOF
[node]
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25992"
[api]
listen = "127.0.0.1:26992"
[telemetry.metrics]
listen = "127.0.0.1:27992"
[telemetry.qlog]
flush_interval_secs = 1
[[record]]
name = "nas.routers.test"
type = "A"
value = "10.0.0.8"
[[router]]
name = "udm"
type = "unifi"
url = "http://127.0.0.1:26981"
username = "telltale"
password_file = "$E/unifi-pass"
[[router]]
name = "opnsense"
type = "opnsense"
url = "http://127.0.0.1:26982"
api_key_file = "$E/opn-key"
api_secret_file = "$E/opn-secret"
[clients]
mdns = true
mdns_port = 25353
EOF
"$B" run -c "$E/telltale.toml" > "$E/node.log" 2>&1 & P=$!
for _ in $(seq 100); do curl -s -o /dev/null "$API/api/v1/auth/status" && break; sleep 0.1; done
for _ in $(seq 50); do [ "$(grep -c 'router integration: devices read' "$E/node.log")" -ge 2 ] && break; sleep 0.2; done
[ "$(grep -c 'router integration: devices read' "$E/node.log")" -ge 2 ] || fail "both routers weren't read"

ST=$(cat "$E/data/setup-token")
CSRF=$(curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$ST\",\"username\":\"admin\",\"password\":\"routers-e2e-pass-1\"}" \
  "$API/api/v1/auth/setup" | field 'd["csrfToken"]')
curl -sf -b "$E/jar" "$API/api/v1/dhcp/leases" | python3 -c '
import json, sys
items = {x["ip"]: x for x in json.load(sys.stdin)["items"]}
assert items["127.0.0.1"]["hostname"] == "Desk laptop" and items["127.0.0.1"]["source"] == "router", items
assert items["192.168.1.31"]["hostname"] == "roku", items
assert items["192.168.1.40"]["hostname"] == "printer", "Kea leases from OPNsense"
print(f"leases: {len(items)} from the routers")
' || fail "leases API"

# A device named from the router in the query log.
dig +short -p 25992 @127.0.0.1 nas.routers.test >/dev/null
sleep 2
curl -sf -b "$E/jar" "$API/api/v1/queries?name=nas.routers.test" | python3 -c '
import json, sys
rows = json.load(sys.stdin)["items"]
assert rows and rows[0]["clientName"] == "Desk laptop", rows[:1]
print("query log: the device is named Desk laptop")
' || fail "naming"

# REQ: T8.3 — a device that announces nas-box.local over mDNS (sent unicast here) is named so.
python3 - <<'EOF'
import socket
def wire(n):
    return b"".join(bytes([len(l)]) + l.encode() for l in n.split(".")) + b"\0"
m = bytes([0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]) + wire("nas-box.local")
m += bytes([0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 127, 0, 0, 2])
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(m, ("127.0.0.1", 25353))
EOF
sleep 6
dig +short -b 127.0.0.2 -p 25992 @127.0.0.1 nas.routers.test >/dev/null
sleep 2
curl -sf -b "$E/jar" "$API/api/v1/queries?name=nas.routers.test" | python3 -c '
import json, sys
rows = [r for r in json.load(sys.stdin)["items"] if r["client"] == "127.0.0.2"]
assert rows and rows[0]["clientName"] == "nas-box", rows[:1]
print("query log: the mDNS device is named nas-box")
' || fail "mDNS naming"
echo "routers-e2e: ok"
