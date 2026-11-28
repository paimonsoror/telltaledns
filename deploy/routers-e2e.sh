#!/usr/bin/env bash
# REQ: T8.2, T8.3, FLT-006 (ADR-183, ADR-189) — router integrations against fake UniFi OS, OPNsense and FRITZ!Box (TR-064) APIs, and mDNS: a UniFi login
# (cookie) and its client list (connected, then the offline clients it knows), OPNsense leases with an
# API key, the leases in the API, a device named from the router in the query log, and a device named by the
# MAC its router reports: a rule for it blocks at the address the router gives it, and the explanation, the
# identity and the metrics say so. Needs python3, dig, curl. Nothing leaves this machine: the routers are fakes
# on loopback, and the upstream below is a closed port.
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
import base64, http.server, json, sys, threading, time
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
        elif self.path.startswith("/proxy/network/v2/api/site/default/clients/history?") and "TOKEN=abc123" in (self.headers.get("cookie") or ""):
            # What the console was asked for (its window), for the check below.
            open(sys.argv[1] + "/history.path", "w").write(self.path)
            now = int(time.time())
            self.reply(200, [
                {"mac": "02:00:00:00:00:04", "last_ip": "192.168.1.50", "name": "Old iPad", "last_seen": now - 3600},
                {"mac": "02:00:00:00:00:05", "last_ip": "192.168.1.31", "hostname": "stale", "last_seen": now - 7200},
                # Outside the default 30 days: the console may still send it, TelltaleDNS doesn't use it.
                {"mac": "02:00:00:00:00:07", "last_ip": "192.168.1.52", "name": "Long gone laptop", "last_seen": now - 90 * 86400}])
        elif self.path == "/proxy/network/api/s/default/rest/user" and "TOKEN=abc123" in (self.headers.get("cookie") or ""):
            self.reply(200, {"meta": {"rc": "ok"}, "data": [
                {"mac": "02:00:00:00:00:06", "use_fixedip": True, "fixed_ip": "192.168.1.51", "name": "Garage camera"}]})
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
class Fritz(http.server.BaseHTTPRequestHandler):
    HOSTS = "urn:dslforum-org:service:Hosts:1"
    def xml(self, code, text):
        body = text.encode()
        self.send_response(code)
        self.send_header("content-type", "text/xml")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def envelope(self, name, inner):
        return ('<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
                f'<u:{name}Response xmlns:u="{self.HOSTS}">{inner}</u:{name}Response></s:Body></s:Envelope>')
    def do_GET(self):
        self.xml(200, f"<root><service><serviceType>{self.HOSTS}</serviceType><controlURL>/upnp/control/hosts</controlURL></service></root>")
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0))).decode()
        if "GetHostNumberOfEntries" in self.headers["soapaction"]:
            # One more than it has: the last index faults 713, which ends the list.
            return self.xml(200, self.envelope("GetHostNumberOfEntries", "<NewHostNumberOfEntries>2</NewHostNumberOfEntries>"))
        if "<NewIndex>0</NewIndex>" in body:
            return self.xml(200, self.envelope("GetGenericHostEntry", "<NewIPAddress>192.168.60.7</NewIPAddress><NewMACAddress>02:00:00:00:00:08</NewMACAddress><NewHostName>fritz-tablet</NewHostName><NewActive>1</NewActive>"))
        self.xml(500, '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError xmlns="urn:dslforum-org:control-1-0"><errorCode>713</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>')
    def log_message(self, *a):
        pass
s3 = http.server.ThreadingHTTPServer(("127.0.0.1", 26983), Fritz)
threading.Thread(target=s3.serve_forever, daemon=True).start()
s1 = http.server.ThreadingHTTPServer(("127.0.0.1", 26981), UniFi)
s2 = http.server.ThreadingHTTPServer(("127.0.0.1", 26982), OPN)
threading.Thread(target=s1.serve_forever, daemon=True).start()
s2.serve_forever()
EOF
python3 "$E/fake.py" "$E" & H=$!
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
# Nothing listens here (as in the UI's e2e node): only a blocked or a local name is answered.
[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"
[[upstream_group]]
name = "default"
members = ["nowhere"]
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
[[router]]
name = "fritz"
type = "fritzbox"
url = "http://127.0.0.1:26983"
client_subnets = ["192.168.60.0/24"]
[clients]
mdns = true
mdns_port = 25353
EOF
"$B" run -c "$E/telltale.toml" > "$E/node.log" 2>&1 & P=$!
for _ in $(seq 100); do curl -s -o /dev/null "$API/api/v1/auth/status" && break; sleep 0.1; done
for _ in $(seq 50); do [ "$(grep -c 'router integration: devices read' "$E/node.log")" -ge 3 ] && break; sleep 0.2; done
[ "$(grep -c 'router integration: devices read' "$E/node.log")" -ge 3 ] || fail "the three routers weren't read"

ST=$(cat "$E/data/setup-token")
CSRF=$(curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$ST\",\"username\":\"admin\",\"password\":\"routers-e2e-pass-1\"}" \
  "$API/api/v1/auth/setup" | field 'd["csrfToken"]')
curl -sf -b "$E/jar" "$API/api/v1/dhcp/leases" | python3 -c '
import json, sys
items = {x["ip"]: x for x in json.load(sys.stdin)["items"]}
assert items["127.0.0.1"]["hostname"] == "Desk laptop" and items["127.0.0.1"]["source"] == "router", items
assert items["192.168.1.31"]["hostname"] == "roku", "an offline client must not take the address of a connected one"
assert items["192.168.1.50"]["hostname"] == "Old iPad", "offline clients from the v2 history"
assert items["192.168.1.51"]["hostname"] == "Garage camera", "known clients from rest/user"
assert "192.168.1.52" not in items, "a client last seen 90 days ago is outside offline_days (30)"
assert items["192.168.1.40"]["hostname"] == "printer", "Kea leases from OPNsense"
assert items["192.168.60.7"]["hostname"] == "fritz-tablet", "TR-064 hosts from the FRITZ!Box"
print(f"leases: {len(items)} from the routers")
' || fail "leases API"
# REQ: T8.2 (ADR-166) — the console is asked only for the window (30 days = 720 hours).
grep -q "withinHours=720" "$E/history.path" || fail "the history request didn't carry the window: $(cat "$E/history.path")"

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

# REQ: FLT-006 (ADR-183) — a device named by a MAC address is recognized by the MAC its router reports
# for the address (the kernel's neighbor table has no entry for loopback): the fake UniFi gives
# 127.0.0.1 the MAC 02:00:00:00:00:01. A rule for the device blocks at that address, and not at
# 127.0.0.2, whose MAC no router reports. Every wait is bounded (the table is rebuilt within seconds).
put() { # <path> <json>
  local code
  code=$(curl -s -o "$E/put.json" -w '%{http_code}' -b "$E/jar" -X PUT -H "x-csrf-token: $CSRF" \
    -H 'content-type: application/json' -d "$2" "$API$1")
  [ "$code" = 200 ] || fail "PUT $1 answered $code: $(cat "$E/put.json")"
}
put /api/v1/clients/desk '{"match":["02:00:00:00:00:01"],"groups":["default"]}'
put /api/v1/rules/desk-block '{"action":"block","domain":"blocked.routers.test","devices":["desk"]}'
ask() { # [dig options] -> the answer, or nothing
  dig +time=1 +tries=1 +short -p 25992 "$@" @127.0.0.1 blocked.routers.test A 2>/dev/null || true
}
ok=
for _ in $(seq 60); do [ "$(ask)" = 0.0.0.0 ] && { ok=1; break; }; sleep 0.5; done
[ -n "$ok" ] || fail "the rule for desk (the MAC the router reports for 127.0.0.1) doesn't block 127.0.0.1 within 30 s"
[ "$(ask -b 127.0.0.2)" != 0.0.0.0 ] || fail "the rule for desk blocks 127.0.0.2, whose MAC no router reports"
echo "desk is recognized by the MAC its router reports: blocked at 127.0.0.1, not at 127.0.0.2"

curl -sf -b "$E/jar" "$API/api/v1/explain?name=blocked.routers.test&client=127.0.0.1" | python3 -c '
import json, sys
c = json.load(sys.stdin)["client"]
assert c["identifiedBy"] == "router_mac" and c["macFrom"] == "router" and c["device"] == "desk", c
assert c["mac"] == "02:00:00:00:00:01", c
print("explain: desk, by router_mac, the MAC from the router")
' || fail "explain doesn't say the router's MAC identified the client"

# The identity offers the MAC (to a signed-in person) for naming a device by it.
curl -sf -b "$E/jar" "$API/api/v1/clients/127.0.0.1/identity" | python3 -c '
import json, sys
r = json.load(sys.stdin)["recognition"]
assert r["mac"] == "02:00:00:00:00:01" and r["macFrom"] == "router", r
assert r["macRandomized"] is True and not r.get("macShared"), r
assert r["device"] == "desk" and r["identifiedBy"] == "router_mac", r
print("identity: recognition offers the router MAC, a made-up (private) one")
' || fail "the identity's recognition"

ok=
for _ in $(seq 20); do
  curl -sf "http://127.0.0.1:27992/metrics" | grep -Eq '^telltale_router_macs\{source="router"\} [1-9]' && { ok=1; break; }
  sleep 0.5
done
[ -n "$ok" ] || fail "/metrics has no telltale_router_macs{source=\"router\"} of at least 1"
echo "metrics: telltale_router_macs{source=\"router\"} >= 1"
echo "routers-e2e: ok"
