#!/usr/bin/env bash
# REQ: OPS-008 — T7.19 acceptance: a running node's DHCP server leases an address
# (DISCOVER, OFFER, REQUEST, ACK) with the configured options, keeps the lease on disk, shows
# it in the API, and names the device by its host name. Ports 26767/26768 on loopback (no
# root needed; replies go to the sender). Needs python3, curl.
# Usage: deploy/dhcp-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
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
API=http://127.0.0.1:26996

cat > "$E/telltale.toml" <<EOF
[node]
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25996"
[api]
listen = "127.0.0.1:26996"
[telemetry.metrics]
listen = "127.0.0.1:27996"
[dhcp]
enabled = true
server_ip = "192.168.77.2"
range_start = "192.168.77.100"
range_end = "192.168.77.150"
router = "192.168.77.1"
domain = "lan"
search = ["lan"]
lease_secs = 3600
bind = "127.0.0.1"
port = 26767
client_port = 26768
reply_to_source = true
[[dhcp.reservation]]
mac = "02:00:00:00:00:10"
ip = "192.168.77.10"
hostname = "nas"
EOF
"$B" run -c "$E/telltale.toml" > "$E/node.log" 2>&1 & P=$!
for _ in $(seq 100); do curl -s -o /dev/null "$API/api/v1/auth/status" && break; sleep 0.1; done
for _ in $(seq 50); do grep -q "DHCP server started" "$E/node.log" && break; sleep 0.1; done

python3 - <<'EOF' || fail "DHCP exchange"
import socket, struct
MAGIC = bytes([99, 130, 83, 99])
def packet(t, mac, xid, extra=b""):
    b = bytearray(240)
    b[0], b[1], b[2] = 1, 1, 6
    b[4:8] = struct.pack("!I", xid)
    b[10:12] = struct.pack("!H", 0x8000)
    b[28:34] = mac
    b[236:240] = MAGIC
    opts = bytes([53, 1, t]) + bytes([12, 6]) + b"laptop" + extra + bytes([255])
    return bytes(b) + opts
def options(r):
    o, i = {}, 240
    while r[i] != 255:
        if r[i] == 0:
            i += 1
            continue
        o.setdefault(r[i], b"")
        o[r[i]] += r[i + 2:i + 2 + r[i + 1]]
        i += 2 + r[i + 1]
    return o
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
s.settimeout(3)
mac = bytes([2, 0, 0, 0, 0, 0x55])
s.sendto(packet(1, mac, 0x1111), ("127.0.0.1", 26767))
offer = s.recv(1500)
o = options(offer)
assert o[53] == bytes([2]), o
ip = offer[16:20]
assert socket.inet_ntoa(ip) == "192.168.77.100", socket.inet_ntoa(ip)
assert o[3] == socket.inet_aton("192.168.77.1") and o[6] == socket.inet_aton("192.168.77.2"), o
assert o[15] == b"lan" and o[51] == struct.pack("!I", 3600), o
server = o[54]
s.sendto(packet(3, mac, 0x2222, bytes([50, 4]) + ip + bytes([54, 4]) + server), ("127.0.0.1", 26767))
ack = s.recv(1500)
assert options(ack)[53] == bytes([5]) and ack[16:20] == ip, options(ack)
# The reservation.
s.sendto(packet(1, bytes([2, 0, 0, 0, 0, 0x10]), 0x3333), ("127.0.0.1", 26767))
assert socket.inet_ntoa(s.recv(1500)[16:20]) == "192.168.77.10"
print("DHCP: offered and acknowledged 192.168.77.100; reservation 192.168.77.10")
EOF

python3 - "$E/data/dhcp-leases.json" <<'EOF' || fail "lease file"
import json, sys
leases = json.load(open(sys.argv[1]))["leases"]
l = leases["02:00:00:00:00:55"]
assert l["ip"] == "192.168.77.100" and l["hostname"] == "laptop", l
print("lease file: ok")
EOF

ST=$(cat "$E/data/setup-token")
curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$ST\",\"username\":\"admin\",\"password\":\"dhcp-e2e-pass-1\"}" \
  "$API/api/v1/auth/setup" > /dev/null
curl -sf -b "$E/jar" "$API/api/v1/dhcp/leases" | python3 -c '
import json, sys
items = json.load(sys.stdin)["items"]
l = [x for x in items if x["mac"] == "02:00:00:00:00:55"][0]
assert l["ip"] == "192.168.77.100" and l["hostname"] == "laptop" and l["clientName"] == "laptop", l
print("API: lease listed, device named laptop")
' || fail "leases API"
echo "dhcp-e2e: ok"
