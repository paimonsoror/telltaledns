#!/usr/bin/env bash
# REQ: FLT-006, CLU-002 (ADR-183) — a device named by its MAC address is recognized by the MAC its
# router reports, on every node, and is followed to a new address, on two real processes (a primary
# that reads a fake UniFi API, and a replica that doesn't):
#   1. the primary blocks the named device at the address the router gives it, and not another;
#   2. the replica does the same, from the primary's answer (its quick retry: within seconds of
#      starting), and says the MAC is a member's (`telltale_router_macs{source="peer"} 1`);
#   3. the router moves the MAC to another address: the primary follows, then the replica;
#   4. the router stops answering: the primary keeps blocking at the address it last had.
# Every wait is bounded. Nothing leaves this machine: the router is a fake on loopback, the
# upstream is a closed port, and the "devices" are loopback source addresses. Needs python3, curl.
# Usage: deploy/cluster/router-macs-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P_PID= R_PID= F_PID=
cleanup() {
  # Wait for the nodes to exit: their listeners use SO_REUSEPORT, so one still draining would
  # share its ports with the next run's.
  [ -n "$P_PID" ] && kill "$P_PID" 2>/dev/null && wait "$P_PID" 2>/dev/null || true
  [ -n "$R_PID" ] && kill "$R_PID" 2>/dev/null && wait "$R_PID" 2>/dev/null || true
  [ -n "$F_PID" ] && kill "$F_PID" 2>/dev/null && wait "$F_PID" 2>/dev/null || true
  [ "${KEEP:-}" = 1 ] || rm -rf "$E"
}
trap cleanup EXIT
fail() {
  set +e
  echo "FAIL: $*"
  # Annotations are readable without a token (job logs aren't).
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  echo "--- primary log"; tail -30 "$E/p.log" || true
  echo "--- primary's router and MAC lines"; grep -iE "router|mac" "$E/p.log" | tail -15 || true
  echo "--- replica's devices.names rounds (TELLTALE_LOG=debug)"; grep "devices.names round" "$E/r.log" | tail -5 || true
  echo "--- replica log"; tail -30 "$E/r.log" || true
  echo "--- MAC table metrics (primary, replica)"
  for port in 29801 29802; do
    curl -s "http://127.0.0.1:$port/metrics" | grep -E '^telltale_(router_macs|neighbors)' || true
  done
  echo "--- the fake router's answer: $(cat "$E/sta.json" 2>/dev/null)"
  # What each node says about the device (best effort: an admin made on the primary works on both).
  local st
  st=$(cat "$E/p/setup-token" 2>/dev/null) || st=
  if [ -n "$st" ] && curl -s -o /dev/null -c "$E/jar-p" -H 'content-type: application/json' \
    -d "{\"setupToken\":\"$st\",\"username\":\"admin\",\"password\":\"router-macs-e2e-pass-1\"}" \
    http://127.0.0.1:28801/api/v1/auth/setup; then
    sleep 2
    curl -s -o /dev/null -c "$E/jar-r" -H 'content-type: application/json' \
      -d '{"username":"admin","password":"router-macs-e2e-pass-1"}' http://127.0.0.1:28802/api/v1/auth/login || true
    for pair in "28801 jar-p" "28802 jar-r"; do
      set -- $pair
      echo "--- :$1 /api/v1/clients"; curl -s -b "$E/$2" "http://127.0.0.1:$1/api/v1/clients" | head -c 500; echo
      echo "--- :$1 explain"; curl -s -b "$E/$2" "http://127.0.0.1:$1/api/v1/explain?name=blocked.e2e-mac.test&client=127.0.0.41" | head -c 600; echo
      echo "--- :$1 identity"; curl -s -b "$E/$2" "http://127.0.0.1:$1/api/v1/clients/127.0.0.41/identity" | head -c 400; echo
    done
  fi
  if [ "${KEEP:-}" = 1 ]; then echo "logs kept in $E"; fi
  exit 1
}

# The fake UniFi: `stat/sta` is whatever sta.json holds (the script rewrites it), for the right key.
cat > "$E/fake.py" <<'PY'
import http.server, sys
sta, key = sys.argv[1], sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("x-api-key") == key and self.path == "/proxy/network/api/s/default/stat/sta":
            body, code = open(sta, "rb").read(), 200
        else:
            body, code = b'{"meta":{"rc":"error","msg":"api.err.LoginRequired"}}', 401
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("127.0.0.1", 26961), H).serve_forever()
PY
echo -n e2e-router-key > "$E/unifi-key"
# `router_at <ip>`: the router says the device (MAC ...:41) is at <ip>. Replaced whole, so a read
# never sees half a file.
router_at() {
  printf '{"meta":{"rc":"ok"},"data":[{"mac":"02:00:00:00:00:41","ip":"%s","hostname":"roamer-phone"}]}' "$1" > "$E/sta.tmp"
  mv "$E/sta.tmp" "$E/sta.json"
}
router_at 127.0.0.41
python3 "$E/fake.py" "$E/sta.json" e2e-router-key & F_PID=$!
for _ in $(seq 50); do curl -s -o /dev/null http://127.0.0.1:26961/ && break; sleep 0.1; done

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
# Nothing listens here: only a blocked name is answered.
[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"
[[upstream_group]]
name = "default"
members = ["nowhere"]
EOF
}
mkdir -p "$E/p" "$E/r"
node_config p 25801 28801 29801 28841 > "$E/p.toml"
node_config r 25802 28802 29802 28842 > "$E/r.toml"
# The shared part of the primary's config: the router (read by the primary only: the replica
# takes the entry, and holds it back, since the key file isn't one its own files define), the
# device named by its MAC, and a rule for it.
cat >> "$E/p.toml" <<EOF
[[router]]
name = "fakeudm"
type = "unifi"
url = "http://127.0.0.1:26961"
api_key_file = "$E/unifi-key"
interval_secs = 30
offline_days = 0
[[client]]
name = "roamer"
match = ["02:00:00:00:00:41"]
groups = ["default"]
[[rule]]
id = "roamer-block"
action = "block"
domain = "blocked.e2e-mac.test"
devices = ["roamer"]
EOF

# One A query over UDP from the source address <src>; prints the answer address, nothing when
# there is none, TIMEOUT when nobody answered.
cat > "$E/q.py" <<'PY'
import random, socket, struct, sys
port, src, name = int(sys.argv[1]), sys.argv[2], sys.argv[3]
q = struct.pack('>HHHHHH', random.randrange(65536), 0x0100, 1, 0, 0, 0)
q += b''.join(bytes([len(l)]) + l.encode() for l in name.split('.')) + b'\0' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.5)
try:
    s.bind((src, 0))
    s.sendto(q, ('127.0.0.1', port))
    r, _ = s.recvfrom(4096)
except OSError:
    print('TIMEOUT')
    sys.exit(0)
print('' if struct.unpack('>H', r[6:8])[0] == 0 else '.'.join(str(b) for b in r[-4:]))
PY
q() { python3 "$E/q.py" "$@"; }
NAME=blocked.e2e-mac.test
# blocked_on <dns-port> <source>: whether the rule for roamer applies to a query from <source>.
blocked_on() { [ "$(q "$1" "$2" "$NAME")" = 0.0.0.0 ]; }
# wait_blocked <dns-port> <source> <tries>: up to <tries> half-seconds for it to block.
wait_blocked() {
  for _ in $(seq "$3"); do blocked_on "$1" "$2" && return 0; sleep 0.5; done
  return 1
}
metric() { curl -s "http://127.0.0.1:$1/metrics" | awk -v n="$2" '$1 == n {print $2}'; }

"$B" cluster init --name e2e-macs --advertise https://127.0.0.1:28841 -c "$E/p.toml" >/dev/null
"$B" run -c "$E/p.toml" > "$E/p.log" 2>&1 & P_PID=$!
for _ in $(seq 50); do [ "$(q 25801 127.0.0.1 a.example.test)" != TIMEOUT ] && break; sleep 0.1; done
T=$("$B" cluster token create --ttl 10m --eligible -c "$E/p.toml" 2>/dev/null)
# Retries until the primary's cluster port is up (a loaded machine can take longer to start).
joined=""
for _ in $(seq 40); do
  "$B" cluster join "$T" --site r --eligible --advertise https://127.0.0.1:28842 -c "$E/r.toml" >/dev/null 2>"$E/join.err" \
    && { joined=1; break; }
  sleep 0.5
done
[ -n "$joined" ] || fail "the replica couldn't join: $(cat "$E/join.err")"
"$B" run -c "$E/r.toml" > "$E/r.log" 2>&1 & R_PID=$!

echo "== 1. the primary blocks the device at the address its router gives it"
wait_blocked 25801 127.0.0.41 60 || fail "the primary doesn't block 127.0.0.41, the address its router gives roamer (within 30 s)"
blocked_on 25801 127.0.0.42 && fail "the primary blocks 127.0.0.42, an address its router doesn't know"
echo "ok"

echo "== 2. the replica does the same, from the primary's answer"
wait_blocked 25802 127.0.0.41 60 || fail "the replica doesn't block 127.0.0.41 (the primary's router binding) within 30 s"
blocked_on 25802 127.0.0.42 && fail "the replica blocks 127.0.0.42, an address no router knows"
[ "$(metric 29802 'telltale_router_macs{source="peer"}')" = 1 ] \
  || fail "the replica doesn't count one binding from another node's router ($(metric 29802 'telltale_router_macs{source="peer"}'))"
[ "$(metric 29802 'telltale_router_macs{source="router"}')" = 0 ] \
  || fail "the replica counts a binding from its own router: it should hold the router back"
[ "$(metric 29801 'telltale_router_macs{source="router"}')" = 1 ] \
  || fail "the primary doesn't count one binding from its own router ($(metric 29801 'telltale_router_macs{source="router"}'))"
grep -E "not read on this node" "$E/r.log" | head -1 || true
echo "ok"

echo "== 3. the router moves the MAC to another address: both nodes follow"
router_at 127.0.0.43
wait_blocked 25801 127.0.0.43 90 || fail "the primary doesn't follow the device to 127.0.0.43 within 45 s"
blocked_on 25801 127.0.0.41 && fail "the primary still blocks 127.0.0.41, which the router no longer gives to roamer"
wait_blocked 25802 127.0.0.43 150 || fail "the replica doesn't follow the device to 127.0.0.43 within 75 s of the primary"
blocked_on 25802 127.0.0.41 && fail "the replica still blocks 127.0.0.41"
echo "ok"

echo "== 4. the router stops answering: the primary keeps its last answer"
kill "$F_PID" 2>/dev/null && wait "$F_PID" 2>/dev/null || true
F_PID=
for _ in $(seq 20); do
  blocked_on 25801 127.0.0.43 || fail "the primary stopped blocking 127.0.0.43 when the router went quiet (its last answer is kept)"
  sleep 1
done
echo "ok"
echo "router-macs-e2e: ok"
