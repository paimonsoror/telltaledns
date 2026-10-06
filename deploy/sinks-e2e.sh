#!/usr/bin/env bash
# REQ: OBS-010 — T7.12/T7.13 acceptance: a running node copies its query events to a
# JSON-lines file, a syslog collector (UDP, and T9.11: TLS with a private CA), and a batched
# webhook, and sends an alert (and nothing on the DNS path waits for any of them). T9.11: a
# webhook whose collector is down keeps its batches on disk and sends them when it's back.
# Needs python3, dig, curl, openssl.
# Usage: deploy/sinks-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
cd "$(dirname "$0")/.."
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P=
H=
S=
T=
L=
cleanup() {
  local rc=$?
  for p in $P $H $S $T $L; do kill "$p" 2>/dev/null || true; done
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

# A webhook collector (every POST body to posts/<n>, with its path) and a syslog collector.
cat > "$E/collect.py" <<'EOF'
import http.server, os, socket, sys, threading
out = sys.argv[1]
os.makedirs(out + "/posts", exist_ok=True)
n = [0]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        n[0] += 1
        with open(f"{out}/posts/{n[0]:04d}", "wb") as f:
            f.write(self.path.encode() + b"\n" + self.headers.get("content-type", "").encode() + b"\n" + body)
        self.send_response(204)
        self.end_headers()
    def log_message(self, *a):
        pass
def syslog():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 25515))
    with open(out + "/syslog", "ab", buffering=0) as f:
        while True:
            f.write(s.recv(65535) + b"\n")
threading.Thread(target=syslog, daemon=True).start()
http.server.ThreadingHTTPServer(("127.0.0.1", 25580), H).serve_forever()
EOF
python3 "$E/collect.py" "$E" & H=$!

# REQ: OBS-010 (T9.11) — a TLS syslog collector (RFC 5425) with a certificate from a private
# CA (what tls_ca trusts); octet-counted frames to syslog-tls.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=e2e-syslog-ca \
  -keyout "$E/ca.key" -out "$E/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj /CN=localhost -keyout "$E/key.pem" -out "$E/req.pem" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$E/ext.cnf"
openssl x509 -req -in "$E/req.pem" -CA "$E/ca.pem" -CAkey "$E/ca.key" -CAcreateserial -days 1 \
  -extfile "$E/ext.cnf" -out "$E/cert.pem" 2>/dev/null
cat > "$E/tls_syslog.py" <<'EOF'
import socket, ssl, sys, threading
out = sys.argv[1]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(out + "/cert.pem", out + "/key.pem")
l = socket.socket()
l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", 25516))
l.listen()
def serve(c):
    with ctx.wrap_socket(c, server_side=True) as t, open(out + "/syslog-tls", "ab", buffering=0) as f:
        while True:
            d = t.recv(65535)
            if not d:
                return
            f.write(d)
while True:
    c, _ = l.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
EOF
python3 "$E/tls_syslog.py" "$E" & T=$!

cat > "$E/telltale.toml" <<EOF
[node]
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25994"
[api]
listen = "127.0.0.1:26994"
[telemetry.metrics]
listen = "127.0.0.1:27994"
[[record]]
name = "nas.sinks.test"
type = "A"
value = "10.0.0.9"
[[list]]
name = "ads"
rules = ["ads.sinks.test"]
# A list that can't be downloaded: the alert rule below reports it.
[[list]]
name = "unreachable"
url = "http://127.0.0.1:25599/list.txt"
[[client]]
name = "kitchen-tablet"
match = ["127.0.0.1"]

[[telemetry.sink]]
name = "file"
type = "file"
path = "$E/events.jsonl"
[[telemetry.sink]]
name = "syslog"
type = "syslog"
address = "udp://127.0.0.1:25515"
statuses = ["blocked"]
[[telemetry.sink]]
name = "syslog-tls"
type = "syslog"
address = "tls://localhost:25516"
tls_ca = "$E/ca.pem"
statuses = ["blocked"]
# REQ: OBS-010 (T9.11) — its collector starts later: batches wait on disk.
[[telemetry.sink]]
name = "late"
type = "webhook"
url = "http://127.0.0.1:25581/late"
flush_secs = 1
spill_max_bytes = "1MiB"
[[telemetry.sink]]
name = "collector"
type = "webhook"
url = "http://127.0.0.1:25580/ingest"
flush_secs = 1
# REQ: OBS-006 (T7.17) — query events as OpenTelemetry logs, and metrics over OTLP/HTTP.
[[telemetry.sink]]
name = "otel-logs"
type = "webhook"
url = "http://127.0.0.1:25580/v1/logs"
format = "otlp_logs"
flush_secs = 1
[telemetry.otlp]
endpoint = "http://127.0.0.1:25580"
interval_secs = 5

[alerts]
interval_secs = 5
[[alerts.destination]]
name = "hook"
type = "webhook"
url = "http://127.0.0.1:25580/alert"
[[alerts.rule]]
name = "Lists failing"
when = "list_failing"
for_secs = 0
to = ["hook"]
EOF
"$B" run -c "$E/telltale.toml" > "$E/node.log" 2>&1 & P=$!
for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:26994/api/v1/auth/status" && break; sleep 0.1; done
# The first snapshot waits for the unreachable list's fetch to give up (about 10 s).
for _ in $(seq 60); do [[ $(dig +time=1 -p 25994 @127.0.0.1 ads.sinks.test) == *'EDE: 15'* ]] && break; sleep 0.5; done
for _ in $(seq 5); do dig +short +time=1 -p 25994 @127.0.0.1 nas.sinks.test >/dev/null || true; done

# File: one JSON object per event, the API's query-row fields.
for _ in $(seq 50); do [ "$(grep -c 'nas.sinks.test' "$E/events.jsonl" 2>/dev/null)" -ge 5 ] 2>/dev/null && break; sleep 0.2; done
python3 - "$E/events.jsonl" <<'EOF' || fail "file sink"
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
nas = [r for r in rows if r["name"] == "nas.sinks.test"]
ads = [r for r in rows if r["name"] == "ads.sinks.test"]
assert len(nas) >= 5, sorted({(r["name"], r["status"]) for r in rows})
assert nas[0]["status"] == "local" and nas[0]["clientName"] == "kitchen-tablet", nas[0]
assert ads and ads[-1]["status"] == "blocked" and ads[-1]["list"] == "ads", [(r["status"], r.get("list")) for r in ads][-3:]
print(f"file sink: {len(rows)} events")
EOF

# Syslog: RFC 5424, blocked events only (statuses filter), severity notice (local0 → 133).
for _ in $(seq 50); do grep -q 'ads.sinks.test' "$E/syslog" 2>/dev/null && break; sleep 0.2; done
grep -q '^<133>1 .* telltale - query - {.*"name":"ads.sinks.test"' "$E/syslog" || fail "syslog: $(head -c 300 "$E/syslog")"
! grep -q 'nas.sinks.test' "$E/syslog" || fail "syslog got an event its statuses filter excludes"
echo "syslog sink: ok"

# REQ: OBS-010 (T9.11) — syslog over TLS: octet-counted RFC 5424 frames.
for _ in $(seq 50); do grep -q 'ads.sinks.test' "$E/syslog-tls" 2>/dev/null && break; sleep 0.2; done
grep -Eq '^[0-9]+ <133>1 .* telltale - query - \{.*"name":"ads.sinks.test"' "$E/syslog-tls" || fail "syslog over TLS: $(head -c 300 "$E/syslog-tls" 2>/dev/null)"
echo "syslog over TLS: ok"

# Webhook: newline-delimited JSON batches.
for _ in $(seq 50); do grep -lq 'ads.sinks.test' "$E"/posts/* 2>/dev/null && break; sleep 0.2; done
python3 - "$E/posts" <<'EOF' || fail "webhook sink"
import json, os, sys
d = sys.argv[1]
events = 0
for f in sorted(os.listdir(d)):
    path, ct, body = open(os.path.join(d, f)).read().split("\n", 2)
    if path == "/ingest":
        assert ct == "application/x-ndjson", ct
        events += len([json.loads(l) for l in body.splitlines() if l])
assert events >= 6, events
print(f"webhook sink: {events} events")
EOF

# OTLP: metrics every 5 s, and query events as log records.
for _ in $(seq 60); do grep -lq '^/v1/metrics' "$E"/posts/* 2>/dev/null && break; sleep 0.5; done
python3 - "$E/posts" <<'EOF' || fail "OTLP"
import json, os, sys
d = sys.argv[1]
metrics, logs = None, []
for f in sorted(os.listdir(d)):
    path, ct, body = open(os.path.join(d, f)).read().split("\n", 2)
    if path == "/v1/metrics":
        assert ct == "application/json", ct
        metrics = json.loads(body)
    elif path == "/v1/logs":
        logs += json.loads(body)["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
assert metrics, "no OTLP metrics"
rm = metrics["resourceMetrics"][0]
names = {m["name"]: m for m in rm["scopeMetrics"][0]["metrics"]}
assert names["telltale_queries_total"]["sum"]["isMonotonic"], names["telltale_queries_total"]
assert "histogram" in names["telltale_query_duration_seconds"]
assert any(a["key"] == "service.name" for a in rm["resource"]["attributes"])
attrs = [{a["key"]: a["value"].get("stringValue") for a in r["attributes"]} for r in logs]
assert any(a.get("dns.question.name") == "ads.sinks.test" and a.get("telltale.status") == "blocked" for a in attrs), attrs[:3]
print(f"OTLP: {len(names)} metrics, {len(logs)} log records")
EOF

# Alert: the failing list, as JSON to the alert webhook.
# The list's failure is recorded once the fetcher's retries are over (about 40 s).
for _ in $(seq 180); do grep -lq '^/alert' "$E"/posts/* 2>/dev/null && break; sleep 0.5; done
python3 - "$E/posts" <<'EOF' || fail "alert"
import json, os, sys
d = sys.argv[1]
alerts = []
for f in sorted(os.listdir(d)):
    path, ct, body = open(os.path.join(d, f)).read().split("\n", 2)
    if path == "/alert":
        alerts.append(json.loads(body))
assert alerts, "no alert"
a = alerts[0]
assert a["rule"] == "Lists failing" and a["status"] == "firing" and a["subject"] == "unreachable", a
print("alert:", a["summary"])
EOF

# REQ: OBS-010 (T9.11) — the late collector: refused batches (after their retries, about 7 s)
# are kept on disk, then sent once it's up, and the spill file goes.
for _ in $(seq 60); do [ -s "$E/data/sinks/late.spill" ] && break; sleep 0.5; done
[ -s "$E/data/sinks/late.spill" ] || fail "no spill file for the late webhook"
cat > "$E/late.py" <<'EOF'
import http.server, os, sys
out = sys.argv[1]
os.makedirs(out + "/late", exist_ok=True)
n = [0]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        n[0] += 1
        with open(f"{out}/late/{n[0]:04d}", "wb") as f:
            f.write(body)
        self.send_response(204)
        self.end_headers()
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("127.0.0.1", 25581), H).serve_forever()
EOF
python3 "$E/late.py" "$E" & L=$!
dig +short +time=1 -p 25994 @127.0.0.1 nas.sinks.test >/dev/null || true
for _ in $(seq 60); do grep -lq 'ads.sinks.test' "$E"/late/* 2>/dev/null && [ ! -e "$E/data/sinks/late.spill" ] && break; sleep 0.5; done
grep -lq 'ads.sinks.test' "$E"/late/* 2>/dev/null || fail "the kept batches never reached the late collector"
[ ! -e "$E/data/sinks/late.spill" ] || fail "spill file left after sending: $(wc -c < "$E/data/sinks/late.spill") bytes"
echo "webhook spill: $(cat "$E"/late/* | grep -c '"name"') events delivered late"

# DNS never waited: still answering.
[[ $(dig +short +time=1 -p 25994 @127.0.0.1 nas.sinks.test) == *10.0.0.9* ]] || fail "DNS stopped answering"
echo "sinks-e2e: ok"
