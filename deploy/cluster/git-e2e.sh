#!/usr/bin/env bash
# REQ: CLU-003, OPS-005 — T5.12 acceptance (ADR-049): the cluster's configuration from a Git
# repository, served over smart HTTP by `git upload-pack` (the protocol GitHub speaks).
#   1. a pushed commit is served by both nodes, which report the same commit;
#   2. an invalid commit is never published (both keep the last good one; it's flagged);
#   3. the next good commit is;
#   4. a force-push is refused;
#   5. with the repository unreachable, both keep serving (and it's flagged);
#   6. the primary dies, the replica is promoted, and it follows the repository.
# The primary polls rarely here: each push triggers the webhook, which also proves it.
# Usage: deploy/cluster/git-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P_PID= R_PID= G_PID=
cleanup() {
  for p in $P_PID $R_PID $G_PID; do kill "$p" 2>/dev/null && wait "$p" 2>/dev/null || true; done
  [ "${KEEP:-}" = 1 ] || rm -rf "$E"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  # Annotations are readable without a token (job logs aren't).
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  for f in "$E"/*.log; do echo "--- $(basename "$f")"; tail -20 "$f"; done
  exit 1
}

# The repository, and a smart-HTTP front for it (what `git http-backend` does).
git init -q --bare -b main "$E/repo.git"
git -C "$E/repo.git" config uploadpack.allowFilter true
git -C "$E/repo.git" config uploadpack.allowAnySHA1InWant true
git init -q -b main "$E/work"
gw() { git -C "$E/work" -c user.name=Ada -c user.email=ada@example.com -c commit.gpgsign=false "$@"; }
gw remote add origin "$E/repo.git"
cat > "$E/githttp.py" <<'PY'
import http.server, os, subprocess, sys
repo = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def run(self, extra, body=b''):
        env = dict(os.environ, GIT_PROTOCOL=self.headers.get('Git-Protocol', ''))
        out = subprocess.run(['git', 'upload-pack', '--stateless-rpc', *extra, repo], input=body, env=env, capture_output=True).stdout
        self.send_response(200); self.send_header('Content-Length', str(len(out))); self.end_headers(); self.wfile.write(out)
    def do_GET(self):
        self.run(['--advertise-refs'])
    def do_POST(self):
        self.run([], self.rfile.read(int(self.headers['Content-Length'])))
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY
start_git() { python3 "$E/githttp.py" 28799 "$E/repo.git" & G_PID=$!; sleep 0.5; }
start_git

shared() { # value -> a shared configuration with one record
  mkdir -p "$E/work/telltale"
  cat > "$E/work/telltale/shared.toml" <<EOF
[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"
[[upstream_group]]
name = "default"
members = ["nowhere"]
[[record]]
name = "git.test"
type = "A"
value = "$1"
EOF
}
push() { gw add -A; gw commit -q -m "$1"; gw push -q "${2:-origin}" "${3:-main}" 2>/dev/null; gw rev-parse HEAD; }
echo -n "hook-secret" > "$E/hook"
hook() { # api-port: the push webhook, signed as GitHub does
  local body='{"ref":"refs/heads/main"}'
  local sig
  sig=$(printf '%s' "$body" | openssl dgst -sha256 -hmac hook-secret | awk '{print $NF}')
  curl -s -o /dev/null -w '%{http_code}' -X POST -H "X-Hub-Signature-256: sha256=$sig" \
    -H 'content-type: application/json' -d "$body" "http://127.0.0.1:$1/api/v1/hooks/git"
}

node_config() { # name dns api metrics cluster
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
[cluster.git]
repo = "http://127.0.0.1:28799/repo.git"
ref = "main"
path = "telltale/shared.toml"
poll_secs = 600
webhook_secret_file = "$E/hook"
EOF
}
mkdir -p "$E/p" "$E/r"
node_config p 25701 28701 29701 28741 > "$E/p.toml"
node_config r 25702 28702 29702 28742 > "$E/r.toml"

cat > "$E/q.py" <<'PY'
import socket, struct, sys, random
q = struct.pack('>HHHHHH', random.randrange(65536), 0x0100, 1, 0, 0, 0) + b'\x03git\x04test\x00' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.5)
try:
    s.sendto(q, ('127.0.0.1', int(sys.argv[1]))); r, _ = s.recvfrom(4096)
    print('.'.join(str(b) for b in r[-4:]) if struct.unpack('>H', r[6:8])[0] else '')
except OSError:
    print('TIMEOUT')
PY
q() { python3 "$E/q.py" "$1"; }
wait_answer() { # port value seconds
  for _ in $(seq $(( $3 * 10 ))); do [ "$(q "$1")" = "$2" ] && return 0; sleep 0.1; done
  return 1
}
metric() { { curl -s --max-time 2 "http://127.0.0.1:$1/metrics" || true; } | awk -v n="$2" 'index($1, n) == 1 {print $1, $2; exit}'; }
commit_of() { metric "$1" telltale_cluster_config_commit | sed -n 's/.*commit="\([0-9a-f]*\)".*/\1/p'; }

echo "== 1. a pushed commit is served by both nodes"
shared 10.0.0.1; c1=$(push first)
"$B" cluster init --name git --advertise https://127.0.0.1:28741 -c "$E/p.toml" >/dev/null
"$B" run -c "$E/p.toml" > "$E/p.log" 2>&1 & P_PID=$!
wait_answer 25701 10.0.0.1 15 || fail "the primary never served the commit"
T=$("$B" cluster token create --ttl 10m -c "$E/p.toml" 2>/dev/null)
"$B" cluster join "$T" --site r --eligible --advertise https://127.0.0.1:28742 -c "$E/r.toml" >/dev/null
"$B" run -c "$E/r.toml" > "$E/r.log" 2>&1 & R_PID=$!
wait_answer 25702 10.0.0.1 15 || fail "the replica never served the commit"
for _ in $(seq 50); do [ "$(commit_of 29702)" = "$c1" ] && break; sleep 0.1; done
[ "$(commit_of 29701)" = "$c1" ] && [ "$(commit_of 29702)" = "$c1" ] || fail "nodes report commits $(commit_of 29701) / $(commit_of 29702), not $c1"
echo "ok (both on ${c1:0:12})"

echo "== 2. an invalid commit is never published"
echo 'this is = not [valid' >> "$E/work/telltale/shared.toml"; push broken >/dev/null
[ "$(hook 28701)" = 202 ] || fail "the webhook wasn't accepted"
for _ in $(seq 50); do [ "$(metric 29701 telltale_cluster_git_refused | awk '{print $2}')" = 1 ] && break; sleep 0.1; done
[ "$(metric 29701 telltale_cluster_git_refused | awk '{print $2}')" = 1 ] || fail "the invalid commit wasn't flagged"
sleep 1
[ "$(q 25702)" = 10.0.0.1 ] && [ "$(commit_of 29702)" = "$c1" ] || fail "the invalid commit reached the replica"
echo ok

echo "== 3. the next good commit is published"
shared 10.0.0.2; c2=$(push second)
hook 28701 >/dev/null
wait_answer 25702 10.0.0.2 10 || fail "the good commit didn't reach the replica"
[ "$(commit_of 29702)" = "$c2" ] || fail "the replica reports $(commit_of 29702), not $c2"
[ "$(metric 29701 telltale_cluster_git_refused | awk '{print $2}')" = 0 ] || fail "still flagged after a good commit"
echo ok

echo "== 4. a force-push is refused"
gw reset -q --hard "$c1"; shared 10.0.0.9; gw add -A; gw commit -q -m rewritten; gw push -q -f origin main 2>/dev/null
hook 28701 >/dev/null
for _ in $(seq 50); do [ "$(metric 29701 telltale_cluster_git_refused | awk '{print $2}')" = 1 ] && break; sleep 0.1; done
[ "$(metric 29701 telltale_cluster_git_refused | awk '{print $2}')" = 1 ] || fail "the force-push wasn't refused"
[ "$(q 25702)" = 10.0.0.2 ] || fail "the force-pushed commit was served"
grep -q "doesn't descend" "$E/p.log" || fail "the primary's log doesn't say why"
gw reset -q --hard "$c2"; gw push -q -f origin main 2>/dev/null
echo ok

echo "== 5. with the repository unreachable, both keep serving"
kill "$G_PID"; wait "$G_PID" 2>/dev/null || true; G_PID=
hook 28701 >/dev/null
for _ in $(seq 50); do [ "$(metric 29701 telltale_cluster_git_failing | awk '{print $2}')" = 1 ] && break; sleep 0.1; done
[ "$(metric 29701 telltale_cluster_git_failing | awk '{print $2}')" = 1 ] || fail "the unreachable repository wasn't flagged"
[ "$(q 25701)" = 10.0.0.2 ] && [ "$(q 25702)" = 10.0.0.2 ] || fail "a node stopped serving the last commit"
start_git
echo ok

echo "== 6. the primary dies; the promoted replica follows the repository"
kill "$P_PID"; wait "$P_PID" 2>/dev/null || true; P_PID=
kill "$R_PID"; wait "$R_PID" 2>/dev/null || true; R_PID=
"$B" cluster promote -c "$E/r.toml" >/dev/null || fail "promotion refused"
"$B" run -c "$E/r.toml" >> "$E/r.log" 2>&1 & R_PID=$!
wait_answer 25702 10.0.0.2 10 || fail "the promoted node doesn't serve the last commit"
shared 10.0.0.3; c3=$(push third)
for _ in $(seq 30); do [ "$(hook 28702)" = 202 ] && break; sleep 0.2; done
wait_answer 25702 10.0.0.3 10 || fail "the promoted node didn't follow the repository"
for _ in $(seq 50); do [ "$(commit_of 29702)" = "$c3" ] && break; sleep 0.1; done
[ "$(commit_of 29702)" = "$c3" ] || fail "the promoted node reports $(commit_of 29702), not $c3"
echo ok
echo PASS
