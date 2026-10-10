#!/usr/bin/env bash
# REQ: CLU-009 — T5.10 acceptance on kind with this build's binary: `mode: scaled`.
#   1. the controller creates the cluster; resolver pods join it with the generated Secret and
#      turn ready only once synced (so `helm install --wait` passing proves join + sync);
#   2. DNS answers through a resolver pod;
#   3. a node outside Kubernetes (like a Pi) joins through the cluster port with a token from
#      the controller, and both sides see each other;
#   4. a deleted resolver pod is replaced by a new member, and the old one leaves at once.
#   6. staged rollouts (CLU-013): with nothing set, a change reaches the outside node at once;
#      after `canaries = ["ephemeral"]` through the settings API, the pods are the canaries and
#      the outside node gets the next change only after the bake.
#
#   deploy/helm/scaled-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
#   KEEP=1 ...   leave the kind cluster running
# Needs docker, kind, kubectl, helm, python3.
set -euo pipefail
cd "$(dirname "$0")/../.."
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
name=telltale-scaled
ns=dns
image=telltale:scaled-e2e
E=$(mktemp -d)
export KUBECONFIG="$E/kubeconfig"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do pkill -P "$p" 2>/dev/null || true; kill "$p" 2>/dev/null || true; done
  [[ "${KEEP:-}" == 1 ]] && { echo "kept: KUBECONFIG=$KUBECONFIG, files in $E"; return; }
  kind delete cluster --name "$name" >/dev/null 2>&1 || true
  rm -rf "$E"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  # Annotations are readable without a token (job logs aren't).
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  kubectl -n "$ns" get pods -o wide || true
  for p in $(kubectl -n "$ns" get pods -o name 2>/dev/null); do echo "--- $p"; kubectl -n "$ns" logs "$p" --tail=20 || true; done
  [[ -f "$E/pi.log" ]] && { echo "--- outside node"; tail -20 "$E/pi.log"; }
  exit 1
}
k() { kubectl -n "$ns" "$@"; }
# kubectl port-forward exits on some connection errors (a reset forwarded connection, a
# restarted pod): keep each one running for the whole test.
forward() { # target ports
  ( while true; do kubectl -n "$ns" port-forward "$1" "$2" >/dev/null 2>&1; sleep 0.5; done ) &
  PIDS+=($!)
}
wait_port() { # local port: until a forward accepts connections (at most 20 s)
  for _ in $(seq 40); do
    python3 -c "import socket,sys; socket.create_connection(('127.0.0.1', int(sys.argv[1])), 1)" "$1" 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}
metric() { # url name [label-filter] -> value
  { curl -s --max-time 3 "$1/metrics" || true; } | awk -v n="$2" -v f="${3:-}" 'index($1, n) == 1 && (f == "" || index($1, f)) {print $2; exit}'
}

echo "== image and cluster"
mkdir -p "$E/ctx" && cp "$B" "$E/ctx/telltale"
printf '%s\n' 'FROM ubuntu:24.04' 'COPY telltale /usr/local/bin/telltale' \
  'ENTRYPOINT ["/usr/local/bin/telltale"]' 'CMD ["run"]' > "$E/ctx/Dockerfile"
docker build -q -t "$image" "$E/ctx" >/dev/null
kind create cluster --name "$name" --wait 120s >/dev/null
kind load docker-image "$image" --name "$name" >/dev/null

echo "== 1. helm install mode=scaled (waits for every pod to be ready, i.e. joined and synced)"
cat > "$E/values.yaml" <<'EOF'
mode: scaled
image: { repository: telltale, tag: scaled-e2e, pullPolicy: Never }
persistence: { enabled: false }
service: { dns: { type: ClusterIP } }
resolvers: { replicas: 2, ephemeralTtlSeconds: 60 }
# How the outside node reaches the controller (a LoadBalancer URL in real life).
cluster: { advertise: ["https://127.0.0.1:19443"] }
config: |
  [[upstream]]
  name = "nowhere"
  url = "udp://127.0.0.1:9"
  [[upstream_group]]
  name = "default"
  members = ["nowhere"]
  [[record]]
  name = "scaled.e2e.test"
  type = "A"
  value = "10.9.8.7"
EOF
helm install t deploy/helm/telltale -n "$ns" --create-namespace -f "$E/values.yaml" --wait --timeout 300s >/dev/null \
  || fail "helm install --wait"
# Resolver pods are ready only once they applied the controller's configuration.
k wait --for=condition=Ready pod -l app.kubernetes.io/component=resolver --timeout 180s >/dev/null \
  || fail "resolver pods never became ready (joined and synced)"
forward svc/t-telltale-metrics 19153:9153
forward svc/t-telltale-cluster 19443:9443
sleep 2
up=""
for _ in $(seq 30); do up=$(metric http://127.0.0.1:19153 telltale_cluster_peers 'state="up"'); [[ "$up" == 2 ]] && break; sleep 1; done
[[ "$up" == 2 ]] || fail "the controller sees $up resolver pods up, not 2"
echo "ok (2 resolver pods joined)"

echo "== 2. DNS through a resolver pod"
pod=$(k get pods -l app.kubernetes.io/component=resolver -o jsonpath='{.items[0].metadata.name}')
forward "pod/$pod" 15353:5353
wait_port 15353 || fail "the port-forward to $pod never came up"
ans=$(python3 - <<'PY'
import socket, struct
q = struct.pack('>HHHHHH', 7, 0x0100, 1, 0, 0, 0) + b''.join(bytes([len(l)]) + l.encode() for l in 'scaled.e2e.test'.split('.')) + b'\0' + struct.pack('>HH', 1, 1)
s = socket.create_connection(('127.0.0.1', 15353), 3); s.sendall(struct.pack('>H', len(q)) + q)
n = struct.unpack('>H', s.recv(2))[0]; r = b''
while len(r) < n: r += s.recv(n - len(r))
print('.'.join(str(b) for b in r[-4:]) if struct.unpack('>H', r[6:8])[0] else '')
PY
)
[[ "$ans" == 10.9.8.7 ]] || fail "resolver pod answered '$ans'"
echo "ok"

echo "== 2b. the controller knows each pod's name, Kubernetes node, and load (T6.14)"
# REQ: CLU-008 — 150 more queries to that pod: over 2 q/s for the last minute.
python3 - <<'PY'
import socket, struct
q = struct.pack('>HHHHHH', 8, 0x0100, 1, 0, 0, 0) + b''.join(bytes([len(l)]) + l.encode() for l in 'scaled.e2e.test'.split('.')) + b'\0' + struct.pack('>HH', 1, 1)
s = socket.create_connection(('127.0.0.1', 15353), 3)
for _ in range(150):
    s.sendall(struct.pack('>H', len(q)) + q)
    n = struct.unpack('>H', s.recv(2))[0]; r = b''
    while len(r) < n: r += s.recv(n - len(r))
PY
knode=$(k get pod "$pod" -o jsonpath='{.spec.nodeName}')
info=""
for _ in $(seq 30); do
  info=$({ curl -s --max-time 3 http://127.0.0.1:19153/metrics || true; } | grep '^telltale_cluster_peer_info{' || true)
  grep -q "pod=\"$pod\"" <<<"$info" && break; sleep 1
done
grep -q "pod=\"$pod\"" <<<"$info" || fail "the controller doesn't report pod $pod: $info"
grep "pod=\"$pod\"" <<<"$info" | grep -q "kube_node=\"$knode\"" || fail "pod $pod isn't on Kubernetes node $knode: $info"
id=$(grep "pod=\"$pod\"" <<<"$info" | sed -n 's/.*{node="\([^"]*\)".*/\1/p' | head -1)
qps=0
for _ in $(seq 30); do
  qps=$(metric http://127.0.0.1:19153 telltale_cluster_peer_queries_per_second "node=\"$id\"")
  [[ "${qps:-0}" -ge 2 ]] && break; sleep 1
done
[[ "${qps:-0}" -ge 2 ]] || fail "the controller sees ${qps:-0} q/s from pod $pod, not 2 or more"
echo "ok ($pod on $knode, $qps q/s)"

echo "== 3. a node outside Kubernetes joins through the cluster port"
args=(-c /etc/telltale/00-chart.toml -c /etc/telltale/10-values.toml -c /etc/telltale/20-controller.toml)
T=$(k exec sts/t-telltale -- telltale cluster token create --ttl 10m --url https://127.0.0.1:19443 "${args[@]}" 2>/dev/null)
mkdir -p "$E/pi"
cat > "$E/pi.toml" <<EOF
[node]
data_dir = "$E/pi"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25599"
[telemetry.metrics]
listen = "127.0.0.1:29599"
# Every port its own: on a CI runner the default API port (8053) can still be taken by an
# earlier step, and then this node exits at start.
[api]
listen = "127.0.0.1:27599"
[cluster]
listen = "127.0.0.1:28599"
EOF
"$B" cluster join "$T" --site pi -c "$E/pi.toml" >/dev/null || fail "the outside node couldn't join"
# Cluster-link errors are debug-level: keep them for the failure message (TELLTALE_LOG is
# a single level).
TELLTALE_LOG=debug "$B" run -c "$E/pi.toml" > "$E/pi.log" 2>&1 & PIDS+=($!)
seen=""
for _ in $(seq 120); do seen=$(metric http://127.0.0.1:29599 telltale_cluster_peer_up 'site="k8s"'); [[ "$seen" == 1 ]] && break; sleep 0.5; done
if [[ "$seen" != 1 ]]; then
  # Job logs need a token; annotations don't. Log lines carry no module target, so pick the
  # cluster-related ones by content, one annotation each.
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    grep -viE 'upstream|setup token|list (updated|fetcher)|serving|listening' "$E/pi.log" \
      | grep -iE 'cluster|peer|primary|stream|join|tls|cert|connect|refused|error|warn' \
      | tail -8 | cut -c1-300 | while IFS= read -r l; do echo "::warning title=outside node log::$l"; done
    echo "::warning title=outside node cluster.json::$(tr -d '\n ' < "$E/pi/cluster/cluster.json" | grep -o '"primary_urls":\[[^]]*\]')"
    echo "::warning title=outside node metrics::$({ curl -s --max-time 3 http://127.0.0.1:29599/metrics || true; } | grep '^telltale_cluster' | tr '\n' ' ' | cut -c1-400)"
  fi
  fail "the outside node doesn't see the controller"
fi
for _ in $(seq 30); do up=$(metric http://127.0.0.1:19153 telltale_cluster_peers 'state="up"'); [[ "$up" == 3 ]] && break; sleep 1; done
[[ "$up" == 3 ]] || fail "the controller sees $up peers up, not 3"
# It applies the controller's configuration: blobs come over the URL it connected with, not an
# in-cluster name it can't resolve.
for _ in $(seq 60); do [[ "$(metric http://127.0.0.1:29599 telltale_cluster_sync_error)" == 0 && "$(metric http://127.0.0.1:29599 telltale_cluster_config_seq)" -gt 0 ]] && break; sleep 0.5; done
[[ "$(metric http://127.0.0.1:29599 telltale_cluster_sync_error)" == 0 ]] || fail "the outside node can't apply the controller's configuration"
echo "ok"

echo "== 4. a deleted resolver pod is replaced, and the old one leaves at once"
k delete pod "$pod" --wait=false >/dev/null
k rollout status deploy/t-telltale-resolver --timeout 180s >/dev/null || fail "the replacement pod never became ready"
# REQ: CLU-009 — it leaves on SIGTERM: well before its 60 s expiry.
for _ in $(seq 30); do
  total=$({ curl -s --max-time 3 http://127.0.0.1:19153/metrics || true; } | awk '/^telltale_cluster_peers\{/ {s += $2} END {print s+0}')
  [[ "$total" == 3 ]] && break; sleep 1
done
[[ "$total" == 3 ]] || fail "the controller still lists $total peers 30 s after the pod was deleted (it didn't leave)"
echo "ok"

echo "== 5. scaling: the controller's view follows within 5 s (the Cluster page polls every 5 s)"
# REQ: CLU-008 (T6.14 AC) — the topology updates within 10 s when a pod is added or removed.
peers() { { curl -s --max-time 3 http://127.0.0.1:19153/metrics || true; } | awk '/^telltale_cluster_peers\{state="up"\}/ {print $2+0}'; }
since() { python3 -c "import time; print(f'{time.time() - $1:.1f}')"; }
k scale deploy/t-telltale-resolver --replicas=3 >/dev/null
k rollout status deploy/t-telltale-resolver --timeout 180s >/dev/null || fail "the third resolver pod never became ready"
t0=$(date +%s.%N)
for _ in $(seq 100); do [[ "$(peers)" == 4 ]] && break; sleep 0.1; done
[[ "$(peers)" == 4 ]] || fail "the controller doesn't show the new pod 10 s after it turned ready"
added=$(since "$t0")
t0=$(date +%s.%N)
k scale deploy/t-telltale-resolver --replicas=2 >/dev/null
for _ in $(seq 100); do [[ "$(peers)" == 3 ]] && break; sleep 0.1; done
[[ "$(peers)" == 3 ]] || fail "the controller still shows the removed pod 10 s after scaling in"
removed=$(since "$t0")
python3 -c "import sys; sys.exit(0 if $added <= 5 and $removed <= 5 else 1)" \
  || fail "the controller took ${added} s (added) / ${removed} s (removed), over 5 s"
echo "ok (a new pod shows ${added} s after it's ready; a removed one is gone ${removed} s after scaling in)"

echo "== 6. staged rollouts: off by default, then the resolver pods are the canaries (CLU-013)"
forward svc/t-telltale-api 18053:8053
wait_port 18053 || fail "the port-forward to the API never came up"
ST=$(k exec sts/t-telltale -- cat /var/lib/telltale/setup-token)
field() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
CSRF=$(curl -sf -c "$E/jar" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$ST\",\"username\":\"admin\",\"password\":\"e2e-password-123\"}" \
  http://127.0.0.1:18053/api/v1/auth/setup | field 'd["csrfToken"]') || fail "couldn't set up the admin"
api() { # method path [json] -> HTTP status; the body in out.json
  curl -s -o "$E/out.json" -w '%{http_code}' --max-time 20 -b "$E/jar" -X "$1" -H "x-csrf-token: $CSRF" \
    -H 'content-type: application/json' ${3:+-d "$3"} "http://127.0.0.1:18053/api/v1$2"
}
pi_q() { # name -> the outside node's first A record ('' for none)
  python3 - "$1" <<'PY'
import socket, struct, sys
q = struct.pack('>HHHHHH', 9, 0x0100, 1, 0, 0, 0) + b''.join(bytes([len(l)]) + l.encode() for l in sys.argv[1].split('.')) + b'\0' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
try:
    s.sendto(q, ('127.0.0.1', 25599)); r, _ = s.recvfrom(4096)
    print('.'.join(str(b) for b in r[-4:]) if struct.unpack('>H', r[6:8])[0] else '')
except OSError:
    print('TIMEOUT')
PY
}
code=$(api PUT /records/roll1.e2e.test '{"records":[{"type":"A","value":"10.9.8.1"}]}')
[[ "$code" == 200 ]] || fail "the first change answered $code: $(cat "$E/out.json")"
for _ in $(seq 40); do [[ "$(pi_q roll1.e2e.test)" == 10.9.8.1 ]] && break; sleep 0.25; done
[[ "$(pi_q roll1.e2e.test)" == 10.9.8.1 ]] || fail "with no canaries, the outside node didn't get the change at once"
code=$(api PUT /cluster/rollout-settings/default '{"canaries":["ephemeral"],"bake_secs":30}')
[[ "$code" == 200 ]] || fail "the rollout settings answered $code: $(cat "$E/out.json")"
sleep 6   # the publisher's next report
code=$(api PUT /records/roll2.e2e.test '{"records":[{"type":"A","value":"10.9.8.2"}]}')
[[ "$code" == 200 ]] || fail "the second change answered $code: $(cat "$E/out.json")"
stage=""
for _ in $(seq 40); do api GET /cluster/rollout >/dev/null; stage=$(field 'd["stage"]' < "$E/out.json"); [[ "$stage" == canary ]] && break; sleep 0.25; done
[[ "$stage" == canary ]] || fail "the change wasn't staged: $(cat "$E/out.json")"
python3 - "$E/out.json" <<'PY' || fail "canaries aren't the resolver pods: $(cat "$E/out.json")"
import json, sys
d = json.load(open(sys.argv[1]))
nodes = {n['site']: n for n in d['nodes']}
pods = [n for n in d['nodes'] if n['site'] == 'k8s' and n['canary']]
sys.exit(0 if len(d['rolloutCanaries']) == 2 and len(pods) >= 2 and not nodes['pi']['canary'] else 1)
PY
[[ "$(pi_q roll2.e2e.test)" == "" ]] || fail "the outside node got the change during the bake"
for _ in $(seq 120); do [[ "$(pi_q roll2.e2e.test)" == 10.9.8.2 ]] && break; sleep 0.5; done
[[ "$(pi_q roll2.e2e.test)" == 10.9.8.2 ]] || fail "the outside node never got the change after the bake"
echo "ok (pods first, the outside node after the bake)"
echo PASS
