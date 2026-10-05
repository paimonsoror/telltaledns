#!/usr/bin/env bash
# REQ: CLU-009 — T5.10 acceptance on kind with this build's binary: `mode: scaled`.
#   1. the controller creates the cluster; resolver pods join it with the generated Secret and
#      turn ready only once synced (so `helm install --wait` passing proves join + sync);
#   2. DNS answers through a resolver pod;
#   3. a node outside Kubernetes (like a Pi) joins through the cluster port with a token from
#      the controller, and both sides see each other;
#   4. a deleted resolver pod is replaced by a new member, and the old one leaves at once.
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
sleep 2
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
echo PASS
