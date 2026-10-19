#!/usr/bin/env bash
# REQ: OPS-002, OPS-003 — T4.1 acceptance: install the chart into a cluster with a
# LoadBalancer (MetalLB), query DNS through the LoadBalancer from outside the cluster, and
# prove the client's real address reached the query log (externalTrafficPolicy: Local).
#
#   deploy/helm/e2e.sh                # a kind cluster named telltale-e2e (deleted afterwards)
#   TOOL=k3d deploy/helm/e2e.sh       # the same on k3d (k3s), e.g. on an arm64 runner
#   KEEP=1 deploy/helm/e2e.sh         # leave it running (E2E_KUBECONFIG=... to choose its kubeconfig)
#
# Needs docker, kind or k3d, kubectl, helm, dig, python3.
set -euo pipefail
cd "$(dirname "$0")/../.."
name="${CLUSTER:-telltale-e2e}"
image="${IMAGE:-ghcr.io/paimonsoror/telltale:edge}"
metallb="${METALLB_VERSION:-v0.14.9}"
ns=telltale

# A private kubeconfig: never switch (or, on delete, clear) the caller's current context.
export KUBECONFIG="${E2E_KUBECONFIG:-$(mktemp)}"
tool="${TOOL:-kind}"
case "$tool" in
  kind) ctx="kind-$name"; net=kind ;;
  # k3d's own load balancer and servicelb are off: MetalLB does what a real LAN LB would.
  k3d) ctx="k3d-$name"; net="k3d-$name" ;;
  *) echo "TOOL must be kind or k3d"; exit 2 ;;
esac
cleanup() {
  [[ "${KEEP:-}" == 1 ]] && return
  if [[ "$tool" == kind ]]; then kind delete cluster --name "$name" >/dev/null 2>&1 || true
  else k3d cluster delete "$name" >/dev/null 2>&1 || true; fi
  rm -f "$KUBECONFIG"
}
trap cleanup EXIT

if [[ "$tool" == kind ]]; then
  kind create cluster --name "$name" --wait 120s
else
  # Own pod/service ranges, so it also runs on a host that is itself a k3s node.
  k3d cluster create "$name" --no-lb --wait --timeout 180s \
    --k3s-arg "--disable=servicelb@server:0" --k3s-arg "--disable=traefik@server:0" \
    --k3s-arg "--cluster-cidr=10.142.0.0/16@server:0" --k3s-arg "--service-cidr=10.143.0.0/16@server:0"
fi
k() { kubectl --context "$ctx" "$@"; }
# A single control-plane node is skipped for LoadBalancer announcements by default.
k label nodes --all node.kubernetes.io/exclude-from-external-load-balancers- >/dev/null 2>&1 || true

# MetalLB with addresses from the end of the cluster's docker network.
k apply -f "https://raw.githubusercontent.com/metallb/metallb/$metallb/config/manifests/metallb-native.yaml" >/dev/null
k -n metallb-system wait --for=condition=available deploy/controller --timeout=180s
k -n metallb-system rollout status ds/speaker --timeout=180s
subnet=$(docker network inspect "$net" -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' | tr ' ' '\n' | grep -m1 '\.')
prefix=$(echo "$subnet" | cut -d. -f1-2)
gateway=$(docker network inspect "$net" -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}' | tr ' ' '\n' | grep -m1 '\.')
cat <<EOF | k apply -f - >/dev/null
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata: { name: e2e, namespace: metallb-system }
spec: { addresses: ["$prefix.255.200-$prefix.255.250"] }
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata: { name: e2e, namespace: metallb-system }
EOF

# Pull the image on the host once and load it (faster, and works without registry auth). A
# local build (IMAGE=telltale:dev) is used as is.
docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null
if [[ "$tool" == kind ]]; then kind load docker-image "$image" --name "$name" >/dev/null
else k3d image import "$image" -c "$name" >/dev/null; fi

helm --kube-context "$ctx" install telltale deploy/helm/telltale -n "$ns" --create-namespace \
  --set image.repository="${image%:*}" --set image.tag="${image##*:}" --set image.pullPolicy=IfNotPresent \
  --set-string config='[[record]]
name = "e2e.home.arpa"
type = "A"
value = "192.0.2.53"' \
  --wait --timeout 300s

lb=""
for _ in $(seq 60); do
  lb=$(k -n "$ns" get svc telltale-dns -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
  [[ -n "$lb" ]] && break
  sleep 2
done
[[ -n "$lb" ]] || { echo "FAIL: no LoadBalancer address"; exit 1; }
echo "LoadBalancer: $lb (this host on the $tool network: $gateway)"

# DNS answers through the LoadBalancer (UDP and TCP); the L2 announcement can take a moment.
udp="" tcp=""
for _ in $(seq 15); do
  udp=$(dig +short +time=2 +tries=1 @"$lb" e2e.home.arpa A 2>/dev/null || true)
  [[ "$udp" == 192.0.2.53 ]] && break
  sleep 2
done
tcp=$(dig +short +tcp +time=3 +tries=2 @"$lb" e2e.home.arpa A 2>/dev/null || true)
[[ "$udp" == 192.0.2.53 && "$tcp" == 192.0.2.53 ]] || { echo "FAIL: answers udp=$udp tcp=$tcp"; exit 1; }
echo "DNS via LoadBalancer: OK (udp and tcp)"

# The query log names the real client, not a node or pod address.
marker="client-ip-$RANDOM.home.arpa"
dig +short +time=3 @"$lb" "$marker" A >/dev/null || true
cfg=(-c /etc/telltale/00-chart.toml -c /etc/telltale/10-values.toml)
seen=""
for _ in $(seq 30); do
  seen=$(k -n "$ns" exec telltale-0 -- /usr/local/bin/telltale qlog search "${cfg[@]}" --match exact --json "$marker" 2>/dev/null \
    | python3 -c 'import json,sys
rows=[json.loads(l) for l in sys.stdin if l.startswith("{")]
print(rows[0]["client"] if rows else "")' || true)
  [[ -n "$seen" ]] && break
  sleep 2
done
echo "query log client for $marker: ${seen:-<none>}"
[[ "$seen" == "$gateway" ]] || { echo "FAIL: expected client $gateway (client IP not preserved)"; exit 1; }
echo "PASS ($tool): DNS via the LoadBalancer, client IP preserved in the query log"

# REQ: FLT-017 (T15.1, AC 6) — Kubernetes workloads as devices: the controller pod (only) gets a
# token and a read-only ClusterRole; a pod whose dnsConfig points at TelltaleDNS resolves an
# outside name and a cluster name (forwarded to CoreDNS), and its query is named by its
# workload. Images older than the feature skip this part.
# (Captured first: with pipefail, `grep -q` closing the pipe early would fail the check.)
schema=$(docker run --rm "$image" config schema 2>/dev/null || true)
if ! grep -q '"kubernetes"' <<<"$schema"; then
  echo "SKIP: $image predates Kubernetes workloads (FLT-017)"
  exit 0
fi
kubedns=$(k -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}')
helm --kube-context "$ctx" upgrade telltale deploy/helm/telltale -n "$ns" \
  --set image.repository="${image%:*}" --set image.tag="${image##*:}" --set image.pullPolicy=IfNotPresent \
  --set kubernetes.enabled=true --set kubernetes.clusterDns="$kubedns" \
  --set-string config='[[record]]
name = "e2e.home.arpa"
type = "A"
value = "192.0.2.53"

[[upstream]]
name = "quad9"
url = "udp://9.9.9.9"

[[upstream_group]]
name = "default"
members = ["quad9"]' \
  --wait --timeout 300s
k -n "$ns" rollout status sts/telltale --timeout=180s >/dev/null
[[ "$(k -n "$ns" get pod telltale-0 -o jsonpath='{.spec.automountServiceAccountToken}')" == true ]] \
  || { echo "FAIL: the controller pod has no service-account token"; exit 1; }
rules=$(k get clusterrole telltale-workloads -o json | python3 -c 'import json,sys
r=json.load(sys.stdin)["rules"]
print(";".join(sorted(",".join(sorted(x["resources"]))+":"+",".join(sorted(x["verbs"])) for x in r)))')
[[ "$rules" == "namespaces,pods:get,list,watch" ]] || { echo "FAIL: ClusterRole rules: $rules"; exit 1; }
echo "RBAC: OK (token on the controller only; $rules)"

dnsip=$(k -n "$ns" get svc telltale-dns -o jsonpath='{.spec.clusterIP}')
k -n default delete pod busybox --ignore-not-found --wait >/dev/null
k -n default run busybox --image=busybox:1.36 --restart=Never --overrides="{\"spec\":{\"dnsPolicy\":\"None\",\"dnsConfig\":{\"nameservers\":[\"$dnsip\"],\"searches\":[\"default.svc.cluster.local\",\"svc.cluster.local\",\"cluster.local\"],\"options\":[{\"name\":\"ndots\",\"value\":\"5\"}]}}}" -- sleep 3600 >/dev/null
k -n default wait --for=condition=Ready pod/busybox --timeout=180s >/dev/null
podip=$(k -n default get pod busybox -o jsonpath='{.status.podIP}')

# The API, for names at read time.
pf=$(mktemp)
( while true; do kubectl --context "$ctx" -n "$ns" port-forward svc/telltale-api 18059:8053 >/dev/null 2>&1; sleep 0.5; done ) &
pfpid=$!
trap 'kill $pfpid 2>/dev/null || true; cleanup' EXIT
for _ in $(seq 40); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:18059/api/v1/auth/status && break; sleep 0.5; done
st=$(k -n "$ns" exec telltale-0 -- cat /var/lib/telltale/setup-token)
csrf=$(curl -sf -c "$pf" -H 'content-type: application/json' \
  -d "{\"setupToken\":\"$st\",\"username\":\"admin\",\"password\":\"e2e-password-123\"}" \
  http://127.0.0.1:18059/api/v1/auth/setup | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrfToken"])') \
  || { echo "FAIL: couldn't set up the admin"; exit 1; }
api() { curl -s --max-time 10 -b "$pf" -H "x-csrf-token: $csrf" "http://127.0.0.1:18059/api/v1$1"; }
seen=""
for _ in $(seq 60); do
  seen=$(api /kubernetes/workloads | python3 -c 'import json,sys
d=json.load(sys.stdin)
print(" ".join(w["name"] for w in d.get("items", [])))' 2>/dev/null || true)
  [[ " $seen " == *" default/pod/busybox "* ]] && break
  sleep 1
done
[[ " $seen " == *" default/pod/busybox "* ]] || { echo "FAIL: busybox isn't in the workload table: $seen"; exit 1; }
echo "workloads: $seen"

marker="flt017-$RANDOM.example.com"
k -n default exec busybox -- nslookup e2e.home.arpa >/dev/null || { echo "FAIL: busybox can't resolve e2e.home.arpa"; exit 1; }
k -n default exec busybox -- nslookup kubernetes.default.svc.cluster.local >/tmp/flt017-ns.txt 2>&1 \
  || { echo "FAIL: kubernetes.default.svc.cluster.local didn't resolve through CoreDNS"; cat /tmp/flt017-ns.txt; exit 1; }
k -n default exec busybox -- nslookup one.one.one.one >/dev/null \
  || { echo "FAIL: busybox can't resolve an outside name through TelltaleDNS"; exit 1; }
k -n default exec busybox -- nslookup "$marker" >/dev/null 2>&1 || true
row=""
for _ in $(seq 30); do
  row=$(api "/queries?name=$marker&match=exact&limit=5" | python3 -c 'import json,sys
items=json.load(sys.stdin).get("items", [])
print(items[0]["client"] + " " + str(items[0].get("clientName")) if items else "")' 2>/dev/null || true)
  [[ -n "$row" ]] && break
  sleep 1
done
echo "query log row for $marker: ${row:-<none>}"
[[ "$row" == "$podip default/pod/busybox" ]] || { echo "FAIL: expected '$podip default/pod/busybox'"; exit 1; }
echo "PASS ($tool): Kubernetes workloads (the pod's own address, named by its workload; cluster names via CoreDNS)"