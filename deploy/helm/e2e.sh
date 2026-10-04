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

# Pull the image on the host once and load it (faster, and works without registry auth).
docker pull -q "$image" >/dev/null
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
