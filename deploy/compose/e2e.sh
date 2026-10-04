#!/usr/bin/env bash
# REQ: OPS-004 — the Compose bundle end to end: `deploy/compose/e2e.sh IMAGE`.
# Runs compose.yaml unchanged except for the image and an override that moves DNS to port
# 5300 and the API to 18053 (so it can run beside a real resolver), then checks DNS over
# UDP and TCP, the container healthcheck, and the read-only, capability-limited container.
set -euo pipefail

IMAGE="${1:?usage: e2e.sh IMAGE}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
cp "$HERE/compose.yaml" "$HERE/telltale.toml" "$WORK/"
cat >> "$WORK/telltale.toml" <<'EOF'

# e2e override: unprivileged ports.
[[listen]]
proto = "udp"
addr = "127.0.0.1:5300"

[[listen]]
proto = "tcp"
addr = "127.0.0.1:5300"

[api]
listen = "127.0.0.1:18053"
EOF
cat > "$WORK/compose.override.yaml" <<EOF
services:
  telltale:
    image: $IMAGE
    pull_policy: never
    healthcheck:
      test: ["CMD", "/usr/local/bin/telltale", "health", "--url", "http://127.0.0.1:18053/readyz"]
      interval: 2s
      start_period: 5s
EOF
cd "$WORK"
dc() { docker compose -p telltale-e2e "$@"; }
cleanup() {
  dc logs --tail 30 || true
  dc down -v >/dev/null 2>&1 || true
  # ./data belongs to root (Docker created it).
  docker run --rm -v "$WORK:/w" busybox:1.37 rm -rf /w/data >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

dc config -q
dc up -d
echo "== waiting for healthy"
for _ in $(seq 1 30); do
  state="$(docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q telltale)")"
  [ "$state" = healthy ] && break
  sleep 1
done
[ "$state" = healthy ] || { echo "FAIL: container is $state"; exit 1; }

echo "== DNS over UDP and TCP"
dig +short +time=3 @127.0.0.1 -p 5300 example.com A | grep -qE '^[0-9.]+$' || { echo "FAIL: UDP"; exit 1; }
dig +short +tcp +time=3 @127.0.0.1 -p 5300 example.com A | grep -qE '^[0-9.]+$' || { echo "FAIL: TCP"; exit 1; }

echo "== hardening"
id="$(dc ps -q telltale)"
[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$id")" = true ] || { echo "FAIL: root fs writable"; exit 1; }
[ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$id")" = host ] || { echo "FAIL: not host network"; exit 1; }
caps="$(docker inspect -f '{{.HostConfig.CapAdd}}' "$id")"
[ "$caps" = "[NET_BIND_SERVICE]" ] || [ "$caps" = "[CAP_NET_BIND_SERVICE]" ] || { echo "FAIL: caps $caps"; exit 1; }
dc exec -T telltale telltale auth setup-token -c /etc/telltale/telltale.toml >/dev/null

echo "PASS"
