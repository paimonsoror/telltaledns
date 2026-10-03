#!/usr/bin/env bash
# REQ: OPS-001 — run the image the way spec/08 §2 says production runs it, and prove it answers.
# Usage: deploy/image/smoke.sh <image> [platform]   e.g. telltale:ci linux/arm64 (QEMU)
#
# Hardening under test: non-root 65532, read-only rootfs, all capabilities dropped,
# no-new-privileges, default CMD binding :53 (Docker's bridge netns allows unprivileged low
# ports, so no NET_BIND_SERVICE is needed there).
set -euo pipefail

image="${1:?usage: smoke.sh <image> [platform]}"
platform="${2:-}"
name="telltale-smoke-$$"
port="${SMOKE_PORT:-5353}"
metrics="${SMOKE_METRICS_PORT:-9253}"
dir="$(mktemp -d)"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$dir"' EXIT

cat > "$dir/telltale.toml" <<'EOF'
config_version = 1

[[record]]
name = "smoke.home.arpa"
type = "A"
value = "192.0.2.53"
EOF
chmod 0644 "$dir/telltale.toml"

docker run -d --name "$name" ${platform:+--platform "$platform"} \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /var/lib/telltale:uid=65532,gid=65532 \
    -v "$dir/telltale.toml:/etc/telltale/telltale.toml:ro" \
    -p "127.0.0.1:$port:53/udp" -p "127.0.0.1:$port:53/tcp" -p "127.0.0.1:$metrics:9153/tcp" \
    "$image" >/dev/null

# QEMU-emulated startup is slow; allow up to 60 s.
for _ in $(seq 120); do
    if curl -fsS "http://127.0.0.1:$metrics/readyz" >/dev/null 2>&1; then ready=1; break; fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]]; then break; fi
    sleep 0.5
done
if [[ -z "${ready:-}" ]]; then
    echo "FAIL: not ready"; docker logs "$name"; exit 1
fi

fail=0
check() {  # check <desc> <expected> <cmd...>
    local desc="$1" want="$2"; shift 2
    local got; got="$("$@" 2>&1 || true)"
    if [[ "$got" == *"$want"* ]]; then echo "ok   $desc"; else echo "FAIL $desc: got '$got'"; fail=1; fi
}
check "UDP answer"     192.0.2.53 dig +short +time=5 +tries=2 @127.0.0.1 -p "$port" smoke.home.arpa A
check "TCP answer"     192.0.2.53 dig +short +tcp +time=5 @127.0.0.1 -p "$port" smoke.home.arpa A
check "metrics"        telltale_  curl -fsS "http://127.0.0.1:$metrics/metrics"
check "runs as 65532"  65532:65532 docker inspect -f '{{.Config.User}}' "$name"
check "version"        telltale   docker run --rm ${platform:+--platform "$platform"} "$image" --version
arch="$(docker image inspect -f '{{.Architecture}}{{with .Variant}}/{{.}}{{end}}' "$image")"
echo "image arch: $arch"

if [[ $fail -ne 0 ]]; then docker logs "$name"; exit 1; fi
echo "smoke OK: $image ${platform:-native}"
