#!/usr/bin/env bash
# REQ: CLU-008 (T6.11) — the chart's alert rules, evaluated by Prometheus's own `promtool test
# rules` against synthetic series (deploy/helm/tests/alerts.test.yml): a disk under 10% free,
# memory pressure, an OOM kill, CPU throttling, and heat fire; healthy values don't.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
helm template telltale "$here/telltale" --set prometheusRule.enabled=true \
  --show-only templates/monitoring.yaml > "$out/rendered.yaml"
# The PrometheusRule's `spec` is a plain Prometheus rules file, indented by two.
python3 - "$out/rendered.yaml" "$out/rules.yml" <<'PY'
import sys
docs = open(sys.argv[1]).read().split("\n---")
doc = next(d for d in docs if "kind: PrometheusRule" in d)
lines = doc.split("\n")
start = next(i for i, l in enumerate(lines) if l.strip() == "spec:")
body = [l[2:] if l.startswith("  ") else l for l in lines[start + 1:]]
open(sys.argv[2], "w").write("\n".join(body) + "\n")
PY
cp "$here/tests/alerts.test.yml" "$out/"
chmod -R a+rX "$out"   # promtool runs as nobody in its image
[ "${SHOW:-}" = 1 ] && cat "$out/rules.yml"
# A promtool on PATH (3.x) if there is one, else Prometheus's image.
if command -v promtool >/dev/null; then
  (cd "$out" && promtool test rules alerts.test.yml)
else
  docker run --rm -v "$out:/w" -w /w --entrypoint promtool prom/prometheus:v3.5.0 test rules alerts.test.yml
fi
