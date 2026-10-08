#!/bin/sh
# REQ: DOC-002 — dashboard screenshots for the README (docs/images/) and the site
# (site/assets/shots/dashboard-*.jpg) on a made-up network, so no real network ever appears in
# them. Starts two stub upstreams and a fresh server with demo.toml, sends synthetic traffic, and
# runs shots.spec.ts. Nothing here is real: every device, name, and address is invented.
#
#   (cd ui && npm run build) && cargo build -p telltale     # the binary embeds the UI
#   ui/tests/demo/run.sh [seconds]     # 840 (the default) fills the 15-minute charts
#
# Needs python3, the debug binary (or TELLTALE_BIN), and the UI's Playwright browsers.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
bin=${TELLTALE_BIN:-$repo/target/debug/telltale}
secs=${1:-840}

rm -rf /tmp/telltale-demo
mkdir -p /tmp/telltale-demo/data
pids=""
cleanup() { [ -n "$pids" ] && kill $pids 2>/dev/null || true; }
trap cleanup EXIT INT TERM

python3 "$here/stub.py" 25401 8 30 & pids="$pids $!"
python3 "$here/stub.py" 25402 12 45 & pids="$pids $!"
TELLTALE_BOOTSTRAP_ADMIN_USER=admin TELLTALE_BOOTSTRAP_ADMIN_PASSWORD='correct horse battery' \
  "$bin" run -c "$here/demo.toml" > /tmp/telltale-demo/server.log 2>&1 & pids="$pids $!"

i=0
until curl -fs -m1 -o /dev/null http://127.0.0.1:29154/readyz; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then echo "the server didn't start; see /tmp/telltale-demo/server.log" >&2; exit 1; fi
  sleep 0.5
done

echo "sending ${secs}s of traffic"
python3 "$here/traffic.py" "$secs"
sleep 3
mkdir -p "$repo/docs/images"
cd "$repo/ui"
npx playwright test -c tests/demo/playwright.config.ts
