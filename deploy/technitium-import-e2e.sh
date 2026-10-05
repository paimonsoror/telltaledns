#!/usr/bin/env bash
# REQ: API-007 — T6.4 acceptance against a real Technitium DNS Server (needs Docker and
# internet: the Advanced Blocking app is installed from Technitium's store).
#   1. configure forwarders, blocking (NXDOMAIN, a block list, allowed and blocked names), a
#      zone with records, a forwarder zone, the Advanced Blocking app with two groups, and a
#      DHCP reservation, all through Technitium's own API;
#   2. `telltale import technitium` with an API token; the output must load and carry each of
#      those over;
#   3. run TelltaleDNS on it: local names, a CNAME's TTL, a blocked name (NXDOMAIN, EDE 15),
#      an Advanced Blocking regex and name, and an allowed name that a list blocks.
# Usage: deploy/technitium-import-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
IMAGE=technitium/dns-server:15.6.0
E=$(mktemp -d)
P= LISTS=
cleanup() {
  local rc=$?
  trap - ERR TERM INT
  for p in $P $LISTS; do kill "$p" 2>/dev/null && { wait "$p" 2>/dev/null || true; }; done
  docker rm -f tt-tech >/dev/null 2>&1 || true
  rm -rf "$E"
  exit "$rc"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  for f in "$E"/*.log "$E"/*.err; do [ -f "$f" ] && { echo "--- $(basename "$f")"; tail -20 "$f"; }; done
  exit 1
}
command -v dig >/dev/null || { echo "needs dig"; exit 2; }
command -v docker >/dev/null || { echo "needs docker"; exit 2; }
# Say where a command failed or a signal arrived (job logs need a token; annotations don't).
trap 'fail "line $LINENO: \`$BASH_COMMAND\` failed"' ERR
trap 'fail "terminated at line $LINENO (\`$BASH_COMMAND\`)"' TERM INT

# A local block list, served to both Technitium and TelltaleDNS.
mkdir -p "$E/www"
printf 'listed.example\nalso-allowed.example\n' > "$E/www/block.txt"
(cd "$E/www" && exec python3 -m http.server 28780 --bind 0.0.0.0 >/dev/null 2>&1) & LISTS=$!
HOST_IP=$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || true)
# Some Docker setups don't report the gateway: the docker0 address is the same thing.
[ -n "$HOST_IP" ] || HOST_IP=$(ip -4 -o addr show docker0 | awk '{print $4}' | cut -d/ -f1)
[ -n "$HOST_IP" ] || fail "can't find the Docker host address"
LIST_URL="http://$HOST_IP:28780/block.txt"

echo "== Technitium ($IMAGE)"
docker run -d --name tt-tech -e DNS_SERVER_ADMIN_PASSWORD=e2e-admin "$IMAGE" >/dev/null
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tt-tech)
U="http://$IP:5380"
for _ in $(seq 90); do curl -s -o /dev/null "$U/" && break; sleep 1; done
login=$(curl -s "$U/api/user/login?user=admin&pass=e2e-admin")
S=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("token",""))' "$login")
[ -n "$S" ] || fail "can't sign in to Technitium"
api() { # path, then key=value pairs (URL-encoded)
  local path=$1; shift
  local args=(-s -G "$U/api/$path" --data-urlencode "token=$S")
  for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  local out; out=$(curl "${args[@]}")
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if d.get("status")=="ok" else 1)' "$out" \
    || fail "Technitium /api/$path: $(echo "$out" | head -c 300)"
}
api settings/set forwarders=9.9.9.9,dns.quad9.net forwarderProtocol=Udp enableBlocking=true \
  blockingType=NxDomain "blockListUrls=$LIST_URL" dnssecValidation=true saveCache=true
api zones/create zone=home.arpa type=Primary
api zones/records/add domain=nas.home.arpa zone=home.arpa type=A ipAddress=192.168.1.10 ttl=3600
api zones/records/add domain=media.home.arpa zone=home.arpa type=CNAME cname=nas.home.arpa ttl=300
api zones/records/add domain=home.arpa zone=home.arpa type=MX preference=10 exchange=mail.home.arpa ttl=300
api zones/create zone=corp.example type=Forwarder protocol=Udp forwarder=10.0.0.53
api blocked/add domain=blocked.example
api allowed/add domain=also-allowed.example
# The app comes from Technitium's store over the internet. If the store doesn't answer, skip
# only the Advanced Blocking checks (with a warning) rather than fail on someone else's CDN.
APP=0
for _ in 1 2 3; do
  out=$(curl -s -G "$U/api/apps/downloadAndInstall" --data-urlencode "token=$S" \
    --data-urlencode "name=Advanced Blocking" \
    --data-urlencode "url=https://download.technitium.com/dns/apps/AdvancedBlockingApp-v11.2.1.zip")
  echo "$out" | grep -q '"status":"ok"' && { APP=1; break; }
  sleep 5
done
if [ "$APP" = 0 ]; then
  echo "warning: Technitium's app store didn't answer; skipping the Advanced Blocking checks"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::warning title=$(basename "$0")::Technitium's app store didn't answer; Advanced Blocking checks skipped"
fi
cat > "$E/ab.json" <<'EOF'
{"enableBlocking": true, "blockingAnswerTtl": 30, "blockListUrlUpdateIntervalHours": 24,
 "localEndPointGroupMap": {},
 "networkGroupMap": {"192.168.50.0/24": "kids", "0.0.0.0/0": "everyone", "[::]/0": "everyone"},
 "groups": [
  {"name": "everyone", "enableBlocking": true, "allowTxtBlockingReport": true, "blockAsNxDomain": true,
   "blockingAddresses": ["0.0.0.0", "::"], "allowed": [], "blocked": ["app-blocked.example"],
   "allowListUrls": [], "blockListUrls": [], "allowedRegex": [], "blockedRegex": ["^tracker[0-9]+\\."],
   "regexAllowListUrls": [], "regexBlockListUrls": [], "adblockListUrls": []},
  {"name": "kids", "enableBlocking": true, "allowTxtBlockingReport": true, "blockAsNxDomain": true,
   "blockingAddresses": ["0.0.0.0", "::"], "allowed": [], "blocked": ["games.example"],
   "allowListUrls": [], "blockListUrls": [], "allowedRegex": [], "blockedRegex": [],
   "regexAllowListUrls": [], "regexBlockListUrls": [], "adblockListUrls": []}
 ]}
EOF
if [ "$APP" = 1 ]; then
  out=$(curl -s "$U/api/apps/config/set?token=$S" --data-urlencode "name=Advanced Blocking" --data-urlencode "config@$E/ab.json")
  echo "$out" | grep -q '"status":"ok"' || fail "Advanced Blocking config: $(echo "$out" | head -c 300)"
fi
# (Technitium ships a "Default" scope for 192.168.1.0/24, so use another network.)
api dhcp/scopes/set name=lan startingAddress=10.77.0.100 endingAddress=10.77.0.200 \
  subnetMask=255.255.255.0 "reservedLeases=kids-tablet|aa-bb-cc-dd-ee-01|10.77.0.150|tablet"
# An API token, as a user would create one (Administration → Sessions).
tok=$(curl -s "$U/api/user/createToken?user=admin&pass=e2e-admin&tokenName=telltale-import")
TOKEN=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("token",""))' "$tok")
[ -n "$TOKEN" ] || fail "can't create an API token"

echo "== import"
TECHNITIUM_TOKEN=$TOKEN "$B" import technitium "$U" -o "$E/t.toml" 2> "$E/import.err" || fail "import failed"
grep -v '^  - ' "$E/import.err"
t="$E/t.toml"
wants=('url = "udp://9.9.9.9:53"' 'match_suffix = ["corp.example"]' 'url = "udp://10.0.0.53:53"'
  'name = "nas.home.arpa"' 'value = "10 mail.home.arpa"' "url = \"$LIST_URL\""
  'rules = ["blocked.example"]' 'rules = ["also-allowed.example"]' 'block_mode = "nxdomain"'
  'match = ["aa:bb:cc:dd:ee:01", "10.77.0.150"]' 'mode = "validate"' 'persist = true')
[ "$APP" = 1 ] && wants+=('rules = ["/^tracker[0-9]+\\./"]' 'name = "kids"' 'networks = ["192.168.50.0/24"]')
for want in "${wants[@]}"; do
  grep -qF -- "$want" "$t" || fail "the import lacks $want"
done
grep -q 'dns.quad9.net' "$E/import.err" || fail "the forwarder with no address isn't reported"
grep -q 'TOKEN\|token=' "$t" && fail "the token leaked into the output"

echo "== serve"
port=25971
cat > "$E/run.toml" <<EOF
[node]
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:$port"
[api]
listen = "127.0.0.1:26971"
[telemetry.metrics]
listen = "127.0.0.1:27971"
[dnssec]
mode = "off"
EOF
# The imported [dnssec] comes after ours: drop it so the test doesn't depend on the internet.
grep -v '^mode = "validate"' "$t" | sed '/^\[dnssec\]$/d' > "$E/t2.toml"
"$B" run -c "$E/run.toml" -c "$E/t2.toml" > "$E/serve.log" 2>&1 & P=$!
d() { dig +time=2 +tries=2 -p "$port" @127.0.0.1 "$@"; }
for _ in $(seq 100); do d +short nas.home.arpa A 2>/dev/null | grep -q 192.168.1.10 && break; sleep 0.2; done
[ "$(d +short nas.home.arpa A)" = 192.168.1.10 ] || fail "nas.home.arpa doesn't answer"
d media.home.arpa A | grep -q 'media.home.arpa.*300.*CNAME.*nas.home.arpa' || fail "media.home.arpa isn't a CNAME with TTL 300"
for _ in $(seq 60); do d listed.example A | grep -q 'EDE: 15' && break; sleep 0.5; done
names=(listed.example blocked.example)
[ "$APP" = 1 ] && names+=(app-blocked.example tracker7.example)
for n in "${names[@]}"; do
  out=$(d "$n" A)
  echo "$out" | grep -q 'EDE: 15' || fail "$n isn't blocked"
  echo "$out" | grep -q 'status: NXDOMAIN' || fail "$n: blocking mode isn't NXDOMAIN"
done
d also-allowed.example A | grep -q 'EDE: 15' && fail "an allowed name was blocked"
d games.example A | grep -q 'EDE: 15' && fail "a kids-only name blocked the default group"
echo PASS
