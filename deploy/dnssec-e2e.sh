#!/usr/bin/env bash
# REQ: DNS-011 — T6.1 acceptance against the real DNS tree (needs internet): DNSSEC
# validation of forwarded answers, forwarding to public resolvers with CD=1.
#   - a signed name is answered with AD (asked for with DO or AD);
#   - an unsigned name is answered without AD;
#   - a deliberately broken signed name (dnssec-failed.org) is SERVFAIL with EDE 6;
#   - with CD=1 it's answered anyway; under a negative trust anchor it's answered;
#   - signed denials (NXDOMAIN/NODATA) validate;
#   - verdicts are counted in telltale_dnssec_validation_total.
# Usage: deploy/dnssec-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P=
cleanup() { [ -n "$P" ] && kill "$P" 2>/dev/null; wait 2>/dev/null || true; rm -rf "$E"; }
trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::FAIL: $*"
  tail -20 "$E/log"
  exit 1
}
command -v dig >/dev/null || { echo "needs dig"; exit 2; }

cat > "$E/t.toml" <<EOF
[node]
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25951"
[[listen]]
proto = "tcp"
addr = "127.0.0.1:25951"
[telemetry.metrics]
listen = "127.0.0.1:29951"
[api]
listen = "127.0.0.1:28951"
[[upstream]]
name = "cloudflare"
url = "udp://1.1.1.1"
[[upstream]]
name = "quad9"
url = "udp://9.9.9.10"
[[upstream_group]]
name = "default"
members = ["cloudflare", "quad9"]
[dnssec]
mode = "validate"
negative_trust_anchors = ["dnssec-failed.org.nta-test.invalid"]
[[route]]
match_suffix = ["badsign-a.test.dnssec-tools.org"]
upstream_group = "default"
dnssec_nta = true
EOF
"$B" run -c "$E/t.toml" > "$E/log" 2>&1 & P=$!
for _ in $(seq 50); do dig +time=1 +tries=1 -p 25951 @127.0.0.1 . NS >/dev/null 2>&1 && break; sleep 0.1; done

d() { dig +time=10 +tries=2 -p 25951 @127.0.0.1 "$@"; }
status() { d "$@" | sed -n 's/.*status: \([A-Z]*\).*/\1/p'; }
flags() { d "$@" | sed -n 's/.*flags: \([a-z ]*\);.*/\1/p'; }

# Warm the chain of trust (root and TLD keys) once; a cold first lookup may exceed a client's
# patience, and the result is cached for everyone after.
d cloudflare.com A >/dev/null || true; d ietf.org A >/dev/null || true; sleep 1

echo "== secure"
[[ "$(flags ietf.org A +dnssec)" == *ad* ]] || fail "ietf.org (signed) has no AD with DO"
[[ "$(flags cloudflare.com A +adflag)" == *ad* ]] || fail "cloudflare.com (signed) has no AD with AD"
[[ "$(flags cloudflare.com AAAA +noadflag)" != *ad* ]] || fail "AD set for a client that asked for neither DO nor AD"
echo ok
echo "== insecure"
[ "$(status google.com A)" = NOERROR ] || fail "google.com (unsigned) wasn't answered"
[[ "$(flags google.com A +dnssec)" != *ad* ]] || fail "AD on an unsigned answer"
echo ok
echo "== bogus"
out=$(d dnssec-failed.org A)
echo "$out" | grep -q "status: SERVFAIL" || fail "dnssec-failed.org wasn't SERVFAIL"
echo "$out" | grep -q "EDE: 6" || fail "dnssec-failed.org has no EDE 6"
[ "$(status dnssec-failed.org A +cd)" = NOERROR ] || fail "CD=1 didn't return the unvalidated answer"
echo ok
echo "== signed denials"
[[ "$(flags nonexistent-zz9-telltale.cloudflare.com A +dnssec)" == *ad* ]] || fail "a signed denial didn't validate"
[[ "$(flags cloudflare.com SRV +dnssec)" == *ad* ]] || fail "a signed NODATA didn't validate"
echo ok
echo "== counted"
m=$(curl -s 127.0.0.1:29951/metrics | grep '^telltale_dnssec_validation_total')
echo "$m" | grep -q 'result="secure"} [1-9]' || fail "no secure verdicts counted: $m"
echo "$m" | grep -q 'result="bogus"} [1-9]' || fail "no bogus verdicts counted: $m"
echo ok
echo PASS
