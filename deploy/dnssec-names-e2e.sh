#!/usr/bin/env bash
# REQ: DNS-011 — names from public reports through the validator, against the real DNS tree
# (needs internet): forwarding to public resolvers with CD=1 in `validate` mode.
#   - dns.nextdns.io A and AAAA (issue #115): NOERROR, at least one address, no AD (its CNAME
#     chain ends in an unsigned zone);
#   - www.nasa.gov A, c.pki.goog A, www.netflix.com A: NOERROR with at least one address;
#   - www.paypal.com AAAA: NOERROR (status only: its CNAME chain can end without an AAAA record);
#   - controls: ietf.org A is answered with an address and AD; dnssec-failed.org A is SERVFAIL
#     with EDE 6.
# Each check gets two tries at once, and either one matching counts: that absorbs a slow first
# answer (dig gives up after 10 s while the node finishes the lookup and caches it). The checks
# that still fail are run once more 61 s later: that absorbs a failure inside a proof (an
# upstream that didn't answer while the chain was checked), which the node remembers for a
# minute. The wait costs nothing while every check passes. A check that passes only on that
# second pass is reported as such (in the summary, and as a warning on GitHub): it doesn't fail
# the run. The first try's time is printed for the trend: informational, it never fails the run.
# These are third-party zones and they change. A red run means "re-check the name" (what it
# answers today at a public validating resolver), not "the resolver broke".
# Usage: deploy/dnssec-names-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -uo pipefail
B=${1:-target/debug/telltale}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
E=$(mktemp -d)
P=
cleanup() { [ -n "$P" ] && kill "$P" 2>/dev/null; wait 2>/dev/null; rm -rf "$E"; }
trap cleanup EXIT
command -v dig >/dev/null || { echo "needs dig"; exit 2; }

cat > "$E/t.toml" <<EOF
[node]
data_dir = "$E/data"
[[listen]]
proto = "udp"
addr = "127.0.0.1:25952"
[[listen]]
proto = "tcp"
addr = "127.0.0.1:25952"
[telemetry.metrics]
listen = "127.0.0.1:29952"
[api]
listen = "127.0.0.1:28952"
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
EOF
"$B" run -c "$E/t.toml" > "$E/log" 2>&1 & P=$!
up=
for _ in $(seq 100); do
  dig +time=1 +tries=1 -p 25952 @127.0.0.1 . NS >/dev/null 2>&1 && { up=1; break; }
  sleep 0.1
done
[ -n "$up" ] || { echo "FAIL: the node didn't answer"; tail -20 "$E/log"; exit 1; }

d() { dig +time=10 +tries=1 -p 25952 @127.0.0.1 "$@"; }

# Warm the shared part of the chain of trust (the root's and each TLD's keys) without asking
# for a checked name, so a name's first try times that name's own lookup.
for z in org. com. io. gov. goog.; do d "$z" SOA +dnssec >/dev/null 2>&1; done

# judge OUTPUT TYPE STATUS [ad|noad|addr|ede6]...: prints the first expectation the dig output
# doesn't meet, or an expectation it doesn't know; nothing when every one is met.
judge() {
  local out=$1 type=$2 want=$3 st fl e
  shift 3
  st=$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<<"$out")
  [ -n "$st" ] || { echo "no answer"; return 0; }
  [ "$st" = "$want" ] || { echo "status $st, expected $want"; return 0; }
  fl=$(sed -n 's/^;; flags: \([a-z ]*\);.*/\1/p' <<<"$out")
  for e in "$@"; do
    case $e in
      ad) [[ " $fl " == *" ad "* ]] || { echo "no AD (flags: $fl)"; return 0; } ;;
      noad) [[ " $fl " != *" ad "* ]] || { echo "AD set (flags: $fl)"; return 0; } ;;
      addr)
        grep -Eq "[[:space:]]IN[[:space:]]+$type[[:space:]]" \
          <<<"$(awk '/^;; ANSWER SECTION:/{f=1;next} f&&/^$/{exit} f' <<<"$out")" \
          || { echo "no $type record in the answer"; return 0; } ;;
      ede6) grep -q 'EDE: 6' <<<"$out" || { echo "no EDE 6 ($(grep -o -m1 'EDE: [0-9]*' <<<"$out"))"; return 0; } ;;
      *) echo "unknown expectation $e"; return 0 ;;
    esac
  done
  return 0
}

pass=1
order=()
declare -A first=() result=()
failed=()
# check NAME TYPE STATUS [EXPECTATION]...: two tries at once (DO set, so AD shows when it's
# earned). The first pass keeps the first try's time; a check that fails goes in `failed` (its
# arguments) for the pass after it.
check() {
  local name=$1 type=$2 key=$1/$2 out why t n
  shift 2
  for n in 1 2; do
    out=$(d "$name" "$type" +dnssec 2>&1)
    if [ "$n" = 1 ] && [ "$pass" = 1 ]; then
      t=$(sed -n 's/^;; Query time: \([0-9]*\) msec.*/\1/p' <<<"$out")
      first[$key]=${t:-timeout}
      order+=("$key")
    fi
    why=$(judge "$out" "$type" "$@")
    [ -z "$why" ] && break
  done
  if [ -z "$why" ] && [ "$pass" = 1 ]; then
    result[$key]=ok
    printf 'ok    %-20s %-5s first try: %s ms\n' "$name" "$type" "${first[$key]}"
  elif [ -z "$why" ]; then
    # Passed only on the second pass: kept visible, as a failure shorter than a minute that comes
    # back every night would otherwise go unseen.
    result[$key]="ok (second pass)"
    printf 'ok    %-20s %-5s first try: %s ms, on the second pass\n' "$name" "$type" "${first[$key]}"
    [ -n "${GITHUB_ACTIONS:-}" ] && echo "::warning title=$(basename "$0")::$name $type passed only on the second pass"
  else
    result[$key]="FAIL: $why"
    failed+=("$name $type $*")
    printf 'FAIL  %-20s %-5s %s (first try: %s ms)\n' "$name" "$type" "$why" "${first[$key]}"
    # What the node answered on the last try: its status, its flags, any EDE (or no answer).
    grep -E 'status:|^;; flags:|EDE:|timed out|no servers' <<<"$out" | sed 's/^/        /'
  fi
  return 0
}

echo "== controls"
check ietf.org A NOERROR addr ad
check dnssec-failed.org A SERVFAIL ede6
echo "== names from public reports"
check dns.nextdns.io A NOERROR addr noad
check dns.nextdns.io AAAA NOERROR addr noad
check www.paypal.com AAAA NOERROR
check www.nasa.gov A NOERROR addr
check c.pki.goog A NOERROR addr
check www.netflix.com A NOERROR addr

if [ "${#failed[@]}" -gt 0 ]; then
  again=("${failed[@]}")
  failed=()
  pass=2
  echo "== ${#again[@]} check(s) failed: once more in 61 s (the node remembers a failure inside a proof for a minute)"
  sleep 61
  for c in "${again[@]}"; do
    read -r -a args <<<"$c"
    check "${args[@]}"
  done
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## DNSSEC live names"
    echo
    echo "| name | type | result | first try (ms) |"
    echo "|---|---|---|---|"
    for key in "${order[@]}"; do
      echo "| ${key%/*} | ${key#*/} | ${result[$key]} | ${first[$key]} |"
    done
  } >> "$GITHUB_STEP_SUMMARY"
fi
if [ "${#failed[@]}" -gt 0 ]; then
  echo "FAIL: ${#failed[@]} check(s) didn't match, in either pass:"
  for c in "${failed[@]}"; do
    read -r name type _ <<<"$c"
    why=${result[$name/$type]#FAIL: }
    echo "  $name $type: $why"
    [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$(basename "$0")::$name $type: $why (a third-party zone: re-check the name)"
  done
  echo "These are third-party zones: re-check what each name answers today at a public validating resolver."
  tail -20 "$E/log"
  exit 1
fi
echo PASS
