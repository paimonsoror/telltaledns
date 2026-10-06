#!/usr/bin/env bash
# REQ: OPS-001 (T7.6 AC) — install.sh's questions, without installing anything: answers fed on
# stdin with --interactive --config-only, and every resulting config passes `telltale config
# check`. Also: Enter at the first question gives the usual starter config, and without a
# terminal nothing is asked.
# Usage: deploy/systemd/guided-e2e.sh [path/to/telltale]   (default: target/debug/telltale)
set -euo pipefail
cd "$(dirname "$0")/../.."
B=${1:-target/debug/telltale}
E=$(mktemp -d)
trap 'rm -rf "$E"' EXIT
fail() {
  echo "FAIL: $*"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=guided-e2e::FAIL: $*"
  exit 1
}
n=0
# answers (one per line) → a config that must pass `config check`; prints the file name.
run() { # name answers
  local f="$E/$1.toml"
  printf '%b' "$2" | sh deploy/systemd/install.sh --interactive --config-only "$f" > "$E/$1.out" 2>&1 \
    || { cat "$E/$1.out"; fail "$1: install.sh exited non-zero"; }
  [ -f "$f" ] || { cat "$E/$1.out"; fail "$1: no config written"; }
  "$B" config check "$f" > "$E/$1.check" 2>&1 || { cat "$f" "$E/$1.check"; fail "$1: config check"; }
  n=$((n + 1))
  echo "$f"
}

# Enter at the first question: the usual starter config.
f=$(run defaults '\n')
cmp -s "$f" deploy/compose/telltale.toml || fail "Enter at the first question didn't give the starter config"

# The guided path. Answers in order: walk (2), builds, upstreams [+ address [+ TLS name]],
# lists, listen [+ address], resolved, admin [+ user, password, again], days, detail, confirm.
f=$(run guided-defaults '2\n\n\n\n\n\n\n\n\n\ny\n')
grep -q 'url = "tls://1.1.1.1:853"' "$f" && grep -q 'name = "hagezi-pro"' "$f" || { cat "$f"; fail "guided defaults"; }
for up in 1 2 3 4 5 6 7; do
  run "up-$up" "2\n1\n$up\n\n\n\n\n\n\ny\n" >/dev/null
done
f=$(run custom-tls '2\n2\n8\ntls://192.0.2.53\ndns.example.net\n0\n2\n192.0.2.10\nn\n1\n30\n2\ny\n')
grep -q 'tls_server_name = "dns.example.net"' "$f" || { cat "$f"; fail "custom TLS upstream"; }
grep -q 'addr = "192.0.2.10:53"' "$f" || { cat "$f"; fail "listen address"; }
grep -q '\[\[list\]\]' "$f" && fail "lists were written for 'none'"
grep -q 'privacy_level = 2' "$f" && grep -q 'retention_days = 30' "$f" || { cat "$f"; fail "query log"; }
f=$(run custom-plain '2\n\n8\n192.168.1.1\n1 2 3 4 5 6\n\n\n\n\n\ny\n')
grep -q 'url = "udp://192.168.1.1"' "$f" || { cat "$f"; fail "plain custom upstream"; }
[ "$(grep -c '^\[\[list\]\]' "$f")" = 6 ] || { cat "$f"; fail "six lists"; }
f=$(run ipv6-listen '2\n\n\n\n2\n2001:db8::53\n\n\n\n3\ny\n')
grep -q 'addr = "\[2001:db8::53\]:53"' "$f" || { cat "$f"; fail "IPv6 listen address"; }
# An admin made now: the config is the same; the summary names the user.
run admin-now '2\n\n\n\n\n\n2\nalice\ncorrect-horse-battery\ncorrect-horse-battery\n\n\ny\n' >/dev/null
grep -q 'First admin: alice (created now)' "$E/admin-now.out" || { cat "$E/admin-now.out"; fail "admin summary"; }
# Wrong answers are asked again, then fall back to the default.
f=$(run retries '2\nx\n9\n\nzz\n1\n\n\n\nabc\n\n\ny\n')
grep -q 'name = "hagezi-pro"' "$f" || { cat "$f"; fail "retries"; }

# "No" at the summary installs nothing.
printf '2\n\n\n\n\n\n\n\n\nn\n' | sh deploy/systemd/install.sh --interactive --config-only "$E/no.toml" > "$E/no.out" 2>&1
[ -f "$E/no.toml" ] && fail "a config was written after 'no'"
grep -q 'Nothing was installed' "$E/no.out" || fail "no 'Nothing was installed'"

# Without a terminal (piped or automated) nothing is asked: the starter config.
sh deploy/systemd/install.sh --config-only "$E/piped.toml" < /dev/null > "$E/piped.out" 2>&1
grep -q 'Which' "$E/piped.out" && fail "asked a question without a terminal"
cmp -s "$E/piped.toml" deploy/compose/telltale.toml || fail "the piped install's config isn't the starter"
printf '2\n' | sh deploy/systemd/install.sh --yes --config-only "$E/yes.toml" > "$E/yes.out" 2>&1
grep -q 'Which' "$E/yes.out" && fail "--yes asked a question"
echo "PASS ($(find "$E" -name '*.check' | wc -l) configs checked)"
