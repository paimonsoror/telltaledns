#!/usr/bin/env bash
# REQ: OPS-001 (T7.6 AC) — install.sh's questions, without installing anything: answers fed on
# stdin with --interactive --config-only, and every resulting config passes `telltale config
# check`. Also: Enter at the first question gives the usual starter config, and without a
# terminal nothing is asked. Ends with portwait-test.sh (the wait for port 53, OPS-004).
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
# answers (one per line) → a config that must pass `config check`; prints the file name. It runs
# inside `$(...)`, so what a failure prints goes to stderr: on stdout it would be swallowed into the
# caller's variable, and the step would end with no FAIL line.
run() { # name answers
  local f="$E/$1.toml"
  printf '%b' "$2" | sh deploy/systemd/install.sh --interactive --config-only "$f" > "$E/$1.out" 2>&1 \
    || { cat "$E/$1.out"; fail "$1: install.sh exited non-zero"; } >&2
  [ -f "$f" ] || { cat "$E/$1.out"; fail "$1: no config written"; } >&2
  "$B" config check "$f" > "$E/$1.check" 2>&1 || { cat "$f" "$E/$1.check"; fail "$1: config check"; } >&2
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

# REQ: OPS-004 — a zero-padded answer is the number it spells. `[ -le ]` reads `08` as 8, but the
# answers go on as text: `08` matched no upstream and ended the install after the binary was in
# place, `030` days wrote `retention_days = 030` and `03` or `00` wrote `privacy_level = 03` (not
# valid TOML: the installed config failed `config check` and a re-run didn't ask again), and `02`
# at the first question quietly meant "the recommended settings".
# A run's answers, in order after the first (walk) one: builds, upstream [+ address], lists, listen,
# resolved, admin, days, detail, confirm. Each padded answer is a number that is NOT the default
# (02, 08, 030, 03; the default of the zero cases is 0 itself), and the run must not have asked
# again: a reply that was refused and then fell back to the default would otherwise pass for
# "read as the number".
first_time() { # run-name: no question was asked a second time
  ! grep -q 'Please type' "$E/$1.out" || { cat "$E/$1.out"; fail "ops_004_zero_padded_answers: $1: an answer was refused and asked again"; }
}
f=$(run padded-walk '02\n02\n\n\n\n\n\n\n\ny\n')                 # the walk-through, and edge builds
grep -q 'written by install.sh (guided setup)' "$f" || { cat "$f"; fail "ops_004_zero_padded_answers: 02 at the first question didn't start the walk-through"; }
grep -q 'Builds:      edge' "$E/padded-walk.out" || { cat "$E/padded-walk.out"; fail "ops_004_zero_padded_answers: 02 at the builds question isn't edge"; }
first_time padded-walk
f=$(run padded-upstream '2\n\n08\n192.168.1.1\n\n\n\n\n\n\ny\n')   # your own upstream
grep -q 'url = "udp://192.168.1.1"' "$f" && grep -q 'name = "mine"' "$f" || { cat "$f"; fail "ops_004_zero_padded_answers: 08 isn't your own upstream"; }
first_time padded-upstream
f=$(run padded-days '2\n\n\n\n\n\n\n030\n\ny\n')                  # 30 days (the default is 7)
grep -qx 'retention_days = 30' "$f" || { cat "$f"; fail "ops_004_zero_padded_answers: 030 days isn't 30"; }
first_time padded-days
f=$(run padded-privacy-3 '2\n\n\n\n\n\n\n\n03\ny\n')              # privacy level 3
grep -qx 'privacy_level = 3' "$f" || { cat "$f"; fail "ops_004_zero_padded_answers: 03 isn't privacy level 3"; }
first_time padded-privacy-3
for zeros in 00 000; do                                          # level 0 (everything): nothing is written for it
  f=$(run "padded-privacy-$zeros" "2\n\n\n\n\n\n\n\n$zeros\ny\n")
  { grep -q 'written by install.sh (guided setup)' "$f" && ! grep -q 'privacy_level' "$f"; } \
    || { cat "$f"; fail "ops_004_zero_padded_answers: $zeros isn't privacy level 0"; }
  first_time "padded-privacy-$zeros"                             # 0 is the default too: only "no second asking" shows it was read
done
echo "ok ops_004_zero_padded_answers_are_the_number_they_spell"

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

# REQ: OPS-004 — the installer's wait for port 53 (after it turns the resolver's stub off, before it
# starts the service) and its single start, against a fake `ss`; nothing on this machine changes.
bash deploy/systemd/portwait-test.sh "$B" > "$E/portwait.out" 2>&1 || { cat "$E/portwait.out"; fail "portwait-test.sh"; }
cat "$E/portwait.out"
echo "PASS ($(find "$E" -name '*.check' | wc -l) configs checked)"
