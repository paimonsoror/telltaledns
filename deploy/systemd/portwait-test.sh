#!/usr/bin/env bash
# REQ: OPS-004 — install.sh waits (bounded) for port 53 to be free after it turns systemd-resolved's
# stub listener off, says what holds the port when it isn't, and starts the service once.
# No root, nothing is installed and nothing on the machine changes: the wait functions are cut out
# of install.sh (the `port53-wait` block) and run under `sh` against a fake `ss` and a fake
# `telltale`, so every case is deterministic and the sockets of the machine don't matter.
# Usage: deploy/systemd/portwait-test.sh [path/to/telltale]
#   With the real binary it also checks the effective-config format that install.sh reads to know
#   which addresses TelltaleDNS will bind (`telltale config check FILE --no-env --print`).
# The same way it also runs two blocks cut out of other scripts: the failure report of
# deploy/systemd/e2e.sh (it must say who held port 53 and never hang), and the epoch reads of
# deploy/cluster/gitops-failover-e2e.sh (REQ: CLU-005; they must not end that script silently).
# Section 7e runs the rest of install.sh after the block (the call sites) with every system path
# moved into a temp tree and a fake `systemctl`, to see that the wait comes after the resolver's stub
# was turned off and before the one start, and nowhere else. It is skipped when run as root.
# A fake tool on PATH does not bind a busybox shell (PORTWAIT_TEST_SH=busybox ash): it runs its own
# applet for awk, sed, sleep, hostname, grep and the like without looking at PATH. What must hold
# under busybox is therefore a shell function (the awk failures) or a tool busybox doesn't have
# (ss, systemctl, telltale); a fake `sleep` or `hostname` is only a speed-up.
set -euo pipefail
cd "$(dirname "$0")/../.."
INSTALL=deploy/systemd/install.sh
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
# The load average goes into every failure: the checks of how long something took are the ones a
# stalled or busy machine can fail, and the number says whether it was.
fail() {
  local load=
  [ ! -r /proc/loadavg ] || load=" [load average: $(cut -d' ' -f1-3 /proc/loadavg)]"
  echo "FAIL: $*$load"
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=portwait-test::FAIL: $*$load"
  exit 1
}
n=0
ok() { n=$((n + 1)); echo "ok $1"; }

SH=${PORTWAIT_TEST_SH:-$(command -v sh)}   # the shell that runs install.sh's functions (try busybox ash: PORTWAIT_TEST_SH=/path/to/sh)
FAKE="$T/fake"
FAKEBIN="$T/fakebin"
FAKEROOT="$T/root"
mkdir -p "$FAKE" "$FAKEBIN" "$FAKEROOT/bin"

# ---- the fakes ---------------------------------------------------------------------------------
# ss: a "check" is one `ss -Hlun[p]` plus one `ss -Hltn[p]`. The first $FAKE/busy_checks checks find
# the port held ("always": every check); later ones find it free, or show what the
# `*_holder_after` files hold if there are any. The holder files carry the `users:(...)` column as
# `ss -p` prints it; it is left off unless `p` was asked for. `ss -Hlunpt` is the report with
# process names. $FAKE/ss_fails makes it refuse like an old `ss` that doesn't know -H; $FAKE/ss_delay
# is a number of seconds every look takes (`ss -p` walks every process's descriptors, which costs
# time on a busy machine). Every call is added to $FAKE/calls.
cat > "$FAKEBIN/ss" <<'EOF'
#!/bin/sh
echo "ss $*" >> "$FAKE/calls"
case "$*" in *-Hlunpt*) cat "$FAKE/who"; exit 0 ;; esac
if [ -f "$FAKE/ss_fails" ]; then echo "ss: invalid option -- 'H'" >&2; exit 1; fi
[ ! -f "$FAKE/ss_delay" ] || sleep "$(cat "$FAKE/ss_delay")"
case "$*" in
  *-Hlun*) c=$(cat "$FAKE/checks" 2>/dev/null || echo 0); c=$((c + 1)); echo "$c" > "$FAKE/checks"; held=udp_holder ;;
  *-Hltn*) c=$(cat "$FAKE/checks"); held=tcp_holder ;;
  *) exit 1 ;;
esac
busy=$(cat "$FAKE/busy_checks")
if [ "$busy" = always ] || [ "$c" -le "$busy" ]; then f="$FAKE/$held"; else f="$FAKE/${held}_after"; fi
[ -f "$f" ] || exit 0
case "$*" in
  *-Hlunp*|*-Hltnp*) cat "$f" ;;
  *) sed 's/ users:.*$//' "$f" ;;
esac
exit 0
EOF
# systemctl: only `show -p MainPID telltale`: the pid in $FAKE/mainpid (0: not running), or the pid
# in $FAKE/mainpid_after once the first look at the sockets has been made (the service restarted
# during the wait), or a failure.
cat > "$FAKEBIN/systemctl" <<'EOF'
#!/bin/sh
[ -f "$FAKE/systemctl_fails" ] && exit 1
[ "$*" = "show -p MainPID telltale" ] || exit 2
c=$(cat "$FAKE/checks" 2>/dev/null || echo 0)
if [ -f "$FAKE/mainpid_after" ] && [ "$c" -ge 1 ]; then echo "MainPID=$(cat "$FAKE/mainpid_after")"; else echo "MainPID=$(cat "$FAKE/mainpid")"; fi
EOF
# telltale: `config check FILE --no-env --print`, which prints the canned effective config, and
# `health` (fails when $FAKE/health_fails exists).
cat > "$FAKEROOT/bin/telltale" <<'EOF'
#!/bin/sh
if [ "$1" = health ]; then [ ! -f "$FAKE/health_fails" ]; exit; fi
[ "$1 $2" = "config check" ] || exit 2
[ "$4 $5" = "--no-env --print" ] || exit 2
[ -f "$FAKE/config_fails" ] && exit 1
cat "$FAKE/config.printed"
EOF
chmod +x "$FAKEBIN/ss" "$FAKEBIN/systemctl" "$FAKEROOT/bin/telltale"
# awk: the real one, unless $FAKE/awk_fails (every call fails) or $FAKE/awk_binds_fails (only the
# program that reads the config's listeners, which counts `blocks`, fails). A shell function, sourced
# before the block, rather than a program on PATH: a function comes first in any POSIX shell, and a
# busybox shell runs its own `awk` applet without looking at PATH.
cat > "$T/awkwrap.sh" <<'EOF'
awk() {
  [ ! -f "$FAKE/awk_fails" ] || return 2
  if [ -f "$FAKE/awk_binds_fails" ]; then case "$*" in *blocks*) return 2 ;; esac; fi
  command awk "$@"
}
EOF

# A tool directory without `ss`, for the machine that doesn't have it.
NOSS="$T/noss"
mkdir -p "$NOSS"
for tool in awk tr sleep cat sed date; do ln -s "$(command -v "$tool")" "$NOSS/$tool"; done
# A hung install.sh function fails the test instead of the job: that needs coreutils' `timeout`.
TIMEOUT=$(command -v timeout) || fail "ops_004_test_setup: \`timeout\` isn't installed (coreutils), and the test can't guard install.sh's functions against a hang without it"

DEFAULT_CONFIG='config_version = 1

[[listen]]
proto = "udp"
addr = "0.0.0.0:53"
proxy_protocol = false

[[listen]]
proto = "tcp"
addr = "0.0.0.0:53"
proxy_protocol = false

[[listen]]
proto = "udp"
addr = "[::]:53"
proxy_protocol = false

[[listen]]
proto = "tcp"
addr = "[::]:53"
proxy_protocol = false

[api]
listen = "0.0.0.0:8053"
'
STUB_UDP='UNCONN 0      0       127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=612,fd=13))'
STUB_TCP='LISTEN 0      4096    127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=612,fd=14))'
STUB_WHO='udp UNCONN 0      0       127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=612,fd=13))
tcp LISTEN 0      4096    127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=612,fd=14))'

# fixture BUSY [CONFIG [UDP_LINE TCP_LINE WHO [MAINPID]]]: resets the fakes for one case. MAINPID is
# the pid systemd reports for the telltale service (default 0: the service isn't running).
fixture() {
  rm -f "$FAKE"/checks "$FAKE"/ss_fails "$FAKE"/config_fails "$FAKE"/systemctl_fails "$FAKE"/udp_holder_after "$FAKE"/tcp_holder_after \
    "$FAKE"/ss_delay "$FAKE"/awk_fails "$FAKE"/awk_binds_fails "$FAKE"/mainpid_after "$FAKE"/health_fails "$FAKE"/resolved_inactive "$FAKE"/calls
  printf '%s\n' "$1" > "$FAKE/busy_checks"
  printf '%s\n' "${2-$DEFAULT_CONFIG}" > "$FAKE/config.printed"
  printf '%s\n' "${3-$STUB_UDP}" > "$FAKE/udp_holder"
  printf '%s\n' "${4-$STUB_TCP}" > "$FAKE/tcp_holder"
  printf '%s\n' "${5-$STUB_WHO}" > "$FAKE/who"
  printf '%s\n' "${6-0}" > "$FAKE/mainpid"
  echo "# the installed config (the fake binary ignores it)" > "$T/telltale.toml"
}
checks() { cat "$FAKE/checks" 2>/dev/null || echo 0; }
# Milliseconds on a clock that never steps (/proc/uptime, centiseconds), so a time sync in the
# middle of a case can't fail a timing bound; the wall clock where there is no /proc/uptime.
now_ms() {
  local up
  if read -r up _ 2>/dev/null < /proc/uptime; then
    echo $((10#${up%.*} * 1000 + 10#${up#*.} * 10))
  else
    echo $(($(date +%s%N) / 1000000))
  fi
}
t0=$(now_ms); sleep 0.3; t1=$(now_ms)
{ [ $((t1 - t0)) -ge 250 ] && [ $((t1 - t0)) -lt 3000 ]; } || fail "ops_004_test_clock: now_ms measured $((t1 - t0)) ms for a 0.3 s sleep"

# run_wait [WAIT_SECONDS] [PATH]: runs wait_for_port53 the way install.sh does (POSIX sh, set -eu);
# sets RC, OUT and MS (milliseconds it took).
run_wait() {
  local start end
  start=$(now_ms)
  set +e
  OUT=$(PATH="${2:-$FAKEBIN:$PATH}" FAKE="$FAKE" PREFIX="$FAKEROOT" TELLTALE_PORT_WAIT="${1:-}" \
    "$TIMEOUT" 90 "$SH" -c 'set -eu; say() { printf "==> %s\n" "$*"; }; . "$3"; . "$1"; wait_for_port53 "$2"' sh "$T/lib.sh" "$T/telltale.toml" "$T/awkwrap.sh" 2>&1)
  RC=$?
  set -e
  end=$(now_ms)
  MS=$((end - start))
}
has() { printf '%s\n' "$OUT" | grep -qF -- "$1"; }

# ---- the wait functions come out of install.sh -------------------------------------------------
sed -n '/^# BEGIN port53-wait/,/^# END port53-wait/p' "$INSTALL" > "$T/lib.sh"
[ -s "$T/lib.sh" ] || fail "ops_004_port53_wait: $INSTALL has no port53-wait block (the wait for port 53)"
grep -q '^# END port53-wait' "$T/lib.sh" || fail "ops_004_port53_wait: the port53-wait block in $INSTALL has no END marker"
"$SH" -n "$T/lib.sh" || fail "ops_004_port53_wait: the block isn't valid sh"

# ---- 1. free at once: nothing to say, no waiting -----------------------------------------------
fixture 0
run_wait
[ "$RC" = 0 ] || fail "ops_004_port53_free_at_once: rc=$RC: $OUT"
[ -z "$OUT" ] || fail "ops_004_port53_free_at_once: said something on a free port: $OUT"
[ "$(checks)" = 1 ] || fail "ops_004_port53_free_at_once: $(checks) checks, not 1"
[ "$MS" -lt 2000 ] || fail "ops_004_port53_free_at_once: took $MS ms"
ok ops_004_port53_free_at_once
# The default config binds each address twice (UDP and TCP): it is named once.
got=$(FAKE="$FAKE" PREFIX="$FAKEROOT" "$SH" -c 'set -eu; . "$1"; port53_binds "$2"' sh "$T/lib.sh" "$T/telltale.toml" | tr '\n' ' ')
[ "$got" = "0.0.0.0 :: " ] || fail "ops_004_port53_binds_each_address_once: got '$got'"
ok ops_004_port53_binds_each_address_once

# ---- 2. held for the first 3 checks, then free: waits for it, no longer ------------------------
fixture 3
run_wait
[ "$RC" = 0 ] || fail "ops_004_port53_wait_ends_when_free: rc=$RC: $OUT"
[ "$(checks)" = 4 ] || fail "ops_004_port53_wait_ends_when_free: $(checks) checks, expected 4 (3 held + 1 free): $OUT"
[ "$MS" -ge 700 ] || fail "ops_004_port53_wait_ends_when_free: returned after $MS ms, before three polling intervals"
has "Waiting" || fail "ops_004_port53_wait_ends_when_free: no 'Waiting' line: $OUT"
has "Port 53 is free" || fail "ops_004_port53_wait_ends_when_free: no 'free' line: $OUT"
ok ops_004_port53_wait_ends_when_free

# ---- 3. never freed: bounded by the limit, names the holder and the next step, fails (rc 1) ----
fixture always
run_wait 2
[ "$RC" = 1 ] || fail "ops_004_port53_wait_is_bounded: rc=$RC, expected 1: $OUT"
[ "$MS" -ge 1900 ] || fail "ops_004_port53_wait_is_bounded: gave up after $MS ms, before the 2 s limit"
[ "$(checks)" -le 9 ] || fail "ops_004_port53_wait_is_bounded: $(checks) looks for a 2 s limit (the first and at most 8 polls); it took $MS ms"
has "still held after 2s" || fail "ops_004_port53_wait_is_bounded: no 'still held' line: $OUT"
has 'systemd-resolve' || fail "ops_004_port53_wait_is_bounded: the holder's process isn't named: $OUT"
has "sudo systemctl restart telltale" || fail "ops_004_port53_wait_is_bounded: no next step: $OUT"
ok ops_004_port53_wait_is_bounded

# ---- 4. a bad limit falls back to the default (15 s); the wait still ends when the port frees --
fixture 1
run_wait abc
[ "$RC" = 0 ] && has "up to 15s" || fail "ops_004_port53_wait_default_limit: rc=$RC: $OUT"
ok ops_004_port53_wait_default_limit
# The limit is plain decimal seconds, 0 to 300. A leading zero is decimal (`08` once ended the
# install through an octal arithmetic error, after the resolver had been turned off); anything
# else gets the default and one line saying so.
for pair in 08:8 09:9 010:10 0015:15 007:7 300:300 0300:300; do
  fixture 1
  run_wait "${pair%%:*}"
  { [ "$RC" = 0 ] && has "up to ${pair##*:}s" && ! has "isn't a whole number"; } \
    || fail "ops_004_port53_wait_limit_is_decimal: TELLTALE_PORT_WAIT=${pair%%:*}: rc=$RC: $OUT"
done
ok ops_004_port53_wait_limit_is_decimal
for junk in abc 1.5 -3 301 1000 99999999999999999999 ' 5' '5 ' 0x10; do
  fixture 1
  run_wait "$junk"
  { [ "$RC" = 0 ] && has "up to 15s" && [ "$(printf '%s\n' "$OUT" | grep -c "isn't a whole number")" = 1 ]; } \
    || fail "ops_004_port53_wait_limit_junk_gets_the_default: TELLTALE_PORT_WAIT='$junk': rc=$RC: $OUT"
done
ok ops_004_port53_wait_limit_junk_gets_the_default
# 0 means don't wait: it still says what holds the port, at once.
fixture always
run_wait 0
{ [ "$RC" = 1 ] && [ "$MS" -lt 2000 ] && has "still held after 0s" && ! has "Waiting up to"; } \
  || fail "ops_004_port53_wait_limit_zero: rc=$RC ms=$MS: $OUT"
ok ops_004_port53_wait_limit_zero

# ---- 5. no `ss` on the machine: one line, no waiting, no failure -------------------------------
fixture always
run_wait "" "$NOSS"
[ "$RC" = 0 ] || fail "ops_004_port53_wait_without_ss: rc=$RC: $OUT"
has "not checking that port 53 is free" || fail "ops_004_port53_wait_without_ss: no explanation: $OUT"
[ "$(checks)" = 0 ] || fail "ops_004_port53_wait_without_ss: ss was called"
[ "$(printf '%s\n' "$OUT" | wc -l)" = 1 ] || fail "ops_004_port53_wait_without_ss: more than one line: $OUT"
ok ops_004_port53_wait_without_ss

# ---- 6. an `ss` that can't list (too old for -H): the same --------------------------------------
fixture always
touch "$FAKE/ss_fails"
run_wait
[ "$RC" = 0 ] || fail "ops_004_port53_wait_ss_cannot_list: rc=$RC: $OUT"
has "not checking that port 53 is free" || fail "ops_004_port53_wait_ss_cannot_list: no explanation: $OUT"
[ "$MS" -lt 2000 ] || fail "ops_004_port53_wait_ss_cannot_list: waited ($MS ms)"
ok ops_004_port53_wait_ss_cannot_list

# ---- 7. which addresses count: only the ones TelltaleDNS binds ---------------------------------
LAN_CONFIG='config_version = 1

[[listen]]
proto = "udp"
addr = "192.0.2.10:53"

[[listen]]
proto = "tcp"
addr = "192.0.2.10:53"

[[listen]]
proto = "dot"
addr = "0.0.0.0:853"

[listen.tls]
cert = "/c.pem"
key = "/k.pem"
'
# (a) the stub on 127.0.0.53 doesn't conflict with a listener on the LAN address alone.
fixture always "$LAN_CONFIG"
run_wait
[ "$RC" = 0 ] && [ -z "$OUT" ] && [ "$(checks)" = 1 ] || fail "ops_004_port53_wait_other_address: rc=$RC checks=$(checks): $OUT"
ok ops_004_port53_wait_other_address
# (b) a wildcard holder (dual-stack `*:53`) does.
fixture 1 "$LAN_CONFIG" 'UNCONN 0      0              *:53       *:*' 'LISTEN 0      4096       *:53       *:*'
run_wait
[ "$RC" = 0 ] && has "Waiting" && [ "$(checks)" = 2 ] || fail "ops_004_port53_wait_wildcard_holder: rc=$RC checks=$(checks): $OUT"
ok ops_004_port53_wait_wildcard_holder
# (c) the same address does (IPv6, with brackets).
V6_CONFIG='config_version = 1

[[listen]]
proto = "udp"
addr = "[2001:db8::53]:53"
'
fixture 1 "$V6_CONFIG" 'UNCONN 0      0   [2001:db8::53]:53    [::]:*' 'LISTEN 0      4096   [2001:db8::53]:53    [::]:*'
run_wait
[ "$RC" = 0 ] && has "Waiting" && [ "$(checks)" = 2 ] || fail "ops_004_port53_wait_same_address: rc=$RC checks=$(checks): $OUT"
ok ops_004_port53_wait_same_address
# (d) a config with no port-53 listener at all: say so, don't wait, don't even look.
fixture always 'config_version = 1

[[listen]]
proto = "udp"
addr = "127.0.0.1:5353"
'
run_wait
[ "$RC" = 0 ] && has "no listener on port 53" && [ "$(checks)" = 0 ] || fail "ops_004_port53_wait_not_port_53: rc=$RC checks=$(checks): $OUT"
ok ops_004_port53_wait_not_port_53
# (e) a config the binary can't print: assume every address (the default), so wait.
fixture 1
touch "$FAKE/config_fails"
run_wait
[ "$RC" = 0 ] && has "Waiting" && [ "$(checks)" = 2 ] || fail "ops_004_port53_wait_unreadable_config: rc=$RC checks=$(checks): $OUT"
ok ops_004_port53_wait_unreadable_config

# ---- 7b. TelltaleDNS's own sockets aren't a holder -----------------------------------------------
# A re-run in a terminal can turn the stub off for the first time while the service is already
# running (the stub was left on, with a LAN-only [[listen]]; or turned off in a spelling the
# installer doesn't look for). The old instance's sockets are what `restart` replaces: they must
# not make the install wait 15 s and warn that port 53 is "still held".
OWN_UDP='UNCONN 0      0       192.0.2.10:53 0.0.0.0:* users:(("telltale",pid=700,fd=7))'
OWN_TCP='LISTEN 0      4096    192.0.2.10:53 0.0.0.0:* users:(("telltale",pid=700,fd=8))'
OWN_WHO="udp $OWN_UDP
tcp $OWN_TCP"
# (f) the service itself holds its LAN address: free at once, silent.
fixture always "$LAN_CONFIG" "$OWN_UDP" "$OWN_TCP" "$OWN_WHO" 700
run_wait
{ [ "$RC" = 0 ] && [ -z "$OUT" ] && [ "$(checks)" = 1 ] && [ "$MS" -lt 2000 ]; } \
  || fail "ops_004_port53_wait_ignores_the_services_own_sockets: rc=$RC checks=$(checks) ms=$MS: $OUT"
# (g) and on every address (the default config, the stub already off in another spelling).
fixture always "$DEFAULT_CONFIG" \
  'UNCONN 0      0       0.0.0.0:53 0.0.0.0:* users:(("telltale",pid=700,fd=7))' \
  'LISTEN 0      4096    0.0.0.0:53 0.0.0.0:* users:(("telltale",pid=700,fd=8))' '' 700
run_wait
{ [ "$RC" = 0 ] && [ -z "$OUT" ] && [ "$(checks)" = 1 ]; } \
  || fail "ops_004_port53_wait_ignores_the_services_own_sockets: wildcard: rc=$RC checks=$(checks): $OUT"
ok ops_004_port53_wait_ignores_the_services_own_sockets
# (h) its own sockets and a real foreign holder: it waits, and names only the foreign one.
fixture always "$DEFAULT_CONFIG" \
  "$OWN_UDP
$STUB_UDP" "$OWN_TCP
$STUB_TCP" "$OWN_WHO
$STUB_WHO" 700
run_wait 1
{ [ "$RC" = 1 ] && has "still held after 1s" && has 'systemd-resolve' && ! has '"telltale"'; } \
  || fail "ops_004_port53_wait_still_waits_for_a_foreign_holder: rc=$RC: $OUT"
ok ops_004_port53_wait_still_waits_for_a_foreign_holder
# (h2) the foreign holder lets go while the service's own sockets stay: the wait ends (the polls
# leave the service out too, not only the first look).
fixture 1 "$DEFAULT_CONFIG" \
  "$OWN_UDP
$STUB_UDP" "$OWN_TCP
$STUB_TCP" '' 700
printf '%s\n' "$OWN_UDP" > "$FAKE/udp_holder_after"
printf '%s\n' "$OWN_TCP" > "$FAKE/tcp_holder_after"
run_wait
{ [ "$RC" = 0 ] && has "Waiting up to" && has "Port 53 is free" && [ "$(checks)" = 2 ]; } \
  || fail "ops_004_port53_wait_ends_when_only_its_own_sockets_remain: rc=$RC checks=$(checks) ms=$MS: $OUT"
ok ops_004_port53_wait_ends_when_only_its_own_sockets_remain
# (i) a telltale that isn't the service's main process (a stray `telltale run`) is a holder.
fixture always "$LAN_CONFIG" "$OWN_UDP" "$OWN_TCP" "$OWN_WHO" 999
run_wait 1
{ [ "$RC" = 1 ] && has "still held after 1s" && has 'pid=700'; } \
  || fail "ops_004_port53_wait_a_stray_telltale_is_a_holder: rc=$RC: $OUT"
ok ops_004_port53_wait_a_stray_telltale_is_a_holder
# (j) systemd can't say which process is the service: nothing is excluded (the old behaviour).
fixture always "$LAN_CONFIG" "$OWN_UDP" "$OWN_TCP" "$OWN_WHO" 700
touch "$FAKE/systemctl_fails"
run_wait 1
{ [ "$RC" = 1 ] && has "still held after 1s" && has 'pid=700'; } \
  || fail "ops_004_port53_wait_without_the_service_pid: rc=$RC: $OUT"
ok ops_004_port53_wait_without_the_service_pid
# (k) the service restarts while the wait runs (a start that failed at its bind is retried every two
# seconds): its new process, pid 800, is its own too, not a holder. The stub holds the port at the
# first look and is gone at the second; the service has it under its new pid.
NEW_UDP='UNCONN 0      0       192.0.2.10:53 0.0.0.0:* users:(("telltale",pid=800,fd=7))'
NEW_TCP='LISTEN 0      4096    192.0.2.10:53 0.0.0.0:* users:(("telltale",pid=800,fd=8))'
fixture 1 "$DEFAULT_CONFIG" "$STUB_UDP" "$STUB_TCP" "$STUB_WHO" 700
printf '%s\n' "$NEW_UDP" > "$FAKE/udp_holder_after"
printf '%s\n' "$NEW_TCP" > "$FAKE/tcp_holder_after"
printf '%s\n' 800 > "$FAKE/mainpid_after"
run_wait 2
{ [ "$RC" = 0 ] && has "Waiting up to" && has "Port 53 is free" && [ "$(checks)" = 2 ]; } \
  || fail "ops_004_port53_wait_ignores_a_restarted_service: rc=$RC checks=$(checks) ms=$MS: $OUT"
ok ops_004_port53_wait_ignores_a_restarted_service
# (l) and the report, after the wait ran out, doesn't name it as the holder either.
fixture always "$DEFAULT_CONFIG" "$STUB_UDP
$NEW_UDP" "$STUB_TCP
$NEW_TCP" "$STUB_WHO
udp $NEW_UDP
tcp $NEW_TCP" 700
printf '%s\n' 800 > "$FAKE/mainpid_after"
run_wait 1
{ [ "$RC" = 1 ] && has "still held after 1s" && has 'systemd-resolve' && ! has 'pid=800'; } \
  || fail "ops_004_port53_report_leaves_out_a_restarted_service: rc=$RC: $OUT"
# (l2) the same with no wait at all, so no poll read the pid again: the report reads it itself.
printf '%s\n' 800 > "$FAKE/mainpid_after"
rm -f "$FAKE/checks"
run_wait 0
{ [ "$RC" = 1 ] && has "still held after 0s" && has 'systemd-resolve' && ! has 'pid=800'; } \
  || fail "ops_004_port53_report_leaves_out_a_restarted_service: no wait: rc=$RC: $OUT"
ok ops_004_port53_report_leaves_out_a_restarted_service

# ---- 7c. the limit is seconds on the clock, whatever a look costs --------------------------------
# `ss -p` walks every process's descriptors, so on a busy or slow machine each look takes real time
# and a count of polls alone made "up to 3 s" take about 30: the limit also counts the clock. Each
# look here takes 2 s (two `ss` calls of 1 s).
fixture always
echo 1 > "$FAKE/ss_delay"
run_wait 3
{ [ "$RC" = 1 ] && has "still held after 3s" && [ "$MS" -ge 5000 ] && [ "$(checks)" -le 4 ]; } \
  || fail "ops_004_port53_wait_is_bounded_by_the_clock: rc=$RC ms=$MS looks=$(checks) (a first look of 2 s, a 3 s wait, at most one look more: 3 looks, 13 on the base): $OUT"
ok ops_004_port53_wait_is_bounded_by_the_clock
# The clock itself: hundredths of a second since boot from /proc/uptime. A copy of the block reads
# a file of the test's instead, to feed it values (a leading zero in the fraction is decimal).
sed "s#/proc/uptime#$T/uptime#g" "$T/lib.sh" > "$T/lib-uptime.sh"
grep -qF "$T/uptime" "$T/lib-uptime.sh" || fail "ops_004_port53_clock: the block doesn't read /proc/uptime"
now() { "$SH" -c 'set -eu; . "$1"; port53_now' sh "$T/lib-uptime.sh"; }
for pair in '12345.67:1234567' '0.45:45' '5.05:505' '100.00:10000' '3.5:350' '17:1700' '999999999.99:99999999999' '08.09 1:809'; do
  printf '%s 99.99\n' "${pair%%:*}" > "$T/uptime"
  [ "$(now)" = "${pair##*:}" ] || fail "ops_004_port53_clock_reads_uptime: '${pair%%:*}' gave '$(now)', expected ${pair##*:}"
done
ok ops_004_port53_clock_reads_uptime
# No file, or something that isn't an uptime: the wall clock's seconds, times 100 (never a shell error).
rm -f "$T/uptime"
for junk in missing 'abc 1.0' '' '12.3x 5' '.5 1' '-5.00 2' '1e3.00 1'; do
  if [ "$junk" = missing ]; then rm -f "$T/uptime"; else printf '%s\n' "$junk" > "$T/uptime"; fi
  before=$(date +%s); got=$(now); after=$(date +%s)
  { [ $((got % 100)) = 0 ] && [ $((got / 100)) -ge "$before" ] && [ $((got / 100)) -le "$after" ]; } \
    || fail "ops_004_port53_clock_falls_back_to_date: '$junk' gave '$got' (date is $before to $after)"
done
ok ops_004_port53_clock_falls_back_to_date
# The real thing steps in hundredths and doesn't go backwards.
if [ -r /proc/uptime ]; then
  a=$("$SH" -c 'set -eu; . "$1"; port53_now' sh "$T/lib.sh"); sleep 0.3
  b=$("$SH" -c 'set -eu; . "$1"; port53_now' sh "$T/lib.sh")
  { [ $((b - a)) -ge 25 ] && [ $((b - a)) -lt 300 ]; } || fail "ops_004_port53_clock_follows_the_boot_clock: 0.3 s moved it by $((b - a)) hundredths"
  ok ops_004_port53_clock_follows_the_boot_clock
fi

# ---- 7d. awk failing is said, not mistaken for "nothing to wait for" -----------------------------
# (n) awk can't read the printed config: assume every address (the default), as for a config that
# can't be printed at all. A LAN-only config would not wait for the stub on 127.0.0.53; this one does.
fixture 1 "$LAN_CONFIG"
touch "$FAKE/awk_binds_fails"
run_wait
{ [ "$RC" = 0 ] && has "Waiting" && ! has "no listener on port 53" && [ "$(checks)" = 2 ]; } \
  || fail "ops_004_port53_wait_awk_failing_on_the_config_assumes_every_address: rc=$RC checks=$(checks): $OUT"
ok ops_004_port53_wait_awk_failing_on_the_config_assumes_every_address
# (o) awk can't read the socket list either: one line, no wait, no failure (as without `ss`).
fixture always "$DEFAULT_CONFIG"
touch "$FAKE/awk_fails"
run_wait
{ [ "$RC" = 0 ] && has "awk can't read the socket list here: not checking that port 53 is free" && [ "$MS" -lt 2000 ] \
  && [ "$(printf '%s\n' "$OUT" | wc -l)" = 1 ]; } \
  || fail "ops_004_port53_wait_awk_failing_on_the_sockets_says_so: rc=$RC ms=$MS: $OUT"
ok ops_004_port53_wait_awk_failing_on_the_sockets_says_so

# ---- 7e. the call sites in install.sh ------------------------------------------------------------
# REQ: OPS-004 — what the part of install.sh after the block does: the wait comes after the
# resolver's stub was turned off and before the one start, and nowhere else. The text is cut out of
# install.sh like the block, with every path to the system moved into a temp tree (the commands that
# change files run against it, and `systemctl` is a fake that only logs). Nothing here runs the real
# installer. Not run as root (the body of this `if` is not indented, to keep the section readable):
# every command in it is faked or confined to the temp tree, and the guard below refuses a path
# the rewrite missed, but a test that could change a real machine when someone runs it with sudo
# is one mistake away from doing so.
if [ "$(id -u)" = 0 ]; then
echo "skipped: section 7e (the call sites of install.sh) isn't run as root"
else
TREE="$T/tree"
sed -n '/^# END port53-wait/,$p' "$INSTALL" > "$T/tail.raw"
[ -s "$T/tail.raw" ] || fail "ops_004_install_call_sites: $INSTALL has no port53-wait END marker"
sed "s#/etc/#$TREE/etc/#g; s#/run/#$TREE/run/#g" "$T/tail.raw" > "$T/tail.sh"
"$SH" -n "$T/tail.sh" || fail "ops_004_install_call_sites: the rest of $INSTALL isn't valid sh"
if grep -nE '(^|[^A-Za-z0-9_./-])/(etc|run|var|usr|opt|home|root|sys|boot|lib|bin|sbin|srv|mnt|media)/' "$T/tail.sh" >&2; then
  fail "ops_004_install_call_sites: the rest of $INSTALL names a system path the test doesn't move into its temp tree (see above)"
fi
TAILBIN="$T/tailbin"
mkdir -p "$TAILBIN"
cat > "$TAILBIN/systemctl" <<'EOF'
#!/bin/sh
echo "systemctl $*" >> "$FAKE/calls"
case "$*" in
  "show -p MainPID telltale")
    c=$(cat "$FAKE/checks" 2>/dev/null || echo 0)
    if [ -f "$FAKE/mainpid_after" ] && [ "$c" -ge 1 ]; then echo "MainPID=$(cat "$FAKE/mainpid_after")"; else echo "MainPID=$(cat "$FAKE/mainpid")"; fi ;;
  "is-active --quiet systemd-resolved") [ ! -f "$FAKE/resolved_inactive" ]; exit ;;
esac
exit 0
EOF
printf '#!/bin/sh\nexit 0\n' > "$TAILBIN/sleep"      # the polls and the health loop don't wait here
printf '#!/bin/sh\necho 192.0.2.10\n' > "$TAILBIN/hostname"
chmod +x "$TAILBIN"/*
# tail_tree: a fresh tree with a resolv.conf that is the stub's link, and no stub setting.
tail_tree() {
  rm -rf "$TREE"
  mkdir -p "$TREE/etc/systemd/resolved.conf.d" "$TREE/etc/systemd/system/telltale.service.d" "$TREE/etc/telltale" "$TREE/run/systemd/resolve"
  ln -s "$TREE/run/systemd/resolve/stub-resolv.conf" "$TREE/etc/resolv.conf"
  : > "$TREE/etc/systemd/resolved.conf"
  echo '# the installed config (the fake binary ignores it)' > "$TREE/etc/telltale/telltale.toml"
  : > "$FAKE/calls"
}
# tail_run [VAR=value ...]: runs the text as install.sh does at that point; sets RC and OUT.
# $FAKE/calls says in which order the fakes were called.
tail_run() {
  set +e
  OUT=$(env PATH="$TAILBIN:$FAKEBIN:$PATH" FAKE="$FAKE" PREFIX="$FAKEROOT" TREE="$TREE" "$@" \
    "$TIMEOUT" 60 "$SH" -c 'set -eu
      say() { printf "==> %s\n" "$*"; }
      die() { printf "error: %s\n" "$*" >&2; exit 1; }
      RESOLVED_DROPIN=$TREE/etc/systemd/resolved.conf.d/telltale.conf
      RESOLV_BACKUP=$TREE/etc/resolv.conf.telltale-backup
      DROPIN=$TREE/etc/systemd/system/telltale.service.d/10-first-admin.conf
      ADMIN=token; ADMIN_USER=admin; WAIT_PORT53=no
      : "${DISABLE_STUB:=ask}" "${START:=yes}"
      . "$1"; . "$2"' sh "$T/lib.sh" "$T/tail.sh" < /dev/null 2>&1)
  RC=$?
  set -e
}
call_line() { { grep -n -m1 -x -F -- "$1" "$FAKE/calls" || true; } | cut -d: -f1; }   # the first line that is exactly $1
call_count() { grep -c -x -F -- "$1" "$FAKE/calls" || true; }
ss_looks() { grep -c '^ss -Hlunp ' "$FAKE/calls" || true; }               # looks at the UDP sockets: one per check
ss_calls() { grep -c '^ss ' "$FAKE/calls" || true; }
ss_first() { { grep -n -m1 '^ss ' "$FAKE/calls" || true; } | cut -d: -f1; }
ss_last() { { grep -n '^ss ' "$FAKE/calls" || true; } | tail -n 1 | cut -d: -f1; }
starts() { call_count 'systemctl restart telltale'; }
# T1: the stub is turned off, the port stays held for two looks, then it is free: the wait comes
# after the resolver restarted and before the one start, which is `enable` and then `restart`.
fixture 2 "$DEFAULT_CONFIG"
tail_tree
tail_run DISABLE_STUB=yes START=yes TELLTALE_PORT_WAIT=5
l_resolved=$(call_line 'systemctl restart systemd-resolved'); l_ss=$(ss_first); last_ss=$(ss_last)
l_enable=$(call_line 'systemctl enable telltale'); l_start=$(call_line 'systemctl restart telltale')
{ [ "$RC" = 0 ] && has "TelltaleDNS is running" && has "Waiting up to 5s" && has "Port 53 is free" \
  && [ -n "$l_resolved" ] && [ -n "$l_ss" ] && [ -n "$l_start" ] && [ -n "$l_enable" ] \
  && [ "$l_resolved" -lt "$l_ss" ] && [ "$last_ss" -lt "$l_enable" ] && [ "$l_enable" -lt "$l_start" ]; } \
  || fail "ops_004_install_waits_for_port_53_before_its_one_start: rc=$RC resolved=$l_resolved ss=$l_ss..$last_ss enable=$l_enable start=$l_start: $OUT
$(cat "$FAKE/calls")"
{ [ "$(ss_looks)" = 3 ] && [ "$(starts)" = 1 ] && [ "$(call_count 'systemctl enable --now telltale')" = 0 ]; } \
  || fail "ops_004_install_waits_for_port_53_before_its_one_start: $(ss_looks) looks (2 held, 1 free), $(starts) starts: $(cat "$FAKE/calls")"
grep -q '^DNSStubListener=no' "$TREE/etc/systemd/resolved.conf.d/telltale.conf" \
  || fail "ops_004_install_waits_for_port_53_before_its_one_start: the drop-in wasn't written in the test's tree"
ok ops_004_install_waits_for_port_53_before_its_one_start
# T2..T4, T6: no wait unless this run turned the stub off, and none without a start.
no_wait() { # name
  [ "$(ss_calls)" = 0 ] || fail "ops_004_install_waits_only_after_turning_the_stub_off: $1: ss was called: $(cat "$FAKE/calls")"
  ! has "Waiting up to" || fail "ops_004_install_waits_only_after_turning_the_stub_off: $1: it waited: $OUT"
}
fixture 2 "$DEFAULT_CONFIG"; tail_tree; tail_run DISABLE_STUB=no START=yes
{ [ "$RC" = 0 ] && has "Leaving systemd-resolved as is" && [ "$(starts)" = 1 ] && [ "$(call_count 'systemctl restart systemd-resolved')" = 0 ]; } \
  || fail "ops_004_install_waits_only_after_turning_the_stub_off: declined: rc=$RC: $OUT $(cat "$FAKE/calls")"
no_wait declined
fixture 2 "$DEFAULT_CONFIG"; tail_tree; tail_run START=yes          # the answer is still "ask" and there is no terminal
{ [ "$RC" = 0 ] && has "Leaving systemd-resolved as is" && [ "$(starts)" = 1 ] && [ "$(call_count 'systemctl restart systemd-resolved')" = 0 ]; } \
  || fail "ops_004_install_waits_only_after_turning_the_stub_off: no terminal: rc=$RC: $OUT $(cat "$FAKE/calls")"
no_wait "no terminal"
fixture 2 "$DEFAULT_CONFIG"; tail_tree
printf '[Resolve]\nDNSStubListener=no\n' > "$TREE/etc/systemd/resolved.conf.d/10-mine.conf"
tail_run DISABLE_STUB=yes START=yes                                 # the stub is already off
{ [ "$RC" = 0 ] && [ "$(starts)" = 1 ] && [ "$(call_count 'systemctl restart systemd-resolved')" = 0 ]; } \
  || fail "ops_004_install_waits_only_after_turning_the_stub_off: already off: rc=$RC: $OUT $(cat "$FAKE/calls")"
no_wait "already off"
fixture 2 "$DEFAULT_CONFIG"; tail_tree; touch "$FAKE/resolved_inactive"
tail_run DISABLE_STUB=yes START=yes                                 # no systemd-resolved at all
{ [ "$RC" = 0 ] && [ "$(starts)" = 1 ] && [ "$(call_count 'systemctl restart systemd-resolved')" = 0 ]; } \
  || fail "ops_004_install_waits_only_after_turning_the_stub_off: no resolved: rc=$RC: $OUT $(cat "$FAKE/calls")"
no_wait "no resolved"
fixture 2 "$DEFAULT_CONFIG"; tail_tree; tail_run DISABLE_STUB=yes START=no   # --no-start: turned off, never started
{ [ "$RC" = 0 ] && [ "$(call_count 'systemctl restart systemd-resolved')" = 1 ] && [ "$(starts)" = 0 ] && [ "$(call_count 'systemctl enable telltale')" = 0 ]; } \
  || fail "ops_004_install_waits_only_after_turning_the_stub_off: --no-start: rc=$RC: $OUT $(cat "$FAKE/calls")"
no_wait "--no-start"
ok ops_004_install_waits_only_after_turning_the_stub_off
# T5: the port stays held: it says what holds it, and still starts the service once; the failure that
# follows names the port as the likely reason.
fixture always "$DEFAULT_CONFIG"; tail_tree; touch "$FAKE/health_fails"
tail_run DISABLE_STUB=yes START=yes TELLTALE_PORT_WAIT=1
{ [ "$RC" = 1 ] && has "still held after 1s" && has 'systemd-resolve' && has "Port 53 was still held when the service started" \
  && has "the service didn't become ready" && [ "$(starts)" = 1 ]; } \
  || fail "ops_004_install_starts_once_even_when_port_53_stays_held: rc=$RC starts=$(starts): $OUT"
l_start=$(call_line 'systemctl restart telltale'); last_ss=$(ss_last)
[ "$last_ss" -lt "$l_start" ] || fail "ops_004_install_starts_once_even_when_port_53_stays_held: it looked at the sockets after the start: $(cat "$FAKE/calls")"
ok ops_004_install_starts_once_even_when_port_53_stays_held
fi

# ---- 8. the real binary prints the effective config the way install.sh reads it ----------------
REAL=${1:-}
if [ -n "$REAL" ] && [ -x "$REAL" ]; then
  mkdir -p "$T/real/bin"
  ln -s "$(cd "$(dirname "$REAL")" && pwd)/$(basename "$REAL")" "$T/real/bin/telltale"
  binds() { PREFIX="$T/real" "$SH" -c 'set -eu; . "$1"; port53_binds "$2"' sh "$T/lib.sh" "$1" | tr '\n' ' '; }
  echo 'config_version = 1' > "$T/c-default.toml"
  [ "$(binds "$T/c-default.toml")" = "0.0.0.0 :: " ] || fail "ops_004_port53_binds_real_default: got '$(binds "$T/c-default.toml")'"
  printf '%s\n' 'config_version = 1' '[[listen]]' 'proto = "udp"' 'addr = "192.0.2.10:53"' \
    '[[listen]]' 'proto = "tcp"' 'addr = "[2001:db8::53]:53"' \
    '[[listen]]' 'proto = "udp"' 'addr = "127.0.0.1:5353"' > "$T/c-lan.toml"
  [ "$(binds "$T/c-lan.toml")" = "192.0.2.10 2001:db8::53 " ] || fail "ops_004_port53_binds_real_lan: got '$(binds "$T/c-lan.toml")'"
  printf '%s\n' 'config_version = 1' '[[listen]]' 'proto = "udp"' 'addr = "127.0.0.1:5353"' > "$T/c-5353.toml"
  [ -z "$(binds "$T/c-5353.toml")" ] || fail "ops_004_port53_binds_real_no_53: got '$(binds "$T/c-5353.toml")'"
  ok ops_004_port53_binds_real_binary
else
  echo "skipped: no telltale binary given (the effective-config format is checked in CI)"
fi

# ---- 9. the service is started once -------------------------------------------------------------
# `enable --now` and then `restart` two milliseconds apart spent two of systemd's five starts per
# ten seconds and killed the first instance before it handled SIGTERM. One `restart` starts a
# stopped service and swaps in a new binary under a running one.
starts=$(grep -cE '^[[:space:]]*systemctl[[:space:]]+(enable[^#|]*--now|start|restart)[[:space:]]+telltale([[:space:]]|$)' "$INSTALL" || true)
[ "$starts" = 1 ] || fail "ops_004_install_starts_once: $INSTALL has $starts commands that start telltale, expected 1"
grep -qE '^[[:space:]]*systemctl[[:space:]]+restart[[:space:]]+telltale([[:space:]]|$)' "$INSTALL" \
  || fail "ops_004_install_starts_once: the one start isn't a restart"
grep -qE '^[[:space:]]*systemctl[[:space:]]+enable[[:space:]]+telltale([[:space:]>]|$)' "$INSTALL" \
  || fail "ops_004_install_starts_once: the service isn't enabled (without --now)"
ok ops_004_install_starts_once

# ---- 10. e2e.sh's failure report says who held port 53, and never hangs -------------------------
# The systemd e2e step failed on "Address already in use" on port 53 and the log didn't say who
# held it. fail() in deploy/systemd/e2e.sh now records the sockets with their processes,
# systemd-resolved's state, journal and configuration. Here it runs against fake tools.
E2E=deploy/systemd/e2e.sh
sed -n '/^# BEGIN failure-report/,/^# END failure-report/p' "$E2E" > "$T/report.sh"
[ -s "$T/report.sh" ] || fail "ops_004_e2e_failure_report: $E2E has no failure-report block"
grep -q '^# END failure-report' "$T/report.sh" || fail "ops_004_e2e_failure_report: the failure-report block in $E2E has no END marker"
bash -n "$T/report.sh" || fail "ops_004_e2e_failure_report: the block isn't valid bash"
RFAKE="$T/rfake"
RBIN="$T/rbin"
mkdir -p "$RFAKE" "$RBIN" "$T/work"
cat > "$RBIN/ss" <<'EOF'
#!/bin/sh
[ -f "$RFAKE/hang" ] && exec sleep 30
[ -f "$RFAKE/nobody" ] && exit 0
case "$*" in
  *-Hulpn*) echo 'UNCONN 0      0       127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=612,fd=13))' ;;
  *-Htlpn*) echo 'LISTEN 0      4096    127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=612,fd=14))' ;;
esac
EOF
cat > "$RBIN/systemctl" <<'EOF'
#!/bin/sh
[ -f "$RFAKE/hang" ] && exec sleep 30
echo '● systemd-resolved.service - Network Name Resolution'
echo '     Active: active (running) since Wed 2026-11-18 00:35:14 UTC; 1s ago'
EOF
cat > "$RBIN/journalctl" <<'EOF'
#!/bin/sh
[ -f "$RFAKE/hang" ] && exec sleep 30
case "$*" in
  *systemd-resolved*) echo 'Nov 18 00:35:14 runner systemd-resolved[612]: Listening on stub address 127.0.0.54' ;;
  *telltale*)
    echo 'Nov 18 00:35:14 runner systemd[1]: Started telltale.service - TelltaleDNS resolver.'
    echo 'Nov 18 00:35:14 runner telltale[700]: 14.100 INFO anomaly baselines loaded'
    echo 'Nov 18 00:35:14 runner telltale[700]: telltale: Udp 0.0.0.0:53: Address already in use (os error 98)'
    echo 'Nov 18 00:35:14 runner systemd[1]: telltale.service: Main process exited, code=exited, status=1/FAILURE' ;;
esac
EOF
cat > "$RBIN/systemd-analyze" <<'EOF'
#!/bin/sh
[ -f "$RFAKE/hang" ] && exec sleep 30
printf '%s\n' '# /etc/systemd/resolved.conf' '[Resolve]' '#DNS=' '' '# /etc/systemd/resolved.conf.d/telltale.conf' '[Resolve]' 'DNSStubListener=no'
EOF
chmod +x "$RBIN"/*
# e2e.sh's own wiring: the block, then the ERR trap that calls fail, then a failing command.
cat > "$T/harness.sh" <<'EOF'
set -euo pipefail
. "$1"
trap 'fail "line $LINENO: \`$BASH_COMMAND\` failed"' ERR
false
EOF
# run_report [PATH]: the failure path as e2e.sh takes it; sets RC, OUT, MS.
run_report() {
  local start end
  start=$(now_ms)
  set +e
  OUT=$(PATH="${1:-$RBIN:$PATH}" RFAKE="$RFAKE" WORK="$T/work" REPORT_TIMEOUT="${REPORT_TIMEOUT_TEST:-8}" \
    "$TIMEOUT" 120 bash "$T/harness.sh" "$T/report.sh" 2>&1)
  RC=$?
  set -e
  end=$(now_ms)
  MS=$((end - start))
}
rm -f "$RFAKE/hang" "$RFAKE/nobody" "$T/work/guided.out"
printf 'install line one\nTelltaleDNS is running\n' > "$T/work/guided.out"
run_report
[ "$RC" = 1 ] || fail "ops_004_e2e_failure_report_names_the_holder: rc=$RC: $OUT"
[ "$(printf '%s\n' "$OUT" | head -1 | cut -c1-6)" = 'FAIL: ' ] \
  || fail "ops_004_e2e_failure_report_names_the_holder: no FAIL line first: $OUT"
for want in 'udp UNCONN' 'tcp LISTEN' 'systemd-resolve",pid=612' 'Active: active (running)' 'Listening on stub address' \
            '# /etc/systemd/resolved.conf.d/telltale.conf' 'DNSStubListener=no' 'Address already in use' 'install line one'; do
  has "$want" || fail "ops_004_e2e_failure_report_names_the_holder: the report lacks '$want': $OUT"
done
has '#DNS=' && fail "ops_004_e2e_failure_report_names_the_holder: commented defaults weren't left out of the resolved.conf listing"
[ "$(printf '%s\n' "$OUT" | grep -c '^::error title=systemd-e2e::')" = 1 ] \
  || fail "ops_004_e2e_failure_report_names_the_holder: not exactly one annotation: $OUT"
ann=$(printf '%s\n' "$OUT" | grep '^::error title=systemd-e2e::')
for want in 'port 53: udp UNCONN' 'DNSStubListener=no' 'Address already in use' 'install line one'; do
  case "$ann" in *"$want"*) ;; *) fail "ops_004_e2e_failure_report_names_the_holder: the annotation lacks '$want': $ann" ;; esac
done
[ "${#ann}" -lt 6000 ] || fail "ops_004_e2e_failure_report_names_the_holder: the annotation is ${#ann} characters"
ok ops_004_e2e_failure_report_names_the_holder

# Nobody holds the port: it says so.
touch "$RFAKE/nobody"
run_report
[ "$RC" = 1 ] && has '(nothing)' && has 'port 53: nothing' || fail "ops_004_e2e_failure_report_nobody: rc=$RC: $OUT"
ok ops_004_e2e_failure_report_nobody
rm -f "$RFAKE/nobody"

# Every tool hangs: still finishes, still prints the FAIL line and the annotation, exit 1.
touch "$RFAKE/hang"
REPORT_TIMEOUT_TEST=1 run_report
[ "$RC" = 1 ] || fail "ops_004_e2e_failure_report_never_hangs: rc=$RC: $OUT"
[ "$MS" -lt 30000 ] || fail "ops_004_e2e_failure_report_never_hangs: took $MS ms with every tool hanging (1 s timeouts)"
[ "$(printf '%s\n' "$OUT" | grep -c '^::error title=systemd-e2e::')" = 1 ] || fail "ops_004_e2e_failure_report_never_hangs: no annotation: $OUT"
ok ops_004_e2e_failure_report_never_hangs
rm -f "$RFAKE/hang"

# The tools aren't there at all (a minimal machine): the same.
mkdir -p "$T/rnotools"
for tool in awk tr sleep cat sed date grep head tail cut timeout bash printf; do
  p=$(command -v "$tool" 2>/dev/null) && [ -x "$p" ] && ln -sf "$p" "$T/rnotools/$tool"
done
run_report "$T/rnotools"
[ "$RC" = 1 ] && [ "$(printf '%s\n' "$OUT" | grep -c '^::error title=systemd-e2e::')" = 1 ] \
  || fail "ops_004_e2e_failure_report_without_tools: rc=$RC: $OUT"
ok ops_004_e2e_failure_report_without_tools

# ---- 11. the GitOps takeover step reads epochs without ending silently --------------------------
# REQ: CLU-005 — deploy/cluster/gitops-failover-e2e.sh runs under `set -euo pipefail` and `metric`
# returns curl's status, so an epoch read while a node's metrics are unreachable used to end the
# script with no FAIL line and no log dump. The reads now say so and go on. Here the real `metric`
# and the epoch-report block run against a port nothing listens on.
G=deploy/cluster/gitops-failover-e2e.sh
sed -n '/^# BEGIN epoch-report/,/^# END epoch-report/p' "$G" > "$T/epoch.sh"
[ -s "$T/epoch.sh" ] || fail "clu_005_epoch_reads: $G has no epoch-report block"
grep -q '^# END epoch-report' "$T/epoch.sh" || fail "clu_005_epoch_reads: the epoch-report block in $G has no END marker"
sed -n '/^metric() {/,/^}/p' "$G" > "$T/metric.sh"
[ -s "$T/metric.sh" ] || fail "clu_005_epoch_reads: $G has no metric function"
set +e
out=$(bash -c 'set -euo pipefail; . "$1"; . "$2"
  e=$(epoch_of 1); echo "read:[$e]"
  echo "advance:[$(epoch_advance "$e" 3)]"; echo "advance:[$(epoch_advance 2 4)]"
  metric() { echo 7; }; e=$(epoch_of 1); echo "read:[$e]"; echo "advance:[$(epoch_advance 2 "$e")]"
  echo reached-the-end' bash "$T/metric.sh" "$T/epoch.sh" 2>&1)
rc=$?
set -e
for want in 'read:[]' "couldn't read the epoch" 'advance:[?]' 'advance:[2]' 'read:[7]' 'advance:[5]' 'reached-the-end'; do
  case "$out" in *"$want"*) ;; *) fail "clu_005_epoch_reads_report_instead_of_exiting: rc=$rc, no '$want': $out" ;; esac
done
[ "$rc" = 0 ] || fail "clu_005_epoch_reads_report_instead_of_exiting: rc=$rc: $out"
ok clu_005_epoch_reads_report_instead_of_exiting
# The block is only safe where it is used: no step of the script may read an epoch with a bare
# `x=$(metric ...)`, which ends the whole run silently when the node's metrics can't be reached
# (the step 3 read did once). Every epoch read goes through `epoch_of`.
bare=$(grep -nE '^[[:space:]]*[A-Za-z_][A-Za-z_0-9]*=\$\(metric ' "$G" | grep -vF '|| true' || true)
[ -z "$bare" ] || fail "clu_005_no_epoch_read_ends_the_takeover_step_silently: a bare metric read in $G: $bare"
[ "$(grep -cE '=\$\(epoch_of ' "$G")" -ge 3 ] || fail "clu_005_no_epoch_read_ends_the_takeover_step_silently: $G reads fewer than three epochs through epoch_of"
ok clu_005_no_epoch_read_ends_the_takeover_step_silently

echo "PASS ($n checks)"
