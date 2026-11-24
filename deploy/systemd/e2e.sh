#!/usr/bin/env bash
# REQ: OPS-004 — install.sh end to end on a disposable systemd machine (CI runner):
#   sudo deploy/systemd/e2e.sh target/release/telltale
# Publishes the binary as a fake release (signed with a throwaway minisign key) on a local
# HTTP server, runs install.sh against it, and checks: the service answers DNS on port 53,
# the UI port is up, the sandbox holds, re-running upgrades in place, and a tampered release
# is refused. Changes the machine (user, unit, systemd-resolved stub): never run it on a
# machine you care about.
set -euo pipefail

BIN="$(realpath "${1:?usage: e2e.sh path/to/telltale}")"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
REL="$WORK/release"
mkdir -p "$REL"
case "$(uname -m)" in
  x86_64) ASSET=telltale-x86_64-linux ;;
  aarch64) ASSET=telltale-aarch64-linux ;;
  *) echo "unsupported test arch"; exit 1 ;;
esac

# BEGIN failure-report — REQ: OPS-004. portwait-test.sh cuts this block out and runs it with fake
# tools (including ones that hang), so keep it self-contained.
# Failures become CI annotations with the installer's output, the service's journal and, for the
# bind failure that has failed this step ("Address already in use" on port 53), who held the port:
# the sockets with their processes, systemd-resolved's state and journal, and the resolved.conf it
# ran with (the job log isn't always at hand). Every command is bounded by `timeout` and may fail:
# fail() runs from the ERR trap, and it must never hang or die before it has printed.
REPORT_TIMEOUT=${REPORT_TIMEOUT:-8}
oneline() { # max-chars: stdin as one short line
  tr '\n' ' ' | tr -s ' ' | cut -c1-"$1"
}
# Who holds UDP and TCP port 53, with the process (the kernel's view; empty when nobody does).
port53_report() {
  timeout "$REPORT_TIMEOUT" ss -Hulpn 'sport = :53' 2>&1 | sed 's/^/udp /' || true
  timeout "$REPORT_TIMEOUT" ss -Htlpn 'sport = :53' 2>&1 | sed 's/^/tcp /' || true
}
# systemd-resolved as systemd reads its configuration: the files and settings, comments left out.
resolved_config() {
  timeout "$REPORT_TIMEOUT" systemd-analyze cat-config systemd/resolved.conf 2>&1 | grep -E '^(# /|[^#])' || true
}
fail() {
  echo "FAIL: $*"
  local extra="" held cfg state rlog tlog heldline=nothing
  if [ -f "$WORK/guided.out" ]; then
    extra=" | install.sh: $(tail -n 8 "$WORK/guided.out" | oneline 600)"
  fi
  held="$(port53_report)"
  cfg="$(resolved_config)"
  state="$(timeout "$REPORT_TIMEOUT" systemctl status systemd-resolved --no-pager 2>&1 | head -n 12 || true)"
  rlog="$(timeout "$REPORT_TIMEOUT" journalctl -u systemd-resolved -n 20 --no-pager 2>&1 || true)"
  tlog="$(timeout "$REPORT_TIMEOUT" journalctl -u telltale --no-pager -n 120 2>&1 || true)"
  # The job log gets all of it.
  echo "--- who holds port 53 now"; echo "${held:-(nothing)}"
  echo "--- systemd-resolved"; echo "$state"; echo "$rlog"
  echo "--- resolved.conf as systemd reads it"; echo "$cfg"
  echo "--- telltale journal (last 120 lines)"; echo "$tlog"
  # The annotation (readable without a token) gets the short version. For the service's journal:
  # its first lines that aren't routine INFO (the first failing start, and why), then the last few.
  [ -z "$held" ] || heldline="$(printf '%s\n' "$held" | oneline 500)"
  echo "::error title=systemd-e2e::FAIL: $*$extra | port 53: $heldline | resolved.conf: $(printf '%s\n' "$cfg" | oneline 300) | resolved journal: $(printf '%s\n' "$rlog" | tail -n 6 | cut -c1-170 | oneline 700) | journal: $(printf '%s\n' "$tlog" | grep -vE ' (INFO|DEBUG|TRACE) ' | cut -c1-170 | head -n 10 | oneline 1200) | last: $(printf '%s\n' "$tlog" | tail -n 4 | cut -c1-170 | oneline 600)"
  exit 1
}
# END failure-report
trap 'fail "line $LINENO: \`$BASH_COMMAND\` failed"' ERR

command -v minisign >/dev/null || { apt-get update -qq && apt-get install -y -qq minisign dnsutils; }
command -v dig >/dev/null || apt-get install -y -qq dnsutils

publish() { # binary
  cp "$1" "$REL/$ASSET"
  (cd "$REL" && sha256sum "$ASSET" > SHA256SUMS)
  rm -f "$REL/SHA256SUMS.minisig"
  minisign -S -s "$WORK/test.key" -m "$REL/SHA256SUMS" -t "e2e" >/dev/null
}

minisign -G -W -p "$WORK/test.pub" -s "$WORK/test.key" >/dev/null
publish "$BIN"
(cd "$REL" && exec python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1) &
SERVER=$!
trap 'kill $SERVER 2>/dev/null; rm -r "$WORK"' EXIT
sleep 1

export TELLTALE_RELEASE_URL=http://127.0.0.1:8765
TELLTALE_RELEASE_PUBKEY="$(sed -n 2p "$WORK/test.pub")"
export TELLTALE_RELEASE_PUBKEY

# Who holds port 53 before the install, for the job log: systemd-resolved's stub is expected (the
# install turns it off); anything else is what a bind failure further down would be about.
echo "== port 53 before the install"
held="$(port53_report)"
echo "${held:-(nothing)}"

echo "== install"
sh "$HERE/install.sh" --disable-resolved-stub

echo "== DNS on port 53"
ok=""
for _ in $(seq 1 20); do
  if dig +short +time=2 +tries=1 @127.0.0.1 example.com A | grep -qE '^[0-9.]+$'; then ok=1; break; fi
  sleep 1
done
[ -n "$ok" ] || { journalctl -u telltale --no-pager | tail -30; fail "no DNS answer"; }
dig +short +tcp @127.0.0.1 example.com A | grep -qE '^[0-9.]+$' || { fail "TCP"; }
/usr/local/bin/telltale health --url http://127.0.0.1:8053/readyz

echo "== runs as telltale, sandboxed"
# The service's own process (a stray `telltale` of someone else's on the machine isn't it).
user="$(ps -o user= -p "$(systemctl show -p MainPID --value telltale)" | head -1)"
[ "$user" = telltale ] || { fail "running as $user"; }
systemd-analyze security telltale --no-pager | tail -1
[ -f /var/lib/telltale/setup-token ] || { fail "no setup token in the data directory"; }
sudo -u telltale /usr/local/bin/telltale auth setup-token -c /etc/telltale/telltale.toml >/dev/null

echo "== re-run upgrades in place and keeps the config"
echo "# local edit" >> /etc/telltale/telltale.toml
sh "$HERE/install.sh" --disable-resolved-stub >/dev/null
grep -q "# local edit" /etc/telltale/telltale.toml || { fail "config overwritten"; }
systemctl is-active --quiet telltale

# REQ: OPS-014 (ADR-182) — the update service: installed and off, its units written for the data
# directory and passing `systemd-analyze verify`. Its sandbox lets it restart the node, read the
# node's health and write the binary's directory and <data_dir>/update/, and nothing else of the
# data directory or of /etc. Once on, it picks up a request the telltale user writes (through a
# temporary file and a rename, as the node does), removes it, refuses this build (a local build
# never installs from a request), records the outcome where the node can read it, logs to the
# journal, exits 0 for a refusal (the path unit stays on), and leaves the node running; a FIFO at
# the request is refused and removed without blocking.
echo "== the update service picks a request up"
UPATH=/etc/systemd/system/telltale-update.path USVC=/etc/systemd/system/telltale-update.service
UPD=/var/lib/telltale/update RESULT=/var/lib/telltale-update/result.json
[ -f "$UPATH" ] && [ -f "$USVC" ] || { fail "the update units aren't installed"; }
if systemctl is-enabled --quiet telltale-update.path; then fail "telltale-update.path is on by default"; fi
grep -qx "PathExists=$UPD/request.json" "$UPATH" || { fail "the path unit watches $(grep PathExists "$UPATH")"; }
grep -qx "ReadWritePaths=/usr/local/bin -$UPD" "$USVC" || { fail "the service writes $(grep ReadWritePaths "$USVC")"; }
# REQ: OPS-014 (ADR-182) — the channel (in both units) and the health check's address (from the
# config's [api] listen, 0.0.0.0:8053: asked at loopback), written by install.sh.
grep -qx 'Environment=TELLTALE_UPDATE_CHANNEL=stable' "$USVC" \
  && grep -qx 'Environment=TELLTALE_UPDATE_CHANNEL=stable' /etc/systemd/system/telltale.service \
  || { fail "the update channel isn't in the units: $(grep -h CHANNEL "$USVC" /etc/systemd/system/telltale.service)"; }
grep -qx 'Environment=TELLTALE_UPDATE_HEALTH_URL=http://127.0.0.1:8053/readyz?startup=1' "$USVC" \
  || { fail "the health URL: $(grep HEALTH_URL "$USVC")"; }
systemd-analyze verify "$UPATH" "$USVC" || { fail "systemd-analyze verify"; }
echo "telltale-update.service: $(systemd-analyze security telltale-update.service --no-pager | tail -1)"
# The sandbox as the service gets it (a drop-in with another command, removed afterwards).
mkdir -p /etc/systemd/system/telltale-update.service.d
before="$(systemctl show -p MainPID --value telltale)"
cat > /etc/systemd/system/telltale-update.service.d/e2e.conf <<EOF
[Service]
ExecStart=
ExecStart=/bin/sh -c 'touch /usr/local/bin/.tt-e2e && rm /usr/local/bin/.tt-e2e && touch $UPD/.tt-e2e && rm $UPD/.tt-e2e && ! touch /var/lib/telltale/.tt-e2e 2>/dev/null && ! touch /etc/.tt-e2e 2>/dev/null'
ExecStart=/usr/bin/systemctl restart telltale
ExecStart=/bin/sh -c 'for i in \$\$(seq 1 40); do /usr/local/bin/telltale health --url "\${TELLTALE_UPDATE_HEALTH_URL}" && exit 0; sleep 0.5; done; exit 1'
EOF
sudo -u telltale mkdir -p -m 0750 "$UPD"
systemctl daemon-reload
systemctl start telltale-update.service || { journalctl -u telltale-update --no-pager | tail -20; fail "the update service's sandbox: a write, the restart, or the health check"; }
[ "$(systemctl show -p MainPID --value telltale)" != "$before" ] || { fail "the node wasn't restarted"; }
rm -rf /etc/systemd/system/telltale-update.service.d
systemctl daemon-reload
systemctl reset-failed telltale telltale-update.service 2>/dev/null || true
systemctl enable --now telltale-update.path
# As the node writes a request: a temporary file in the folder, then a rename.
ask() { # json
  printf '%s' "$1" | sudo -u telltale sh -c "cat > $UPD/.request.tmp && mv -f $UPD/.request.tmp $UPD/request.json"
}
outcome() { # pattern: waits for the service's result to match it
  for _ in $(seq 1 40); do grep -q "$1" "$RESULT" 2>/dev/null && return 0; sleep 0.5; done
  journalctl -u telltale-update --no-pager | tail -20
  return 1
}
settled() { # the service has run and stopped; the path unit is still on
  for _ in $(seq 1 40); do [ "$(systemctl show -p ActiveState --value telltale-update.service)" = inactive ] && break; sleep 0.5; done
  [ "$(systemctl show -p Result --value telltale-update.service)" = success ] || { fail "a refusal failed the unit ($(systemctl show -p Result --value telltale-update.service))"; }
  systemctl is-active --quiet telltale-update.path || { fail "the path unit stopped after a refusal"; }
}
rm -f "$RESULT"
# A local build refuses every request before anything is fetched: the binary under test must be
# one, or this request would start a real download.
case " $(/usr/local/bin/telltale --version) " in
  *" dev "*) ;;
  *) fail "the binary under test isn't a local (dev) build: $(/usr/local/bin/telltale --version)" ;;
esac
# This run's journal lines only (a machine that ran the e2e before keeps the older ones).
since="$(date '+%Y-%m-%d %H:%M:%S')"
ask "{\"id\":\"1a-2b\",\"to\":\"9.9.9\",\"by\":\"e2e\",\"requestedMs\":$(( $(date +%s) * 1000 ))}"
outcome '"id": "1a-2b"' || { fail "no outcome recorded for the request"; }
result="$(sudo -u telltale cat "$RESULT" 2>&1)" || { fail "the node can't read the outcome: $result"; }
grep -q '"state": "refused"' <<<"$result" || { fail "no refusal recorded: $result"; }
[ ! -e "$UPD/request.json" ] || { fail "the request was left behind"; }
settled
# Read whole, then searched: `journalctl | grep -q` under pipefail fails when grep stops reading
# early and journalctl, still writing, gets SIGPIPE (a long journal from earlier runs).
journal="$(journalctl -u telltale-update --since "$since" --no-pager)"
grep -q 'update: refused' <<<"$journal" || { fail "the refusal isn't in the journal"; }
systemctl is-active --quiet telltale || { fail "the update service stopped the node"; }
rm -f "$RESULT"
sudo -u telltale mkfifo "$UPD/request.json"
outcome 'regular file' || { fail "a FIFO at the request wasn't refused"; }
[ ! -e "$UPD/request.json" ] || { fail "the FIFO was left behind"; }
settled
systemctl disable --now telltale-update.path
# REQ: OPS-014 (ADR-182) — install.sh --cluster-updates turns it on only once the node answers
# where the health check will ask, and says where that is.
out="$(sh "$HERE/install.sh" --disable-resolved-stub --cluster-updates 2>&1)" \
  || { echo "$out" | tail -20; fail "install.sh --cluster-updates"; }
grep -q 'health check after each update asks http://127.0.0.1:8053/readyz?startup=1, which answers now' <<<"$out" \
  || { echo "$out" | tail -10; fail "install.sh --cluster-updates didn't say where the health check asks"; }
grep -q 'Update channel: stable' <<<"$out" || { echo "$out" | tail -10; fail "install.sh didn't say the update channel"; }
systemctl is-enabled --quiet telltale-update.path || { fail "--cluster-updates left the path unit off"; }
systemctl disable --now telltale-update.path

# REQ: OPS-001 (T7.6) — the guided setup on a fresh machine: answers on stdin, the first admin
# made from the answers (its drop-in removed once the service is up), the answers in the config.
echo "== guided install, admin made now"
systemctl stop telltale
rm -rf /etc/telltale /var/lib/telltale/*
printf '2\n\n\n0\n\n\n2\nalice\ne2e-guided-pass-1\ne2e-guided-pass-1\n3\n\ny\n' \
  | sh "$HERE/install.sh" --interactive > "$WORK/guided.out" 2>&1 \
  || { cat "$WORK/guided.out"; journalctl -u telltale --no-pager | tail -30; fail "guided install"; }
grep -q 'retention_days = 3' /etc/telltale/telltale.toml || { cat /etc/telltale/telltale.toml; fail "answers not in the config"; }
grep -q '\[\[list\]\]' /etc/telltale/telltale.toml && { fail "lists written for 'none'"; }
[ -f /etc/systemd/system/telltale.service.d/10-first-admin.conf ] && { fail "the first-admin drop-in is still there"; }
grep -q 'sign in as alice' "$WORK/guided.out" || { cat "$WORK/guided.out"; fail "closing message"; }
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
  -d '{"username":"alice","password":"e2e-guided-pass-1"}' http://127.0.0.1:8053/api/v1/auth/login)
[ "$code" = 200 ] || { fail "alice can't sign in ($code)"; }
# The test started the service several times in a few seconds: reset systemd's start limit.
systemctl reset-failed telltale 2>/dev/null || true
systemctl restart telltale   # the drop-in is gone: a restart doesn't need it
for _ in $(seq 1 20); do /usr/local/bin/telltale health --url http://127.0.0.1:8053/readyz >/dev/null 2>&1 && break; sleep 0.5; done
/usr/local/bin/telltale health --url http://127.0.0.1:8053/readyz

echo "== tampered release is refused"
cp "$BIN" "$WORK/evil" && printf 'x' >> "$WORK/evil"
cp "$WORK/evil" "$REL/$ASSET"     # binary swapped after signing
if sh "$HERE/install.sh" --no-start >/dev/null 2>&1; then fail "tampered binary installed"; fi
publish "$BIN"
printf 'x' >> "$REL/SHA256SUMS"   # checksums changed after signing
if sh "$HERE/install.sh" --no-start >/dev/null 2>&1; then fail "bad signature accepted"; fi
cmp -s "$BIN" /usr/local/bin/telltale || { fail "binary changed by a refused install"; }

# REQ: OPS-004 (T9.21) — uninstall: the service, unit, and binary go; systemd-resolved is put
# back as the first install found it; the config and data stay; --purge removes them too.
echo "== uninstall"
was="$(sed -n 's/^# resolv.conf was: //p' /etc/systemd/resolved.conf.d/telltale.conf)"
[ -n "$was" ] || fail "the install didn't record what /etc/resolv.conf was"
sh "$HERE/install.sh" --uninstall --yes
systemctl is-active --quiet telltale && fail "the service still runs"
[ -e /etc/systemd/system/telltale.service ] && fail "the unit is still there"
[ -e /usr/local/bin/telltale ] && fail "the binary is still there"
[ -e /etc/systemd/resolved.conf.d/telltale.conf ] && fail "the resolved drop-in is still there"
if [ "$was" != file ]; then
  [ "$(readlink /etc/resolv.conf)" = "$was" ] || fail "resolv.conf points at $(readlink /etc/resolv.conf), not $was"
fi
ok=""
for _ in $(seq 1 10); do getent hosts example.com >/dev/null && { ok=1; break; }; sleep 1; done
[ -n "$ok" ] || fail "the machine can't resolve after uninstalling"
[ -f /etc/telltale/telltale.toml ] || fail "the config was deleted without --purge"
echo "== uninstall --purge (again, idempotent)"
sh "$HERE/install.sh" --uninstall --purge --yes
[ -e /etc/telltale ] && fail "/etc/telltale is still there"
[ -e /var/lib/telltale ] && fail "/var/lib/telltale is still there"
id telltale >/dev/null 2>&1 && fail "the telltale user is still there"

echo "PASS"
