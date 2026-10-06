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

# Failures become CI annotations with the installer's output and the service's journal (the
# job log isn't always at hand).
fail() {
  echo "FAIL: $*"
  local extra=""
  if [ -f "$WORK/guided.out" ]; then
    extra=" | install.sh: $(tail -n 8 "$WORK/guided.out" | tr '\n' ' ' | cut -c1-600)"
  fi
  echo "::error title=systemd-e2e::FAIL: $*$extra | journal: $(journalctl -u telltale --no-pager -n 8 2>/dev/null | tr '\n' ' ' | cut -c1-800)"
  exit 1
}
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
user="$(ps -o user= -C telltale | head -1)"
[ "$user" = telltale ] || { fail "running as $user"; }
systemd-analyze security telltale --no-pager | tail -1
[ -f /var/lib/telltale/setup-token ] || { fail "no setup token in the data directory"; }
sudo -u telltale /usr/local/bin/telltale auth setup-token -c /etc/telltale/telltale.toml >/dev/null

echo "== re-run upgrades in place and keeps the config"
echo "# local edit" >> /etc/telltale/telltale.toml
sh "$HERE/install.sh" --disable-resolved-stub >/dev/null
grep -q "# local edit" /etc/telltale/telltale.toml || { fail "config overwritten"; }
systemctl is-active --quiet telltale

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

echo "PASS"
