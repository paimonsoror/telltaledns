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
[ -n "$ok" ] || { journalctl -u telltale --no-pager | tail -30; echo "FAIL: no DNS answer"; exit 1; }
dig +short +tcp @127.0.0.1 example.com A | grep -qE '^[0-9.]+$' || { echo "FAIL: TCP"; exit 1; }
/usr/local/bin/telltale health --url http://127.0.0.1:8053/readyz

echo "== runs as telltale, sandboxed"
user="$(ps -o user= -C telltale | head -1)"
[ "$user" = telltale ] || { echo "FAIL: running as $user"; exit 1; }
systemd-analyze security telltale --no-pager | tail -1
[ -f /var/lib/telltale/setup-token ] || { echo "FAIL: no setup token in the data directory"; exit 1; }
sudo -u telltale /usr/local/bin/telltale auth setup-token -c /etc/telltale/telltale.toml >/dev/null

echo "== re-run upgrades in place and keeps the config"
echo "# local edit" >> /etc/telltale/telltale.toml
sh "$HERE/install.sh" --disable-resolved-stub >/dev/null
grep -q "# local edit" /etc/telltale/telltale.toml || { echo "FAIL: config overwritten"; exit 1; }
systemctl is-active --quiet telltale

echo "== tampered release is refused"
cp "$BIN" "$WORK/evil" && printf 'x' >> "$WORK/evil"
cp "$WORK/evil" "$REL/$ASSET"     # binary swapped after signing
if sh "$HERE/install.sh" --no-start >/dev/null 2>&1; then echo "FAIL: tampered binary installed"; exit 1; fi
publish "$BIN"
printf 'x' >> "$REL/SHA256SUMS"   # checksums changed after signing
if sh "$HERE/install.sh" --no-start >/dev/null 2>&1; then echo "FAIL: bad signature accepted"; exit 1; fi
cmp -s "$BIN" /usr/local/bin/telltale || { echo "FAIL: binary changed by a refused install"; exit 1; }

echo "PASS"
