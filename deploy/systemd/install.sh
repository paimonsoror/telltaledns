#!/bin/sh
# TelltaleDNS native installer (REQ: OPS-004, spec/08 §4, ADR-038).
#
#   curl -fsSLO https://raw.githubusercontent.com/paimonsoror/telltaledns/main/deploy/systemd/install.sh
#   less install.sh                 # read it first
#   sudo sh install.sh              # latest release;  --edge for builds from main
#
# Downloads the static binary for this machine, verifies the release signature (minisign)
# and the binary's SHA-256, creates the `telltale` system user, installs a hardened systemd
# unit and a starter config (an existing config is never overwritten), and starts the
# service. Re-running it upgrades the binary (or use `telltale self-update`).
#
# Options:
#   --edge                   follow builds from main instead of tagged releases
#   --disable-resolved-stub  turn off systemd-resolved's stub listener on 127.0.0.53:53
#                            (needed when it holds port 53; asked interactively otherwise)
#   --no-start               install but don't enable or start the service
# Environment (mirrors and tests): TELLTALE_RELEASE_URL (base URL of the release files),
# TELLTALE_RELEASE_PUBKEY (minisign public key), TELLTALE_PREFIX (default /usr/local).
set -eu

REPO_RAW="https://raw.githubusercontent.com/paimonsoror/telltaledns/main"
# Run from a checkout (or the tests), the unit and starter config come from next to this script.
HERE="$(cd "$(dirname "$0")" && pwd)"
PUBKEY_DEFAULT="RWQSVukPYI4mZximvuqnLSiH56cyTwz6uEWQEFyWDhqvpBHC8DdyYK5T"
PUBKEY="${TELLTALE_RELEASE_PUBKEY:-$PUBKEY_DEFAULT}"
PREFIX="${TELLTALE_PREFIX:-/usr/local}"
CHANNEL=stable
DISABLE_STUB=ask
START=yes

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --edge) CHANNEL=edge ;;
    --disable-resolved-stub) DISABLE_STUB=yes ;;
    --no-start) START=no ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo sh install.sh)"
[ "$(uname -s)" = Linux ] || die "Linux only"
command -v systemctl >/dev/null || die "systemd is required (or use the container image)"

case "$(uname -m)" in
  x86_64|amd64) ASSET=telltale-x86_64-linux ;;
  aarch64|arm64) ASSET=telltale-aarch64-linux ;;
  armv7l|armv8l) ASSET=telltale-armv7-linux ;;
  armv6l) die "ARMv6 (Pi Zero W / Pi 1) isn't supported; a Pi Zero 2 W, 3, 4, or 5 is" ;;
  *) die "no release binary for $(uname -m)" ;;
esac

if [ -n "${TELLTALE_RELEASE_URL:-}" ]; then
  BASE="$TELLTALE_RELEASE_URL"
elif [ "$CHANNEL" = edge ]; then
  BASE="https://github.com/paimonsoror/telltaledns/releases/download/edge"
else
  BASE="https://github.com/paimonsoror/telltaledns/releases/latest/download"
fi

fetch() { # url dest
  if command -v curl >/dev/null; then curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null; then wget -q -O "$2" "$1"
  else die "curl or wget is required"; fi
}

if ! command -v minisign >/dev/null; then
  say "Installing minisign (verifies the release signature)"
  if command -v apt-get >/dev/null; then apt-get install -y -qq minisign >/dev/null
  elif command -v dnf >/dev/null; then dnf install -y -q minisign
  elif command -v apk >/dev/null; then apk add -q minisign
  elif command -v pacman >/dev/null; then pacman -S --noconfirm --needed minisign >/dev/null
  fi
  command -v minisign >/dev/null || die "minisign is required to verify the download; install it and re-run"
fi

TMP="$(mktemp -d)"
trap 'rm -r "$TMP"' EXIT

say "Downloading $ASSET ($CHANNEL) from $BASE"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || {
  [ "$CHANNEL" = stable ] && [ -z "${TELLTALE_RELEASE_URL:-}" ] \
    && die "no stable release found (there may not be one yet): try --edge"
  die "cannot download $BASE/SHA256SUMS"
}
fetch "$BASE/SHA256SUMS.minisig" "$TMP/SHA256SUMS.minisig"
minisign -Vq -P "$PUBKEY" -m "$TMP/SHA256SUMS" -x "$TMP/SHA256SUMS.minisig" \
  || die "the release signature doesn't verify: not installing"
fetch "$BASE/$ASSET" "$TMP/$ASSET"
want="$(awk -v a="$ASSET" '$2 == a || $2 == "*" a { print $1 }' "$TMP/SHA256SUMS")"
[ -n "$want" ] || die "SHA256SUMS has no entry for $ASSET"
got="$(sha256sum "$TMP/$ASSET" | cut -d' ' -f1)"
[ "$want" = "$got" ] || die "checksum mismatch for $ASSET: not installing"
chmod 755 "$TMP/$ASSET"
"$TMP/$ASSET" --version >/dev/null || die "the downloaded binary doesn't run on this machine"
say "Verified $("$TMP/$ASSET" --version) (signature and SHA-256)"

if ! id telltale >/dev/null 2>&1; then
  say "Creating the telltale system user"
  useradd --system --home-dir /var/lib/telltale --no-create-home --shell /usr/sbin/nologin telltale 2>/dev/null \
    || adduser --system --home /var/lib/telltale --no-create-home --shell /usr/sbin/nologin --group telltale
fi
getent group telltale >/dev/null || groupadd --system telltale

install -d -m 0755 "$PREFIX/bin"
install -m 0755 "$TMP/$ASSET" "$PREFIX/bin/telltale.new"
mv -f "$PREFIX/bin/telltale.new" "$PREFIX/bin/telltale"   # atomic swap

install -d -m 0750 -o root -g telltale /etc/telltale
if [ ! -f /etc/telltale/telltale.toml ]; then
  say "Writing a starter config to /etc/telltale/telltale.toml"
  if [ -f "$HERE/../compose/telltale.toml" ]; then cp "$HERE/../compose/telltale.toml" "$TMP/telltale.toml"
  else fetch "$REPO_RAW/deploy/compose/telltale.toml" "$TMP/telltale.toml"; fi
  install -m 0640 -o root -g telltale "$TMP/telltale.toml" /etc/telltale/telltale.toml
fi
"$PREFIX/bin/telltale" config check /etc/telltale/telltale.toml >/dev/null \
  || die "/etc/telltale/telltale.toml has errors (telltale config check /etc/telltale/telltale.toml)"

UNIT=/etc/systemd/system/telltale.service
if [ -f "$HERE/telltale.service" ]; then cp "$HERE/telltale.service" "$TMP/telltale.service"
else fetch "$REPO_RAW/deploy/systemd/telltale.service" "$TMP/telltale.service"; fi
sed "s#/usr/local/bin/telltale#$PREFIX/bin/telltale#" "$TMP/telltale.service" > "$UNIT"
systemctl daemon-reload

# systemd-resolved's stub listener holds 127.0.0.53:53, which blocks binding 0.0.0.0:53.
if systemctl is-active --quiet systemd-resolved 2>/dev/null \
   && ! grep -qs '^DNSStubListener=no' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/*.conf; then
  if [ "$DISABLE_STUB" = ask ] && [ -t 0 ]; then
    printf 'systemd-resolved is listening on 127.0.0.53:53. Turn its stub listener off so TelltaleDNS can use port 53? [Y/n] '
    read -r answer
    case "$answer" in n|N|no) DISABLE_STUB=no ;; *) DISABLE_STUB=yes ;; esac
  fi
  if [ "$DISABLE_STUB" = yes ]; then
    say "Turning off systemd-resolved's stub listener (this machine now resolves through TelltaleDNS)"
    install -d /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNSStubListener=no\nDNS=127.0.0.1\n' > /etc/systemd/resolved.conf.d/telltale.conf
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
  else
    say "Leaving systemd-resolved as is: if port 53 is busy, set [[listen]] to this machine's LAN address"
  fi
fi

if [ "$START" = yes ]; then
  systemctl enable --now telltale >/dev/null 2>&1 || true
  systemctl restart telltale
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    "$PREFIX/bin/telltale" health >/dev/null 2>&1 && break
    sleep 1
  done
  if "$PREFIX/bin/telltale" health >/dev/null 2>&1; then
    say "TelltaleDNS is running"
  else
    systemctl --no-pager status telltale | tail -n 15 || true
    die "the service didn't become ready (journalctl -u telltale)"
  fi
  ip="$(hostname -I 2>/dev/null | cut -d' ' -f1)"
  cat <<EOF

  Web UI:      http://${ip:-<this machine>}:8053/
  First admin: sudo -u telltale $PREFIX/bin/telltale auth setup-token -c /etc/telltale/telltale.toml
  Test:        dig @${ip:-127.0.0.1} example.com
  Updates:     sudo telltale self-update --restart   (--channel edge for builds from main)
  Then point your router's DHCP DNS setting at ${ip:-this machine}.
EOF
fi
