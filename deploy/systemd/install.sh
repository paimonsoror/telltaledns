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
# In a terminal, a new install first asks: the recommended settings (press Enter), or a walk
# through the options (builds, upstreams, blocklists, the listen address, systemd-resolved, the
# first admin, the query log), each with its default (Enter or `skip` keeps it).
#
# Options:
#   --edge                   follow builds from main instead of tagged releases
#   --yes                    ask nothing: the recommended settings
#   --interactive            ask even without a terminal, reading answers from stdin
#   --config-only FILE       ask, write the config to FILE, and stop (no root needed)
#   --disable-resolved-stub  turn off systemd-resolved's stub listener on 127.0.0.53:53
#                            (needed when it holds port 53; asked interactively otherwise)
#   --no-start               install but don't enable or start the service
#   --uninstall              stop and remove the service, its unit, and the binary; offers to
#                            restore systemd-resolved if the install changed it, and keeps
#                            /etc/telltale and /var/lib/telltale unless you say otherwise
#   --purge                  with --uninstall: also delete the config, the data, and the user
#   --keep-resolver          with --uninstall: leave systemd-resolved as the install set it
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
INTERACTIVE=auto
CONFIG_ONLY=
UNINSTALL=no
PURGE=ask
RESTORE_RESOLVER=ask

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --edge) CHANNEL=edge ;;
    --disable-resolved-stub) DISABLE_STUB=yes ;;
    --no-start) START=no ;;
    --yes|-y) INTERACTIVE=no ;;
    --interactive) INTERACTIVE=yes ;;
    --config-only) shift; [ $# -gt 0 ] || die "--config-only needs a file"; CONFIG_ONLY=$1 ;;
    --uninstall) UNINSTALL=yes ;;
    --purge) PURGE=yes ;;
    --keep-resolver) RESTORE_RESOLVER=no ;;
    -h|--help) sed -n '2,/^set -eu$/{/^#/p;}' "$0"; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
  shift
done

if [ -z "$CONFIG_ONLY" ]; then
  [ "$(id -u)" -eq 0 ] || die "run as root (sudo sh install.sh)"
  [ "$(uname -s)" = Linux ] || die "Linux only"
  command -v systemctl >/dev/null || die "systemd is required (or use the container image)"
fi

# Questions only for a new install, and only in a terminal (or with --interactive).
ASK=no
if [ -n "$CONFIG_ONLY" ] || [ ! -f /etc/telltale/telltale.toml ]; then
  case "$INTERACTIVE" in
    yes) ASK=yes ;;
    auto) if [ -t 0 ]; then ASK=yes; fi ;;
  esac
fi

# REQ: OPS-001, DOC-001 (T7.6) — the guided setup. In a terminal, a new install asks first:
# the recommended settings (Enter) or a walk through the options, each with its default shown
# (Enter or `skip` keeps it). Piped or automated installs (no terminal), --yes, and re-runs
# over an existing config ask nothing and behave as before. --interactive asks even without a
# terminal, reading the answers from stdin (for automation and tests).

# One answer: REPLY is the reply, or the default for Enter, `skip`, or the end of input.
ask() { # prompt default
  printf '%s [%s]: ' "$1" "$2"
  if ! IFS= read -r REPLY; then REPLY=; echo; fi
  REPLY="$(printf '%s' "$REPLY" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  case "$REPLY" in ''|skip|s|S) REPLY="$2" ;; esac
}

# A number from 1 to max (or 0 when zero is allowed); asks again on anything else, then gives up
# on the default after three tries (so piped answers can't loop).
choose() { # prompt default max [allow-zero]
  _tries=0
  while :; do
    ask "$1" "$2"
    case "$REPLY" in
      *[!0-9]*|'') ;;
      *) if [ "$REPLY" -le "$3" ] && { [ "$REPLY" -ge 1 ] || [ "${4:-}" = zero ]; }; then return; fi ;;
    esac
    _tries=$((_tries + 1))
    if [ "$_tries" -ge 3 ]; then REPLY="$2"; return; fi
    if [ "${4:-}" = zero ]; then echo "  Please type a number from 0 to $3."; else echo "  Please type a number from 1 to $3."; fi
  done
}

yes_no() { # prompt default(y/n) → 0 for yes
  ask "$1 (y/n)" "$2"
  case "$REPLY" in y|Y|yes|Yes|YES) return 0 ;; *) return 1 ;; esac
}

# The drop-in the install writes when it turns systemd-resolved's stub listener off; it also
# records what /etc/resolv.conf was, for --uninstall.
RESOLVED_DROPIN=/etc/systemd/resolved.conf.d/telltale.conf
RESOLV_BACKUP=/etc/resolv.conf.telltale-backup

# REQ: OPS-004 (T9.21) — puts systemd-resolved back as it was before the install: its stub
# listener on, and /etc/resolv.conf pointing where it did (the recorded link, the backed-up
# file, or, for installs from before the record, the usual stub link).
restore_resolver() {
  was="$(sed -n 's/^# resolv.conf was: //p' "$RESOLVED_DROPIN" 2>/dev/null | head -n 1)"
  rm -f "$RESOLVED_DROPIN"
  if [ "$was" = file ] && [ -f "$RESOLV_BACKUP" ]; then
    mv -f "$RESOLV_BACKUP" /etc/resolv.conf
  elif [ -n "$was" ] && [ "$was" != file ]; then
    ln -sf "$was" /etc/resolv.conf
  elif [ -e /run/systemd/resolve/stub-resolv.conf ]; then
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
  fi
  systemctl restart systemd-resolved 2>/dev/null || true
  say "Restored systemd-resolved: this machine resolves through it again ($(readlink /etc/resolv.conf 2>/dev/null || echo /etc/resolv.conf))"
}

# REQ: OPS-004 (T9.21) — `--uninstall`: the reverse of an install. Asks (in a terminal) whether
# to restore systemd-resolved (if the install changed it) and whether to delete the config and
# data; without a terminal (or with --yes), restores the resolver and keeps the config and data.
uninstall() {
  [ "$(id -u)" -eq 0 ] || die "run as root (sudo sh install.sh --uninstall)"
  asking=no
  case "$INTERACTIVE" in
    yes) asking=yes ;;
    auto) if [ -t 0 ]; then asking=yes; fi ;;
  esac
  if [ -f "$RESOLVED_DROPIN" ] && [ "$RESTORE_RESOLVER" = ask ]; then
    RESTORE_RESOLVER=yes
    if [ "$asking" = yes ]; then
      echo "The install turned off systemd-resolved's stub listener so TelltaleDNS could use port 53,"
      echo "and pointed this machine's own lookups at TelltaleDNS. Without TelltaleDNS, they'd go nowhere."
      yes_no "Restore systemd-resolved as this machine's resolver?" y || RESTORE_RESOLVER=no
    fi
  fi
  if [ "$PURGE" = ask ]; then
    PURGE=no
    if [ "$asking" = yes ] && { [ -d /etc/telltale ] || [ -d /var/lib/telltale ]; }; then
      yes_no "Also delete the configuration and data (/etc/telltale, /var/lib/telltale: users, query log, lists)?" n \
        && PURGE=yes
    fi
  fi

  if systemctl list-unit-files telltale.service >/dev/null 2>&1; then
    say "Stopping and removing the telltale service"
    systemctl disable --now telltale >/dev/null 2>&1 || true
  fi
  rm -f /etc/systemd/system/telltale.service
  rm -rf /etc/systemd/system/telltale.service.d
  systemctl daemon-reload
  systemctl reset-failed telltale >/dev/null 2>&1 || true
  rm -f "$PREFIX/bin/telltale" "$PREFIX/bin/telltale.old" "$PREFIX/bin/telltale.new"
  say "Removed $PREFIX/bin/telltale"

  if [ -f "$RESOLVED_DROPIN" ]; then
    if [ "$RESTORE_RESOLVER" = yes ]; then
      restore_resolver
    else
      say "Left systemd-resolved as the install set it: $RESOLVED_DROPIN still points lookups at 127.0.0.1"
    fi
  fi

  if [ "$PURGE" = yes ]; then
    rm -rf /etc/telltale /var/lib/telltale
    userdel telltale >/dev/null 2>&1 || true
    groupdel telltale >/dev/null 2>&1 || true
    say "Deleted /etc/telltale, /var/lib/telltale, and the telltale user"
  else
    say "Kept /etc/telltale and /var/lib/telltale (a later install picks them up; --purge deletes them)"
  fi
  say "TelltaleDNS is uninstalled. Point your router's DNS setting back at your previous server if it used this machine."
}

if [ "$UNINSTALL" = yes ]; then
  uninstall
  exit 0
fi

# Defaults: what a plain `sudo sh install.sh` has always installed.
UPSTREAMS=1
LISTS=1
LISTEN_IP=
STUB_ANSWER=yes
ADMIN=token
ADMIN_USER=admin
ADMIN_PASS=
RETENTION=7
PRIVACY=0
CUSTOM_URL=
CUSTOM_SNI=

upstream_label() {
  case "$1" in
    1) echo "Cloudflare and Quad9, encrypted (DNS over TLS), whichever is faster" ;;
    2) echo "Cloudflare, encrypted" ;;
    3) echo "Quad9, encrypted (also blocks known malware domains)" ;;
    4) echo "Google, encrypted" ;;
    5) echo "Mullvad, encrypted" ;;
    6) echo "AdGuard, encrypted (also blocks ads)" ;;
    7) echo "Cloudflare and Quad9, plain DNS (for networks that block port 853)" ;;
    8) echo "your own: $CUSTOM_URL" ;;
  esac
}

list_label() {
  case "$1" in
    1) echo "HaGeZi Pro: ads, trackers, and more; the balanced choice" ;;
    2) echo "HaGeZi Light: fewer names, the safest picks" ;;
    3) echo "HaGeZi Pro++: stricter, may need an occasional allow" ;;
    4) echo "HaGeZi Threat Intelligence: malware, phishing, scams" ;;
    5) echo "Steven Black's unified hosts: ads and malware" ;;
    6) echo "OISD small: ads, low false positives" ;;
  esac
}

privacy_label() {
  case "$1" in
    0) echo "everything: which device asked for what" ;;
    1) echo "queries without the names asked for" ;;
    2) echo "queries without names or devices" ;;
    3) echo "counts only" ;;
  esac
}

guided() {
  echo
  echo "Press Enter (or type skip) to keep the value in [brackets]."
  echo
  echo "1. Builds"
  echo "   1) Releases (tested, tagged versions)"
  echo "   2) Edge (every build from main: newest features, less tested)"
  if [ "$CHANNEL" = edge ]; then _d=2; else _d=1; fi
  choose "   Which" "$_d" 2
  if [ "$REPLY" = 2 ]; then CHANNEL=edge; else CHANNEL=stable; fi

  echo
  echo "2. Where answers come from (upstream DNS servers)"
  for i in 1 2 3 4 5 6 7; do echo "   $i) $(upstream_label "$i")"; done
  echo "   8) Your own server (an address like 192.168.1.1, tls://..., or https://...)"
  choose "   Which" "$UPSTREAMS" 8
  UPSTREAMS=$REPLY
  if [ "$UPSTREAMS" = 8 ]; then
    ask "   Address" "udp://192.168.1.1"
    CUSTOM_URL=$REPLY
    case "$CUSTOM_URL" in *://*) ;; *) CUSTOM_URL="udp://$CUSTOM_URL" ;; esac
    case "$CUSTOM_URL" in
      tls://[0-9]*|quic://[0-9]*)
        ask "   Name on its TLS certificate (e.g. dns.example.com)" "none"
        [ "$REPLY" = none ] || CUSTOM_SNI=$REPLY ;;
    esac
  fi

  echo
  echo "3. Starting blocklists (more can be added later on the Lists page)"
  for i in 1 2 3 4 5 6; do echo "   $i) $(list_label "$i")"; done
  echo "   0) None for now"
  _ok=no
  _tries=0
  while [ "$_ok" = no ]; do
    ask "   Which (one or more, e.g. 1 4)" "$LISTS"
    _ok=yes
    for n in $(printf '%s' "$REPLY" | tr ',' ' '); do
      case "$n" in [0-6]) ;; *) _ok=no ;; esac
    done
    _tries=$((_tries + 1))
    if [ "$_ok" = no ] && [ "$_tries" -ge 3 ]; then REPLY=$LISTS; _ok=yes; fi
    if [ "$_ok" = no ]; then echo "  Please type numbers from 0 to 6."; fi
  done
  LISTS=$(printf '%s' "$REPLY" | tr ',' ' ' | tr -s ' ')
  case " $LISTS " in *" 0 "*) LISTS=0 ;; esac

  echo
  echo "4. Where DNS listens"
  echo "   1) Every address of this machine, port 53"
  echo "   2) One address only"
  choose "   Which" 1 2
  if [ "$REPLY" = 2 ]; then
    _ip="$(hostname -I 2>/dev/null | cut -d' ' -f1)"
    ask "   Address" "${_ip:-127.0.0.1}"
    LISTEN_IP=$REPLY
  fi

  echo
  echo "5. systemd-resolved (Ubuntu, Debian, and others run it on 127.0.0.53:53)"
  if yes_no "   If it holds port 53, turn its stub listener off so TelltaleDNS can use it?" y; then
    STUB_ANSWER=yes
  else
    STUB_ANSWER=no
  fi

  echo
  echo "6. The first admin"
  echo "   1) Later: open the web UI and use a one-time setup token"
  echo "   2) Now: choose a username and password"
  choose "   Which" 1 2
  if [ "$REPLY" = 2 ]; then
    ADMIN=create
    ask "   Username" "admin"
    ADMIN_USER=$REPLY
    while :; do
      printf '   Password (at least 10 characters): '
      if [ -t 0 ]; then stty -echo 2>/dev/null || true; fi
      IFS= read -r ADMIN_PASS || ADMIN_PASS=
      printf '\n   Again: '
      IFS= read -r _again || _again=
      if [ -t 0 ]; then stty echo 2>/dev/null || true; fi
      echo
      if [ "${#ADMIN_PASS}" -lt 10 ]; then echo "   Too short."
      elif [ "$ADMIN_PASS" != "$_again" ]; then echo "   They don't match."
      else break; fi
      if [ ! -t 0 ]; then echo "   Falling back to a setup token."; ADMIN=token; break; fi
    done
  fi

  echo
  echo "7. The query log"
  _tries=0
  while :; do
    ask "   Keep it for how many days" "$RETENTION"
    case "$REPLY" in *[!0-9]*|'') ;; *) [ "$REPLY" -ge 1 ] && [ "$REPLY" -le 400 ] && break ;; esac
    _tries=$((_tries + 1))
    if [ "$_tries" -ge 3 ]; then REPLY=$RETENTION; break; fi
    echo "  Please type a number of days from 1 to 400."
  done
  RETENTION=$REPLY
  echo "   What it records:"
  for i in 0 1 2 3; do echo "   $i) $(privacy_label "$i")"; done
  choose "   Which" "$PRIVACY" 3 zero
  PRIVACY=$REPLY
}

summary() {
  echo
  echo "Summary:"
  echo "  Builds:      $([ "$CHANNEL" = edge ] && echo edge || echo releases)"
  echo "  Upstreams:   $(upstream_label "$UPSTREAMS")"
  if [ "$LISTS" = 0 ]; then echo "  Blocklists:  none for now"
  else for n in $LISTS; do echo "  Blocklist:   $(list_label "$n")"; done; fi
  echo "  DNS listens: ${LISTEN_IP:-every address}, port 53"
  echo "  resolved:    $([ "$STUB_ANSWER" = yes ] && echo "turn its stub listener off if it holds port 53" || echo "leave it as is")"
  echo "  First admin: $([ "$ADMIN" = create ] && echo "$ADMIN_USER (created now)" || echo "a setup token for the web UI")"
  echo "  Query log:   $RETENTION days; $(privacy_label "$PRIVACY")"
}

# The answers as a starter telltale.toml.
write_config() { # file
  {
    echo "# TelltaleDNS config written by install.sh (guided setup). Every key is optional: see"
    echo "# docs/configuration.md. Check edits with: telltale config check /etc/telltale/telltale.toml"
    echo "# Upstreams, lists, and groups can also be changed in the web UI (http://<this machine>:8053/)."
    echo "config_version = 1"
    if [ -n "$LISTEN_IP" ]; then
      for p in udp tcp; do
        printf '\n[[listen]]\nproto = "%s"\naddr = "%s"\n' "$p" "$(case "$LISTEN_IP" in *:*) printf '[%s]:53' "$LISTEN_IP" ;; *) printf '%s:53' "$LISTEN_IP" ;; esac)"
      done
    fi
    echo
    echo "# Where answers come from: $(upstream_label "$UPSTREAMS")."
    up() { # name url [tls name]
      printf '[[upstream]]\nname = "%s"\nurl = "%s"\n' "$1" "$2"
      if [ -n "${3:-}" ]; then printf 'tls_server_name = "%s"\n' "$3"; fi
      echo
    }
    case "$UPSTREAMS" in
      1) up cloudflare "tls://1.1.1.1:853" cloudflare-dns.com; up quad9 "tls://9.9.9.9:853" dns.quad9.net; M='"cloudflare", "quad9"' ;;
      2) up cloudflare "tls://1.1.1.1:853" cloudflare-dns.com; up cloudflare-2 "tls://1.0.0.1:853" cloudflare-dns.com; M='"cloudflare", "cloudflare-2"' ;;
      3) up quad9 "tls://9.9.9.9:853" dns.quad9.net; up quad9-2 "tls://149.112.112.112:853" dns.quad9.net; M='"quad9", "quad9-2"' ;;
      4) up google "tls://8.8.8.8:853" dns.google; up google-2 "tls://8.8.4.4:853" dns.google; M='"google", "google-2"' ;;
      5) up mullvad "tls://194.242.2.2:853" dns.mullvad.net; M='"mullvad"' ;;
      6) up adguard "tls://94.140.14.14:853" dns.adguard-dns.com; up adguard-2 "tls://94.140.15.15:853" dns.adguard-dns.com; M='"adguard", "adguard-2"' ;;
      7) up cloudflare "udp://1.1.1.1"; up quad9 "udp://9.9.9.9"; M='"cloudflare", "quad9"' ;;
      8) up mine "$CUSTOM_URL" "$CUSTOM_SNI"; M='"mine"' ;;
    esac
    case "$M" in *,*) S=fastest ;; *) S=failover ;; esac
    printf '[[upstream_group]]\nname = "default"\nmembers = [%s]\nstrategy = "%s"\n' "$M" "$S"
    HG="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock"
    if [ "$LISTS" != 0 ]; then
      for n in $LISTS; do
        echo
        echo "# $(list_label "$n")."
        case "$n" in
          1) printf '[[list]]\nname = "hagezi-pro"\nurl = "%s/pro.txt"\n' "$HG" ;;
          2) printf '[[list]]\nname = "hagezi-light"\nurl = "%s/light.txt"\n' "$HG" ;;
          3) printf '[[list]]\nname = "hagezi-pro-plus"\nurl = "%s/pro.plus.txt"\n' "$HG" ;;
          4) printf '[[list]]\nname = "hagezi-tif"\nurl = "%s/tif.txt"\n' "$HG" ;;
          5) printf '[[list]]\nname = "stevenblack"\nurl = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"\n' ;;
          6) printf '[[list]]\nname = "oisd-small"\nurl = "https://small.oisd.nl/"\n' ;;
        esac
      done
    fi
    echo
    echo "# The query log: kept $RETENTION days; it records $(privacy_label "$PRIVACY")."
    printf '[telemetry.qlog]\nretention_days = %s\n' "$RETENTION"
    if [ "$PRIVACY" != 0 ]; then printf 'privacy_level = %s\n' "$PRIVACY"; fi
  } > "$1"
}

GUIDED=no
if [ "$ASK" = yes ]; then
  echo "Welcome to TelltaleDNS."
  echo "  1) Install with the recommended settings (encrypted upstreams, a balanced blocklist)"
  echo "  2) Walk me through the options"
  choose "Which" 1 2
  if [ "$REPLY" = 2 ]; then
    GUIDED=yes
    guided
    summary
    if ! yes_no "Install with these settings?" y; then
      echo "Nothing was installed."
      exit 0
    fi
  fi
  DISABLE_STUB=$STUB_ANSWER
fi
if [ -n "$CONFIG_ONLY" ]; then
  if [ "$GUIDED" = yes ]; then write_config "$CONFIG_ONLY"
  else cp "$HERE/../compose/telltale.toml" "$CONFIG_ONLY"; fi
  echo "Wrote $CONFIG_ONLY"
  exit 0
fi

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
  if [ "$GUIDED" = yes ]; then write_config "$TMP/telltale.toml"
  elif [ -f "$HERE/../compose/telltale.toml" ]; then cp "$HERE/../compose/telltale.toml" "$TMP/telltale.toml"
  else fetch "$REPO_RAW/deploy/compose/telltale.toml" "$TMP/telltale.toml"; fi
  install -m 0640 -o root -g telltale "$TMP/telltale.toml" /etc/telltale/telltale.toml
fi
"$PREFIX/bin/telltale" config check /etc/telltale/telltale.toml >/dev/null \
  || die "/etc/telltale/telltale.toml has errors (telltale config check /etc/telltale/telltale.toml)"

UNIT=/etc/systemd/system/telltale.service
if [ -f "$HERE/telltale.service" ]; then cp "$HERE/telltale.service" "$TMP/telltale.service"
else fetch "$REPO_RAW/deploy/systemd/telltale.service" "$TMP/telltale.service"; fi
sed "s#/usr/local/bin/telltale#$PREFIX/bin/telltale#" "$TMP/telltale.service" > "$UNIT"
# The first admin, when chosen in the guided setup: its Argon2id hash goes to the service for
# its first start only (a root-only drop-in, removed once the service is up).
DROPIN=/etc/systemd/system/telltale.service.d/10-first-admin.conf
if [ "$ADMIN" = create ]; then
  hash="$(printf '%s\n' "$ADMIN_PASS" | "$PREFIX/bin/telltale" auth hash-password)" \
    || die "couldn't hash the admin password"
  install -d -m 0755 "$(dirname "$DROPIN")"
  ( umask 077; printf '[Service]\nEnvironment="TELLTALE_BOOTSTRAP_ADMIN_USER=%s"\nEnvironment="TELLTALE_BOOTSTRAP_ADMIN_PASSWORD_HASH=%s"\n' \
      "$ADMIN_USER" "$hash" > "$DROPIN" )
  ADMIN_PASS=
fi
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
    # REQ: OPS-004 (T9.21) — what /etc/resolv.conf was, so --uninstall can put it back.
    if [ -L /etc/resolv.conf ]; then was="$(readlink /etc/resolv.conf)"
    elif [ -f /etc/resolv.conf ]; then cp -p /etc/resolv.conf "$RESOLV_BACKUP"; was=file
    else was=; fi
    printf '# Written by TelltaleDNS install.sh; install.sh --uninstall removes it.\n# resolv.conf was: %s\n[Resolve]\nDNSStubListener=no\nDNS=127.0.0.1\n' \
      "$was" > "$RESOLVED_DROPIN"
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
  if [ -f "$DROPIN" ]; then rm -f "$DROPIN"; systemctl daemon-reload; fi
  if "$PREFIX/bin/telltale" health >/dev/null 2>&1; then
    say "TelltaleDNS is running"
  else
    systemctl --no-pager status telltale | tail -n 15 || true
    die "the service didn't become ready (journalctl -u telltale)"
  fi
  ip="$(hostname -I 2>/dev/null | cut -d' ' -f1)"
  if [ "$ADMIN" = create ]; then first="sign in as $ADMIN_USER"
  else first="sudo -u telltale $PREFIX/bin/telltale auth setup-token -c /etc/telltale/telltale.toml"; fi
  cat <<EOF

  Web UI:      http://${ip:-<this machine>}:8053/
  First admin: $first
  Test:        dig @${ip:-127.0.0.1} example.com
  Updates:     sudo telltale self-update --restart   (--channel edge for builds from main)
  Then point your router's DHCP DNS setting at ${ip:-this machine}.
EOF
fi
