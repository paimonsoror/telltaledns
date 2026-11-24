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
#   --stable                 follow tagged releases (the default). With --cluster-updates on a node
#                            that runs an edge build, one of --edge or --stable must be given.
#   --yes                    skip the guided questions: the recommended settings. (In a terminal,
#                            the one about systemd-resolved's stub listener is still asked,
#                            unless --disable-resolved-stub answers it.)
#   --interactive            ask even without a terminal, reading answers from stdin
#   --config-only FILE       ask, write the config to FILE, and stop (no root needed)
#   --disable-resolved-stub  turn off systemd-resolved's stub listener on 127.0.0.53:53
#                            (needed when it holds port 53; asked interactively otherwise).
#                            The install then waits (up to 15 s) for port 53 to be free before
#                            it starts the service, and says what holds it if it isn't.
#   --no-start               install but don't enable or start the service
#   --cluster-updates        let the cluster install newer versions on this node: enables
#                            telltale-update.path (REQ: OPS-014). Off by default; re-runs keep
#                            whatever it is. `telltale ctl upgrade` and the Helm chart's
#                            upgradeHook use it. The units are written for the config's
#                            [node] data_dir (they watch <data_dir>/update/ only), its [api]
#                            address (the health check after an update), and the update channel
#                            (--edge: edge, else the installed version's). Refused when the
#                            binary's folder isn't root's alone, the data directory is under
#                            /home or /root or in a folder that isn't root's, the API is off, or
#                            the node doesn't answer at its [api] address; and on a node that
#                            runs an edge build unless --edge (stay on edge) or --stable is given.
#   --uninstall              stop and remove the service, its unit, and the binary; offers to
#                            restore systemd-resolved if the install changed it, and keeps
#                            /etc/telltale and /var/lib/telltale unless you say otherwise
#   --purge                  with --uninstall: also delete the config, the data, and the user
#   --keep-resolver          with --uninstall: leave systemd-resolved as the install set it
# Environment (mirrors and tests): TELLTALE_RELEASE_URL (base URL of the release files),
# TELLTALE_RELEASE_PUBKEY (minisign public key), TELLTALE_PREFIX (default /usr/local),
# TELLTALE_PORT_WAIT (seconds to wait for port 53 after turning the stub listener off; default 15).
set -eu

REPO_RAW="https://raw.githubusercontent.com/paimonsoror/telltaledns/main"
# Run from a checkout (or the tests), the unit and starter config come from next to this script.
HERE="$(cd "$(dirname "$0")" && pwd)"
PUBKEY_DEFAULT="RWQSVukPYI4mZximvuqnLSiH56cyTwz6uEWQEFyWDhqvpBHC8DdyYK5T"
PUBKEY="${TELLTALE_RELEASE_PUBKEY:-$PUBKEY_DEFAULT}"
PREFIX="${TELLTALE_PREFIX:-/usr/local}"
CHANNEL=stable
CHANNEL_FLAG=
DISABLE_STUB=ask
START=yes
INTERACTIVE=auto
CONFIG_ONLY=
UNINSTALL=no
PURGE=ask
RESTORE_RESOLVER=ask
WAIT_PORT53=no
CLUSTER_UPDATES=no

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --edge) CHANNEL=edge; CHANNEL_FLAG=edge ;;
    --stable) CHANNEL=stable; CHANNEL_FLAG=stable ;;
    --disable-resolved-stub) DISABLE_STUB=yes ;;
    --no-start) START=no ;;
    --cluster-updates) CLUSTER_UPDATES=yes ;;
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
# over an existing config skip these questions and behave as before (in a terminal, the one about
# systemd-resolved's stub listener is still asked below). --interactive asks even without a
# terminal, reading the answers from stdin (for automation and tests).

# One answer: REPLY is the reply, or the default for Enter, `skip`, or the end of input.
ask() { # prompt default
  printf '%s [%s]: ' "$1" "$2"
  if ! IFS= read -r REPLY; then REPLY=; echo; fi
  REPLY="$(printf '%s' "$REPLY" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  case "$REPLY" in ''|skip|s|S) REPLY="$2" ;; esac
}

# REPLY, when it is a whole number, without its leading zeros (`08` is 8, `007` is 7, `00` is 0).
# `[ -le ]` reads them as decimal, but the answers go on as text: `08` would match no `case` (no
# upstream, so the config couldn't be written) and `retention_days = 007` isn't valid TOML.
plain_number() {
  case "$REPLY" in ''|*[!0123456789]*) return 0 ;; esac
  while [ "${#REPLY}" -gt 1 ] && [ "${REPLY#0}" != "$REPLY" ]; do REPLY="${REPLY#0}"; done
}

# A number from 1 to max (or 0 when zero is allowed); asks again on anything else, then gives up
# on the default after three tries (so piped answers can't loop).
choose() { # prompt default max [allow-zero]
  _tries=0
  while :; do
    ask "$1" "$2"
    plain_number
    case "$REPLY" in
      *[!0123456789]*|'') ;;
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
  systemctl disable --now telltale-update.path >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/telltale.service /etc/systemd/system/telltale-update.path \
    /etc/systemd/system/telltale-update.service
  rm -rf /etc/systemd/system/telltale.service.d /var/lib/telltale-update
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
  CHANNEL_FLAG=$CHANNEL

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
    plain_number
    case "$REPLY" in *[!0123456789]*|'') ;; *) [ "$REPLY" -ge 1 ] && [ "$REPLY" -le 400 ] && break ;; esac
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

# BEGIN update-units — REQ: OPS-014 (ADR-182). deploy/systemd/update-units-test.sh cuts this block
# out and runs it with configs of its own, so keep it self-contained (it needs only $PREFIX).
# The node's data directory, from its effective config (the binary prints it), or the default when
# the config names none. The root update service watches and writes only <data_dir>/update/, and
# the path goes into its units as written, so it must be plain: absolute, of letters, digits, `.`,
# `_`, `-` and `/`, without `.` or `..` parts. Fails (prints nothing) otherwise. (The character
# lists are spelled out, not ranges: what a range holds depends on the locale and the shell.)
update_data_dir() { # config
  _cfg="$("$PREFIX/bin/telltale" config check "$1" --no-env --print 2>/dev/null)" || return 1
  _dd="$(printf '%s\n' "$_cfg" | awk '
    /^\[node\]/ { on = 1; next }
    /^\[/ { on = 0; next }
    on && /^data_dir[ \t]*=/ { v = $0; sub(/^[^=]*=[ \t]*"/, "", v); sub(/".*$/, "", v); print v; exit }')" || return 1
  [ -n "$_dd" ] || _dd=/var/lib/telltale
  while [ "${#_dd}" -gt 1 ] && [ "${_dd%/}" != "$_dd" ]; do _dd="${_dd%/}"; done
  case "$_dd" in /?*) ;; *) return 1 ;; esac
  case "$_dd" in
    *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-]*) return 1 ;;
    */./*|*/../*|*/.|*/..|*//*) return 1 ;;
  esac
  printf '%s\n' "$_dd"
}

# The URL the root update service's health gate asks, from the node's effective [api] (as the
# install's own readiness wait below asks it): http://<address>:<port>/readyz?startup=1 at the
# listen address and port, a wildcard bind (0.0.0.0, [::]) asked at loopback. Prints nothing when
# the API is off ([api] enabled = false: then --cluster-updates is refused). Fails when the
# config can't be read or its listen address isn't a plain IP address and port.
update_health_url() { # config
  _cfg="$("$PREFIX/bin/telltale" config check "$1" --no-env --print 2>/dev/null)" || return 1
  _api="$(printf '%s\n' "$_cfg" | awk '
    /^\[api\]/ { on = 1; next }
    /^\[/ { on = 0; next }
    on && /^enabled[ \t]*=/ { v = $0; sub(/^[^=]*=[ \t]*/, "", v); sub(/[ \t]*$/, "", v); en = v }
    on && /^listen[ \t]*=/ { v = $0; sub(/^[^=]*=[ \t]*"/, "", v); sub(/".*$/, "", v); li = v }
    END { if (en == "") en = "true"; if (li == "") li = "0.0.0.0:8053"; print en " " li }')" || return 1
  _en="${_api%% *}"; _li="${_api#* }"
  case "$_en" in false) return 0 ;; true) ;; *) return 1 ;; esac
  _port="${_li##*:}"; _host="${_li%:*}"
  case "$_port" in ''|0*|*[!0123456789]*) return 1 ;; esac
  [ "${#_port}" -le 5 ] && [ "$_port" -le 65535 ] || return 1
  case "$_host" in
    0.0.0.0) _host=127.0.0.1 ;;
    '[::]') _host='[::1]' ;;
    \[*\])
      _in="${_host#?}"; _in="${_in%?}"
      case "$_in" in ''|*[!0123456789abcdefABCDEF:.]*) return 1 ;; esac ;;
    ''|*[!0123456789.]*) return 1 ;;
  esac
  printf 'http://%s:%s/readyz?startup=1\n' "$_host" "$_port"
}

# Whether the folder $1 (its links resolved) and every folder above it belong to root and can't be
# written by their group or others; prints the first that doesn't. The root update service runs
# and renames binaries only in such a place, and keeps its request spool only under one.
update_root_owned() { # dir
  _p="$(cd "$1" 2>/dev/null && pwd -P)" || { printf '%s\n' "$1"; return 1; }
  while :; do
    _st="$(stat -c '%u %a' "$_p" 2>/dev/null)" || { printf '%s\n' "$_p"; return 1; }
    _mode="${_st#* }"; _o="${_mode#"${_mode%?}"}"; _g="${_mode%?}"; _g="${_g#"${_g%?}"}"
    if [ "${_st%% *}" != 0 ]; then printf '%s\n' "$_p"; return 1; fi
    case "$_g$_o" in *[2367]*) printf '%s\n' "$_p"; return 1 ;; esac
    [ "$_p" != / ] || return 0
    _p="$(dirname "$_p")"
  done
}

# Why --cluster-updates can't be used with the binary in $PREFIX/bin, the data directory $1 and
# the health check's URL $2, or nothing: the binary's folder must be root's alone, the data
# directory not under /home or /root, in a folder root's alone (only its update/ folder is the
# node's to write), and the API on (its /readyz is how the update service sees a new build come up).
update_refusal() { # data-dir health-url
  _d="$PREFIX/bin"
  while [ ! -d "$_d" ]; do _d="$(dirname "$_d")"; done
  if _bad="$(update_root_owned "$_d")"; then :; else
    echo "install location is not root-owned: $_bad belongs to another user or can be written by its group or others (on older Debian and Raspberry Pi OS images /usr/local is root:staff 2775: sudo chmod g-w /usr/local /usr/local/bin, or install to a prefix only root can write with TELLTALE_PREFIX)"
    return 0
  fi
  if [ -z "$2" ]; then
    echo "the update service needs the API: it checks the node's /readyz to see that a new build came up, and [api] enabled = false leaves it nothing to ask (turn the API on, or upgrade this node by hand)"
    return 0
  fi
  case "$1/" in /home/*|/root/*)
    echo "the data directory $1 is under /home or /root: move [node] data_dir out of the home folders"
    return 0 ;;
  esac
  if _bad="$(update_root_owned "$(dirname "$1")")"; then :; else
    echo "the data directory's parent folder is not root-owned ($_bad belongs to another user or can be written by its group or others)"
  fi
}

# Why --cluster-updates can't go on over the installed binary whose version line is $2, given the
# channel flag $1 (edge, stable, or empty), or nothing: a node running an edge build needs one of
# them (without --edge, a re-run installs the newest release: an older version, and the stable
# channel).
update_channel_refusal() { # flag version-line
  [ -z "$1" ] || return 0
  case "$2" in
    *-edge.*) echo "this node runs an edge build ($2): pass --edge to stay on edge builds, or --stable to move it to the stable channel (the newest release, which may be older than the edge build you run now)" ;;
  esac
}

# The two update units from the folder $1 into the folder $2, for the binary in $PREFIX/bin, the
# data directory $3, the node's update channel $4 (edge or stable), and the health gate's URL $5
# (empty only with the API off, which --cluster-updates refuses: the service then installs nothing).
render_update_units() { # from to data-dir channel health-url
  for _u in telltale-update.path telltale-update.service; do
    sed -e "s#/usr/local/bin#$PREFIX/bin#g" -e "s#/var/lib/telltale/update#$3/update#g" \
      -e "s#^Environment=TELLTALE_UPDATE_CHANNEL=.*#Environment=TELLTALE_UPDATE_CHANNEL=$4#" \
      -e "s#^Environment=TELLTALE_UPDATE_HEALTH_URL=.*#Environment=TELLTALE_UPDATE_HEALTH_URL=$5#" \
      "$1/$_u" > "$2/$_u" || return 1
  done
}
# END update-units

# REQ: OPS-014 (ADR-182) — --cluster-updates over an existing install is refused before anything
# is downloaded or changed when the binary's folder or the data directory isn't fit for a root
# service (a new install is checked below, once its config exists).
if [ "$CLUSTER_UPDATES" = yes ] && [ -x "$PREFIX/bin/telltale" ]; then
  WHY="$(update_channel_refusal "$CHANNEL_FLAG" "$("$PREFIX/bin/telltale" --version 2>/dev/null || true)")"
  [ -z "$WHY" ] || die "--cluster-updates: $WHY. Nothing was changed."
fi
if [ "$CLUSTER_UPDATES" = yes ] && [ -x "$PREFIX/bin/telltale" ] && [ -f /etc/telltale/telltale.toml ]; then
  DATA_DIR="$(update_data_dir /etc/telltale/telltale.toml)" \
    || die "--cluster-updates needs [node] data_dir in /etc/telltale/telltale.toml to be a plain absolute path (letters, digits, . _ - /). Nothing was changed."
  HEALTH_URL_NOW="$(update_health_url /etc/telltale/telltale.toml)" \
    || die "--cluster-updates needs [api] listen in /etc/telltale/telltale.toml to be a plain IP address and port. Nothing was changed."
  WHY="$(update_refusal "$DATA_DIR" "$HEALTH_URL_NOW")"
  [ -z "$WHY" ] || die "--cluster-updates: $WHY. Nothing was changed."
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
VERSION_LINE="$("$TMP/$ASSET" --version)"
say "Verified $VERSION_LINE (signature and SHA-256)"
# REQ: OPS-014 (ADR-182) — the node's update channel, written into its unit and its update
# service's: with --edge, edge (it stays on edge builds when the cluster gives it a release);
# otherwise the channel of the version installed.
if [ "$CHANNEL" = edge ]; then
  UPDATE_CHANNEL=edge; CHANNEL_FROM="--edge"
else
  case "$VERSION_LINE" in *-edge.*) UPDATE_CHANNEL=edge ;; *) UPDATE_CHANNEL=stable ;; esac
  CHANNEL_FROM="the version installed; --edge sets edge"
fi
say "Update channel: $UPDATE_CHANNEL (from $CHANNEL_FROM)"

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
sed -e "s#/usr/local/bin/telltale#$PREFIX/bin/telltale#" \
  -e "s#^Environment=TELLTALE_UPDATE_CHANNEL=.*#Environment=TELLTALE_UPDATE_CHANNEL=$UPDATE_CHANNEL#" \
  "$TMP/telltale.service" > "$UNIT"

# REQ: OPS-014 (ADR-182) — the root update service for versions the cluster asks for (off until
# enabled), written for this node's data directory, channel, and API address.
for u in telltale-update.path telltale-update.service; do
  if [ -f "$HERE/$u" ]; then cp "$HERE/$u" "$TMP/$u"
  else fetch "$REPO_RAW/deploy/systemd/$u" "$TMP/$u"; fi
done
HEALTH_KNOWN=no
UPDATE_HEALTH_URL=
if DATA_DIR="$(update_data_dir /etc/telltale/telltale.toml)" \
   && UPDATE_HEALTH_URL="$(update_health_url /etc/telltale/telltale.toml)"; then
  HEALTH_KNOWN=yes
  if [ "$CLUSTER_UPDATES" = yes ]; then
    WHY="$(update_refusal "$DATA_DIR" "$UPDATE_HEALTH_URL")"
    [ -z "$WHY" ] || die "--cluster-updates: $WHY"
  fi
  render_update_units "$TMP" /etc/systemd/system "$DATA_DIR" "$UPDATE_CHANNEL" "$UPDATE_HEALTH_URL"
else
  systemctl disable --now telltale-update.path >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/telltale-update.path /etc/systemd/system/telltale-update.service
  [ "$CLUSTER_UPDATES" = no ] \
    || die "--cluster-updates needs [node] data_dir in /etc/telltale/telltale.toml to be a plain absolute path (letters, digits, . _ - /), and [api] listen a plain IP address and port"
  say "Updates from the cluster aren't installed: [node] data_dir isn't a plain absolute path (letters, digits, . _ - /), or [api] listen isn't a plain IP address and port"
fi
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

# BEGIN port53-wait — REQ: OPS-004. deploy/systemd/portwait-test.sh cuts this block out and runs
# it against a fake `ss`, so keep it self-contained (it needs only `say` and $PREFIX).
# After systemd-resolved's stub listener is turned off, the service must not start before port 53
# is free: a start that finds it held dies at its first bind, and systemd allows five starts per
# ten seconds.

# The addresses TelltaleDNS binds on port 53, one per line, each once, from the effective config
# (the binary prints it: a `[[listen]]` table per listener, with `addr = "host:port"`). `*` stands
# for every address: when the config can't be read or `awk` fails on it, or it has no `[[listen]]`
# (then the default is every address, port 53). Nothing when the config has listeners and none is
# on port 53.
port53_binds() { # config
  _cfg="$("$PREFIX/bin/telltale" config check "$1" --no-env --print 2>/dev/null)" || { echo '*'; return 0; }
  _addrs="$(printf '%s\n' "$_cfg" | awk '
    /^\[\[listen\]\]/ { on = 1; blocks++; next }
    /^\[/ { on = 0; next }
    on && /^addr[ \t]*=/ {
      v = $0; sub(/^[^=]*=[ \t]*"/, "", v); sub(/".*$/, "", v)
      if (v ~ /:53$/) { sub(/:53$/, "", v); gsub(/[][]/, "", v); if (!seen[v]++) print v }
    }
    END { if (!blocks) print "*" }')" || { echo '*'; return 0; }
  [ -z "$_addrs" ] || printf '%s\n' "$_addrs"
}

# The `ss -p` lines on stdin whose local address (the column numbered $2) overlaps one of the
# addresses in $1: the same address, or either side is a wildcard. Lines of the process numbered
# $3 (the telltale service's own, see port53_own_pid; 0 for none) are left out.
port53_filter() { # binds column own-pid
  awk -v binds="$(printf '%s' "$1" | tr '\n' ' ')" -v col="$2" -v own="${3:-0}" '
    function wild(a) { return a == "*" || a == "0.0.0.0" || a == "::" }
    BEGIN { nb = split(binds, b, " ") }
    NF == 0 { next }
    own != 0 && index($0, "pid=" own ",") { next }
    {
      a = $col; sub(/:[0-9]+$/, "", a); gsub(/[][]/, "", a); sub(/%.*$/, "", a)
      hit = wild(a)
      for (i = 1; i <= nb && !hit; i++) if (wild(b[i]) || b[i] == a) hit = 1
      if (hit) print
    }'
}

# The UDP and TCP sockets that listen on port 53, with their processes (we run as root); fails when
# `ss` can't list them.
port53_sockets() {
  ss -Hlunp 'sport = :53' 2>/dev/null && ss -Hltnp 'sport = :53' 2>/dev/null
}

# The process id of the telltale service (0: it isn't running, or systemd can't say). An upgrade
# re-run finds the old instance on port 53; its sockets are what the `restart` below replaces, so
# they are not what the wait is for. Only the service's own process: a stray `telltale run` is.
# Read again before every look, because the service can restart during the wait (a start that
# failed at its bind is retried every two seconds): its new process is still its own.
port53_own_pid() {
  _own="$(systemctl show -p MainPID telltale 2>/dev/null | sed -n 's/^MainPID=//p')"
  case "$_own" in ''|*[!0123456789]*) _own=0 ;; esac
  echo "$_own"
}

# Whether something other than the service holds port 53 on an address TelltaleDNS binds: looks at
# the `ss -p` lines in $_socks for the addresses in $_binds, leaving out the process $_own. Returns
# 0 when something does, 1 when nothing does, 2 when `awk` failed (nothing can be said).
port53_held() {
  _held="$(printf '%s\n' "$_socks" | port53_filter "$_binds" 4 "$_own")" || return 2
  [ -n "$_held" ]
}

# The clock the wait's deadline reads: hundredths of a second since boot, from /proc/uptime (it
# never steps; a Pi without a battery clock has its time set in the middle of an install); the wall
# clock's seconds times 100 where there is no usable /proc/uptime (then it can step, and only a
# deadline that passes early or late comes of it: the poll count still ends the wait).
port53_now() {
  _up=
  if [ -r /proc/uptime ]; then read -r _up _ < /proc/uptime || _up=; fi
  _whole="${_up%%.*}"
  _frac="${_up#*.}"; [ "$_frac" != "$_up" ] || _frac=
  _frac="${_frac}00"; _frac="${_frac%"${_frac#??}"}"       # exactly two digits
  case "$_whole" in ''|*[!0123456789]*) _whole= ;; esac
  case "$_frac" in *[!0123456789]*) _whole= ;; esac
  if [ -z "$_whole" ]; then _whole="$(date +%s 2>/dev/null)" || _whole=; _frac=00; fi
  case "$_whole" in ''|*[!0123456789]*) _whole=0 ;; esac
  while [ "${#_whole}" -gt 1 ] && [ "${_whole#0}" != "$_whole" ]; do _whole="${_whole#0}"; done
  echo $((_whole * 100 + ${_frac#0}))
}

# Waits until nothing else holds UDP or TCP port 53 on an address TelltaleDNS binds (the config's
# listeners; $1 is the config file), for up to $TELLTALE_PORT_WAIT seconds (whole seconds, 0 to
# 300; default 15) by the clock, and no more polls than the seconds allow at four a second (each
# look takes time of its own, longer on a slow machine). Returns 0 when the port is free, or can't
# be checked (no `ss`, or one or the other tool fails: it says so in one line, and carries on as an
# install always did); 1 when it is still held after the wait, after printing what holds it and
# the next step.
wait_for_port53() { # config
  command -v ss >/dev/null 2>&1 || { say "ss isn't installed: not checking that port 53 is free"; return 0; }
  _binds="$(port53_binds "$1")"
  [ -n "$_binds" ] || { say "The config has no listener on port 53: not waiting for it"; return 0; }
  _own="$(port53_own_pid)"
  _socks="$(port53_sockets)" || { say "ss can't list sockets here: not checking that port 53 is free"; return 0; }
  _rc=0; port53_held || _rc=$?
  case "$_rc" in
    1) return 0 ;;
    2) say "awk can't read the socket list here: not checking that port 53 is free"; return 0 ;;
  esac
  # Plain decimal seconds. A leading zero is decimal, not octal: `08` in `$((...))` ends the shell.
  _limit="${TELLTALE_PORT_WAIT:-15}"
  while [ "${#_limit}" -gt 1 ] && [ "${_limit#0}" != "$_limit" ]; do _limit="${_limit#0}"; done
  case "$_limit" in ''|*[!0123456789]*) _limit= ;; esac
  if [ -z "$_limit" ] || [ "${#_limit}" -gt 3 ] || [ "$_limit" -gt 300 ]; then
    say "TELLTALE_PORT_WAIT=${TELLTALE_PORT_WAIT:-} isn't a whole number of seconds from 0 to 300: waiting up to 15s"
    _limit=15
  fi
  if [ "$_limit" -gt 0 ]; then say "Waiting up to ${_limit}s for port 53 to be free"; fi
  # A quarter-second step where `sleep` takes fractions, else a second: the limit holds either way.
  if sleep 0.1 2>/dev/null; then _step=0.25; _left=$((_limit * 4)); else _step=1; _left=$_limit; fi
  _end=$(( $(port53_now) + _limit * 100 ))
  while [ "$_left" -gt 0 ] && [ "$(port53_now)" -lt "$_end" ]; do
    sleep "$_step"
    _own="$(port53_own_pid)"
    _socks="$(port53_sockets)" || return 0
    _rc=0; port53_held || _rc=$?
    case "$_rc" in
      1) say "Port 53 is free"; return 0 ;;
      2) say "awk can't read the socket list here: not checking that port 53 is free"; return 0 ;;
    esac
    _left=$((_left - 1))
  done
  _own="$(port53_own_pid)"
  say "Port 53 is still held after ${_limit}s, by:"
  ss -Hlunpt 'sport = :53' 2>/dev/null | port53_filter "$_binds" 5 "$_own" | sed 's/^/    /'
  say "Starting TelltaleDNS anyway. If it can't bind, stop what holds port 53 (or set [[listen]] in /etc/telltale/telltale.toml to an address it doesn't hold), then: sudo systemctl restart telltale"
  return 1
}
# END port53-wait

# Whether the node answers where the update service's health gate asks (the API's own address;
# with the API off, systemd's word that it runs; without a known address, the default one). Here,
# after the port53-wait block, with the start it serves: portwait-test.sh runs this part of the
# script on its own (it sets what the script sets before it: HEALTH_KNOWN, UPDATE_HEALTH_URL,
# UPDATE_CHANNEL, CLUSTER_UPDATES).
node_ready() {
  if [ "$HEALTH_KNOWN" = no ]; then "$PREFIX/bin/telltale" health >/dev/null 2>&1
  elif [ -n "$UPDATE_HEALTH_URL" ]; then "$PREFIX/bin/telltale" health --url "$UPDATE_HEALTH_URL" >/dev/null 2>&1
  else systemctl is-active --quiet telltale; fi
}

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
    WAIT_PORT53=yes   # checked before the service starts, below
  else
    say "Leaving systemd-resolved as is: if port 53 is busy, set [[listen]] to this machine's LAN address"
  fi
fi

if [ "$START" = yes ]; then
  # REQ: OPS-004 — port 53 must be free first (a just-restarted systemd-resolved may take a moment
  # to let go of it); if it isn't after the wait, the message says what holds it and the start is
  # tried anyway, so the health check below reports the rest.
  PORT_BUSY=no
  if [ "$WAIT_PORT53" = yes ]; then wait_for_port53 /etc/telltale/telltale.toml || PORT_BUSY=yes; fi
  # One start: `restart` starts a stopped service and swaps a running one onto the new binary.
  # (`enable --now` followed by `restart` started it twice within milliseconds: two of systemd's
  # five starts per ten seconds, and the first instance killed before it handled SIGTERM.)
  systemctl enable telltale >/dev/null 2>&1 || true
  systemctl restart telltale
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    node_ready && break
    sleep 1
  done
  if [ -f "$DROPIN" ]; then rm -f "$DROPIN"; systemctl daemon-reload; fi
  if node_ready; then
    say "TelltaleDNS is running"
    # REQ: OPS-014 (ADR-182) — on only once the node answers where the update service's health
    # gate will ask (else every update would be rolled back).
    if [ "$CLUSTER_UPDATES" = yes ]; then
      systemctl enable --now telltale-update.path >/dev/null
      say "Updates from the cluster are on (telltale-update.path, $UPDATE_CHANNEL channel); the health check after each update asks $UPDATE_HEALTH_URL, which answers now"
    fi
  else
    systemctl --no-pager status telltale | tail -n 15 || true
    if [ "$PORT_BUSY" = yes ]; then echo "Port 53 was still held when the service started (see above): that is the likely reason." >&2; fi
    if [ "$CLUSTER_UPDATES" = yes ]; then
      systemctl disable --now telltale-update.path >/dev/null 2>&1 || true
      echo "Updates from the cluster stay off: ${UPDATE_HEALTH_URL:-the node} didn't answer 200, and the update service's health check would roll every update back. Check [api] listen, and that [access] allowed_networks lets this host in." >&2
    fi
    die "the service didn't become ready (journalctl -u telltale)"
  fi
  ip="$(hostname -I 2>/dev/null | cut -d' ' -f1)"
  if [ "$ADMIN" = create ]; then first="sign in as $ADMIN_USER"
  else first="sudo -u telltale $PREFIX/bin/telltale auth setup-token -c /etc/telltale/telltale.toml"; fi
  if [ "$UPDATE_CHANNEL" = edge ]; then by_hand="sudo telltale self-update --channel edge --restart"; again="--edge --cluster-updates"
  else by_hand="sudo telltale self-update --restart   (--channel edge for builds from main)"; again="--cluster-updates"; fi
  cat <<EOF

  Web UI:      http://${ip:-<this machine>}:8053/
  First admin: $first
  Test:        dig @${ip:-127.0.0.1} example.com
  Updates:     $by_hand
               or from the cluster: sudo sh install.sh $again
  Then point your router's DHCP DNS setting at ${ip:-this machine}.
EOF
elif [ "$CLUSTER_UPDATES" = yes ]; then
  # REQ: OPS-014 (ADR-182) — not started (--no-start): on, with the check left to the admin.
  systemctl enable --now telltale-update.path >/dev/null
  say "WARNING: updates from the cluster are on (telltale-update.path, $UPDATE_CHANNEL channel), but the service isn't running, so its health check couldn't be tried: once it runs, check that curl -fsS '$UPDATE_HEALTH_URL' answers before asking for an update, or every update is rolled back"
fi
