#!/usr/bin/env bash
# REQ: OPS-014 (ADR-182) — install.sh writes the node's data directory, its update channel and
# where the health check asks into the root update units: the path unit watches
# <data_dir>/update/request.json, and the service reads the request there and may write only that
# folder, the binary's directory and its own state; its health check asks the node's [api]
# address (a wildcard bind at loopback; nothing when the API is off, and then --cluster-updates is
# refused). The data directory comes
# from the config's effective [node] data_dir (the default when it names none); one that isn't a
# plain absolute path gets no units. --cluster-updates is refused for a binary folder or a data
# directory that isn't fit for a root service. No root, nothing installed: the `update-units`
# block is cut out of install.sh and run under `sh` with the real binary (to print the effective
# config).
# Usage: deploy/systemd/update-units-test.sh path/to/telltale
set -euo pipefail
BIN="$(realpath "${1:?usage: update-units-test.sh path/to/telltale}")"
cd "$(dirname "$0")/../.."
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }
n=0
ok() { n=$((n + 1)); echo "ok $1"; }

mkdir -p "$T/prefix/bin" "$T/units"
cp "$BIN" "$T/prefix/bin/telltale"
sed -n '/^# BEGIN update-units/,/^# END update-units/p' deploy/systemd/install.sh > "$T/block.sh"
grep -q 'update_data_dir()' "$T/block.sh" || fail "the update-units block isn't in install.sh"
# Runs the block's functions in `sh` (as install.sh does): `data <config>` prints the data
# directory; `url <config>` the health check's URL; `render <data_dir> <dir> <channel> <url>`
# writes the units into <dir>; `owned <dir>` and `refusal <data_dir>` (with PREFIX=$prefix).
run() {
  PREFIX="${P:-$T/prefix}" sh -c '. "$1"; shift; case "$1" in
    data) update_data_dir "$2" ;;
    url) update_health_url "$2" ;;
    render) render_update_units deploy/systemd "$3" "$2" "$4" "$5" ;;
    owned) update_root_owned "$2" ;;
    refusal) update_refusal "$2" "$3" ;;
    chan) update_channel_refusal "$2" "$3" ;;
  esac' sh "$T/block.sh" "$@"
}
URL='http://127.0.0.1:8053/readyz?startup=1'
cfg() { # name [data_dir]
  { echo 'config_version = 1'
    if [ -n "${2:-}" ]; then printf '[node]\ndata_dir = "%s"\n' "$2"; fi
  } > "$T/$1.toml"
  echo "$T/$1.toml"
}
api() { # name listen [enabled]
  { echo 'config_version = 1'
    printf '[api]\nlisten = "%s"\n' "$2"
    if [ -n "${3:-}" ]; then printf 'enabled = %s\n' "$3"; fi
  } > "$T/$1.toml"
  echo "$T/$1.toml"
}

d=$(run data "$(cfg default)") || fail "the default config: no data directory"
[ "$d" = /var/lib/telltale ] || fail "the default data directory is $d"
ok "a config without [node] data_dir: /var/lib/telltale"

d=$(run data "$(cfg other /srv/telltale-data/)") || fail "a plain data directory refused"
[ "$d" = /srv/telltale-data ] || fail "the data directory is $d (the trailing / goes)"
ok "[node] data_dir = \"/srv/telltale-data/\": /srv/telltale-data"

# The health check's URL, from [api] (the install's own readiness wait asks the same).
u=$(run url "$(cfg default)") || fail "the default config: no health URL"
[ "$u" = 'http://127.0.0.1:8053/readyz?startup=1' ] || fail "default: $u"
for spec in \
  "192.168.3.2:8053|http://192.168.3.2:8053/readyz?startup=1" \
  "0.0.0.0:9443|http://127.0.0.1:9443/readyz?startup=1" \
  "127.0.0.1:18053|http://127.0.0.1:18053/readyz?startup=1" \
  "[::]:8053|http://[::1]:8053/readyz?startup=1" \
  "[fd00::53]:8053|http://[fd00::53]:8053/readyz?startup=1"; do
  listen=${spec%%|*} want=${spec#*|}
  u=$(run url "$(api a "$listen")") || fail "[api] listen = $listen: refused"
  [ "$u" = "$want" ] || fail "[api] listen = $listen: $u, not $want"
done
ok "the health URL: the default, a specific address, another port, a wildcard (IPv4 and IPv6) at loopback, IPv6"
u=$(run url "$(api off 127.0.0.1:8053 false)") || fail "the API off: refused"
[ -z "$u" ] || fail "the API off: $u"
ok "the API off: no health URL (--cluster-updates is then refused)"

run render "$d" "$T/units" edge 'http://192.168.3.2:8053/readyz?startup=1'
path="$T/units/telltale-update.path" svc="$T/units/telltale-update.service"
grep -qx 'PathExists=/srv/telltale-data/update/request.json' "$path" || fail "path unit: $(grep PathExists "$path")"
grep -qx "ExecStart=$T/prefix/bin/telltale self-update --request /srv/telltale-data/update/request.json --restart" "$svc" \
  || fail "service: $(grep ExecStart "$svc")"
grep -qx "ReadWritePaths=$T/prefix/bin -/srv/telltale-data/update" "$svc" || fail "service: $(grep ReadWritePaths "$svc")"
[ "$(grep -c '^ReadWritePaths=' "$svc")" = 1 ] || fail "more than one ReadWritePaths"
if cat "$path" "$svc" | grep -v '^#' | grep -q '/var/lib/telltale/'; then fail "the default data directory is left in a unit"; fi
ok "the units watch and write only /srv/telltale-data/update/, and run the binary from the prefix"
grep -qx 'Environment=TELLTALE_UPDATE_CHANNEL=edge' "$svc" || fail "channel: $(grep CHANNEL "$svc")"
grep -qx 'Environment=TELLTALE_UPDATE_HEALTH_URL=http://192.168.3.2:8053/readyz?startup=1' "$svc" \
  || fail "health URL: $(grep HEALTH_URL "$svc")"
[ "$(grep -c '^Environment=TELLTALE_UPDATE_' "$svc")" = 2 ] || fail "the update variables aren't there once each"
ok "the service gets the node's channel and the health URL as Environment lines (never an ExecStart flag)"
run render "$d" "$T/units" stable ''
grep -qx 'Environment=TELLTALE_UPDATE_HEALTH_URL=' "$svc" || fail "API off: $(grep HEALTH_URL "$svc")"
grep -qx 'Environment=TELLTALE_UPDATE_CHANNEL=stable' "$svc" || fail "stable: $(grep CHANNEL "$svc")"
ok "the API off: the health URL is written empty (the update service then installs nothing)"
# REQ: OPS-014 (ADR-182) — the run fits in the unit's limit: node_update::run_budget_secs (884 s)
# is checked against this value by ops_014_the_run_fits_in_the_units_time_limit; the render keeps it.
[ "$(grep '^TimeoutStartSec=' "$svc")" = "$(grep '^TimeoutStartSec=' deploy/systemd/telltale-update.service)" ] \
  || fail "the render changed TimeoutStartSec"
[ "$(sed -n 's/^TimeoutStartSec=//p' "$svc")" -ge 944 ] || fail "TimeoutStartSec is under the run's budget and a minute"
ok "the rendered service keeps TimeoutStartSec=960 (above the run's 884 s budget and a minute)"

# (The last one is a letter outside the explicit list, which a locale's range might take.)
for bad in "/srv/my data" "relative/dir" "/srv/../etc" "/srv/./x" "/srv/tt;rm" '/srv/$HOME' $'/srv/tt\xc3\xa9'; do
  if run data "$(cfg bad "$bad")" >/dev/null; then fail "data_dir \"$bad\" was taken"; fi
done
ok "a data directory that isn't a plain absolute path gets no units"

# REQ: OPS-014 (ADR-182) — only where root alone can write: the binary's folder, and the data
# directory's parent (not under /home or /root).
run owned /usr/bin >/dev/null || fail "/usr/bin isn't root-owned?"
mkdir -p "$T/mine/bin"
bad=$(run owned "$T/mine/bin") && fail "a folder of $(id -un) passed"
[ "$bad" = "$(cd "$T/mine/bin" && pwd -P)" ] || fail "the folder named: $bad"
why=$(P="$T/mine" run refusal /var/lib/telltale "$URL")
case "$why" in "install location is not root-owned: $(cd "$T/mine/bin" && pwd -P) "*) ;; *) fail "prefix: $why" ;; esac
case "$why" in *"chmod g-w"*) ;; *) fail "the prefix refusal doesn't say how to fix it: $why" ;; esac
why=$(P=/usr run refusal /var/lib/telltale "$URL")
[ -z "$why" ] || fail "/usr and /var/lib/telltale refused: $why"
for dd in /home/pi/telltale /root/telltale; do
  why=$(P=/usr run refusal "$dd" "$URL")
  case "$why" in *"under /home or /root"*) ;; *) fail "$dd: $why" ;; esac
done
why=$(P=/usr run refusal "$T/mine/data" "$URL")
case "$why" in "the data directory's parent folder is not root-owned"*) ;; *) fail "$T/mine/data: $why" ;; esac
ok "--cluster-updates is refused for a binary folder that isn't root's, and a data directory under /home, /root or a folder that isn't root's"
# REQ: OPS-014 (ADR-182) — and with the API off: nothing could prove a new build came up.
why=$(P=/usr run refusal /var/lib/telltale "")
case "$why" in *"needs the API"*"[api] enabled = false"*) ;; *) fail "the API off: $why" ;; esac
ok "--cluster-updates is refused with the API off"

# REQ: OPS-014 (ADR-182) — an edge build installed and neither --edge nor --stable given: refused
# before anything changes (a re-run would replace it with the newest release). A flag, or a
# release installed, goes on.
edge='telltale 0.8.0-edge.404 (commit 99a9f22, built 2026-11-19T20:35:00Z, channel edge, aarch64-unknown-linux-musl)'
why=$(run chan "" "$edge")
case "$why" in "this node runs an edge build"*"pass --edge to stay on edge builds, or --stable to move it to the stable channel (the newest release, which may be older than the edge build you run now)"*) ;;
  *) fail "an edge build with no flag: $why" ;; esac
for flag in edge stable; do
  why=$(run chan "$flag" "$edge"); [ -z "$why" ] || fail "--$flag refused: $why"
done
why=$(run chan "" 'telltale 0.7.0 (commit 1234567, built 2026-11-16T00:00:00Z, channel stable, x86_64-unknown-linux-musl)')
[ -z "$why" ] || fail "a release with no flag refused: $why"
grep -q -- '--stable) CHANNEL=stable; CHANNEL_FLAG=stable ;;' deploy/systemd/install.sh || fail "install.sh has no --stable"
ok "--cluster-updates over an edge build needs --edge or --stable"

echo "PASS ($n checks)"
