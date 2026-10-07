#!/bin/sh
# REQ: OPS-004 (T9.26, ADR-097) — checks that a stable release landed everywhere it should.
# The image workflow runs it at the end of a tag build; it also works by hand (anonymous
# reads of public GitHub and GHCR data).
#
#   deploy/release/verify.sh 0.1.0
#
# Needs: curl, minisign, sha256sum, helm, and docker (buildx) or crane.
set -eu
v=${1:?usage: verify.sh <X.Y.Z>}
repo=${GITHUB_REPOSITORY:-paimonsoror/telltaledns}
owner=${repo%%/*}
image="ghcr.io/$owner/telltale"
chart="oci://ghcr.io/$owner/charts/telltale"
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0
ok() { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fails=$((fails + 1)); }

# 1. The GitHub release: signed sums and index, the binaries match the sums.
base="https://github.com/$repo/releases/download/v$v"
for f in SHA256SUMS SHA256SUMS.minisig releases.json releases.json.minisig telltale-x86_64-linux; do
  curl -fsSL --retry 3 -o "$tmp/$f" "$base/$f" || bad "release asset $f missing"
done
if minisign -Vq -p deploy/release/telltale-release.pub -m "$tmp/SHA256SUMS" &&
  minisign -Vq -p deploy/release/telltale-release.pub -m "$tmp/releases.json"; then
  ok "SHA256SUMS and releases.json signed with the release key"
else
  bad "signatures don't verify"
fi
if (cd "$tmp" && grep ' telltale-x86_64-linux$' SHA256SUMS | sha256sum -c --quiet -); then
  ok "telltale-x86_64-linux matches SHA256SUMS"
else
  bad "telltale-x86_64-linux doesn't match SHA256SUMS"
fi
for t in x86_64-linux aarch64-linux armv7-linux; do
  grep -q " telltale-$t\$" "$tmp/SHA256SUMS" || bad "no telltale-$t in SHA256SUMS"
done
grep -q "\"channel\": \"stable\"" "$tmp/releases.json" && grep -q "\"version\": \"$v\"" "$tmp/releases.json" &&
  ok "releases.json: channel stable, version $v" || bad "releases.json isn't stable $v"
chmod +x "$tmp/telltale-x86_64-linux"
if "$tmp/telltale-x86_64-linux" --version | grep -q "^telltale $v (.*channel stable"; then
  ok "the binary says: $("$tmp/telltale-x86_64-linux" --version | head -1)"
else
  bad "the binary reports $("$tmp/telltale-x86_64-linux" --version | head -1)"
fi

# 2. "Latest release" (what install.sh and self-update take) is this one.
latest=$(curl -fsSI "https://github.com/$repo/releases/latest" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')
case $latest in
  */tag/v$v) ok "releases/latest -> v$v" ;;
  *) bad "releases/latest -> ${latest:-nothing}" ;;
esac

# 3. Images: X.Y.Z, X.Y, X, and latest are the same multi-arch image.
digest() {
  if command -v crane >/dev/null 2>&1; then crane digest "$1"
  else docker buildx imagetools inspect "$1" --format '{{json .Manifest.Digest}}' | tr -d '"'; fi
}
want=$(digest "$image:$v" 2>/dev/null || true)
if [ -z "$want" ]; then
  bad "image $image:$v missing"
else
  ok "image $image:$v ($want)"
  for t in "${v%.*}" "${v%%.*}" latest; do
    [ "$(digest "$image:$t" 2>/dev/null || true)" = "$want" ] && ok "image :$t is $v" || bad "image :$t isn't $v"
  done
  if command -v docker >/dev/null 2>&1; then
    plats=$(docker buildx imagetools inspect "$image:$v" | grep -c 'Platform: *linux/\(amd64\|arm64\|arm/v7\)' || true)
    [ "$plats" -ge 3 ] && ok "image has amd64, arm64, arm/v7" || bad "image platforms: $plats of 3"
  fi
fi

# 4. The chart: version and appVersion X.Y.Z (so it installs the image above).
if helm show chart "$chart" --version "$v" >"$tmp/Chart.yaml" 2>/dev/null; then
  grep -q "^version: $v\$" "$tmp/Chart.yaml" && grep -q "^appVersion: \"\{0,1\}$v\"\{0,1\}\$" "$tmp/Chart.yaml" &&
    ok "chart $v (appVersion $v)" || bad "chart $v has: $(grep -E '^(version|appVersion):' "$tmp/Chart.yaml" | tr '\n' ' ')"
else
  bad "chart $chart --version $v missing"
fi

if [ "$fails" -gt 0 ]; then
  echo "verify: $fails check(s) failed for v$v"
  exit 1
fi
echo "verify: v$v is published everywhere"
