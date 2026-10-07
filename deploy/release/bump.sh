#!/bin/sh
# REQ: OPS-004 (T9.26, ADR-097) — set the version everywhere it's written: the workspace
# version, the workspace crates' requirements on each other, the chart version, the OpenAPI
# document's version, and Cargo.lock. The release workflow runs it after tagging (main moves on to the next version,
# so `<next>-edge.N` sorts above the release); it also works by hand.
#
#   deploy/release/bump.sh 0.2.0
set -eu
new=${1:?usage: bump.sh <X.Y.Z>}
case $new in
  *[!0-9.]* | *..* | .* | *.) echo "bump.sh: not X.Y.Z: $new" >&2; exit 2 ;;
esac
[ "$(echo "$new" | tr -cd . | wc -c)" -eq 2 ] || { echo "bump.sh: not X.Y.Z: $new" >&2; exit 2; }
cd "$(dirname "$0")/../.."
old=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1 | tr -d '\r')
[ -n "$old" ] || { echo "bump.sh: no workspace version in Cargo.toml" >&2; exit 1; }
[ "$old" != "$new" ] || { echo "bump.sh: already $new" >&2; exit 0; }

# The first `version = ` in Cargo.toml is [workspace.package]'s.
sed -i "0,/^version = \"$old\"/s//version = \"$new\"/" Cargo.toml
for f in crates/*/Cargo.toml; do
  sed -i -E "s/^(telltale-[a-z-]+ = \{ version = \")$old(\", path)/\1$new\2/" "$f"
done
sed -i -E "s/^version: .*/version: $new/" deploy/helm/telltale/Chart.yaml
# The committed OpenAPI document carries the version (`info.version`; CI compares it with the
# code's, api_001_committed_openapi). It's the document's first "version" key.
sed -i "0,/^    \"version\": \"$old\"/s//    \"version\": \"$new\"/" docs/api/openapi.json
grep -q "^    \"version\": \"$new\"" docs/api/openapi.json || { echo "bump.sh: openapi.json info.version not updated" >&2; exit 1; }
# Workspace members only; nothing else in the lock file changes.
cargo update --workspace --offline 2>/dev/null || cargo update --workspace

left=$(grep -rn "version = \"$old\", path" crates/*/Cargo.toml || true)
[ -z "$left" ] || { echo "bump.sh: still at $old:" >&2; echo "$left" >&2; exit 1; }
echo "version $old -> $new"
