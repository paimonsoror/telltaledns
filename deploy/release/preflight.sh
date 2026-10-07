#!/bin/sh
# REQ: OPS-004 (T9.26, ADR-097) — checks before a release is tagged; the release workflow
# stops at the first failure, before anything is published.
#
#   GH_TOKEN=... deploy/release/preflight.sh 0.1.0 [commit]
#
# 1. X.Y.Z, with no suffix (pre-releases aren't cut by this workflow).
# 2. Cargo.toml's workspace version and the chart's version are X.Y.Z.
# 3. The tag vX.Y.Z doesn't exist yet.
# 4. Release notes exist: deploy/release/notes/vX.Y.Z.md.
# 5. CI passed on the commit being tagged (default: HEAD).
set -eu
v=${1:?usage: preflight.sh <X.Y.Z> [commit]}
sha=$(git rev-parse "${2:-HEAD}")
cd "$(dirname "$0")/../.."
fail() { echo "::error title=preflight::$*"; echo "preflight: $*" >&2; exit 1; }

echo "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || fail "version must be X.Y.Z (got '$v')"
cargo_v=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ "$cargo_v" = "$v" ] || fail "Cargo.toml says $cargo_v, not $v: run deploy/release/bump.sh $v on main first"
chart_v=$(awk '/^version:/ {print $2}' deploy/helm/telltale/Chart.yaml)
[ "$chart_v" = "$v" ] || fail "Chart.yaml says $chart_v, not $v: run deploy/release/bump.sh $v on main first"
if git ls-remote --exit-code --tags origin "refs/tags/v$v" >/dev/null 2>&1; then
  fail "tag v$v already exists"
fi
[ -s "deploy/release/notes/v$v.md" ] || fail "write deploy/release/notes/v$v.md (the release's notes) first"

# The CI workflow's runs for this commit: the newest must have succeeded.
ci=$(gh run list --workflow ci.yml --commit "$sha" --limit 1 --json status,conclusion \
  --jq '.[0] | "\(.status) \(.conclusion)"' 2>/dev/null || true)
[ "$ci" = "completed success" ] || fail "CI on ${sha%"${sha#???????}"} is '${ci:-missing}', not a success: fix or re-run it first"

echo "preflight OK: v$v at $sha (Cargo.toml, Chart.yaml, notes, CI)"
