#!/usr/bin/env bash
# REQ: NFR-001 — bench entry point used by `make bench-smoke` / `make bench-full`.
# Usage: bench/run.sh <smoke|full> [bench.py run options...]
# Builds the bench-fast profile (thin LTO; the fat-LTO release build is too slow for a
# per-task gate) unless TELLTALE_BIN or --target points elsewhere.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:?usage: bench/run.sh <smoke|full> [options]}"
shift

args=("$@")
if [[ -n "${TELLTALE_BIN:-}" ]]; then
    args+=(--bin "$TELLTALE_BIN")
elif [[ " $* " != *" --target "* ]]; then
    cargo build --profile bench-fast -p telltale
fi

exec python3 bench/bench.py run "$mode" "${args[@]}"
