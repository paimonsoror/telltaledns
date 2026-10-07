#!/bin/sh
# Installs Ubuntu packages on a CI runner without hanging on a stuck mirror (a bench-smoke
# job waited 40 minutes on `apt-get install dnsperf`, 2026-10-07): each attempt gets three
# minutes, and a failed or stuck one is tried again (three attempts).
#
#   sh .github/scripts/apt-install.sh dnsperf minisign
set -u
for attempt in 1 2 3; do
  if timeout 180 sh -c "sudo apt-get update -qq && sudo apt-get install -y -qq $*"; then
    exit 0
  fi
  echo "::warning title=apt::installing $* failed or timed out (attempt $attempt of 3)"
  sleep 10
done
echo "::error title=apt::couldn't install $*"
exit 1
