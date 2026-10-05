"""Writes `releases.json` (REQ: OPS-004, ADR-046): the release index nodes read once a day to
see whether a newer build exists, and which asset to take per architecture. Signed with the
release key next to SHA256SUMS.

Usage: index.py <dist dir> <channel> <version> <commit> <date> <notes url>
"""
import json, os, sys

dist, channel, version, commit, date, notes = sys.argv[1:7]
targets = {
    "telltale-x86_64-linux": "x86_64-unknown-linux-musl",
    "telltale-aarch64-linux": "aarch64-unknown-linux-musl",
    "telltale-armv7-linux": "armv7-unknown-linux-musleabihf",
}
assets = {}
for line in open(os.path.join(dist, "SHA256SUMS")):
    sha, name = line.split()
    name = name.lstrip("*")
    if name in targets:
        assets[targets[name]] = {"name": name, "sha256": sha}
print(json.dumps({
    "channel": channel,
    "version": version,
    "commit": commit,
    "date": date,
    "notes": notes,
    "assets": assets,
}, indent=2))
