#!/usr/bin/env python3
"""Builds presets/oui.bin, the MAC vendor table (REQ: OBS-025, ADR-117).

Source: IEEE Registration Authority's public exports of the MAC address block registries,
  MA-L (24-bit prefixes): https://standards-oui.ieee.org/oui/oui.csv
  MA-M (28-bit prefixes): https://standards-oui.ieee.org/oui28/mam.csv
The registry is public data published by the IEEE. Clean room (NFR-006): nothing here comes
from another project's vendor file (Wireshark's `manuf`, nmap's MAC prefix list, ...).
Downloaded for the committed table on 2026-10-09.

Usage: python3 -I presets/build-oui.py oui.csv mam.csv -o presets/oui.bin

Reproducible: the same CSVs give the same bytes (sorted, no timestamps).

Format (little-endian):
  b"TTOUI1\\0\\0"
  u32 vendors, u32 ma_m entries, u32 ma_l entries
  vendors: u8 length + UTF-8 bytes each (sorted, deduplicated; index = position)
  ma_m: u32 prefix (28 bits) + u16 vendor index each, sorted by prefix
  ma_l: 3-byte prefix (big-endian) + u16 vendor index each, sorted by prefix
"""

import argparse
import csv
import re
import struct
import sys

MAGIC = b"TTOUI1\0\0"
MAX_NAME = 32
# Company-form words dropped from the end of a name ("Apple, Inc." -> "Apple").
SUFFIXES = re.compile(
    r"(,|\s)+(inc|incorporated|ltd|limited|llc|l\.l\.c|corp|corporation|co|company|gmbh|ag|sa|s\.a|"
    r"srl|s\.r\.l|spa|s\.p\.a|bv|b\.v|nv|n\.v|oy|ab|as|a/s|kg|plc|pty|pte|sas|sarl|kk|k\.k|"
    r"co\.,? ?ltd|technology|technologies|tech|electronics|international|holdings|group)\.?$",
    re.IGNORECASE,
)


def short(name: str) -> str:
    """A vendor's display name: whitespace collapsed, company forms dropped, capped."""
    n = " ".join(name.replace(" ", " ").split()).strip(" ,.")
    prev = None
    while prev != n:
        prev = n
        n = SUFFIXES.sub("", n).strip(" ,.")
    if not n:
        n = " ".join(name.split()).strip(" ,.") or "?"
    b = n.encode("utf-8")
    if len(b) > MAX_NAME:
        b = b[:MAX_NAME]
        # Don't cut inside a UTF-8 sequence.
        while b and (b[-1] & 0xC0) == 0x80:
            b = b[:-1]
        if b and b[-1] >= 0xC0:
            b = b[:-1]
        n = b.decode("utf-8").rstrip(" ,.-&")
    return n


def read(path: str, registry: str, digits: int):
    out = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("Registry") != registry:
                continue
            a = row["Assignment"].strip().upper()
            if len(a) != digits or any(c not in "0123456789ABCDEF" for c in a):
                continue
            out[int(a, 16)] = short(row["Organization Name"])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ma_l")
    ap.add_argument("ma_m")
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()
    ma_l = read(a.ma_l, "MA-L", 6)
    ma_m = read(a.ma_m, "MA-M", 7)
    vendors = sorted(set(ma_l.values()) | set(ma_m.values()))
    index = {v: i for i, v in enumerate(vendors)}
    if len(vendors) > 0xFFFF:
        print("too many vendors for a u16 index", file=sys.stderr)
        return 1
    blob = bytearray(MAGIC)
    blob += struct.pack("<III", len(vendors), len(ma_m), len(ma_l))
    for v in vendors:
        b = v.encode("utf-8")
        blob += bytes([len(b)]) + b
    for p in sorted(ma_m):
        blob += struct.pack("<IH", p, index[ma_m[p]])
    for p in sorted(ma_l):
        blob += p.to_bytes(3, "big") + struct.pack("<H", index[ma_l[p]])
    with open(a.out, "wb") as f:
        f.write(bytes(blob))
    print(f"{a.out}: {len(vendors)} vendors, {len(ma_m)} MA-M and {len(ma_l)} MA-L prefixes, {len(blob)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
