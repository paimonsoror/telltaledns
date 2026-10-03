#!/usr/bin/env python3
"""REQ: OPS-001 / T0.4 AC — compressed image size per platform must be ≤ 15 MiB (00 §5).

Reads an OCI layout tarball (`docker buildx build --output type=oci,dest=image.tar`) or a
pushed image (`--remote ghcr.io/...:edge`, via `docker buildx imagetools inspect --raw`) and
sums the compressed layer sizes for each platform manifest.
"""

import argparse
import json
import subprocess
import sys
import tarfile

LIMIT = 15 * 1024 * 1024
ATTESTATION = "unknown/unknown"


def platform(desc):
    p = desc.get("platform", {})
    s = f"{p.get('os', 'unknown')}/{p.get('architecture', 'unknown')}"
    return s + (f"/{p['variant']}" if p.get("variant") else "")


def from_tar(path):
    with tarfile.open(path) as tar:
        def blob(digest):
            algo, hexd = digest.split(":", 1)
            return json.load(tar.extractfile(f"blobs/{algo}/{hexd}"))

        def walk(index):
            for d in index.get("manifests", []):
                if "index" in d["mediaType"] or "manifest.list" in d["mediaType"]:
                    yield from walk(blob(d["digest"]))
                else:
                    yield platform(d), blob(d["digest"])

        yield from walk(json.load(tar.extractfile("index.json")))


def from_remote(ref):
    def raw(r):
        out = subprocess.run(["docker", "buildx", "imagetools", "inspect", "--raw", r],
                             capture_output=True, text=True, check=True).stdout
        return json.loads(out)

    index = raw(ref)
    # Strip the digest or tag (a ':' after the last '/' is a tag, not a registry port).
    repo = ref.split("@", 1)[0]
    head, _, last = repo.rpartition("/")
    if ":" in last:
        repo = f"{head}/{last.split(':', 1)[0]}" if head else last.split(":", 1)[0]
    for d in index.get("manifests", []):
        yield platform(d), raw(f"{repo}@{d['digest']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--oci", help="OCI layout tarball")
    src.add_argument("--remote", help="pushed image reference")
    ap.add_argument("--limit-mib", type=float, default=LIMIT / 1024 / 1024)
    args = ap.parse_args()

    limit = args.limit_mib * 1024 * 1024
    manifests = from_tar(args.oci) if args.oci else from_remote(args.remote)
    seen = fail = 0
    for plat, manifest in manifests:
        if plat == ATTESTATION:  # provenance/SBOM attestation manifests
            continue
        size = sum(layer["size"] for layer in manifest.get("layers", []))
        ok = size <= limit
        fail |= not ok
        seen += 1
        print(f"{'ok  ' if ok else 'FAIL'} {plat:<16} {size / 1024 / 1024:6.2f} MiB compressed (limit {args.limit_mib:g} MiB)")
    if not seen:
        sys.exit("no platform manifests found")
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
