"""REQ: NFR-005 (T10.10) — checks the release SBOMs before they're published: CycloneDX JSON,
listing the Rust crates the binary was built from (read from its cargo-auditable data, so an
SBOM with only a handful of components means that data was missing).

Usage: sbom_check.py <file.cdx.json>...
"""
import json
import sys

MIN_COMPONENTS = 100
MUST_LIST = ("tokio", "rustls", "fst", "telltale-filter")

failed = False
for path in sys.argv[1:]:
    doc = json.load(open(path))
    names = {c.get("name") for c in doc.get("components", [])}
    missing = [n for n in MUST_LIST if n not in names]
    ok = doc.get("bomFormat") == "CycloneDX" and len(names) >= MIN_COMPONENTS and not missing
    print(f"{path}: CycloneDX {doc.get('specVersion')}, {len(names)} components"
          + (f", missing {missing}" if missing else ""))
    failed |= not ok
sys.exit(1 if failed else 0)
