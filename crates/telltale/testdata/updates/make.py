"""Test fixtures for the release index (REQ: OPS-004, ADR-046): a throwaway minisign key (NOT
the release key), an index signed with it, and a tampered copy. Regenerate with
`python3 make.py` (needs the `cryptography` package). The format is minisign's prehashed
`ED` signature: Ed25519 over BLAKE2b-512 of the file, plus a global signature over the
signature and the trusted comment."""
import base64, hashlib, json, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

here = os.path.dirname(os.path.abspath(__file__))
sk = Ed25519PrivateKey.generate()
pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
key_id = os.urandom(8)

def sign(data: bytes, name: str) -> str:
    sig = sk.sign(hashlib.blake2b(data, digest_size=64).digest())
    trusted = f"timestamp:1791201600\tfile:{name}\thashed"
    glob = sk.sign(sig + trusted.encode())
    return (
        "untrusted comment: signature from a TelltaleDNS test key\n"
        + base64.b64encode(b"ED" + key_id + sig).decode() + "\n"
        + f"trusted comment: {trusted}\n"
        + base64.b64encode(glob).decode() + "\n"
    )

index = {
    "channel": "edge",
    "version": "0.1.0-edge.60",
    "commit": "abc1234",
    "date": "2026-10-05T12:00:00Z",
    "notes": "https://github.com/paimonsoror/telltaledns/releases/tag/edge",
    "assets": {
        "x86_64-unknown-linux-musl": {"name": "telltale-x86_64-linux", "sha256": "00" * 32},
        "aarch64-unknown-linux-musl": {"name": "telltale-aarch64-linux", "sha256": "11" * 32},
        "armv7-unknown-linux-musleabihf": {"name": "telltale-armv7-linux", "sha256": "22" * 32},
    },
}
data = (json.dumps(index, indent=2) + "\n").encode()
open(os.path.join(here, "releases.json"), "wb").write(data)
open(os.path.join(here, "releases.json.minisig"), "w").write(sign(data, "releases.json"))
open(os.path.join(here, "releases-tampered.json"), "wb").write(data.replace(b"edge.60", b"edge.99"))
open(os.path.join(here, "test.pub"), "w").write(base64.b64encode(b"Ed" + key_id + pk).decode() + "\n")
print("ok")
