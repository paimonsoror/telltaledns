"""Pinned self-update fixtures (REQ: OPS-014, ADR-182; not a real release): `release-binary`
listed in `SHA256SUMS`, and signed release indexes that name a release (`releases.json`, 9.9.9),
an edge build (`releases-edge.json`, 9.9.9-edge.7), a release whose index lists another
SHA-256 than `SHA256SUMS` (`releases-mismatch.json`), and an index of the edge channel that names
a release version (`releases-channel.json`), all signed by a throwaway minisign key
whose public half is `test.pub` (the secret half isn't kept). Regenerate with
`python3 make.py` (needs the `cryptography` package); the format is as in ../updates/make.py."""
import base64, hashlib, json, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

here = os.path.dirname(os.path.abspath(__file__))
sk = Ed25519PrivateKey.generate()
pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
key_id = os.urandom(8)

def sign(data: bytes, name: str) -> str:
    sig = sk.sign(hashlib.blake2b(data, digest_size=64).digest())
    trusted = f"timestamp:1795000000\tfile:{name}\thashed"
    glob = sk.sign(sig + trusted.encode())
    return (
        "untrusted comment: signature from a TelltaleDNS test key\n"
        + base64.b64encode(b"ED" + key_id + sig).decode() + "\n"
        + f"trusted comment: {trusted}\n"
        + base64.b64encode(glob).decode() + "\n"
    )

def write(name: str, data: bytes) -> None:
    open(os.path.join(here, name), "wb").write(data)
    open(os.path.join(here, name + ".minisig"), "w").write(sign(data, name))

binary = open(os.path.join(here, "release-binary"), "rb").read()
sha = hashlib.sha256(binary).hexdigest()
names = {"x86_64-unknown-linux-musl": "telltale-x86_64-linux",
         "aarch64-unknown-linux-musl": "telltale-aarch64-linux",
         "armv7-unknown-linux-musleabihf": "telltale-armv7-linux"}
write("SHA256SUMS", "".join(f"{sha}  {n}\n" for n in names.values()).encode())

def index(channel: str, version: str, digest: str) -> bytes:
    return (json.dumps({
        "channel": channel, "version": version, "commit": "abc1234",
        "date": "2026-11-19T00:00:00Z",
        "assets": {t: {"name": n, "sha256": digest} for t, n in names.items()},
    }, indent=2) + "\n").encode()

write("releases.json", index("stable", "9.9.9", sha))
write("releases-edge.json", index("edge", "9.9.9-edge.7", sha))
write("releases-mismatch.json", index("stable", "9.9.9", "ab" * 32))
write("releases-channel.json", index("edge", "9.9.9", sha))
open(os.path.join(here, "test.pub"), "w").write(base64.b64encode(b"Ed" + key_id + pk).decode() + "\n")
print("ok")
