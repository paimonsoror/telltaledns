Self-update test fixtures (not a real release): `SHA256SUMS` lists `release-binary` under
each release asset name and is signed by a throwaway minisign key whose public half is
`test.pub` (the secret half isn't kept). To regenerate, make a new key and replace `test.pub`:

    minisign -G -W -p test.pub -s /tmp/test.key
    printf '#!/bin/sh\necho "telltale 9.9.9"\n' > release-binary
    for a in x86_64 aarch64 armv7; do echo "$(sha256sum release-binary | cut -d' ' -f1)  telltale-$a-linux"; done > SHA256SUMS
    minisign -S -s /tmp/test.key -m SHA256SUMS -t "telltale test release"
