#!/bin/sh
# REQ: NFR-005 (T10.10) — signs a pushed image by digest with cosign, keyless (this run's GitHub
# OIDC identity; the certificate and the signature go to Sigstore's public transparency log),
# then verifies the signature against this workflow's identity.
# Usage: cosign-sign.sh <image> <buildx --metadata-file output>
set -eu
image=$1
digest=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$2")
cosign="$RUNNER_TEMP/cosign"
if [ ! -x "$cosign" ]; then
  curl -fsSLo "$cosign" https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64
  echo "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71  $cosign" | sha256sum -c -
  chmod 755 "$cosign"
fi
"$cosign" sign --yes "$image@$digest"
"$cosign" verify "$image@$digest" \
  --certificate-identity-regexp "^https://github\.com/${GITHUB_REPOSITORY}/\.github/workflows/image\.yml@" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null
echo "::notice title=image signed::$image@$digest"
