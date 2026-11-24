#!/usr/bin/env bash
# REQ: OPS-014 (ADR-182) — the chart's upgrade hook: off by default; on, a pre-upgrade Job that
# runs `ctl upgrade --to-self` from the same image as the controller, with the token from the
# named Secret; it refuses to render without one; and a NetworkPolicy that limits the API lets
# the hook in.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
fail=0
ok() { echo "ok:   $*"; }
bad() { echo "FAIL: $*"; fail=1; }
render() { helm template up "$here/telltale" "$@"; }
on=(--set upgradeHook.enabled=true --set upgradeHook.tokenSecret.name=tt-upgrade)

if render | grep -q 'helm.sh/hook'; then bad "a hook renders by default"; else ok "no hook by default"; fi

if out=$(render --set upgradeHook.enabled=true 2>&1); then
  bad "renders without upgradeHook.tokenSecret.name"
elif grep -q 'needs upgradeHook.tokenSecret.name' <<<"$out"; then
  ok "refuses to render without a token Secret"
else
  bad "unexpected error: $out"
fi

job=$(render "${on[@]}" --set image.tag=sha-abc1234 --show-only templates/upgrade-hook.yaml)
sts=$(render "${on[@]}" --set image.tag=sha-abc1234 --show-only templates/statefulset.yaml)
grep -q '"helm.sh/hook": pre-upgrade' <<<"$job" && ok "a pre-upgrade hook" || bad "not a pre-upgrade hook"
grep -q -- '- --to-self' <<<"$job" && grep -q -- '- --skip-if-unreachable' <<<"$job" \
  && ok "ctl upgrade --to-self --skip-if-unreachable" || bad "args: $job"
# REQ: OPS-014 (ADR-182) — optional: a missing Secret starts the pod, and ctl fails at once
# ("set TELLTALE_TOKEN") instead of the pod waiting for it until activeDeadlineSeconds.
grep -q 'secretKeyRef: { name: tt-upgrade, key: token, optional: true }' <<<"$job" \
  && ok "the token from the Secret (optional: a missing one fails fast)" || bad "token"
# The Job (and its log, with any skip warning) stays until the next run's hook replaces it.
grep -q '"helm.sh/hook-delete-policy": before-hook-creation$' <<<"$job" \
  && ok "the Job's log is kept after a run that succeeded" || bad "delete policy: $(grep delete-policy <<<"$job")"
# REQ: OPS-014 (ADR-182) — caSecret: the API's certificate for an https:// url, as --ca-file.
grep -q -- '--ca-file' <<<"$job" && bad "--ca-file without caSecret" || ok "no CA by default"
# REQ: OPS-014 (ADR-182) — the Job's deadline covers two native nodes at the per-node timeout
# (15m), plus the pre-flight and the pod's start.
grep -q 'activeDeadlineSeconds: 2700$' <<<"$job" && grep -A1 -- '- --timeout' <<<"$job" | grep -q '"15m"' \
  && ok "activeDeadlineSeconds 2700 by default, 15m per node" || bad "deadline: $(grep -E 'activeDeadlineSeconds|timeout' <<<"$job")"
ca=$(render "${on[@]}" --set upgradeHook.url=https://tt.example:8053 --set upgradeHook.caSecret.name=tt-api-ca \
  --show-only templates/upgrade-hook.yaml)
grep -A1 -- '- --ca-file' <<<"$ca" | grep -q -- '- /etc/telltale-hook-ca/ca.crt' \
  && grep -q 'secretName: tt-api-ca' <<<"$ca" && grep -q 'mountPath: /etc/telltale-hook-ca' <<<"$ca" \
  && ok "caSecret mounts the certificate and passes --ca-file" || bad "caSecret: $ca"
ca=$(render "${on[@]}" --set upgradeHook.caSecret.name=tt-api-ca --set upgradeHook.caSecret.key=api.pem \
  --show-only templates/upgrade-hook.yaml)
grep -q -- '- /etc/telltale-hook-ca/api.pem' <<<"$ca" && grep -q 'key: api.pem' <<<"$ca" \
  && ok "caSecret.key names the file" || bad "caSecret.key"
grep -q '"http://up-telltale-api.default.svc:8053"' <<<"$job" && ok "the release's API Service" || bad "url"
img_job=$(grep -m1 'image:' <<<"$job" | awk '{print $2}')
img_sts=$(grep -m1 'image:' <<<"$sts" | awk '{print $2}')
[ "$img_job" = "$img_sts" ] && ok "the controller's image ($img_job)" || bad "image $img_job vs $img_sts"
grep -q -- '--skip-down' <<<"$job" && bad "--skip-down by default" || ok "no --skip-down by default"
render "${on[@]}" --set upgradeHook.skipDown=true --show-only templates/upgrade-hook.yaml | grep -q -- '- --skip-down' \
  && ok "skipDown passes --skip-down" || bad "skipDown"

# REQ: OPS-014 (ADR-182) — whenUnavailable: `fail` (the default) keeps a sync blocked while a
# native node can't fetch the image's edge build; `skip` passes --skip-unavailable; nothing else.
grep -q -- '--skip-unavailable' <<<"$job" && bad "--skip-unavailable by default" || ok "whenUnavailable: fail by default"
render "${on[@]}" --set upgradeHook.whenUnavailable=skip --show-only templates/upgrade-hook.yaml | grep -q -- '- --skip-unavailable' \
  && ok "whenUnavailable: skip passes --skip-unavailable" || bad "whenUnavailable: skip"
if render "${on[@]}" --set upgradeHook.whenUnavailable=maybe >/dev/null 2>&1; then
  bad "whenUnavailable takes any value"
else
  ok "whenUnavailable is fail or skip (values.schema.json)"
fi

np=(--set networkPolicy.enabled=true)
render "${on[@]}" "${np[@]}" --set 'networkPolicy.apiFrom={192.168.1.0/24}' --show-only templates/networkpolicy.yaml \
  | grep -q 'app.kubernetes.io/component: upgrade-hook' && ok "a limited API lets the hook in" || bad "networkpolicy"
render "${on[@]}" "${np[@]}" --show-only templates/networkpolicy.yaml | grep -q 'upgrade-hook' \
  && bad "an extra rule for an open API" || ok "no extra rule when the API is open"
# Off (the default): no hook Job, and a limited API gets no rule for one.
render "${np[@]}" --set 'networkPolicy.apiFrom={192.168.1.0/24}' --show-only templates/networkpolicy.yaml | grep -q 'upgrade-hook' \
  && bad "a NetworkPolicy rule for a hook that is off" || ok "no NetworkPolicy rule while the hook is off"
render --set upgradeHook.tokenSecret.name=tt-upgrade | grep -q 'name: up-telltale-upgrade$' \
  && bad "a Job without upgradeHook.enabled" || ok "a token Secret alone renders no Job"

exit "$fail"
