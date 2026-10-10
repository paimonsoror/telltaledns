# Staged rollouts and pins: design notes (T13.2)

**Requirement:** CLU-013. **ADR:** ADR-116. **Task:** T13.2 in `spec/10`. **Spec section:** `12` §4.1.
**Owner request:** 2026-10-09, from the capability review.

Opinionated by design: *decision* means build it this way; amend ADR-116 if you can't. *Open* means
ask the owner. Read ADR-047 (manifests), ADR-048 (authority), ADR-051 (epochs, orphans), ADR-056
(leases), ADR-049 (Git source), and ADR-059 (N/N−1) first: this feature sits on all of them and must
not weaken any.

## 1. What it is
Today `publish_loop` (`crates/telltale/src/replication.rs`) signs this node's shared configuration and
newest filter snapshot as version `(epoch, seq)` and every replica applies anything newer. A rollout
splits that into two steps: **canary** nodes get the new version first; after a bake under a guard,
everyone else gets it. If the guard fails, the cluster is **pinned** to the previous version and the
operator is told. An operator can also pin any kept version by hand ("roll back"), and unpin.

## 2. Invariants that must hold (not negotiable)
1. **Versions never go backwards.** `seq` is monotonic within an epoch; fencing (ADR-051 rule 4) and
   orphan detection compare `(epoch, seq)`. A rollback is therefore a **new** version whose content is
   an older version's blobs. Never re-send an old manifest.
2. **DNS never waits on a rollout.** Every node serves its last applied version at all times (CLU-004).
   A stuck or failed rollout changes what is *published*, never whether a node answers.
3. **N−1 nodes never see a canary version.** They don't know the field; the only safe way is not to
   send it to them. Targeted delivery, not a flag they'd ignore.
4. **One writer per epoch** (ADR-056) is unchanged: only the lease-holding primary publishes either
   head.
5. **GitOps authority is unchanged:** the source stays Git; a pin changes what is served, not what is
   in the repository.

## 3. Heads and delivery (decision)
- The primary keeps **two heads** in `<cluster dir>/published.json` (extend `Published`): `stable:
  (epoch, seq)` and `canary: Option<(epoch, seq)>`. Both are signed manifests in the blob store.
- **Which peer gets which:** a peer is a canary when its node ID, its site (`site:<name>`), or its
  standing (`ephemeral`) is in `[cluster.rollout] canaries`. **The list is empty by default: rollouts
  are off until the owner sets it** (decision 2026-10-09), so an upgrade changes nothing for existing
  clusters. Canary peers are sent the canary head
  when there is one, else stable; every other peer is sent stable. A reconnecting peer that asks for
  the latest version (today: the primary pushes the newest manifest on Hello) is answered the same
  way. Implement as `fn head_for(&self, peer: &NodeRecord) -> &Signed` in the publisher, used by
  **every** path that sends a manifest (initial push, change broadcast, blob-fetch follow-ups).
- **The manifest gains** (all `#[serde(default)]`, N−1 safe; raise `SCHEMA` only if the config
  document itself changes — it doesn't):
  ```rust
  pub rollout: Option<RolloutInfo>, // { stage: "canary"|"stable", of: (epoch, seq), started_ms, bake_secs, canaries: Vec<String> }
  pub pinned:  Option<PinInfo>,     // { to: (epoch, seq), since_ms, by: String, reason: String }
  ```
  `rollout` is informational for the replica (it shows "canary of version X" on the Cluster page);
  `pinned` is **authoritative**: a node that applies a pinned manifest and later becomes primary keeps
  the pin (§6).
- **The primary applies its own configuration at once**, exactly as today, and is counted as a canary
  for the guard. Decoupling the primary's serving configuration from its published one is out of
  scope (ADR-116 records why). Document plainly: "the primary and the canaries run the new version
  during the bake; every other node waits."

## 4. Starting a rollout (decision)
In `publish_loop`, where a new version would be published to all:
- If `canaries` is empty, or the cluster has **no reachable canary peer**, or this is an emergency
  primary: publish to stable as today (no rollout). Log once if canaries are configured but none is
  reachable: "rollout skipped: no canary online".
- Else: sign the version, set `canary = version`, send it to canary peers only, record
  `RolloutState { version, started, before: GuardSample }` in `published.json`, emit a `rollout.start`
  event. `before` is the canaries' serving stats over the previous `bake_secs` (from the per-peer
  heartbeat history the Cluster page already keeps).
- A **newer change during a bake** replaces the canary head (the previous canary version is simply
  superseded; nobody else saw it) and restarts the bake. Don't queue rollouts.
- `[cluster.rollout]` is **shared** configuration (every node should know who the canaries are for
  display) and a **one-of managed section** like `[exclusions]` (ADR-111 pattern), so it's editable
  in **Settings → Cluster → Staged rollouts**: a canary picker listing the cluster's nodes (by name
  and site), each site, and "resolver pods (ephemeral)"; the bake time; the guard thresholds; a
  plain-language preview ("Changes reach *k8s-resolver-0, k8s-resolver-1* first and the rest after 5
  minutes if nothing fails"); Revert to the file; under GitOps, the TOML to commit.
  `PUT`/`DELETE /api/v1/cluster/rollout-settings/default` (admin; dry run, `If-Match`, idempotency,
  audit `rollout_settings.put`; agent scope `cluster:admin`). A change to the rollout section itself
  **bypasses the rollout** (published straight to stable), or you could never fix a bad canary set.
  A canary ID that names no current member is a validation warning, not an error (pods come and go).

## 5. The guard (decision)
Evaluated by the primary every heartbeat tick (5 s) while a rollout is in progress, from data the
primary already holds per peer:
- **Fail immediately** when any canary peer reports: `sync_error` for the canary version (apply
  failed), `ready = false` for ≥ 15 s after applying, or its listener probes failing (`probe_failing`
  for that node). Also when a canary peer disconnects for > 60 s *after* applying (it might have
  crashed on the new config) — `open:` is that too eager? Default on; `fail_on_disconnect = true`.
- **At the end of the bake** (`bake_secs`, default 300, minimum 5 so tests can use it):
  `after = SERVFAIL share over the bake` across canaries (and the primary); fail if `after >
  max(before + 2 percentage points, servfail_pct)` with `servfail_pct` default 5 and **at least 50
  answers** in the bake window; or if an objective (`[slo]`) burns at the fast rate on a canary
  (`slo::burning` already computes this per node). With fewer than 50 answers: pass, unless
  `require_traffic = true` (then keep baking until 50 answers or `max_bake_secs`, default 3,600, then
  fail).
- **Pass** → `stable = version`, `canary = None`, send stable to every non-canary peer, event
  `rollout.promote`. **Fail** → §6 pin to the previous stable, event `rollout.fail`, alert
  `rollout_failed` (once per version) with the reason and the readings.
- Operators: `POST /api/v1/cluster/rollout/promote` (skip the rest of the bake) and `/abort`
  (= pin to the previous stable with `reason = "aborted by <user>"`). Admin role; audited.

The guard is deliberately small and legible. Don't add latency percentiles: canaries and the Pi differ
in hardware, so "slower than before" is noise on a home network.

## 6. Pins (decision)
- **Pin to version N** (`POST /api/v1/cluster/versions/{epoch}.{seq}/pin { reason }`, admin; or the
  guard): the primary builds a **new** manifest `(epoch, seq+1)` with N's `config` and `filter` blob
  refs (both already in the blob store — §7 guarantees it), `pinned = { to: N, since, by, reason }`,
  the current registry/authority/failover/identities/acks, publishes it to **stable**, clears the
  canary head, and **applies it to itself** through the same `apply()` path a replica uses (an
  emergency primary already serves an inherited version this way; reuse that path, with
  `install_filter` for the snapshot). The primary's own files/overrides are untouched: they are now
  "ahead" of what is served.
- **While pinned:** configuration writes (API, plans, UI) answer `409 cluster_pinned` with
  `hint: "the cluster is pinned to version N since …: <reason>. Unpin to publish changes."` and a
  `diff` (§8); the Git source keeps polling and recording the latest good commit but publishes
  nothing; list refreshes continue (they only change local state) but no new filter version is
  published. Health `degraded` with reason `cluster_pinned`; alert `cluster_pinned` fires while pinned
  (set `for_secs` high if you pin on purpose for long).
- **Unpin** (`DELETE /api/v1/cluster/pin`, admin): clears `pinned`, the next `publish_loop` iteration
  publishes the current source as usual — through a rollout if canaries exist. The primary reloads
  its own configuration from its files/overrides as a normal reload.
- **Pin survives failover:** `pinned` is in the manifest, so an eligible replica that is promoted
  publishes its first manifest with the same `pinned`. An emergency primary (publishes nothing new)
  is consistent by construction.
- **Not in v1:** rewriting the *source* (managed entries in `state.db`, or Git) back to N. The diff
  (§8) tells the operator what to change; record the follow-up in ADR-116's deferred list.

## 7. Version history and blob protection (decision)
- `<cluster dir>/versions.json`: the last `history` (default 20) published manifests with `created`,
  `author`/provenance (API user, agent, or Git commit — from the existing audit/provenance), `stage`
  outcome (`stable | canary_promoted | canary_failed | aborted | pinned_to`), the guard readings, and
  the manifest's blob hashes.
- The blob store's pruning (whatever removes old snapshots: today "last 3 kept" for compiled
  snapshots in `lists.rs`) must **not** remove blobs referenced by `versions.json`. Add a protection
  set the pruner consults. Measure the disk cost: 20 versions × (config JSON + filter blobs that
  differ) — filter blobs are content-addressed, so unchanged shards cost nothing extra.
- `GET /api/v1/cluster/versions` (viewer) lists them; `GET /api/v1/cluster/rollout` shows the current
  rollout, the guard readings, and the pin.

## 8. The diff
The shared configuration of any two versions is two JSON documents in the blob store. Compute an
RFC 6902-style patch (add/remove/replace with paths) at request time; show it in the 409 body and on
the Cluster page's pin banner ("Pinned to version 124. Since then: +1 list (`hagezi-tif`), upstream
group `default` members changed"). Keep it as JSON Patch in the API and a sentence per op in the UI
(the help glossary has names for sections).

## 9. Surfaces
- **API:** `GET /api/v1/cluster/rollout`, `POST …/rollout/promote`, `POST …/rollout/abort`,
  `GET /api/v1/cluster/versions`, `POST /api/v1/cluster/versions/{epoch}.{seq}/pin`,
  `DELETE /api/v1/cluster/pin`. Problem codes `cluster_pinned`, `no_rollout`, `version_unknown`,
  `version_blobs_missing`. Audited: `rollout.promote|abort`, `cluster.pin|unpin`.
- **CLI:** `telltale cluster rollout status|promote|abort`, `telltale cluster versions`,
  `telltale cluster pin <epoch>.<seq> --reason …`, `telltale cluster unpin`.
- **Cluster page:** a **Rollout** card (stage, version, canaries with ✓/… per node, bake countdown,
  guard readings before/after, Promote/Abort); a **pin banner** above everything while pinned (version,
  since, by, reason, the diff sentences, Unpin); a **Versions** table (Pin action per row, outcome
  chips); per-node rows show "runs 125 (canary)" vs "runs 124". Topology diagram: canary nodes get a
  dashed outline during a bake.
- **MCP:** `rollout_status` (read); `plan_pin_version { epoch, seq, reason }`, `plan_unpin { reason }`
  (plan/apply, `cluster:admin`); `cluster_promote`'s human-approval rule is unchanged and applies to
  pins too (they change what every node serves).
- **Helm:** `cluster.rollout.{canaries, bakeSeconds, servfailPct, requireTraffic, history}` rendered
  into the controller's `[cluster.rollout]`; default `canaries: []` (off). `values.yaml` comments
  recommend `[ephemeral]` for `mode: scaled` and explain what it does. PrometheusRule
  `TelltaleDNSRolloutFailed`, `TelltaleDNSClusterPinned`.
- **Metrics:** `telltale_cluster_rollout_stage` (0 none, 1 canary), `telltale_cluster_rollout_info{version,started}`,
  `telltale_cluster_pinned`, `telltale_cluster_pinned_to{version}`; per node (already): applied
  version.
- **Health/alerts:** reasons `cluster_pinned` (degraded), `rollout_stuck` (degraded; canaries
  configured, none online for > 10 min while a change waits). Alert rules `rollout_failed`,
  `cluster_pinned`.

## 10. Config
```toml
[cluster.rollout]              # shared one-of section; changes to it skip the rollout itself
canaries = []                  # node IDs, "site:<name>", or "ephemeral"; [] (default) = no rollouts
bake_secs = 300                # ≥ 5
servfail_pct = 5               # fail when SERVFAIL share > max(before + 2, this)
require_traffic = false        # true: keep baking until 50 answers, then judge
max_bake_secs = 3600           # with require_traffic
fail_on_disconnect = true
history = 20                   # kept versions (blobs protected)
```

## 11. Performance and footprint
- Query path and telemetry thread: untouched.
- The primary's publish loop does slightly more bookkeeping per tick; nothing per query.
- Disk: `history` manifests + protected blobs (measure; report in the task).
- Heartbeat size: no new fields needed for the guard (serving stats, probes, readiness, sync error are
  already there). Only `has_qlog` from T13.1 and `maintenance_until` from T13.4 land in heartbeats.

## 12. Tests (map to the AC in `spec/10`)
- Unit: `head_for` per peer class; guard math (before/after, the 50-answer minimum, `require_traffic`,
  immediate fails); `versions.json` rotation and protection; manifest fields default; pin builds a new
  `seq` with N's blobs; `409 cluster_pinned` with a diff; emergency primaries never start rollouts.
- `deploy/cluster/rollout-e2e.sh` (new, CI): primary + canary replica + plain replica + two-server
  dnsperf load: ordering, failure pin, resume, manual pin of an older version, failover keeps the pin.
- `deploy/cluster/upgrade-e2e.sh`: the edge binary (N−1) as a plain replica during a rollout receives
  stable only.
- `deploy/helm/scaled-e2e.sh`: with nothing set, a change reaches every pod at once; after setting
  `canaries = ["ephemeral"]` through the settings API, pods are canaries and an outside node is not.
- Playwright: Settings → Cluster → Staged rollouts picks a node (checked, applied, reverted).
- Promtool tests for the two chart alerts.

## 13. Implementation order
1. `versions.json` + blob protection + `GET /cluster/versions` (useful alone; no behaviour change).
2. Manifest fields `rollout`/`pinned` (defaults), `Published` with two heads, `head_for`, targeted
   delivery on every send path; a unit test that a non-canary peer never receives the canary head.
3. `[cluster.rollout]` as a managed one-of section + Settings → Cluster editor (useful before any
   rollout logic: the picker and validation stand alone).
4. Rollout start/promote/abort + events + API/CLI (no guard yet; `promote` by hand).
5. The guard; `rollout_failed`; the e2e script's failure case.
6. Pins: build, apply-to-self, `409 cluster_pinned` + diff, unpin, failover persistence.
7. Health, alerts, metrics, Helm values and rules, Cluster page, MCP tools, docs, site. Tick the task.

## 14. Decisions taken with the owner (2026-10-09)
- **Off until set:** `canaries = []` by default; the option lives in Settings → Cluster → Staged
  rollouts (and in Helm values / Git for GitOps users).
- `fail_on_disconnect = true` stays the default (a pod rescheduled mid-bake fails the rollout; the
  operator can retry with Unpin).
- `abort` pins (the primary already runs the change and must be reverted too). Not raised with the
  owner as a question; recorded here as the design's choice.
