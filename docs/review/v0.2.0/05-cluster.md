# Pass 05: cluster and HA (v0.2.0)

Reviewed at tag `v0.2.0` (commit 338db09) in `~/telltale-review`. Since the tag, `main` has
changed `crates/telltale-cluster/src/net.rs` (+20 lines: a pod that left is no longer listed
as a node that didn't answer, 7aa39c3), its tests, and one line each in `forward.rs` and
`managed.rs`. Patches 05-01 and 05-02 touch `net.rs` near `record_member` and
`observe_epoch`; the implementing agent should expect a small offset there. Nothing here
touched the Pi, the homelab, or `~/homelab-charts`; every experiment ran in-process.

## Summary

The mechanics are careful: the join pins the CA before any secret leaves the node, peers are
named by their certificate and their Hello must agree with it, manifests are signed and
versioned by `(epoch, seq)` with the fence held under the same lock as role changes, blobs
are content-addressed and checked before they're stored, the election is a pure state machine
with one vote per epoch and a lease margin that a 10,000-schedule simulator mutation-checks,
and nothing on the cluster side can delay a DNS answer. The weak spot is one layer up: **who a
member says it is decides what it may do.** A member's standing (eligible, witness, ephemeral)
and the epoch it announces are taken from the member itself, and the primary acts on them:
it shares the cluster key with any member the registry marks eligible, it steps down for any
member announcing a higher epoch, and it applies writes from any member in a user's name.
That is fine for an eligible node, which holds the key anyway, and wrong for a resolver pod,
which ADR-058 deliberately keeps out of the trust circle.

Top three points:

1. **A joiner decides its own eligibility, so the bootstrap secret in every resolver pod
   buys the cluster's CA key** (05-01, high, verified by a test that fails on v0.2.0). A join
   with the Helm chart's shared secret may say `eligible: true, ephemeral: false`; the primary
   records it so and, on the next heartbeat, sends `ca.key`. A Hello can also raise a known
   member to eligible. With the key, a compromised pod signs manifests (configuration, lists,
   users and tokens) for every node and issues certificates. Patch: joins by the bootstrap
   secret are ephemeral whatever they ask, and a Hello can't change a known member's standing.
2. **Any member fences the primary with one unsigned frame** (05-02, high, verified). A
   Hello or heartbeat with `epoch: 99` makes the primary step down to replica; in manual mode
   nobody can promote while the rogue keeps claiming to be the primary, so the cluster's
   configuration is frozen until an operator removes the member. Patch: only voters (eligible
   nodes and witnesses, per the signed registry) can announce an epoch.
3. **An emergency primary can't be relieved** (05-04, medium). ADR-048 says a returning
   Git-managed node "takes over again automatically"; nothing does, and `promote` refuses
   while any primary is up, so handing the cluster back from the Pi to the homelab node needs
   the Pi stopped first. Patch: promotion is allowed over the emergency primary of the version
   this node applied.

Also medium: ephemeral members may forward configuration writes in any user's name and pause
blocking or flush caches cluster-wide (05-03, patched), and leases are timed on the wall
clock, which a Pi steps after boot (05-05, a challenge to ADR-056's clock assumption). The rest
is low.

## Strengths

- **Joining never trusts first.** The joiner verifies the server's chain against the CA
  fingerprint in the token before the secret is sent (`crates/telltale-cluster/src/net.rs:238-271`,
  `:1890-1952`), and a bootstrap join trusts the CA only after the server proves it knows the
  shared secret with an HMAC over a fresh nonce (`:129-133`, `:182-236`, `:1680-1703`). The
  primary stores only hashes of token secrets and compares them in constant time
  (`node.rs:581-603`, `:677-680`), and it picks every certificate's names itself, never from
  the CSR (`pki.rs:209-250`).
- **Peers are who their certificate says.** The node ID is read from the client certificate
  at the handshake (`net.rs:308-318`, `:1838-1843`) and the Hello must carry the same ID
  (`:1334-1338`); RPC handlers get that ID, not a claim (`:423-434`). A vote request can only
  ask for the stream's own node (`failover.rs:63-66`), a renewal is signed only for the peer
  the stream names, with names from the signed registry (`renew.rs:46-65`), and an ephemeral
  member can only remove itself (`net.rs:880-882`).
- **Replication is signed, ordered, and content-addressed.** Manifests are Ed25519-signed
  over their exact bytes and verified against the trusted CA bundle (`sync.rs:124-148`); a
  replica applies only manifests newer than what it has and never from an older epoch than its
  own (`net.rs:2232`); blobs are stored only if they hash to their reference
  (`sync.rs:216-225`), fetched with a size cap in parallel, installed under plain file names
  through a temporary directory and a rename (`replication.rs:168-215`), and a merged
  configuration is validated before anything touches disk (`:384-399`). An unknown newer
  schema keeps the last version and says to upgrade (CLU-010).
- **Fencing is held under the right lock.** `publish_as` checks role and epoch under the same
  mutex as `set_role`, so a step-down either precedes a publish or outranks it
  (`net.rs:1099-1116`, test `clu_005_a_fenced_primary_never_publishes`); orphaned versions
  are kept with the changed paths for the Conflicts list rather than applied
  (`replication.rs:550-600`).
- **The election is a pure state machine and it's tested like one.** One vote per epoch, a
  refusal while a lease runs, candidates behind the voter refused, pre-vote so a partitioned
  node never inflates epochs, and the primary's own lease ending `MARGIN_MS` before any voter's
  (`election.rs:69-95`, `:257-268`); the ballot is fsynced before a vote is answered
  (`node.rs:423-436`, `failover.rs:83-86`). `tests/sim.rs` drives exactly this code through
  random asymmetric partitions, loss, heavy-tailed delays, crashes, and ±1 % clock rates,
  checking one primary per epoch, never two writers at once, every write kept or reported
  orphaned, and recovery within 60 s; ADR-056 records that removing the lease check is caught.
- **DNS never waits for the cluster (CLU-004).** A missing identity or an unbindable port only
  logs (`crates/telltale/src/cluster.rs:29-57`); a replica serves its last applied snapshot
  before contacting anyone (`replication.rs:323-330`); applying a version goes through the
  ordinary reload path; shipped segments and federated reads are answered on blocking threads
  (`federated.rs:195-227`); a forwarded write fails fast with 503 and is never queued
  (`forward.rs:224-233`). Federated reads have a 2 s deadline per peer and name the nodes
  that didn't answer (`federated.rs:28`, `:564-623`).
- **The Git source refuses rather than guesses.** History must move forward unless
  `allow_rewind` (`crates/telltale-git/src/lib.rs:286-309`), commits can be required to
  carry an SSH signature by an allowed key (`sshsig.rs:55-107`, Ed25519, namespace `git`),
  the file must load and validate merged with the node's own settings before it's published
  (`gitsource.rs:93-111`), a promoted node fetches only from the pinned source (`:193-205`),
  plain HTTP is loopback-only, and the webhook is HMAC-checked (`:403-425`).
- **CA rotation moves trust one step at a time.** A node adopts a bundle only if it keeps a CA
  it already trusts (`node.rs:293-308`), a key that arrives before its CA is held until a
  verified bundle includes it (`:261-287`), and every phase is gated on every non-ephemeral
  member reporting the right trust and issuer (`rotation.rs:129-208`).
- **Shipped query logs are verified and sandboxed.** Only hex node IDs become paths, the
  whole file's BLAKE3 is checked before it's filed, chunks must arrive in order, and segments
  over 256 MiB are refused (`ship.rs:162-165`, `:214-275`).
- **Version compatibility is explicit.** Protocols one apart interoperate, further apart are
  refused at Hello (`wire.rs:13-15`, `net.rs:1325-1330`); manifests carry a schema; the
  upgrade e2e runs the published edge binary as N−1 (ADR-059).

## Measurements

| What | Result |
|---|---|
| `cargo test -p telltale-cluster -p telltale-git` at v0.2.0 (debug) | 24 + 4 unit tests, the simulator (200 schedules in debug) and 4 `upload_pack` tests: all pass |
| `cargo test -p telltale --bin telltale clu_` at v0.2.0 | 23 pass |
| Each patch applied alone to v0.2.0: the new test (fails unpatched for 05-01 and 05-02), the crate's tests, `cargo clippy … -D warnings` | all pass, all clean (details in each finding's Patch row) |

No e2e script was run (`deploy/cluster/*.sh` start two to three processes and take minutes
each; CI runs them), and no load test. The two high findings are shown by unit tests against
the in-process `Cluster`, which exercise the same frame handling as the network path.

## Findings

### 05-01 A joiner decides its own eligibility, so the bootstrap secret buys the cluster key

| Field | Content |
|---|---|
| Severity | **high** |
| Category | security (trust model) |
| Where | `crates/telltale-cluster/src/node.rs:583-617` (`accept_join`: `eligible` and `witness` come from the request; the bootstrap secret is accepted exactly like a token); `crates/telltale-cluster/src/net.rs:597-622` (`record_member`: a known member's `eligible` is overwritten from its Hello); `:572-595` (`key_share_for`: the key goes to any peer the registry marks eligible); `:1620-1635` (sent on every stream, re-checked each heartbeat); `crates/telltale/src/cluster.rs:173-201` (`bootstrap_join`: the pod's own config decides `eligible`); `deploy/helm/telltale/templates/configmap.yaml:89-93` (resolver pods set `eligible = false`, `ephemeral = true`: client-side only) |
| Evidence | **verified.** The new test `clu_009_a_bootstrap_join_or_a_hello_cannot_claim_eligibility` fails on v0.2.0 at its first assertion: a join with the bootstrap secret asking for `eligible: true, witness: true, ephemeral: false` is recorded eligible and as a witness, and `key_share_for` returns the CA key for it. On v0.2.0 a Hello with `eligible: true` from a member recorded as not eligible also flips the registry (the test's second assertion). The secret is mounted in every resolver pod (`emptyDir` data, no CA key by design, ADR-058); anyone who reads it (a pod compromise, a leaked Secret, anyone with `get secrets` in the namespace) can run `telltale cluster join` with it from anywhere that reaches the LoadBalancer's port 8443, as an eligible node. |
| Impact | With the CA key, the attacker signs manifests: every node applies their configuration (upstreams, lists, local records, groups), their users and API tokens (T9.1), and their CA bundle (ADR-066 lets a trusted CA rotate trust to a new one); they can issue certificates for new members and vote in elections. ADR-058's "no CA key" for pods is the only thing keeping a pod compromise from being a cluster compromise, and it isn't enforced by the primary. The same applies to a join token (ADR-044: reusable until it expires): membership was meant to be what it grants, but it grants the key too. |
| Recommendation | Standing is the primary's decision. (1) A join with the bootstrap secret is an ephemeral member whatever it asks (never eligible, never a witness): that is what ADR-058's pods are, and `scaled-e2e.sh` joins its outside node with a token, so nothing legitimate changes. (2) A Hello never raises a known member's eligibility (an unknown member, from before registries existed, is still taken at its word once, to keep ADR-051's migration). Both in the patch. (3) Next, carry `eligible` in the join token (`telltale cluster token create --eligible`, a token field defaulting to false), so a leaked plain token can't bring an eligible node either; that changes the owner's workflow (question 1), so it isn't in the patch. |
| Patch | `patches/05-01-joiners-dont-decide-eligibility.patch` (`node.rs`, `net.rs`, `docs/running.md`, test in `net_tests.rs`). **Verified:** the test alone fails on v0.2.0 (the bootstrap join is recorded eligible and as a witness); with the fix `cargo test -p telltale-cluster` (25 unit tests, the simulator, `upload_pack`) and `cargo test -p telltale --bin telltale clu_` (23) pass, and `cargo clippy -p telltale-cluster -p telltale --all-targets -- -D warnings` is clean. The existing `clu_009_bootstrap_secret_joins_ephemeral_members_that_expire` still passes (its pod asked for `eligible: true` and was already recorded as not eligible because it also said `ephemeral: true`). |
| Effort | S (patch); S for the token flag |
| References | CLU-001, CLU-005, CLU-009, ADR-044, ADR-051 (key sharing), ADR-058, `spec/12` §2–3 |

### 05-02 Any member fences the primary with one unsigned frame

| Field | Content |
|---|---|
| Severity | **high** |
| Category | security (control-plane denial of service), reliability |
| Where | `crates/telltale-cluster/src/net.rs:994-1010` (`observe_epoch`: a higher epoch from anyone demotes a primary); `:1390` (called for every Hello) and `:1465` (every heartbeat); `crates/telltale-cluster/src/failover.rs:157-162` (in auto mode, the leader observes the highest epoch any member reports); `net.rs:929-954` and `:957-965` (`candidate_urls` and `primary_url` prefer whoever claims `primary` with the highest epoch, so replicas dial the claimant and fetch blobs from it); `crates/telltale/src/cluster.rs:723-729` (`promote` is refused while a member claiming `primary` is up) |
| Evidence | **verified.** The new test `clu_005_only_voters_can_fence_the_primary` fails on v0.2.0: a Hello from an ephemeral member with `primary: true, epoch: 99`, then a heartbeat with `epoch: 100`, turns the primary into a replica of epoch 100. Hellos and heartbeats are authenticated as "some member" by mTLS, nothing more; a resolver pod (or any member whose certificate leaked) can send them. In manual mode (the owner's cluster) the demoted primary never comes back by itself; `promote` on it is refused while the rogue is up and claiming the role; the registry keeps the rogue because it's an ephemeral member that is connected. In auto mode the leader steps down on every such heartbeat and the voters re-elect at a higher epoch, so the cluster churns for as long as the frames keep coming. KeyShare frames are also accepted from whoever claims `primary` (`:1490-1497`), but `store_ca_key` only stores a key whose public half matches a trusted CA, so that path yields nothing (`node.rs:261-287`). |
| Impact | Configuration is frozen cluster-wide (no primary publishes; API writes return 503 or 409) until an operator finds the member and removes it; the UI shows the rogue as the primary. DNS keeps answering on every node from the last version, as designed. One frame, repeatable, from the least-trusted kind of member. |
| Recommendation | Only a voter can announce an epoch: an eligible node or a witness in the signed registry. Members the registry doesn't know keep today's behaviour (pre-registry clusters). Both `observe_epoch` and the election's `seen` fold apply the check. With 05-01 in place, "voter" is then something the primary decided, not the member. A stricter follow-up would fence only on a verified manifest (signed by the CA), which is what the epoch really proves; it needs the old primary to verify incoming manifests even while it isn't following, so it's a bigger change than this one. |
| Patch | `patches/05-02-only-voters-fence-the-primary.patch` (`net.rs`, `failover.rs`, test in `net_tests.rs`). **Verified:** the test alone fails on v0.2.0 (the primary ends as `(Replica, 100)`); with the fix `cargo test -p telltale-cluster` (25 + simulator) passes and clippy is clean. **Depends on 05-01:** a Hello that also claims `eligible: true` would, on v0.2.0's `record_member`, make the member a voter first; 05-01 closes that, so apply both (the test sends `eligible: false` so it stands alone). |
| Effort | S |
| References | CLU-005, ADR-051 (fencing rules), ADR-056, ADR-058 |

### 05-03 Ephemeral members can forward writes in any user's name and change other nodes' state

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | security (privilege of forwarded operations) |
| Where | `crates/telltale/src/federated.rs:168-230` (`rpc_handler`: no check of the peer's standing before dispatch); `crates/telltale/src/forward.rs:109-128`, `:130-193` (the primary applies `Write { by }` from any member as `<by> via <site>`); `federated.rs:147-161` (`BlockingPause`, `BlockingResume`, `CacheFlush` are "reads" any member may send; `answer` applies them with no actor) |
| Evidence | **verified by reading.** ADR-054 chose to trust the entry node because "a member node is trusted to replicate configuration anyway". That was true of the nodes that existed then; ADR-058 added members that are not trusted with the key and serve no UI. A resolver pod's certificate is enough to send `api.write` with `by: "admin"`: under an `api` authority the primary stores an upstream, list, rule, or group change and audits it as `admin via k8s`. Under the owner's `gitops` authority those writes are refused (`:118-126` falls through to `write_managed`, which answers 409), but `BlockingPause` for `group: None` pauses blocking on every node that receives it, from any member, with no audit entry. |
| Impact | A pod compromise (or a leaked pod certificate) can change the cluster's configuration on API-authority clusters, and can pause filtering on every node on any cluster, silently. The blast radius is a notch below 05-01 (no key, no signing) but needs nothing but a member certificate. |
| Recommendation | Refuse `api.write` and the state-changing reads (`BlockingPause`, `BlockingResume`, `CacheFlush`) from members the registry marks ephemeral: they have no users to vouch for. Patched. Longer term, forwarded writes could carry the entry node's audit entry ID so the primary can verify the user existed there, but that's a design change. |
| Patch | `patches/05-03-ephemeral-members-cannot-write.patch` (`federated.rs`, test `clu_009_ephemeral_members_cannot_change_other_nodes` for the classification; the gate itself is six lines). **Verified:** builds, `cargo test -p telltale --bin telltale clu_` (24) passes, `cargo clippy -p telltale --all-targets -- -D warnings` clean. The gate's registry lookup is one file read per RPC from an ephemeral peer; peers that aren't ephemeral pay the same read, which `renew::answer` and `rotation::step` already do per call. |
| Effort | S |
| References | CLU-002, CLU-009, ADR-054, ADR-058, API-006 (audit) |

### 05-04 An emergency primary can't be relieved: the returning Git-managed node is fenced and can't promote

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | correctness (a promised behaviour), operability |
| Where | `crates/telltale/src/cluster.rs:723-729` (`promote_plan` refuses while any member claiming `primary` is up); `crates/telltale-cluster/src/net.rs:994-1010` (the returning node sees the emergency primary's higher epoch and becomes a replica); `replication.rs:685-779` (an emergency primary republishes the inherited version only); no code path promotes a Git-managed node automatically |
| Evidence | **verified by reading**, and the scenario is the owner's: the homelab node (GitOps primary) is down long enough that the Pi is promoted `--emergency`. When the homelab node returns it is fenced into a replica (correct). ADR-048: "When an authority-matching node returns it takes over again automatically; the emergency primary had no writes, so nothing is orphaned." Nothing implements the takeover, and the manual route is refused: `promote` on the homelab node says "the primary (…, site home-pi) is up". The only way back is to stop telltale on the Pi (a DNS outage on the Pi's clients), promote the homelab node, then start the Pi, which is then fenced. The docs (`docs/running.md:1498-1499`) say the emergency primary "publishes nothing new until a Git-managed node is back" without saying how it hands back. |
| Impact | After any emergency promotion, configuration stays frozen (no Git commit applies) until an operator does a procedure that the docs don't describe and that costs the Pi's DNS availability. |
| Recommendation | Allow promotion over an emergency primary: when the member that is up and primary is the `primary` of the `emergency` manifest this node applied, and this node would publish (it isn't itself asking for an emergency role), `promote` proceeds; its newer epoch fences the emergency primary, which had no writes. Patched (manual). Automatic takeover, as ADR-048 promises, is the same check run by the Git-managed node's replication supervisor when it has synced an emergency manifest and its Git source works; worth doing after the manual path is in. |
| Patch | `patches/05-04-takeover-from-emergency-primary.patch` (`cluster.rs`, `docs/running.md`, test `clu_005_takeover_from_an_emergency_primary` on the extracted rule). **Verified:** `cargo test -p telltale --bin telltale clu_005` (2, the existing promotion rules included) passes, `cargo clippy -p telltale --all-targets -- -D warnings` clean. Not exercised end to end (that needs three processes); the rule is tested on its own and the wiring is five lines. |
| Effort | S (manual) / M (automatic) |
| References | CLU-005, ADR-048, ADR-051 |

### 05-05 Leases are timed on the wall clock, which a Pi steps after boot

| Field | Content |
|---|---|
| Severity | **medium** |
| Category | correctness (failover safety) |
| Where | `crates/telltale-cluster/src/election.rs:25-33`, `:69-95` (`lease_until_ms` is an absolute Unix time on the voter's clock), `:257-268`, `:357-369` (the primary's lease end is absolute too); `crates/telltale-cluster/src/failover.rs:55-59` (`now_ms` is `SystemTime`); `node.rs:423-436` (the ballot persists the absolute lease end); ADR-056: "Clocks are assumed not to jump by more than the margin; NTP slews rather than steps in normal operation." |
| Evidence | **suspected** (reasoned from the code; the simulator models rates, not steps). A Raspberry Pi has no RTC: it boots on the clock it shut down with and `systemd-timesyncd` steps it, by minutes to hours, once DNS works (pass 04, finding 04-01, the same mechanism). If the Pi is a voter: a forward step makes every lease it granted look expired, so it grants a newer epoch to a candidate while the primary's own lease (by the primary's clock) still runs; with a candidate asking at that moment (a partition that is healing, or the primary briefly unreachable from the candidate), two writers overlap, which is exactly what the lease prevents. A backward step extends leases and delays failover by the step. The sim's safety checks hold only under its ±1 % model. |
| Impact | Rare, needs a voter whose clock steps during an election window, but it breaks the one property auto failover exists for; and the owner's planned witness (a NAS) or the Pi as a voter are the kind of hosts that step their clocks. |
| Recommendation | Time leases with a monotonic clock on each node: a voter stores "granted at (monotonic) + 15 s" and, after a restart, assumes the full lease still runs (conservative); the primary's `lease_until` is monotonic too. `now_ms` values that cross the wire (`Ask`/`Reply`) carry no time already, so only local arithmetic changes. Teach the simulator clock steps (a jump of ±N seconds at a random instant) and keep the mutation checks. Record the change against ADR-056. |
| Patch | none (the simulator and the protocol change together; M) |
| Effort | M |
| References | CLU-005, ADR-056, pass 04 finding 04-01 |

### 05-06 `POST /cluster/v1/ca` is an unauthenticated HMAC oracle on the bootstrap secret

| Field | Content |
|---|---|
| Severity | low |
| Category | security |
| Where | `crates/telltale-cluster/src/net.rs:1680-1703` (`serve_ca`: for any nonce, returns `HMAC-SHA256(secret, nonce:fp)` with no client certificate and no rate limit) |
| Evidence | **verified by reading.** The proof is what lets a pod trust the CA, so it must be computable by the primary for anyone; but it also lets anyone on the LAN (or the LoadBalancer's reach) collect `(nonce, tag)` pairs and brute-force the secret offline. The chart's generated secret is random (fine); `existingSecret` lets a user supply a weak one, and ADR-058 doesn't say the secret must be strong. |
| Impact | Only with a weak user-chosen secret; then it's 05-01's path. |
| Recommendation | Say in the chart's values and the docs that the secret must be at least 32 random bytes; refuse a secret under 16 bytes at startup (`bootstrap_secret_file`), and consider a slow KDF (argon2 is already in the tree) for the HMAC key. |
| Patch | none |
| Effort | S |
| References | CLU-009, ADR-058 |

### 05-07 Join tokens can't be revoked

| Field | Content |
|---|---|
| Severity | low |
| Category | security (operability) |
| Where | `crates/telltale-cluster/src/node.rs:542-579` (`create_token` keeps hashes until expiry); `crates/telltale/src/main.rs:306-310` (`cluster token` has only `create`) |
| Evidence | **verified by reading.** ADR-044 makes tokens reusable until they expire (the docs say "treat it like a password"). A token leaked during its TTL can only be stopped by editing `tokens.json` by hand. With 05-01 a leaked token still brings eligible members. |
| Recommendation | `telltale cluster token list|revoke <prefix>` over `tokens.json` (S), and a shorter default TTL in the docs' examples than `1h` where a one-shot join is the case. |
| Patch | none |
| Effort | S |
| References | CLU-001, ADR-044 |

### 05-08 The Git history check is shallow, so a long gap is refused as a rewind

| Field | Content |
|---|---|
| Severity | low |
| Category | correctness |
| Where | `crates/telltale-git/src/lib.rs:286-309` (`deepen 1000` with a tree filter, `50` without; `descends` only sees the commits fetched) |
| Evidence | **verified by reading.** If the ref moved by more than 1,000 commits since the commit in use (a primary that was down for a long time on a busy repository, or a server without `filter`: 50), the ancestor isn't in the pack and the poll is refused as "doesn't descend … a force-push or rewind", with no way out but `allow_rewind`. |
| Impact | Rare on a homelab repository; confusing when it happens, since the message blames a force-push. |
| Recommendation | Fetch with `have <last>` already narrows the pack; when the ancestor isn't found and the pack is at the depth limit, say so ("more than N commits since …; set allow_rewind once") instead of calling it a rewind. |
| Patch | none |
| Effort | S |
| References | CLU-003, ADR-049 |

### 05-09 Promotion through the API needs an admin session and nothing else

| Field | Content |
|---|---|
| Severity | low (for pass 06) |
| Category | security |
| Where | `crates/telltale-api/src/config_api.rs:448-483` (`cluster_promote`: admin route, no password or TOTP confirmation); `spec/12` §5 ("admin + TOTP confirm"); ADR-051 ("T5.7 adds TOTP confirmation") |
| Evidence | **verified by reading.** The spec and ADR both expect a second confirmation for the one action that changes who publishes configuration. The CLI path is offline and needs the data directory. |
| Impact | A stolen admin session promotes a node. |
| Recommendation | The API pass should decide whether the `PasswordConfirm` pattern already used elsewhere in `auth::routes` applies here. Noted so it isn't lost. |
| Patch | none |
| Effort | S |
| References | CLU-005, API-003, ADR-051 |

### 05-10 ADR-066 overstates what a stolen CA can't do

| Field | Content |
|---|---|
| Severity | low |
| Category | docs |
| Where | `spec/11-decisions.md` ADR-066 ("A node adopts a new bundle only if it keeps at least one CA the node already trusts, so trust moves step by step and a stolen CA alone can't replace it"); `crates/telltale-cluster/src/node.rs:293-350` |
| Evidence | **verified by reading.** The rule is exactly as described, and it means the holder of the *current* CA key can rotate trust to a CA of their own in three manifests (old+new, new+old, new), as the legitimate primary does. What the rule prevents is a CA the node doesn't trust replacing trust; it doesn't contain a stolen current key. That's inherent (the key signs everything), so the fix is the sentence, plus a line in the docs that a suspected CA compromise means re-creating the cluster. |
| Patch | none (a wording change in the ADR) |
| Effort | S |
| References | CLU-001, ADR-066 |

### 05-11 Shipped-segment leftovers and per-segment retention listings on the receiver

| Field | Content |
|---|---|
| Severity | low |
| Category | footprint |
| Where | `crates/telltale/src/ship.rs:232-273` (`.incoming/<hour>-<node>-<part>.seg.part` is removed only on a checksum mismatch; a transfer that stops mid-way, or a sender that dies, leaves it; `retention::enforce` lists every file under the node's directory after each received segment) |
| Evidence | **verified by reading.** Aborted transfers accumulate under `qlog-nodes/<id>/.incoming/` until the same `(hour, node, part)` is retried from offset 0; with ephemeral pods (a new node ID per start) a half-sent part from a pod that died is never retried. Retention per received segment is a full listing of that node's files every `interval_secs` per sender; fine at homelab sizes. |
| Recommendation | Remove `.part` files older than a day in the receiver's retention pass; run that pass per sender at most every few minutes. |
| Patch | none |
| Effort | S |
| References | CLU-007, ADR-055 |

## Questions for the owner

1. **Should a join token carry whether it may bring an eligible node** (`token create
   --eligible`), so a leaked plain token buys membership but not the cluster key (05-01)? It
   changes how the Pi (or a future eligible node) is joined; a witness would need it too.
2. **Automatic takeover from an emergency primary** (05-04): the patch makes the manual
   `promote` work; do you want the Git-managed node to take over by itself when it's back
   and its Git source works, as ADR-048 says?
3. **Leases on a monotonic clock plus clock steps in the simulator** (05-05): this amends
   ADR-056's clock assumption. Do it before adding a witness on the NAS?
4. **A second confirmation for promotion through the API** (05-09): the spec wants TOTP;
   pass 06 can implement it if you still do.
5. **Token revocation** (05-07): is `telltale cluster token revoke` worth having, or is the
   short TTL enough for how tokens are used?

## Not reviewed

- The e2e scripts (`deploy/cluster/*.sh`) were read, not run; CI runs them. The unit, net, and
  simulator tests ran here (debug, 200 schedules).
- API authentication around cluster endpoints (promote, set-failover, set-authority),
  identity replication's import rules (`state/identity.rs`), and `managed.rs` (UI/API-made
  entries, ADR-040): pass 06.
- The Helm chart's templates beyond how resolver pods join, `NetworkPolicy`, and what the
  LoadBalancer exposes: pass 07. Note for it: the cluster port is on the same LoadBalancer IP
  as DNS (`service.dns.alsoServe.cluster`), so 05-01, 05-02, and 05-06 are reachable from the
  whole LAN, not only from the pod network.
- The witness process (`telltale cluster witness`) beyond its use of the same election and
  renewal code; CA rotation was read and its unit tests ran, the rotation e2e did not.
- Federation merging (top-K error bounds, histogram merging, cursor interleaving) was read for
  deadlines and `missingNodes`, not checked for merge correctness; the latency merge is
  exact per ADR-053's follow-up (T9.2), the top-K merge approximate as documented.
- The UI's cluster page: pass 08.
