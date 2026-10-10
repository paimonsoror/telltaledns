# 12 — Clustering, HA, and the Single Management Plane

## 1. Requirements recap
CLU-001..011. Design driver: **the owner's topology is two nodes in two failure domains (a Raspberry Pi on bare metal + a Kubernetes deployment).** Two-voter consensus cannot survive losing either voter, so pure Raft is the wrong default. The design must:
1. keep **DNS answering** on every node regardless of cluster state,
2. give **one management plane** reachable from either site,
3. make **config writes** safe (no split-brain) and simple to recover,
4. scale up to Raft-style automatic failover when ≥ 3 voters (or a witness) exist.

## 2. Topology concepts
| Concept | Meaning |
|---|---|
| **Cluster** | Nodes sharing a cluster ID, a CA, and a config history |
| **Node** | One `telltale` process with a persistent identity (key pair). Kubernetes pods are nodes too |
| **Site** | A display/grouping label (e.g. `home-pi`, `k8s`) used for aggregation and placement (where alerts route, which nodes are "the same place") |
| **Eligible node** | Role `all` or `controller` with persistent storage; can become primary |
| **Primary** | The one eligible node that accepts config writes, compiles snapshots, issues certs, and evaluates alerts |
| **Replica** | Every other node: it applies snapshots, serves DNS, and serves the UI/API (read locally, writes proxied to the primary) |
| **Witness** (optional) | A tiny `telltale witness` process (or any eligible node) that only votes in promotions; ~5 MiB RSS; can run on a NAS, router, or VPS |

## 3. Joining (CLU-001)
```
# on the first node (becomes primary, creates the CA)
telltale cluster init --name home --advertise https://pi.lan:8443
telltale cluster token create --ttl 1h                # prints vgl_join_…  (contains CA fingerprint + primary URLs + secret)

# on another node (or via Helm value / Secret in k8s)
telltale cluster join vgl_join_… --advertise https://telltale-ctl.k8s.lan:8443 --site k8s --eligible
```
- Join flow: the node generates an Ed25519 key, then connects to any listed URL and pins the CA fingerprint from the token. It proves the token secret and receives a node certificate (SAN = node ID + advertise names), valid 90 days and auto-renewed at 2/3 of its life.
- All node-to-node traffic is **mTLS over HTTP/2** on the cluster port (default 8443), with protobuf (`prost`) messages. One persistent bidirectional stream per peer pair, with reconnect plus jittered backoff.
- **Kubernetes:** a long-lived join token lives in a Secret. Resolver pods join as **ephemeral** members (CLU-009): no persistent identity, so they get a fresh identity per pod start, auto-expire after `ephemeral_ttl` (default 10 min) without heartbeats, and display aggregated under their site.
- **NAT/cross-site:** only the primary's (and eligible nodes') cluster ports must be reachable. Replicas dial out. Advertise multiple URLs (LAN IP, LB IP, ingress with TLS passthrough).

## 4. Config replication (CLU-003)
- Config state is a **change log** of `Change { epoch, seq, author, ts, op (JSON-Patch on the config document or a typed op), checksum }` held in the primary's SQLite. Every N changes or on list compile, the primary produces a **snapshot** (see `02 §5`) stamped `(epoch, seq)` and **signed with the cluster signing key** (Ed25519, held by eligible nodes, rotated with the CA).
- Replicas track `applied = (epoch, seq)`. On connect, a replica sends its version. The primary streams the missing changes if it still has them; otherwise it sends the latest full snapshot manifest. Blobs are fetched by hash, and the replica already has most of them (content addressing).
- The replica verifies the signature, chain, and schema version, writes to disk, applies via `ArcSwap`, and acks. The primary tracks per-node lag (CLU-008).
- **Node-local overrides (CLU-006):** `node.toml` (or the `telltale.node.*` Helm values) is merged *after* the cluster config and is never replicated. Allowed keys are listen addrs, cache size, qlog retention, worker count, `site`, and local-only records. Attempts to override non-allowed keys are rejected at startup with a clear error.
- **GitOps mode:** the primary loads the config from a file/ConfigMap and produces changes from the diff. API writes are rejected (`409 gitops_managed`) except for operational actions (pause blocking, flush cache).

### 4.1 Staged rollouts and pins (CLU-013, ADR-116)
- **Heads:** the primary keeps a `stable` head and, during a rollout, a `canary` head. Canary manifests are sent only to canary peers; a peer that asks for the latest version gets the head for its set. Older nodes (no `rollout` support) are non-canary and never see a canary version.
- **Canaries:** `[cluster.rollout] canaries` = node IDs, `site:<name>`, or `ephemeral`; **default empty = no rollouts** (off until set). A shared one-of section edited in Settings → Cluster → *Staged rollouts* (`PUT /api/v1/cluster/rollout-settings`, ADR-111 pattern; GitOps shows the TOML). The primary applies its own configuration at once (as today) and is counted as a canary for the guard.
- **Stages:** `canary` → (bake `bake_secs`, default 300, under the guard) → `all`. Guard inputs come from heartbeats: apply error, not ready, listener probes failing (fail at once); at the end of the bake, SERVFAIL share above `max(before + 2 points, servfail_pct)` with ≥ 50 answers, or a fast SLO burn on a canary. Too little traffic passes unless `require_traffic`. `POST /api/v1/cluster/rollout/promote|abort` for operators.
- **Pins:** a failed guard, or `POST /api/v1/cluster/versions/{epoch}.{seq}/pin`, makes the primary publish that version's blobs as the stable head (a **new** `seq`; versions never go backwards), apply them to itself, and refuse configuration writes with `409 cluster_pinned` and the diff. `pinned` travels in the manifest (a new primary stays pinned). `DELETE /api/v1/cluster/pin` resumes from the current source. Git polling continues while pinned and publishes nothing.
- **History:** the last `history` (20) manifests in `<cluster dir>/versions.json`, their blobs protected; `GET /api/v1/cluster/versions`.
- Alerts `rollout_failed`, `cluster_pinned`; health `cluster_pinned` (degraded); timeline events; `telltale_cluster_rollout_stage`, `telltale_cluster_pinned`; MCP `rollout_status`, `plan_pin_version`, `plan_unpin`. Design: `docs/design/staged-rollouts.md`.

## 5. Primary election, failover, and fencing (CLU-005)
**Epoch** = a monotonically increasing u64, persisted. Every change and snapshot carries the epoch of the primary that created it.

### Modes
| Mode | When | Behavior |
|---|---|---|
| `manual` (default with 2 eligible nodes and no witness) | The owner's 2-site setup | If the primary is unreachable, replicas keep serving DNS, and the UI on any node shows a **read-only banner** with the "Promote this node" action (admin + TOTP confirm, or `telltale cluster promote`). Promotion sets `epoch = max_seen + 1`. |
| `witness` | 2 eligible nodes + 1 witness | Automatic. A candidate must obtain votes from a majority of {eligible nodes + witness} for `epoch+1`, and promotes only after the old primary's **lease** (default 15 s, renewed every 5 s) has expired from its perspective. |
| `quorum` | ≥ 3 eligible nodes | The same lease + epoch-vote protocol across all eligible nodes (a simplified Raft-style election; no log replication by vote, because the change log replicates as above). |

### Fencing rules (split-brain prevention)
1. A primary accepts writes only while it holds a valid lease: in `witness`/`quorum` modes, renewed with a majority; in `manual`, an implicit lease that is lost as soon as it sees any peer with a higher epoch.
2. Any node receiving a message with a higher epoch immediately demotes itself to replica.
3. When an old primary returns and discovers a higher epoch, any local changes with its stale epoch that the new primary never saw become **orphaned changes**. They are *not* applied. They are kept and shown in the UI under "Conflicts" with a one-click "re-apply on current primary" (each change is a semantic op, so re-applying is usually clean). This is the honest trade-off for availability in a 2-node setup.
4. Snapshots with a lower epoch than a replica's applied epoch are rejected.

### What fails over, and what doesn't
| Function | Primary down |
|---|---|
| DNS resolution, filtering, caching | **Unaffected** on all nodes (last snapshot) |
| List refresh | Paused (replicas keep the last compiled lists). In P1, eligible replicas can compile locally from cached list sources if the primary has been down > 24 h, *without* producing a new cluster version |
| UI/API read (dashboards, query log) | Works on any node. Federation covers reachable nodes, and the UI shows which nodes are missing |
| UI/API config writes | Read-only until promotion (manual) or ≤ 30 s (witness/quorum) |
| Alerts | Evaluated by the new primary after promotion; replicas raise a local "primary unreachable" alert via their own sinks |
| Cert issuance | Existing certs keep working (90-day validity); renewal waits for a primary |

## 6. Single management plane (CLU-002)
- Every node serves the same UI and API. A request carries an optional `scope` (`node:<id>`, `site:<name>`, `cluster`; default `cluster`).
- **Reads:**
  - Config reads are local, since every node has the replicated config.
  - Analytics reads are **federated**: the receiving node fans out to the peers in scope over the cluster channel, then merges.
  - Merging rules: counters sum; top-K merges by summing Space-Saving counters (bounded error, shown as approximate); HDR histograms merge exactly; query-log searches are k-way merged by timestamp with per-node cursors.
  - Per-peer timeout is 2 s. Partial results are returned with `missing_nodes: [...]`, so a dead node never hangs the UI.
- **Writes:** the receiving node forwards to the primary over the cluster channel with the user's identity (signed by the receiving node, so the audit log shows both the user and the entry node). Users/RBAC/OIDC config are part of the replicated config, so login works on every node even with the primary down (read-only).
- **Recommended access:** point a DNS name (`telltale.lan`) at both nodes (or use the k8s Ingress + Pi IP) so the UI is reachable from either site.

## 7. Telemetry topology (CLU-007)
Per node, configurable:
| Mode | Raw query log | Rollups | Use when |
|---|---|---|---|
| `local` (default for eligible nodes) | Stored locally | Local; federated on read | Pi with SSD/USB storage; controller pods with a PVC |
| `ship` (default for k8s resolver pods) | Streamed to a target node (the primary, or a designated `store` node); spilled to a local buffer (default 64 MiB, memory or disk) when the target is unreachable, then replayed | Shipped as per-minute aggregates | Ephemeral pods; Pi on an SD card (avoids write wear) |
| `both` | Both | Both | Belt and braces |

Shipping uses the same mTLS channel, in batches of columnar blocks (the same encoding as on-disk blocks, so the receiver appends them without re-encoding). Receiving nodes store shipped data in per-source-node segments, so federation and dedup stay correct.

## 8. Client-facing HA (documented in `08`)
- Hand out **both** node IPs via DHCP (primary + secondary DNS). Most OSes fail over within 1–5 s. TelltaleDNS's job is to make both nodes behave identically (same config, same lists, same client→group mapping).
- Optional VIP: keepalived/VRRP on Linux nodes (docs + example), MetalLB L2/BGP in k8s. TelltaleDNS exposes `/readyz` for health scripts.
- **Client identity across nodes:** groups are keyed by IP/MAC/client ID, so they behave the same whichever node a client hits. MAC-based identification requires L2 adjacency (a k8s pod usually can't see client MACs). The UI warns when a group relies on MAC and a node can't resolve MACs. Remedy: use IP reservations or EDNS MAC from the router.

## 9. Protocol versioning (CLU-010)
- The cluster RPC uses protobuf with a `protocol_version`; the snapshot manifest has a `schema_version`.
- A node accepts N and N-1. The primary refuses to emit features unsupported by the oldest connected node and warns in the UI (the "cluster minimum version" concept).
- Upgrade order: replicas first, then the primary. Helm upgrades handle this via hooks or separate releases.

## 10. Test matrix (must pass in CI, see `09`)
Partition primary ↔ replica for 1 h → DNS keeps serving, and convergence after heal is ≤ 10 s. Kill the primary in witness mode → new primary ≤ 30 s and no dual-writer window (Jepsen-style checker over the change log). Old primary returns with orphaned writes → they appear under Conflicts, and nothing is applied silently. Rolling upgrade N-1 → N with live traffic → 0 failed queries at clients with two DNS servers configured.
