# Pass 05: cluster and HA

**Output:** `docs/review/v0.2.0/05-cluster.md` (+ `patches/05-*`)

## Scope
Several nodes acting as one: joining, mTLS between nodes, replicated configuration,
forwarded writes, federated reads, query-log shipping, failover and elections, CA rotation,
version compatibility, configuration from Git.

- `crates/telltale-cluster/` (`pki.rs`, `token.rs`, `net.rs`, `wire.rs`, `sync.rs`,
  `election.rs`, `failover.rs`, `renew.rs`, `rotation.rs`, `node.rs`)
- `crates/telltale-git/` (a minimal Git client for config from a repository)
- `crates/telltale/src/`: `cluster.rs`, `replication.rs`, `federated.rs`, `forward.rs`,
  `ship.rs`, `gitsource.rs`, `managed.rs`
- `crates/telltale-cluster/tests/sim.rs` (the election simulator), `deploy/cluster/*.sh`

## Read first
1. `spec/12-clustering-and-ha.md`; ADR-044 to ADR-059, ADR-066.
2. `token.rs` + `pki.rs` (trust) → `sync.rs` + `crates/telltale/src/replication.rs`
   (config) → `election.rs` + `failover.rs` (who is primary).

## Look for
- **Trust model:** join tokens (lifetime, reuse, revocation), certificate issuance and
  renewal, what a compromised replica or a stolen token can do, how resolver pods prove
  possession of the bootstrap secret (ADR-058).
- **Split brain and fencing:** epochs, leases, the witness, a partitioned old primary,
  orphaned config versions; check the simulator covers the scenarios that matter.
- **DNS independence (CLU-004):** a node answers from its last snapshot whatever the
  cluster does; look for any path where cluster trouble blocks, slows, or crashes query
  handling.
- **Replication correctness:** signed manifests, schema versioning (N and N-1, CLU-010),
  node-local vs shared sections (CLU-006), partial or corrupt blobs.
- **Git source:** signature checks, untrusted repository content, webhook authentication.

## Threat surface
The cluster port is exposed on the LAN (and on a Kubernetes LoadBalancer here): mTLS
handshake handling, message parsing in `wire.rs`, resource exhaustion from a peer,
privilege of forwarded writes.

## Useful
```sh
cargo test -p telltale-cluster --release --test sim -- --nocapture
bash deploy/cluster/e2e.sh target/debug/telltale            # needs a release-like build; see the script header
bash deploy/cluster/failover-e2e.sh target/debug/telltale
```
