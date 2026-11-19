//! Automatic failover at runtime (REQ: CLU-005; ADR-056): runs [`crate::election`] over the
//! cluster channel.
//!
//! It's on when the cluster's failover mode is `auto` (set on the primary, carried in signed
//! manifests) and the registry has at least three voters (eligible nodes plus witnesses), this
//! node among them. Otherwise the cluster stays in manual mode (ADR-051) and nothing here
//! changes roles.
//!
//! - Votes travel as RPCs (`elect.ask`) on the streams. A candidate can only ask for itself:
//!   the peer ID comes from the stream's certificate.
//! - The ballot is written to disk (fsync) before a vote is answered.
//! - The primary publishes only while its lease is valid ([`Cluster::may_publish`]). A primary
//!   that can't renew stops publishing before anyone else can be elected. DNS keeps answering
//!   throughout (CLU-004): none of this is on the query path.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::election::{Ask, Ballot, Elector, LEASE_MS, Out, Reply};
use crate::net::Cluster;
use crate::node::{Identity, Role};

/// The vote RPC.
pub const KIND: &str = "elect.ask";
/// REQ: CLU-005 (ADR-154, GitHub issue #3) — a Git-managed node asks an emergency primary to
/// hand over (automatic failover under the `GitOps` authority).
pub const HANDOVER_KIND: &str = "elect.handover";
/// How often the election advances.
const TICK: Duration = Duration::from_millis(250);
/// How long a vote request may take.
const ASK_DEADLINE: Duration = Duration::from_secs(2);
/// How often the registry and mode are re-read.
const RELOAD: Duration = Duration::from_secs(5);

/// The cluster's voters (eligible nodes and witnesses), sorted.
pub fn voters(id: &Identity) -> Vec<String> {
    voters_in(&id.registry())
}

/// The voters among `registry`, sorted: for a caller that has read the registry once and needs
/// more than the voters from it.
pub fn voters_in(registry: &[crate::node::NodeRecord]) -> Vec<String> {
    let mut v: Vec<String> = registry
        .iter()
        .filter(|n| n.voter())
        .map(|n| n.node_id.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Whether automatic failover runs on this node: `auto` mode, three or more voters, and this
/// node one of them.
pub fn active(id: &Identity) -> bool {
    active_among(id, &voters(id))
}

/// [`active`], given the registry's voters ([`voters_in`]) already.
pub fn active_among(id: &Identity, voters: &[String]) -> bool {
    id.meta.failover == "auto" && voters.len() >= 3 && voters.contains(&id.meta.node_id)
}

/// REQ: CLU-005 (review 05-05) — leases are timed on the election clock, which never steps:
/// on the wall clock, NTP setting a Pi's time after boot made every lease it granted look
/// expired at once.
fn now_ms() -> u64 {
    crate::clock::now_ms()
}

/// This node's ballot on this process's election clock ([`Ballot::adopt`]). A ballot moved
/// from another clock is stored at once, so later reads don't extend its lease again.
fn load_ballot(cluster: &Cluster, now: u64) -> Ballot {
    let mut b = cluster.identity.ballot();
    if b.adopt(crate::clock::id(), now)
        && let Err(e) = cluster.identity.save_ballot(&b)
    {
        warn!("cluster: can't store this node's ballot: {e}");
    }
    b
}

/// Answers `peer`'s vote request. Without a running election (a witness, or a node in manual
/// mode) the stored ballot answers, with nothing applied.
pub fn answer(cluster: &Cluster, peer: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let ask: Ask = serde_json::from_slice(body).map_err(|e| format!("bad vote request: {e}"))?;
    if ask.candidate != peer {
        return Err("a node can only ask for votes for itself".into());
    }
    // REQ: CLU-005 (T10.7) — only a node the registry lists as eligible may stand: a resolver
    // pod or a witness asking is refused before the ballot moves (a granted vote would bind
    // this node to it for the epoch, and a high epoch would fence the primary).
    if !cluster
        .identity
        .registry()
        .iter()
        .any(|n| n.node_id == peer && n.eligible && !n.witness)
    {
        return Err("only an eligible node can ask for votes".into());
    }
    let now = now_ms();
    let mut guard = cluster
        .election
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (reply, ballot) = if let Some(el) = guard.as_mut() {
        let (reply, outs) = el.on_ask(&ask, now);
        let changed = outs.contains(&Out::Persist);
        (reply, changed.then(|| el.ballot.clone()))
    } else {
        let mut b = load_ballot(cluster, now);
        let before = b.clone();
        let reply = b.decide(&ask, now, (0, 0));
        (reply, (b != before).then_some(b))
    };
    if let Some(b) = ballot {
        // Durable before the vote leaves this node.
        cluster.identity.save_ballot(&b)?;
    }
    drop(guard);
    if reply.granted && !ask.pre {
        cluster.note_vote(&ask.candidate, ask.epoch);
    }
    serde_json::to_vec(&reply).map_err(|e| e.to_string())
}

/// REQ: CLU-005 (ADR-154, GitHub issue #3) — why an emergency primary refuses to hand over, on
/// plain facts (`None`: it agrees). `role` is this node's; `peer_can_take_over` is whether the
/// asker is an eligible voter, Git-managed, and up.
fn handover_refusal(
    auto: bool,
    gitops: bool,
    role: Role,
    peer_can_take_over: bool,
) -> Option<&'static str> {
    if !auto {
        Some("automatic failover is off: promote the node instead")
    } else if !gitops {
        Some("the configuration doesn't come from Git: nothing needs taking over")
    } else if role != Role::Emergency {
        Some("this node isn't an emergency primary")
    } else if !peer_can_take_over {
        Some(
            "only an eligible, Git-managed node that is up can ask an emergency primary to hand over",
        )
    } else {
        None
    }
}

/// REQ: CLU-005 (ADR-154, GitHub issue #3) — `peer`, a Git-managed eligible node, asks this
/// emergency primary to hand over. The primary stops renewing its lease; the nodes that aren't
/// Git-managed hold back ([`Cluster::defers_to_git_node`]), so the election picks `peer`. If no
/// one takes over within the give-up time the primary keeps its role (ADR-118). The peer ID
/// comes from the stream's certificate; its Git-managed claim is its Hello's, which only a
/// registry-eligible node (one that already holds the cluster key) could abuse.
pub fn answer_handover(cluster: &Cluster, peer: &str) -> Result<Vec<u8>, String> {
    let id = cluster.identity.reload();
    let now = crate::net::wall_ms();
    let eligible = id
        .registry()
        .iter()
        .any(|n| n.node_id == peer && n.eligible && !n.witness);
    let git_and_up = cluster
        .members()
        .iter()
        .any(|m| m.node_id == peer && m.config_source == "gitops" && m.up(now));
    if let Some(why) = handover_refusal(
        active(&id),
        id.meta.config_authority == "gitops",
        cluster.role().0,
        eligible && git_and_up,
    ) {
        return Err(why.to_owned());
    }
    cluster.start_handover(peer);
    Ok(b"handing over".to_vec())
}

/// REQ: CLU-005 (ADR-154, GitHub issue #3) — asks the emergency primary `primary` to hand over
/// to this (Git-managed) node.
pub async fn ask_handover(cluster: &Cluster, primary: &str) -> Result<(), String> {
    cluster
        .call(primary, HANDOVER_KIND, Vec::new(), ASK_DEADLINE)
        .await
        .map(|_| ())
}

/// The election loop: until `stop`, keeps this node's role in step with the votes.
pub async fn run(cluster: Arc<Cluster>, mut stop: watch::Receiver<bool>) {
    let (tx, mut rx) = mpsc::channel::<(String, Reply)>(64);
    let mut tick = tokio::time::interval(TICK);
    let mut id = cluster.identity.reload();
    let mut reloaded = tokio::time::Instant::now();
    loop {
        let reply = tokio::select! {
            _ = stop.changed() => return,
            _ = tick.tick() => None,
            Some(r) = rx.recv() => Some(r),
        };
        if reloaded.elapsed() >= RELOAD {
            id = cluster.identity.reload();
            reloaded = tokio::time::Instant::now();
        }
        let outs = step(&cluster, &id, reply, now_ms());
        dispatch(&cluster, &id, outs, &tx);
    }
}

/// One turn of the election, under its lock: returns what to send and do.
fn step(cluster: &Cluster, id: &Identity, reply: Option<(String, Reply)>, now: u64) -> Vec<Out> {
    let mut guard = cluster
        .election
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !active(id) {
        // Manual mode: roles change only by `promote` (ADR-051).
        *guard = None;
        drop(guard);
        cluster.set_lease_ok(true);
        return Vec::new();
    }
    let voters = voters(id);
    // Only a node holding the cluster key may stand: a winner must be able to sign.
    let can_lead = id.meta.eligible && !id.meta.witness && id.holds_ca();
    if guard
        .as_ref()
        .is_none_or(|e| e.voters != voters || e.eligible != can_lead)
    {
        let mut el = Elector::new(
            &id.meta.node_id,
            voters,
            can_lead,
            load_ballot(cluster, now),
        );
        // A primary that restarts resumes its epoch if its own ballot is for it.
        let (role, epoch) = cluster.role();
        if role == Role::Primary
            && el.ballot.epoch == epoch
            && el.ballot.candidate == id.meta.node_id
        {
            el.resume(epoch);
        }
        info!(voters = el.voters.len(), can_lead, "automatic failover on");
        *guard = Some(el);
    }
    let Some(el) = guard.as_mut() else {
        return Vec::new();
    };
    let local = cluster.local_state();
    el.applied = (local.epoch, local.applied_seq);
    // REQ: OPS-010 (ADR-118) — in maintenance this node votes but doesn't stand; a primary
    // handing over stops renewing, unless no one took over within the give-up time.
    // REQ: CLU-005 (ADR-154) — and under the GitOps authority a node that isn't Git-managed
    // leaves the election to one that is, while one is up (it votes either way).
    // "A primary is up" is the election's own evidence, the lease this node granted that is still
    // running: a member's `primary` flag comes from its Hello, and stays stale when a node is
    // elected on a stream that was already open (CI hit it: the deference clock ran out while an
    // emergency primary held the lease, and a node that isn't Git-managed won the handover).
    let lease_held = el.ballot.lease_held_by_other(&el.id, now);
    el.standing = !cluster.in_maintenance() && !cluster.defers_to_git_node(id, lease_held);
    if el.leading().is_some() {
        cluster.give_up_handover(crate::net::wall_ms());
    }
    el.stepping_down = cluster.stepping_down();
    // ADR-051 — only voters' epochs count (see `Cluster::may_announce_epoch`).
    let seen = cluster
        .members()
        .iter()
        .filter(|m| cluster.may_announce_epoch(&m.node_id))
        .map(|m| m.epoch)
        .fold(cluster.role().1, u64::max);
    let mut outs = el.observe(seen);
    if let Some((from, r)) = reply {
        outs.extend(el.on_reply(&from, &r, now));
    }
    let jitter = rand::random::<u64>() % (LEASE_MS / 2);
    outs.extend(el.tick(now, jitter));
    // A primary writes only while its lease holds.
    cluster.set_lease_ok(!cluster.is_primary() || el.writable(now));
    cluster.set_failover_view(FailoverView {
        active: true,
        voters: el.voters.clone(),
        leading: el.leading(),
        lease_ms_left: match el.phase {
            crate::election::Phase::Leader { lease_until_ms, .. } => {
                lease_until_ms.saturating_sub(now)
            }
            _ => 0,
        },
        ballot_epoch: el.ballot.epoch,
        ballot_for: el.ballot.candidate.clone(),
    });
    // Durable before any request for votes leaves this node.
    if outs.contains(&Out::Persist)
        && let Err(e) = cluster.identity.save_ballot(&el.ballot)
    {
        warn!("cluster: can't store this node's ballot: {e}");
    }
    outs
}

/// Sends vote requests (their replies come back on `tx`) and applies role changes.
fn dispatch(
    cluster: &Arc<Cluster>,
    id: &Identity,
    outs: Vec<Out>,
    tx: &mpsc::Sender<(String, Reply)>,
) {
    for o in outs {
        match o {
            Out::Send { to, ask } => {
                let (c, tx) = (Arc::clone(cluster), tx.clone());
                tokio::spawn(async move {
                    let body = serde_json::to_vec(&ask).unwrap_or_default();
                    if let Ok(b) = c.call(&to, KIND, body, ASK_DEADLINE).await
                        && let Ok(r) = serde_json::from_slice::<Reply>(&b)
                    {
                        let _ = tx.send((to, r)).await;
                    }
                });
            }
            Out::Elected { epoch } => elected(cluster, id, epoch),
            Out::StepDown { epoch } => {
                cluster.set_lease_ok(false);
                cluster.event(
                    "stepped_down",
                    &id.meta.node_id,
                    if cluster.stepping_down() && cluster.in_maintenance() {
                        format!("handed over for maintenance: a newer epoch than {epoch} exists")
                    } else if cluster.stepping_down() {
                        format!(
                            "handed over to a Git-managed node: a newer epoch than {epoch} exists"
                        )
                    } else {
                        format!("a newer epoch than {epoch} exists")
                    },
                );
                // A handover asked for by a Git-managed node ends with the step-down, so a later
                // election doesn't find this node still refusing to renew.
                cluster.end_handover();
            }
            Out::Persist => {}
        }
    }
}

/// Becomes the primary of `epoch` after winning it.
fn elected(cluster: &Cluster, id: &Identity, epoch: u64) {
    if !id.holds_ca() {
        warn!(
            epoch,
            "cluster: won the election but doesn't hold the cluster key yet; staying a replica"
        );
        return;
    }
    // ADR-048 — a GitOps cluster's node that isn't GitOps-managed coordinates only.
    let gitops = id.meta.config_authority == "gitops";
    let role = if gitops && cluster.config_source() != "gitops" {
        Role::Emergency
    } else {
        Role::Primary
    };
    match cluster.set_role(role, epoch) {
        Ok(()) => {
            info!(epoch, ?role, "cluster: elected primary");
            cluster.event(
                "elected",
                &id.meta.node_id,
                format!("epoch {epoch} by vote"),
            );
        }
        Err(e) => warn!("cluster: elected but can't store the new role: {e}"),
    }
}

/// What the Cluster page shows about the election (ADR-056).
#[derive(Debug, Clone, Default)]
pub struct FailoverView {
    pub active: bool,
    pub voters: Vec<String>,
    /// The epoch this node leads, when it's the elected primary.
    pub leading: Option<u64>,
    /// How long this primary's lease still runs (0 when it isn't leading).
    pub lease_ms_left: u64,
    pub ballot_epoch: u64,
    pub ballot_for: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: CLU-005 (ADR-154, GitHub issue #3) — an emergency primary hands over only under
    /// automatic failover and the `GitOps` authority, only when it is an emergency primary, and
    /// only to an eligible, Git-managed node that is up; every refusal says why.
    #[test]
    fn clu_005_an_emergency_primary_hands_over_only_to_a_node_that_can_publish() {
        let emergency = Role::Emergency;
        assert_eq!(handover_refusal(true, true, emergency, true), None);
        let refusals = [
            handover_refusal(false, true, emergency, true),
            handover_refusal(true, false, emergency, true),
            handover_refusal(true, true, Role::Primary, true),
            handover_refusal(true, true, emergency, false),
        ];
        assert!(handover_refusal(true, true, Role::Replica, true).is_some());
        for (i, r) in refusals.iter().enumerate() {
            assert!(r.is_some(), "case {i} was agreed to");
            for (j, other) in refusals.iter().enumerate() {
                assert!(
                    i == j || r != other,
                    "cases {i} and {j} give the same reason"
                );
            }
        }
        // The reasons name the way out where there is one.
        assert!(refusals[0].is_some_and(|r| r.contains("promote")));
    }
}
