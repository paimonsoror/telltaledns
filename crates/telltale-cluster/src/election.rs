//! Automatic failover (REQ: CLU-005; `spec/12` §5, ADR-056): one vote per epoch, and leases.
//!
//! This module is the protocol only: no I/O and no clocks of its own (every call takes
//! `now_ms` on the caller's clock), so the partition simulator (`tests/sim.rs`) drives exactly
//! the code the server runs.
//!
//! - **Voters** are the eligible nodes plus any witness. A voter keeps one [`Ballot`] on disk:
//!   the highest epoch it voted in, for whom, and until when it promised not to vote for
//!   anyone else (the lease it granted).
//! - **One vote per epoch:** a voter grants epoch `e` to one candidate only, so each epoch has
//!   at most one primary.
//! - **Leases:** a voter refuses a newer epoch while the lease it granted is still running.
//!   The primary renews with every voter every [`RENEW_MS`], and treats its lease as ending
//!   [`LEASE_MS`] − [`MARGIN_MS`] after it *sent* the round that a majority granted. That ends
//!   before any majority voter's own lease runs out, so a new primary can't be elected while
//!   the old one still writes (for clock rates within ±1 %).
//! - **Pre-vote:** a node that lost contact first asks whether it *would* win, without
//!   changing any ballot. A node cut off from the cluster therefore never inflates epochs and
//!   doesn't depose a healthy primary when the partition heals.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// How long a granted lease lasts on the voter's clock.
pub const LEASE_MS: u64 = 15_000;
/// How often the primary renews.
pub const RENEW_MS: u64 = 5_000;
/// How much earlier the primary treats its lease as over (clock rates, delays).
pub const MARGIN_MS: u64 = 2_000;
/// How long a (pre-)election round may take before it's abandoned.
pub const ROUND_MS: u64 = 2_000;

/// A configuration version: `(epoch, seq)`, ordered.
pub type Version = (u64, u64);

/// A request for a vote (an election, a pre-vote, or a primary's renewal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ask {
    pub epoch: u64,
    pub candidate: String,
    pub round: u64,
    /// Would you vote for me? Changes nothing.
    pub pre: bool,
    /// The newest version the candidate has applied; voters refuse candidates behind them.
    pub applied: Version,
}

/// A voter's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    pub round: u64,
    pub granted: bool,
    /// The voter's epoch (a refused candidate or a deposed primary learns it).
    pub epoch: u64,
}

/// A voter's persistent state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ballot {
    /// The highest epoch voted in.
    pub epoch: u64,
    /// Who got that vote.
    pub candidate: String,
    /// Until when (voter's clock, Unix ms) no one else gets a newer epoch.
    pub lease_until_ms: u64,
}

impl Ballot {
    /// Whether the lease granted to someone other than `who` is still running.
    pub fn lease_held_by_other(&self, who: &str, now_ms: u64) -> bool {
        now_ms < self.lease_until_ms && self.candidate != who
    }

    /// Decides `ask`. `applied` is the voter's own newest version (a witness has none).
    pub fn decide(&mut self, ask: &Ask, now_ms: u64, applied: Version) -> Reply {
        let same = !self.candidate.is_empty()
            && ask.epoch == self.epoch
            && ask.candidate == self.candidate;
        let newer = ask.epoch > self.epoch
            && !self.lease_held_by_other(&ask.candidate, now_ms)
            && ask.applied >= applied;
        let granted = same || newer;
        if granted && !ask.pre {
            self.epoch = ask.epoch;
            self.candidate.clone_from(&ask.candidate);
            self.lease_until_ms = self.lease_until_ms.max(now_ms + LEASE_MS);
        }
        Reply {
            round: ask.round,
            granted,
            epoch: self.epoch,
        }
    }
}

/// Where a node stands in the election.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Follower,
    /// Asking whether it would win `epoch` (nothing changes yet).
    PreCandidate {
        epoch: u64,
        round: u64,
        started_ms: u64,
        grants: BTreeSet<String>,
    },
    /// Asking for real votes in `epoch`.
    Candidate {
        epoch: u64,
        round: u64,
        started_ms: u64,
        grants: BTreeSet<String>,
    },
    /// Primary of `epoch`; writes while `now < lease_until_ms`.
    Leader {
        epoch: u64,
        round: u64,
        round_started_ms: u64,
        grants: BTreeSet<String>,
        lease_until_ms: u64,
    },
}

/// What the caller should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    /// Send `ask` to voter `to`, and hand its reply to [`Elector::on_reply`].
    Send { to: String, ask: Ask },
    /// This node won `epoch`: become the primary (it may write once [`Elector::writable`]).
    Elected { epoch: u64 },
    /// The primary of `epoch` stops being primary (a newer epoch exists).
    StepDown { epoch: u64 },
    /// The ballot changed: persist it before answering anyone (a vote must survive restarts).
    Persist,
}

/// One node's election driver.
#[derive(Debug, Clone)]
pub struct Elector {
    pub id: String,
    /// Every voter's ID (this node's included when it votes).
    pub voters: Vec<String>,
    /// Whether this node may become primary (a witness only votes).
    pub eligible: bool,
    pub ballot: Ballot,
    pub phase: Phase,
    /// The highest epoch seen anywhere.
    pub max_epoch: u64,
    /// This node's newest applied version.
    pub applied: Version,
    next_round: u64,
    /// No new election before this (backoff with jitter).
    next_try_ms: u64,
}

impl Elector {
    pub fn new(id: &str, voters: Vec<String>, eligible: bool, ballot: Ballot) -> Self {
        Self {
            id: id.to_owned(),
            max_epoch: ballot.epoch,
            voters,
            eligible,
            ballot,
            phase: Phase::Follower,
            applied: (0, 0),
            next_round: 1,
            next_try_ms: 0,
        }
    }

    fn majority(&self) -> usize {
        self.voters.len() / 2 + 1
    }

    fn votes_itself(&self) -> bool {
        self.voters.contains(&self.id)
    }

    /// Picks up as primary of `epoch` after a restart (its own ballot is for itself in that
    /// epoch): it renews at once and writes again once a majority still grants it.
    pub fn resume(&mut self, epoch: u64) {
        self.max_epoch = self.max_epoch.max(epoch);
        let round = self.round();
        self.phase = Phase::Leader {
            epoch,
            round,
            round_started_ms: 0,
            grants: BTreeSet::new(),
            lease_until_ms: 0,
        };
    }

    /// Whether this node is the primary and may write now.
    pub fn writable(&self, now_ms: u64) -> bool {
        matches!(self.phase, Phase::Leader { lease_until_ms, .. } if now_ms < lease_until_ms)
    }

    /// The epoch this node leads, if it's the primary.
    pub fn leading(&self) -> Option<u64> {
        match self.phase {
            Phase::Leader { epoch, .. } => Some(epoch),
            _ => None,
        }
    }

    /// Asks every other voter, and itself (returned grants count).
    fn ask_all(&mut self, ask: &Ask, now_ms: u64, out: &mut Vec<Out>) -> BTreeSet<String> {
        let mut grants = BTreeSet::new();
        if self.votes_itself() {
            let before = self.ballot.clone();
            let applied = self.applied;
            if self.ballot.decide(ask, now_ms, applied).granted {
                grants.insert(self.id.clone());
            }
            if self.ballot != before {
                out.push(Out::Persist);
            }
        }
        for v in &self.voters {
            if *v != self.id {
                out.push(Out::Send {
                    to: v.clone(),
                    ask: ask.clone(),
                });
            }
        }
        grants
    }

    fn round(&mut self) -> u64 {
        let r = self.next_round;
        self.next_round += 1;
        r
    }

    /// Advances timers. `jitter_ms` is random in `0..LEASE_MS / 2` (spreads candidates).
    pub fn tick(&mut self, now_ms: u64, jitter_ms: u64) -> Vec<Out> {
        let mut out = Vec::new();
        match self.phase.clone() {
            Phase::Leader {
                epoch,
                round_started_ms,
                lease_until_ms,
                ..
            } => {
                if now_ms.saturating_sub(round_started_ms) >= RENEW_MS {
                    let round = self.round();
                    let ask = Ask {
                        epoch,
                        candidate: self.id.clone(),
                        round,
                        pre: false,
                        applied: self.applied,
                    };
                    let grants = self.ask_all(&ask, now_ms, &mut out);
                    let lease = if grants.len() >= self.majority() {
                        lease_until_ms.max(now_ms + LEASE_MS - MARGIN_MS)
                    } else {
                        lease_until_ms
                    };
                    self.phase = Phase::Leader {
                        epoch,
                        round,
                        round_started_ms: now_ms,
                        grants,
                        lease_until_ms: lease,
                    };
                }
            }
            Phase::PreCandidate { started_ms, .. } | Phase::Candidate { started_ms, .. }
                if now_ms.saturating_sub(started_ms) >= ROUND_MS =>
            {
                self.phase = Phase::Follower;
                self.next_try_ms = now_ms + jitter_ms;
            }
            Phase::Follower
                if self.eligible
                    && now_ms >= self.next_try_ms
                    && !self.ballot.lease_held_by_other(&self.id, now_ms) =>
            {
                let epoch = self.max_epoch.max(self.ballot.epoch) + 1;
                let round = self.round();
                let ask = Ask {
                    epoch,
                    candidate: self.id.clone(),
                    round,
                    pre: true,
                    applied: self.applied,
                };
                let grants = self.ask_all(&ask, now_ms, &mut out);
                self.next_try_ms = now_ms + LEASE_MS / 3 + jitter_ms;
                self.phase = Phase::PreCandidate {
                    epoch,
                    round,
                    started_ms: now_ms,
                    grants,
                };
                self.check_won(now_ms, &mut out);
            }
            _ => {}
        }
        out
    }

    /// Answers a peer's ask.
    pub fn on_ask(&mut self, ask: &Ask, now_ms: u64) -> (Reply, Vec<Out>) {
        let mut out = Vec::new();
        let before = self.ballot.clone();
        let reply = self.ballot.decide(ask, now_ms, self.applied);
        if self.ballot != before {
            out.push(Out::Persist);
        }
        if !ask.pre && reply.granted {
            self.observe_epoch(ask.epoch, &mut out);
        }
        (reply, out)
    }

    /// Notes an epoch seen anywhere (a vote, a heartbeat, a manifest): a primary of an older
    /// epoch steps down.
    pub fn observe(&mut self, epoch: u64) -> Vec<Out> {
        let mut out = Vec::new();
        self.observe_epoch(epoch, &mut out);
        out
    }

    fn observe_epoch(&mut self, epoch: u64, out: &mut Vec<Out>) {
        self.max_epoch = self.max_epoch.max(epoch);
        let mine = match &self.phase {
            Phase::Leader { epoch: e, .. } | Phase::Candidate { epoch: e, .. } => Some(*e),
            _ => None,
        };
        if let Some(e) = mine
            && epoch > e
        {
            if matches!(self.phase, Phase::Leader { .. }) {
                out.push(Out::StepDown { epoch: e });
            }
            self.phase = Phase::Follower;
        }
    }

    /// Handles a voter's reply.
    pub fn on_reply(&mut self, from: &str, r: &Reply, now_ms: u64) -> Vec<Out> {
        let mut out = Vec::new();
        if !r.granted {
            self.observe_epoch(r.epoch, &mut out);
            return out;
        }
        match &mut self.phase {
            Phase::PreCandidate { round, grants, .. } | Phase::Candidate { round, grants, .. }
                if *round == r.round =>
            {
                grants.insert(from.to_owned());
            }
            Phase::Leader {
                round,
                grants,
                round_started_ms,
                lease_until_ms,
                ..
            } if *round == r.round => {
                grants.insert(from.to_owned());
                if grants.len() > self.voters.len() / 2 {
                    *lease_until_ms =
                        (*lease_until_ms).max(*round_started_ms + LEASE_MS - MARGIN_MS);
                }
            }
            _ => return out,
        }
        self.check_won(now_ms, &mut out);
        out
    }

    /// Moves a candidate on when a majority granted.
    fn check_won(&mut self, now_ms: u64, out: &mut Vec<Out>) {
        let majority = self.majority();
        match self.phase.clone() {
            Phase::PreCandidate { epoch, grants, .. } if grants.len() >= majority => {
                let round = self.round();
                let ask = Ask {
                    epoch,
                    candidate: self.id.clone(),
                    round,
                    pre: false,
                    applied: self.applied,
                };
                let grants = self.ask_all(&ask, now_ms, out);
                self.phase = Phase::Candidate {
                    epoch,
                    round,
                    started_ms: now_ms,
                    grants,
                };
                self.check_won(now_ms, out);
            }
            Phase::Candidate {
                epoch,
                round,
                started_ms,
                grants,
            } if grants.len() >= majority => {
                self.max_epoch = self.max_epoch.max(epoch);
                self.phase = Phase::Leader {
                    epoch,
                    round,
                    round_started_ms: started_ms,
                    grants,
                    lease_until_ms: started_ms + LEASE_MS - MARGIN_MS,
                };
                out.push(Out::Elected { epoch });
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(epoch: u64, who: &str, pre: bool) -> Ask {
        Ask {
            epoch,
            candidate: who.into(),
            round: 1,
            pre,
            applied: (0, 0),
        }
    }

    // REQ: CLU-005 — one vote per epoch, and no newer epoch while a lease runs.
    #[test]
    fn clu_005_a_voter_grants_each_epoch_once_and_honours_leases() {
        let mut b = Ballot::default();
        assert!(b.decide(&ask(1, "a", false), 0, (0, 0)).granted);
        assert!(
            !b.decide(&ask(1, "b", false), 1, (0, 0)).granted,
            "epoch 1 is taken"
        );
        assert!(
            !b.decide(&ask(2, "b", false), 1_000, (0, 0)).granted,
            "a's lease runs"
        );
        assert!(
            b.decide(&ask(1, "a", false), 10_000, (0, 0)).granted,
            "renewal"
        );
        assert!(
            !b.decide(&ask(2, "b", false), 20_000, (0, 0)).granted,
            "renewed lease runs"
        );
        assert!(
            b.decide(&ask(2, "b", true), 30_000, (0, 0)).granted,
            "pre-vote after expiry"
        );
        assert_eq!(b.epoch, 1, "a pre-vote changes nothing");
        assert!(b.decide(&ask(2, "b", false), 30_000, (0, 0)).granted);
        assert!(
            !b.decide(&ask(1, "a", false), 30_001, (0, 0)).granted,
            "a is deposed"
        );
        let mut behind = ask(3, "c", false);
        behind.applied = (1, 4);
        assert!(
            !b.decide(&behind, 60_000, (2, 1)).granted,
            "candidates behind lose"
        );
    }

    // Two eligible nodes and a witness: the primary renews; when it dies, the other wins
    // only after the lease ran out.
    #[test]
    fn clu_005_witness_failover_waits_for_the_lease() {
        let voters = vec!["a".to_owned(), "b".to_owned(), "w".to_owned()];
        let mut a = Elector::new("a", voters.clone(), true, Ballot::default());
        let mut b = Elector::new("b", voters.clone(), true, Ballot::default());
        let mut w = Elector::new("w", voters, false, Ballot::default());
        b.next_try_ms = 100_000; // let a go first
        // Deliver everything a sends, synchronously.
        // Delivers what `from` sends (and what its replies make it send), synchronously.
        let deliver = |from: &mut Elector, outs: Vec<Out>, peers: &mut [&mut Elector], now| {
            let mut events = Vec::new();
            let mut queue: std::collections::VecDeque<Out> = outs.into();
            while let Some(o) = queue.pop_front() {
                match o {
                    Out::Send { to, ask } => {
                        if let Some(p) = peers.iter_mut().find(|p| p.id == to) {
                            let (r, _) = p.on_ask(&ask, now);
                            queue.extend(from.on_reply(&to, &r, now));
                        }
                    }
                    other => events.push(other),
                }
            }
            events
        };
        let outs = a.tick(0, 0);
        let ev = deliver(&mut a, outs, &mut [&mut b, &mut w], 0);
        assert!(ev.contains(&Out::Elected { epoch: 1 }), "{ev:?}");
        assert!(a.writable(1));
        for t in (5_000..=30_000).step_by(5_000) {
            let outs = a.tick(t, 0);
            deliver(&mut a, outs, &mut [&mut b, &mut w], t);
            assert!(a.writable(t + 1));
        }
        // a dies at 30 s. b's lease from a runs until 45 s.
        b.next_try_ms = 0;
        assert!(b.tick(40_000, 0).is_empty(), "the lease still runs");
        let outs = b.tick(46_000, 0);
        let ev = deliver(&mut b, outs, &mut [&mut w], 46_000);
        assert!(ev.contains(&Out::Elected { epoch: 2 }), "{ev:?}");
        assert!(
            !a.writable(46_000),
            "a's own view of its lease ended earlier"
        );
        // a returns and renews: refused with epoch 2, so it steps down.
        let outs = a.tick(47_000, 0);
        let ev = deliver(&mut a, outs, &mut [&mut b, &mut w], 47_000);
        assert!(ev.contains(&Out::StepDown { epoch: 1 }), "{ev:?}");
        assert_eq!(a.phase, Phase::Follower);
    }
}
