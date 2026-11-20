//! Automatic failover (REQ: CLU-005; `spec/12` §5, ADR-056): one vote per epoch, and leases.
//!
//! This module is the protocol only: no I/O and no clocks of its own (every call takes
//! `now_ms` on the caller's clock), so the partition simulator (`tests/sim.rs`) drives exactly
//! the code the server runs. The server's clock is [`crate::clock`], which never steps.
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
//! - **Giving way (ADR-178):** a node that grants a pre-vote to a node whose ID sorts before
//!   its own lets that node have the round ([`Elector::on_ask`]), so two nodes freed by the same
//!   lease end don't both ask for votes: with three voters they don't split them, short of a
//!   lost or badly delayed message, a restart, or a disagreement over the epoch, and with more
//!   voters a split gets rarer. It changes only when a node stands.
//! - **Maintenance (OPS-010, ADR-118):** a node in maintenance doesn't stand ([`Elector::standing`]
//!   is false) but still votes, so a planned event never weakens the quorum. A primary that
//!   hands over ([`Elector::stepping_down`]) stops renewing: its lease runs out and another node
//!   is elected the usual way.

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
    /// Until when no one else gets a newer epoch, on the voter's election clock
    /// ([`crate::clock`]).
    pub lease_until_ms: u64,
    /// The process whose election clock `lease_until_ms` is on ([`crate::clock::id`]); 0 for
    /// a ballot written by a build that timed leases on the wall clock.
    #[serde(default)]
    pub clock: u64,
}

impl Ballot {
    /// REQ: CLU-005 (ADR-056, review 05-05) — moves a ballot onto `clock`, whose time is now
    /// `now_ms`. A lease on another clock (another process, or the wall clock of an older
    /// build) can't be compared with this one, so a lease it granted is taken to run a full
    /// [`LEASE_MS`] from now: never shorter than what was promised. Returns whether the
    /// ballot changed (and must be stored before it's read again).
    pub fn adopt(&mut self, clock: u64, now_ms: u64) -> bool {
        if self.clock == clock {
            return false;
        }
        if self.lease_until_ms > 0 {
            self.lease_until_ms = now_ms + LEASE_MS;
        }
        self.clock = clock;
        true
    }

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
    /// REQ: OPS-010 — whether this eligible node stands for election now: false while it's in
    /// maintenance. It keeps voting either way.
    pub standing: bool,
    /// REQ: OPS-010 — a primary handing over (maintenance): it stops renewing its lease, so
    /// another node is elected once the lease runs out.
    pub stepping_down: bool,
    next_round: u64,
    /// No new election before this (backoff with jitter, or a round given to another node:
    /// ADR-178).
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
            standing: true,
            stepping_down: false,
            next_round: 1,
            next_try_ms: 0,
        }
    }

    /// Whether this node may become primary now: eligible and not in maintenance.
    fn may_stand(&self) -> bool {
        self.eligible && self.standing
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
                // REQ: OPS-010 — a primary handing over lets its lease run out.
                if !self.stepping_down && now_ms.saturating_sub(round_started_ms) >= RENEW_MS {
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
                if !self.may_stand() || now_ms.saturating_sub(started_ms) >= ROUND_MS =>
            {
                self.phase = Phase::Follower;
                self.next_try_ms = now_ms + jitter_ms;
            }
            Phase::Follower
                if self.may_stand()
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

    /// Answers a peer's ask. The reply is the ballot's ([`Ballot::decide`]); granting a pre-vote
    /// may also make this node give that candidate the round ([`Self::give_way`]).
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
        if ask.pre && reply.granted {
            self.give_way(ask, now_ms);
        }
        (reply, out)
    }

    /// REQ: CLU-005 (ADR-178) — this node has just granted `ask`, a pre-vote. When the candidate
    /// sorts before this node and asks for the epoch this node would stand for (or a newer one),
    /// this node gives it the round, and that round is all it costs this node. A pre-candidate
    /// stands down and may stand again [`ROUND_MS`] from now (not at the retry time it set when
    /// its attempt started, 5 to 12.5 s after that start). A follower doesn't stand for
    /// [`ROUND_MS`], or until a later retry time it already had.
    /// Two nodes freed by the same lease end otherwise both send pre-votes on their next tick,
    /// grant each other's (a pre-vote binds nothing), vote for themselves, and split the vote;
    /// each one's own vote is then a lease the other has to wait out. With three voters, where
    /// neither can win without the other, they don't split the vote, short of a lost or badly
    /// delayed message, a restart, or a disagreement over the epoch (there is no giving way to an
    /// older epoch than this node's own); with more voters a split only gets rarer (ADR-178). A
    /// candidate (it has voted for itself) and a primary don't give way. Only when this node
    /// stands changes: no ballot, epoch, lease or reply does.
    fn give_way(&mut self, ask: &Ask, now_ms: u64) {
        if ask.candidate >= self.id {
            return;
        }
        let contest = match self.phase {
            Phase::Follower => self.max_epoch.max(self.ballot.epoch) + 1,
            Phase::PreCandidate { epoch, .. } => epoch,
            Phase::Candidate { .. } | Phase::Leader { .. } => return,
        };
        if ask.epoch >= contest {
            self.next_try_ms = if matches!(self.phase, Phase::PreCandidate { .. }) {
                now_ms + ROUND_MS
            } else {
                self.next_try_ms.max(now_ms + ROUND_MS)
            };
            self.phase = Phase::Follower;
        }
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
        // REQ: OPS-010 — maintenance started mid-election: stand down instead of winning.
        if !self.may_stand()
            && matches!(
                self.phase,
                Phase::PreCandidate { .. } | Phase::Candidate { .. }
            )
        {
            self.phase = Phase::Follower;
            return;
        }
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

    // REQ: CLU-005 (review 05-05) — a ballot from another process, or from a build that
    // timed leases on the wall clock, keeps the lease it granted for a full term on the new
    // clock, whatever the two clocks read.
    #[test]
    fn clu_005_a_ballot_from_another_clock_keeps_its_lease() {
        let mut b = Ballot::default();
        // Granted on the wall clock by an older build (clock 0).
        assert!(
            b.decide(&ask(1, "a", false), 1_700_000_000_000, (0, 0))
                .granted
        );
        // A new process whose clock reads 5 s: the lease runs 15 s from now, not forever.
        assert!(b.adopt(7, 5_000));
        assert_eq!((b.clock, b.lease_until_ms), (7, 5_000 + LEASE_MS));
        assert!(!b.adopt(7, 9_000), "same clock: nothing to do");
        assert!(
            !b.decide(&ask(2, "b", false), 19_000, (0, 0)).granted,
            "still a's"
        );
        assert!(b.decide(&ask(2, "b", false), 20_001, (0, 0)).granted);
        // Another restart whose clock reads far ahead: the lease is not taken as over.
        assert!(b.adopt(9, 90_000_000));
        assert!(!b.decide(&ask(3, "c", false), 90_000_001, (0, 0)).granted);
        // A ballot that never granted a lease stays without one.
        let mut fresh = Ballot::default();
        assert!(fresh.adopt(7, 5_000));
        assert_eq!(fresh.lease_until_ms, 0);
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

    /// Delivers what `from` sends, and what the replies make it send, synchronously: the
    /// sender's events, then the peers' (by peer).
    fn exchange(
        from: &mut Elector,
        outs: Vec<Out>,
        peers: &mut [&mut Elector],
        now: u64,
    ) -> (Vec<Out>, Vec<(String, Out)>) {
        let (mut mine, mut theirs) = (Vec::new(), Vec::new());
        let mut queue: std::collections::VecDeque<Out> = outs.into();
        while let Some(o) = queue.pop_front() {
            match o {
                Out::Send { to, ask } => {
                    if let Some(p) = peers.iter_mut().find(|p| p.id == to) {
                        let (r, outs) = p.on_ask(&ask, now);
                        theirs.extend(outs.into_iter().map(|o| (to.clone(), o)));
                        queue.extend(from.on_reply(&to, &r, now));
                    }
                }
                other => mine.push(other),
            }
        }
        (mine, theirs)
    }

    /// Elects `a` among `voters` at time 0 and renews until 25 s (the others wait).
    fn elect_a(voters: &[&str]) -> Vec<Elector> {
        let ids: Vec<String> = voters.iter().map(|v| (*v).to_owned()).collect();
        let mut nodes: Vec<Elector> = ids
            .iter()
            .map(|id| Elector::new(id, ids.clone(), *id != "w", Ballot::default()))
            .collect();
        for n in nodes.iter_mut().skip(1) {
            n.next_try_ms = 1_000_000;
        }
        let (a, rest) = nodes.split_first_mut().unwrap();
        let mut peers: Vec<&mut Elector> = rest.iter_mut().collect();
        let outs = a.tick(0, 0);
        let (ev, _) = exchange(a, outs, &mut peers, 0);
        assert!(ev.contains(&Out::Elected { epoch: 1 }), "{ev:?}");
        for t in (5_000..=25_000).step_by(5_000) {
            let outs = a.tick(t, 0);
            exchange(a, outs, &mut peers, t);
        }
        for n in nodes.iter_mut().skip(1) {
            n.next_try_ms = 0;
        }
        nodes
    }

    // REQ: OPS-010 (ADR-118) — a node in maintenance never stands but still votes: with the
    // primary gone and the only other eligible node in maintenance nobody is elected; the
    // maintenance node's vote still elects a third node; and once maintenance ends it stands.
    #[test]
    fn ops_010_a_node_in_maintenance_votes_but_never_stands() {
        let mut nodes = elect_a(&["a", "b", "w"]);
        let (_a, rest) = nodes.split_first_mut().unwrap();
        let (b, w) = rest.split_at_mut(1);
        let (b, w) = (&mut b[0], &mut w[0]);
        b.standing = false;
        // a died at 25 s; its lease ran out at 40 s.
        for t in (30_000..=120_000).step_by(250) {
            let outs = b.tick(t, 0);
            assert!(
                outs.iter().all(|o| !matches!(o, Out::Send { .. })),
                "b asked for votes at {t} while in maintenance: {outs:?}"
            );
            let (ev, _) = exchange(b, outs, &mut [&mut *w], t);
            assert!(ev.is_empty(), "{ev:?}");
        }
        assert_eq!(b.phase, Phase::Follower);
        // Maintenance ends: b stands and wins.
        b.standing = true;
        let outs = b.tick(121_000, 0);
        let (ev, _) = exchange(b, outs, &mut [&mut *w], 121_000);
        assert!(ev.contains(&Out::Elected { epoch: 2 }), "{ev:?}");

        // Three eligible nodes: c is elected with b's vote while b is in maintenance.
        let mut nodes = elect_a(&["a", "b", "c"]);
        let (_a, rest) = nodes.split_first_mut().unwrap();
        let (b, c) = rest.split_at_mut(1);
        let (b, c) = (&mut b[0], &mut c[0]);
        b.standing = false;
        let mut elected = None;
        for t in (30_000..=60_000).step_by(250) {
            let outs = b.tick(t, 0);
            let (ev, _) = exchange(b, outs, &mut [&mut *c], t);
            assert!(ev.is_empty(), "{ev:?}");
            let outs = c.tick(t, 0);
            let (ev, _) = exchange(c, outs, &mut [&mut *b], t);
            if ev.contains(&Out::Elected { epoch: 2 }) {
                elected = Some(t);
                break;
            }
        }
        assert!(elected.is_some(), "c wasn't elected with b's vote");
        assert_eq!(b.ballot.candidate, "c", "b voted");
        // A candidate that enters maintenance mid-election stands down instead of winning.
        let mut nodes = elect_a(&["a", "b", "w"]);
        let (_a, rest) = nodes.split_first_mut().unwrap();
        let b = &mut rest[0];
        let _outs = b.tick(41_000, 0);
        let Phase::PreCandidate { round, .. } = b.phase else {
            panic!("expected a pre-vote, got {:?}", b.phase)
        };
        b.standing = false;
        let r = Reply {
            round,
            granted: true,
            epoch: 1,
        };
        b.on_reply("w", &r, 41_100);
        assert_eq!(b.phase, Phase::Follower);
    }

    // REQ: OPS-010 (ADR-118) — a primary handing over stops renewing: its lease ends, the
    // other eligible node is elected within the lease window, never while the old primary can
    // still write, and the old primary steps down and doesn't stand again.
    #[test]
    fn ops_010_a_primary_hands_over() {
        let mut nodes = elect_a(&["a", "b", "w"]);
        let (a, rest) = nodes.split_first_mut().unwrap();
        let (b, w) = rest.split_at_mut(1);
        let (b, w) = (&mut b[0], &mut w[0]);
        a.stepping_down = true;
        a.standing = false;
        let (mut elected, mut stepped_down) = (None, false);
        for t in (30_000..=90_000).step_by(250) {
            let outs = a.tick(t, 0);
            let (ev, theirs) = exchange(a, outs, &mut [&mut *b, &mut *w], t);
            assert!(!ev.iter().any(|o| matches!(o, Out::Elected { .. })));
            assert!(theirs.is_empty() || elected.is_some(), "{theirs:?}");
            let outs = b.tick(t, 0);
            let (ev, theirs) = exchange(b, outs, &mut [&mut *a, &mut *w], t);
            if ev.contains(&Out::Elected { epoch: 2 }) {
                elected = Some(t);
            }
            stepped_down |= theirs
                .iter()
                .any(|(who, o)| who == "a" && *o == Out::StepDown { epoch: 1 });
            assert!(!(a.writable(t) && b.writable(t)), "two writers at {t} ms");
        }
        let at = elected.expect("b was elected");
        assert!(
            at <= 25_000 + LEASE_MS + ROUND_MS,
            "elected at {at} ms, after the lease window"
        );
        assert!(stepped_down, "a stepped down");
        assert_eq!(a.phase, Phase::Follower);
        assert!(b.writable(90_000));
    }

    // REQ: CLU-005 (ADR-154, GitHub issue #3) — an emergency primary hands over to a Git-managed
    // node: the other eligible voter (not Git-managed) holds back, so the Git-managed node is the
    // only one that stands. It is elected within the lease window, never while the old primary
    // can still write, the voter that held back still voted for it and never asked, and the old
    // primary steps down.
    #[test]
    fn clu_005_a_git_node_is_elected_when_the_emergency_primary_hands_over() {
        let mut nodes = elect_a(&["a", "b", "c"]);
        let (a, rest) = nodes.split_first_mut().unwrap();
        let (b, c) = rest.split_at_mut(1);
        let (b, c) = (&mut b[0], &mut c[0]);
        // a is the emergency primary, b the Git-managed node, c another node that isn't.
        a.stepping_down = true;
        a.standing = false;
        c.standing = false;
        let (mut elected, mut stepped_down) = (None, false);
        for t in (30_000..=90_000).step_by(250) {
            let outs = a.tick(t, 0);
            let (ev, _) = exchange(a, outs, &mut [&mut *b, &mut *c], t);
            assert!(!ev.iter().any(|o| matches!(o, Out::Elected { .. })));
            let outs = c.tick(t, 0);
            assert!(
                outs.iter().all(|o| !matches!(o, Out::Send { .. })),
                "c asked for votes at {t} ms while holding back: {outs:?}"
            );
            let outs = b.tick(t, 0);
            let (ev, theirs) = exchange(b, outs, &mut [&mut *a, &mut *c], t);
            if ev.contains(&Out::Elected { epoch: 2 }) {
                elected = Some(t);
            }
            stepped_down |= theirs
                .iter()
                .any(|(who, o)| who == "a" && *o == Out::StepDown { epoch: 1 });
            assert!(!(a.writable(t) && b.writable(t)), "two writers at {t} ms");
        }
        let at = elected.expect("the Git-managed node was elected");
        assert!(
            at <= 25_000 + LEASE_MS + ROUND_MS,
            "elected at {at} ms, after the lease window"
        );
        assert!(stepped_down, "the emergency primary stepped down");
        assert_eq!(a.phase, Phase::Follower);
        assert_eq!(c.phase, Phase::Follower, "c never stood");
        assert_eq!(c.ballot.candidate, "b", "c voted for the Git-managed node");
        assert!(b.writable(90_000));
    }

    /// The ask `outs` sends to `to`.
    fn ask_to(outs: &[Out], to: &str) -> Ask {
        outs.iter()
            .find_map(|o| match o {
                Out::Send { to: t, ask } if t == to => Some(ask.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no ask to {to} in {outs:?}"))
    }

    // REQ: CLU-005 (ADR-178) — two pre-candidates whose pre-votes cross (the primary, a, is gone):
    // each grants the other's, as before, but the one that sorts after gives the other its round,
    // so only one of them asks for real votes and the vote doesn't split. The replies are exactly
    // what the ballots decide, and a pre-vote still changes no ballot.
    #[test]
    fn clu_005_crossed_pre_votes_elect_the_lower_node_in_one_round() {
        let voters: Vec<String> = ["a", "b", "c"].iter().map(|v| (*v).to_owned()).collect();
        let mut b = Elector::new("b", voters.clone(), true, Ballot::default());
        let mut c = Elector::new("c", voters, true, Ballot::default());
        let (from_b, from_c) = (b.tick(1_000, 0), c.tick(1_000, 0));
        assert!(matches!(b.phase, Phase::PreCandidate { epoch: 1, .. }));
        assert!(matches!(c.phase, Phase::PreCandidate { epoch: 1, .. }));
        let (pre_b, pre_c) = (ask_to(&from_b, "c"), ask_to(&from_c, "b"));
        let (ballot_b, ballot_c) = (b.ballot.clone(), c.ballot.clone());
        // The pre-votes cross: each node grants the other's, from its ballot, which doesn't move.
        let (to_c, outs) = b.on_ask(&pre_c, 1_005);
        assert_eq!(to_c, ballot_b.clone().decide(&pre_c, 1_005, (0, 0)));
        assert!(to_c.granted && outs.is_empty());
        let (to_b, outs) = c.on_ask(&pre_b, 1_005);
        assert_eq!(to_b, ballot_c.clone().decide(&pre_b, 1_005, (0, 0)));
        assert!(to_b.granted && outs.is_empty());
        assert_eq!((&b.ballot, &c.ballot), (&ballot_b, &ballot_c));
        // c granted b, which sorts before it: c gives b the round; b, which granted c, goes on.
        assert_eq!(c.phase, Phase::Follower, "c gave way");
        assert!(matches!(b.phase, Phase::PreCandidate { .. }));
        // b's pre-vote wins with c's grant; c's own grant from b arrives too late to matter.
        let real = b.on_reply("c", &to_b, 1_010);
        assert!(matches!(b.phase, Phase::Candidate { epoch: 1, .. }));
        assert!(
            c.on_reply("b", &to_c, 1_010).is_empty(),
            "c no longer stands"
        );
        assert_eq!(c.phase, Phase::Follower);
        // c votes for b, which is elected in epoch 1: one round.
        let (vote, outs) = c.on_ask(&ask_to(&real, "c"), 1_015);
        assert!(vote.granted && outs.contains(&Out::Persist));
        assert!(
            b.on_reply("c", &vote, 1_020)
                .contains(&Out::Elected { epoch: 1 })
        );
        assert_eq!((c.ballot.epoch, c.ballot.candidate.as_str()), (1, "b"));
        // At 7 s c's retry time (a round after it gave way at 1.005 s) has long passed, and b's
        // lease on c's ballot runs until 1.015 s + LEASE_MS: only the lease keeps c from
        // standing here.
        assert!(c.tick(7_000, 0).is_empty(), "c holds b's lease");
    }

    // REQ: CLU-005 (ADR-178) — giving a node the round costs the giver that round and no more: a
    // pre-candidate that gives way may stand again exactly ROUND_MS later, not at the retry time
    // it set when its attempt started; a follower waits at least ROUND_MS and keeps a later
    // retry time it already had.
    #[test]
    fn clu_005_giving_way_costs_the_giver_one_round() {
        let voters: Vec<String> = ["a", "b", "c"].iter().map(|v| (*v).to_owned()).collect();
        let pre = |who: &str| Ask {
            epoch: 1,
            candidate: who.into(),
            round: 1,
            pre: true,
            applied: (0, 0),
        };
        let stands = |outs: &[Out]| outs.iter().any(|o| matches!(o, Out::Send { .. }));
        // c starts an attempt at 1 s with the largest jitter: its own retry time is 13.5 s.
        let mut c = Elector::new("c", voters.clone(), true, Ballot::default());
        assert!(stands(&c.tick(1_000, LEASE_MS / 2 - 1)));
        assert!(matches!(c.phase, Phase::PreCandidate { epoch: 1, .. }));
        assert_eq!(c.next_try_ms, 1_000 + LEASE_MS / 3 + LEASE_MS / 2 - 1);
        // It grants a's pre-vote at t and gives way: it may stand again at t + ROUND_MS.
        let t = 1_010;
        assert!(c.on_ask(&pre("a"), t).0.granted);
        assert_eq!(c.phase, Phase::Follower);
        assert_eq!(
            c.next_try_ms,
            t + ROUND_MS,
            "a pre-candidate waits one round"
        );
        assert!(!stands(&c.tick(t + ROUND_MS - 1, 0)));
        assert!(stands(&c.tick(t + ROUND_MS, 0)), "c stands a round later");
        // A follower: a later retry time it had stays, and none becomes a round from now.
        let mut f = Elector::new("c", voters.clone(), true, Ballot::default());
        f.next_try_ms = 50_000;
        assert!(f.on_ask(&pre("a"), 10_000).0.granted);
        assert_eq!(f.next_try_ms, 50_000);
        let mut g = Elector::new("c", voters, true, Ballot::default());
        assert!(g.on_ask(&pre("a"), 10_000).0.granted);
        assert_eq!(g.next_try_ms, 10_000 + ROUND_MS);
    }

    // REQ: CLU-005 (ADR-178) — a follower that grants a pre-vote to a node that sorts before it
    // doesn't stand for a round (that node may be about to ask for real votes); one that grants a
    // node that sorts after it, or refuses, stands as before.
    #[test]
    fn clu_005_a_follower_gives_a_lower_node_whose_pre_vote_it_grants_a_round() {
        let voters: Vec<String> = ["a", "b", "c"].iter().map(|v| (*v).to_owned()).collect();
        let pre = |who: &str| Ask {
            epoch: 1,
            candidate: who.into(),
            round: 1,
            pre: true,
            applied: (0, 0),
        };
        let stands = |outs: &[Out]| outs.iter().any(|o| matches!(o, Out::Send { .. }));
        // c grants a's pre-vote at 5 s: it doesn't stand until a round later.
        let mut c = Elector::new("c", voters.clone(), true, Ballot::default());
        assert!(c.on_ask(&pre("a"), 5_000).0.granted);
        assert!(
            !stands(&c.tick(5_000 + ROUND_MS - 1, 0)),
            "c stood within a's round"
        );
        assert!(
            stands(&c.tick(5_000 + ROUND_MS, 0)),
            "c stands after a's round"
        );
        // a grants c's pre-vote: a sorts before c, so a may stand at once.
        let mut a = Elector::new("a", voters.clone(), true, Ballot::default());
        assert!(a.on_ask(&pre("c"), 5_000).0.granted);
        assert!(
            stands(&a.tick(5_000, 0)),
            "a waited for a node that sorts after it"
        );
        // A pre-vote it refuses gives nothing: c, holding b's lease until 15 s, refuses a's
        // pre-vote just before and stands when the lease ends.
        let mut c = Elector::new("c", voters, true, Ballot::default());
        assert!(c.on_ask(&ask(1, "b", false), 0).0.granted);
        let mut again = pre("a");
        again.epoch = 2;
        assert!(
            !c.on_ask(&again, LEASE_MS - 100).0.granted,
            "b's lease runs"
        );
        assert!(
            stands(&c.tick(LEASE_MS, 0)),
            "a refused pre-vote held c back"
        );
    }
}
