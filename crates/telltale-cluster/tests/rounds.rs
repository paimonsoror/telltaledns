//! `telltale-rounds`: how many election rounds a failover takes, on the real election code
//! (REQ: CLU-005, ADR-178).
//!
//! `sim.rs` checks that the election is safe under partitions; this one measures how quickly a
//! healthy cluster elects a new primary after `kill -9` of the old one, which is what
//! `deploy/cluster/gitops-failover-e2e.sh` and `failover-e2e.sh` time on CI. Every node runs the
//! real [`Elector`], driven the way `failover::run` drives it:
//! - each node's election loop wakes on its 250 ms tick (`failover::TICK`, a grid whose phase is
//!   set when the process starts) and on every vote reply, and each wake-up is one
//!   `failover::step`: the `GitOps` hold-back decides `standing` (`Cluster::defers_to_git_node` and
//!   `bounded_deference`, from the heartbeats the node last had from the Git-managed node), the
//!   reply goes to `on_reply`, and then `tick(now, jitter)` runs with `jitter` drawn afresh from
//!   `0..LEASE_MS / 2` on every step, exactly as the caller draws it (one generator per process);
//! - a step whose output says `Persist` writes the ballot (an fsync, 0.5 to 5 ms here) before
//!   anything it sends leaves the node, and a voter writes its ballot before its reply leaves;
//! - every vote request, reply and heartbeat takes an explicit one-way delay ([`Net`]);
//! - the primary renews with the real code until it is killed, and then sends nothing more.
//!
//! The topologies are the scripts' ([`Topology`]). The replicas are started together after the
//! primary, open their streams to it 20 to 50 ms apart, may stand only once they hold the cluster
//! key (the server then builds a new `Elector` from the stored ballot), and the primary is killed
//! 0.1 to 0.6 s after the last of them does, as the scripts do. Because the scripts start the
//! replicas back to back, their election loops tick almost in step: in the 48 kept runs of the
//! VM study (2026-11-19) the two replicas' tick phases were 0 to 34 ms apart (median 8 ms), where
//! independent phases would spread over 0 to 125 ms. [`Model::scripts`] reproduces that (each
//! replica's phase within 30 ms of a common one); [`Model::spread`] gives every node its own
//! phase, as nodes started at different times have.
//!
//! Not modelled: epochs seen in heartbeats (`observe`; nothing in these runs changes them), clock
//! drift and restarts (`sim.rs` has both), and the server's processing time beyond the delays.
//!
//! A *round* is one epoch: the new primary's epoch minus the dead one's, as the e2e scripts
//! report it. `TELLTALE_ROUNDS_SEEDS` sets the runs per scenario (default 20,000 in release
//! builds, 1,000 in debug builds), `TELLTALE_ROUNDS_SEED` the first seed; to explore,
//! `TELLTALE_ROUNDS_DELAY_US` replaces the timing tests' mean delay and `TELLTALE_ROUNDS_ALIGN_US`
//! their phase spread (0: independent phases).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};

use telltale_cluster::election::{Ask, Ballot, Elector, LEASE_MS, Out, Phase, ROUND_MS, Reply};

/// The election loop's tick (`failover::TICK`).
const TICK_US: u64 = 250_000;
/// Heartbeats on a stream (`net::HEARTBEAT`).
const HEARTBEAT_US: u64 = 5_000_000;
/// A peer heard from within three heartbeats is up (`Member::up`).
const UP_MS: u64 = 15_000;
/// How long a node holds back for a Git-managed node with no primary up (`net::DEFER_MAX_MS`).
const DEFER_MAX_MS: u64 = 60_000;
/// Give up on a run that elected nobody this long after the kill (µs).
const GIVE_UP_US: u64 = 300_000_000;

/// The mean one-way delay of a vote request or reply (beyond a 50 µs floor) at which the first
/// round splits about as often as on CI's runners, the model's one free parameter: 14 of the 79
/// `GitOps` runs there needed more than one round (18 %); before ADR-178 this model gives 19 % at
/// 6 ms. The VM study's 2 of 48 (4 %) corresponds to 0.5 to 1 ms (3 to 6 %).
const CI_DELAY_US: u64 = 6_000;
/// How far apart the replicas' tick phases are when the scripts start them together (above).
const SCRIPTS_ALIGN_US: u64 = 30_000;

/// xorshift64*: deterministic per seed (as in `sim.rs`).
struct Rng(u64);

impl Rng {
    fn new(seed: u64, stream: u64) -> Self {
        let mut r = Self(
            (seed ^ stream.wrapping_mul(0xD1B5_4A32_D192_ED03)).wrapping_mul(0x9E37_79B9_7F4A_7C15)
                | 1,
        );
        r.next();
        r
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo)
    }
    #[allow(clippy::cast_precision_loss)]
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }
}

/// The message delay model (one way, drawn for every message independently).
#[derive(Debug, Clone, Copy)]
struct Net {
    /// Every message takes at least this (µs).
    floor_us: u64,
    /// Plus an exponential delay with this mean (µs): scheduling, TLS, the handler.
    mean_us: u64,
    /// This share of messages is delayed by up to `tail_us` more (a stall; 0 for none).
    tail: f64,
    tail_us: u64,
    /// This share of messages is lost (the RPC never answers).
    loss: f64,
}

/// A scenario's timing.
#[derive(Debug, Clone, Copy)]
struct Model {
    net: Net,
    /// 0: every node's tick grid has its own random phase. Otherwise the replicas' phases lie
    /// within this many µs of a common phase.
    align_us: u64,
}

impl Model {
    /// The scripts on CI: the replicas started together, nothing lost.
    fn scripts() -> Self {
        Self {
            net: Net {
                floor_us: 50,
                mean_us: env("TELLTALE_ROUNDS_DELAY_US", CI_DELAY_US),
                tail: 0.0,
                tail_us: 0,
                loss: 0.0,
            },
            align_us: env("TELLTALE_ROUNDS_ALIGN_US", SCRIPTS_ALIGN_US),
        }
    }

    /// Nodes started at different times (independent tick phases), the same delays.
    fn spread() -> Self {
        Self {
            align_us: 0,
            ..Self::scripts()
        }
    }
}

/// Who runs, after the scripts in `deploy/cluster/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Topology {
    /// `gitops-failover-e2e.sh`: three eligible nodes under the `GitOps` authority. The primary
    /// (node 0) is Git-managed; the other two aren't, so they hold back while it is up.
    GitOps,
    /// Three eligible nodes without the `GitOps` authority.
    Three,
    /// `failover-e2e.sh`: two eligible nodes and a witness (node 2), which only votes.
    Witness,
    /// Five eligible nodes: four candidates once the primary is gone.
    Five,
    /// Three eligible nodes and two witnesses (nodes 3 and 4): five voters, majority three, so
    /// once the primary is gone each of the two candidates can win with the witnesses alone.
    TwoWitnesses,
    /// Four eligible nodes {P, L, X, H}: H (node 3) sorts after L and X, and the L-X link is
    /// cut, so once P is gone only H can reach a majority, while L and X keep asking H.
    Cut4,
    /// Five eligible nodes: H (node 4) in the middle of a star of three lower leaves that reach
    /// only H (and P), so once P is gone only H can win.
    Star5,
}

impl Topology {
    fn nodes(self) -> usize {
        match self {
            Self::GitOps | Self::Three | Self::Witness => 3,
            Self::Cut4 => 4,
            Self::Five | Self::TwoWitnesses | Self::Star5 => 5,
        }
    }

    /// Whether node `i` may stand once it holds the cluster key (a witness only votes).
    fn can_lead(self, i: usize) -> bool {
        match self {
            Self::Witness => i != 2,
            Self::TwoWitnesses => i < 3,
            _ => true,
        }
    }

    /// Whether the link between `a` and `b` is cut (both ways).
    fn cut(self, a: usize, b: usize) -> bool {
        match self {
            Self::Cut4 => (a == 1 && b == 2) || (a == 2 && b == 1),
            Self::Star5 => a != b && (1..=3).contains(&a) && (1..=3).contains(&b),
            _ => false,
        }
    }

    /// The node that alone can win once the primary is gone, where there is one.
    fn only_winner(self) -> Option<usize> {
        match self {
            Self::Cut4 | Self::Star5 => Some(self.nodes() - 1),
            _ => None,
        }
    }
}

#[derive(Debug)]
enum Msg {
    Ask(Ask),
    Reply(Reply),
}

#[derive(Debug)]
enum Ev {
    Tick(usize),
    Deliver {
        from: usize,
        to: usize,
        msg: Msg,
    },
    /// A heartbeat leaves `from` for `to` (and the next one is due a heartbeat later).
    HeartbeatSend {
        from: usize,
        to: usize,
    },
    Heartbeat {
        from: usize,
        to: usize,
    },
    /// `to` receives the cluster key: it may stand from now on.
    Key(usize),
    Kill(usize),
}

struct Node {
    el: Elector,
    up: bool,
    /// Git-managed (`config_source = "gitops"`).
    git: bool,
    /// May stand once it holds the cluster key (false for a witness).
    can_lead: bool,
    /// When this node last heard from each peer, on the election clock (ms).
    last_seen_ms: Vec<Option<u64>>,
    /// `Cluster::defer_since_ms`.
    defer_since_ms: u64,
    /// This process's own source of the caller's jitter.
    jitter: Rng,
    /// The first step after the kill that found this node free to stand (eligible, standing, a
    /// follower, and no other node's lease running on its ballot), µs.
    free_us: Option<u64>,
    /// When it sent each of its pre-votes after the kill, µs.
    pre_votes_us: Vec<u64>,
}

/// What one run did.
#[derive(Debug, Clone)]
struct Outcome {
    rounds: u64,
    took_ms: u64,
    /// The first pre-votes of the two earliest candidates after the kill (µs after it).
    first_tries_us: Vec<u64>,
    /// For each node that stood: whether its first pre-vote went out on the step that found
    /// it free to stand (no wait of its own).
    first_try_at_once: Vec<bool>,
    /// The node that became primary.
    winner: usize,
}

struct Sim {
    t: u64,
    topo: Topology,
    net: Net,
    /// `cut[a][b]`: nothing gets from `a` to `b`.
    cut: Vec<Vec<bool>>,
    nodes: Vec<Node>,
    ids: Vec<String>,
    queue: BinaryHeap<Reverse<(u64, u64)>>,
    slab: Vec<Option<Ev>>,
    rng: Rng,
    winners: HashMap<u64, String>,
    killed_us: Option<u64>,
    dead_epoch: u64,
    /// The first primary holding a lease after the kill: (epoch, when, which node).
    elected: Option<(u64, u64, usize)>,
}

/// `net::bounded_deference`, with `since` kept by the caller.
fn bounded_deference(wants: bool, primary_up: bool, since: &mut u64, now: u64) -> bool {
    if !wants || primary_up {
        *since = 0;
        return wants;
    }
    if *since == 0 {
        *since = now;
    }
    now.saturating_sub(*since) < DEFER_MAX_MS
}

impl Sim {
    fn new(seed: u64, topo: Topology, model: Model) -> Self {
        let mut scen = Rng::new(seed, 1);
        let n = topo.nodes();
        // Node IDs are random, so the primary's place among the sorted voters is too.
        let mut ids: Vec<String> = (0..n).map(|_| format!("{:016x}", scen.next())).collect();
        if topo.only_winner().is_some() {
            // H, the last node, sorts after every other replica.
            ids[1..].sort();
        }
        let mut voters = ids.clone();
        voters.sort();
        let cut = (0..n)
            .map(|a| (0..n).map(|b| topo.cut(a, b)).collect())
            .collect();
        let nodes = (0..n)
            .map(|i| Node {
                // Only the first node holds the key at the start; the others are joining.
                el: Elector::new(&ids[i], voters.clone(), i == 0, Ballot::default()),
                up: true,
                git: topo == Topology::GitOps && i == 0,
                can_lead: topo.can_lead(i),
                last_seen_ms: vec![None; n],
                defer_since_ms: 0,
                jitter: Rng::new(seed, 100 + i as u64),
                free_us: None,
                pre_votes_us: Vec::new(),
            })
            .collect();
        let mut sim = Self {
            t: 0,
            topo,
            net: model.net,
            cut,
            nodes,
            ids,
            queue: BinaryHeap::new(),
            slab: Vec::new(),
            rng: Rng::new(seed, 2),
            winners: HashMap::new(),
            killed_us: None,
            dead_epoch: 0,
            elected: None,
        };
        // The primary started earlier; its election loop ticks from a phase of its own.
        let phase = scen.below(TICK_US);
        sim.at(phase, Ev::Tick(0));
        let base = scen.below(TICK_US);
        let mut last_key = 0;
        for i in 1..n {
            // The replica opens its stream to the primary; heartbeats flow every 5 s on it.
            let open = scen.range(20_000, 50_000);
            sim.at(open, Ev::HeartbeatSend { from: 0, to: i });
            // It receives the cluster key 3 to 5.5 s in: from then on it may stand.
            let key = scen.range(3_000_000, 5_500_000);
            last_key = last_key.max(key);
            sim.at(key, Ev::Key(i));
            // Its loop ticks on a grid set when its process started (its first ticks before the
            // key do nothing, so they aren't run).
            let phase = if model.align_us == 0 {
                scen.below(TICK_US)
            } else {
                (base + scen.below(model.align_us)) % TICK_US
            };
            sim.at(key.div_ceil(TICK_US) * TICK_US + phase, Ev::Tick(i));
        }
        let kill = last_key + scen.range(100_000, 600_000);
        sim.at(kill, Ev::Kill(0));
        sim
    }

    fn at(&mut self, t: u64, ev: Ev) {
        let seq = self.slab.len() as u64;
        self.slab.push(Some(ev));
        self.queue.push(Reverse((t, seq)));
    }

    fn delay(&mut self) -> u64 {
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let exp = (-(1.0 - self.rng.unit()).ln() * self.net.mean_us as f64) as u64;
        let stall = if self.net.tail > 0.0 && self.rng.chance(self.net.tail) {
            self.rng.below(self.net.tail_us)
        } else {
            0
        };
        self.net.floor_us + exp + stall
    }

    fn fsync(&mut self) -> u64 {
        self.rng.range(500, 5_000)
    }

    fn send(&mut self, leave: u64, from: usize, to: usize, msg: Msg) {
        if self.cut[from][to] {
            return;
        }
        if self.net.loss > 0.0 && self.rng.chance(self.net.loss) {
            return;
        }
        let at = leave + self.delay();
        self.at(at, Ev::Deliver { from, to, msg });
    }

    /// One `failover::step` on node `i`, woken by its tick or by a reply.
    fn step(&mut self, i: usize, reply: Option<(usize, Reply)>) {
        let now = self.t / 1000;
        let n = self.nodes.len();
        // REQ: CLU-005 (ADR-154) — the GitOps hold-back (`Cluster::defers_to_git_node`).
        if self.topo == Topology::GitOps && !self.nodes[i].git {
            let wants = (0..n).any(|j| {
                j != i
                    && self.nodes[j].git
                    && self.nodes[i].last_seen_ms[j].is_some_and(|s| now.saturating_sub(s) <= UP_MS)
            });
            let node = &mut self.nodes[i];
            let lease_held = node.el.ballot.lease_held_by_other(&node.el.id, now);
            let primary_up = node.el.leading().is_some() || lease_held;
            let defer = bounded_deference(wants, primary_up, &mut node.defer_since_ms, now);
            node.el.standing = !defer;
        }
        let killed = self.killed_us.is_some();
        let node = &mut self.nodes[i];
        let free = node.el.eligible
            && node.el.standing
            && node.el.phase == Phase::Follower
            && !node.el.ballot.lease_held_by_other(&node.el.id, now);
        if killed && free && node.free_us.is_none() {
            node.free_us = Some(self.t);
        }
        let mut outs = Vec::new();
        if let Some((from, r)) = reply {
            outs.extend(node.el.on_reply(&self.ids[from], &r, now));
        }
        let jitter = node.jitter.next() % (LEASE_MS / 2);
        outs.extend(node.el.tick(now, jitter));
        self.handle(i, outs);
    }

    /// Carries out what a step returned: the ballot is durable before anything leaves.
    fn handle(&mut self, i: usize, outs: Vec<Out>) {
        let leave = self.t
            + if outs.contains(&Out::Persist) {
                self.fsync()
            } else {
                0
            };
        for o in outs {
            match o {
                Out::Send { to, ask } => {
                    if ask.pre && self.killed_us.is_some() {
                        self.nodes[i].pre_votes_us.push(self.t);
                    }
                    let j = self.ids.iter().position(|x| *x == to).unwrap_or(i);
                    if j != i {
                        self.send(leave, i, j, Msg::Ask(ask));
                    }
                }
                Out::Elected { epoch } => {
                    let me = self.ids[i].clone();
                    if let Some(prev) = self.winners.insert(epoch, me.clone()) {
                        assert_eq!(prev, me, "two primaries elected in epoch {epoch}");
                    }
                }
                Out::StepDown { .. } | Out::Persist => {}
            }
        }
    }

    fn process(&mut self, ev: Ev) {
        let now = self.t / 1000;
        match ev {
            Ev::Tick(i) => {
                if self.nodes[i].up {
                    self.step(i, None);
                    let next = self.t + TICK_US;
                    self.at(next, Ev::Tick(i));
                }
            }
            Ev::Deliver { from, to, msg } => {
                if !self.nodes[to].up {
                    return;
                }
                match msg {
                    Msg::Ask(ask) => {
                        // `failover::answer`: decided under the election lock, the ballot
                        // stored before the reply leaves.
                        let (reply, outs) = self.nodes[to].el.on_ask(&ask, now);
                        let leave = self.t
                            + if outs.contains(&Out::Persist) {
                                self.fsync()
                            } else {
                                0
                            };
                        self.send(leave, to, from, Msg::Reply(reply));
                    }
                    Msg::Reply(r) => self.step(to, Some((from, r))),
                }
            }
            Ev::HeartbeatSend { from, to } => {
                if self.nodes[from].up {
                    let at = self.t + self.delay();
                    self.at(at, Ev::Heartbeat { from, to });
                    let next = self.t + HEARTBEAT_US;
                    self.at(next, Ev::HeartbeatSend { from, to });
                }
            }
            Ev::Heartbeat { from, to } => {
                if self.nodes[to].up {
                    self.nodes[to].last_seen_ms[from] = Some(now);
                }
            }
            Ev::Key(i) => {
                // `failover::step` sees `can_lead` change and builds a new `Elector` from the
                // stored ballot.
                let node = &mut self.nodes[i];
                let (voters, ballot) = (node.el.voters.clone(), node.el.ballot.clone());
                let standing = node.el.standing;
                node.el = Elector::new(&self.ids[i], voters, node.can_lead, ballot);
                node.el.standing = standing;
            }
            Ev::Kill(first) => {
                // The scripts kill the primary once it holds a lease: the first node, or (when
                // lost or stalled messages made it lose the role) whichever node holds it now;
                // with none holding one, a second later.
                let primary = std::iter::once(first)
                    .chain(0..self.nodes.len())
                    .find(|&j| self.nodes[j].up && self.nodes[j].el.writable(now));
                let Some(i) = primary else {
                    let later = self.t + 1_000_000;
                    self.at(later, Ev::Kill(first));
                    return;
                };
                self.nodes[i].up = false;
                self.killed_us = Some(self.t);
                self.dead_epoch = self.nodes[i].el.leading().unwrap_or(0);
            }
        }
    }

    /// Never two writers at once (every clock runs at one rate here); notes the first writable
    /// primary after the kill (what the scripts wait for: `telltale_cluster_lease_held`).
    fn check_writers(&mut self) {
        let now = self.t / 1000;
        let mut writers =
            (0..self.nodes.len()).filter(|&i| self.nodes[i].up && self.nodes[i].el.writable(now));
        let first = writers
            .next()
            .and_then(|i| self.nodes[i].el.leading().map(|e| (e, i)));
        assert!(writers.next().is_none(), "two writers at {now} ms");
        if let Some((epoch, i)) = first
            && self.killed_us.is_some()
            && self.elected.is_none()
        {
            self.elected = Some((epoch, self.t, i));
        }
    }

    /// Runs until a primary holds a lease after the kill and then `tail_us` more.
    fn run(mut self, tail_us: u64) -> Option<Outcome> {
        while let Some(Reverse((t, seq))) = self.queue.pop() {
            if let Some((_, e, _)) = self.elected
                && t > e + tail_us
            {
                break;
            }
            if t > self.killed_us.unwrap_or(0) + GIVE_UP_US {
                return None;
            }
            self.t = t;
            let slot = usize::try_from(seq).unwrap_or(usize::MAX);
            let Some(ev) = self.slab.get_mut(slot).and_then(Option::take) else {
                continue;
            };
            self.process(ev);
            self.check_writers();
        }
        let (epoch, at, winner) = self.elected?;
        let kill = self.killed_us?;
        let mut tries: Vec<(u64, bool)> = self
            .nodes
            .iter()
            .filter_map(|n| {
                let first = *n.pre_votes_us.first()?;
                Some((first - kill, n.free_us == Some(first)))
            })
            .collect();
        tries.sort_unstable();
        Some(Outcome {
            rounds: epoch.saturating_sub(self.dead_epoch),
            took_ms: (at - kill) / 1000,
            first_tries_us: tries.iter().take(2).map(|t| t.0).collect(),
            first_try_at_once: tries.iter().map(|t| t.1).collect(),
            winner,
        })
    }
}

/// A scenario's results.
#[derive(Debug, Default)]
struct Stats {
    runs: u64,
    rounds: BTreeMap<u64, u64>,
    took: Vec<u64>,
    /// The runs that took one round: how long those took (the first round's latency).
    took_one: Vec<u64>,
    /// Two candidates' first pre-votes this far apart (µs, bucket) → (runs, of them split).
    gap: BTreeMap<u64, (u64, u64)>,
    tries: u64,
    tries_at_once: u64,
    worst: (u64, u64),
}

const GAP_BUCKETS: [u64; 8] = [
    1_000,
    2_000,
    5_000,
    10_000,
    30_000,
    100_000,
    250_000,
    u64::MAX,
];

impl Stats {
    fn add(&mut self, seed: u64, o: &Outcome) {
        self.runs += 1;
        *self.rounds.entry(o.rounds.min(3)).or_default() += 1;
        self.took.push(o.took_ms);
        if o.rounds == 1 {
            self.took_one.push(o.took_ms);
        }
        if o.took_ms > self.worst.0 {
            self.worst = (o.took_ms, seed);
        }
        if let [a, b] = o.first_tries_us[..] {
            let gap = b - a;
            let bucket = GAP_BUCKETS
                .iter()
                .copied()
                .find(|&x| gap < x)
                .unwrap_or(u64::MAX);
            let e = self.gap.entry(bucket).or_default();
            e.0 += 1;
            e.1 += u64::from(o.rounds > 1);
        }
        self.tries += o.first_try_at_once.len() as u64;
        self.tries_at_once += o.first_try_at_once.iter().filter(|x| **x).count() as u64;
    }

    /// The runs that took `rounds` rounds (3: three or more).
    fn count(&self, rounds: u64) -> u64 {
        self.rounds.get(&rounds).copied().unwrap_or(0)
    }

    /// Their share.
    #[allow(clippy::cast_precision_loss)]
    fn share(&self, rounds: u64) -> f64 {
        self.count(rounds) as f64 / self.runs.max(1) as f64
    }

    fn mean_ms(&self) -> u64 {
        self.took.iter().sum::<u64>() / self.runs.max(1)
    }

    fn pct_ms(&mut self, p: u64) -> u64 {
        self.took.sort_unstable();
        let last = self.took.len().saturating_sub(1);
        let i = usize::try_from(self.took.len() as u64 * p / 100).map_or(last, |i| i.min(last));
        self.took.get(i).copied().unwrap_or(0)
    }

    fn report(&mut self, name: &str) {
        let (p50, p90, p99) = (self.pct_ms(50), self.pct_ms(90), self.pct_ms(99));
        eprintln!(
            "{name}: {} runs; rounds 1 / 2 / 3+: {} / {} / {} ({:.4} / {:.4} / {:.5}); seconds to a primary: mean {:.2}, p50 {:.2}, p90 {:.2}, p99 {:.2}, worst {:.2} (seed {})",
            self.runs,
            self.count(1),
            self.count(2),
            self.count(3),
            self.share(1),
            self.share(2),
            self.share(3),
            ms(self.mean_ms()),
            ms(p50),
            ms(p90),
            ms(p99),
            ms(self.worst.0),
            self.worst.1,
        );
        let gaps: Vec<String> = self
            .gap
            .iter()
            .map(|(b, (n, split))| {
                let label = if *b == u64::MAX {
                    "more".to_owned()
                } else {
                    format!("<{} ms", ms(*b))
                };
                format!("{label}: {split} of {n}")
            })
            .collect();
        eprintln!(
            "  the two earliest candidates' first pre-votes apart by (runs that needed another round of them): {}",
            gaps.join(", ")
        );
        eprintln!(
            "  first pre-votes sent on the step that found the node free to stand: {} of {}",
            self.tries_at_once, self.tries
        );
        self.took_one.sort_unstable();
        let one = self.took_one.len() as u64;
        let p99 = self
            .took_one
            .get(usize::try_from(one * 99 / 100).unwrap_or(0))
            .copied()
            .unwrap_or(0);
        eprintln!(
            "  the {one} runs that took one round: mean {:.3} s, p99 {:.3} s",
            ms(self.took_one.iter().sum::<u64>() / one.max(1)),
            ms(p99)
        );
    }
}

#[allow(clippy::cast_precision_loss)]
fn ms(x: u64) -> f64 {
    x as f64 / 1000.0
}

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn seeds() -> std::ops::Range<u64> {
    let n = env(
        "TELLTALE_ROUNDS_SEEDS",
        if cfg!(debug_assertions) {
            1_000
        } else {
            20_000
        },
    );
    let first = env("TELLTALE_ROUNDS_SEED", 1);
    first..first + n
}

fn scenario(topo: Topology, model: Model) -> Stats {
    let mut stats = Stats::default();
    for seed in seeds() {
        let o = Sim::new(seed, topo, model).run(2_000_000);
        assert!(
            o.is_some(),
            "{topo:?} seed {seed}: no primary within {} s of the kill",
            GIVE_UP_US / 1_000_000
        );
        if let Some(o) = o {
            stats.add(seed, &o);
        }
    }
    stats
}

/// Asserts what ADR-178 promises for a failover with more than one candidate.
fn assert_one_round(name: &str, s: &mut Stats) {
    let (two, mean, p99) = (s.share(2), s.mean_ms(), s.pct_ms(99));
    assert!(
        two < 0.01,
        "{name}: {:.1} % of the failovers needed a second round",
        two * 100.0
    );
    assert_eq!(
        s.count(3),
        0,
        "{name}: failovers needed three rounds or more"
    );
    // One round is at most a lease after the kill, and the tail of a second is gone.
    assert!(
        mean < 16_000 && p99 < 17_000,
        "{name}: mean {mean} ms, p99 {p99} ms"
    );
}

// REQ: CLU-005 (ADR-178) — two nodes that can lead after the primary dies, as in
// `gitops-failover-e2e.sh`: the failover takes one round, with the scripts' timing and with nodes
// started at different times. Before ADR-178 both candidates sent their first pre-vote on the
// first tick after the lease (or the hold-back) ended, with no wait of their own, so with the
// scripts' near-lockstep ticks their pre-votes often crossed: each granted the other's (a pre-vote
// binds nothing), each then voted for itself, the vote split, and each one's own vote, a 15 s
// lease, made the next round wait for it (18 % of the runs took two rounds, and 0.15 % three).
#[test]
fn clu_005_a_failover_with_two_candidates_takes_one_round() {
    let mut all = Vec::new();
    for (topo, model, name) in [
        (
            Topology::GitOps,
            Model::scripts(),
            "GitOps (the scripts' timing)",
        ),
        (
            Topology::Three,
            Model::scripts(),
            "Three (the scripts' timing)",
        ),
        (
            Topology::GitOps,
            Model::spread(),
            "GitOps (independent phases)",
        ),
    ] {
        let mut s = scenario(topo, model);
        s.report(name);
        all.push((name, s));
    }
    for (name, mut s) in all {
        assert_one_round(name, &mut s);
    }
}

// REQ: CLU-005 (ADR-178) — five eligible nodes, so four candidates once the primary dies. Giving
// way doesn't make every split impossible here: a follower can grant the pre-votes of two of
// them before either asks it for its vote, and the two that sort first can then each win a part
// of the votes. It makes them several times rarer: before ADR-178, 24 % of the failovers needed a
// second round with the scripts' timing (2.1 % a third) and 3.8 % with independent phases (0.10 %);
// after it, 4.0 % (0.07 %) and 0.74 % (0.003 %), from 200,000 seeds each.
#[test]
fn clu_005_four_candidates_split_the_vote_far_less_often() {
    for (model, name, two, three) in [
        (Model::scripts(), "Five (the scripts' timing)", 0.06, 0.005),
        (Model::spread(), "Five (independent phases)", 0.02, 0.002),
    ] {
        let mut s = scenario(Topology::Five, model);
        s.report(name);
        assert!(
            s.share(2) < two && s.share(3) < three,
            "{name}: {:.2} % of the failovers took two rounds and {:.3} % more",
            s.share(2) * 100.0,
            s.share(3) * 100.0
        );
        assert!(s.pct_ms(90) < 16_000, "{name}: p90 {} ms", s.pct_ms(90));
    }
}

// REQ: CLU-005 — one candidate (two eligible nodes and a witness, as `failover-e2e.sh`): one round,
// always, before ADR-178 and after it.
#[test]
fn clu_005_a_failover_with_one_candidate_takes_one_round() {
    let mut s = scenario(Topology::Witness, Model::scripts());
    s.report("Witness (the scripts' timing)");
    assert_eq!(
        s.count(1),
        s.runs,
        "a single candidate needed another round"
    );
}

// REQ: CLU-005 (ADR-056, ADR-178) — whatever the timing, a failover never elects two primaries in
// one epoch and never has two writers at once, and it does elect one: mean delays from 0.2 to
// 60 ms, up to a fifth of the messages stalled by up to 3 s (which reorders them), up to 5 % lost,
// either tick model, every topology, and each run goes on for 20 s after the election.
#[test]
fn clu_005_failover_timing_never_elects_two_primaries() {
    let mut rng = Rng::new(env("TELLTALE_ROUNDS_SEED", 1), 7);
    for topo in [
        Topology::GitOps,
        Topology::Three,
        Topology::Witness,
        Topology::Five,
        Topology::TwoWitnesses,
        Topology::Cut4,
        Topology::Star5,
    ] {
        let mut s = Stats::default();
        for seed in seeds() {
            #[allow(clippy::cast_precision_loss)]
            let model = Model {
                net: Net {
                    floor_us: 50,
                    mean_us: rng.range(200, 60_000),
                    tail: rng.below(21) as f64 / 100.0,
                    tail_us: 3_000_000,
                    loss: rng.below(6) as f64 / 100.0,
                },
                align_us: if rng.chance(0.5) { SCRIPTS_ALIGN_US } else { 0 },
            };
            let o = Sim::new(seed, topo, model).run(20_000_000);
            assert!(o.is_some(), "{topo:?} seed {seed} ({model:?}): no primary");
            if let Some(o) = o {
                s.add(seed, &o);
            }
        }
        s.report(&format!("{topo:?} (adversarial delays and loss)"));
    }
}

/// How long after the kill the one node that can win may take when lower nodes that can't win
/// keep asking it for pre-votes (`clu_005_a_lower_node_that_cannot_win_only_delays_the_election`).
/// The lease ends at most `LEASE_MS` after the kill. Every pre-vote H grants a lower node then
/// keeps H from standing for `ROUND_MS`, as a follower or as a pre-candidate that stands down, and
/// H stands again on the next tick of its loop after that: each spoiled attempt costs H at most
/// `ROUND_MS` plus one tick, 2.25 s. The bound is the lease plus twenty of those: 15 + 45 = 60 s.
/// It is not a worst case in theory: the lower nodes' asks follow their own jitter, redrawn on
/// every step, so each further spoil is a fresh draw and the tail falls off geometrically. With
/// the scripts' near-lockstep ticks all of them are freed together, so H's first attempts are
/// often spoiled; the measured worst is well inside the bound (ADR-178).
const HELD_BACK_BOUND_MS: u64 = LEASE_MS + 20 * (ROUND_MS + TICK_US / 1_000);

// REQ: CLU-005 (ADR-178) — a lower node that can't win only delays the election; it never stops
// it. `Cut4`: four voters {P, L, X, H}, L and X sort before H, the L-X link is cut, so once P dies
// only H can reach a majority (3 of 4), while L and X keep sending H pre-votes that it grants and
// gives way to. `Star5`: five voters, H in the middle of three lower leaves that reach only H.
// Every seed elects H, within `HELD_BACK_BOUND_MS` of the kill.
#[test]
fn clu_005_a_lower_node_that_cannot_win_only_delays_the_election() {
    for (topo, model, name) in [
        (
            Topology::Cut4,
            Model::scripts(),
            "Cut4 (the scripts' timing)",
        ),
        (Topology::Cut4, Model::spread(), "Cut4 (independent phases)"),
        (
            Topology::Star5,
            Model::scripts(),
            "Star5 (the scripts' timing)",
        ),
        (
            Topology::Star5,
            Model::spread(),
            "Star5 (independent phases)",
        ),
    ] {
        let mut s = Stats::default();
        for seed in seeds() {
            let o = Sim::new(seed, topo, model).run(2_000_000);
            assert!(o.is_some(), "{name} seed {seed}: no primary");
            if let Some(o) = o {
                assert_eq!(
                    Some(o.winner),
                    topo.only_winner(),
                    "{name} seed {seed}: a node that can't reach a majority won"
                );
                s.add(seed, &o);
            }
        }
        s.report(name);
        assert!(
            s.worst.0 < HELD_BACK_BOUND_MS,
            "{name}: seed {} took {} ms",
            s.worst.1,
            s.worst.0
        );
    }
}

// REQ: CLU-005 (ADR-178) — three eligible nodes and two witnesses (five voters, majority three).
// Once the primary dies, each of the two candidates can win with the two witnesses' votes alone,
// so giving way can't rule a split out: the higher candidate may finish its pre-vote round (and
// then refuse the lower one) before the lower one's request reaches it, while the lower one
// collects the witnesses' pre-votes as well. It makes a split rarer, not impossible: before
// ADR-178 12.4 % of the failovers took more than one round with the scripts' timing and 1.9 % with
// independent phases; after it 2.3 % and 0.38 % (200,000 seeds each). The bounds sit between.
#[test]
fn clu_005_two_candidates_with_two_witnesses_split_less_often() {
    for (model, name, two) in [
        (Model::scripts(), "TwoWitnesses (the scripts' timing)", 0.05),
        (Model::spread(), "TwoWitnesses (independent phases)", 0.012),
    ] {
        let mut s = scenario(Topology::TwoWitnesses, model);
        s.report(name);
        assert!(
            s.share(2) + s.share(3) < two,
            "{name}: {:.2} % of the failovers took more than one round",
            (s.share(2) + s.share(3)) * 100.0
        );
    }
}
