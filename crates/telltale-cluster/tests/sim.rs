//! `telltale-sim`: the election protocol under randomized partitions (REQ: CLU-005, T5.4b AC).
//!
//! Each schedule builds a cluster (2 eligible nodes + a witness, 3 eligible, or 4 eligible +
//! a witness), then runs it with links that randomly break and heal, lost and delayed
//! messages, crashing and restarting nodes (each restart on a new, unrelated clock, as a new
//! process's election clock is), and clocks that drift up to ±1 %. Primaries write
//! whole-version histories (as the change log does), and replicas adopt newer epochs'
//! histories. Checked:
//! - **one primary per epoch;**
//! - **never two writers at once** (by real time, whatever each node's clock says);
//! - **orphaned writes are always surfaced:** after everything heals, every write is in the
//!   final history or was reported as orphaned when its node adopted a newer history;
//! - **liveness:** once healed, a writable primary exists within 60 s.
//!
//! `TELLTALE_SIM_SCHEDULES` sets the number of schedules (default: 10,000 in release builds,
//! which CI runs; 200 in debug builds) and `TELLTALE_SIM_SEED` the first seed. A failure
//! names its seed, so `TELLTALE_SIM_SEED=<seed> TELLTALE_SIM_SCHEDULES=1` replays it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use telltale_cluster::election::{Ask, Ballot, Elector, Out, Reply};

/// xorshift64*: deterministic per seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, p: f64) -> bool {
        #[allow(clippy::cast_precision_loss)]
        let x = (self.next() >> 11) as f64 / (1u64 << 53) as f64;
        x < p
    }
}

type Write = (u64, u64);

#[derive(Debug)]
enum Msg {
    Ask(Ask),
    Reply(Reply),
    /// A primary's whole version: its epoch and history.
    Replicate(u64, Vec<Write>),
}

struct Node {
    el: Elector,
    /// Clock: `offset + real * rate`.
    offset: u64,
    /// Which process's clock (a restart is a new one, at a new offset).
    clock: u64,
    rate: f64,
    up: bool,
    /// Persisted: the applied history and the epoch it came from.
    history: Vec<Write>,
    history_epoch: u64,
    next_write_ms: u64,
}

impl Node {
    fn now(&self, real: u64) -> u64 {
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let local = (real as f64 * self.rate) as u64;
        self.offset + local
    }
}

struct Sim {
    rng: Rng,
    nodes: Vec<Node>,
    ids: Vec<String>,
    /// Links that work now (`link[a][b]`).
    link: Vec<Vec<bool>>,
    drop: f64,
    /// (deliver at real ms, from, to, message).
    inflight: Vec<(u64, usize, usize, Msg)>,
    winners: HashMap<u64, String>,
    writes: Vec<Write>,
    orphans: HashSet<Write>,
}

const STEP_MS: u64 = 50;

impl Sim {
    fn new(seed: u64) -> Self {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let (eligible, witness) = match rng.below(3) {
            0 => (2, 1),
            1 => (3, 0),
            _ => (4, 1),
        };
        let n = eligible + witness;
        let ids: Vec<String> = (0..n).map(|i| format!("n{i}")).collect();
        let nodes = (0..n)
            .map(|i| {
                #[allow(clippy::cast_precision_loss)]
                let rate = 0.99 + (rng.below(2001) as f64) / 100_000.0;
                Node {
                    el: Elector::new(&ids[i], ids.clone(), i < eligible, Ballot::default()),
                    offset: 1_700_000_000_000 + rng.below(10_000_000),
                    clock: 0,
                    rate,
                    up: true,
                    history: Vec::new(),
                    history_epoch: 0,
                    next_write_ms: 0,
                }
            })
            .collect();
        #[allow(clippy::cast_precision_loss)]
        let drop = rng.below(15) as f64 / 100.0;
        Self {
            rng,
            nodes,
            ids,
            link: vec![vec![true; n]; n],
            drop,
            inflight: Vec::new(),
            winners: HashMap::new(),
            writes: Vec::new(),
            orphans: HashSet::new(),
        }
    }

    fn send(&mut self, real: u64, from: usize, to: usize, m: Msg) {
        if !self.link[from][to] || self.rng.chance(self.drop) {
            return;
        }
        // Heavy-tailed delays: mostly fast, sometimes seconds (widens every race window).
        let delay = match self.rng.below(100) {
            0..70 => self.rng.below(50),
            70..95 => self.rng.below(500),
            _ => self.rng.below(3_000),
        };
        let at = real + 1 + delay;
        self.inflight.push((at, from, to, m));
    }

    fn idx(&self, id: &str) -> usize {
        self.ids.iter().position(|x| x == id).unwrap_or(0)
    }

    fn handle(&mut self, real: u64, i: usize, outs: Vec<Out>) {
        for o in outs {
            match o {
                Out::Send { to, ask } => {
                    let j = self.idx(&to);
                    self.send(real, i, j, Msg::Ask(ask));
                }
                Out::Elected { epoch } => {
                    let me = self.ids[i].clone();
                    if let Some(prev) = self.winners.insert(epoch, me.clone()) {
                        assert_eq!(prev, me, "two primaries elected in epoch {epoch}");
                    }
                    self.nodes[i].history_epoch = epoch;
                }
                Out::StepDown { .. } | Out::Persist => {}
            }
        }
    }

    /// Adopts a newer primary's history; whatever it drops is reported as orphaned.
    fn adopt(&mut self, i: usize, epoch: u64, history: Vec<Write>) {
        let n = &mut self.nodes[i];
        if epoch < n.history_epoch || n.el.leading().is_some_and(|e| e >= epoch) {
            return;
        }
        let keep: BTreeSet<Write> = history.iter().copied().collect();
        for w in &n.history {
            if !keep.contains(w) {
                self.orphans.insert(*w);
            }
        }
        n.history = history;
        n.history_epoch = epoch;
        n.el.applied = n.history.last().copied().unwrap_or((epoch, 0));
    }

    fn deliver(&mut self, real: u64) {
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.inflight)
            .into_iter()
            .partition(|(at, ..)| *at <= real);
        self.inflight = later;
        for (_, from, to, m) in due {
            // A message needs the link and the receiver at delivery time too.
            if !self.nodes[to].up || !self.link[from][to] {
                continue;
            }
            let now = self.nodes[to].now(real);
            match m {
                Msg::Ask(ask) => {
                    let (reply, outs) = self.nodes[to].el.on_ask(&ask, now);
                    self.handle(real, to, outs);
                    self.send(real, to, from, Msg::Reply(reply));
                }
                Msg::Reply(r) => {
                    let who = self.ids[from].clone();
                    let outs = self.nodes[to].el.on_reply(&who, &r, now);
                    self.handle(real, to, outs);
                }
                Msg::Replicate(epoch, h) => {
                    let outs = self.nodes[to].el.observe(epoch);
                    self.handle(real, to, outs);
                    self.adopt(to, epoch, h);
                }
            }
        }
    }

    fn step(&mut self, real: u64, chaos: bool) {
        let n = self.nodes.len();
        if chaos {
            // Links change now and then: random partitions, sometimes asymmetric.
            if self.rng.chance(0.02) {
                for a in 0..n {
                    for b in 0..n {
                        if a != b {
                            self.link[a][b] = !self.rng.chance(0.3);
                        }
                    }
                }
                if self.rng.chance(0.5) {
                    for a in 0..n {
                        for b in 0..a {
                            self.link[a][b] = self.link[b][a];
                        }
                    }
                }
            }
            // Crashes and restarts (ballots and histories survive; roles don't). A restarted
            // process times leases on a new clock, unrelated to the old one (review 05-05):
            // anywhere from far behind to far ahead. Its ballot is adopted as the server does.
            for i in 0..n {
                let flip = if self.nodes[i].up { 0.002 } else { 0.05 };
                if self.rng.chance(flip) {
                    let offset = self.rng.below(4_000_000_000_000);
                    let node = &mut self.nodes[i];
                    node.up = !node.up;
                    if node.up {
                        node.clock += 1;
                        node.offset = offset;
                        node.next_write_ms = 0;
                        let mut ballot = node.el.ballot.clone();
                        ballot.adopt(node.clock, node.now(real));
                        let applied = node.el.applied;
                        let eligible = node.el.eligible;
                        node.el = Elector::new(&self.ids[i], self.ids.clone(), eligible, ballot);
                        node.el.applied = applied;
                        node.el.max_epoch = node.el.max_epoch.max(node.history_epoch);
                    }
                }
            }
        }
        self.deliver(real);
        for i in 0..n {
            if !self.nodes[i].up {
                continue;
            }
            let now = self.nodes[i].now(real);
            // Often near zero: candidates race the lease boundary.
            let jitter = if self.rng.chance(0.5) {
                self.rng.below(200)
            } else {
                self.rng.below(7_500)
            };
            let outs = self.nodes[i].el.tick(now, jitter);
            self.handle(real, i, outs);
            // A writable primary writes and replicates.
            if self.nodes[i].el.writable(now) && now >= self.nodes[i].next_write_ms {
                let epoch = self.nodes[i].el.leading().unwrap_or(0);
                let node = &mut self.nodes[i];
                let seq = match node.history.last() {
                    Some((e, s)) if *e == epoch => s + 1,
                    _ => 1,
                };
                node.history.push((epoch, seq));
                node.el.applied = (epoch, seq);
                node.next_write_ms = now + 300 + self.rng.below(700);
                self.writes.push((epoch, seq));
                let h = self.nodes[i].history.clone();
                for j in 0..n {
                    if j != i {
                        self.send(real, i, j, Msg::Replicate(epoch, h.clone()));
                    }
                }
            }
        }
        // Never two writers at once, by real time.
        let writers: Vec<&String> = (0..n)
            .filter(|&i| self.nodes[i].up && self.nodes[i].el.writable(self.nodes[i].now(real)))
            .map(|i| &self.ids[i])
            .collect();
        assert!(writers.len() <= 1, "two writers at {real} ms: {writers:?}");
    }

    /// Heals everything and returns how long until a writable primary existed.
    fn heal(&mut self, start: u64) -> Option<u64> {
        for row in &mut self.link {
            row.fill(true);
        }
        self.drop = 0.0;
        for i in 0..self.nodes.len() {
            if !self.nodes[i].up {
                self.nodes[i].up = true;
                let ballot = self.nodes[i].el.ballot.clone();
                let (applied, eligible) = (self.nodes[i].el.applied, self.nodes[i].el.eligible);
                let mut el = Elector::new(&self.ids[i], self.ids.clone(), eligible, ballot);
                el.applied = applied;
                el.max_epoch = el.max_epoch.max(self.nodes[i].history_epoch);
                self.nodes[i].el = el;
            }
        }
        let mut found = None;
        let mut real = start;
        // Run until a primary exists, then long enough for every node to converge.
        while real < start + 120_000 && found.is_none_or(|f| real < start + f + 20_000) {
            self.step(real, false);
            if found.is_none() && self.nodes.iter().any(|n| n.el.writable(n.now(real))) {
                found = Some(real - start);
            }
            real += STEP_MS;
        }
        found
    }
}

/// What a schedule did (for the summary).
struct Outcome {
    took: u64,
    epochs: usize,
    writes: usize,
    orphans: usize,
}

fn run(seed: u64) -> Outcome {
    let mut sim = Sim::new(seed);
    let length = 30_000 + sim.rng.below(150_000);
    let mut real = 0;
    while real < length {
        sim.step(real, true);
        real += STEP_MS;
    }
    let took = sim.heal(real);
    assert!(
        took.is_some(),
        "seed {seed}: no primary within 120 s of healing"
    );
    let took = took.unwrap_or_default();
    assert!(
        took <= 60_000,
        "seed {seed}: a primary took {took} ms after healing"
    );
    // Everyone converged on the final primary's history; every write is in it or orphaned.
    let leader = sim
        .nodes
        .iter()
        .max_by_key(|n| n.el.leading().unwrap_or(0))
        .map(|n| n.history.clone())
        .unwrap_or_default();
    let kept: BTreeSet<Write> = leader.iter().copied().collect();
    for w in &sim.writes {
        assert!(
            kept.contains(w) || sim.orphans.contains(w),
            "seed {seed}: write {w:?} was lost without being reported"
        );
    }
    Outcome {
        took,
        epochs: sim.winners.len(),
        writes: sim.writes.len(),
        orphans: sim.orphans.len(),
    }
}

// REQ: CLU-005 — T5.4b AC: 10k randomized partition schedules; never two writers in one
// epoch (or at once); orphaned writes always surfaced.
#[test]
fn clu_005_sim_randomized_partition_schedules() {
    let n: u64 = std::env::var("TELLTALE_SIM_SCHEDULES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(if cfg!(debug_assertions) { 200 } else { 10_000 });
    let first: u64 = std::env::var("TELLTALE_SIM_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let mut worst = 0;
    let mut hist: BTreeMap<u64, u64> = BTreeMap::new();
    let (mut epochs, mut writes, mut orphans, mut failovers) = (0, 0, 0, 0);
    for seed in first..first + n {
        let o = run(seed);
        worst = worst.max(o.took);
        *hist.entry(o.took / 10_000 * 10).or_default() += 1;
        epochs += o.epochs;
        writes += o.writes;
        orphans += o.orphans;
        failovers += u64::from(o.epochs > 1);
    }
    eprintln!(
        "{n} schedules: {epochs} primaries elected ({failovers} schedules with a failover), {writes} writes, {orphans} orphaned and reported; seconds to a primary after healing (bucket → count): {hist:?}, worst {worst} ms"
    );
    assert!(
        failovers * 2 > n,
        "the schedules should mostly include failovers"
    );
}
