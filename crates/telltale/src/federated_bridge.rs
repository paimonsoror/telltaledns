//! REQ: CLU-002, CLU-004, OPS-012 (ADR-174, GitHub issue #7) — how synchronous code waits for the
//! cluster channel.
//!
//! The `Backend` trait is synchronous, so a federated read starts its RPCs on the runtime and
//! waits for the answers on a thread of its own: a blocking-pool thread, where the API runs its
//! backend calls. Four rules:
//!
//! 1. The wait never needs the runtime to end it. It is a `recv_timeout` on a `std` channel,
//!    for the RPC's own timeout plus a short grace. A runtime that can't run the tasks (every
//!    worker parked, or this very call made on a worker) costs the read its deadline, never the
//!    node its life. Before, the wait was a scoped thread running `Handle::block_on` and a
//!    `join()` with no bound: with every worker parked in one, nothing could write an RPC, read
//!    its answer or fire its timer, and the node stopped answering for good.
//! 2. Few waits at once. Each holds a thread (of the blocking pool's 512) for up to its deadline,
//!    so a slow or dead primary can't pile them up. Past [`MAX_WAITS`] a read is not sent: each
//!    of its calls is told "wasn't asked".
//! 3. Few calls at once. A read is one task per call and holds one place under rule 2 for all
//!    of them, so the places bound reads, not tasks. Two limits bound the calls. The calls of all
//!    reads together are a budget of [`CALL_BUDGET`] (32,768: the most that 32 reads of 1,024
//!    calls, the first cap, could have had): a read takes a share for each of its calls, all of
//!    them or none. A call's share travels with its answer and comes back when the read is done
//!    with the answer (`Pending::wait` returns, or the read is dropped), or when the call's task
//!    is dropped; so a call that has answered still counts while its answer waits for the read,
//!    and tasks queued on a stuck runtime keep theirs. And one read may have at most
//!    [`MAX_READ_CALLS`] calls, which is what a range of time on a large cluster needs (a read
//!    for the nodes' time buckets is one call per node and window of time,
//!    `telltale_api::federation::timeseries_chunks`, which bounds the windows on its own,
//!    first). A read over either is not sent (every call: "wasn't asked"), and takes nothing.
//!    This counts calls and the answers they hold; rule 4 is what the answers weigh.
//! 4. Few bytes at once. An answer is as big as its peer makes it, up to the cluster channel's
//!    1 MiB frame, so each is weighed as it comes in, on the task that got it and before it is
//!    kept: its length is added to what its read holds and to what all reads hold together. If
//!    either would pass its cap ([`READ_BYTES`] a read, [`HELD_BYTES`] in all), the answer is
//!    dropped there and its call is "wasn't kept", which the caller treats as it treats a peer
//!    that didn't answer (`missingNodes`): an answer is never cut short, and the rest of the read
//!    is kept. The bytes are part of the call's share, so they go back when the share does. What
//!    the caller does with the answers once `wait` has returned them (parsing them, merging them,
//!    writing the response) is not covered (ADR-174 says why and what bounds it).
//!
//! A read that is refused, or that loses an answer to rule 4, is counted (the metric
//! `telltale_federated_refused_total`, [`Limiter::refusals`]) and said in the log, as a warning
//! at most once a minute ([`Limiter::refused`]).
//!
//! What this does not do: a read made on a worker thread of a multi-thread runtime costs its
//! deadline even when the runtime is healthy. Tokio puts a task a worker spawns in that worker's
//! own LIFO slot, which no other worker steals, and the worker is the one parked in
//! `recv_timeout`, so the task (the last, or only, call of the read) never runs. No caller does
//! that: every one is under `blocking()` or `spawn_blocking`. This is for the next handler.
//!
//! No `block_in_place`: it panics outside a worker (the release profile aborts on a panic) and
//! ties the runtime's own liveness to the blocking pool.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, mpsc};
use std::time::{Duration, Instant};

/// How long past a call's own timeout the caller keeps waiting for the runtime to run it.
pub(super) const GRACE: Duration = Duration::from_millis(250);

/// Federated waits in flight at once on this node (each is a read: all of its peers together).
/// A healthy cluster's reads end in milliseconds; this only bounds a slow or dead peer's cost, in
/// threads: each wait holds one of the blocking pool's.
const MAX_WAITS: usize = 32;

/// The most calls one read may have. A read is one call to each peer, or, for a range of time,
/// one to each peer for each window of it. The longest range any step documents is 87 windows
/// (`step=day` over all of history, one window more every 240 days, so 88 from March 2027; 7
/// days of minutes is 43, 400 days of hours 41, 15 minutes of seconds 4), and
/// `telltale_api::federation::TIMESERIES_MAX_WINDOWS` caps one read at 256 a peer. So 4,096 lets
/// floor(4,096 / windows) peers ask for a range whole: 47 for all of history by the day today (46
/// from March 2027), 95 for 7 days of minutes, 99 for 400 days of hours. A read over it is not
/// sent. It bounds what one request can ask; [`CALL_BUDGET`] bounds what all of them hold.
pub(super) const MAX_READ_CALLS: usize = 4096;

/// The calls that may be counted at once, all reads together: a call counts from its start
/// until its read is done with its answer, so it covers the tasks that are running and the
/// answers that wait for their read. It is a count; [`HELD_BYTES`] is their bytes. 32,768 is 32
/// reads ([`MAX_WAITS`]) of 1,024 calls, the most the first, flat cap (1,024 calls a read) could
/// ever have had, so raising [`MAX_READ_CALLS`] did not raise the number of calls or answers that
/// can be held: it lets one big read use what many small ones could. At most 8 reads of
/// [`MAX_READ_CALLS`] fit at once.
pub(super) const CALL_BUDGET: usize = 32 * 1024;

/// REQ: CLU-004 (ADR-174) — the bytes of the peers' answers one read may hold: 20 MiB. What a
/// read costs is mostly after `wait`: parsing and merging its answers took a node to 6.6 to 7.3
/// times their bytes above its own use (two real nodes, a peer padding its answers, a replica
/// with no data of its own: 33 MB of answers, under a first cap of 32 MiB, took it from 42 MB
/// resident to a 251 MiB high-water mark; 20.7 MB, under this cap, to 185 MiB). It bounds the
/// peers' answers only: this node's own part of a read (which `Federated::timeseries` adds after
/// the wait) and reads that merge at the same time are not counted, so two reads at this cap, or
/// one on a node with its own week of minutes and big buckets, can pass a Pi's 256 MiB
/// (`MemoryMax`). Measured (ADR-174) for a cluster of 5 nodes (4 peers asked) whose buckets look
/// like a home network's: the longest range the dashboard asks for, 48 hours of minutes, is 16.9
/// MiB of answers a read (1.2 times under this; a refresh makes two such reads, the summary and
/// the chart, 33.7 MiB of [`HELD_BYTES`]'s 40), the others 8.4 MiB or less, and a read of one call a
/// peer (a top list, a page of the query log, a support part) 4 MiB at most. The longest ranges
/// the API documents (7 days of minutes, 400 days of hours) are 59 to 62 MiB there, and come back
/// partial. An answer that would take the read past it is "wasn't kept".
pub(super) const READ_BYTES: usize = 20 << 20;

/// REQ: CLU-004 (ADR-174) — the bytes of answers all reads may hold at once: 40 MiB, two reads
/// at [`READ_BYTES`]. Before, held answers were bounded only by count: [`CALL_BUDGET`] of them,
/// each up to the cluster channel's 1 MiB frame, 32 GiB. What callers do once `wait` has
/// returned (the parse and the merge) is not in it (ADR-174).
pub(super) const HELD_BYTES: usize = 40 << 20;

// The budget lives in the low half of a `u64` beside the reads in the high half (see `Limiter`),
// and a read that is allowed at all must be able to fit.
const _: () = assert!(MAX_READ_CALLS <= CALL_BUDGET);
const _: () = assert!(CALL_BUDGET as u64 <= CALL_MASK);
// One read may hold up to its own cap without passing everyone's, and no one answer (at most a
// frame) is over a read's cap on its own.
const _: () = assert!(READ_BYTES <= HELD_BYTES);
const _: () = assert!(telltale_cluster::wire::MAX_FRAME < READ_BYTES);

/// The cap every federated read of this process shares.
pub(super) static WAITS: LazyLock<Limiter> = LazyLock::new(|| Limiter::new(MAX_WAITS));

/// How often, at most, refused reads are said in the log.
const SAY_EVERY_MS: u64 = 60_000;

/// Why a read was not sent, or (`Bytes`) not kept whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// [`MAX_WAITS`] reads were already waiting.
    Full,
    /// The calls other reads have running, or waiting to be read, left no room for all of this
    /// read's: the [`CALL_BUDGET`] was spent.
    Spent,
    /// The read asked for too much at once: over [`MAX_READ_CALLS`] calls, or a range of time of
    /// too many windows.
    TooBig,
    /// An answer came in that would have taken the bytes held past [`READ_BYTES`] for its read or
    /// [`HELD_BYTES`] for all of them, and was dropped (rule 4). The read was sent, and keeps its
    /// other answers.
    Bytes,
}

impl Refused {
    /// Every reason, in the order the metric lists them.
    pub(super) const ALL: [Self; 4] = [Self::Full, Self::Spent, Self::TooBig, Self::Bytes];

    /// What each call of the read is told: after "wasn't asked", or (`Bytes`) "wasn't kept".
    fn why(self) -> &'static str {
        match self {
            Self::Full => "too many cluster reads are already waiting",
            Self::Spent => "too many cluster calls are already running or waiting to be read",
            Self::TooBig => "the read has too many calls at once",
            Self::Bytes => "the answers held would pass the bytes cluster reads may hold",
        }
    }

    /// The metric's label: a closed set.
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Full => "waits",
            Self::Spent => "spent",
            Self::TooBig => "ceiling",
            Self::Bytes => "bytes",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Full => 0,
            Self::Spent => 1,
            Self::TooBig => 2,
            Self::Bytes => 3,
        }
    }
}

/// How many reads were refused for each reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Tally {
    full: u64,
    spent: u64,
    too_big: u64,
    bytes: u64,
}

/// What was refused since the last line said so, and when that was; and every refusal since the
/// process started (the metric), which nothing resets.
#[derive(Debug, Default)]
struct RefusalLog {
    /// The clock (milliseconds, any origin) of the last line, plus one: zero is "never".
    last: AtomicU64,
    /// Since the last line, by [`Refused::index`].
    unsaid: [AtomicU64; 4],
    /// Since the start, by [`Refused::index`].
    total: [AtomicU64; 4],
}

impl RefusalLog {
    /// Counts a refused read. Returns what to say when a line is due: the first time, then once
    /// a minute at most, with what was counted since the last line (which this resets). Of any
    /// number of threads that find a line due, one gets it, and a refusal is in exactly one line.
    fn note(&self, why: Refused, now_ms: u64) -> Option<Tally> {
        self.total[why.index()].fetch_add(1, Ordering::AcqRel);
        self.unsaid[why.index()].fetch_add(1, Ordering::AcqRel);
        let stamp = now_ms.saturating_add(1);
        let last = self.last.load(Ordering::Acquire);
        if last != 0 && stamp.saturating_sub(last) < SAY_EVERY_MS {
            return None;
        }
        self.last
            .compare_exchange(last, stamp, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        let take = |why: Refused| self.unsaid[why.index()].swap(0, Ordering::AcqRel);
        Some(Tally {
            full: take(Refused::Full),
            spent: take(Refused::Spent),
            too_big: take(Refused::TooBig),
            bytes: take(Refused::Bytes),
        })
    }

    /// Refusals since the start, for `why`.
    fn total(&self, why: Refused) -> u64 {
        self.total[why.index()].load(Ordering::Acquire)
    }

    /// What is counted and not yet said.
    #[cfg(test)]
    fn pending(&self) -> Tally {
        let n = |why: Refused| self.unsaid[why.index()].load(Ordering::Acquire);
        Tally {
            full: n(Refused::Full),
            spent: n(Refused::Spent),
            too_big: n(Refused::TooBig),
            bytes: n(Refused::Bytes),
        }
    }
}

/// One read is `ONE_READ` in the limiter's count, and one call is `1`: the reads waiting are
/// the count's high half and the calls in flight its low half (`CALL_MASK`).
const ONE_READ: u64 = 1 << 32;
const CALL_MASK: u64 = ONE_READ - 1;

/// What the federated reads of a process may hold at once: places among the reads waiting
/// ([`MAX_WAITS`]), shares of the budget of calls ([`CALL_BUDGET`]), and bytes of answers
/// ([`HELD_BYTES`], [`READ_BYTES`] a read).
///
/// The places and the shares are one number, so one compare-and-swap takes a read's place and all
/// of its calls' shares together, or takes nothing: a refused read never holds a share for a
/// moment, which two counts taken one after the other could not promise (a read refused for lack
/// of a place would, for an instant, have held shares that made a read that fits look too big).
/// The bytes are taken later, one answer at a time, as the answers come in ([`Scale`]).
#[derive(Debug)]
pub(super) struct Limiter {
    /// Reads waiting (high half) and calls counted (low half).
    state: Arc<AtomicU64>,
    max_reads: u64,
    budget: u64,
    /// The bytes held and the refusals, shared with the reads this lets go.
    ledger: Arc<Ledger>,
}

/// What a limiter shares with each read it lets go: the bytes all reads hold, the caps on them,
/// and the refusals (the log and the metric), so an answer can be weighed, and a read that loses
/// one counted, without the limiter.
#[derive(Debug)]
struct Ledger {
    /// The bytes of answers held, all reads together.
    bytes: AtomicU64,
    /// What `bytes` may be at most.
    held_cap: u64,
    /// What one read's answers may hold at most.
    read_cap: u64,
    log: RefusalLog,
    /// The refusal log's clock: monotonic, from when this was made.
    since: Instant,
    /// For the log line: the limiter's caps on reads and calls.
    max_reads: u64,
    budget: u64,
}

impl Ledger {
    /// REQ: CLU-004 (final review, F2) — counts a read that was not sent or (`Bytes`) not kept
    /// whole, and says so in the log as a warning: the first time, then at most once a minute,
    /// with how many were refused since the last line. A silent refusal showed as healthy peers
    /// in `missingNodes`.
    fn refused(&self, why: Refused) {
        let now = u64::try_from(self.since.elapsed().as_millis()).unwrap_or(u64::MAX);
        if let Some(n) = self.log.note(why, now) {
            tracing::warn!(
                "federated reads are being refused and were not sent: {} because {} reads were \
                 already waiting (a slow or silent node), {} because the {} calls that reads may \
                 have running or waiting to be read at once were spent, {} because they asked for \
                 too much at once (over {MAX_READ_CALLS} calls, or over {} windows of time a \
                 node); and {} were sent but lost answers, which would have passed the {} bytes \
                 of answers one read may hold or the {} all of them may; counted since the last \
                 line of this kind, at most one a minute. The nodes they were for show as not \
                 answering",
                n.full,
                self.max_reads,
                n.spent,
                self.budget,
                n.too_big,
                telltale_api::federation::TIMESERIES_MAX_WINDOWS,
                n.bytes,
                self.read_cap,
                self.held_cap,
            );
        }
    }
}

/// What one read's answers weigh, beside what all reads' do ([`Ledger::bytes`]).
#[derive(Debug)]
struct Scale {
    ledger: Arc<Ledger>,
    /// The bytes of this read's answers that are held.
    read: AtomicU64,
}

impl Scale {
    /// REQ: CLU-004 (ADR-174) — adds `n` bytes to what this read holds and to what all reads
    /// hold, or adds nothing and says no when either would pass its cap. The read's own total is
    /// taken first and given back if everyone's has no room, so for an instant it can make another
    /// answer of the same read look too big (that answer is dropped: the safe side), never one of
    /// another read.
    fn take(&self, n: u64) -> bool {
        let fits = |cap: u64| move |held: u64| held.checked_add(n).filter(|t| *t <= cap);
        if self
            .read
            .try_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                fits(self.ledger.read_cap),
            )
            .is_err()
        {
            return false;
        }
        let all = &self.ledger.bytes;
        if all
            .try_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                fits(self.ledger.held_cap),
            )
            .is_err()
        {
            self.read.fetch_sub(n, Ordering::AcqRel);
            return false;
        }
        true
    }

    /// Gives back `n` bytes that [`Scale::take`] took.
    fn give(&self, n: u64) {
        self.read.fetch_sub(n, Ordering::AcqRel);
        self.ledger.bytes.fetch_sub(n, Ordering::AcqRel);
    }
}

/// What an answer weighs: the bytes it holds (a peer's error is a peer's text, and is weighed
/// too).
fn weight(answer: &Answer) -> u64 {
    let n = match answer {
        Ok(body) => body.len(),
        Err(text) => text.len(),
    };
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// One read's place among the reads waiting. It is given back when the read's last task ends
/// (not when the caller stops waiting: a task still queued on a stuck runtime still counts).
#[derive(Debug)]
struct Place(Arc<AtomicU64>);

impl Drop for Place {
    fn drop(&mut self) {
        self.0.fetch_sub(ONE_READ, Ordering::AcqRel);
    }
}

/// One call's share of the budget: the right to have the call running, and then to have its
/// answer held, with the answer's bytes once it is in ([`Share::weigh`]). The task owns it while
/// it runs and sends it with the answer; the read keeps it until it is done with the answer. It is
/// given back, call and bytes together, when `Pending::wait` returns, when the read is dropped
/// (the answers still in the channel go with it), when a task that is over finds nobody waiting
/// (it gave up, or the send fails), or when the task is dropped, run or not (the runtime shutting
/// down drops the tasks it never ran). A task still queued on a stuck runtime keeps its share, as
/// it keeps the read's place. Each share is dropped once, by whoever owns it last; nothing clones
/// it.
#[derive(Debug)]
struct Share {
    state: Arc<AtomicU64>,
    /// The bytes of the answer it holds, and the scale they count on: `None` until an answer of
    /// some bytes is in and kept.
    weight: Option<(Arc<Scale>, u64)>,
}

impl Share {
    /// REQ: CLU-004 (ADR-174) — weighs the answer of `n` bytes this share's call got: `true` if
    /// it may be kept, its bytes counted until the share is given back; `false` if they would
    /// pass a cap, and nothing was counted.
    fn weigh(&mut self, scale: &Arc<Scale>, n: u64) -> bool {
        if n == 0 {
            return true;
        }
        let kept = scale.take(n);
        if kept {
            self.weight = Some((Arc::clone(scale), n));
        }
        kept
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        if let Some((scale, n)) = self.weight.take() {
            scale.give(n);
        }
        self.state.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The shares a read took and has not handed to a task yet. What is left when it is dropped goes
/// back to the budget, so a read that stops half-way (a panic) leaks nothing.
#[derive(Debug)]
struct Unissued {
    state: Arc<AtomicU64>,
    left: u64,
}

impl Unissued {
    fn issue(&mut self) -> Option<Share> {
        self.left = self.left.checked_sub(1)?;
        Some(Share {
            state: Arc::clone(&self.state),
            weight: None,
        })
    }
}

impl Drop for Unissued {
    fn drop(&mut self) {
        if self.left > 0 {
            self.state.fetch_sub(self.left, Ordering::AcqRel);
        }
    }
}

/// What a read that was allowed holds.
#[derive(Debug)]
struct Grant {
    place: Arc<Place>,
    shares: Unissued,
}

impl Limiter {
    /// Up to `max_reads` reads waiting, [`CALL_BUDGET`] calls counted, and the production caps
    /// on bytes.
    pub(super) fn new(max_reads: usize) -> Self {
        Self::with_budget(max_reads, CALL_BUDGET)
    }

    pub(super) fn with_budget(max_reads: usize, budget: usize) -> Self {
        Self::with_caps(max_reads, budget, HELD_BYTES, READ_BYTES)
    }

    /// Any caps: `held_bytes` for all reads' answers, `read_bytes` for one read's.
    pub(super) fn with_caps(
        max_reads: usize,
        budget: usize,
        held_bytes: usize,
        read_bytes: usize,
    ) -> Self {
        // The reads live in the high half: more than it holds could not be counted.
        let max_reads = u64::try_from(max_reads).unwrap_or(u64::MAX).min(CALL_MASK);
        let budget = u64::try_from(budget).unwrap_or(CALL_MASK).min(CALL_MASK);
        Self {
            state: Arc::new(AtomicU64::new(0)),
            max_reads,
            budget,
            ledger: Arc::new(Ledger {
                bytes: AtomicU64::new(0),
                held_cap: u64::try_from(held_bytes).unwrap_or(u64::MAX),
                read_cap: u64::try_from(read_bytes).unwrap_or(u64::MAX),
                log: RefusalLog::default(),
                since: Instant::now(),
                max_reads,
                budget,
            }),
        }
    }

    /// REQ: CLU-004 (final review, F2) — counts a read that was not sent, and says so in the log
    /// ([`Ledger::refused`]).
    pub(super) fn refused(&self, why: Refused) {
        self.ledger.refused(why);
    }

    /// REQ: CLU-004 (ADR-174) — the reads refused since the start, for each reason (the metric
    /// `telltale_federated_refused_total`).
    pub(super) fn refusals(&self) -> [(Refused, u64); 4] {
        Refused::ALL.map(|why| (why, self.ledger.log.total(why)))
    }

    /// REQ: CLU-004, CLU-002 (ADR-174) — a place among the reads and a share for each of `n`
    /// calls, all or nothing. Over the places: [`Refused::Full`]; over the budget:
    /// [`Refused::Spent`]. The caller has already kept `n` within [`MAX_READ_CALLS`].
    fn acquire(&self, n: usize) -> Result<Grant, Refused> {
        let n = u64::try_from(n).unwrap_or(u64::MAX);
        self.state
            .try_update(Ordering::AcqRel, Ordering::Acquire, |s| {
                let (reads, calls) = (s >> 32, s & CALL_MASK);
                // `calls + n` fits the low half: it is at most the budget, which does.
                (reads < self.max_reads && calls.saturating_add(n) <= self.budget)
                    .then_some(s + ONE_READ + n)
            })
            .map(|_| Grant {
                place: Arc::new(Place(Arc::clone(&self.state))),
                shares: Unissued {
                    state: Arc::clone(&self.state),
                    left: n,
                },
            })
            .map_err(|seen| {
                if seen >> 32 >= self.max_reads {
                    Refused::Full
                } else {
                    Refused::Spent
                }
            })
    }

    /// Reads waiting now.
    #[cfg(test)]
    pub(super) fn in_flight(&self) -> usize {
        usize::try_from(self.state.load(Ordering::Acquire) >> 32).unwrap_or(usize::MAX)
    }

    /// Calls counted now: a task that is running, or an answer that waits for its read.
    #[cfg(test)]
    fn calls_in_flight(&self) -> usize {
        usize::try_from(self.state.load(Ordering::Acquire) & CALL_MASK).unwrap_or(usize::MAX)
    }

    /// Bytes of answers held now, all reads together.
    #[cfg(test)]
    fn bytes_held(&self) -> u64 {
        self.ledger.bytes.load(Ordering::Acquire)
    }

    /// The refusal log (tests feed it and read it).
    #[cfg(test)]
    fn log(&self) -> &RefusalLog {
        &self.ledger.log
    }
}

/// One call's result: the peer's answer, or why there is none.
type Answer = Result<Vec<u8>, String>;

/// What a call's task sends when it is over: which call, its answer (`None`: it came in and was
/// dropped, its bytes over a cap), and the call's share, which travels with the answer so the
/// budget goes on counting it, and its bytes, until the read is done with it.
type Done = (usize, Option<Answer>, Share);

/// Calls started on the runtime, to be waited for on the calling thread.
#[derive(Debug)]
pub(super) struct Pending {
    peers: Vec<String>,
    /// What is in so far, by call.
    results: Vec<Option<Answer>>,
    /// The shares of the answers that are in, kept until `wait` returns.
    shares: Vec<Share>,
    rx: Option<mpsc::Receiver<Done>>,
    /// What this read's answers weigh (`None` for a read that wasn't sent).
    scale: Option<Arc<Scale>>,
    /// Whether an answer of this read was dropped for its bytes: the read is counted once.
    lost: bool,
    /// When the caller stops waiting.
    until: Instant,
    /// Set when the caller stops waiting: a call still queued then isn't sent, and an answer
    /// that comes in after isn't weighed or kept.
    gave_up: Arc<AtomicBool>,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.gave_up.store(true, Ordering::Release);
    }
}

/// Starts each of `calls` (a peer, and its RPC) as a task on `rt` and returns at once. `timeout`
/// is the RPCs' own; the wait ends [`GRACE`] after it at the latest. Over the cap of reads, with
/// more than [`MAX_READ_CALLS`] calls, or without room for all of them in the [`CALL_BUDGET`],
/// nothing is started and nothing is taken, and every call's result is "wasn't asked". An
/// answer whose bytes would pass a cap ([`READ_BYTES`], [`HELD_BYTES`]) is "wasn't kept".
pub(super) fn start<Fut>(
    limiter: &Limiter,
    rt: &tokio::runtime::Handle,
    calls: Vec<(String, Fut)>,
    timeout: Duration,
) -> Pending
where
    Fut: Future<Output = Answer> + Send + 'static,
{
    let (peers, futures): (Vec<String>, Vec<Fut>) = calls.into_iter().unzip();
    let mut results: Vec<Option<Answer>> = vec![None; peers.len()];
    let pending = |peers, results, rx, scale| Pending {
        peers,
        results,
        shares: Vec::new(),
        rx,
        scale,
        lost: false,
        until: Instant::now() + timeout + GRACE,
        gave_up: Arc::new(AtomicBool::new(false)),
    };
    if futures.is_empty() {
        return pending(peers, results, None, None);
    }
    // REQ: CLU-004, CLU-002 (ADR-174; final review, F1) — the places count reads, not the tasks
    // each makes, so the tasks are bounded here: a read of too many calls, or one the budget of
    // calls in flight has no room for, is not sent, and takes neither a place nor a share.
    let allowed = if futures.len() > MAX_READ_CALLS {
        Err(Refused::TooBig)
    } else {
        limiter.acquire(futures.len())
    };
    let mut grant = match allowed {
        Ok(grant) => grant,
        Err(why) => {
            limiter.refused(why);
            drop(futures);
            for (r, peer) in results.iter_mut().zip(&peers) {
                *r = Some(Err(format!("{peer} wasn't asked: {}", why.why())));
            }
            return pending(peers, results, None, None);
        }
    };
    let (tx, rx) = mpsc::channel();
    let scale = Arc::new(Scale {
        ledger: Arc::clone(&limiter.ledger),
        read: AtomicU64::new(0),
    });
    let started = pending(peers, results, Some(rx), Some(Arc::clone(&scale)));
    for (i, call) in futures.into_iter().enumerate() {
        // One share for each task, and every task keeps the read's place until it ends. The
        // share goes with the answer to the read, which gives it back when it is done with it;
        // a task that is dropped, or that finds nobody waiting, drops it itself.
        let Some(mut share) = grant.shares.issue() else {
            break;
        };
        let (tx, place, gave_up, scale) = (
            tx.clone(),
            Arc::clone(&grant.place),
            Arc::clone(&started.gave_up),
            Arc::clone(&scale),
        );
        drop(rt.spawn(async move {
            let _place = place;
            if gave_up.load(Ordering::Acquire) {
                return;
            }
            let answer = call.await;
            // REQ: CLU-004 (ADR-174) — nobody waits for it: it isn't weighed, and goes now.
            if gave_up.load(Ordering::Acquire) {
                return;
            }
            // Weighed before it is kept: over a cap it goes here, and its call is "wasn't kept".
            let kept = share.weigh(&scale, weight(&answer)).then_some(answer);
            let _ = tx.send((i, kept, share));
        }));
    }
    started
}

impl Pending {
    /// Waits for every call, or until the deadline: one entry per call, in the order given, with
    /// the answer or why there is none (`didn't answer in time` for a call the runtime never
    /// finished, `wasn't kept` for one whose answer was over a cap on bytes). Blocks the calling
    /// thread only: it needs nothing from the runtime to wake. The shares of the answers it
    /// returns, with their bytes, go back as it returns: the read is done with them. (A call that
    /// never answered keeps its own until its task ends.)
    pub(super) fn wait(mut self) -> Vec<(String, Answer)> {
        let mut missing = self.results.iter().filter(|r| r.is_none()).count();
        let mut why = "didn't answer in time";
        if let Some(rx) = self.rx.take() {
            while missing > 0 {
                let left = self.until.saturating_duration_since(Instant::now());
                match rx.recv_timeout(left) {
                    Ok((i, r, share)) => self.put(i, r, share, &mut missing),
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        why = "wasn't answered: its call was dropped";
                        break;
                    }
                }
            }
            // What came in as the deadline passed.
            while let Ok((i, r, share)) = rx.try_recv() {
                self.put(i, r, share, &mut missing);
            }
        }
        // Done with the answers: their shares and bytes go back (an answer that comes in later
        // finds nobody waiting, and its task drops its share).
        self.shares.clear();
        // REQ: CLU-004 (ADR-174) — a read that lost an answer to a cap on bytes is counted once,
        // here on the caller's thread.
        if self.lost
            && let Some(scale) = &self.scale
        {
            scale.ledger.refused(Refused::Bytes);
        }
        let peers = std::mem::take(&mut self.peers);
        let results = std::mem::take(&mut self.results);
        peers
            .into_iter()
            .zip(results)
            .map(|(peer, r)| {
                let r = r.unwrap_or_else(|| Err(format!("{peer} {why}")));
                (peer, r)
            })
            .collect()
    }

    /// Takes in one call's answer, and keeps its share until `wait` returns. An answer that was
    /// dropped for its bytes is "wasn't kept", which a caller reads as it reads a peer that didn't
    /// answer.
    fn put(&mut self, i: usize, r: Option<Answer>, share: Share, missing: &mut usize) {
        self.shares.push(share);
        if let Some(slot) = self.results.get_mut(i)
            && slot.is_none()
        {
            *slot = Some(r.unwrap_or_else(|| {
                self.lost = true;
                let peer = self.peers.get(i).map_or("a node", String::as_str);
                Err(format!("{peer} wasn't kept: {}", Refused::Bytes.why()))
            }));
            *missing -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc::channel;

    use super::*;

    type Call = Pin<Box<dyn Future<Output = Answer> + Send>>;

    fn runtime(workers: usize) -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()
            .unwrap()
    }

    fn answer(text: &'static str) -> Call {
        Box::pin(async move { Ok(text.as_bytes().to_vec()) })
    }

    /// Parks the runtime's only worker until the returned sender is used, and returns once it is
    /// parked: the production wedge.
    fn wedge(rt: &tokio::runtime::Runtime) -> mpsc::Sender<()> {
        let (gate, shut) = channel::<()>();
        let (parked_tx, parked) = channel::<()>();
        drop(rt.spawn(async move {
            let _ = parked_tx.send(());
            // Blocking on purpose; it gives up after a minute so a failed test leaves nothing.
            let _ = shut.recv_timeout(Duration::from_secs(60));
        }));
        parked.recv_timeout(Duration::from_secs(10)).unwrap();
        gate
    }

    /// A bounded wait for a condition that another thread will make true.
    fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(10);
        while !ok() {
            assert!(Instant::now() < until, "not met in time: {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A count the calls of a test share.
    fn count() -> Arc<AtomicUsize> {
        Arc::new(AtomicUsize::new(0))
    }

    /// Counts itself while it exists: held by a call (queued, running, or dropped without having
    /// run), so a test can see how many calls a limiter really let live without asking the
    /// limiter.
    #[derive(Debug)]
    struct Live(Arc<AtomicUsize>);

    impl Live {
        fn new(live: &Arc<AtomicUsize>) -> Self {
            live.fetch_add(1, Ordering::SeqCst);
            Self(Arc::clone(live))
        }
    }

    impl Drop for Live {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// A door the calls wait at: shut until `open`. (A `watch`, so a call that reaches the door
    /// after it was opened goes through, and a test can start any number of calls on it.)
    struct Gate(tokio::sync::watch::Sender<bool>);

    impl Gate {
        fn shut() -> Self {
            Self(tokio::sync::watch::channel(false).0)
        }

        fn open(&self) {
            self.0.send_replace(true);
        }

        /// A call that waits at the gate, then answers `ok`. It counts in `live` while it exists
        /// and in `ran` once it is run.
        fn call(&self, live: &Arc<AtomicUsize>, ran: &Arc<AtomicUsize>) -> Call {
            let (mut door, live, ran) = (self.0.subscribe(), Live::new(live), Arc::clone(ran));
            Box::pin(async move {
                let _live = live;
                let _ = door.wait_for(|open| *open).await;
                ran.fetch_add(1, Ordering::SeqCst);
                Ok(b"ok".to_vec())
            })
        }

        /// `n` such calls to peers named `<tag><i>`.
        fn calls(
            &self,
            n: usize,
            tag: &str,
            live: &Arc<AtomicUsize>,
            ran: &Arc<AtomicUsize>,
        ) -> Vec<(String, Call)> {
            (0..n)
                .map(|i| (format!("{tag}{i}"), self.call(live, ran)))
                .collect()
        }
    }

    /// Tells a watching thread to stop when it goes out of scope, a panic included.
    struct StopOnDrop(Arc<AtomicBool>);

    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    /// Whether `start` sent the read (it did not when it was refused: every call answered at once).
    fn was_sent(read: &Pending) -> bool {
        read.rx.is_some()
    }

    /// Whether every call of an answered read was refused with `wasn't asked` and `why`.
    fn refused_for(got: &[(String, Answer)], why: &str) -> bool {
        !got.is_empty()
            && got.iter().all(|(_, r)| {
                r.as_ref()
                    .is_err_and(|e| e.contains("wasn't asked") && e.contains(why))
            })
    }

    // REQ: CLU-002 — a read's results come back in the order its calls were given, whatever
    // order they finished in; an error is the peer's own answer and passes through.
    #[test]
    fn clu_002_the_bridge_answers_in_the_order_asked() {
        let rt = runtime(2);
        let limiter = Limiter::new(8);
        let (first_done, first) = tokio::sync::oneshot::channel::<()>();
        let calls: Vec<(String, Call)> = vec![
            (
                "a".into(),
                // Finishes last: it waits for "c".
                Box::pin(async move {
                    let _ = first.await;
                    Ok(b"A".to_vec())
                }),
            ),
            (
                "b".into(),
                Box::pin(async { Err("no such read".to_owned()) }),
            ),
            (
                "c".into(),
                Box::pin(async move {
                    let _ = first_done.send(());
                    Ok(b"C".to_vec())
                }),
            ),
        ];
        let got = start(&limiter, rt.handle(), calls, Duration::from_secs(5)).wait();
        let want: Vec<(String, Answer)> = vec![
            ("a".into(), Ok(b"A".to_vec())),
            ("b".into(), Err("no such read".into())),
            ("c".into(), Ok(b"C".to_vec())),
        ];
        assert_eq!(got, want);
        // Nothing to ask is nothing to wait for.
        let none = start::<Call>(&limiter, rt.handle(), Vec::new(), Duration::from_secs(5));
        assert!(none.wait().is_empty(), "no calls, no answers");
        wait_until("every place is given back", || limiter.in_flight() == 0);
    }

    // REQ: CLU-002, CLU-004 — a call that never finishes costs the read its deadline (and the
    // grace), and the calls that did finish still answer.
    #[test]
    fn clu_004_a_call_that_never_finishes_costs_only_its_deadline() {
        let rt = runtime(2);
        let limiter = Limiter::new(8);
        let calls: Vec<(String, Call)> = vec![
            ("quick".into(), answer("Q")),
            (
                "stuck".into(),
                Box::pin(async {
                    std::future::pending::<()>().await;
                    Ok(Vec::new())
                }),
            ),
        ];
        let started = Instant::now();
        let got = start(&limiter, rt.handle(), calls, Duration::from_millis(100)).wait();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(got[0], ("quick".to_owned(), Ok(b"Q".to_vec())));
        let (peer, r) = &got[1];
        assert_eq!(peer, "stuck");
        assert!(
            r.as_ref().unwrap_err().contains("didn't answer in time"),
            "{r:?}"
        );
    }

    // REQ: CLU-004 (ADR-174, GitHub issue #7) — every worker parked: the wait still ends at its
    // deadline, from a plain thread; and a call nobody ran is not sent once the caller has gone
    // (the runtime wakes to find the queue full of calls whose callers left).
    #[test]
    fn clu_004_a_wedged_runtime_costs_the_bridge_its_deadline_and_the_call_is_not_sent_late() {
        let rt = runtime(1);
        let limiter = Limiter::new(8);
        let gate = wedge(&rt);
        let sent = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&sent);
        let calls: Vec<(String, Call)> = vec![(
            "peer".into(),
            Box::pin(async move {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            }),
        )];
        let started = Instant::now();
        let got = start(&limiter, rt.handle(), calls, Duration::from_millis(100)).wait();
        // Only an upper bound, far above the 350 ms: no race.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(
            got[0]
                .1
                .as_ref()
                .unwrap_err()
                .contains("didn't answer in time"),
            "{got:?}"
        );
        assert_eq!(
            limiter.in_flight(),
            1,
            "the queued task still holds its place"
        );
        // The runtime comes back: the task runs, finds nobody waiting, and sends nothing.
        gate.send(()).unwrap();
        wait_until("the queued task ends", || limiter.in_flight() == 0);
        assert_eq!(
            sent.load(Ordering::SeqCst),
            0,
            "a call was sent after its caller left"
        );
    }

    // REQ: CLU-004 (ADR-174) — over the cap a read is not sent: it is told "wasn't asked" at
    // once, without a wait; when the place is free again, reads go out.
    #[test]
    fn clu_004_over_the_cap_a_read_is_not_sent() {
        let rt = runtime(2);
        let limiter = Limiter::new(1);
        let (open, shut) = tokio::sync::oneshot::channel::<()>();
        let held: Vec<(String, Call)> = vec![(
            "held".into(),
            Box::pin(async move {
                let _ = shut.await;
                Ok(b"H".to_vec())
            }),
        )];
        let first = start(&limiter, rt.handle(), held, Duration::from_secs(30));
        assert_eq!(limiter.in_flight(), 1);
        let sent = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&sent);
        let second_calls: Vec<(String, Call)> = vec![(
            "late".into(),
            Box::pin(async move {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            }),
        )];
        let started = Instant::now();
        let second = start(&limiter, rt.handle(), second_calls, Duration::from_secs(30)).wait();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(
            second[0].1.as_ref().unwrap_err().contains("wasn't asked"),
            "{second:?}"
        );
        assert_eq!(limiter.in_flight(), 1, "a refused read takes no place");
        // The held read finishes; its place comes back; the next read goes out.
        open.send(()).unwrap();
        assert_eq!(first.wait()[0].1, Ok(b"H".to_vec()));
        wait_until("the place is given back", || limiter.in_flight() == 0);
        let third = start(
            &limiter,
            rt.handle(),
            vec![("again".into(), answer("T"))],
            Duration::from_secs(5),
        )
        .wait();
        assert_eq!(third[0].1, Ok(b"T".to_vec()));
        assert_eq!(sent.load(Ordering::SeqCst), 0);
    }

    /// A call that counts the times it is run.
    fn counting(sent: &Arc<AtomicUsize>) -> Call {
        let sent = Arc::clone(sent);
        Box::pin(async move {
            sent.fetch_add(1, Ordering::SeqCst);
            Ok(b"ok".to_vec())
        })
    }

    // REQ: CLU-004, CLU-002 (ADR-174, final review F1) — a read of more than 4,096 calls is not
    // sent at all: none of its calls is run, it takes neither a place nor a share of the budget,
    // and every call is told "wasn't asked". Before: one task per call, however many (a viewer's
    // request for a long range of seconds made millions), under one place.
    #[test]
    fn clu_004_a_read_over_the_ceiling_is_not_sent() {
        let rt = runtime(2);
        let limiter = Limiter::new(8);
        let sent = count();
        assert_eq!(MAX_READ_CALLS, 4096, "the number the ADR and the docs give");
        let calls: Vec<(String, Call)> = (0..=MAX_READ_CALLS)
            .map(|i| (format!("p{i}"), counting(&sent)))
            .collect();
        let started = Instant::now();
        let got = start(&limiter, rt.handle(), calls, Duration::from_secs(30)).wait();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            got.len(),
            MAX_READ_CALLS + 1,
            "one answer for each call, in order"
        );
        assert!(
            got.iter().enumerate().all(|(i, (peer, r))| {
                *peer == format!("p{i}") && r.as_ref().is_err_and(|e| e.contains("wasn't asked"))
            }),
            "{:?}",
            got.first()
        );
        assert_eq!(limiter.in_flight(), 0, "a refused read takes no place");
        assert_eq!(
            limiter.calls_in_flight(),
            0,
            "a refused read takes no share"
        );
        assert_eq!(sent.load(Ordering::SeqCst), 0, "no call was run");
    }

    // REQ: CLU-004, CLU-002 (ADR-174, final review F1) — the ceiling is on what a read may ask,
    // not a cut in what is sent: a read of exactly 4,096 calls (a 47-node cluster's whole history by
    // the day) is sent in full and answered in order, and every share and place comes back.
    // Before: a flat cap of 1,024 refused it.
    #[test]
    fn clu_004_a_read_at_the_ceiling_is_sent_in_full() {
        let rt = runtime(2);
        let limiter = Limiter::new(8);
        let sent = count();
        let calls: Vec<(String, Call)> = (0..MAX_READ_CALLS)
            .map(|i| (format!("p{i}"), counting(&sent)))
            .collect();
        let got = start(&limiter, rt.handle(), calls, Duration::from_secs(30)).wait();
        assert_eq!(got.len(), MAX_READ_CALLS);
        assert!(
            got.iter()
                .enumerate()
                .all(|(i, (peer, r))| { *peer == format!("p{i}") && *r == Ok(b"ok".to_vec()) }),
            "{:?}",
            got.iter().find(|(_, r)| r.is_err())
        );
        assert_eq!(sent.load(Ordering::SeqCst), MAX_READ_CALLS);
        wait_until("every place and share is given back", || {
            limiter.in_flight() == 0 && limiter.calls_in_flight() == 0
        });
    }

    // REQ: CLU-004, CLU-002 (ADR-174) — the longest range any step documents, for a cluster of 40
    // peers, is sent in full: 40 peers x 4, 43, 41 and 87 windows (160, 1,720, 1,640 and 3,480
    // calls). Each call runs once and the answers come back in the order asked. Before: the flat
    // cap of 1,024 calls refused three of the four, whole (this is what a 12-peer cluster hit at
    // `step=day`). The edges are 47 peers at the largest range and no more.
    #[test]
    fn clu_002_the_documented_ranges_are_sent_in_full_to_forty_peers() {
        use telltale_api::federation::timeseries_chunks;
        use telltale_api::model::Step;
        let rt = runtime(2);
        let now = 1_791_072_000;
        let cases = [
            (Step::Second, now - 900, now + 1, 4),
            (Step::Minute, now - 7 * 86_400, now + 1, 43),
            (Step::Hour, now - 400 * 86_400, now + 1, 41),
            (Step::Day, 0, now + 1, 87),
        ];
        for (step, from, to, windows) in cases {
            let limiter = Limiter::new(MAX_WAITS);
            let chunks = timeseries_chunks(step, from, to).expect("a documented range");
            assert_eq!(chunks.len(), windows, "{step:?}");
            // One call per peer and window, in the order `peer_timeseries` makes them. Each
            // answers its own number, so a call run twice or out of order shows.
            let ran = count();
            let calls: Vec<(String, Call)> = (0..40)
                .flat_map(|p| (0..chunks.len()).map(move |w| (p, w)))
                .enumerate()
                .map(|(i, (p, w))| {
                    let ran = Arc::clone(&ran);
                    let call: Call = Box::pin(async move {
                        ran.fetch_add(1, Ordering::SeqCst);
                        Ok(i.to_le_bytes().to_vec())
                    });
                    (format!("peer{p}/window{w}"), call)
                })
                .collect();
            let total = calls.len();
            assert_eq!(total, 40 * windows);
            let got = start(&limiter, rt.handle(), calls, Duration::from_secs(30)).wait();
            assert_eq!(got.len(), total, "{step:?}");
            assert!(
                got.iter()
                    .enumerate()
                    .all(|(i, (_, r))| *r == Ok(i.to_le_bytes().to_vec())),
                "{step:?}: {:?}",
                got.iter().find(|(_, r)| r.is_err())
            );
            assert_eq!(ran.load(Ordering::SeqCst), total, "{step:?}");
            wait_until("every place and share is given back", || {
                limiter.in_flight() == 0 && limiter.calls_in_flight() == 0
            });
        }
        // The arithmetic the docs give: the peers whose calls fit in 4,096 at each range.
        assert_eq!(MAX_READ_CALLS / 87, 47, "all of history by the day");
        assert_eq!(MAX_READ_CALLS / 43, 95, "7 days of minutes");
        assert_eq!(MAX_READ_CALLS / 41, 99, "400 days of hours");
    }

    // REQ: CLU-004, CLU-002 (ADR-174) — the worst case did not grow. The budget is the number
    // the flat cap's worst case was (32 reads of 1,024 calls), and a ceiling above the budget's
    // 32nd part must not be a way past it.
    #[test]
    fn clu_004_the_budget_is_the_worst_case_the_flat_cap_allowed() {
        assert_eq!(MAX_WAITS, 32);
        assert_eq!(CALL_BUDGET, 32 * 1024, "32,768 calls in flight, as before");
        assert_eq!(CALL_BUDGET / MAX_READ_CALLS, 8, "eight whole reads fill it");
        assert_eq!(
            MAX_WAITS * MAX_READ_CALLS,
            4 * CALL_BUDGET,
            "the places times the ceiling is four times the budget: the budget is what bounds"
        );
    }

    // REQ: CLU-004, CLU-002 (ADR-174) — a big read is sent when there is room in the budget for
    // all of it, and refused (whole, taking nothing) when there is not. The budget is the
    // production one: eight reads of the ceiling use it all.
    #[test]
    fn clu_004_a_big_read_is_sent_when_the_budget_is_free_and_refused_when_it_is_not() {
        let rt = runtime(2);
        let limiter = Limiter::new(MAX_WAITS);
        let _ = limiter.log().note(Refused::Full, 0); // so the next refusals are only counted
        let (live, ran) = (count(), count());
        let (hold, free) = (Gate::shut(), Gate::shut());
        let long = Duration::from_secs(60);
        let mut parked = Vec::new();
        for r in 0..7 {
            let calls = hold.calls(MAX_READ_CALLS, &format!("hold{r}-"), &live, &ran);
            let read = start(&limiter, rt.handle(), calls, long);
            assert!(was_sent(&read), "read {r} fits");
            parked.push(read);
        }
        // The eighth is the one that will be let go: with it, the budget is spent.
        let last = free.calls(MAX_READ_CALLS, "free-", &live, &ran);
        let last = start(&limiter, rt.handle(), last, long);
        assert!(was_sent(&last));
        assert_eq!(limiter.calls_in_flight(), CALL_BUDGET);
        assert_eq!(limiter.in_flight(), 8);
        // A read of 4,000 calls: refused, whole, and taking nothing.
        let big = hold.calls(4_000, "big-", &live, &ran);
        let started = Instant::now();
        let got = start(&limiter, rt.handle(), big, long).wait();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            refused_for(&got, "calls are already running or waiting to be read"),
            "{:?}",
            got.first()
        );
        assert_eq!(got.len(), 4_000);
        assert_eq!(limiter.calls_in_flight(), CALL_BUDGET, "it took no share");
        assert_eq!(limiter.in_flight(), 8, "it took no place");
        assert_eq!(
            live.load(Ordering::SeqCst),
            CALL_BUDGET,
            "its calls were dropped"
        );
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert_eq!(
            limiter.log().pending(),
            Tally {
                full: 0,
                spent: 1,
                too_big: 0,
                bytes: 0
            }
        );
        // One read of the ceiling ends: there is room for 4,000 again.
        free.open();
        assert!(last.wait().iter().all(|(_, r)| r.is_ok()));
        wait_until("its shares are back", || {
            limiter.calls_in_flight() == CALL_BUDGET - MAX_READ_CALLS
        });
        let again = hold.calls(4_000, "again-", &live, &ran);
        let again = start(&limiter, rt.handle(), again, long);
        assert!(
            was_sent(&again),
            "4,000 calls fit in the room that was left"
        );
        assert_eq!(
            limiter.calls_in_flight(),
            CALL_BUDGET - MAX_READ_CALLS + 4_000
        );
        hold.open();
        for read in parked.into_iter().chain([again]) {
            assert!(read.wait().iter().all(|(_, r)| r.is_ok()));
        }
        wait_until("everything is given back", || {
            limiter.calls_in_flight() == 0 && limiter.in_flight() == 0
        });
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    // REQ: CLU-004 (ADR-174) — two reads that together are over the budget: the first is sent,
    // the second is refused whole and takes nothing (not a place, not a share, and not part of
    // what it asked: none of its calls runs), and a read that does fit still goes. Exact, with a
    // budget of ten.
    #[test]
    fn clu_004_two_reads_over_the_budget_the_second_is_refused_and_takes_nothing() {
        let rt = runtime(2);
        let limiter = Limiter::with_budget(8, 10);
        let _ = limiter.log().note(Refused::Full, 0);
        let (live, ran, gate) = (count(), count(), Gate::shut());
        let long = Duration::from_secs(60);
        let first = start(&limiter, rt.handle(), gate.calls(6, "a", &live, &ran), long);
        assert!(was_sent(&first));
        assert_eq!((limiter.in_flight(), limiter.calls_in_flight()), (1, 6));
        // 6 + 5 is over 10: refused, with nothing taken and nothing run.
        let second = start(&limiter, rt.handle(), gate.calls(5, "b", &live, &ran), long).wait();
        assert!(
            refused_for(&second, "calls are already running or waiting to be read"),
            "{second:?}"
        );
        assert_eq!((limiter.in_flight(), limiter.calls_in_flight()), (1, 6));
        assert_eq!(live.load(Ordering::SeqCst), 6, "the refused calls are gone");
        assert_eq!(
            limiter.log().pending(),
            Tally {
                full: 0,
                spent: 1,
                too_big: 0,
                bytes: 0
            }
        );
        // 6 + 4 is exactly 10: it fits. One call more does not.
        let third = start(&limiter, rt.handle(), gate.calls(4, "c", &live, &ran), long);
        assert!(was_sent(&third));
        assert_eq!((limiter.in_flight(), limiter.calls_in_flight()), (2, 10));
        let fourth = start(&limiter, rt.handle(), gate.calls(1, "d", &live, &ran), long).wait();
        assert!(refused_for(
            &fourth,
            "calls are already running or waiting to be read"
        ));
        assert_eq!(limiter.calls_in_flight(), 10);
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "nothing ran while the gate was shut"
        );
        gate.open();
        assert!(first.wait().iter().all(|(_, r)| r.is_ok()));
        assert!(third.wait().iter().all(|(_, r)| r.is_ok()));
        wait_until("everything is given back", || {
            limiter.calls_in_flight() == 0 && limiter.in_flight() == 0
        });
        assert_eq!(ran.load(Ordering::SeqCst), 10, "only the two reads ran");
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    /// Calls that answer at once, counting each one that has (so a test knows its answers are in).
    fn quick(n: usize, tag: &str, done: &Arc<AtomicUsize>) -> Vec<(String, Call)> {
        (0..n)
            .map(|i| (format!("{tag}{i}"), counting(done)))
            .collect()
    }

    // REQ: CLU-004, CLU-002 (ADR-174, final review round 2, F1) — a call's share is the right to
    // hold its answer, so it comes back when the read is done with the answer (`wait` returns, or
    // the read is dropped), not when the call's task ends: answers that wait for their read count
    // against the budget. Before: the share went with the task, so a read with 7 answers in and one
    // call out held one share, and the next read could take as many again. Budget of ten.
    #[test]
    fn clu_004_a_finished_call_keeps_its_share_until_the_read_is_done_with_its_answer() {
        let rt = runtime(2);
        let limiter = Limiter::with_budget(8, 10);
        let _ = limiter.log().note(Refused::Full, 0);
        let (live, ran, done, gate) = (count(), count(), count(), Gate::shut());
        let long = Duration::from_secs(60);
        let mut calls = quick(7, "quick", &done);
        calls.extend(gate.calls(1, "held", &live, &ran));
        let first = start(&limiter, rt.handle(), calls, long);
        assert!(was_sent(&first));
        // Seven answers are in and their tasks are over; the eighth call is still out.
        wait_until("the quick calls answered", || {
            done.load(Ordering::SeqCst) == 7
        });
        wait_until("only the held call's task is alive", || {
            rt.metrics().num_alive_tasks() == 1
        });
        assert_eq!(
            limiter.calls_in_flight(),
            8,
            "the answers that wait for their read still count"
        );
        assert_eq!(limiter.in_flight(), 1);
        assert_eq!(
            limiter.bytes_held(),
            14,
            "the seven answers' bytes are held with them"
        );
        // So a second read of 3 does not fit (8 + 3 > 10), and takes nothing.
        let second = start(&limiter, rt.handle(), gate.calls(3, "b", &live, &ran), long).wait();
        assert!(
            refused_for(&second, "calls are already running or waiting to be read"),
            "{second:?}"
        );
        assert_eq!(limiter.calls_in_flight(), 8);
        assert_eq!(
            limiter.log().pending(),
            Tally {
                full: 0,
                spent: 1,
                too_big: 0,
                bytes: 0
            }
        );
        // The held call answers, and the read is done: every share is back at once.
        gate.open();
        let got = first.wait();
        assert_eq!(got.len(), 8);
        assert!(got.iter().all(|(_, r)| r.is_ok()), "{got:?}");
        assert_eq!(
            limiter.calls_in_flight(),
            0,
            "wait gave the answers' shares back"
        );
        assert_eq!(
            limiter.bytes_held(),
            0,
            "and their bytes, at the same moment"
        );
        wait_until("the place is back", || limiter.in_flight() == 0);
        // And now the second read fits.
        let third = start(&limiter, rt.handle(), gate.calls(3, "c", &live, &ran), long).wait();
        assert!(third.iter().all(|(_, r)| r.is_ok()), "{third:?}");
        wait_until("everything is given back", || {
            limiter.calls_in_flight() == 0 && limiter.in_flight() == 0
        });
    }

    // REQ: CLU-004, CLU-002 (ADR-174, final review round 2, F1) — the answers a waiting read
    // holds are bounded by the budget, not only the calls still out. Thirty-two reads of the
    // ceiling are tried, each with 4,095 calls that answer at once and one that is held: the
    // answers that wait for their reads (counted by the calls that ran, none is consumed yet) plus
    // the held calls never pass 32,768. Before: 4,095 shares came back as the quick calls
    // ended, so all 32 reads were sent and 131,040 answers waited, four times the old cap's.
    #[test]
    fn clu_004_answers_held_while_waiting_never_pass_the_budget() {
        let rt = runtime(2);
        let limiter = Limiter::new(MAX_WAITS);
        let (live, ran, done, gate) = (count(), count(), count(), Gate::shut());
        let long = Duration::from_secs(60);
        let mut waiting = Vec::new();
        let mut answered = 0;
        for r in 0..MAX_WAITS {
            let mut calls = quick(MAX_READ_CALLS - 1, &format!("q{r}-"), &done);
            calls.extend(gate.calls(1, &format!("held{r}-"), &live, &ran));
            let read = start(&limiter, rt.handle(), calls, long);
            if was_sent(&read) {
                waiting.push(read);
                answered += MAX_READ_CALLS - 1;
                // This read's quick answers are in, and their tasks are over.
                wait_until("the quick calls answered", || {
                    done.load(Ordering::SeqCst) == answered
                });
                wait_until("only the held calls' tasks are alive", || {
                    rt.metrics().num_alive_tasks() == waiting.len()
                });
            }
        }
        let held = done.load(Ordering::SeqCst) + waiting.len();
        assert!(
            held <= CALL_BUDGET,
            "{} reads waiting hold {held} answers and calls: more than the budget of {CALL_BUDGET}",
            waiting.len()
        );
        assert_eq!(waiting.len(), CALL_BUDGET / MAX_READ_CALLS);
        assert_eq!(limiter.calls_in_flight(), CALL_BUDGET);
        // Each read, done with its answers, gives its shares back.
        gate.open();
        for read in waiting {
            assert!(read.wait().iter().all(|(_, r)| r.is_ok()));
        }
        assert_eq!(limiter.calls_in_flight(), 0);
        wait_until("every place is back", || limiter.in_flight() == 0);
    }

    // REQ: CLU-004 (ADR-174, final review round 2, F1) — a caller that drops its read with
    // answers waiting gets every share of them back at once; the call still out keeps its share
    // and the place until its task ends, and nothing is returned twice.
    #[test]
    fn clu_004_shares_come_back_when_the_caller_drops_a_read_with_answers_waiting() {
        let rt = runtime(2);
        let limiter = Limiter::with_budget(8, 100);
        let (live, ran, done, gate) = (count(), count(), count(), Gate::shut());
        let mut calls = quick(20, "quick", &done);
        calls.extend(gate.calls(1, "held", &live, &ran));
        let read = start(&limiter, rt.handle(), calls, Duration::from_secs(60));
        wait_until("the quick calls answered", || {
            done.load(Ordering::SeqCst) == 20
        });
        wait_until("only the held call's task is alive", || {
            rt.metrics().num_alive_tasks() == 1
        });
        assert_eq!(limiter.calls_in_flight(), 21, "20 answers wait, 1 call out");
        assert_eq!(limiter.bytes_held(), 40, "and the 20 answers' bytes");
        drop(read);
        assert_eq!(
            limiter.calls_in_flight(),
            1,
            "the dropped read's answers are gone, and their shares"
        );
        assert_eq!(limiter.bytes_held(), 0, "and their bytes");
        assert_eq!(
            limiter.in_flight(),
            1,
            "the call that is out keeps the place"
        );
        gate.open();
        wait_until("the last task ends", || {
            limiter.calls_in_flight() == 0 && limiter.in_flight() == 0
        });
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(
            limiter.bytes_held(),
            0,
            "the answer that came after the read was dropped is not held"
        );
    }

    // REQ: CLU-004 (ADR-174, final review round 2, F1) — a read that gives up at its deadline with
    // some answers in: the answers it returns give their shares back, the calls that never
    // answered keep theirs until their tasks end, and then everything is back, once.
    #[test]
    fn clu_004_shares_come_back_when_a_read_times_out_with_some_answers_in() {
        let rt = runtime(2);
        let limiter = Limiter::with_budget(8, 100);
        let (live, ran, done, gate) = (count(), count(), count(), Gate::shut());
        let mut calls = quick(5, "quick", &done);
        calls.extend(gate.calls(2, "held", &live, &ran));
        let read = start(&limiter, rt.handle(), calls, Duration::from_millis(100));
        // The five answers are in (sent, not only run: their tasks are over) before the wait
        // starts, so a slow machine can't make them late.
        wait_until("the quick calls answered", || {
            done.load(Ordering::SeqCst) == 5
        });
        wait_until("only the held calls' tasks are alive", || {
            rt.metrics().num_alive_tasks() == 2
        });
        assert_eq!(limiter.bytes_held(), 10, "the five answers' bytes");
        let got = read.wait();
        assert_eq!(got.iter().filter(|(_, r)| r.is_ok()).count(), 5);
        assert!(
            got[5..].iter().all(|(_, r)| r
                .as_ref()
                .is_err_and(|e| e.contains("didn't answer in time"))),
            "{got:?}"
        );
        assert_eq!(
            limiter.calls_in_flight(),
            2,
            "the five answers are consumed; the two calls still out hold theirs"
        );
        assert_eq!(
            limiter.bytes_held(),
            0,
            "the consumed answers' bytes are back"
        );
        gate.open();
        wait_until("the late tasks end", || {
            limiter.calls_in_flight() == 0 && limiter.in_flight() == 0
        });
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(
            limiter.bytes_held(),
            0,
            "the late answers found nobody waiting and are not held"
        );
    }

    // REQ: CLU-004 (ADR-174, final review round 2, F1) — a runtime that is dropped with answers
    // already waiting in their read: the call that was out is dropped with its share, the answers
    // keep theirs until the read is done with them, and then everything is back, once.
    #[test]
    fn clu_004_answers_waiting_when_the_runtime_is_dropped_keep_their_shares_until_the_read_is_done()
     {
        let rt = runtime(2);
        let limiter = Limiter::with_budget(8, 100);
        let (live, ran, done, gate) = (count(), count(), count(), Gate::shut());
        let mut calls = quick(10, "quick", &done);
        calls.extend(gate.calls(1, "held", &live, &ran));
        let read = start(&limiter, rt.handle(), calls, Duration::from_secs(60));
        wait_until("the quick calls answered", || {
            done.load(Ordering::SeqCst) == 10
        });
        wait_until("only the held call's task is alive", || {
            rt.metrics().num_alive_tasks() == 1
        });
        assert_eq!(limiter.bytes_held(), 20, "the ten answers' bytes");
        drop(rt);
        assert_eq!(
            limiter.calls_in_flight(),
            10,
            "the call that was out is dropped with its share; the answers still wait"
        );
        assert_eq!(limiter.bytes_held(), 20, "with their bytes");
        assert_eq!(limiter.in_flight(), 0, "no task is left to hold the place");
        let got = read.wait();
        assert_eq!(got.iter().filter(|(_, r)| r.is_ok()).count(), 10);
        assert!(
            got[10]
                .1
                .as_ref()
                .is_err_and(|e| e.contains("its call was dropped")),
            "{got:?}"
        );
        assert_eq!(limiter.calls_in_flight(), 0);
        assert_eq!(limiter.bytes_held(), 0);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    // REQ: CLU-004 (ADR-174) — tasks queued on a stuck runtime keep their shares and the place,
    // after the caller has given up, and give them back when the runtime runs them and finds
    // nobody waiting (none of the calls is sent). Same pattern as the place under the cap of reads.
    #[test]
    fn clu_004_shares_stay_with_queued_tasks_after_the_caller_gives_up() {
        let rt = runtime(1);
        let limiter = Limiter::with_budget(8, 100);
        let gate = wedge(&rt);
        let (live, ran, door) = (count(), count(), Gate::shut());
        door.open();
        let calls = door.calls(50, "q", &live, &ran);
        let got = start(&limiter, rt.handle(), calls, Duration::from_millis(100)).wait();
        assert_eq!(got.len(), 50);
        assert!(
            got.iter().all(|(_, r)| r
                .as_ref()
                .is_err_and(|e| e.contains("didn't answer in time"))),
            "{:?}",
            got.first()
        );
        // The caller is gone; the tasks are queued behind the wedge and still count.
        assert_eq!(limiter.calls_in_flight(), 50);
        assert_eq!(limiter.in_flight(), 1);
        gate.send(()).unwrap();
        wait_until("the queued tasks end", || {
            limiter.calls_in_flight() == 0 && limiter.in_flight() == 0
        });
        assert_eq!(ran.load(Ordering::SeqCst), 0, "no call was sent late");
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(limiter.bytes_held(), 0, "nothing answered, nothing is held");
    }

    // REQ: CLU-004 (ADR-174) — a runtime that is shutting down drops its tasks without running
    // them: their shares and the place come back, and so does a spawn onto a runtime that is
    // already gone.
    #[test]
    fn clu_004_shares_come_back_when_the_runtime_drops_the_tasks() {
        let rt = runtime(2);
        let limiter = Limiter::with_budget(8, 100);
        let (live, ran, gate) = (count(), count(), Gate::shut());
        let read = start(
            &limiter,
            rt.handle(),
            gate.calls(40, "p", &live, &ran),
            Duration::from_secs(60),
        );
        assert_eq!(limiter.calls_in_flight(), 40);
        let handle = rt.handle().clone();
        drop(rt);
        let got = read.wait();
        assert!(
            got.iter().all(|(_, r)| r
                .as_ref()
                .is_err_and(|e| e.contains("its call was dropped"))),
            "{:?}",
            got.first()
        );
        wait_until("the dropped tasks gave everything back", || {
            limiter.calls_in_flight() == 0 && limiter.in_flight() == 0
        });
        assert_eq!(live.load(Ordering::SeqCst), 0);
        // A read started on the dead runtime: its tasks are dropped as they are spawned.
        let late = start(
            &limiter,
            &handle,
            gate.calls(10, "late", &live, &ran),
            Duration::from_secs(60),
        )
        .wait();
        assert_eq!(late.len(), 10);
        wait_until("a spawn on a dead runtime gave everything back", || {
            limiter.calls_in_flight() == 0 && limiter.in_flight() == 0
        });
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(ran.load(Ordering::SeqCst), 0);
    }

    // REQ: CLU-004 (ADR-174) — the worst case never holds more than the budget. Thirty-two
    // reads of the ceiling are tried (131,072 calls): eight are sent, and the calls that exist,
    // counted by the calls themselves and not by the limiter, are exactly the budget: 32,768,
    // what 32 reads of the old flat cap could hold. With the old reads (32 of 1,024) all
    // 32 are sent, which is the budget again, and a 33rd is refused for want of a place.
    #[test]
    fn clu_004_the_worst_case_never_holds_more_than_the_budget() {
        let rt = runtime(2);
        let long = Duration::from_secs(60);
        // Big reads: the budget is what stops them.
        let limiter = Limiter::new(MAX_WAITS);
        let (live, ran, gate) = (count(), count(), Gate::shut());
        let mut sent = 0;
        let mut held = Vec::new();
        for r in 0..MAX_WAITS {
            let calls = gate.calls(MAX_READ_CALLS, &format!("r{r}-"), &live, &ran);
            let read = start(&limiter, rt.handle(), calls, long);
            if was_sent(&read) {
                sent += 1;
                held.push(read);
            }
            assert!(limiter.calls_in_flight() <= CALL_BUDGET);
            assert!(
                live.load(Ordering::SeqCst) <= CALL_BUDGET,
                "{} calls exist",
                live.load(Ordering::SeqCst)
            );
        }
        assert_eq!(sent, CALL_BUDGET / MAX_READ_CALLS);
        assert_eq!(live.load(Ordering::SeqCst), CALL_BUDGET);
        assert_eq!(limiter.calls_in_flight(), CALL_BUDGET);
        gate.open();
        for read in held {
            assert!(read.wait().iter().all(|(_, r)| r.is_ok()));
        }
        wait_until("everything is given back", || {
            limiter.calls_in_flight() == 0 && limiter.in_flight() == 0
        });
        assert_eq!(live.load(Ordering::SeqCst), 0);
        // Small reads: the places are what stops them, at the same total.
        let limiter = Limiter::new(MAX_WAITS);
        let gate = Gate::shut();
        let mut held = Vec::new();
        for r in 0..MAX_WAITS {
            let calls = gate.calls(1024, &format!("s{r}-"), &live, &ran);
            let read = start(&limiter, rt.handle(), calls, long);
            assert!(was_sent(&read), "read {r}");
            held.push(read);
        }
        assert_eq!(live.load(Ordering::SeqCst), CALL_BUDGET);
        assert_eq!(limiter.calls_in_flight(), CALL_BUDGET);
        let more = start(
            &limiter,
            rt.handle(),
            gate.calls(1, "more", &live, &ran),
            long,
        )
        .wait();
        assert!(refused_for(&more, "reads are already waiting"), "{more:?}");
        assert_eq!(live.load(Ordering::SeqCst), CALL_BUDGET);
        gate.open();
        for read in held {
            assert!(read.wait().iter().all(|(_, r)| r.is_ok()));
        }
        wait_until("everything is given back", || {
            limiter.calls_in_flight() == 0 && limiter.in_flight() == 0
        });
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    // REQ: CLU-004 (ADR-174) — from many threads at once, reads of every size never get past
    // the budget or the places; a refused read leaves nothing behind, and what was sent is exactly
    // what the limiter says is in flight. A thread watches the counts all the while.
    #[test]
    fn clu_004_reads_started_from_many_threads_never_pass_the_budget() {
        const SIZES: [usize; 6] = [1, 50, 1_000, 4_096, 4_096, 3_000];
        let rt = runtime(2);
        let limiter = Arc::new(Limiter::new(MAX_WAITS));
        let (live, ran, gate) = (count(), count(), Arc::new(Gate::shut()));
        let watching = Arc::new(AtomicBool::new(true));
        // A failed assertion below must not leave the watcher spinning.
        let _stop = StopOnDrop(Arc::clone(&watching));
        let watcher = {
            let (limiter, watching) = (Arc::clone(&limiter), Arc::clone(&watching));
            std::thread::spawn(move || {
                let mut worst = (0, 0);
                while watching.load(Ordering::SeqCst) {
                    let (calls, reads) = (limiter.calls_in_flight(), limiter.in_flight());
                    worst = (worst.0.max(calls), worst.1.max(reads));
                    std::thread::yield_now();
                }
                worst
            })
        };
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let (limiter, gate, live, ran) = (
                    Arc::clone(&limiter),
                    Arc::clone(&gate),
                    Arc::clone(&live),
                    Arc::clone(&ran),
                );
                let handle = rt.handle().clone();
                std::thread::spawn(move || {
                    let (mut held, mut accepted) = (Vec::new(), 0);
                    for i in 0..30 {
                        let n = SIZES[(t * 7 + i * 5) % SIZES.len()];
                        let calls = gate.calls(n, &format!("t{t}-{i}-"), &live, &ran);
                        let read = start(&limiter, &handle, calls, Duration::from_secs(60));
                        if was_sent(&read) {
                            accepted += n;
                            held.push(read);
                        }
                        assert!(limiter.calls_in_flight() <= CALL_BUDGET);
                    }
                    (held, accepted)
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let accepted: usize = results.iter().map(|(_, n)| n).sum();
        let reads: usize = results.iter().map(|(h, _)| h.len()).sum();
        assert!(accepted <= CALL_BUDGET && reads <= MAX_WAITS);
        assert_eq!(limiter.calls_in_flight(), accepted, "what was sent is held");
        assert_eq!(limiter.in_flight(), reads);
        assert_eq!(
            live.load(Ordering::SeqCst),
            accepted,
            "the calls that exist are the ones that were sent"
        );
        // A read that was refused is not lost to the budget: it is the room that ran out.
        assert!(accepted > CALL_BUDGET - MAX_READ_CALLS || reads == MAX_WAITS);
        gate.open();
        for (held, _) in results {
            for read in held {
                assert!(read.wait().iter().all(|(_, r)| r.is_ok()));
            }
        }
        wait_until("everything is given back", || {
            limiter.calls_in_flight() == 0 && limiter.in_flight() == 0
        });
        watching.store(false, Ordering::SeqCst);
        let (calls, places) = watcher.join().unwrap();
        assert!(calls <= CALL_BUDGET, "{calls} calls in flight");
        assert!(places <= MAX_WAITS, "{places} reads waiting");
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    // REQ: CLU-004 (final review, F2) — a refused read is said out loud (a warning) the first
    // time, then at most once a minute, with how many were refused for each reason since the
    // last line. The clock is the test's own.
    #[test]
    fn clu_004_refused_reads_are_logged_once_a_minute_with_their_count() {
        let log = RefusalLog::default();
        let tally = |full, spent, too_big| {
            Some(Tally {
                full,
                spent,
                too_big,
                bytes: 0,
            })
        };
        // The first one is said at once.
        assert_eq!(log.note(Refused::Full, 5), tally(1, 0, 0));
        // Then a minute of counting and no line.
        assert_eq!(log.note(Refused::Full, 6), None);
        assert_eq!(log.note(Refused::TooBig, 30_000), None);
        assert_eq!(log.note(Refused::Spent, 40_000), None);
        assert_eq!(log.note(Refused::Full, 59_004), None);
        // A minute after the last line, one line with what came in since (and this one).
        assert_eq!(log.note(Refused::TooBig, 60_005), tally(2, 1, 2));
        assert_eq!(log.pending(), Tally::default(), "a line resets the count");
        // And quiet for another minute.
        assert_eq!(log.note(Refused::Full, 60_006), None);
        assert_eq!(log.note(Refused::Full, 120_004), None);
        assert_eq!(log.note(Refused::Spent, 120_005), tally(2, 1, 0));
    }

    // REQ: CLU-004 (final review, F2) — however many threads refuse at once, no refusal is lost
    // or counted twice: what the lines said, and what is still waiting for the next line, add up
    // to every refusal.
    #[test]
    fn clu_004_refusals_are_counted_exactly_under_concurrency() {
        let log = Arc::new(RefusalLog::default());
        let (threads, each) = (8_u64, 2_000_u64);
        let said: u64 = (0..threads)
            .map(|t| {
                let log = Arc::clone(&log);
                std::thread::spawn(move || {
                    let mut said = 0;
                    for i in 0..each {
                        // A virtual second per refusal, so a line is due about every 60th.
                        let why = match (t + i) % 3 {
                            0 => Refused::TooBig,
                            1 => Refused::Spent,
                            _ => Refused::Full,
                        };
                        if let Some(n) = log.note(why, i * 1000) {
                            said += n.full + n.spent + n.too_big;
                        }
                    }
                    said
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .sum();
        let waiting = log.pending();
        assert_eq!(
            said + waiting.full + waiting.spent + waiting.too_big,
            threads * each
        );
    }

    // REQ: CLU-004 (final review, F2) — a read that `start` does not send is counted for the
    // line, for each of the three reasons.
    #[test]
    fn clu_004_a_refused_read_is_counted_for_the_log() {
        let rt = runtime(2);
        // One place, and room for two calls.
        let limiter = Limiter::with_budget(1, 2);
        // The first refusal is the one that is said at once; take it, so the next are only counted.
        let _ = limiter.log().note(Refused::Full, 0);
        let (open, shut) = tokio::sync::oneshot::channel::<()>();
        let held: Vec<(String, Call)> = vec![(
            "held".into(),
            Box::pin(async move {
                let _ = shut.await;
                Ok(b"H".to_vec())
            }),
        )];
        let first = start(&limiter, rt.handle(), held, Duration::from_secs(30));
        let sent = count();
        // Over the cap of reads.
        let _ = start(
            &limiter,
            rt.handle(),
            vec![("late".into(), counting(&sent))],
            Duration::from_secs(30),
        )
        .wait();
        assert_eq!(
            limiter.log().pending(),
            Tally {
                full: 1,
                spent: 0,
                too_big: 0,
                bytes: 0
            }
        );
        open.send(()).unwrap();
        assert_eq!(first.wait()[0].1, Ok(b"H".to_vec()));
        wait_until("the place is given back", || limiter.in_flight() == 0);
        // Over the budget of calls: three calls, with room for two.
        let three: Vec<(String, Call)> =
            (0..3).map(|i| (format!("q{i}"), counting(&sent))).collect();
        let _ = start(&limiter, rt.handle(), three, Duration::from_secs(30)).wait();
        assert_eq!(
            limiter.log().pending(),
            Tally {
                full: 1,
                spent: 1,
                too_big: 0,
                bytes: 0
            }
        );
        // Over the ceiling on the calls of a read.
        let calls: Vec<(String, Call)> = (0..=MAX_READ_CALLS)
            .map(|i| (format!("p{i}"), counting(&sent)))
            .collect();
        let _ = start(&limiter, rt.handle(), calls, Duration::from_secs(30)).wait();
        assert_eq!(
            limiter.log().pending(),
            Tally {
                full: 1,
                spent: 1,
                too_big: 1,
                bytes: 0
            }
        );
        assert_eq!(sent.load(Ordering::SeqCst), 0);
    }

    // REQ: CLU-004 (ADR-174) — any calling context: from a current-thread runtime's own thread
    // (nothing else to run the call) the wait times out and returns; it neither panics nor
    // hangs. Before: a deadlock.
    #[test]
    fn clu_004_the_bridge_returns_from_a_current_thread_runtime() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let limiter = Limiter::new(8);
        let got = rt.block_on(async {
            let calls: Vec<(String, Call)> = vec![("peer".into(), answer("never run"))];
            start(
                &limiter,
                &tokio::runtime::Handle::current(),
                calls,
                Duration::from_millis(50),
            )
            .wait()
        });
        assert!(
            got[0]
                .1
                .as_ref()
                .unwrap_err()
                .contains("didn't answer in time"),
            "{got:?}"
        );
    }

    // ---- bytes (rule 4) ----------------------------------------------------------------------

    /// Calls that answer at once with `sizes[i]` bytes each, counting each one that has.
    fn sized(sizes: &[usize], tag: &str, done: &Arc<AtomicUsize>) -> Vec<(String, Call)> {
        sizes
            .iter()
            .enumerate()
            .map(|(i, &n)| {
                let done = Arc::clone(done);
                let call: Call = Box::pin(async move {
                    done.fetch_add(1, Ordering::SeqCst);
                    Ok(vec![b'x'; n])
                });
                (format!("{tag}{i}"), call)
            })
            .collect()
    }

    /// A call that waits at `gate`, then answers `n` bytes.
    fn gated(gate: &Gate, n: usize) -> Call {
        let mut door = gate.0.subscribe();
        Box::pin(async move {
            let _ = door.wait_for(|open| *open).await;
            Ok(vec![b'y'; n])
        })
    }

    /// Whether a result is the "wasn't kept" of an answer a cap on bytes dropped.
    fn not_kept(r: &Answer) -> bool {
        r.as_ref().is_err_and(|e| e.contains("wasn't kept"))
    }

    // REQ: CLU-004 (ADR-174) — an answer that would take its read past the read's cap on bytes is
    // dropped as it comes in and its call is "wasn't kept" (which `gather` lists as a node that
    // didn't answer); the read's other answers are kept, whole and in order; the bytes held are
    // only what was kept, until the read is done; and the read is counted once. Before: every
    // answer was kept, however big. Caps: 100 bytes a read, 1,000 in all.
    #[test]
    fn clu_004_an_answer_over_the_read_cap_is_dropped_and_the_rest_are_kept() {
        let rt = runtime(2);
        let limiter = Limiter::with_caps(8, 100, 1_000, 100);
        let _ = limiter.log().note(Refused::Full, 0); // so the next refusals are only counted
        let (live, ran, done, gate) = (count(), count(), count(), Gate::shut());
        // 40 and 40 fit; 150 is over the read's cap on its own, whichever comes first.
        let mut calls = sized(&[40, 150, 40], "p", &done);
        calls.extend(gate.calls(1, "held", &live, &ran));
        let read = start(&limiter, rt.handle(), calls, Duration::from_secs(60));
        wait_until("the three answers are in", || {
            done.load(Ordering::SeqCst) == 3
        });
        wait_until("only the held call's task is alive", || {
            rt.metrics().num_alive_tasks() == 1
        });
        assert_eq!(limiter.bytes_held(), 80, "only what was kept is held");
        assert_eq!(
            limiter.calls_in_flight(),
            4,
            "the dropped answer's call counts until the read is done, as a timed-out one would"
        );
        gate.open();
        let got = read.wait();
        assert_eq!(got.len(), 4);
        assert_eq!(got[0], ("p0".to_owned(), Ok(vec![b'x'; 40])));
        assert!(not_kept(&got[1].1), "{:?}", got[1]);
        assert!(
            got[1]
                .1
                .as_ref()
                .is_err_and(|e| e.starts_with("p1 wasn't kept")),
            "names its node: {:?}",
            got[1]
        );
        assert_eq!(got[2], ("p2".to_owned(), Ok(vec![b'x'; 40])));
        assert_eq!(got[3], ("held0".to_owned(), Ok(b"ok".to_vec())));
        assert_eq!(
            limiter.bytes_held(),
            0,
            "the read is done: its bytes are back"
        );
        assert_eq!(limiter.calls_in_flight(), 0);
        assert_eq!(
            limiter.log().pending(),
            Tally {
                bytes: 1,
                ..Tally::default()
            },
            "the read is counted once"
        );
        wait_until("the place is back", || limiter.in_flight() == 0);
    }

    // REQ: CLU-004 (ADR-174) — two reads that together would hold more bytes than all reads may:
    // the first keeps every answer, the second keeps what fits in the room that is left and loses
    // only the rest. Caps: 100 bytes in all, 100 a read.
    #[test]
    fn clu_004_two_reads_over_the_held_cap_the_second_loses_only_the_excess() {
        let rt = runtime(2);
        let limiter = Limiter::with_caps(8, 100, 100, 100);
        let _ = limiter.log().note(Refused::Full, 0); // so the next refusals are only counted
        let (live, ran, done, gate) = (count(), count(), count(), Gate::shut());
        let long = Duration::from_secs(60);
        // The first: 90 bytes of answers in, and a call still out, so it holds them.
        let mut calls = sized(&[30, 30, 30], "a", &done);
        calls.extend(gate.calls(1, "a-held", &live, &ran));
        let first = start(&limiter, rt.handle(), calls, long);
        wait_until("the first's answers are in", || {
            done.load(Ordering::SeqCst) == 3
        });
        wait_until("only the first's held call is alive", || {
            rt.metrics().num_alive_tasks() == 1
        });
        assert_eq!(limiter.bytes_held(), 90);
        // The second: 5 and 5 fit in the 10 bytes left, 20 doesn't, in whatever order they come.
        let second = start(&limiter, rt.handle(), sized(&[5, 20, 5], "b", &done), long).wait();
        assert_eq!(second[0], ("b0".to_owned(), Ok(vec![b'x'; 5])));
        assert!(not_kept(&second[1].1), "{second:?}");
        assert_eq!(second[2], ("b2".to_owned(), Ok(vec![b'x'; 5])));
        assert_eq!(
            limiter.bytes_held(),
            90,
            "the second is done and gave its 10 back; the first still holds its 90"
        );
        // The first lost nothing: its last answer comes into the room the second left.
        gate.open();
        let got = first.wait();
        assert!(got.iter().all(|(_, r)| r.is_ok()), "{got:?}");
        assert_eq!(limiter.bytes_held(), 0);
        assert_eq!(limiter.log().pending().bytes, 1, "the second, once");
        wait_until("every place is back", || limiter.in_flight() == 0);
    }

    // REQ: CLU-004 (ADR-174) — an answer that everyone's cap turns away takes nothing from its own
    // read either: the read's total it had added is given back at once, so a later answer of the
    // same read still has the read's whole room. Caps: 100 bytes in all, 40 a read.
    #[test]
    fn clu_004_an_answer_turned_away_by_the_held_cap_takes_nothing_from_its_read() {
        let rt = runtime(2);
        let limiter = Limiter::with_caps(8, 100, 100, 40);
        let (live, ran, done) = (count(), count(), count());
        let (hold_a, hold_b) = (Gate::shut(), Gate::shut());
        let long = Duration::from_secs(60);
        // Two reads hold 35 bytes each of everyone's 100, so 30 are left.
        let mut held = Vec::new();
        for r in 0..2 {
            let mut calls = sized(&[35], &format!("a{r}-"), &done);
            calls.extend(hold_a.calls(1, &format!("a{r}-held"), &live, &ran));
            held.push(start(&limiter, rt.handle(), calls, long));
        }
        wait_until("their answers are in", || {
            done.load(Ordering::SeqCst) == 2 && rt.metrics().num_alive_tasks() == 2
        });
        assert_eq!(limiter.bytes_held(), 70);
        // The second read: 35 now (over the 30 left in all, within its own 40), 30 later.
        let calls: Vec<(String, Call)> = sized(&[35], "b", &done)
            .into_iter()
            .chain([("b-late".to_owned(), gated(&hold_b, 30))])
            .collect();
        let second = start(&limiter, rt.handle(), calls, long);
        wait_until("its first answer came and went", || {
            done.load(Ordering::SeqCst) == 3 && rt.metrics().num_alive_tasks() == 3
        });
        assert_eq!(limiter.bytes_held(), 70, "turned away: nothing was taken");
        // The first reads finish, and the second's late answer comes: 30 fits its own 40 only if
        // the 35 that was turned away took nothing from it.
        hold_a.open();
        for read in held {
            assert!(read.wait().iter().all(|(_, r)| r.is_ok()));
        }
        hold_b.open();
        let got = second.wait();
        assert!(not_kept(&got[0].1), "{got:?}");
        assert_eq!(got[1], ("b-late".to_owned(), Ok(vec![b'y'; 30])));
        assert_eq!(limiter.bytes_held(), 0);
    }

    // REQ: CLU-004 (ADR-174) — from many threads at once, reads whose answers are of every size
    // never get the bytes held past the cap for all reads, nor one read's past its own, nor the
    // calls past the budget: a thread watches the counts all the while. Every read keeps a call
    // out until all of them have started, so they all hold their answers at once, and the answers
    // offered are many times the cap; what the reads kept is exactly what was counted as held, an
    // answer is kept whole or not at all, and everything comes back. (Long: one scenario, start to
    // end.)
    #[test]
    #[allow(clippy::too_many_lines)]
    fn clu_004_reads_from_many_threads_never_pass_the_caps_on_bytes() {
        const HELD: usize = 64 * 1024;
        const READ: usize = 16 * 1024;
        const LARGEST: usize = 3_000;
        let rt = runtime(2);
        let limiter = Arc::new(Limiter::with_caps(MAX_WAITS, CALL_BUDGET, HELD, READ));
        let (live, ran, done, gate) = (count(), count(), count(), Arc::new(Gate::shut()));
        let watching = Arc::new(AtomicBool::new(true));
        // A failed assertion below must not leave the watcher spinning.
        let _stop = StopOnDrop(Arc::clone(&watching));
        let watcher = {
            let (limiter, watching) = (Arc::clone(&limiter), Arc::clone(&watching));
            std::thread::spawn(move || {
                let mut worst = (0, 0);
                while watching.load(Ordering::SeqCst) {
                    let (bytes, calls) = (limiter.bytes_held(), limiter.calls_in_flight());
                    worst = (worst.0.max(bytes), worst.1.max(calls));
                    std::thread::yield_now();
                }
                worst
            })
        };
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let (limiter, gate, live, ran, done) = (
                    Arc::clone(&limiter),
                    Arc::clone(&gate),
                    Arc::clone(&live),
                    Arc::clone(&ran),
                    Arc::clone(&done),
                );
                let handle = rt.handle().clone();
                std::thread::spawn(move || {
                    let mut reads = Vec::new();
                    // 8 threads of 4 reads: the 32 places, every read sent.
                    for i in 0..4 {
                        let sizes: Vec<usize> = (0..20)
                            .map(|k| 1 + (t * 7_919 + i * 104_729 + k * 1_299_709) % LARGEST)
                            .collect();
                        let tag = format!("t{t}-{i}-");
                        let mut calls = sized(&sizes, &tag, &done);
                        calls.extend(gate.calls(1, &format!("{tag}held"), &live, &ran));
                        let read = start(&limiter, &handle, calls, Duration::from_secs(60));
                        assert!(was_sent(&read), "read {tag}");
                        reads.push((read, sizes));
                    }
                    reads
                })
            })
            .collect();
        let reads: Vec<_> = threads
            .into_iter()
            .flat_map(|t| t.join().unwrap())
            .collect();
        let offered: usize = reads.iter().flat_map(|(_, s)| s).sum();
        let quick: usize = reads.iter().map(|(_, s)| s.len()).sum();
        wait_until("every quick answer is in", || {
            done.load(Ordering::SeqCst) == quick
        });
        wait_until("only the held calls' tasks are alive", || {
            rt.metrics().num_alive_tasks() == reads.len()
        });
        let held = usize::try_from(limiter.bytes_held()).unwrap();
        assert!(
            offered > 8 * HELD,
            "the answers offered ({offered}) dwarf the cap"
        );
        assert!(held <= HELD, "{held} bytes held");
        assert!(
            held > HELD - LARGEST,
            "everyone's cap was what turned answers away: {held} bytes held"
        );
        gate.open();
        let mut kept_all = 0;
        for (read, sizes) in reads {
            let got = read.wait();
            let mut kept = 0;
            for ((peer, r), n) in got.iter().zip(&sizes) {
                match r {
                    Ok(body) => {
                        assert_eq!(body.len(), *n, "{peer}: an answer is kept whole");
                        kept += n;
                    }
                    Err(e) => assert!(e.contains("wasn't kept"), "{peer}: {e}"),
                }
            }
            assert!(
                kept <= READ,
                "a read kept {kept} bytes, more than its {READ}"
            );
            kept_all += kept;
        }
        assert_eq!(
            kept_all, held,
            "what the reads kept is what was counted as held"
        );
        wait_until("everything is given back", || {
            limiter.calls_in_flight() == 0 && limiter.in_flight() == 0 && limiter.bytes_held() == 0
        });
        watching.store(false, Ordering::SeqCst);
        let (bytes, calls) = watcher.join().unwrap();
        assert!(
            bytes <= u64::try_from(HELD).unwrap(),
            "{bytes} bytes held at once"
        );
        assert!(calls <= CALL_BUDGET, "{calls} calls counted at once");
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    // REQ: CLU-004 (ADR-174) — a pin of the constants, not a test of what the bridge does: the
    // caps are the ones the docs and the metric's help give, two reads at a read's fit everyone's,
    // the dashboard's longest range on a cluster of 5 nodes (measured: 17,683,487 bytes of answers
    // a read on home-network buckets) fits a read's 1.18 times (the 11 below is ten times that,
    // rounded down), and the ADR's arithmetic for a node with no data of its own (42 MiB, plus 7.3
    // times the peers' answers, as measured on two real nodes) gives under three quarters of the
    // Pi's 256 MiB. This node's own part and reads merging at once are not in it.
    #[test]
    fn clu_004_the_caps_on_bytes_are_the_documented_ones() {
        assert_eq!(READ_BYTES, 20 * 1024 * 1024);
        assert_eq!(HELD_BYTES, 40 * 1024 * 1024);
        assert_eq!(HELD_BYTES / READ_BYTES, 2, "two reads at their cap");
        let dashboard_48h_of_minutes_5_nodes: usize = 17_683_487;
        assert_eq!(READ_BYTES * 10 / dashboard_48h_of_minutes_5_nodes, 11);
        let (mib, pi) = (1024 * 1024, 256 * 1024 * 1024);
        let at_the_cap = 42 * mib + READ_BYTES * 73 / 10;
        assert_eq!(
            at_the_cap * 4 / pi,
            2,
            "under three quarters of the Pi's unit, over half"
        );
    }
}
