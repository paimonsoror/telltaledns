//! REQ: CLU-002, CLU-004, OPS-012 (ADR-174, GitHub issue #7) — how synchronous code waits for the
//! cluster channel.
//!
//! The `Backend` trait is synchronous, so a federated read starts its RPCs on the runtime and
//! waits for the answers on a thread of its own: a blocking-pool thread, where the API runs its
//! backend calls. Three rules:
//!
//! 1. The wait never needs the runtime to end it. It is a `recv_timeout` on a `std` channel,
//!    for the RPC's own timeout plus a short grace. A runtime that can't run the tasks (every
//!    worker parked, or this very call made on a worker) costs the read its deadline, never the
//!    node its life. Before, the wait was a scoped thread running `Handle::block_on` and a
//!    `join()` with no bound: with every worker parked in one, nothing could write an RPC, read
//!    its answer or fire its timer, and the node stopped answering for good.
//! 2. Few waits at once. Each holds a thread (of the blocking pool's 512) for up to its deadline,
//!    so a slow or dead primary can't pile them up. Past [`MAX_WAITS`] a read is told "didn't
//!    answer" without being sent.
//! 3. Few calls in a read. A read is one task per call and holds one place under rule 2 for all
//!    of them, so the places bound reads, not tasks: a read of more than [`MAX_CALLS`] calls is
//!    not sent either (every call: "wasn't asked"). A read for the nodes' time buckets is one
//!    call per node and window of time (`telltale_api::federation::timeseries_chunks`, which
//!    bounds that on its own, first).
//!
//! A read that is refused is counted and said in the log, as a warning at most once a minute
//! ([`Limiter::refused`]).
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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, mpsc};
use std::time::{Duration, Instant};

/// How long past a call's own timeout the caller keeps waiting for the runtime to run it.
pub(super) const GRACE: Duration = Duration::from_millis(250);

/// Federated waits in flight at once on this node (each is a read: all of its peers together).
/// A healthy cluster's reads end in milliseconds; this only bounds a slow or dead peer's cost.
const MAX_WAITS: usize = 32;

/// The most calls one read may have. A read is one call to each peer, or, for a range of time,
/// one to each peer for each window of it (the longest range any step documents is 87 windows,
/// and `telltale_api::federation::TIMESERIES_MAX_WINDOWS` caps one at 256): this lets a cluster
/// of 11 peers ask for all of history by the day, and 23 for 7 days of minutes, and no more.
/// Over it the whole read is not sent: each of its calls is a task, and the places of
/// [`MAX_WAITS`] count reads.
pub(super) const MAX_CALLS: usize = 1024;

/// The cap every federated read of this process shares.
pub(super) static WAITS: LazyLock<Limiter> = LazyLock::new(|| Limiter::new(MAX_WAITS));

/// How often, at most, refused reads are said in the log.
const SAY_EVERY_MS: u64 = 60_000;

/// Why a read was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// [`MAX_WAITS`] reads were already waiting.
    Full,
    /// The read asked for too much at once: over [`MAX_CALLS`] calls, or a range of time of too
    /// many windows.
    TooBig,
}

/// How many reads were refused for each reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Tally {
    full: u64,
    too_big: u64,
}

/// What was refused since the last line said so, and when that was.
#[derive(Debug, Default)]
struct RefusalLog {
    /// The clock (milliseconds, any origin) of the last line, plus one: zero is "never".
    last: AtomicU64,
    full: AtomicU64,
    too_big: AtomicU64,
}

impl RefusalLog {
    /// Counts a refused read. Returns what to say when a line is due: the first time, then once
    /// a minute at most, with what was counted since the last line (which this resets). Of any
    /// number of threads that find a line due, one gets it, and a refusal is in exactly one line.
    fn note(&self, why: Refused, now_ms: u64) -> Option<Tally> {
        match why {
            Refused::Full => self.full.fetch_add(1, Ordering::AcqRel),
            Refused::TooBig => self.too_big.fetch_add(1, Ordering::AcqRel),
        };
        let stamp = now_ms.saturating_add(1);
        let last = self.last.load(Ordering::Acquire);
        if last != 0 && stamp.saturating_sub(last) < SAY_EVERY_MS {
            return None;
        }
        self.last
            .compare_exchange(last, stamp, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(Tally {
            full: self.full.swap(0, Ordering::AcqRel),
            too_big: self.too_big.swap(0, Ordering::AcqRel),
        })
    }

    /// What is counted and not yet said.
    #[cfg(test)]
    fn pending(&self) -> Tally {
        Tally {
            full: self.full.load(Ordering::Acquire),
            too_big: self.too_big.load(Ordering::Acquire),
        }
    }
}

/// A count of federated waits in flight, with a cap.
#[derive(Debug)]
pub(super) struct Limiter {
    in_flight: Arc<AtomicUsize>,
    max: usize,
    log: RefusalLog,
    /// The refusal log's clock: monotonic, from when this was made.
    since: Instant,
}

/// One wait's place under the cap. It is given back when the wait's last task ends (not when
/// the caller stops waiting: a task still queued on a stuck runtime still counts).
#[derive(Debug)]
struct Permit(Arc<AtomicUsize>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Limiter {
    pub(super) fn new(max: usize) -> Self {
        Self {
            in_flight: Arc::new(AtomicUsize::new(0)),
            max,
            log: RefusalLog::default(),
            since: Instant::now(),
        }
    }

    /// REQ: CLU-004 (final review, F2) — counts a read that was not sent, and says so in the log
    /// as a warning: the first time, then at most once a minute, with how many were refused
    /// since the last line. A silent refusal showed as healthy peers in `missingNodes`.
    pub(super) fn refused(&self, why: Refused) {
        let now = u64::try_from(self.since.elapsed().as_millis()).unwrap_or(u64::MAX);
        if let Some(n) = self.log.note(why, now) {
            tracing::warn!(
                "federated reads are being refused and were not sent: {} because {} reads were \
                 already waiting (a slow or silent node), {} because they asked for too much at \
                 once (over {MAX_CALLS} calls, or over {} windows of time a node); counted since \
                 the last line of this kind, at most one a minute. The nodes they were for show \
                 as not answering",
                n.full,
                self.max,
                n.too_big,
                telltale_api::federation::TIMESERIES_MAX_WINDOWS,
            );
        }
    }

    fn acquire(&self) -> Option<Permit> {
        self.in_flight
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.max).then_some(n + 1)
            })
            .ok()
            .map(|_| Permit(Arc::clone(&self.in_flight)))
    }

    /// Waits in flight now.
    #[cfg(test)]
    fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }
}

/// One call's result: the peer's answer, or why there is none.
type Answer = Result<Vec<u8>, String>;

/// Calls started on the runtime, to be waited for on the calling thread.
#[derive(Debug)]
pub(super) struct Pending {
    peers: Vec<String>,
    /// What is in so far, by call.
    results: Vec<Option<Answer>>,
    rx: Option<mpsc::Receiver<(usize, Answer)>>,
    /// When the caller stops waiting.
    until: Instant,
    /// Set when the caller stops waiting: a call still queued then isn't sent.
    gave_up: Arc<AtomicBool>,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.gave_up.store(true, Ordering::Release);
    }
}

/// Starts each of `calls` (a peer, and its RPC) as a task on `rt` and returns at once. `timeout`
/// is the RPCs' own; the wait ends [`GRACE`] after it at the latest. Over the cap of reads, or
/// with more than [`MAX_CALLS`] calls, nothing is started, and every call's result is "wasn't
/// asked".
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
    let pending = |peers, results, rx| Pending {
        peers,
        results,
        rx,
        until: Instant::now() + timeout + GRACE,
        gave_up: Arc::new(AtomicBool::new(false)),
    };
    if futures.is_empty() {
        return pending(peers, results, None);
    }
    // REQ: CLU-004, CLU-002 (final review, F1) — the places below count reads, not the tasks
    // each makes: a read of this many calls is not sent, and takes no place.
    if futures.len() > MAX_CALLS {
        limiter.refused(Refused::TooBig);
        drop(futures);
        for (r, peer) in results.iter_mut().zip(&peers) {
            *r = Some(Err(format!(
                "{peer} wasn't asked: the read has too many calls at once"
            )));
        }
        return pending(peers, results, None);
    }
    let Some(permit) = limiter.acquire() else {
        limiter.refused(Refused::Full);
        for (r, peer) in results.iter_mut().zip(&peers) {
            *r = Some(Err(format!(
                "{peer} wasn't asked: too many cluster reads are already waiting"
            )));
        }
        return pending(peers, results, None);
    };
    let permit = Arc::new(permit);
    let (tx, rx) = mpsc::channel();
    let started = pending(peers, results, Some(rx));
    for (i, call) in futures.into_iter().enumerate() {
        let (tx, permit, gave_up) = (
            tx.clone(),
            Arc::clone(&permit),
            Arc::clone(&started.gave_up),
        );
        drop(rt.spawn(async move {
            let _place = permit;
            if gave_up.load(Ordering::Acquire) {
                return;
            }
            let _ = tx.send((i, call.await));
        }));
    }
    started
}

impl Pending {
    /// Waits for every call, or until the deadline: one entry per call, in the order given, with
    /// the answer or why there is none (`didn't answer in time` for a call the runtime never
    /// finished). Blocks the calling thread only: it needs nothing from the runtime to wake.
    pub(super) fn wait(mut self) -> Vec<(String, Answer)> {
        let mut missing = self.results.iter().filter(|r| r.is_none()).count();
        let mut why = "didn't answer in time";
        if let Some(rx) = self.rx.take() {
            while missing > 0 {
                let left = self.until.saturating_duration_since(Instant::now());
                match rx.recv_timeout(left) {
                    Ok((i, r)) => self.put(i, r, &mut missing),
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        why = "wasn't answered: its call was dropped";
                        break;
                    }
                }
            }
            // What came in as the deadline passed.
            while let Ok((i, r)) = rx.try_recv() {
                self.put(i, r, &mut missing);
            }
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

    fn put(&mut self, i: usize, r: Answer, missing: &mut usize) {
        if let Some(slot) = self.results.get_mut(i)
            && slot.is_none()
        {
            *slot = Some(r);
            *missing -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
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

    // REQ: CLU-004, CLU-002 (ADR-174, final review F1) — a read of more than 1024 calls is not
    // sent at all: none of its calls is run, none takes a place under the cap, and every call is
    // told "wasn't asked". Before: one task per call, however many (a viewer's request for a long
    // range of seconds made millions), under one place.
    #[test]
    fn clu_004_a_read_over_the_call_cap_is_not_sent() {
        let rt = runtime(2);
        let limiter = Limiter::new(8);
        let sent = Arc::new(AtomicUsize::new(0));
        assert_eq!(MAX_CALLS, 1024, "the number the ADR and the docs give");
        let calls: Vec<(String, Call)> = (0..=MAX_CALLS)
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
            MAX_CALLS + 1,
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
        assert_eq!(sent.load(Ordering::SeqCst), 0, "no call was run");
    }

    // REQ: CLU-004, CLU-002 (final review, F1) — the cap is on what a read may ask, not a cut
    // in what is sent: a read of exactly 1024 calls (a 12-node cluster's whole history by the
    // day) is sent in full and answered in order.
    #[test]
    fn clu_004_a_read_at_the_call_cap_is_sent_in_full() {
        let rt = runtime(2);
        let limiter = Limiter::new(8);
        let sent = Arc::new(AtomicUsize::new(0));
        let calls: Vec<(String, Call)> = (0..MAX_CALLS)
            .map(|i| (format!("p{i}"), counting(&sent)))
            .collect();
        let got = start(&limiter, rt.handle(), calls, Duration::from_secs(30)).wait();
        assert_eq!(got.len(), MAX_CALLS);
        assert!(
            got.iter()
                .enumerate()
                .all(|(i, (peer, r))| { *peer == format!("p{i}") && *r == Ok(b"ok".to_vec()) }),
            "{:?}",
            got.iter().find(|(_, r)| r.is_err())
        );
        assert_eq!(sent.load(Ordering::SeqCst), MAX_CALLS);
        wait_until("every place is given back", || limiter.in_flight() == 0);
    }

    // REQ: CLU-004 (final review, F2) — a refused read is said out loud (a warning) the first
    // time, then at most once a minute, with how many were refused for each reason since the
    // last line. The clock is the test's own.
    #[test]
    fn clu_004_refused_reads_are_logged_once_a_minute_with_their_count() {
        let log = RefusalLog::default();
        let tally = |full, too_big| Some(Tally { full, too_big });
        // The first one is said at once.
        assert_eq!(log.note(Refused::Full, 5), tally(1, 0));
        // Then a minute of counting and no line.
        assert_eq!(log.note(Refused::Full, 6), None);
        assert_eq!(log.note(Refused::TooBig, 30_000), None);
        assert_eq!(log.note(Refused::Full, 59_004), None);
        // A minute after the last line, one line with what came in since (and this one).
        assert_eq!(log.note(Refused::TooBig, 60_005), tally(2, 2));
        assert_eq!(log.pending(), Tally::default(), "a line resets the count");
        // And quiet for another minute.
        assert_eq!(log.note(Refused::Full, 60_006), None);
        assert_eq!(log.note(Refused::Full, 120_004), None);
        assert_eq!(log.note(Refused::Full, 120_005), tally(3, 0));
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
                        let why = if (t + i) % 3 == 0 {
                            Refused::TooBig
                        } else {
                            Refused::Full
                        };
                        if let Some(n) = log.note(why, i * 1000) {
                            said += n.full + n.too_big;
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
        assert_eq!(said + waiting.full + waiting.too_big, threads * each);
    }

    // REQ: CLU-004 (final review, F2) — a read that `start` does not send is counted for the
    // line, for either reason.
    #[test]
    fn clu_004_a_refused_read_is_counted_for_the_log() {
        let rt = runtime(2);
        let limiter = Limiter::new(1);
        // The first refusal is the one that is said at once; take it, so the next are only counted.
        let _ = limiter.log.note(Refused::Full, 0);
        let (open, shut) = tokio::sync::oneshot::channel::<()>();
        let held: Vec<(String, Call)> = vec![(
            "held".into(),
            Box::pin(async move {
                let _ = shut.await;
                Ok(b"H".to_vec())
            }),
        )];
        let first = start(&limiter, rt.handle(), held, Duration::from_secs(30));
        let sent = Arc::new(AtomicUsize::new(0));
        // Over the cap of reads.
        let _ = start(
            &limiter,
            rt.handle(),
            vec![("late".into(), counting(&sent))],
            Duration::from_secs(30),
        )
        .wait();
        assert_eq!(
            limiter.log.pending(),
            Tally {
                full: 1,
                too_big: 0
            }
        );
        open.send(()).unwrap();
        assert_eq!(first.wait()[0].1, Ok(b"H".to_vec()));
        wait_until("the place is given back", || limiter.in_flight() == 0);
        // Over the cap of calls.
        let calls: Vec<(String, Call)> = (0..=MAX_CALLS)
            .map(|i| (format!("p{i}"), counting(&sent)))
            .collect();
        let _ = start(&limiter, rt.handle(), calls, Duration::from_secs(30)).wait();
        assert_eq!(
            limiter.log.pending(),
            Tally {
                full: 1,
                too_big: 1
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
}
