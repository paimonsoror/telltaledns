//! Hot-path capture (OBS-002): one wait-free SPSC byte ring per producing thread.
//!
//! A thread gets its ring on its first event (one allocation and one short lock per thread
//! for its lifetime). After that, emitting is a thread-local lookup, a stack encode, and one
//! `push_entire_slice`: a whole record or nothing, never blocking. A full ring drops the
//! event and counts it; counters and histograms in [`crate::Metrics`] never drop.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rtrb::{Consumer, Producer, RingBuffer};

use crate::agg::Aggregates;
use crate::event::{self, MAX_RECORD, QueryEvent, Record, UpstreamEvent};

/// Per-ring counters, written by the producing thread and read by scrapes.
#[derive(Debug, Default)]
pub struct RingStats {
    pub emitted: AtomicU64,
    pub dropped: AtomicU64,
}

/// A ring's consumer end, held by the drainer.
#[derive(Debug)]
struct RingEnd {
    consumer: Consumer<u8>,
}

/// Where events go: hands out per-thread rings and collects their consumer ends.
#[derive(Debug)]
pub struct Hub {
    id: u64,
    ring_bytes: usize,
    /// Rings registered since the drainer last looked.
    pending: Mutex<Vec<Consumer<u8>>>,
    /// Every ring's name and counters, for `/metrics`.
    stats: Mutex<Vec<(String, Arc<RingStats>)>>,
    /// Wall clock = `epoch_us` + (instant − `epoch_at`): one clock read per query, not two.
    /// `epoch_us` moves when the system clock steps (see [`Hub::resync_clock`]).
    epoch_at: Instant,
    epoch_us: AtomicU64,
    /// Clock steps followed so far, and the latest one (microseconds, signed).
    clock_steps: AtomicU64,
    clock_step_us: AtomicI64,
    /// What the aggregator thread has folded in so far.
    aggregates: Mutex<Aggregates>,
    /// The privacy level the analytics follow ([`Hub::set_privacy`]).
    privacy: AtomicU8,
    /// REQ: OBS-022 — queries left out of the analytics and every sink, and how many so far.
    exclusions: Mutex<Option<Arc<crate::exclude::Exclusions>>>,
    excluded: AtomicU64,
}

static NEXT_HUB: AtomicU64 = AtomicU64::new(1);

/// A difference between the wall clock and the epoch-derived time at least this large is a
/// step the epoch follows. NTP slewing adjusts `Instant`'s clock too, so only a step
/// (`settimeofday`: the first sync on a Pi without an RTC, a resumed VM) ever gets here.
pub const CLOCK_STEP_US: u64 = 1_000_000;

/// Microseconds since the Unix epoch, now.
fn wall_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// This thread's producer for one hub.
struct Local {
    hub: u64,
    producer: Producer<u8>,
    stats: Arc<RingStats>,
}

thread_local! {
    /// Usually one entry; tests create several hubs per thread.
    static LOCAL: RefCell<Vec<Local>> = const { RefCell::new(Vec::new()) };
}

impl Hub {
    /// `ring_bytes` per producing thread (rounded up to the largest record).
    pub fn new(ring_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            id: NEXT_HUB.fetch_add(1, Ordering::Relaxed),
            ring_bytes: ring_bytes.max(MAX_RECORD * 4),
            pending: Mutex::new(Vec::new()),
            stats: Mutex::new(Vec::new()),
            epoch_at: Instant::now(),
            epoch_us: AtomicU64::new(wall_us()),
            clock_steps: AtomicU64::new(0),
            clock_step_us: AtomicI64::new(0),
            aggregates: Mutex::new(Aggregates::new()),
            privacy: AtomicU8::new(0),
            exclusions: Mutex::new(None),
            excluded: AtomicU64::new(0),
        })
    }

    /// Wall-clock microseconds for an `Instant` taken during this process.
    pub fn ts_us(&self, at: Instant) -> u64 {
        self.epoch_us
            .load(Ordering::Relaxed)
            .saturating_add(self.since_epoch(at))
    }

    fn since_epoch(&self, at: Instant) -> u64 {
        let since = at.saturating_duration_since(self.epoch_at);
        u64::try_from(since.as_micros()).unwrap_or(u64::MAX)
    }

    /// REQ: OBS-001, OBS-004 — keeps event time on the wall clock. `Instant` doesn't follow
    /// a clock step, and a Pi has no RTC: it starts on the clock it shut down with and sets
    /// it from NTP only once DNS answers, so with a fixed epoch every later event, query-log
    /// row, and rollup minute would carry the old offset until a restart. The aggregator
    /// thread calls this every drain (one clock read); the query path still reads one
    /// atomic. Returns the step followed, if any.
    pub fn resync_clock(&self) -> Option<i64> {
        self.resync_to(wall_us(), Instant::now())
    }

    /// [`Self::resync_clock`] for a reading `wall_us` of the wall clock taken at `at`.
    pub fn resync_to(&self, wall_us: u64, at: Instant) -> Option<i64> {
        let expected = self.ts_us(at);
        let step = i64::try_from(wall_us)
            .unwrap_or(i64::MAX)
            .saturating_sub(i64::try_from(expected).unwrap_or(i64::MAX));
        if step.unsigned_abs() < CLOCK_STEP_US {
            return None;
        }
        self.epoch_us.store(
            wall_us.saturating_sub(self.since_epoch(at)),
            Ordering::Relaxed,
        );
        self.clock_steps.fetch_add(1, Ordering::Relaxed);
        self.clock_step_us.store(step, Ordering::Relaxed);
        Some(step)
    }

    /// REQ: OBS-009 (`spec/06` §4, review 04-04) — the query log's privacy level, which the
    /// in-memory analytics follow too: from the next drain on, they get names hashed (1+)
    /// and no client addresses (2+). The query log, tail, and sinks apply it themselves.
    pub fn set_privacy(&self, level: u8) {
        self.privacy.store(level, Ordering::Relaxed);
    }

    /// REQ: OBS-022 (T12.1) — from the next drain on, queries these match are left out of the
    /// analytics and every sink (`None` or empty: nothing is).
    pub fn set_exclusions(&self, x: Option<crate::exclude::Exclusions>) {
        *self
            .exclusions
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = x.filter(|x| !x.is_empty()).map(Arc::new);
    }

    /// Queries left out so far ([`Self::set_exclusions`]), for `/metrics`.
    pub fn excluded_total(&self) -> u64 {
        self.excluded.load(Ordering::Relaxed)
    }

    /// The exclusions in force, read once per drain.
    fn exclusions(&self) -> Option<Arc<crate::exclude::Exclusions>> {
        self.exclusions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether `r` is left out (counting it when it is).
    fn left_out(&self, x: Option<&crate::exclude::Exclusions>, r: &Record) -> bool {
        let out = x.is_some_and(|x| x.excludes(r));
        if out {
            self.excluded.fetch_add(1, Ordering::Relaxed);
        }
        out
    }

    /// Clock steps followed so far and the latest one (microseconds), for `/metrics`.
    pub fn clock_steps(&self) -> (u64, i64) {
        (
            self.clock_steps.load(Ordering::Relaxed),
            self.clock_step_us.load(Ordering::Relaxed),
        )
    }

    /// Records a client transaction. Wait-free; drops (and counts) if this thread's ring is
    /// full. `name` is the wire-format qname.
    // REQ: OBS-001, OBS-002
    pub fn emit_query(&self, ev: &QueryEvent, name: &[u8]) {
        let mut buf = [0u8; MAX_RECORD];
        let len = event::encode_query(ev, name, &mut buf);
        self.push(&buf[..len]);
    }

    /// Records an upstream exchange.
    pub fn emit_upstream(&self, ev: &UpstreamEvent) {
        let mut buf = [0u8; MAX_RECORD];
        let len = event::encode_upstream(ev, &mut buf);
        self.push(&buf[..len]);
    }

    fn push(&self, record: &[u8]) {
        LOCAL.with(|cell| {
            // Re-entrancy is impossible here, but never panic on the query path.
            let Ok(mut locals) = cell.try_borrow_mut() else {
                return;
            };
            let i = if let Some(i) = locals.iter().position(|l| l.hub == self.id) {
                i
            } else {
                // Producers of hubs that are gone (tests) are freed on the way.
                locals.retain(|l| !l.producer.is_abandoned());
                locals.push(self.register());
                locals.len() - 1
            };
            let l = &mut locals[i];
            if l.producer.push_entire_slice(record).is_ok() {
                l.stats.emitted.fetch_add(1, Ordering::Relaxed);
            } else {
                l.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    /// A new ring for the calling thread.
    fn register(&self) -> Local {
        let (producer, consumer) = RingBuffer::new(self.ring_bytes);
        let stats = Arc::new(RingStats::default());
        let name = std::thread::current().name().map_or_else(
            || format!("{:?}", std::thread::current().id()),
            str::to_owned,
        );
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(consumer);
        self.stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((name, Arc::clone(&stats)));
        Local {
            hub: self.id,
            producer,
            stats,
        }
    }

    /// Per-ring (thread name, emitted, dropped), for `telemetry_dropped_total{ring}`.
    pub fn ring_stats(&self) -> Vec<(String, u64, u64)> {
        self.stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(n, s)| {
                (
                    n.clone(),
                    s.emitted.load(Ordering::Relaxed),
                    s.dropped.load(Ordering::Relaxed),
                )
            })
            .collect()
    }

    /// The aggregates (live windows, top-K, histograms). Hold the guard briefly: the
    /// aggregator thread needs it every drain.
    pub fn aggregates(&self) -> MutexGuard<'_, Aggregates> {
        self.aggregates
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts the aggregator thread (`spec/06` §2): drains every ring each `period`, folds
    /// the events into [`Hub::aggregates`], and passes each to `sink` (the query log). Stops
    /// when the handle is dropped; the sink is dropped on the thread after a final drain.
    pub fn spawn_aggregator(
        self: &Arc<Self>,
        period: Duration,
        mut sink: Option<Box<dyn Sink>>,
    ) -> std::io::Result<Aggregator> {
        let stop = Arc::new(AtomicBool::new(false));
        let (hub, flag) = (Arc::clone(self), Arc::clone(&stop));
        let thread = std::thread::Builder::new()
            .name("telltale-telemetry".into())
            .spawn(move || {
                let mut drainer = hub.drainer();
                loop {
                    let done = flag.load(Ordering::Acquire);
                    let t = Instant::now();
                    hub.resync_clock();
                    {
                        let level = hub.privacy.load(Ordering::Relaxed);
                        let excluded = hub.exclusions();
                        let mut agg = hub.aggregates();
                        drainer.drain(|r| {
                            // REQ: OBS-020 — the listener probes stay out of the analytics,
                            // the query log, and every export; so do excluded queries (OBS-022).
                            if r.is_probe() || hub.left_out(excluded.as_deref(), &r) {
                                return;
                            }
                            if level == 0 {
                                agg.record(&r);
                            } else {
                                agg.record(&crate::event::private(&r, level));
                            }
                            if let Some(s) = sink.as_mut() {
                                s.record(&r);
                            }
                        });
                    }
                    if let Some(s) = sink.as_mut() {
                        s.tick(Instant::now());
                    }
                    if done {
                        break;
                    }
                    std::thread::sleep(period.saturating_sub(t.elapsed()));
                }
                drop(sink);
            })?;
        Ok(Aggregator {
            stop,
            thread: Some(thread),
        })
    }

    /// One drain into the aggregates. Returns the number of records.
    pub fn drain_once(&self, drainer: &mut Drainer) -> usize {
        let level = self.privacy.load(Ordering::Relaxed);
        let excluded = self.exclusions();
        let mut agg = self.aggregates();
        drainer.drain(|r| {
            if !r.is_probe() && !self.left_out(excluded.as_deref(), &r) {
                agg.record(&crate::event::private(&r, level));
            }
        })
    }

    /// The single consumer of this hub's rings.
    pub fn drainer(self: &Arc<Self>) -> Drainer {
        Drainer {
            hub: Arc::clone(self),
            rings: Vec::new(),
            scratch: Vec::new(),
        }
    }
}

/// Receives every drained record on the aggregator thread (the query log's write path).
/// Must not block for long: it runs between ring drains.
pub trait Sink: Send {
    fn record(&mut self, r: &Record);
    /// Called after every drain, for time-based work such as flushing aged blocks.
    fn tick(&mut self, _now: Instant) {}
}

/// Stops and joins the aggregator thread when dropped.
#[derive(Debug)]
pub struct Aggregator {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Aggregator {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Reads every ring (owned by the aggregator thread, or a test).
#[derive(Debug)]
pub struct Drainer {
    hub: Arc<Hub>,
    rings: Vec<RingEnd>,
    scratch: Vec<u8>,
}

impl Drainer {
    /// Decodes every complete record currently in the rings, calling `f` for each. Returns
    /// the number of records.
    pub fn drain(&mut self, mut f: impl FnMut(Record)) -> usize {
        {
            let mut pending = self
                .hub
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.rings
                .extend(pending.drain(..).map(|consumer| RingEnd { consumer }));
        }
        let mut n = 0;
        for ring in &mut self.rings {
            let avail = ring.consumer.slots();
            if avail == 0 {
                continue;
            }
            let Ok(chunk) = ring.consumer.read_chunk(avail) else {
                continue;
            };
            let (a, b) = chunk.as_slices();
            self.scratch.clear();
            self.scratch.extend_from_slice(a);
            self.scratch.extend_from_slice(b);
            chunk.commit_all();
            // Producers commit whole records, so the chunk holds only complete ones.
            let mut pos = 0;
            while let Some(len) = event::record_len(&self.scratch[pos..]) {
                let Some(rec) = self.scratch.get(pos..pos + len) else {
                    break;
                };
                if let Some(r) = event::decode(rec) {
                    f(r);
                    n += 1;
                }
                pos += len;
            }
        }
        // A thread that exited leaves an empty, abandoned ring behind.
        self.rings
            .retain(|r| !(r.consumer.is_abandoned() && r.consumer.slots() == 0));
        n
    }
}
