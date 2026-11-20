// REQ: OPS-012 (ADR-163) — the watchdog: when a check counts as stuck, what a round decides, the
// restart limit, the probe's wire format against real sockets, the runtime check against a
// runtime whose worker is blocked, and the dump's content, permissions, and rotation.

use super::*;

const STALL: Duration = Duration::from_secs(60);

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

// ---- the tracker ------------------------------------------------------------------------------

#[test]
fn ops_012_a_check_is_stuck_once_it_has_not_passed_for_the_limit() {
    let t0 = Instant::now();
    let mut tracker = Tracker::new(t0, STALL);
    assert_eq!(tracker.stalled(t0 + secs(59)), None, "not yet");
    let stall = tracker.stalled(t0 + secs(60)).expect("at the limit");
    assert_eq!(stall.check, Check::Runtime);
    assert_eq!(stall.silent, secs(60));
    // A pass starts the count again.
    tracker.observe(t0 + secs(60), Check::Runtime, true);
    assert_eq!(tracker.stalled(t0 + secs(100)), None);
    assert!(tracker.stalled(t0 + secs(120)).is_some());
    // A failure alone changes nothing: only passes move the clock.
    tracker.observe(t0 + secs(110), Check::Runtime, false);
    assert!(tracker.stalled(t0 + secs(120)).is_some());
}

#[test]
fn ops_012_the_listener_counts_only_when_there_is_one_and_the_longest_silence_is_named() {
    let t0 = Instant::now();
    let mut tracker = Tracker::new(t0, STALL);
    assert_eq!(
        tracker.ages(t0 + secs(10)).len(),
        1,
        "no listener, one check"
    );
    tracker.observe(t0 + secs(5), Check::Runtime, true);
    tracker.observe(t0 + secs(5), Check::Listener, false);
    assert_eq!(tracker.ages(t0 + secs(10)).len(), 2);
    tracker.observe(t0 + secs(50), Check::Runtime, true);
    let stall = tracker
        .stalled(t0 + secs(70))
        .expect("the listener never passed");
    assert_eq!(stall.check, Check::Listener);
    assert_eq!(stall.silent, secs(70));
}

// ---- a round ----------------------------------------------------------------------------------

struct Stub {
    runtime: bool,
    listener: Option<bool>,
}

impl Probes for Stub {
    fn runtime(&mut self, _wait: Duration) -> bool {
        self.runtime
    }
    fn listener(&mut self, _wait: Duration) -> Option<bool> {
        self.listener
    }
}

#[derive(Default)]
struct Recorder {
    dumps: Vec<Reason>,
    fail: bool,
}

impl Evidence for Recorder {
    fn dump(&mut self, why: &Reason, _unix: u64) -> io::Result<PathBuf> {
        self.dumps.push(why.clone());
        if self.fail {
            Err(io::Error::other("disk full"))
        } else {
            Ok(PathBuf::from("hang-test.txt"))
        }
    }
}

fn settings(dir: &Path, restart: bool, max_restarts: u32) -> Settings {
    Settings {
        stall: STALL,
        restart,
        max_restarts,
        dir: dir.to_path_buf(),
    }
}

/// Rounds every 5 s from `t0` up to and including `until` seconds; the outcomes that weren't quiet.
fn rounds(
    wd: &mut Watchdog<Stub>,
    ev: &mut Recorder,
    t0: Instant,
    unix0: u64,
    until: u64,
) -> Vec<(u64, Outcome)> {
    (1..=until / 5)
        .filter_map(|n| {
            let at = n * 5;
            match wd.tick(t0 + secs(at), unix0 + at, ev) {
                Outcome::Quiet => None,
                other => Some((at, other)),
            }
        })
        .collect()
}

#[test]
fn ops_012_a_healthy_node_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    let mut wd = Watchdog::new(
        Stub {
            runtime: true,
            listener: Some(true),
        },
        settings(dir.path(), true, 6),
        t0,
    );
    let mut ev = Recorder::default();
    assert_eq!(rounds(&mut wd, &mut ev, t0, 1_000_000, 600).len(), 0);
    assert!(ev.dumps.is_empty());
}

#[test]
fn ops_012_a_stuck_runtime_is_dumped_once_then_restarted() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    let mut wd = Watchdog::new(
        Stub {
            runtime: false,
            listener: Some(true),
        },
        settings(dir.path(), true, 6),
        t0,
    );
    let mut ev = Recorder::default();
    let outcomes = rounds(&mut wd, &mut ev, t0, 1_000_000, 300);
    assert_eq!(outcomes.len(), 1, "one dump for the stall: {outcomes:?}");
    assert_eq!(outcomes[0].0, 60, "at the limit");
    assert!(matches!(outcomes[0].1, Outcome::Restart(Some(_))));
    let why = &ev.dumps[0];
    assert_eq!(why.stall.check, Check::Runtime);
    assert!(why.restart);
    assert_eq!(why.limit, STALL);
    // The restart is remembered, for the limit and the next start's log line.
    assert_eq!(recent_restarts(dir.path(), 1_000_100), 1);
}

#[test]
fn ops_012_a_listener_that_stops_answering_counts_even_while_the_runtime_runs() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    let mut wd = Watchdog::new(
        Stub {
            runtime: true,
            listener: Some(false),
        },
        settings(dir.path(), true, 6),
        t0,
    );
    let mut ev = Recorder::default();
    let outcomes = rounds(&mut wd, &mut ev, t0, 1_000_000, 120);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(ev.dumps[0].stall.check, Check::Listener);
}

#[test]
fn ops_012_dump_only_writes_the_dump_and_keeps_the_node_running() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    let mut wd = Watchdog::new(
        Stub {
            runtime: false,
            listener: None,
        },
        settings(dir.path(), false, 6),
        t0,
    );
    let mut ev = Recorder::default();
    let outcomes = rounds(&mut wd, &mut ev, t0, 1_000_000, 300);
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0].1, Outcome::Dumped(Some(_))));
    assert!(!ev.dumps[0].restart);
    assert_eq!(
        recent_restarts(dir.path(), 1_000_300),
        0,
        "no restart recorded"
    );
}

#[test]
fn ops_012_a_recovered_node_that_stalls_again_gets_a_second_dump() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    let mut wd = Watchdog::new(
        Stub {
            runtime: false,
            listener: None,
        },
        settings(dir.path(), false, 6),
        t0,
    );
    let mut ev = Recorder::default();
    assert_eq!(rounds(&mut wd, &mut ev, t0, 1_000_000, 100).len(), 1);
    // It recovers for one round, then sticks again.
    wd.probes.runtime = true;
    assert!(matches!(
        wd.tick(t0 + secs(105), 1_000_105, &mut ev),
        Outcome::Quiet
    ));
    wd.probes.runtime = false;
    let later = (22..=40)
        .filter(|n| {
            !matches!(
                wd.tick(t0 + secs(n * 5), 1_000_000 + n * 5, &mut ev),
                Outcome::Quiet
            )
        })
        .count();
    assert_eq!(later, 1);
    assert_eq!(ev.dumps.len(), 2);
}

#[test]
fn ops_012_the_restart_limit_turns_a_restart_into_a_dump() {
    let dir = tempfile::tempdir().unwrap();
    // Two restarts in the last hour, limit two.
    record_restart(dir.path(), 1_000_000 - 1800);
    record_restart(dir.path(), 1_000_000 - 600);
    let t0 = Instant::now();
    let mut wd = Watchdog::new(
        Stub {
            runtime: false,
            listener: None,
        },
        settings(dir.path(), true, 2),
        t0,
    );
    let mut ev = Recorder::default();
    let outcomes = rounds(&mut wd, &mut ev, t0, 1_000_000, 100);
    assert!(
        matches!(outcomes[0].1, Outcome::CapReached { dump: Some(_), .. }),
        "{outcomes:?}"
    );
    assert!(!ev.dumps[0].restart);
    assert_eq!(
        ev.dumps[0].cap,
        Some(Cap {
            restarts: 2,
            max: 2
        }),
        "the dump knows it is the limit that held the node back"
    );

    // The same limit an hour later lets it restart again.
    let mut wd = Watchdog::new(
        Stub {
            runtime: false,
            listener: None,
        },
        settings(dir.path(), true, 2),
        t0,
    );
    let outcomes = rounds(&mut wd, &mut Recorder::default(), t0, 1_000_000 + 4000, 100);
    assert!(matches!(outcomes[0].1, Outcome::Restart(_)));
}

#[test]
fn ops_012_zero_restarts_per_hour_never_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    let mut wd = Watchdog::new(
        Stub {
            runtime: false,
            listener: None,
        },
        settings(dir.path(), true, 0),
        t0,
    );
    let outcomes = rounds(&mut wd, &mut Recorder::default(), t0, 1_000_000, 100);
    assert!(matches!(outcomes[0].1, Outcome::CapReached { .. }));
}

#[test]
fn ops_012_a_dump_that_cannot_be_written_still_restarts_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    let mut wd = Watchdog::new(
        Stub {
            runtime: false,
            listener: None,
        },
        settings(dir.path(), true, 6),
        t0,
    );
    let mut ev = Recorder {
        fail: true,
        ..Recorder::default()
    };
    let outcomes = rounds(&mut wd, &mut ev, t0, 1_000_000, 100);
    assert_eq!(outcomes[0].1, Outcome::Restart(None));
}

#[test]
fn ops_012_the_thread_exits_with_status_70_and_stops_at_shutdown() {
    use std::sync::atomic::AtomicI32;
    let dir = tempfile::tempdir().unwrap();
    // A limit of a millisecond and rounds 10 ms apart: the first round decides.
    let quick = |restart| Settings {
        stall: Duration::from_millis(1),
        ..settings(dir.path(), restart, 6)
    };
    let every = Duration::from_millis(10);
    let mut wd = Watchdog::new(
        Stub {
            runtime: false,
            listener: None,
        },
        quick(true),
        Instant::now(),
    );
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let code = AtomicI32::new(0);
    run(&mut wd, &mut Recorder::default(), &rx, every, |c| {
        code.store(c, Ordering::Relaxed);
    });
    assert_eq!(code.load(Ordering::Relaxed), EXIT_STATUS);

    // A node that is shutting down is never restarted.
    let mut wd = Watchdog::new(
        Stub {
            runtime: false,
            listener: None,
        },
        quick(true),
        Instant::now(),
    );
    let (tx, rx) = tokio::sync::watch::channel(false);
    tx.send(true).unwrap();
    let code = AtomicI32::new(0);
    run(&mut wd, &mut Recorder::default(), &rx, every, |c| {
        code.store(c, Ordering::Relaxed);
    });
    assert_eq!(code.load(Ordering::Relaxed), 0);
}

// ---- the restart cap (ADR-163, amended) -------------------------------------------------------
//
// A node that is still stuck after `max_restarts_per_hour` restarts is not restarted again. That
// used to be quiet: one dump with a generic line, and then nothing for as long as it lasted. These
// tests pin what is said now, with an injected clock and a log the test reads: the dump's first
// line, one ERROR line when the limit is found used up and one an hour while the stall lasts, one
// line when it ends by itself, and a counter. Nothing here changes when a node is restarted.

const CAP_LINE: &str = "restart cap reached; not restarting";

/// What a test subscriber saw: each event's level and its whole text (message, then fields).
#[derive(Clone, Default)]
struct Seen(std::sync::Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Seen {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        use std::fmt::Write as _;
        #[derive(Default)]
        struct Text {
            message: String,
            fields: String,
        }
        impl tracing::field::Visit for Text {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.message = format!("{value:?}");
                } else {
                    let _ = write!(self.fields, " {}={value:?}", field.name());
                }
            }
        }
        let mut t = Text::default();
        event.record(&mut t);
        if let Ok(mut v) = self.0.lock() {
            v.push((
                *event.metadata().level(),
                format!("{}{}", t.message, t.fields),
            ));
        }
    }
}

/// Runs `body` with a subscriber that records what is logged, and returns it with the lines.
fn logged<T>(body: impl FnOnce() -> T) -> (T, Vec<(tracing::Level, String)>) {
    use tracing_subscriber::layer::SubscriberExt as _;
    let seen = Seen::default();
    let sub = tracing_subscriber::registry().with(seen.clone());
    let out = tracing::subscriber::with_default(sub, body);
    let lines = seen.0.lock().map(|v| v.clone()).unwrap_or_default();
    (out, lines)
}

/// Rounds 5 s apart from `t0` to `until` seconds, as `run` makes them: each outcome is announced.
/// The outcomes that weren't quiet, with the second they came at.
fn announced_rounds(
    wd: &mut Watchdog<Stub>,
    ev: &mut Recorder,
    t0: Instant,
    unix0: u64,
    from: u64,
    until: u64,
) -> Vec<(u64, Outcome)> {
    (from / 5..=until / 5)
        .filter_map(|n| {
            let at = n * 5;
            let outcome = wd.tick(t0 + secs(at), unix0 + at, ev);
            announce(&outcome);
            (!matches!(outcome, Outcome::Quiet)).then_some((at, outcome))
        })
        .collect()
}

fn stuck_with_cap(dir: &Path, max: u32, t0: Instant) -> Watchdog<Stub> {
    Watchdog::new(
        Stub {
            runtime: false,
            listener: None,
        },
        settings(dir, true, max),
        t0,
    )
}

#[test]
fn ops_012_at_the_restart_cap_the_dump_says_so_in_its_first_line() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    let mut ev = Recorder::default();
    let mut wd = stuck_with_cap(dir.path(), 0, t0);
    rounds(&mut wd, &mut ev, t0, 1_000_000, 100);
    let mut writer = Writer {
        dir: dir.path().join("watchdog"),
        started: Instant::now(),
        runtime: None,
    };
    let text = std::fs::read_to_string(writer.dump(&ev.dumps[0], 1_800_000_000).unwrap()).unwrap();
    let first = text.lines().next().unwrap();
    assert!(first.contains(CAP_LINE), "the first line is `{first}`");
    assert!(
        text.contains("0 restarts in the last hour, [watchdog] max_restarts_per_hour = 0"),
        "the numbers are in the action line:\n{text}"
    );

    // A dump of a node that is about to be restarted is as it was.
    let mut ev = Recorder::default();
    let mut wd = stuck_with_cap(dir.path(), 6, t0);
    rounds(&mut wd, &mut ev, t0, 2_000_000, 100);
    let text = std::fs::read_to_string(writer.dump(&ev.dumps[0], 1_800_003_600).unwrap()).unwrap();
    assert_eq!(text.lines().next(), Some("TelltaleDNS watchdog dump"));
    assert!(!text.contains(CAP_LINE), "{text}");
}

#[test]
fn ops_012_at_the_restart_cap_the_log_says_so_then_once_an_hour_while_the_stall_lasts() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    let mut ev = Recorder::default();
    let mut wd = stuck_with_cap(dir.path(), 0, t0);
    // Two and a half hours stuck, a round every 5 s.
    let (outcomes, lines) = logged(|| announced_rounds(&mut wd, &mut ev, t0, 1_000_000, 5, 9000));
    let said: Vec<&(tracing::Level, String)> =
        lines.iter().filter(|(_, l)| l.contains(CAP_LINE)).collect();
    assert_eq!(
        said.len(),
        3,
        "once when the limit is found used up (60 s), then at 3660 s and 7260 s: {lines:?}"
    );
    assert!(
        said.iter()
            .all(|(level, _)| *level == tracing::Level::ERROR),
        "{said:?}"
    );
    let at: Vec<u64> = outcomes.iter().map(|(s, _)| *s).collect();
    assert_eq!(at, [60, 3660, 7260], "an hour apart, never closer");
    assert_eq!(lines.len(), 3, "and nothing else is said: {lines:?}");
    assert!(
        said[0].1.contains("max_restarts_per_hour = 0"),
        "the first line says why: {}",
        said[0].1
    );
    assert!(
        said[1].1.contains("has not answered for 3660 s"),
        "a repeat says how long: {}",
        said[1].1
    );
    // One dump, not one an hour: the rotation keeps five, and a repeat would push out the ones that
    // show how it began.
    assert_eq!(ev.dumps.len(), 1);
}

#[test]
fn ops_012_a_stall_that_ends_by_itself_after_the_cap_says_so_once_and_the_next_one_starts_over() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    let mut ev = Recorder::default();
    let mut wd = stuck_with_cap(dir.path(), 0, t0);
    let (outcomes, lines) = logged(|| {
        let mut all = announced_rounds(&mut wd, &mut ev, t0, 1_000_000, 5, 100);
        // The node comes back (the listener check, if any, passes with it).
        wd.probes.runtime = true;
        all.extend(announced_rounds(&mut wd, &mut ev, t0, 1_000_000, 105, 400));
        // And sticks again: a new stall, found at the cap again.
        wd.probes.runtime = false;
        all.extend(announced_rounds(&mut wd, &mut ev, t0, 1_000_000, 405, 600));
        all
    });
    let at: Vec<u64> = outcomes.iter().map(|(s, _)| *s).collect();
    assert_eq!(
        at,
        [60, 105, 460],
        "found, ended, found again: {outcomes:?}"
    );
    let said: Vec<&str> = lines.iter().map(|(_, l)| l.as_str()).collect();
    assert_eq!(said.len(), 3, "{said:?}");
    assert!(said[0].contains(CAP_LINE), "{said:?}");
    // It was reported after 60 s of silence and answered again 45 s later: the line says both and
    // that the outage was about 105 s (a report comes `stall_secs` into the outage; final review F2).
    for want in [
        "the node answers again",
        "45 s after it was reported",
        "had not answered for 60 s",
        "about 105 s without answering",
    ] {
        assert!(said[1].contains(want), "no `{want}` in {said:?}");
    }
    assert_eq!(lines[1].0, tracing::Level::INFO, "it is good news");
    assert!(said[2].contains(CAP_LINE), "{said:?}");
    assert_eq!(wd.cap_episodes, 2, "two stalls reached the limit");
    assert_eq!(ev.dumps.len(), 2, "one dump for each");
}

#[test]
fn ops_012_below_the_cap_and_in_dump_only_mode_the_cap_is_never_mentioned() {
    let t0 = Instant::now();
    // A node that is restarted (the limit is not reached): the ordinary line, and no recovery
    // line, since it never stayed stuck.
    let dir = tempfile::tempdir().unwrap();
    let mut wd = stuck_with_cap(dir.path(), 6, t0);
    let (outcomes, lines) =
        logged(|| announced_rounds(&mut wd, &mut Recorder::default(), t0, 1_000_000, 5, 200));
    assert!(matches!(outcomes[0].1, Outcome::Restart(_)), "{outcomes:?}");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(!lines[0].1.contains(CAP_LINE), "{lines:?}");

    // `action = "dump"` never restarts, so the limit isn't what holds it back: as before, one line
    // for the stall, nothing for a recovery, and the counter stays at zero.
    let dir = tempfile::tempdir().unwrap();
    let mut wd = Watchdog::new(
        Stub {
            runtime: false,
            listener: None,
        },
        settings(dir.path(), false, 0),
        t0,
    );
    let mut ev = Recorder::default();
    let ((), lines) = logged(|| {
        announced_rounds(&mut wd, &mut ev, t0, 1_000_000, 5, 8000);
        wd.probes.runtime = true;
        announced_rounds(&mut wd, &mut ev, t0, 1_000_000, 8005, 8100);
    });
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].1.contains("the node keeps running"), "{lines:?}");
    assert_eq!(wd.cap_episodes, 0);
}

#[test]
fn ops_012_the_cap_is_counted_once_per_stall_and_shown_in_the_metrics() {
    let dir = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    let mut ev = Recorder::default();
    let mut wd = stuck_with_cap(dir.path(), 0, t0);
    logged(|| announced_rounds(&mut wd, &mut ev, t0, 1_000_000, 5, 8000));
    assert_eq!(wd.cap_episodes, 1, "two repeats are the same stall");
    // `tick` publishes to the process-wide value, which parallel tests also write, so only a lower
    // bound can be said of it here: a stall that reached the cap left it at one or more.
    assert!(
        shared().cap_reached.load(Ordering::Relaxed) >= 1,
        "tick published the count (a plain store: the test thread stands in for the watchdog's)"
    );

    // What a scrape shows is checked on a `Shared` of this test's own: what `publish_cap_to`
    // stores is what `render_from` says (final review F4).
    let local = Shared::new();
    local.enabled.store(true, Ordering::Relaxed);
    let scrape = |episodes: u64| {
        publish_cap_to(&local, episodes);
        let mut w = PromWriter::default();
        render_from(&local, &mut w);
        w.finish()
    };
    let text = scrape(wd.cap_episodes);
    assert!(
        text.contains("\ntelltale_watchdog_restart_cap_reached_total 1\n"),
        "the count this watchdog reached is what the scrape shows: {text}"
    );
    let text = scrape(2);
    assert!(
        text.contains("# TYPE telltale_watchdog_restart_cap_reached_total counter"),
        "{text}"
    );
    assert!(
        text.contains("\ntelltale_watchdog_restart_cap_reached_total 2\n"),
        "{text}"
    );
    assert!(
        scrape(0).contains("\ntelltale_watchdog_restart_cap_reached_total 0\n"),
        "it is there from the start, so a rate or an increase works"
    );
}

// REQ: OPS-012 — `TT_WEDGE_SECS` (wedge-test builds only) is read from the environment: a value too
// big for an `Instant` must make a very long wedge, not panic the thread that starts it (final
// review F5). Runs with `cargo test -p telltale --features wedge-test`.
#[cfg(feature = "wedge-test")]
#[test]
fn ops_012_a_huge_wedge_time_is_a_long_wedge_not_a_panic() {
    let now = Instant::now();
    assert_eq!(wedge_deadline(now, 45), now + secs(45));
    assert_eq!(wedge_deadline(now, 0), now);
    let ten_years = now + secs(10 * 365 * 24 * 3600);
    for hold in [u64::MAX, u64::MAX / 2, u64::MAX / 1_000_000_000] {
        assert!(
            wedge_deadline(now, hold) > ten_years,
            "{hold} s is a very long wedge"
        );
    }
}

#[test]
fn ops_012_the_cap_line_is_logged_by_the_plain_thread_with_no_runtime() {
    // No Tokio runtime exists in this test: the line comes from `run`, the watchdog thread's loop.
    struct StopAfter {
        rounds: usize,
        stop: tokio::sync::watch::Sender<bool>,
    }
    impl Probes for StopAfter {
        fn runtime(&mut self, _wait: Duration) -> bool {
            self.rounds = self.rounds.saturating_sub(1);
            if self.rounds == 0 {
                let _ = self.stop.send(true);
            }
            false
        }
        fn listener(&mut self, _wait: Duration) -> Option<bool> {
            None
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    let mut wd = Watchdog::new(
        StopAfter {
            rounds: 6,
            stop: tx,
        },
        Settings {
            stall: Duration::from_millis(1),
            ..settings(dir.path(), true, 0)
        },
        Instant::now(),
    );
    let exits = std::sync::atomic::AtomicUsize::new(0);
    let ((), lines) = logged(|| {
        run(
            &mut wd,
            &mut Recorder::default(),
            &rx,
            Duration::from_millis(10),
            |_| {
                exits.fetch_add(1, Ordering::Relaxed);
            },
        );
    });
    assert_eq!(
        exits.load(Ordering::Relaxed),
        0,
        "at the cap the node stays"
    );
    let said = lines.iter().filter(|(_, l)| l.contains(CAP_LINE)).count();
    assert_eq!(said, 1, "{lines:?}");
}

// ---- the probe --------------------------------------------------------------------------------

#[test]
fn ops_012_the_probe_asks_the_probe_name_and_any_response_counts() {
    let q = probe_query(0x1234);
    assert_eq!(&q[..2], &[0x12, 0x34]);
    assert_eq!(q[2] & 0x80, 0, "a query, not a response");
    assert_eq!(&q[4..6], &[0, 1], "one question");
    assert!(
        q.windows(telltale_telemetry::event::PROBE_NAME.len())
            .any(|w| w == telltale_telemetry::event::PROBE_NAME)
    );
    let mut reply = q.clone();
    assert!(
        !is_answer(&reply, 0x1234),
        "the query itself isn't an answer"
    );
    reply[2] |= 0x80;
    assert!(is_answer(&reply, 0x1234));
    reply[3] = 0x03; // NXDOMAIN
    assert!(is_answer(&reply, 0x1234), "any rcode: the node answered");
    assert!(!is_answer(&reply, 0x1235), "another query's answer");
    assert!(!is_answer(&reply[..8], 0x1234), "too short");
}

/// A UDP server on loopback that answers each query as `how` says.
fn server(how: fn(&mut Vec<u8>) -> bool) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let mut reply = buf[..n].to_vec();
            if how(&mut reply) {
                let _ = sock.send_to(&reply, from);
            }
        }
    });
    addr
}

#[test]
fn ops_012_the_listener_check_against_real_sockets() {
    let answering = server(|r| {
        r[2] |= 0x80;
        r[3] |= 0x03;
        true
    });
    assert!(ask_udp(answering, secs(2)), "an answering listener passes");
    let silent = server(|_| false);
    assert!(
        !ask_udp(silent, Duration::from_millis(300)),
        "silence fails"
    );
    let wrong_id = server(|r| {
        r[2] |= 0x80;
        r[0] ^= 0xff;
        true
    });
    assert!(
        !ask_udp(wrong_id, Duration::from_millis(300)),
        "another query's answer fails"
    );
    // Nothing listening: the send is refused or the wait runs out.
    let closed = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    assert!(!ask_udp(closed, Duration::from_millis(300)));
}

#[test]
fn ops_012_the_listener_to_ask_is_the_first_udp_one() {
    let cfg = telltale_config::Loader::new()
        .toml_str(
            "t.toml",
            r#"
[[listen]]
addr = "0.0.0.0:5353"
proto = "tcp"
[[listen]]
addr = "0.0.0.0:5355"
proto = "udp"
[[listen]]
addr = "192.168.1.2:5356"
proto = "udp"
"#,
        )
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    assert_eq!(
        udp_listener(&cfg),
        Some("127.0.0.1:5355".parse().unwrap()),
        "a wildcard is asked on loopback"
    );
    let none = telltale_config::Loader::new()
        .toml_str(
            "t.toml",
            "[[listen]]\naddr = \"127.0.0.1:5353\"\nproto = \"tcp\"\n",
        )
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    assert_eq!(udp_listener(&none), None);
}

// ---- the runtime check ------------------------------------------------------------------------

#[test]
fn ops_012_the_runtime_check_sees_a_runtime_whose_only_worker_is_blocked() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .build()
        .unwrap();
    let mut live = Live {
        handle: rt.handle().clone(),
        udp: None,
    };
    assert!(live.runtime(secs(2)), "a free runtime runs the task");
    assert_eq!(
        live.listener(secs(1)),
        None,
        "no UDP listener: nothing to ask"
    );

    // Block the one worker, as a deadlock would.
    let (release, held) = std::sync::mpsc::channel::<()>();
    let (entered_tx, entered) = std::sync::mpsc::channel::<()>();
    rt.spawn(async move {
        let _ = entered_tx.send(());
        let _ = held.recv(); // blocks the worker thread
    });
    entered.recv_timeout(secs(2)).unwrap();
    assert!(
        !live.runtime(Duration::from_millis(300)),
        "a blocked runtime can't run it"
    );
    release.send(()).unwrap();
    assert!(
        live.runtime(secs(2)),
        "and it passes again once the worker is free"
    );
}

// ---- the dump ---------------------------------------------------------------------------------

#[test]
fn ops_012_the_name_of_a_thread_may_hold_spaces_and_parentheses() {
    let stat = "1234 (tokio (rt) worker) S 1 1234 1234 0 -1 4194304 100 0 0 0 77 33 0 0 20 0 24 0 5 1000 100";
    assert_eq!(parse_stat(stat), Some(('S', 77, 33)));
    assert_eq!(parse_stat("garbage"), None);
}

#[cfg(target_os = "linux")]
#[test]
fn ops_012_the_thread_table_lists_this_process_threads() {
    // A thread takes its name when it starts: wait until it is running before reading the table
    // (a slow machine otherwise shows it still under its parent's name).
    let (up_tx, up) = std::sync::mpsc::channel();
    let me = std::thread::Builder::new()
        .name("wd-test-thread".to_owned())
        .spawn(move || {
            let _ = up_tx.send(());
            std::thread::sleep(secs(2));
        })
        .unwrap();
    up.recv_timeout(secs(5)).unwrap();
    let rows = thread_rows();
    assert!(rows.len() >= 2, "{rows:?}");
    assert!(rows.iter().any(|r| r.name == "wd-test-thread"), "{rows:?}");
    assert!(rows.iter().all(|r| r.state.is_ascii_alphabetic()));
    drop(me);
}

fn sample_report() -> Report {
    Report {
        capped: false,
        time: "2026-11-16T13:37:00.000Z".to_owned(),
        reason: vec![
            "runtime: the runtime did not run a task for 61 s (limit 60 s)".to_owned(),
            "runtime last passed 61 s ago; listener last passed 3 s ago".to_owned(),
        ],
        build: "0.7.0 (commit abcdef0, x86_64-unknown-linux-musl, channel stable)".to_owned(),
        uptime_secs: 4242,
        process: vec!["Threads: 3".to_owned()],
        threads: vec![ThreadRow {
            tid: 10,
            name: "telltale-rt".to_owned(),
            state: 'S',
            wchan: "futex_wait_queue".to_owned(),
            syscall: "202".to_owned(),
            utime: 5,
            stime: 1,
        }],
        stacks: vec![
            (
                "telltale-rt (10)".to_owned(),
                vec![0x4000_1234, 0x4000_2000],
            ),
            ("telltale-udp (11)".to_owned(), vec![]),
        ],
        maps: vec!["00400000-00800000 r-xp 00000000 08:01 1 /usr/local/bin/telltale".to_owned()],
        log: vec!["2026-11-16T13:36:00Z  INFO hello".to_owned()],
    }
}

#[test]
fn ops_012_the_dump_says_why_and_holds_the_evidence() {
    let text = render_report(&sample_report());
    for want in [
        "TelltaleDNS watchdog dump",
        "runtime: the runtime did not run a task for 61 s",
        "build: 0.7.0 (commit abcdef0",
        "10 telltale-rt S futex_wait_queue 202 5 1",
        "telltale-rt (10): 0x40001234 0x40002000",
        "telltale-udp (11): no answer",
        "00400000-00800000 r-xp",
        "INFO hello",
        "== log, last 1 lines",
    ] {
        assert!(text.contains(want), "missing `{want}` in:\n{text}");
    }
    assert!(render_report(&Report::default()).contains("(not captured)"));
}

#[test]
fn ops_012_dumps_are_private_and_only_the_newest_five_stay() {
    let dir = tempfile::tempdir().unwrap();
    let wd = dir.path().join("watchdog");
    let mut last = PathBuf::new();
    for n in 0..7 {
        last = write_dump(&wd, 1_800_000_000 + n * 60, &format!("dump {n}")).unwrap();
    }
    let mut names = dump_names(&wd);
    names.sort();
    assert_eq!(names.len(), KEEP_DUMPS);
    assert!(names[0].starts_with("hang-20"), "{names:?}");
    assert_eq!(
        std::fs::read_to_string(&last).unwrap(),
        "dump 6",
        "the newest stays"
    );
    assert!(
        !names
            .iter()
            .any(|n| std::fs::read_to_string(wd.join(n)).is_ok_and(|t| t == "dump 0")),
        "the oldest went"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = std::fs::metadata(&last).unwrap().permissions().mode() & 0o777;
        let folder = std::fs::metadata(&wd).unwrap().permissions().mode() & 0o777;
        assert_eq!(file, 0o640);
        assert_eq!(folder, 0o750);
    }
}

#[test]
fn ops_012_the_writer_makes_a_real_dump_of_this_process() {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()
        .unwrap();
    let mut writer = Writer {
        dir: dir.path().join("watchdog"),
        started: Instant::now(),
        runtime: Some(rt.handle().clone()),
    };
    let why = Reason {
        stall: Stall {
            check: Check::Runtime,
            silent: secs(61),
        },
        ages: vec![(Check::Runtime, secs(61))],
        limit: STALL,
        restart: true,
        cap: None,
    };
    let path = writer.dump(&why, 1_800_000_000).unwrap();
    let text = std::fs::read_to_string(path).unwrap();
    assert!(
        text.contains("the runtime did not run a task for 61 s (limit 60 s)"),
        "{text}"
    );
    assert!(text.contains("exits with status 70"), "{text}");
    assert!(text.contains(crate::build_info::VERSION), "{text}");
    assert!(text.contains("== threads"), "{text}");
    // REQ: OPS-012 (ADR-174) — the runtime's own numbers are in the process section.
    assert!(
        text.contains("runtime workers: 2, tasks alive: 0, waiting in the global queue: 0"),
        "{text}"
    );
}

// REQ: OPS-012 (ADR-174) — a stuck runtime still reports itself: its one worker is blocked, a
// task is running (alive) and two more wait in the global queue. The numbers need no worker, so
// "workers, tasks waiting, none running" reads at a glance next to the thread table.
#[test]
fn ops_012_the_dump_counts_the_tasks_of_a_stuck_runtime() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .build()
        .unwrap();
    let (release, held) = std::sync::mpsc::channel::<()>();
    let (entered_tx, entered) = std::sync::mpsc::channel::<()>();
    rt.spawn(async move {
        let _ = entered_tx.send(());
        let _ = held.recv(); // blocks the one worker
    });
    entered.recv_timeout(secs(5)).unwrap();
    for _ in 0..2 {
        rt.spawn(async {});
    }
    assert_eq!(
        runtime_line(rt.handle()),
        "runtime workers: 1, tasks alive: 3, waiting in the global queue: 2"
    );
    let lines = process_lines(Some(rt.handle()));
    assert!(
        lines.iter().any(|l| l.starts_with("runtime workers: 1,")),
        "{lines:?}"
    );
    assert!(
        process_lines(None)
            .iter()
            .all(|l| !l.starts_with("runtime ")),
        "no handle, no line"
    );
    release.send(()).unwrap();
}

// ---- settings and metrics ---------------------------------------------------------------------

#[test]
fn ops_012_the_settings_come_from_the_config() {
    let cfg = telltale_config::Loader::new()
        .toml_str(
            "t.toml",
            "[node]\ndata_dir = \"/var/lib/x\"\n[watchdog]\nstall_secs = 90\naction = \"dump\"\nmax_restarts_per_hour = 2\n",
        )
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    let s = Settings::of(&cfg);
    assert_eq!(s.stall, secs(90));
    assert!(!s.restart);
    assert_eq!(s.max_restarts, 2);
    assert_eq!(s.dir, PathBuf::from("/var/lib/x/watchdog"));
    let defaults = Settings::of(&telltale_config::Config::default());
    assert_eq!(defaults.stall, secs(60));
    assert!(defaults.restart);
    assert_eq!(defaults.max_restarts, 6);
}

#[test]
fn ops_012_the_metrics_name_the_watchdog() {
    let mut w = PromWriter::default();
    render(&mut w);
    let text = w.finish();
    assert!(
        text.contains("# TYPE telltale_watchdog_enabled gauge"),
        "{text}"
    );
}
