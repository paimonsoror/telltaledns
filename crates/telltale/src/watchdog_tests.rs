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
        matches!(outcomes[0].1, Outcome::Dumped(Some(_))),
        "{outcomes:?}"
    );
    assert!(!ev.dumps[0].restart);
    assert!(ev.dumps[0].note.is_some_and(|n| n.contains("limit")));

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
    assert!(matches!(outcomes[0].1, Outcome::Dumped(_)));
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
        note: None,
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
