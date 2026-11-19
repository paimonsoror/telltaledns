//! REQ: OPS-012 (ADR-163, GitHub issue #7) — the watchdog: a node that stops answering writes a
//! dump of why and restarts.
//!
//! One OS thread, `telltale-watchdog`, outside the Tokio runtime and apart from the UDP workers
//! (a check that runs on what is stuck can't see it). Every 5 s it makes two checks: the runtime
//! runs a task, and this node's own first UDP listener answers `probe.telltale.invalid` (OBS-020's
//! probe name: answered NXDOMAIN without an upstream, kept out of the query log and analytics).
//! A check that hasn't passed for `[watchdog] stall_secs` means the node is stuck: the dump is
//! written, and with `action = "restart"` the process exits with status 70 for the supervisor
//! to start it again, at most `max_restarts_per_hour` times an hour.
//!
//! Nothing here touches the query path: no pipeline code, and nothing is allocated, locked, or
//! read there.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use telltale_config::{Config, ListenProto, WatchdogAction};
use telltale_telemetry::prom::PromWriter;
use tracing::{error, info, warn};

/// Between two rounds of checks.
pub(crate) const CHECK_EVERY: Duration = Duration::from_secs(5);
/// How long one check waits for its answer.
pub(crate) const CHECK_WAIT: Duration = Duration::from_secs(2);
/// The exit status of a watchdog restart (`EX_SOFTWARE`), so a supervisor's log says why.
pub(crate) const EXIT_STATUS: i32 = 70;
/// Dumps kept under `<data_dir>/watchdog/`.
const KEEP_DUMPS: usize = 5;
/// Log lines in a dump.
const LOG_LINES: usize = 200;
const HOUR_SECS: u64 = 3600;
/// Restart times kept in the `restarts` file.
const KEEP_RESTARTS: usize = 64;

/// What is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Check {
    /// The runtime runs a task.
    Runtime,
    /// The node's own UDP listener answers.
    Listener,
}

impl Check {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Listener => "listener",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Runtime => 0,
            Self::Listener => 1,
        }
    }

    /// What it means in the dump.
    const fn means(self) -> &'static str {
        match self {
            Self::Runtime => "the runtime did not run a task",
            Self::Listener => "the UDP listener did not answer its own probe",
        }
    }
}

/// A check that has gone too long without passing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stall {
    pub(crate) check: Check,
    pub(crate) silent: Duration,
}

/// When each check last passed.
#[derive(Debug)]
pub(crate) struct Tracker {
    stall: Duration,
    last: [Instant; 2],
    /// The listener check only counts once there is a listener to ask.
    listener: bool,
}

impl Tracker {
    /// Both checks count as passed at `start`: a node is never stuck before it has had
    /// `stall` to answer.
    pub(crate) fn new(start: Instant, stall: Duration) -> Self {
        Self {
            stall,
            last: [start; 2],
            listener: false,
        }
    }

    pub(crate) fn observe(&mut self, now: Instant, check: Check, passed: bool) {
        if check == Check::Listener {
            self.listener = true;
        }
        if passed {
            self.last[check.index()] = now;
        }
    }

    /// How long each active check has gone without passing.
    pub(crate) fn ages(&self, now: Instant) -> Vec<(Check, Duration)> {
        let mut v = vec![(Check::Runtime, now.saturating_duration_since(self.last[0]))];
        if self.listener {
            v.push((Check::Listener, now.saturating_duration_since(self.last[1])));
        }
        v
    }

    /// The check that has been silent longest, if one has reached the limit.
    pub(crate) fn stalled(&self, now: Instant) -> Option<Stall> {
        self.ages(now)
            .into_iter()
            .filter(|(_, silent)| *silent >= self.stall)
            .max_by_key(|(_, silent)| *silent)
            .map(|(check, silent)| Stall { check, silent })
    }
}

/// The two checks. A stub in tests.
pub(crate) trait Probes {
    /// Does the runtime run a task within `wait`?
    fn runtime(&mut self, wait: Duration) -> bool;
    /// Does the listener answer within `wait`? `None`: there is no UDP listener to ask.
    fn listener(&mut self, wait: Duration) -> Option<bool>;
}

/// Why a dump is written.
#[derive(Debug, Clone)]
pub(crate) struct Reason {
    pub(crate) stall: Stall,
    pub(crate) ages: Vec<(Check, Duration)>,
    pub(crate) limit: Duration,
    /// The process exits after the dump.
    pub(crate) restart: bool,
    /// Why it doesn't, when it could have.
    pub(crate) note: Option<&'static str>,
}

/// Writes the dump. A stub in tests.
pub(crate) trait Evidence {
    fn dump(&mut self, why: &Reason, unix: u64) -> io::Result<PathBuf>;
}

/// What a round decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Quiet,
    /// A stall began: the dump is written (or couldn't be) and the node keeps running.
    Dumped(Option<PathBuf>),
    /// A stall began: the dump is written (or couldn't be) and the process should exit.
    Restart(Option<PathBuf>),
}

/// The settings of this run.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub(crate) stall: Duration,
    /// `action = "restart"`.
    pub(crate) restart: bool,
    pub(crate) max_restarts: u32,
    pub(crate) dir: PathBuf,
}

impl Settings {
    pub(crate) fn of(cfg: &Config) -> Self {
        Self {
            stall: Duration::from_secs(u64::from(cfg.watchdog.stall_secs)),
            restart: cfg.watchdog.action == WatchdogAction::Restart,
            max_restarts: cfg.watchdog.max_restarts_per_hour,
            dir: Path::new(cfg.node.data_dir.as_str()).join("watchdog"),
        }
    }
}

/// The watchdog's decisions, round by round.
pub(crate) struct Watchdog<P> {
    probes: P,
    tracker: Tracker,
    settings: Settings,
    /// A stall has been dealt with and no check has recovered since: no second dump.
    in_stall: bool,
}

impl<P: Probes> Watchdog<P> {
    pub(crate) fn new(probes: P, settings: Settings, start: Instant) -> Self {
        let tracker = Tracker::new(start, settings.stall);
        Self {
            probes,
            tracker,
            settings,
            in_stall: false,
        }
    }

    /// One round: the checks, then what they mean. `unix` is the wall clock (the restart limit
    /// and the dump's name use it).
    pub(crate) fn tick(&mut self, now: Instant, unix: u64, evidence: &mut dyn Evidence) -> Outcome {
        let ran = self.probes.runtime(CHECK_WAIT);
        self.tracker.observe(now, Check::Runtime, ran);
        if let Some(answered) = self.probes.listener(CHECK_WAIT) {
            self.tracker.observe(now, Check::Listener, answered);
        }
        let ages = self.tracker.ages(now);
        publish_ages(&ages);
        let Some(stall) = self.tracker.stalled(now) else {
            self.in_stall = false;
            return Outcome::Quiet;
        };
        if self.in_stall {
            return Outcome::Quiet;
        }
        self.in_stall = true;
        let allowed = recent_restarts(&self.settings.dir, unix) < self.settings.max_restarts;
        let restart = self.settings.restart && allowed;
        let note = (self.settings.restart && !allowed)
            .then_some("the restart limit for this hour is reached, so the node keeps running");
        let why = Reason {
            stall,
            ages,
            limit: self.settings.stall,
            restart,
            note,
        };
        let path = match evidence.dump(&why, unix) {
            Ok(p) => Some(p),
            Err(e) => {
                warn!("the watchdog's dump wasn't written: {e}");
                None
            }
        };
        publish_action(unix);
        if restart {
            record_restart(&self.settings.dir, unix);
            Outcome::Restart(path)
        } else {
            Outcome::Dumped(path)
        }
    }
}

// ---- the restart limit ---------------------------------------------------------------------

const RESTARTS_FILE: &str = "restarts";

/// Unix times of the watchdog's restarts, newest last.
fn read_restarts(dir: &Path) -> Vec<u64> {
    fs::read_to_string(dir.join(RESTARTS_FILE))
        .map(|t| t.lines().filter_map(|l| l.trim().parse().ok()).collect())
        .unwrap_or_default()
}

/// Restarts in the hour before `unix`.
pub(crate) fn recent_restarts(dir: &Path, unix: u64) -> u32 {
    let n = read_restarts(dir)
        .into_iter()
        .filter(|t| t.saturating_add(HOUR_SECS) > unix && *t <= unix.saturating_add(HOUR_SECS))
        .count();
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Remembers a restart, for the limit and for the next start's log line. Best effort: with a
/// read-only data directory the limit can't hold, and the restart still happens.
fn record_restart(dir: &Path, unix: u64) {
    let mut all = read_restarts(dir);
    all.push(unix);
    let skip = all.len().saturating_sub(KEEP_RESTARTS);
    let text = all.iter().skip(skip).fold(String::new(), |mut s, t| {
        let _ = writeln!(s, "{t}");
        s
    });
    if let Err(e) = make_dir(dir).and_then(|()| write_private(&dir.join(RESTARTS_FILE), &text)) {
        warn!("the watchdog couldn't record its restart: {e}");
    }
}

// ---- metrics ----------------------------------------------------------------------------------

/// `telltale_watchdog_*`: shared between the thread and the scrape.
struct Shared {
    enabled: AtomicBool,
    /// Seconds since each check last passed; `u64::MAX`: not checked.
    ages: [AtomicU64; 2],
    last_action: AtomicU64,
}

fn shared() -> &'static Shared {
    static S: OnceLock<Shared> = OnceLock::new();
    S.get_or_init(|| Shared {
        enabled: AtomicBool::new(false),
        ages: [AtomicU64::new(u64::MAX), AtomicU64::new(u64::MAX)],
        last_action: AtomicU64::new(0),
    })
}

fn publish_ages(ages: &[(Check, Duration)]) {
    for (c, d) in ages {
        shared().ages[c.index()].store(d.as_secs(), Ordering::Relaxed);
    }
}

fn publish_action(unix: u64) {
    shared().last_action.store(unix, Ordering::Relaxed);
}

/// REQ: OPS-012 — the watchdog's metrics.
pub(crate) fn render(w: &mut PromWriter) {
    let s = shared();
    w.family(
        "telltale_watchdog_enabled",
        "gauge",
        "1 while the watchdog watches this node ([watchdog] enabled).",
    )
    .sample(
        "telltale_watchdog_enabled",
        &[],
        u64::from(s.enabled.load(Ordering::Relaxed)),
    );
    if !s.enabled.load(Ordering::Relaxed) {
        return;
    }
    w.family(
        "telltale_watchdog_check_age_seconds",
        "gauge",
        "Seconds since each of the watchdog's checks last passed (runtime: it ran a task; listener: the UDP listener answered its own probe). Near its stall_secs, the node is about to be called stuck.",
    );
    for c in [Check::Runtime, Check::Listener] {
        let age = s.ages[c.index()].load(Ordering::Relaxed);
        if age != u64::MAX {
            w.sample(
                "telltale_watchdog_check_age_seconds",
                &[("check", c.name())],
                age,
            );
        }
    }
    w.family(
        "telltale_watchdog_last_action_timestamp_seconds",
        "gauge",
        "Unix time of the watchdog's last dump or restart, 0 for none.",
    )
    .sample(
        "telltale_watchdog_last_action_timestamp_seconds",
        &[],
        s.last_action.load(Ordering::Relaxed),
    );
}

// ---- the real checks --------------------------------------------------------------------------

/// The runtime check and the UDP check of a running node.
pub(crate) struct Live {
    handle: tokio::runtime::Handle,
    udp: Option<SocketAddr>,
}

impl Probes for Live {
    fn runtime(&mut self, wait: Duration) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        // A stuck runtime never runs this; the task waits in its queue and the check times out.
        self.handle.spawn(async move {
            let _ = tx.send(());
        });
        rx.recv_timeout(wait).is_ok()
    }

    fn listener(&mut self, wait: Duration) -> Option<bool> {
        self.udp.map(|addr| ask_udp(addr, wait))
    }
}

/// The first UDP listener a client could ask (a wildcard bind is asked on loopback).
pub(crate) fn udp_listener(cfg: &Config) -> Option<SocketAddr> {
    cfg.listen
        .iter()
        .find(|l| l.proto == ListenProto::Udp)
        .map(|l| crate::probes::reachable(l.addr))
}

/// A DNS query for the probe name (an A question with recursion desired).
pub(crate) fn probe_query(id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + telltale_telemetry::event::PROBE_NAME.len() + 4);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    q.extend_from_slice(telltale_telemetry::event::PROBE_NAME);
    q.extend_from_slice(&[0, 1, 0, 1]);
    q
}

/// Is `reply` a response to the query with `id`? Any rcode counts: the node answered.
pub(crate) fn is_answer(reply: &[u8], id: u16) -> bool {
    reply.len() >= 12 && reply[..2] == id.to_be_bytes() && reply[2] & 0x80 != 0
}

fn ask_udp(addr: SocketAddr, wait: Duration) -> bool {
    static NEXT: AtomicU16 = AtomicU16::new(0x7e57);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let bind: SocketAddr = match addr.ip() {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let Ok(sock) = UdpSocket::bind(bind) else {
        return false;
    };
    if sock.set_read_timeout(Some(wait)).is_err()
        || sock.connect(addr).is_err()
        || sock.send(&probe_query(id)).is_err()
    {
        return false;
    }
    let mut buf = [0u8; 512];
    // A late answer to an earlier probe can't arrive here: each probe has its own socket.
    sock.recv(&mut buf).is_ok_and(|n| is_answer(&buf[..n], id))
}

// ---- the dump ---------------------------------------------------------------------------------

/// One thread of the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreadRow {
    pub(crate) tid: u64,
    pub(crate) name: String,
    pub(crate) state: char,
    /// What the kernel says it waits in (`futex_wait_queue`, `do_epoll_wait`, `0` for none).
    pub(crate) wchan: String,
    /// The system call it is in, by number (`running` when it isn't in one).
    pub(crate) syscall: String,
    pub(crate) utime: u64,
    pub(crate) stime: u64,
}

/// What a dump holds.
#[derive(Debug, Clone, Default)]
pub(crate) struct Report {
    pub(crate) time: String,
    pub(crate) reason: Vec<String>,
    pub(crate) build: String,
    pub(crate) uptime_secs: u64,
    pub(crate) process: Vec<String>,
    pub(crate) threads: Vec<ThreadRow>,
    pub(crate) stacks: Vec<(String, Vec<u64>)>,
    pub(crate) maps: Vec<String>,
    pub(crate) log: Vec<String>,
}

/// The dump as text.
pub(crate) fn render_report(r: &Report) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "TelltaleDNS watchdog dump");
    let _ = writeln!(s, "time: {}", r.time);
    let _ = writeln!(s, "build: {}", r.build);
    let _ = writeln!(s, "uptime: {} s", r.uptime_secs);
    let _ = writeln!(s, "\n== why");
    for l in &r.reason {
        let _ = writeln!(s, "{l}");
    }
    let _ = writeln!(s, "\n== process");
    for l in &r.process {
        let _ = writeln!(s, "{l}");
    }
    let _ = writeln!(
        s,
        "\n== threads ({}): id, name, state, kernel wait, syscall, user ticks, system ticks",
        r.threads.len()
    );
    for t in &r.threads {
        let _ = writeln!(
            s,
            "{} {} {} {} {} {} {}",
            t.tid, t.name, t.state, t.wchan, t.syscall, t.utime, t.stime
        );
    }
    let _ = writeln!(
        s,
        "\n== stacks: return addresses, newest call first (addr2line -e telltale.debug -f -C <address - base>; see the mappings)"
    );
    if r.stacks.is_empty() {
        let _ = writeln!(s, "(not captured)");
    }
    for (who, frames) in &r.stacks {
        if frames.is_empty() {
            let _ = writeln!(s, "{who}: no answer");
        } else {
            let list: Vec<String> = frames.iter().map(|a| format!("{a:#x}")).collect();
            let _ = writeln!(s, "{who}: {}", list.join(" "));
        }
    }
    let _ = writeln!(s, "\n== executable mappings");
    for l in &r.maps {
        let _ = writeln!(s, "{l}");
    }
    let _ = writeln!(s, "\n== log, last {} lines", r.log.len());
    for l in &r.log {
        let _ = writeln!(s, "{l}");
    }
    s
}

/// `/proc/self/task`: every thread with its state. Empty off Linux.
pub(crate) fn thread_rows() -> Vec<ThreadRow> {
    let Ok(dir) = fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    let mut rows: Vec<ThreadRow> = dir
        .flatten()
        .filter_map(|e| {
            let tid: u64 = e.file_name().to_str()?.parse().ok()?;
            let base = e.path();
            let read = |f: &str| fs::read_to_string(base.join(f)).map(|t| t.trim().to_owned());
            let stat = read("stat").ok()?;
            let (state, utime, stime) = parse_stat(&stat)?;
            let syscall = read("syscall")
                .ok()
                .and_then(|s| s.split_whitespace().next().map(str::to_owned))
                .unwrap_or_else(|| "?".to_owned());
            Some(ThreadRow {
                tid,
                name: read("comm").unwrap_or_default(),
                state,
                wchan: read("wchan").unwrap_or_else(|_| "?".to_owned()),
                syscall,
                utime,
                stime,
            })
        })
        .collect();
    rows.sort_by_key(|r| r.tid);
    rows
}

/// The state and CPU ticks from a `/proc/<pid>/task/<tid>/stat` line. The name sits in
/// parentheses and can hold spaces and parentheses itself, so the fields start after the last `)`.
pub(crate) fn parse_stat(stat: &str) -> Option<(char, u64, u64)> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // After the name: state (field 3), ..., utime (14), stime (15).
    Some((
        f.first()?.chars().next()?,
        f.get(11)?.parse().ok()?,
        f.get(12)?.parse().ok()?,
    ))
}

/// A few lines of `/proc/self/status`, the load average, and what the runtime says of itself.
fn process_lines(runtime: Option<&tokio::runtime::Handle>) -> Vec<String> {
    let mut v = Vec::new();
    if let Ok(t) = fs::read_to_string("/proc/self/status") {
        for l in t.lines() {
            if [
                "Threads:",
                "VmRSS:",
                "VmHWM:",
                "VmSize:",
                "voluntary_ctxt_switches:",
            ]
            .iter()
            .any(|k| l.starts_with(k))
            {
                v.push(l.split_whitespace().collect::<Vec<_>>().join(" "));
            }
        }
    }
    if let Ok(t) = fs::read_to_string("/proc/loadavg") {
        v.push(format!("load average: {}", t.trim()));
    }
    if let Some(rt) = runtime {
        v.push(runtime_line(rt));
    }
    v
}

/// REQ: OPS-012 (ADR-174) — what the runtime says of itself: its workers, the tasks alive, and
/// the tasks waiting in its global queue (where a task started from outside waits for a worker).
/// They are atomic reads that spawn nothing and need no worker, so they answer for a stuck
/// runtime: workers, tasks waiting and nothing running is a wedge at a glance, with the thread
/// table showing where each worker is.
pub(crate) fn runtime_line(rt: &tokio::runtime::Handle) -> String {
    let m = rt.metrics();
    format!(
        "runtime workers: {}, tasks alive: {}, waiting in the global queue: {}",
        m.num_workers(),
        m.num_alive_tasks(),
        m.global_queue_depth()
    )
}

/// The mappings of the running executable (to turn an address into an offset in the file).
fn exe_maps() -> Vec<String> {
    let exe = fs::read_link("/proc/self/exe")
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let Ok(maps) = fs::read_to_string("/proc/self/maps") else {
        return Vec::new();
    };
    maps.lines()
        .filter(|l| !exe.is_empty() && l.contains(exe.trim_end_matches(" (deleted)")))
        .map(str::to_owned)
        .collect()
}

/// The dump of a running node.
pub(crate) struct Writer {
    dir: PathBuf,
    started: Instant,
    /// The runtime the node serves on (its numbers go in the dump).
    runtime: Option<tokio::runtime::Handle>,
}

impl Evidence for Writer {
    fn dump(&mut self, why: &Reason, unix: u64) -> io::Result<PathBuf> {
        let report = self.report(why, unix);
        write_dump(&self.dir, unix, &render_report(&report))
    }
}

impl Writer {
    fn report(&self, why: &Reason, unix: u64) -> Report {
        let mut reason = vec![format!(
            "{}: {} for {} s (limit {} s)",
            why.stall.check.name(),
            why.stall.check.means(),
            why.stall.silent.as_secs(),
            why.limit.as_secs()
        )];
        let passed: Vec<String> = why
            .ages
            .iter()
            .map(|(c, d)| format!("{} last passed {} s ago", c.name(), d.as_secs()))
            .collect();
        reason.push(passed.join("; "));
        reason.push(if why.restart {
            format!(
                "action: the process exits with status {EXIT_STATUS} for its supervisor to restart"
            )
        } else {
            format!(
                "action: the node keeps running ({})",
                why.note.unwrap_or("[watchdog] action = \"dump\"")
            )
        });
        let log = crate::support_log::global().snapshot().lines;
        let skip = log.len().saturating_sub(LOG_LINES);
        Report {
            time: telltale_api::time::format_us(unix * 1_000_000),
            reason,
            build: format!(
                "{} (commit {}, {}, channel {})",
                crate::build_info::VERSION,
                crate::build_info::COMMIT,
                crate::build_info::TARGET,
                crate::build_info::CHANNEL
            ),
            uptime_secs: self.started.elapsed().as_secs(),
            process: process_lines(self.runtime.as_ref()),
            threads: thread_rows(),
            stacks: stacks(),
            maps: exe_maps(),
            log: log.into_iter().skip(skip).collect(),
        }
    }
}

/// Every other thread's stack as raw addresses, asked of the threads themselves (ADR-163).
#[cfg(target_os = "linux")]
fn stacks() -> Vec<(String, Vec<u64>)> {
    telltale_net::stacks::capture(Duration::from_secs(5))
        .into_iter()
        .map(|s| {
            let frames = s
                .frames
                .into_iter()
                .map(|f| u64::try_from(f).unwrap_or_default())
                .collect();
            (format!("{} ({})", s.name, s.tid), frames)
        })
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn stacks() -> Vec<(String, Vec<u64>)> {
    Vec::new()
}

/// Writes `text` to `path`, replacing it, mode 0640 where the platform has modes.
fn write_private(path: &Path, text: &str) -> io::Result<()> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o640);
    o.open(path)?.write_all(text.as_bytes())
}

/// `<dir>/hang-<UTC time>.txt` (the directory 0750, the file 0640), then only the newest
/// [`KEEP_DUMPS`] are kept.
pub(crate) fn write_dump(dir: &Path, unix: u64, text: &str) -> io::Result<PathBuf> {
    make_dir(dir)?;
    let stamp: String = telltale_api::time::format_us(unix * 1_000_000)
        .chars()
        .take(19)
        .filter(|c| *c != '-' && *c != ':')
        .collect();
    let path = dir.join(format!("hang-{stamp}Z.txt"));
    write_private(&path, text)?;
    prune(dir);
    Ok(path)
}

/// Removes all but the newest [`KEEP_DUMPS`] dumps (the names sort by time).
fn prune(dir: &Path) {
    let mut names = dump_names(dir);
    names.sort();
    let extra = names.len().saturating_sub(KEEP_DUMPS);
    for n in names.into_iter().take(extra) {
        let _ = fs::remove_file(dir.join(n));
    }
}

/// The names of the dumps in `dir`.
pub(crate) fn dump_names(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| {
                    n.starts_with("hang-")
                        && Path::new(n)
                            .extension()
                            .is_some_and(|e| e.eq_ignore_ascii_case("txt"))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `dir`, `0750` where the platform has modes.
fn make_dir(dir: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o750);
    b.create(dir)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---- the thread -------------------------------------------------------------------------------

/// Starts the watchdog once the listeners are bound. `stop` ends it at shutdown, so a node that
/// is draining isn't mistaken for a stuck one.
pub(crate) fn spawn(
    cfg: &Config,
    handle: tokio::runtime::Handle,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    let s = shared();
    s.enabled.store(cfg.watchdog.enabled, Ordering::Relaxed);
    let settings = Settings::of(cfg);
    s.last_action
        .store(last_action(&settings.dir), Ordering::Relaxed);
    if !cfg.watchdog.enabled {
        return;
    }
    note_previous_restart(&settings.dir, unix_now());
    let runtime = handle.clone();
    let live = Live {
        handle,
        udp: udp_listener(cfg),
    };
    let listener = live.udp;
    let started = Instant::now();
    let mut writer = Writer {
        dir: settings.dir.clone(),
        started,
        runtime: Some(runtime),
    };
    let mut watchdog = Watchdog::new(live, settings, started);
    let thread = std::thread::Builder::new()
        .name("telltale-watchdog".to_owned())
        .spawn(move || {
            run(&mut watchdog, &mut writer, &stop, CHECK_EVERY, |code| {
                std::process::exit(code)
            });
        });
    match thread {
        Ok(_) => info!(
            listener = ?listener,
            "the watchdog is on: a node that stops answering writes a dump and restarts"
        ),
        Err(e) => warn!("the watchdog couldn't start: {e}"),
    }
}

/// The rounds, `every` apart, until `stop` or a restart. `exit` ends the process.
pub(crate) fn run<P: Probes>(
    watchdog: &mut Watchdog<P>,
    evidence: &mut dyn Evidence,
    stop: &tokio::sync::watch::Receiver<bool>,
    every: Duration,
    exit: impl Fn(i32),
) {
    loop {
        // Waits in slices of at most a second, so a shutdown ends it at once.
        let slice = every.min(Duration::from_secs(1));
        let mut waited = Duration::ZERO;
        while waited < every {
            std::thread::sleep(slice);
            waited += slice;
            if *stop.borrow() {
                return;
            }
        }
        match watchdog.tick(Instant::now(), unix_now(), evidence) {
            Outcome::Quiet => {}
            Outcome::Dumped(path) => error!(
                dump = ?path,
                "the node stopped answering: the watchdog wrote its dump and the node keeps running"
            ),
            Outcome::Restart(path) => {
                error!(
                    dump = ?path,
                    "the node stopped answering: the watchdog wrote its dump and restarts the process"
                );
                // The lines that say why reach the log files before the process ends.
                crate::support_log::global().flush();
                if !*stop.borrow() {
                    exit(EXIT_STATUS);
                    return;
                }
            }
        }
    }
}

/// REQ: OPS-012 — test builds only (`--features wedge-test`): `TT_WEDGE_AFTER_SECS=n` blocks
/// every runtime worker `n` seconds after start, as a deadlock would. The UDP workers have threads
/// of their own and keep answering, so the runtime check is the one that fails.
#[cfg(feature = "wedge-test")]
pub(crate) fn wedge_for_test(handle: &tokio::runtime::Handle) {
    let Some(after) = std::env::var("TT_WEDGE_AFTER_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    else {
        return;
    };
    let handle = handle.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(after));
        // More tasks than any runtime has workers: each one holds a worker.
        for _ in 0..512 {
            handle.spawn(async { wedge_here() });
        }
    });
}

/// Where the blocked workers sit, so a stack in a dump can be recognised.
#[cfg(feature = "wedge-test")]
#[inline(never)]
fn wedge_here() {
    std::thread::sleep(Duration::from_secs(3600));
}

/// The newest dump's time, from the files (0 for none).
fn last_action(dir: &Path) -> u64 {
    let mut newest = 0;
    for n in dump_names(dir) {
        let t = fs::metadata(dir.join(n))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        newest = newest.max(t);
    }
    newest
}

/// Says in the log when the previous run was restarted by the watchdog (within a day).
fn note_previous_restart(dir: &Path, unix: u64) {
    if let Some(t) = read_restarts(dir).last().copied()
        && t.saturating_add(24 * HOUR_SECS) > unix
    {
        warn!(
            "the previous run was restarted by the watchdog at {}: its dump is in {}",
            telltale_api::time::format_us(t * 1_000_000),
            dir.display()
        );
    }
}

#[cfg(test)]
#[path = "watchdog_tests.rs"]
mod tests;
