//! REQ: CLU-008 (T6.11) — the machine a node runs on: memory, CPU, disk, temperature, and
//! process limits, for the Cluster page, `/metrics`, and alerts.
//!
//! A background thread samples every 15 s, off the DNS path, straight from `/proc`, `/sys`,
//! and the cgroup files (v2, else v1), so it works in the `FROM scratch` image without any
//! tool. Anything that can't be read is left out and named in `unavailable`; collection never
//! fails the node (CLU-004). Parsers take file contents, so tests use fixtures.

// Display conversions of bounded values: byte counts and per-mille to f64 for Prometheus and
// the API, rates and uptimes back to integers. Precision loss above 2^52 bytes is irrelevant.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use telltale_cluster::wire::HostStats;

/// How often the collector samples.
pub(crate) const INTERVAL: Duration = Duration::from_secs(15);
/// Samples kept for this node: one hour.
const HISTORY: usize = telltale_cluster::net::HOST_HISTORY;

/// The latest sample and the last hour, shared with the API, heartbeats, and `/metrics`.
#[derive(Default, Debug)]
pub(crate) struct HostMonitor {
    latest: Mutex<Option<HostStats>>,
    history: Mutex<VecDeque<HostStats>>,
}

impl HostMonitor {
    pub(crate) fn latest(&self) -> Option<HostStats> {
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Oldest first.
    pub(crate) fn history(&self) -> Vec<HostStats> {
        self.history
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    fn record(&self, s: HostStats) {
        {
            let mut h = self.history.lock().unwrap_or_else(PoisonError::into_inner);
            if h.len() == HISTORY {
                h.pop_front();
            }
            h.push_back(s.clone());
        }
        *self.latest.lock().unwrap_or_else(PoisonError::into_inner) = Some(s);
    }

    /// Starts the sampling thread for a node whose data lives in `data_dir`.
    pub(crate) fn spawn(self: &std::sync::Arc<Self>, data_dir: PathBuf) {
        let me = std::sync::Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("host-stats".into())
            .spawn(move || {
                telltale_net::background_thread();
                let mut c = Collector::new(data_dir);
                loop {
                    me.record(c.sample());
                    std::thread::sleep(INTERVAL);
                }
            });
        if let Err(e) = spawned {
            tracing::warn!(error = %e, "host statistics are off: couldn't start their thread");
        }
    }
}

/// Warning thresholds (T6.11). The alert rules in the Helm chart use the same numbers.
pub(crate) const DISK_WARN_PERCENT: f64 = 90.0;
pub(crate) const MEM_WARN_PERCENT: f64 = 90.0;
pub(crate) const TEMP_WARN_C: f64 = 80.0;
pub(crate) const CLOCK_WARN_MS: i64 = 2_000;

fn pct(used: u64, total: u64) -> Option<f64> {
    (total > 0).then(|| ((used as f64 / total as f64) * 1000.0).round() / 10.0)
}

/// The API's view of a sample: sizes, percentages, and what looks wrong. `history` (oldest
/// first) also tells whether OOM kills happened within it.
pub(crate) fn info(
    s: &HostStats,
    history: &[HostStats],
    clock_offset_ms: Option<i64>,
) -> telltale_api::model::HostInfo {
    let milli = |v: Option<u32>| v.map(|v| f64::from(v) / 1000.0);
    let tenth = |v: Option<u32>| v.map(|v| f64::from(v) / 10.0);
    let mem_used = match (s.mem_total, s.mem_available) {
        (Some(t), Some(a)) => pct(t.saturating_sub(a), t),
        _ => None,
    };
    let cg_used = match (s.cgroup_mem_limit, s.cgroup_mem_current) {
        (Some(l), Some(c)) => pct(c, l),
        _ => None,
    };
    let disk_used = match (s.disk_total, s.disk_free) {
        (Some(t), Some(f)) => pct(t.saturating_sub(f), t),
        _ => None,
    };
    let temp = s.temp_millic.map(|t| f64::from(t) / 1000.0);
    let mut warnings = Vec::new();
    if let Some(d) = disk_used.filter(|d| *d >= DISK_WARN_PERCENT) {
        warnings.push(format!("the data disk is {d:.0}% full"));
    }
    if let Some(m) = mem_used.filter(|m| *m >= MEM_WARN_PERCENT) {
        warnings.push(format!("the host's memory is {m:.0}% used"));
    }
    if let Some(c) = cg_used.filter(|c| *c >= MEM_WARN_PERCENT) {
        warnings.push(format!("the container uses {c:.0}% of its memory limit"));
    }
    let oom_before = history.first().and_then(|h| h.oom_kills);
    if let (Some(now), Some(then)) = (s.oom_kills, oom_before)
        && now > then
    {
        warnings.push(format!(
            "{} out-of-memory kill(s) in the last hour",
            now - then
        ));
    }
    if let Some(t) = temp.filter(|t| *t >= TEMP_WARN_C) {
        warnings.push(format!("running hot: {t:.0} °C"));
    }
    if let Some(o) = clock_offset_ms.filter(|o| o.abs() >= CLOCK_WARN_MS) {
        warnings.push(format!(
            "its clock is {:.1} s {} this node's",
            o.abs() as f64 / 1000.0,
            if o > 0 { "ahead of" } else { "behind" }
        ));
    }
    telltale_api::model::HostInfo {
        sampled_at: telltale_api::time::format_us(s.ts_ms.saturating_mul(1000)),
        os: Some(s.os.clone()).filter(|v| !v.is_empty()),
        kernel: Some(s.kernel.clone()).filter(|v| !v.is_empty()),
        arch: s.arch.clone(),
        host_uptime_seconds: s.host_uptime_s,
        cpus: s.cpus,
        load1: milli(s.load1_milli),
        load5: milli(s.load5_milli),
        load15: milli(s.load15_milli),
        cpu_percent: tenth(s.cpu_permille),
        mem_total_bytes: s.mem_total,
        mem_available_bytes: s.mem_available,
        mem_used_percent: mem_used,
        swap_total_bytes: s.swap_total,
        swap_used_bytes: s
            .swap_total
            .zip(s.swap_free)
            .map(|(t, f)| t.saturating_sub(f)),
        cgroup_mem_limit_bytes: s.cgroup_mem_limit,
        cgroup_mem_used_bytes: s.cgroup_mem_current,
        cgroup_mem_used_percent: cg_used,
        oom_kills: s.oom_kills,
        cgroup_cpu_quota_cores: milli(s.cgroup_cpu_quota_milli),
        throttled_percent: tenth(s.throttled_permille),
        disk_total_bytes: s.disk_total,
        disk_free_bytes: s.disk_free,
        disk_used_percent: disk_used,
        qlog_bytes: s.qlog_bytes,
        snapshot_bytes: s.snapshot_bytes,
        write_bytes_per_second: s.write_bytes_per_s,
        process_rss_bytes: s.process_rss,
        open_fds: s.open_fds,
        max_fds: s.max_fds,
        threads: s.threads,
        temperature_c: temp,
        clock_offset_ms,
        unavailable: s.unavailable.clone(),
        warnings,
    }
}

/// The latest sample plus the last hour, for one node; `None` before the first sample.
pub(crate) fn report(
    latest: Option<HostStats>,
    history: &[HostStats],
    clock_offset_ms: Option<i64>,
) -> Option<telltale_api::model::HostReport> {
    let latest = latest?;
    let points = history
        .iter()
        .map(|h| {
            let i = info(h, &[], None);
            telltale_api::model::HostPoint {
                t: h.ts_ms / 1000,
                cpu_percent: i.cpu_percent,
                mem_used_percent: i.cgroup_mem_used_percent.or(i.mem_used_percent),
                load1: i.load1,
                disk_used_percent: i.disk_used_percent,
                temperature_c: i.temperature_c,
            }
        })
        .collect();
    Some(telltale_api::model::HostReport {
        latest: info(&latest, history, clock_offset_ms),
        history: points,
    })
}

/// One sample of a metric family: its labels and value (absent = not reported).
type Row<'a> = (&'a [(&'a str, &'a str)], Option<f64>);

/// REQ: OBS-005 (T6.11) — the latest sample as Prometheus metrics. Values a node can't read
/// are left out rather than reported as zero, so alerts don't fire on them.
#[allow(clippy::too_many_lines)] // one metric family after another
pub(crate) fn render(w: &mut telltale_telemetry::prom::PromWriter, s: &HostStats) {
    let fam = |w: &mut telltale_telemetry::prom::PromWriter,
               name: &str,
               kind: &str,
               help: &str,
               rows: &[Row<'_>]| {
        if rows.iter().any(|(_, v)| v.is_some()) {
            w.family(name, kind, help);
            for (labels, v) in rows {
                if let Some(v) = v {
                    w.sample(name, labels, v);
                }
            }
        }
    };
    let f = |v: Option<u64>| v.map(|v| v as f64);
    let milli = |v: Option<u32>| v.map(|v| f64::from(v) / 1000.0);
    w.family(
        "telltale_host_info",
        "gauge",
        "The machine this node runs on.",
    )
    .sample(
        "telltale_host_info",
        &[
            ("os", s.os.as_str()),
            ("kernel", s.kernel.as_str()),
            ("arch", s.arch.as_str()),
        ],
        1,
    );
    fam(
        w,
        "telltale_host_memory_bytes",
        "gauge",
        "Host memory: total, available (MemAvailable), swap total and free.",
        &[
            (&[("kind", "total")], f(s.mem_total)),
            (&[("kind", "available")], f(s.mem_available)),
            (&[("kind", "swap_total")], f(s.swap_total)),
            (&[("kind", "swap_free")], f(s.swap_free)),
        ],
    );
    fam(
        w,
        "telltale_cgroup_memory_bytes",
        "gauge",
        "This container's memory limit and usage (cgroup), when limited.",
        &[
            (&[("kind", "limit")], f(s.cgroup_mem_limit)),
            (&[("kind", "current")], f(s.cgroup_mem_current)),
        ],
    );
    fam(
        w,
        "telltale_cgroup_oom_kills_total",
        "counter",
        "Processes the kernel killed in this container for lack of memory.",
        &[(&[], f(s.oom_kills))],
    );
    fam(
        w,
        "telltale_host_cpus",
        "gauge",
        "CPUs on the host.",
        &[(&[], s.cpus.map(f64::from))],
    );
    fam(
        w,
        "telltale_host_load",
        "gauge",
        "Host load average.",
        &[
            (&[("window", "1m")], milli(s.load1_milli)),
            (&[("window", "5m")], milli(s.load5_milli)),
            (&[("window", "15m")], milli(s.load15_milli)),
        ],
    );
    fam(
        w,
        "telltale_host_cpu_busy_ratio",
        "gauge",
        "Share of host CPU time busy over the last 15 s.",
        &[(&[], milli(s.cpu_permille))],
    );
    fam(
        w,
        "telltale_cgroup_cpu_quota_cores",
        "gauge",
        "This container's CPU quota in cores, when limited.",
        &[(&[], milli(s.cgroup_cpu_quota_milli))],
    );
    fam(
        w,
        "telltale_cgroup_throttled_ratio",
        "gauge",
        "Share of CPU periods this container was throttled over the last 15 s.",
        &[(&[], milli(s.throttled_permille))],
    );
    fam(
        w,
        "telltale_data_filesystem_bytes",
        "gauge",
        "The filesystem holding the data directory: total and free (for unprivileged users).",
        &[
            (&[("kind", "total")], f(s.disk_total)),
            (&[("kind", "free")], f(s.disk_free)),
        ],
    );
    fam(
        w,
        "telltale_data_bytes",
        "gauge",
        "Space used by the query log and filter snapshots.",
        &[
            (&[("kind", "qlog")], f(s.qlog_bytes)),
            (&[("kind", "snapshots")], f(s.snapshot_bytes)),
        ],
    );
    fam(
        w,
        "telltale_write_bytes_per_second",
        "gauge",
        "Bytes this process wrote to storage per second over the last 15 s.",
        &[(&[], f(s.write_bytes_per_s))],
    );
    fam(
        w,
        "telltale_host_uptime_seconds",
        "gauge",
        "Seconds since the host booted.",
        &[(&[], f(s.host_uptime_s))],
    );
    fam(
        w,
        "telltale_host_temperature_celsius",
        "gauge",
        "The hottest thermal zone on the board.",
        &[(&[], s.temp_millic.map(|t| f64::from(t) / 1000.0))],
    );
    fam(
        w,
        "telltale_open_fds",
        "gauge",
        "Open file descriptors.",
        &[(&[], s.open_fds.map(f64::from))],
    );
    fam(
        w,
        "telltale_max_fds",
        "gauge",
        "The soft limit on open file descriptors.",
        &[(&[], s.max_fds.map(f64::from))],
    );
    fam(
        w,
        "telltale_threads",
        "gauge",
        "Threads in this process.",
        &[(&[], s.threads.map(f64::from))],
    );
}

/// Counters from the previous sample, for rates.
#[derive(Default, Clone, Copy)]
struct Prev {
    at: Option<Instant>,
    cpu: Option<(u64, u64)>,
    periods: Option<(u64, u64)>,
    written: Option<u64>,
}

pub(crate) struct Collector {
    proc_root: PathBuf,
    sys_root: PathBuf,
    etc_root: PathBuf,
    data_dir: PathBuf,
    prev: Prev,
}

impl Collector {
    pub(crate) fn new(data_dir: PathBuf) -> Self {
        Self::with_roots("/proc".into(), "/sys".into(), "/etc".into(), data_dir)
    }

    pub(crate) fn with_roots(
        proc_root: PathBuf,
        sys_root: PathBuf,
        etc_root: PathBuf,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            proc_root,
            sys_root,
            etc_root,
            data_dir,
            prev: Prev::default(),
        }
    }

    /// One sample. Rates (CPU, throttling, writes) need two samples, so the first lacks them.
    #[allow(clippy::too_many_lines)] // one source after another
    pub(crate) fn sample(&mut self) -> HostStats {
        let now = Instant::now();
        let mut s = HostStats {
            ts_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            arch: std::env::consts::ARCH.to_owned(),
            ..HostStats::default()
        };
        let mut missing = Vec::new();
        let elapsed = self.prev.at.map(|t| now.duration_since(t));

        match read(&self.proc_root, "meminfo").map(|t| meminfo(&t)) {
            Some(m) => {
                s.mem_total = m.total;
                s.mem_available = m.available;
                s.swap_total = m.swap_total;
                s.swap_free = m.swap_free;
            }
            None => missing.push("memory"),
        }
        match read(&self.proc_root, "loadavg").and_then(|t| loadavg(&t)) {
            Some((a, b, c)) => {
                (s.load1_milli, s.load5_milli, s.load15_milli) = (Some(a), Some(b), Some(c));
            }
            None => missing.push("load"),
        }
        match read(&self.proc_root, "stat") {
            Some(t) => {
                s.cpus = Some(cpu_count(&t)).filter(|n| *n > 0);
                if let Some(now_cpu) = cpu_times(&t) {
                    s.cpu_permille = self.prev.cpu.and_then(|was| busy_permille(was, now_cpu));
                    self.prev.cpu = Some(now_cpu);
                }
            }
            None => missing.push("cpu"),
        }
        s.host_uptime_s = read(&self.proc_root, "uptime")
            .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok())
            .map(|f| f as u64);
        s.kernel = read(&self.proc_root, "sys/kernel/osrelease")
            .map(|t| t.trim().to_owned())
            .unwrap_or_default();
        s.os = read(&self.etc_root, "os-release")
            .map(|t| os_name(&t))
            .unwrap_or_default();
        if s.os.is_empty() {
            missing.push("os");
        }

        // This process.
        match read(&self.proc_root, "self/status") {
            Some(t) => {
                s.process_rss = status_kib(&t, "VmRSS:").map(|k| k * 1024);
                s.threads = status_kib(&t, "Threads:").and_then(|n| u32::try_from(n).ok());
            }
            None => missing.push("process"),
        }
        s.open_fds = std::fs::read_dir(self.proc_root.join("self/fd"))
            .ok()
            .map(|d| u32::try_from(d.count()).unwrap_or(u32::MAX));
        s.max_fds = read(&self.proc_root, "self/limits").and_then(|t| max_open_files(&t));
        if let Some(w) = read(&self.proc_root, "self/io").and_then(|t| io_write_bytes(&t)) {
            if let (Some(was), Some(dt)) = (self.prev.written, elapsed) {
                let secs = dt.as_secs_f64().max(0.001);
                s.write_bytes_per_s = Some((w.saturating_sub(was) as f64 / secs) as u64);
            }
            self.prev.written = Some(w);
        }

        // The container's limits.
        match self.cgroup() {
            Some(cg) => {
                s.cgroup_mem_limit = cg.mem_limit;
                s.cgroup_mem_current = cg.mem_current;
                s.oom_kills = cg.oom_kills;
                s.cgroup_cpu_quota_milli = cg.cpu_quota_milli;
                if let Some(p) = cg.periods {
                    s.throttled_permille =
                        self.prev.periods.and_then(|was| throttled_permille(was, p));
                    self.prev.periods = Some(p);
                }
            }
            None => missing.push("cgroup"),
        }

        // Temperature: the hottest zone the board exposes (Pi: the SoC).
        s.temp_millic = hottest_zone(&self.sys_root.join("class/thermal"));
        if s.temp_millic.is_none() {
            missing.push("thermal");
        }

        // Disk.
        match telltale_net::filesystem_space(&self.data_dir) {
            Some((total, free)) => (s.disk_total, s.disk_free) = (Some(total), Some(free)),
            None => missing.push("disk"),
        }
        s.qlog_bytes = dir_size(&self.data_dir.join("qlog"));
        s.snapshot_bytes = dir_size(&self.data_dir.join("snapshots"));

        s.unavailable = missing.into_iter().map(str::to_owned).collect();
        self.prev.at = Some(now);
        s
    }

    /// The cgroup this process is in: v2 (one unified tree), else v1 (per controller).
    fn cgroup(&self) -> Option<Cgroup> {
        let table = read(&self.proc_root, "self/cgroup")?;
        let base = self.sys_root.join("fs/cgroup");
        // v2: "0::/path". In a container the path is usually "/" and the root is its own.
        if let Some(path) = table.lines().find_map(|l| l.strip_prefix("0::")) {
            let dir = [base.join(path.trim_start_matches('/')), base.clone()]
                .into_iter()
                .find(|d| d.join("memory.current").exists() || d.join("cpu.max").exists())?;
            let r = |f: &str| std::fs::read_to_string(dir.join(f)).ok();
            return Some(Cgroup {
                mem_limit: r("memory.max").and_then(|t| limit(&t)),
                mem_current: r("memory.current").and_then(|t| t.trim().parse().ok()),
                oom_kills: r("memory.events").and_then(|t| keyed(&t, "oom_kill")),
                cpu_quota_milli: r("cpu.max").and_then(|t| cpu_max(&t)),
                periods: r("cpu.stat")
                    .and_then(|t| Some((keyed(&t, "nr_periods")?, keyed(&t, "nr_throttled")?))),
            });
        }
        // v1: "N:controller:/path".
        let v1 = |ctl: &str| {
            let path = table.lines().find_map(|l| {
                let mut it = l.splitn(3, ':');
                let (_, ctls, path) = (it.next()?, it.next()?, it.next()?);
                ctls.split(',')
                    .any(|c| c == ctl)
                    .then(|| path.trim_start_matches('/').to_owned())
            })?;
            let root = base.join(ctl);
            [root.join(&path), root].into_iter().find(|d| d.is_dir())
        };
        let mem = v1("memory");
        let cpu = v1("cpu");
        if mem.is_none() && cpu.is_none() {
            return None;
        }
        let r = |d: &Option<PathBuf>, f: &str| {
            d.as_ref()
                .and_then(|d| std::fs::read_to_string(d.join(f)).ok())
        };
        let quota = r(&cpu, "cpu.cfs_quota_us").and_then(|t| t.trim().parse::<i64>().ok());
        let period = r(&cpu, "cpu.cfs_period_us").and_then(|t| t.trim().parse::<i64>().ok());
        Some(Cgroup {
            mem_limit: r(&mem, "memory.limit_in_bytes").and_then(|t| limit(&t)),
            mem_current: r(&mem, "memory.usage_in_bytes").and_then(|t| t.trim().parse().ok()),
            oom_kills: r(&mem, "memory.oom_control").and_then(|t| keyed(&t, "oom_kill")),
            cpu_quota_milli: match (quota, period) {
                (Some(q), Some(p)) if q > 0 && p > 0 => u32::try_from(q * 1000 / p).ok(),
                _ => None,
            },
            periods: r(&cpu, "cpu.stat")
                .and_then(|t| Some((keyed(&t, "nr_periods")?, keyed(&t, "nr_throttled")?))),
        })
    }
}

struct Cgroup {
    mem_limit: Option<u64>,
    mem_current: Option<u64>,
    oom_kills: Option<u64>,
    cpu_quota_milli: Option<u32>,
    /// `(nr_periods, nr_throttled)`.
    periods: Option<(u64, u64)>,
}

#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct MemInfo {
    pub(crate) total: Option<u64>,
    pub(crate) available: Option<u64>,
    pub(crate) swap_total: Option<u64>,
    pub(crate) swap_free: Option<u64>,
}

/// `/proc/meminfo`, in bytes.
pub(crate) fn meminfo(text: &str) -> MemInfo {
    let get = |key: &str| status_kib(text, key).map(|k| k * 1024);
    MemInfo {
        total: get("MemTotal:"),
        available: get("MemAvailable:"),
        swap_total: get("SwapTotal:"),
        swap_free: get("SwapFree:"),
    }
}

/// A `Key:   123 kB` line's number (also plain counts like `Threads:  9`).
pub(crate) fn status_kib(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix(key))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
}

/// `/proc/loadavg` → the three averages times 1000.
pub(crate) fn loadavg(text: &str) -> Option<(u32, u32, u32)> {
    let mut it = text
        .split_whitespace()
        .map(|v| v.parse::<f64>().ok().map(|f| (f * 1000.0).round() as u32));
    Some((it.next()??, it.next()??, it.next()??))
}

/// `/proc/stat`'s first line → `(busy, total)` jiffies; idle and iowait count as idle.
pub(crate) fn cpu_times(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    if v.len() < 4 {
        return None;
    }
    // user nice system idle iowait irq softirq steal (guest time is already in user/nice).
    let total: u64 = v.iter().take(8).sum();
    let idle = v[3] + v.get(4).copied().unwrap_or(0);
    Some((total - idle, total))
}

/// CPUs listed in `/proc/stat` (`cpu0`, `cpu1`, …).
pub(crate) fn cpu_count(text: &str) -> u32 {
    let n = text
        .lines()
        .filter(|l| l.starts_with("cpu") && l.as_bytes().get(3).is_some_and(u8::is_ascii_digit))
        .count();
    u32::try_from(n).unwrap_or(0)
}

pub(crate) fn busy_permille(was: (u64, u64), now: (u64, u64)) -> Option<u32> {
    let busy = now.0.checked_sub(was.0)?;
    let total = now.1.checked_sub(was.1).filter(|t| *t > 0)?;
    u32::try_from(busy * 1000 / total).ok()
}

pub(crate) fn throttled_permille(was: (u64, u64), now: (u64, u64)) -> Option<u32> {
    let periods = now.0.checked_sub(was.0).filter(|p| *p > 0)?;
    let throttled = now.1.checked_sub(was.1)?;
    u32::try_from(throttled * 1000 / periods).ok()
}

/// A cgroup memory limit: `max` (v2) or a huge number (v1, "unlimited") means none.
pub(crate) fn limit(text: &str) -> Option<u64> {
    let v: u64 = text.trim().parse().ok()?;
    (v < 1 << 60).then_some(v)
}

/// `cpu.max` (v2): `"max 100000"` (no quota) or `"200000 100000"` (2 CPUs = 2000).
pub(crate) fn cpu_max(text: &str) -> Option<u32> {
    let mut it = text.split_whitespace();
    let quota: u64 = it.next()?.parse().ok()?;
    let period: u64 = it.next()?.parse().ok().filter(|p| *p > 0)?;
    u32::try_from(quota * 1000 / period).ok()
}

/// `key value` lines (cgroup `memory.events`, `cpu.stat`, v1 `memory.oom_control`).
pub(crate) fn keyed(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == key).then(|| it.next()?.parse().ok())?
    })
}

/// `/proc/self/limits` → the soft "Max open files".
pub(crate) fn max_open_files(text: &str) -> Option<u32> {
    let rest = text
        .lines()
        .find_map(|l| l.strip_prefix("Max open files"))?;
    rest.split_whitespace().next()?.parse().ok()
}

/// `/proc/self/io` → `write_bytes` (what reached the storage layer).
pub(crate) fn io_write_bytes(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix("write_bytes:")?.trim().parse().ok())
}

/// `/etc/os-release` → `PRETTY_NAME`.
pub(crate) fn os_name(text: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim().trim_matches('"').to_owned())
        .unwrap_or_default()
}

fn hottest_zone(dir: &Path) -> Option<i32> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("thermal_zone"))
        .filter_map(|e| {
            std::fs::read_to_string(e.path().join("temp"))
                .ok()?
                .trim()
                .parse::<i32>()
                .ok()
        })
        .max()
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel)).ok()
}

/// Bytes under `dir` (files only; symlinks not followed). `None` when it doesn't exist.
fn dir_size(dir: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(dir).ok()?;
    if !meta.is_dir() {
        return None;
    }
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(m) = e.file_type() else { continue };
            if m.is_dir() {
                stack.push(e.path());
            } else if m.is_file() {
                total += e.metadata().map_or(0, |m| m.len());
            }
        }
    }
    Some(total)
}

#[cfg(test)]
mod tests;
