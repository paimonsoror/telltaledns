use super::*;
use std::fs;

const MEMINFO: &str = "MemTotal:        3884144 kB\nMemFree:          212340 kB\nMemAvailable:    2911232 kB\nBuffers:           88016 kB\nSwapTotal:        102396 kB\nSwapFree:          98300 kB\n";
const STAT_A: &str = "cpu  1000 0 500 8000 500 0 0 0 0 0\ncpu0 500 0 250 4000 250 0 0 0 0 0\ncpu1 500 0 250 4000 250 0 0 0 0 0\nintr 1 2 3\n";
const STAT_B: &str = "cpu  1300 0 600 8500 600 0 0 0 0 0\ncpu0 650 0 300 4250 300 0 0 0 0 0\ncpu1 650 0 300 4250 300 0 0 0 0 0\nintr 1 2 3\n";

#[test]
fn clu_008_meminfo_in_bytes() {
    let m = meminfo(MEMINFO);
    assert_eq!(m.total, Some(3_884_144 * 1024));
    assert_eq!(m.available, Some(2_911_232 * 1024));
    assert_eq!(m.swap_total, Some(102_396 * 1024));
    assert_eq!(m.swap_free, Some(98_300 * 1024));
    assert_eq!(meminfo(""), MemInfo::default());
}

#[test]
fn clu_008_load_cpu_and_throttling() {
    assert_eq!(
        loadavg("0.52 1.07 2.00 3/451 12345\n"),
        Some((520, 1070, 2000))
    );
    assert_eq!(loadavg("garbage"), None);
    assert_eq!(cpu_count(STAT_A), 2);
    let (a, b) = (cpu_times(STAT_A).unwrap(), cpu_times(STAT_B).unwrap());
    // busy grew 300 + 100 = 400 of 1000 jiffies.
    assert_eq!(busy_permille(a, b), Some(400));
    assert_eq!(
        busy_permille(b, a),
        None,
        "a counter going backwards is no sample"
    );
    assert_eq!(throttled_permille((100, 10), (200, 35)), Some(250));
    assert_eq!(throttled_permille((100, 10), (100, 10)), None);
}

#[test]
fn clu_008_cgroup_values() {
    assert_eq!(limit("max\n"), None);
    assert_eq!(limit("536870912\n"), Some(536_870_912));
    assert_eq!(limit("9223372036854771712\n"), None, "v1's 'unlimited'");
    assert_eq!(cpu_max("max 100000\n"), None);
    assert_eq!(cpu_max("150000 100000\n"), Some(1500));
    assert_eq!(
        keyed("low 0\nhigh 0\nmax 4\noom 2\noom_kill 1\n", "oom_kill"),
        Some(1)
    );
    assert_eq!(
        keyed("oom_kill_disable 0\nunder_oom 0\noom_kill 3\n", "oom_kill"),
        Some(3)
    );
    assert_eq!(keyed("nr_periods 10\n", "nr_throttled"), None);
}

#[test]
fn clu_008_process_files() {
    let status = "Name:\ttelltale\nVmRSS:\t   61234 kB\nThreads:\t9\n";
    assert_eq!(status_kib(status, "VmRSS:"), Some(61_234));
    assert_eq!(status_kib(status, "Threads:"), Some(9));
    let limits = "Limit                     Soft Limit           Hard Limit           Units\nMax open files            65536                524288               files\n";
    assert_eq!(max_open_files(limits), Some(65_536));
    assert_eq!(
        io_write_bytes("rchar: 1\nwrite_bytes: 4096\ncancelled_write_bytes: 0\n"),
        Some(4096)
    );
    assert_eq!(
        os_name("NAME=\"Debian\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"),
        "Debian GNU/Linux 12 (bookworm)"
    );
}

/// A fake machine: `/proc`, `/sys` and `/etc` under one temp dir.
fn machine(v2: bool) -> (tempfile::TempDir, Collector) {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let w = |rel: &str, text: &str| {
        let f = p.join(rel);
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(f, text).unwrap();
    };
    w("proc/meminfo", MEMINFO);
    w("proc/loadavg", "0.52 1.07 2.00 3/451 12345\n");
    w("proc/stat", STAT_A);
    w("proc/uptime", "12345.67 20000.00\n");
    w("proc/sys/kernel/osrelease", "6.6.51+rpt-rpi-v8\n");
    w("proc/self/status", "VmRSS:\t   61234 kB\nThreads:\t9\n");
    w(
        "proc/self/limits",
        "Max open files            1024                 4096                 files\n",
    );
    w("proc/self/io", "write_bytes: 1000\n");
    fs::create_dir_all(p.join("proc/self/fd")).unwrap();
    for i in 0..3 {
        fs::write(p.join(format!("proc/self/fd/{i}")), "").unwrap();
    }
    w(
        "etc/os-release",
        "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
    );
    w("sys/class/thermal/thermal_zone0/temp", "48250\n");
    w("sys/class/thermal/thermal_zone1/temp", "51000\n");
    if v2 {
        w("proc/self/cgroup", "0::/system.slice/telltale.service\n");
        let cg = "sys/fs/cgroup/system.slice/telltale.service";
        w(&format!("{cg}/memory.max"), "536870912\n");
        w(&format!("{cg}/memory.current"), "73400320\n");
        w(
            &format!("{cg}/memory.events"),
            "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
        );
        w(&format!("{cg}/cpu.max"), "200000 100000\n");
        w(
            &format!("{cg}/cpu.stat"),
            "usage_usec 1\nnr_periods 100\nnr_throttled 5\nthrottled_usec 9\n",
        );
    } else {
        w(
            "proc/self/cgroup",
            "12:memory:/docker/abc\n5:cpu,cpuacct:/docker/abc\n",
        );
        w(
            "sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes",
            "268435456\n",
        );
        w(
            "sys/fs/cgroup/memory/docker/abc/memory.usage_in_bytes",
            "10485760\n",
        );
        w(
            "sys/fs/cgroup/memory/docker/abc/memory.oom_control",
            "oom_kill_disable 0\nunder_oom 0\noom_kill 2\n",
        );
        w("sys/fs/cgroup/cpu/docker/abc/cpu.cfs_quota_us", "50000\n");
        w("sys/fs/cgroup/cpu/docker/abc/cpu.cfs_period_us", "100000\n");
    }
    let data = p.join("data");
    fs::create_dir_all(data.join("qlog/2026/10/05")).unwrap();
    fs::write(data.join("qlog/2026/10/05/14.seg"), vec![0u8; 3000]).unwrap();
    fs::create_dir_all(data.join("snapshots/7")).unwrap();
    fs::write(data.join("snapshots/7/a.fst"), vec![0u8; 500]).unwrap();
    let c = Collector::with_roots(p.join("proc"), p.join("sys"), p.join("etc"), data);
    (tmp, c)
}

#[test]
fn clu_008_a_sample_from_a_cgroup_v2_machine() {
    let (tmp, mut c) = machine(true);
    let s = c.sample();
    assert_eq!(s.mem_total, Some(3_884_144 * 1024));
    assert_eq!((s.load1_milli, s.load15_milli), (Some(520), Some(2000)));
    assert_eq!(s.cpus, Some(2));
    assert_eq!(s.cpu_permille, None, "a rate needs two samples");
    assert_eq!(s.host_uptime_s, Some(12_345));
    assert_eq!(s.kernel, "6.6.51+rpt-rpi-v8");
    assert_eq!(s.os, "Debian GNU/Linux 12 (bookworm)");
    assert_eq!((s.process_rss, s.threads), (Some(61_234 * 1024), Some(9)));
    assert_eq!((s.open_fds, s.max_fds), (Some(3), Some(1024)));
    assert_eq!(s.cgroup_mem_limit, Some(536_870_912));
    assert_eq!(s.cgroup_mem_current, Some(73_400_320));
    assert_eq!(s.oom_kills, Some(0));
    assert_eq!(s.cgroup_cpu_quota_milli, Some(2000));
    assert_eq!(s.temp_millic, Some(51_000), "the hottest zone");
    assert_eq!((s.qlog_bytes, s.snapshot_bytes), (Some(3000), Some(500)));
    assert!(
        s.disk_total.is_some_and(|t| t > 0),
        "statvfs of a real directory"
    );
    assert!(s.unavailable.is_empty(), "{:?}", s.unavailable);

    // The second sample has rates.
    let p = tmp.path();
    fs::write(p.join("proc/stat"), STAT_B).unwrap();
    fs::write(p.join("proc/self/io"), "write_bytes: 1000000\n").unwrap();
    fs::write(
        p.join("sys/fs/cgroup/system.slice/telltale.service/cpu.stat"),
        "nr_periods 200\nnr_throttled 30\n",
    )
    .unwrap();
    let s = c.sample();
    assert_eq!(s.cpu_permille, Some(400));
    assert_eq!(s.throttled_permille, Some(250));
    assert!(s.write_bytes_per_s.is_some_and(|w| w > 0));
}

#[test]
fn clu_008_a_sample_from_a_cgroup_v1_container() {
    let (_tmp, mut c) = machine(false);
    let s = c.sample();
    assert_eq!(s.cgroup_mem_limit, Some(268_435_456));
    assert_eq!(s.cgroup_mem_current, Some(10_485_760));
    assert_eq!(s.oom_kills, Some(2));
    assert_eq!(s.cgroup_cpu_quota_milli, Some(500));
}

#[test]
fn clu_004_a_machine_without_proc_reports_what_is_missing_and_never_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path();
    let mut c = Collector::with_roots(p.join("proc"), p.join("sys"), p.join("etc"), p.join("data"));
    let s = c.sample();
    assert!(s.mem_total.is_none() && s.cpus.is_none() && s.temp_millic.is_none());
    for src in [
        "memory", "load", "cpu", "process", "cgroup", "thermal", "os",
    ] {
        assert!(
            s.unavailable.iter().any(|u| u == src),
            "{src} missing from {:?}",
            s.unavailable
        );
    }
    assert_eq!(s.arch, std::env::consts::ARCH);
}

#[test]
fn clu_008_history_keeps_one_hour() {
    let m = HostMonitor::default();
    for i in 0..(HISTORY as u64 + 10) {
        m.record(HostStats {
            ts_ms: i,
            ..HostStats::default()
        });
    }
    let h = m.history();
    assert_eq!(h.len(), HISTORY);
    assert_eq!(h.first().map(|s| s.ts_ms), Some(10));
    assert_eq!(m.latest().map(|s| s.ts_ms), Some(HISTORY as u64 + 9));
}
