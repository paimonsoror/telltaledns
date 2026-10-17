// REQ: OBS-013 (T3.13 AC) — a 14-day fixture of six devices with injected scenarios: each is
// found with evidence, the clean baseline yields nothing, and the findings are byte-identical
// to a committed golden file (CI runs this on x86-64 and arm64).

use super::*;

/// xorshift64*: a tiny deterministic PRNG for the fixture.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn wire(name: &str) -> Vec<u8> {
    let mut w = Vec::new();
    for l in name.split('.') {
        w.push(u8::try_from(l.len()).unwrap());
        w.extend_from_slice(l.as_bytes());
    }
    w.push(0);
    w
}

fn ip(last: u8) -> [u8; 16] {
    std::net::Ipv4Addr::new(192, 168, 1, last)
        .to_ipv6_mapped()
        .octets()
}

const DAY0: u64 = 1_790_000_000 / 86_400 * 86_400; // a midnight in 2026
const PHONE: u8 = 10;
const TV: u8 = 20;
const PLUG: u8 = 30;
const CAMERA: u8 = 40;
const LAPTOP: u8 = 50;
const NAS: u8 = 60;

/// Events for one hour: (ts, device, name).
fn hour_events(rng: &mut Rng, day: u64, h: u64, inject: bool) -> Vec<(u64, u8, String)> {
    let start = DAY0 + day * 86_400 + h * 3600;
    let mut ev = Vec::new();
    let mut add =
        |rng: &mut Rng, dev: u8, name: String| ev.push((start + rng.below(3600), dev, name));
    let daytime = (7..23).contains(&h);
    // Phone: diurnal, a fixed pool of 40 sites.
    for _ in 0..(if daytime {
        120 + rng.below(80)
    } else {
        4 + rng.below(6)
    }) {
        let n = format!("site{}.example", rng.below(40));
        add(rng, PHONE, n);
    }
    // TV: app traffic plus a steady telemetry domain (~120/h).
    for _ in 0..(30 + rng.below(30)) {
        let n = format!("cdn{}.stream.example", rng.below(5));
        add(rng, TV, n);
    }
    let burst = inject && day == 10 && h == 20;
    for _ in 0..(if burst { 4100 } else { 100 + rng.below(40) }) {
        add(rng, TV, "telemetry.vendor.example".into());
    }
    // Plug: two domains, a few times an hour; on day 11, 30 new domains.
    for _ in 0..(3 + rng.below(3)) {
        let n = ["plug-api.vendor.example", "time.vendor.example"]
            [usize::try_from(rng.below(2)).unwrap()];
        add(rng, PLUG, n.into());
    }
    if inject && day == 11 && h < 15 {
        for j in 0..2 {
            add(
                rng,
                PLUG,
                format!("odd{}.domain{}.test", h * 2 + j, h * 2 + j),
            );
        }
    }
    // Camera: irregular check-ins (every 10-30 min).
    for _ in 0..(2 + rng.below(4)) {
        add(rng, CAMERA, "cam.vendor.example".into());
    }
    // Laptop: diurnal, a pool of 80 plus 1-3 genuinely new domains a day.
    for _ in 0..(if daytime {
        80 + rng.below(60)
    } else {
        2 + rng.below(4)
    }) {
        let n = format!("work{}.example", rng.below(80));
        add(rng, LAPTOP, n);
    }
    if h == 12 {
        for j in 0..=rng.below(3) {
            add(rng, LAPTOP, format!("new{day}x{j}.example"));
        }
    }
    // NAS: quiet and steady.
    for _ in 0..(15 + rng.below(10)) {
        let n = format!("update{}.nas.example", rng.below(3));
        add(rng, NAS, n);
    }
    // Camera on day 12, hours 2-10: a beacon every 300 s ± 3 s.
    if inject && day == 12 && (2..10).contains(&h) {
        let mut t = start + 7;
        while t < start + 3600 {
            ev.push((t, CAMERA, "beacon.c2.example".into()));
            t += 297 + rng.below(7);
        }
    }
    ev.sort();
    ev
}

fn run(inject: bool) -> Engine {
    let mut rng = Rng(0x7e11_7a1e);
    let mut e = Engine::new(Settings::default());
    for day in 0..14 {
        for h in 0..24 {
            for (ts, dev, name) in hour_events(&mut rng, day, h, inject) {
                e.observe(ts, ip(dev), &wire(&name));
            }
        }
    }
    // Close the last day.
    e.observe(
        DAY0 + 14 * 86_400 + 1,
        ip(NAS),
        &wire("update0.nas.example"),
    );
    e
}

#[test]
fn obs_013_clean_baseline_has_no_findings() {
    let e = run(false);
    assert_eq!(
        e.findings(),
        &[] as &[Finding],
        "false positives on the clean baseline"
    );
}

#[test]
fn obs_013_injected_scenarios_are_found_with_evidence() {
    let e = run(true);
    let got: Vec<(Kind, u8, Option<&str>)> = e
        .findings()
        .iter()
        .map(|f| (f.kind, f.client[15], f.domain.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            (Kind::DomainVolume, TV, Some("vendor.example")),
            (Kind::Drift, PLUG, None),
            (Kind::Beacon, CAMERA, Some("c2.example")),
        ],
        "{:#?}",
        e.findings()
    );
    let tv = &e.findings()[0];
    assert!(
        tv.observed > 4000.0 && tv.baseline > 50.0 && tv.observed > tv.threshold,
        "{tv:?}"
    );
    let plug = &e.findings()[1];
    assert!(
        plug.observed >= 30.0 && plug.detail.contains("domain"),
        "{plug:?}"
    );
    let beacon = &e.findings()[2];
    assert!(
        (295.0..=305.0).contains(&beacon.observed) && beacon.spread < 5.0,
        "{beacon:?}"
    );
}

#[test]
fn obs_013_findings_are_byte_identical_to_the_golden_file() {
    let e = run(true);
    let text = serde_json::to_string_pretty(e.findings()).unwrap() + "\n";
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/anomaly-golden.json");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &text).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(&path).unwrap_or_default(),
        text,
        "rerun with UPDATE_GOLDEN=1 only for an intended change"
    );
    // And a second replay is identical, state included.
    assert_eq!(run(true), e);
}

#[test]
fn obs_013_per_client_state_is_bounded() {
    let e = run(true);
    for dev in [PHONE, TV, PLUG, CAMERA, LAPTOP, NAS] {
        let b = e.client_bytes(ip(dev)).unwrap();
        assert!(b <= 4096 + RHYTHM_BYTES, "device {dev}: {b} bytes");
    }
    // A device that talks to thousands of domains stays bounded too.
    let mut e = Engine::new(Settings::default());
    for i in 0..5000u64 {
        e.observe(DAY0 + i, ip(99), &wire(&format!("d{i}.x{i}.example")));
    }
    assert!(e.client_bytes(ip(99)).unwrap() <= 4096 + RHYTHM_BYTES);
    // The device cap evicts the least recently seen.
    let mut e = Engine::new(Settings {
        max_clients: 3,
        ..Settings::default()
    });
    for d in 1..=5u8 {
        e.observe(DAY0 + u64::from(d), ip(d), &wire("a.example"));
    }
    assert_eq!((e.clients(), e.evicted), (3, 2));
}

#[test]
fn obs_013_registrable_domains() {
    assert_eq!(
        registrable(&wire("a.b.example.com")).as_deref(),
        Some("example.com")
    );
    assert_eq!(
        registrable(&wire("www.bbc.co.uk")).as_deref(),
        Some("bbc.co.uk")
    );
    assert_eq!(
        registrable(&wire("Example.COM")).as_deref(),
        Some("example.com")
    );
    assert_eq!(registrable(&wire("localhost")), None);
    assert_eq!(registrable(&wire("1.1.168.192.in-addr.arpa")), None);
    assert_eq!(registrable(&[0]), None);
}

#[test]
fn obs_013_state_survives_a_restart() {
    let e = run(true);
    let saved = serde_json::to_string(&e).unwrap();
    let back: Engine = serde_json::from_str(&saved).unwrap();
    assert_eq!(back, e);
}

/// REQ: OBS-009 (T7.14) — an NXDOMAIN storm: one finding (with sample names) when a minute
/// has enough NXDOMAIN answers and they're most of the device's queries; not for a device
/// whose failures are a small share, and once per hour.
#[test]
fn obs_009_nxdomain_storm() {
    let mut e = Engine::new(Settings::default());
    let t = DAY0 + 600;
    // Device A: 40 NXDOMAIN of 50 queries in one minute, twice in the hour.
    for m in [0u64, 5] {
        for i in 0..50u64 {
            let rc = if i < 40 { 3 } else { 0 };
            e.observe_answer(
                t + m * 60 + i % 60,
                ip(1),
                &wire(&format!("q{i}.bad.example")),
                Some(rc),
            );
        }
    }
    // Device B: 40 NXDOMAIN among 400 queries (10%).
    for i in 0..400u64 {
        let rc = if i % 10 == 0 { 3 } else { 0 };
        e.observe_answer(t + i % 60, ip(2), &wire("ok.example"), Some(rc));
    }
    // Close the hour.
    e.observe_answer(t + 3600, ip(3), &wire("x.example"), Some(0));
    let storms: Vec<&Finding> = e
        .findings()
        .iter()
        .filter(|f| f.kind == Kind::NxdomainStorm)
        .collect();
    assert_eq!(storms.len(), 1, "{storms:?}");
    let f = storms[0];
    assert_eq!(
        (f.client, f.observed, f.baseline, f.window_s),
        (ip(1), 40.0, 50.0, 60)
    );
    assert!(
        f.detail.contains("80% of 50") && f.detail.contains("q0.bad.example"),
        "{}",
        f.detail
    );
}

/// REQ: OBS-009 (T7.14) — DGA-like first-seen domains of a learned device are reported (once
/// per hour, with scores); normal new domains go to the first-seen feed only.
#[test]
fn obs_009_dga_and_first_seen_feed() {
    let mut e = Engine::new(Settings {
        learning_days: 1,
        ..Settings::default()
    });
    // Day 0: learning.
    e.observe(DAY0 + 10, ip(7), &wire("www.google.com"));
    let t = DAY0 + 2 * 86_400;
    e.observe(t, ip(7), &wire("cdn.netflix.com"));
    for (i, d) in ["xjwqkzpvb.com", "qwhdkzlmpx.net", "a8f3k2j9x1.org"]
        .iter()
        .enumerate()
    {
        e.observe(t + 60 * (i as u64 + 1), ip(7), &wire(d));
    }
    e.observe(t + 3600, ip(7), &wire("www.google.com"));
    let dga: Vec<&Finding> = e
        .findings()
        .iter()
        .filter(|f| f.kind == Kind::Dga)
        .collect();
    assert_eq!(dga.len(), 1, "{:?}", e.findings());
    assert_eq!(dga[0].observed, 3.0);
    assert!(
        dga[0].detail.contains("xjwqkzpvb.com (1.00)"),
        "{}",
        dga[0].detail
    );
    let feed: Vec<(&str, bool)> = e
        .new_domains()
        .map(|d| (d.domain.as_str(), d.dga_score >= 0.6))
        .collect();
    assert_eq!(
        feed,
        vec![
            ("netflix.com", false),
            ("xjwqkzpvb.com", true),
            ("qwhdkzlmpx.net", true),
            ("a8f3k2j9x1.org", true)
        ],
        "the first day isn't in the feed; known domains aren't new"
    );
}

/// REQ: OBS-010 (T9.5) — a device is "new" only once the engine has known devices for a day,
/// so a fresh start doesn't announce every device on the network.
#[test]
fn obs_010_new_devices_after_the_first_day() {
    let mut e = Engine::new(Settings::default());
    e.observe(DAY0, ip(PHONE), &wire("a.example.com"));
    e.observe(DAY0 + 3600, ip(TV), &wire("b.example.com"));
    assert!(
        e.new_clients(DAY0).is_empty(),
        "the first day: learning, not new"
    );
    e.observe(DAY0 + 2 * 86_400, ip(PLUG), &wire("c.example.com"));
    assert_eq!(
        e.new_clients(DAY0 + 86_400),
        vec![(ip(PLUG), DAY0 + 2 * 86_400)]
    );
    assert!(
        e.new_clients(DAY0 + 3 * 86_400).is_empty(),
        "only since the given time"
    );
}

/// REQ: OBS-031 (T14.5 AC 1) — an NTP loop every 2.5 s ± 0.1 s for an hour lands in bin 3
/// (2.2–3.3 s); a browser's random gaps have no bin above 30 %.
#[test]
fn obs_031_a_time_sync_loop_is_one_bin_and_a_browser_a_smear() {
    let mut e = Engine::new(Settings::default());
    let mut rng = Rng(7);
    let start_us = (DAY0 + 3 * 3600) * 1_000_000;
    let mut events: Vec<(u64, &str)> = Vec::new();
    let mut t = start_us;
    while t < start_us + 3_590_000_000 {
        events.push((t, "time.pool.ntp.org"));
        t += 2_400_000 + rng.below(200_001); // 2.4–2.6 s
    }
    let mut t = start_us;
    while t < start_us + 3_590_000_000 {
        events.push((t, "www.example.com"));
        // 0.5 s × 1.023^k for k in 0..208: about 0.5 s to 56 s, log-uniform.
        let mut gap = 500_000u64;
        for _ in 0..rng.below(208) {
            gap = gap * 1023 / 1000;
        }
        t += gap;
    }
    events.sort_unstable();
    for (ts, name) in &events {
        e.observe_query(*ts, ip(PHONE), &wire(name), Some(0));
    }
    let rows = e.rhythm(ip(PHONE));
    let share = |d: &str| {
        let r = rows.iter().find(|r| r.domain == d).unwrap();
        let total: u32 = r.hour.iter().map(|&n| u32::from(n)).sum();
        let (bin, top) = r.hour.iter().enumerate().max_by_key(|(_, n)| **n).unwrap();
        (bin, f64::from(*top) / f64::from(total), r.typical_gap_s)
    };
    let (bin, ntp, gap) = share("ntp.org");
    assert_eq!(bin, 3, "{rows:?}");
    assert!(ntp >= 0.95, "{ntp}");
    assert!(gap.is_some_and(|g| (2.4..=2.6).contains(&g)), "{gap:?}");
    let (_, web, _) = share("example.com");
    assert!(web <= 0.30, "{web}");
    // `recent` holds this hour too.
    let r = &rows[0];
    assert_eq!(r.recent, r.hour);
    // The alert path is untouched: no finding from an hour of anything.
    assert_eq!(e.findings().len(), 0);
}

/// REQ: OBS-031 (T14.5 AC 2) — at the hour's close the decayed copy is `previous / 2 + hour`,
/// saturating at 65,535; a beacon finding keeps its pair's rhythm.
#[test]
fn obs_031_the_hour_folds_into_the_decayed_copy() {
    let mut t = Tracked::new(1, "x.example".into(), 0);
    t.rhythm_long[3] = 1001;
    t.rhythm[3] = 5;
    t.rhythm[7] = 9;
    t.rhythm_long[20] = u16::MAX;
    t.rhythm[20] = u16::MAX;
    t.fold_rhythm();
    assert_eq!(t.rhythm_long[3], 505);
    assert_eq!(t.rhythm_long[7], 9);
    assert_eq!(t.rhythm_long[20], u16::MAX);
    assert_eq!(t.rhythm, [0; RHYTHM_BINS]);
    assert_eq!(rhythm_bin(0), 0);
    assert_eq!(rhythm_bin(999), 0);
    assert_eq!(rhythm_bin(1_000), 1);
    assert_eq!(rhythm_bin(2_500), 3);
    assert_eq!(rhythm_bin(300_000), 15);
    assert_eq!(rhythm_bin(u64::MAX), RHYTHM_BINS - 1);
    // The 14-day fixture's camera beacon (every 300 s) keeps its strip, around bin 15.
    let e = run(true);
    let beacon = e
        .findings()
        .iter()
        .find(|f| f.kind == Kind::Beacon)
        .unwrap();
    let bins = e.beacon_rhythm(beacon).unwrap();
    let (top, _) = bins.iter().enumerate().max_by_key(|(_, n)| **n).unwrap();
    assert_eq!(top, 15, "{bins:?}");
}

/// REQ: OBS-031 (T14.5 AC 5) — the rhythm's memory: 1,024 devices with 16 tracked pairs each.
#[test]
fn obs_031_rhythm_memory_at_1024_devices() {
    let mut e = Engine::new(Settings::default());
    for dev in 0..1024u32 {
        let [_, _, a, b] = dev.to_be_bytes();
        let ip = std::net::Ipv4Addr::new(10, 0, a, b)
            .to_ipv6_mapped()
            .octets();
        for d in 0..16u64 {
            e.observe_query(
                (DAY0 + d) * 1_000_000,
                ip,
                &wire(&format!("n.d{d}.example")),
                Some(0),
            );
        }
    }
    let total: usize = e
        .clients
        .keys()
        .map(|k| e.client_bytes(*k).unwrap_or(0))
        .sum();
    let rhythm = 1024 * RHYTHM_BYTES;
    println!("anomaly state at 1,024 devices x 16 pairs: {total} bytes, of which rhythm {rhythm}");
    assert!(rhythm <= 2 * 1024 * 1024, "{rhythm}");
}
