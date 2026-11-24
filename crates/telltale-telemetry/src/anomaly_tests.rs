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

/// REQ: OBS-036 — a 2.5 s loop for two hours is one informational `chatty_loop` finding; it
/// isn't reported again until it stops for an hour and starts again; a browser's smear never is.
#[test]
fn obs_036_a_chatty_loop_is_reported_once_per_streak() {
    let mut e = Engine::new(Settings {
        learning_days: 0,
        ..Settings::default()
    });
    let start_us = (DAY0 + 3 * 3600) * 1_000_000;
    let mut rng = Rng(11);
    let mut t = start_us;
    let run = |e: &mut Engine, from: u64, to: u64, rng: &mut Rng| {
        let mut t = from;
        while t < to {
            e.observe_query(t, ip(PHONE), &wire("time.pool.ntp.org"), Some(0));
            // A browser too: gaps from 0.5 s to about 56 s.
            if rng.below(8) == 0 {
                e.observe_query(t + 1, ip(PHONE), &wire("www.example.com"), Some(0));
            }
            t += 2_400_000 + rng.below(200_001);
        }
        t
    };
    t = run(&mut e, t, start_us + 2 * 3_600_000_000, &mut rng);
    // Quiet for an hour and a half, then the loop again for an hour.
    let back = t + 5_400_000_000;
    run(&mut e, back, back + 3_600_000_000, &mut rng);
    // Close that last hour.
    e.observe_query(back + 7_300_000_000, ip(TV), &wire("x.example"), Some(0));
    let chatty: Vec<&Finding> = e
        .findings()
        .iter()
        .filter(|f| f.kind == Kind::ChattyLoop)
        .collect();
    assert_eq!(chatty.len(), 2, "{:#?}", e.findings());
    assert!(
        chatty
            .iter()
            .all(|f| f.domain.as_deref() == Some("ntp.org"))
    );
    assert!(Kind::ChattyLoop.informational() && !Kind::Beacon.informational());
    assert!(
        (2.3..=2.7).contains(&chatty[0].baseline),
        "{}",
        chatty[0].baseline
    );
    assert!(chatty[0].detail.contains("informational"));
    assert_eq!(chatty[0].window_start_s, DAY0 + 3 * 3600);
    assert!(e.beacon_rhythm(chatty[0]).is_some_and(|b| b[3] > 0));
}

/// REQ: OBS-014 (T10.7) — damaged saved state (too few hourly baselines, an impossible gap
/// count, an hour from long ago) is repaired on load: the engine keeps running, and catches up
/// a bounded number of hours instead of every hour since.
#[test]
fn obs_014_damaged_state_is_repaired_on_load() {
    let mut v = serde_json::to_value(run(true)).unwrap();
    let clients = v["clients"].as_array_mut().unwrap();
    let mut gaps = 0;
    for pair in clients.iter_mut() {
        let c = &mut pair[1];
        c["rate"].as_array_mut().unwrap().truncate(3);
        for t in c["tracked"].as_array_mut().unwrap() {
            t["n_intervals"] = serde_json::json!(200);
            gaps += 1;
        }
    }
    assert!(gaps > 0, "the scenario tracks pairs");
    v["hour"] = serde_json::json!(5);
    let mut e: Engine = serde_json::from_value(v).unwrap();
    e.repair();
    let started = std::time::Instant::now();
    for h in 0..30 {
        e.observe(
            DAY0 + 40 * 86_400 + h * 3600,
            ip(PHONE),
            &wire("example.com"),
        );
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert!(e.clients() > 0);
}

/// 40 NXDOMAIN of 50 queries inside one minute from `dev`, at `t`: one storm finding when the
/// hour closes.
fn storm(e: &mut Engine, dev: u8, t: u64) {
    for i in 0..50u64 {
        let rc = if i < 40 { 3 } else { 0 };
        e.observe_answer(
            t + i % 60,
            ip(dev),
            &wire(&format!("q{i}.sweep.example")),
            Some(rc),
        );
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
    std::net::Ipv4Addr::new(a, b, c, d)
        .to_ipv6_mapped()
        .octets()
}

/// REQ: OBS-038 (ADR-161) — a finding a mute matches when it is created is recorded and listed
/// with the mute's name, counted apart, and left out of the totals the badge, the alert and
/// `/metrics` use; the same kind for another device counts as before.
#[test]
fn obs_038_a_muted_device_is_recorded_but_not_counted() {
    let mut mutes = MuteTable::default();
    mutes.add(
        "lg-tv",
        [(v4(192, 168, 1, 1), 128)],
        &[Kind::NxdomainStorm],
        None,
    );
    let mut e = Engine::new(Settings::default());
    e.set_mutes(mutes);
    let t = DAY0 + 600;
    storm(&mut e, 1, t);
    storm(&mut e, 4, t);
    e.observe_answer(t + 3600, ip(9), &wire("x.example"), Some(0));
    let storms: Vec<&Finding> = e
        .findings()
        .iter()
        .filter(|f| f.kind == Kind::NxdomainStorm)
        .collect();
    assert_eq!(storms.len(), 2, "both are recorded: {storms:?}");
    let by = |dev: u8| storms.iter().find(|f| f.client == ip(dev)).unwrap();
    assert_eq!(by(1).muted_by.as_deref(), Some("lg-tv"));
    assert_eq!(by(4).muted_by, None);
    assert_eq!(
        e.total.get(&Kind::NxdomainStorm),
        Some(&1),
        "only device 4 counts"
    );
    assert_eq!(e.total_muted.get(&Kind::NxdomainStorm), Some(&1));
}

/// REQ: OBS-038 — a mute is for its kinds and its networks only, and an end time ends it for
/// findings created after it: one made while it held stays muted.
#[test]
fn obs_038_kinds_networks_and_expiry() {
    let t = DAY0 + 600;
    let run = |nets: [([u8; 16], u8); 1], kinds: &[Kind], until: Option<u64>| {
        let mut m = MuteTable::default();
        m.add("m", nets, kinds, until);
        let mut e = Engine::new(Settings::default());
        e.set_mutes(m);
        storm(&mut e, 1, t);
        e.observe_answer(t + 3600, ip(9), &wire("x.example"), Some(0));
        e.findings()
            .iter()
            .find(|f| f.kind == Kind::NxdomainStorm)
            .unwrap()
            .muted_by
            .clone()
    };
    let one = [(v4(192, 168, 1, 1), 128)];
    // A network covers the device (192.168.1.0/24 is /120 over the v4-mapped form).
    assert_eq!(
        run([(v4(192, 168, 1, 0), 120)], &[Kind::NxdomainStorm], None).as_deref(),
        Some("m")
    );
    // Another network, or another kind, doesn't.
    assert_eq!(
        run([(v4(192, 168, 2, 0), 120)], &[Kind::NxdomainStorm], None),
        None
    );
    assert_eq!(run(one, &[Kind::RateSpike, Kind::Dga], None), None);
    // Ends after the window: muted. Ended before it: counts.
    assert_eq!(
        run(one, &[Kind::NxdomainStorm], Some(DAY0 + 86_400)).as_deref(),
        Some("m")
    );
    assert_eq!(run(one, &[Kind::NxdomainStorm], Some(DAY0 + 100)), None);
}

/// REQ: OBS-038 — the same queries and mutes give the same findings (replay), and changing the
/// mutes later doesn't rewrite findings already recorded.
#[test]
fn obs_038_replay_is_deterministic_and_history_is_kept() {
    let mut m = MuteTable::default();
    m.add(
        "m",
        [(v4(192, 168, 1, 0), 120)],
        &[Kind::NxdomainStorm],
        None,
    );
    let build = |m: &MuteTable| {
        let mut e = Engine::new(Settings::default());
        e.set_mutes(m.clone());
        storm(&mut e, 1, DAY0 + 600);
        e.observe_answer(DAY0 + 600 + 3600, ip(9), &wire("x.example"), Some(0));
        e
    };
    let (a, b) = (build(&m), build(&m));
    assert_eq!(a, b);
    let mut c = build(&m);
    c.set_mutes(MuteTable::default());
    assert_eq!(
        c.findings(),
        a.findings(),
        "removing the mute keeps what was muted"
    );
    assert!(c.findings().iter().any(|f| f.muted_by.is_some()));
}

/// A wire name from raw labels (each at most 63 bytes).
fn wire_of(labels: &[Vec<u8>]) -> Vec<u8> {
    let mut w = Vec::new();
    for l in labels {
        w.push(u8::try_from(l.len()).unwrap());
        w.extend_from_slice(l);
    }
    w.push(0);
    w
}

/// REQ: OBS-009 — the NXDOMAIN samples a fresh engine keeps for `names` (asked in this order,
/// 30 answers in one minute, so the minute is a storm), checked against the storm finding they
/// end up in.
fn storm_samples(names: &[&[u8]]) -> Vec<String> {
    let mut e = Engine::new(Settings::default());
    let t = DAY0 + 600;
    for name in names.iter().cycle().take(30) {
        e.observe_answer(t, ip(1), name, Some(3));
    }
    let kept = e.clients[&ip(1)].nx_samples.clone();
    e.observe_answer(t + 3600, ip(3), &wire("x.example"), Some(0));
    let storm = e
        .findings()
        .iter()
        .find(|f| f.kind == Kind::NxdomainStorm)
        .unwrap();
    assert!(
        storm.detail.ends_with(&format!("e.g. {}", kept.join(", "))),
        "{}",
        storm.detail
    );
    kept
}

/// REQ: OBS-009 — a sample name is cut at a character boundary, valid for any name: with a
/// character of each width (a byte that shows as U+FFFD, and valid 2-, 3- and 4-byte ones) at
/// every offset around the cut, the sample is the longest prefix of the dotted name that is at
/// most [`MAX_DOMAIN`] bytes and ends on a character.
#[test]
fn obs_009_sample_name_cut_at_char_boundary_every_offset() {
    // The bytes on the wire, and the text they show as.
    let shapes: [(&[u8], &str); 4] = [
        (b"\x80", "\u{fffd}"),
        ("\u{e9}".as_bytes(), "\u{e9}"),
        ("\u{20ac}".as_bytes(), "\u{20ac}"),
        ("\u{1f600}".as_bytes(), "\u{1f600}"),
    ];
    for (bytes, shown) in shapes {
        let per_label = 63 / bytes.len();
        let run_wire = bytes.repeat(per_label);
        let run_text = shown.repeat(per_label);
        // Where the cut fell inside a character (bytes after its start).
        let mut inside = std::collections::BTreeSet::new();
        for filler in 0..=70usize {
            let letters: Vec<u8> = (0..filler)
                .map(|i| b'a' + u8::try_from(i % 26).unwrap())
                .collect();
            let mut labels: Vec<Vec<u8>> = letters.chunks(63).map(<[u8]>::to_vec).collect();
            labels.push(run_wire.clone());
            labels.push(run_wire.clone());
            let w = wire_of(&labels);
            let mut parts: Vec<String> = letters
                .chunks(63)
                .map(|c| std::str::from_utf8(c).unwrap().to_owned())
                .collect();
            parts.push(run_text.clone());
            parts.push(run_text.clone());
            let full = parts.join(".");
            assert_eq!(crate::event::dotted(&w), full, "the test's own name");
            assert!(full.len() > MAX_DOMAIN);
            if !full.is_char_boundary(MAX_DOMAIN) {
                let start = (0..MAX_DOMAIN)
                    .rev()
                    .find(|&b| full.is_char_boundary(b))
                    .unwrap();
                inside.insert(MAX_DOMAIN - start);
            }
            let samples = storm_samples(&[w.as_slice()]);
            assert_eq!(samples.len(), 1, "{samples:?}");
            let sample = &samples[0];
            let case = format!("{shown:?} after {filler} letters: {sample:?}");
            assert!(full.starts_with(sample.as_str()), "a prefix: {case}");
            assert!(sample.len() <= MAX_DOMAIN, "at most the limit: {case}");
            assert!(
                full.is_char_boundary(sample.len()),
                "on a character: {case}"
            );
            assert!(sample.len() + 3 >= MAX_DOMAIN, "the longest: {case}");
            let longest = (0..=MAX_DOMAIN)
                .rev()
                .find(|&b| full.is_char_boundary(b))
                .unwrap();
            assert_eq!(sample.as_str(), &full[..longest], "the longest: {case}");
        }
        assert_eq!(
            inside,
            (1..shown.len()).collect::<std::collections::BTreeSet<_>>(),
            "every offset inside {shown:?}"
        );
    }
}

/// REQ: OBS-009 — ASCII names are kept as before: whole up to [`MAX_DOMAIN`] bytes and cut at
/// it when longer; the root shows as `.`; names that differ only after the cut give one sample.
#[test]
fn obs_009_sample_name_short_and_ascii_names_unchanged() {
    let shorter = "a".repeat(62);
    let label = "a".repeat(63);
    let long = format!("{label}.{label}.{label}.bcd");
    for (len, name, want) in [
        (1, "a".to_owned(), "a".to_owned()),
        (63, label.clone(), label.clone()),
        (64, format!("{shorter}.b"), format!("{shorter}.b")),
        (65, format!("{label}.b"), format!("{label}.")),
        (66, format!("{label}.bc"), format!("{label}.")),
        (195, long.clone(), long[..64].to_owned()),
    ] {
        assert_eq!(name.len(), len);
        assert_eq!(storm_samples(&[wire(&name).as_slice()]), [want], "{name}");
    }
    assert_eq!(storm_samples(&[&[0]]), ["."], "the root");
    assert_eq!(storm_samples(&[&[]]), [""], "no name");
    let (one, two) = (wire(&format!("{label}.b")), wire(&format!("{label}.c")));
    assert_eq!(
        storm_samples(&[one.as_slice(), two.as_slice()]),
        [format!("{label}.")],
        "one sample after the cut"
    );
    let short = wire("q.example");
    assert_eq!(
        storm_samples(&[one.as_slice(), short.as_slice(), two.as_slice()]),
        [format!("{label}."), "q.example".to_owned()],
        "in the order asked"
    );
}

/// Label bytes for the property test: mostly bytes of 0x80 and up, and pieces that aren't
/// UTF-8 (lone continuation bytes, cut sequences, overlong forms, surrogates, 0xF8 and up).
fn odd_label(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 4);
    while out.len() < len {
        let r = rng.next();
        let b = u8::try_from(r >> 56).unwrap();
        match r % 8 {
            0 => out.push(b'a' + b % 26),
            1 => out.push(0x80 | (b & 0x3f)),
            2 => out.push(0xc2 + b % 0x33),
            3 => out.extend_from_slice(
                ["\u{e9}", "\u{20ac}", "\u{1f600}"][usize::from(b % 3)].as_bytes(),
            ),
            4 => out.extend_from_slice(
                [
                    &[0xc0, 0x80][..],
                    &[0xe0, 0x80, 0x80],
                    &[0xed, 0xa0, 0x80],
                    &[0xf8 | (b & 7)],
                ][usize::from(b % 4)],
            ),
            5 => out.push(b),
            6 => out.push([b'.', b',', b' ', 0, b'\\'][usize::from(b % 5)]),
            _ => out.push(0x80 | b),
        }
    }
    out.truncate(len);
    out
}

/// A wire name for the property test: labels of 0 to 63 bytes (0 ends the name), at most 255
/// bytes in all; sometimes bytes after the root, or bytes that aren't a name at all.
fn odd_wire(rng: &mut Rng) -> Vec<u8> {
    if rng.below(16) == 0 {
        let n = usize::try_from(rng.below(300)).unwrap();
        return (0..n)
            .map(|_| u8::try_from(rng.next() >> 56).unwrap())
            .collect();
    }
    let mut w = Vec::new();
    loop {
        let len = usize::try_from(rng.below(64)).unwrap();
        if len == 0 || w.len() + len + 2 > 255 || rng.below(5) == 0 {
            break;
        }
        w.push(u8::try_from(len).unwrap());
        w.extend(odd_label(rng, len));
    }
    w.push(0);
    if rng.below(16) == 0 {
        w.extend(odd_label(rng, 8));
    }
    w
}

/// REQ: OBS-009 — the engine takes names with any bytes: 20 000 generated queries (names of
/// mostly non-ASCII and non-UTF-8 bytes, raw bytes, known and new devices, every answer kind,
/// times across minutes, an hour and a day, late events and a long gap) leave every NXDOMAIN
/// sample within [`MAX_DOMAIN`] bytes and every domain text within [`MAX_DOMAIN`] characters.
#[test]
fn obs_009_observe_query_takes_any_wire_bytes() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut engine = Engine::new(Settings {
        learning_days: 1,
        max_clients: 64,
        ..Settings::default()
    });
    // Just before a midnight: the run crosses minutes, an hour and a day.
    let start_s = DAY0 + 3 * 86_400 - 150;
    // Eight devices first seen a day earlier, so their first-seen domains are scored too.
    for dev in 1..=8 {
        engine.observe(start_s - 86_400 - 60, ip(dev), &wire("seed.example"));
    }
    let mut at_us = start_s * 1_000_000;
    for i in 0..20_000u32 {
        at_us += rng.below(60_000);
        if i == 15_000 {
            at_us += 3 * 86_400 * 1_000_000;
        }
        let when = if rng.below(500) == 0 {
            at_us.saturating_sub(rng.below(7_200_000_000))
        } else {
            at_us
        };
        let client = if rng.below(10) == 0 {
            let mut addr = [0u8; 16];
            for byte in &mut addr {
                *byte = u8::try_from(rng.next() >> 56).unwrap();
            }
            addr
        } else {
            ip(u8::try_from(1 + rng.below(8)).unwrap())
        };
        let rcode = match rng.below(10) {
            0..=5 => Some(3),
            6 => None,
            _ => Some(u8::try_from(rng.below(6)).unwrap()),
        };
        let name = odd_wire(&mut rng);
        engine.observe_query(when, client, &name, rcode);
        if let Some(state) = engine.clients.get(&client) {
            assert!(state.nx_samples.len() <= SAMPLES);
            for sample in &state.nx_samples {
                assert!(sample.len() <= MAX_DOMAIN, "{sample:?} from {name:?}");
            }
        }
    }
    engine.observe_answer(at_us / 1_000_000 + 7200, ip(9), &wire("x.example"), Some(0));
    let storms = engine
        .findings()
        .iter()
        .filter(|f| f.kind == Kind::NxdomainStorm)
        .count();
    assert!(storms > 0, "the run makes storms");
    assert!(engine.new_domains().count() > 0, "and first-seen domains");
    let within = |text: &str| text.chars().count() <= MAX_DOMAIN;
    assert!(engine.new_domains().all(|d| within(&d.domain)));
    for state in engine.clients.values() {
        assert!(state.tracked.iter().all(|t| within(&t.domain)));
        assert!(state.dga_samples.iter().all(|(text, _)| within(text)));
        assert!(state.new_samples.iter().all(|text| within(text)));
    }
}
