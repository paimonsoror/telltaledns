//! OBS-002 / NFR-002: recording a query never allocates (own test binary; the allocation counter
//! counts per thread, so each test measures only itself).

use std::time::Duration;

use telltale_telemetry::{Metrics, Proto, Status};

#[test]
fn obs_002_record_does_not_allocate() {
    let m = Metrics::new(1);
    m.record(Proto::Udp, Status::Cached, Some(0), 1, Duration::ZERO); // assigns this thread's slot
    let info = allocation_counter::measure(|| {
        for i in 0..10_000u16 {
            m.record(
                Proto::Udp,
                Status::Cached,
                Some(0),
                i % 300,
                Duration::from_micros(u64::from(i)),
            );
        }
    });
    assert_eq!(info.count_total, 0);
}

/// OBS-009 (ADR-186): counting a sweep of private reverse names (IPv4 and IPv6, NXDOMAIN and
/// NOERROR) allocates nothing per query once the minute's sample names are kept. The engine runs
/// on the aggregator thread, once per event.
#[test]
fn obs_009_counting_a_sweep_allocates_nothing_per_query() {
    use telltale_telemetry::anomaly::{Engine, Settings};
    fn wire(name: &str) -> Vec<u8> {
        let mut w = Vec::new();
        for l in name.split('.') {
            w.push(u8::try_from(l.len()).unwrap());
            w.extend_from_slice(l.as_bytes());
        }
        w.push(0);
        w
    }
    let client = std::net::Ipv4Addr::new(192, 168, 1, 20)
        .to_ipv6_mapped()
        .octets();
    let t = 1_790_000_000 / 86_400 * 86_400 + 600; // a minute's start
    let mut e = Engine::new(Settings::default());
    // Warm-up: the device exists and its minute has more than 5 private reverse NXDOMAINs.
    for i in 1..=10 {
        e.observe_answer(
            t,
            client,
            &wire(&format!("{i}.20.0.10.in-addr.arpa")),
            Some(3),
        );
    }
    let mut names: Vec<Vec<u8>> = (11..=254)
        .map(|i| wire(&format!("{i}.20.0.10.in-addr.arpa")))
        .collect();
    names.extend((0..16).map(|i| wire(&format!("{i:x}.{}d.f.ip6.arpa", "0.".repeat(29)))));
    let info = allocation_counter::measure(|| {
        for i in 0..1_000usize {
            let rcode = if i % 4 == 0 { 0 } else { 3 };
            e.observe_answer(t + 30, client, &names[i % names.len()], Some(rcode));
        }
    });
    assert_eq!(info.count_total, 0);
}

/// OBS-009 (ADR-186): a name the minute already keeps as a sample allocates nothing when it is
/// answered NXDOMAIN again, while fewer than 5 samples are kept: a private reverse name (the
/// sweep's samples), an ordinary one and one with bytes that aren't UTF-8 (the storm's), asked
/// over and over.
#[test]
fn obs_009_a_repeated_sample_name_allocates_nothing() {
    use telltale_telemetry::anomaly::{Engine, Settings};
    fn wire(labels: &[&[u8]]) -> Vec<u8> {
        let mut w = Vec::new();
        for l in labels {
            w.push(u8::try_from(l.len()).unwrap());
            w.extend_from_slice(l);
        }
        w.push(0);
        w
    }
    let client = std::net::Ipv4Addr::new(192, 168, 1, 21)
        .to_ipv6_mapped()
        .octets();
    let t = 1_790_000_000 / 86_400 * 86_400 + 600; // a minute's start
    let names = [
        wire(&[b"5", b"0", b"0", b"10", b"in-addr", b"arpa"]),
        wire(&[b"q", b"bad", b"example"]),
        wire(&[b"\x80\xffq", b"bad", b"example"]),
    ];
    let mut e = Engine::new(Settings::default());
    // Warm-up: the device exists and each name is kept once.
    for n in &names {
        e.observe_answer(t, client, n, Some(3));
    }
    let info = allocation_counter::measure(|| {
        for i in 0..1_000usize {
            e.observe_answer(t + 30, client, &names[i % names.len()], Some(3));
        }
    });
    assert_eq!(info.count_total, 0);
}
