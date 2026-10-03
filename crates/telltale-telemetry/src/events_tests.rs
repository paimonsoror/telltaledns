//! T3.1 tests: event encoding, rings, top-K, aggregation (OBS-001, OBS-002, OBS-004).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::agg::{HourSel, LatencyKey, Resolution, TopKind};
use crate::event::{self, MAX_RECORD, Record};
use crate::topk::SpaceSaving;
use crate::{Aggregates, Hub, Path, Proto, QueryEvent, Rule, RuleKind, Status, UpstreamEvent};

fn wire(name: &str) -> Vec<u8> {
    let mut w = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        w.push(u8::try_from(label.len()).unwrap());
        w.extend_from_slice(label.as_bytes());
    }
    w.push(0);
    w
}

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
    std::net::Ipv4Addr::new(a, b, c, d)
        .to_ipv6_mapped()
        .octets()
}

fn query(ts_us: u64, client: [u8; 16], status: Status, total_us: u32) -> QueryEvent {
    QueryEvent {
        ts_us,
        client_ip: client,
        client_ref: 0,
        group: 0,
        qtype: 1,
        qclass: 1,
        rcode: Some(0),
        status,
        proto: Proto::Udp,
        flags: 0x8180,
        rule: None,
        upstream: 0,
        attempts: 0,
        t_total_us: total_us,
        t_upstream_us: 0,
        resp_size: 64,
        answers: 1,
    }
}

#[test]
fn obs_001_query_and_upstream_records_round_trip() {
    let mut ev = query(
        1_700_000_000_123_456,
        ipv4(192, 168, 1, 20),
        Status::Blocked,
        42,
    );
    ev.rule = Some(Rule {
        list: 3,
        kind: RuleKind::Cname,
        allow: false,
    });
    ev.rcode = None;
    ev.t_upstream_us = 7;
    let mut buf = [0u8; MAX_RECORD];
    let name = wire("Ads.Example.COM");
    let len = event::encode_query(&ev, &name, &mut buf);
    assert_eq!(event::record_len(&buf), Some(len));
    let Some(Record::Query(back, n)) = event::decode(&buf[..len]) else {
        panic!("query record");
    };
    assert_eq!(back, ev);
    assert_eq!(n.dotted(), "ads.example.com", "lowercased");

    // Long names are kept whole (no truncation).
    let long = format!(
        "{}.{}.{}.example.com",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(60)
    );
    let len = event::encode_query(&ev, &wire(&long), &mut buf);
    let Some(Record::Query(_, n)) = event::decode(&buf[..len]) else {
        panic!("long name");
    };
    assert_eq!(n.dotted(), long);

    // A malformed name is recorded as unknown, never read out of bounds.
    let len = event::encode_query(&ev, &[5, b'a', b'b'], &mut buf);
    let Some(Record::Query(_, n)) = event::decode(&buf[..len]) else {
        panic!("malformed");
    };
    assert_eq!(n.as_wire(), b"");

    let up = UpstreamEvent {
        ts_us: 5,
        upstream: 2,
        latency_us: 1234,
        ok: false,
        attempts: 3,
    };
    let len = event::encode_upstream(&up, &mut buf);
    assert_eq!(event::decode(&buf[..len]), Some(Record::Upstream(up)));
}

#[test]
fn obs_001_question_is_read_from_a_raw_message() {
    let mut msg = vec![0u8; 12];
    msg.extend_from_slice(&wire("www.example.org"));
    msg.extend_from_slice(&[0, 28, 0, 1]);
    let (name, class) = event::question(&msg);
    assert_eq!(event::dotted(name), "www.example.org");
    assert_eq!(class, 1);
    assert_eq!(event::question(&[0u8; 5]), (&[][..], 0));
}

#[test]
fn obs_004_space_saving_finds_heavy_hitters_with_bounded_error() {
    // Zipf-like stream: key i appears ~ 10_000 / (i + 1) times, over far more keys than slots.
    let mut truth: HashMap<u32, u64> = HashMap::new();
    let mut stream = Vec::new();
    for i in 0..5_000u32 {
        let n = 10_000 / (u64::from(i) + 1);
        for _ in 0..n.max(1) {
            stream.push(i);
        }
        *truth.entry(i).or_default() += n.max(1);
    }
    // Interleave deterministically so heavy keys don't arrive in one burst.
    let mut rng = 0x9E37_79B9_u64;
    for i in (1..stream.len()).rev() {
        rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let j = usize::try_from(rng >> 33).unwrap() % (i + 1);
        stream.swap(i, j);
    }
    let mut ss = SpaceSaving::new(200);
    for k in &stream {
        ss.offer(k, |k| *k);
    }
    let top = ss.top(10);
    let keys: Vec<u32> = top.iter().map(|t| t.key).collect();
    assert_eq!(
        keys,
        (0..10).collect::<Vec<_>>(),
        "the 10 heaviest, in order"
    );
    for t in &ss.top(200) {
        let real = truth[&t.key];
        assert!(
            t.count >= real && t.count - t.error <= real,
            "{t:?} vs {real}"
        );
    }
    assert_eq!(ss.len(), 200, "fixed memory");
}

#[test]
fn obs_002_rings_carry_every_event_from_every_thread() {
    // Big enough for 1000 undrained events per thread (~75 B each).
    let hub = Hub::new(1 << 18);
    let threads: Vec<_> = (0..4u8)
        .map(|t| {
            let hub = Arc::clone(&hub);
            std::thread::spawn(move || {
                for i in 0..1000u32 {
                    let mut ev = query(u64::from(i), ipv4(10, 0, 0, t), Status::Cached, i);
                    ev.client_ref = u32::from(t);
                    hub.emit_query(&ev, &wire("x.example.com"));
                }
            })
        })
        .collect();
    let mut drainer = hub.drainer();
    let mut per_thread = [0u32; 4];
    let mut seen = 0;
    for t in threads {
        t.join().unwrap();
    }
    seen += drainer.drain(|r| {
        if let Record::Query(e, n) = r {
            assert_eq!(n.dotted(), "x.example.com");
            per_thread[e.client_ref as usize] += 1;
        }
    });
    assert_eq!(seen, 4000);
    assert_eq!(per_thread, [1000; 4]);
    let stats = hub.ring_stats();
    assert_eq!(stats.iter().map(|s| s.1).sum::<u64>(), 4000);
    assert_eq!(stats.iter().map(|s| s.2).sum::<u64>(), 0);
    // Exited threads' rings are released once drained.
    assert_eq!(drainer.drain(|_| {}), 0);
}

#[test]
fn obs_002_a_full_ring_drops_whole_events_and_counts_them() {
    let hub = Hub::new(1); // rounded up to the minimum (4 max-size records)
    let mut drainer = hub.drainer();
    let name = wire("y.example.com");
    for i in 0..1000 {
        hub.emit_query(&query(i, ipv4(10, 0, 0, 1), Status::Forwarded, 1), &name);
    }
    let (_, emitted, dropped) = hub.ring_stats()[0].clone();
    assert_eq!(emitted + dropped, 1000);
    assert!(dropped > 900, "the ring is small: {dropped}");
    let mut got = 0u64;
    drainer.drain(|r| {
        assert!(matches!(r, Record::Query(_, n) if n.dotted() == "y.example.com"));
        got += 1;
    });
    assert_eq!(got, emitted, "no partial or corrupt records");
    // Space again after draining.
    hub.emit_query(&query(0, ipv4(10, 0, 0, 1), Status::Forwarded, 1), &name);
    assert_eq!(drainer.drain(|_| {}), 1);
}

#[test]
fn obs_002_emit_does_not_allocate_after_the_first_event() {
    let hub = Hub::new(1 << 20);
    let ev = query(1, ipv4(10, 0, 0, 1), Status::Cached, 5);
    let name = wire("alloc.example.com");
    hub.emit_query(&ev, &name); // registers this thread's ring
    let info = allocation_counter::measure(|| {
        for _ in 0..1000 {
            hub.emit_query(&ev, &name);
        }
    });
    assert_eq!(info.count_total, 0);
}

#[test]
fn obs_004_aggregates_windows_top_k_and_latency() {
    let mut agg = Aggregates::new();
    let t0 = 1_700_000_000u64; // a second-aligned timestamp
    let a = ipv4(192, 168, 1, 20);
    let b = ipv4(192, 168, 1, 21);
    for i in 0..100u32 {
        let ts = (t0 + u64::from(i % 3)) * 1_000_000;
        let (client, name, status) = if i % 4 == 0 {
            (b, "ads.example.com", Status::Blocked)
        } else {
            (a, "www.example.org", Status::Cached)
        };
        let mut e = query(ts, client, status, 10 + i);
        if i % 10 == 0 {
            e.rcode = Some(3);
            e.status = Status::Forwarded;
            e.t_upstream_us = 5_000;
        }
        agg.record(&Record::Query(e, decoded(name)));
    }
    agg.record(&Record::Upstream(UpstreamEvent {
        ts_us: t0 * 1_000_000,
        upstream: 1,
        latency_us: 9_000,
        ok: false,
        attempts: 2,
    }));
    let secs = agg.series(Resolution::Second, t0, t0 + 3);
    assert_eq!(secs.len(), 3);
    assert_eq!(secs.iter().map(|(_, c)| c.total).sum::<u32>(), 100);
    assert_eq!(secs[0].1.upstreams, vec![0, 1]);
    assert_eq!(secs[0].1.upstream_failures, 1);
    let mins = agg.series(Resolution::Minute, t0 - 60, t0 + 60);
    assert_eq!(mins.iter().map(|(_, c)| c.total).sum::<u32>(), 100);

    let top = agg.top_names(TopKind::Domains, HourSel::Current, 10);
    assert_eq!(top[0].key, "www.example.org");
    assert_eq!((top[1].key.as_str(), top[1].count), ("ads.example.com", 25));
    let blocked = agg.top_names(TopKind::Blocked, HourSel::Current, 10);
    assert_eq!(blocked.len(), 1);
    // The 10 NXDOMAIN answers are split across both names.
    let nx = agg.top_names(TopKind::Nxdomain, HourSel::Current, 10);
    assert_eq!(nx.iter().map(|t| t.count).sum::<u64>(), 10);
    assert_eq!(
        agg.top_names(TopKind::Clients, HourSel::Current, 1)[0].key,
        "192.168.1.20"
    );
    assert_eq!(agg.top_client_domains(b, 5)[0].key, "ads.example.com");

    let all = agg
        .latency(LatencyKey::Total(Path::Cache, Proto::Udp), HourSel::Current)
        .unwrap();
    assert!(all.count > 0 && all.p50 >= 10 && all.max <= 110, "{all:?}");
    let up = agg
        .latency(LatencyKey::Upstream(1), HourSel::Current)
        .unwrap();
    assert_eq!(up.count, 1);
    assert!(
        (8_900..=9_100).contains(&up.p50),
        "2 significant digits: {up:?}"
    );
    assert_eq!(
        agg.latency(LatencyKey::StageUpstream, HourSel::Current)
            .unwrap()
            .count,
        10
    );
    assert!(
        agg.latency(LatencyKey::Client(a), HourSel::Current)
            .is_some()
    );

    // The next hour starts fresh; the finished one stays readable.
    let next = (t0 / 3600 + 1) * 3600 * 1_000_000;
    agg.record(&Record::Query(
        query(next, a, Status::Cached, 1),
        decoded("new.example"),
    ));
    assert_eq!(
        agg.top_names(TopKind::Domains, HourSel::Current, 10).len(),
        1
    );
    assert_eq!(
        agg.top_names(TopKind::Domains, HourSel::Previous, 10).len(),
        2
    );
}

fn decoded(name: &str) -> event::Name {
    let mut buf = [0u8; MAX_RECORD];
    let len = event::encode_query(&query(0, [0; 16], Status::Cached, 0), &wire(name), &mut buf);
    match event::decode(&buf[..len]) {
        Some(Record::Query(_, n)) => n,
        _ => unreachable!(),
    }
}

/// T3.1 AC shape, locally: 4 producers at a sustained 25k events/s each (100k/s total) for
/// 2 s, drained by the aggregator thread on its default period with the default ring size:
/// nothing may drop. The end-to-end AC runs on the homelab against the real server.
/// Optimized builds only: unoptimized, the aggregator is ~10× slower than shipped code.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "needs an optimized build: cargo test --release"
)]
fn obs_002_no_drops_at_100k_events_per_second() {
    let hub = Hub::new(4096 * 128);
    let aggregator = hub.spawn_aggregator(Duration::from_millis(25)).unwrap();
    let per_thread = 50_000u64; // 2 s at 25k/s
    let threads: Vec<_> = (0..4u8)
        .map(|t| {
            let hub = Arc::clone(&hub);
            std::thread::spawn(move || {
                let names: Vec<Vec<u8>> = (0..500)
                    .map(|i| wire(&format!("n{i}.example.com")))
                    .collect();
                let start = Instant::now();
                for i in 0..per_thread {
                    // Pace to 25k/s: busy-wait until this event's time slot.
                    let due = Duration::from_micros(i * 40);
                    while start.elapsed() < due {
                        std::hint::spin_loop();
                    }
                    let ev = query(
                        hub.ts_us(Instant::now()),
                        ipv4(10, 0, 1, t),
                        Status::Cached,
                        30,
                    );
                    hub.emit_query(&ev, &names[usize::try_from(i % 500).unwrap()]);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    drop(aggregator); // stops after a final drain
    let dropped: u64 = hub.ring_stats().iter().map(|s| s.2).sum();
    assert_eq!(dropped, 0);
    let agg = hub.aggregates();
    let total: u32 = agg
        .series(Resolution::Minute, 0, u64::MAX)
        .iter()
        .map(|(_, c)| c.total)
        .sum();
    assert_eq!(u64::from(total), 4 * per_thread);
}
