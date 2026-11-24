//! REQ: FLT-017 (AC 8) — what Kubernetes workloads add to client identification, the one
//! query-path step they touch: no table (every install without Kubernetes), 1,000 pod addresses
//! with the querier among them (a pod: one `ArcSwap` load, one hash lookup, one group-name
//! lookup), and 1,000 pod addresses with the querier not among them (a LAN device beside a
//! cluster: the load and a missed lookup).
//!
//! REQ: FLT-006 (ADR-183) — the MAC step of the same function: a table of 2, 200 and 10,000
//! entries (a Docker node, a home, a large site), read by a device named by its MAC.

// Made-up addresses from small counters; a bench's set-up may unwrap.
#![allow(clippy::cast_possible_truncation, clippy::unwrap_used)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{Criterion, criterion_group, criterion_main};
use telltale_config::Config;
use telltale_policy::{
    ClientTable, GroupOrigin, MacTable, Neighbors, Pod, Workload, WorkloadTable, Workloads,
};

fn table(n: u32) -> WorkloadTable {
    let workloads = (0..n / 10)
        .map(|w| {
            let (namespace, kind, name) = (format!("ns{}", w / 10), "deploy", format!("app{w}"));
            Workload {
                text: Workload::text_of(&namespace, kind, &name).into(),
                key: [
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    (w >> 8) as u8,
                    w as u8,
                ],
                namespace: namespace.into(),
                kind: kind.into(),
                name: name.into(),
                group: Some("default".into()),
                origin: GroupOrigin::NamespaceLabel,
                pods: (0..10)
                    .map(|p| {
                        let i = w * 10 + p;
                        Pod {
                            name: format!("app{w}-6c9f7b-{p}").into(),
                            ips: vec![IpAddr::V4(Ipv4Addr::new(
                                10,
                                42,
                                (i / 250) as u8,
                                (i % 250) as u8 + 1,
                            ))],
                            deleted_s: None,
                        }
                    })
                    .collect(),
                labels: Vec::new(),
            }
        })
        .collect();
    WorkloadTable::new(workloads)
}

fn identify(c: &mut Criterion) {
    let clients = ClientTable::from_config(&Config::default());
    let neighbors = Neighbors::default();
    let pod = IpAddr::V4(Ipv4Addr::new(10, 42, 2, 17));
    let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    let none = Workloads::default();
    let loaded = Workloads::default();
    loaded.replace(table(1_000));
    let mut g = c.benchmark_group("flt_017_identify");
    g.bench_function("no table", |b| {
        b.iter(|| clients.identify(black_box(lan), None, None, &neighbors, &none));
    });
    g.bench_function("1000 pods, pod", |b| {
        b.iter(|| clients.identify(black_box(pod), None, None, &neighbors, &loaded));
    });
    g.bench_function("1000 pods, not a pod", |b| {
        b.iter(|| clients.identify(black_box(lan), None, None, &neighbors, &loaded));
    });
    g.finish();
}

/// The device the MAC benches name by its MAC.
const TV_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01];

/// A MAC no named device has.
const OTHER_MAC: [u8; 6] = [0x02, 0xff, 0xff, 0xff, 0xff, 0xff];

/// A MAC table's `n` entries: `n - 2` made-up devices (`02:00:..` MACs from a counter), the TV
/// at `192.168.1.20`, and a device no named device has at `192.168.1.21`.
fn mac_entries(n: u32) -> Vec<(IpAddr, [u8; 6])> {
    let mut entries: Vec<(IpAddr, [u8; 6])> = (0..n.saturating_sub(2))
        .map(|i| {
            (
                IpAddr::V4(Ipv4Addr::new(10, (i >> 16) as u8, (i >> 8) as u8, i as u8)),
                [0x02, 0x00, 0x00, 0x00, (i >> 8) as u8, i as u8],
            )
        })
        .collect();
    entries.push((IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), TV_MAC));
    entries.push((IpAddr::V4(Ipv4Addr::new(192, 168, 1, 21)), OTHER_MAC));
    entries
}

/// A neighbor table of `n` entries, all from the kernel (as before ADR-183).
fn mac_table(n: u32) -> Neighbors {
    let table = Neighbors::default();
    table.replace(mac_entries(n));
    table
}

/// The clients of the MAC benches: one device, named by its MAC.
fn named_by_mac() -> ClientTable {
    ClientTable::from_config(
        &telltale_config::Loader::new()
            .toml_str(
                "bench.toml",
                "[[client]]\nname = \"tv\"\nmatch = [\"aa:bb:cc:00:00:01\"]\n",
            )
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config,
    )
}

/// REQ: FLT-006 (ADR-183) — the MAC step of `identify`. Without a device named by its MAC the
/// table is never read (the gate); with one, a querier whose MAC it holds is found by two hash
/// lookups, and one whose MAC no device has by the same two (the table's, then the devices').
fn identify_mac(c: &mut Criterion) {
    let none = ClientTable::from_config(&Config::default());
    let named = named_by_mac();
    let hit = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    let miss = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 21));
    let workloads = Workloads::none();
    let mut g = c.benchmark_group("flt_006_identify_mac");
    for n in [2_u32, 200, 10_000] {
        let neighbors = mac_table(n);
        g.bench_function(format!("{n} entries, no MAC client"), |b| {
            b.iter(|| none.identify(black_box(hit), None, None, &neighbors, workloads));
        });
        g.bench_function(format!("{n} entries, MAC client, hit"), |b| {
            b.iter(|| named.identify(black_box(hit), None, None, &neighbors, workloads));
        });
        g.bench_function(format!("{n} entries, MAC client, miss"), |b| {
            b.iter(|| named.identify(black_box(miss), None, None, &neighbors, workloads));
        });
    }
    g.finish();
}

/// REQ: FLT-006 (ADR-183) — head only (the base has no router entries): the same step when the
/// querier's MAC comes from a router, which is what a Docker node or a pod holds. A hit at 2, 200
/// and 10,000 entries, next to `flt_006_identify_mac` (the kernel's entries).
fn identify_router_mac(c: &mut Criterion) {
    let named = named_by_mac();
    let hit = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    let workloads = Workloads::none();
    let mut g = c.benchmark_group("flt_006_identify_router_mac");
    for n in [2_u32, 200, 10_000] {
        let neighbors = Neighbors::default();
        neighbors.swap(MacTable::from_sources([], mac_entries(n), [], 0));
        g.bench_function(format!("{n} entries, router MAC, hit"), |b| {
            b.iter(|| named.identify(black_box(hit), None, None, &neighbors, workloads));
        });
    }
    g.finish();
}

criterion_group!(benches, identify, identify_mac, identify_router_mac);
criterion_main!(benches);
