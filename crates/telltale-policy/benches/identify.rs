//! REQ: FLT-017 (AC 8) — what Kubernetes workloads add to client identification, the one
//! query-path step they touch: no table (every install without Kubernetes), 1,000 pod addresses
//! with the querier among them (a pod: one `ArcSwap` load, one hash lookup, one group-name
//! lookup), and 1,000 pod addresses with the querier not among them (a LAN device beside a
//! cluster: the load and a missed lookup).

#![allow(clippy::cast_possible_truncation)] // made-up addresses from small counters

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{Criterion, criterion_group, criterion_main};
use telltale_config::Config;
use telltale_policy::{
    ClientTable, GroupOrigin, Neighbors, Pod, Workload, WorkloadTable, Workloads,
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

criterion_group!(benches, identify);
criterion_main!(benches);
