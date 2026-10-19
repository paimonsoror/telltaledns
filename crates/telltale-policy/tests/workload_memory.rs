//! REQ: FLT-017 (AC 8) — the workload table for 1,000 pods, with one history interval per
//! address, stays under 300 KB of heap. Its own test binary: the allocation counter replaces
//! the global allocator.

#![allow(clippy::cast_possible_truncation)] // made-up addresses from small counters

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use telltale_policy::{GroupOrigin, Interval, Pod, Workload, WorkloadTable};

/// 100 Deployments of 10 pods each, named like real ones.
fn build(n: u32) -> WorkloadTable {
    let mut history: HashMap<IpAddr, Vec<Interval>> = HashMap::new();
    let workloads = (0..n / 10)
        .map(|w| {
            let (namespace, kind, name) = (
                format!("namespace-{}", w / 10),
                "deploy",
                format!("application-{w}"),
            );
            let text = Workload::text_of(&namespace, kind, &name);
            let mut key = [0u8; 16];
            key[0] = 1;
            key[14] = (w >> 8) as u8;
            key[15] = w as u8;
            let pods = (0..10)
                .map(|p| {
                    let i = w * 10 + p;
                    let ip =
                        IpAddr::V4(Ipv4Addr::new(10, 42, (i / 250) as u8, (i % 250) as u8 + 1));
                    history.entry(ip).or_default().push(Interval {
                        text: text.as_str().into(),
                        key,
                        from_s: 1_000,
                        to_s: None,
                    });
                    Pod {
                        name: format!("application-{w}-6c9f7b8d4-{p:05}").into(),
                        ips: vec![ip],
                        deleted_s: None,
                    }
                })
                .collect();
            Workload {
                text: text.into(),
                key,
                namespace: namespace.into(),
                kind: kind.into(),
                name: name.into(),
                group: Some("media".into()),
                origin: GroupOrigin::NamespaceLabel,
                pods,
                labels: vec![(
                    "app.kubernetes.io/name".into(),
                    format!("application-{w}").into(),
                )],
            }
        })
        .collect();
    WorkloadTable::new(workloads).with_history(history)
}

#[test]
fn flt_017_table_and_history_for_1000_pods_under_300_kb() {
    let mut table = None;
    let info = allocation_counter::measure(|| {
        table = Some(build(1_000));
    });
    let t = table.expect("built");
    assert!(t.get(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1))).is_some());
    let kb = info.bytes_current / 1024;
    println!(
        "1,000 pods: {kb} KB on the heap ({} allocations live)",
        info.count_current
    );
    assert!(kb < 300, "{kb} KB");
}
