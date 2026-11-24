//! REQ: FLT-006 (ADR-183, spec/02 §3) — identifying a device by a MAC the kernel, a router or a
//! cluster member reports is on the query path: it allocates nothing. Its own test binary: the
//! allocation counter replaces the global allocator.

use std::hint::black_box;
use std::net::IpAddr;

use telltale_policy::{ClientTable, IdSource, MacTable, Neighbors, Workloads};

#[test]
fn flt_006_identifying_by_a_router_mac_allocates_nothing() {
    let cfg = telltale_config::Loader::new()
        .toml_str(
            "t.toml",
            "[[client]]\nname = \"tv\"\nmatch = [\"aa:bb:cc:00:00:01\"]\n",
        )
        .env(Vec::<(String, String)>::new())
        .load()
        .expect("config")
        .config;
    let clients = ClientTable::from_config(&cfg);
    let tv = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01];
    let stranger = [0x02, 0, 0, 0, 0, 0x99];
    let ip = |s: &str| -> IpAddr { s.parse().expect("address") };
    let (kernel, router, peer, absent, other) = (
        ip("192.168.1.10"),
        ip("192.168.1.11"),
        ip("::ffff:192.168.1.12"),
        ip("192.168.1.13"),
        ip("192.168.1.14"),
    );
    let neighbors = Neighbors::default();
    neighbors.swap(MacTable::from_sources(
        [(kernel, tv)],
        [(router, tv), (other, stranger)],
        [(peer, tv)],
        0,
    ));
    let source = |ip: IpAddr| {
        clients
            .identify(ip, None, None, &neighbors, Workloads::none())
            .source
    };
    // The first call sets up the shared empty workload table (a one-time allocation); it is
    // not what is measured.
    for ip in [kernel, router, peer, absent, other] {
        black_box(source(ip));
    }
    let info = allocation_counter::measure(|| {
        for _ in 0..1_000 {
            for ip in [kernel, router, peer, absent, other] {
                black_box(source(black_box(ip)));
            }
        }
    });
    assert_eq!(info.count_total, 0, "{info:?}");
    assert_eq!(source(kernel), IdSource::NeighborMac);
    assert_eq!(source(router), IdSource::RouterMac);
    assert_eq!(source(peer), IdSource::RouterMac);
    assert_eq!(source(absent), IdSource::Default);
}
