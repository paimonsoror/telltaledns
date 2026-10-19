use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use telltale_telemetry::seen::{Window, WindowEntry};

use super::*;

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
}

fn key(last: u8) -> [u8; 16] {
    mapped(ip(last))
}

// REQ: CLU-014 (AC 1) — the gate: targets by address, name, workload, or group are dropped;
// loopback, infrastructure, cluster nodes, and excluded devices never are, even under `all`.
#[test]
fn clu_014_targets_drop_and_spare() {
    let t = Targets {
        ips: HashSet::from([ip(14)]),
        names: HashSet::from(["kids-tablet".into()]),
        workloads: HashSet::from(["media/deploy/jellyfin".into()]),
        group: Some("iot".into()),
        spared_ips: HashSet::from([ip(2)]),
        ..Targets::default()
    };
    let none: &[Box<str>] = &[];
    assert!(t.drops(ip(14), None, None, none));
    assert!(t.drops(ip(15), Some("kids-tablet"), None, none));
    assert!(t.drops(ip(16), None, Some("media/deploy/jellyfin"), none));
    assert!(t.drops(ip(17), None, None, &["iot".into()]));
    assert!(
        !t.drops(ip(18), None, None, &["home".into()]),
        "not a target"
    );
    let all = Targets {
        all: true,
        spared_ips: HashSet::from([ip(2)]),
        spared_nets: vec![telltale_config::Cidr::parse("10.42.0.0/16").unwrap()],
        excluded: Some(Arc::new(telltale_telemetry::exclude::Exclusions::new(
            Vec::<Vec<u8>>::new(),
            &[(ip(99), 32)],
        ))),
        ..Targets::default()
    };
    assert!(all.drops(ip(18), None, None, none));
    assert!(
        !all.drops(IpAddr::V4(Ipv4Addr::LOCALHOST), None, None, none),
        "loopback"
    );
    assert!(!all.drops(ip(2), None, None, none), "a cluster node");
    assert!(
        !all.drops("10.42.3.4".parse().unwrap(), None, None, none),
        "infrastructure"
    );
    assert!(!all.drops(ip(99), None, None, none), "excluded");
    // The gate: nothing while no drill runs; the targets until the end.
    let g = Gate::default();
    assert!(g.active().is_none());
    g.set(all, now_ms() + 60_000);
    assert!(g.active().is_some_and(|t| t.all));
    g.clear();
    assert!(g.active().is_none());
    g.set(Targets::default(), now_ms().saturating_sub(1));
    assert!(g.active().is_none(), "past its end");
}

// REQ: CLU-014 (AC 1) — in the pipeline: a target's query gets no answer (`Close`) and is
// logged as `drilled`; another device is answered.
#[test]
fn clu_014_pipeline_drops_targets() {
    use telltale_telemetry::event::Record;
    let p = crate::pipeline::tests_support::pipeline_from(&telltale_config::Config::default());
    let mut drain = p.telemetry.drainer();
    assert!(crate::pipeline::tests_support::answer(
        &p,
        "localhost",
        "192.168.1.14"
    ));
    p.drill.set(
        Targets {
            ips: HashSet::from([ip(14)]),
            ..Targets::default()
        },
        now_ms() + 60_000,
    );
    assert!(!crate::pipeline::tests_support::answer(
        &p,
        "localhost",
        "192.168.1.14"
    ));
    assert!(crate::pipeline::tests_support::answer(
        &p,
        "localhost",
        "192.168.1.15"
    ));
    let mut statuses = Vec::new();
    drain.drain(|r| {
        if let Record::Query(e, _) = r {
            statuses.push((key_text(&e.client_ip), e.status));
        }
    });
    assert!(statuses.contains(&("192.168.1.14".into(), telltale_telemetry::Status::Drilled)));
    assert!(
        statuses
            .iter()
            .any(|(c, s)| c == "192.168.1.15" && *s != telltale_telemetry::Status::Drilled)
    );
    assert_eq!(p.drill.dropped.load(Ordering::Relaxed), 1);
}

fn entry(
    first: u64,
    last: u64,
    queries: u32,
    drilled: u32,
    first_d: u64,
    last_d: u64,
) -> WindowEntry {
    WindowEntry {
        first_ms: first,
        last_ms: last,
        queries,
        drilled,
        first_drilled_ms: first_d,
        last_drilled_ms: last_d,
    }
}

// REQ: CLU-014 (AC 4) — the verdicts: a device another node answered after its first dropped
// query and by 5 s after the end `followed` (time to failover from the two), one with 3+
// dropped and no such answer `stuck`, a target with nothing dropped or too little to tell
// `quiet`, a non-target seen elsewhere `elsewhere`; coverage = followed / (followed + stuck).
// The first live drill (2026-10-19) showed the two cases a looser rule got wrong: an answer
// elsewhere after the drill was over, and a target that only asked elsewhere.
#[test]
fn clu_014_verdicts() {
    let mut pi = Window::new("d1", 1_000);
    pi.clients
        .insert(key(10), entry(1_000, 1_000, 1, 1, 1_000, 1_000)); // laptop: one drop
    pi.clients
        .insert(key(11), entry(1_100, 9_000, 6, 6, 1_100, 9_000)); // tv: stuck
    pi.clients
        .insert(key(12), entry(1_200, 1_200, 1, 1, 1_200, 1_200)); // quiet-ish
    pi.clients
        .insert(key(14), entry(1_400, 1_400, 1, 1, 1_400, 1_400)); // hub: one drop
    pi.clients
        .insert(key(15), entry(1_500, 2_000, 3, 3, 1_500, 2_000)); // three drops
    pi.clients
        .insert(key(17), entry(3_000, 3_000, 1, 1, 3_000, 3_000)); // asks both
    let mut k8s = Window::new("d1", 1_000);
    k8s.clients.insert(key(10), entry(2_250, 8_000, 9, 0, 0, 0)); // laptop followed
    k8s.clients.insert(key(20), entry(1_500, 3_000, 4, 0, 0, 0)); // not a target
    k8s.clients
        .insert(key(14), entry(40_000, 40_000, 1, 0, 0, 0)); // after the end + 5 s
    k8s.clients
        .insert(key(15), entry(50_000, 50_000, 1, 0, 0, 0)); // likewise
    k8s.clients.insert(key(16), entry(5_000, 6_000, 2, 0, 0, 0)); // nothing dropped
    k8s.clients
        .insert(key(17), entry(1_000, 20_000, 5, 0, 0, 0)); // before and after
    let parts = vec![("pi".to_owned(), pi), ("k8s".to_owned(), k8s)];
    let targets: HashSet<[u8; 16]> = (10..=17).map(key).collect();
    let names = HashMap::from([(
        key(10),
        (Some("laptop".to_owned()), Some("home".to_owned())),
    )]);
    let c = compute(&Input {
        drilled: "pi",
        parts: &parts,
        targets: &targets,
        since_ms: 1_000,
        ended_ms: 31_000,
        names: &names,
    });
    let v: HashMap<String, (&str, Option<u64>)> = c
        .devices
        .iter()
        .map(|d| {
            (
                d.client.clone(),
                (d.verdict.as_str(), d.time_to_failover_ms),
            )
        })
        .collect();
    assert_eq!(v["192.168.1.10"], ("followed", Some(1_250)));
    assert_eq!(v["192.168.1.11"], ("stuck", None));
    assert_eq!(
        v["192.168.1.12"].0, "quiet",
        "one dropped query tells nothing"
    );
    assert_eq!(v["192.168.1.13"].0, "quiet", "a target that never asked");
    assert_eq!(
        v["192.168.1.14"].0, "quiet",
        "asked elsewhere only after the drill was over"
    );
    assert_eq!(
        v["192.168.1.15"],
        ("stuck", None),
        "3 dropped; the answer elsewhere came too late"
    );
    assert_eq!(
        v["192.168.1.16"].0, "quiet",
        "nothing dropped: no evidence either way"
    );
    assert_eq!(
        v["192.168.1.17"],
        ("followed", None),
        "it asked the other node before and after: time unknown"
    );
    assert_eq!(v["192.168.1.20"].0, "elsewhere");
    assert_eq!((c.followed, c.stuck, c.quiet, c.elsewhere), (2, 2, 4, 1));
    assert_eq!(c.coverage_percent, Some(50.0));
    assert_eq!((c.median_ms, c.p90_ms), (Some(1_250), Some(1_250)));
    assert_eq!(c.devices[0].verdict, "stuck", "stuck first");
    let laptop = c
        .devices
        .iter()
        .find(|d| d.client == "192.168.1.10")
        .unwrap();
    assert_eq!(laptop.name.as_deref(), Some("laptop"));
    assert_eq!(laptop.nodes, vec!["k8s".to_owned()]);
    assert_eq!(c.last_dropped_ms, Some(9_000));
    let nodes: HashMap<&str, u64> = c
        .nodes
        .iter()
        .map(|n| (n.node.as_str(), n.queries))
        .collect();
    assert_eq!((nodes["pi"], nodes["k8s"]), (13, 22));
}

// REQ: CLU-014 (AC 2, 3) — on a single node a drill is refused ("no other node", 409
// `drill_refused`); a dry run lists every check without dropping anything; an unknown group
// is 422 `drill_targets`.
#[tokio::test]
async fn clu_014_preconditions() {
    let src = Arc::new(crate::http::tests::sources_in(&tmp()));
    let all = || DrillTargets::All(telltale_api::model::DrillAll::All);
    let req = |spec: DrillTargets, dry_run: bool, mode: DrillMode| Request {
        for_secs: 60,
        spec,
        reason: "test".into(),
        handover: true,
        by: "alice".into(),
        dry_run,
        mode,
    };
    let dry = start_here(Arc::clone(&src), req(all(), true, DrillMode::Drop))
        .await
        .unwrap();
    assert!(dry.dry_run && dry.id.is_empty());
    let other = dry.checks.iter().find(|c| c.name == "other_node").unwrap();
    assert!(!other.ok, "{other:?}");
    assert!(dry.checks.iter().any(|c| c.name == "health"));
    assert!(dry.preview.contains("will not answer"), "{}", dry.preview);
    assert!(
        src.pipeline.drill.active().is_none(),
        "a dry run drops nothing"
    );
    let refused = start_here(Arc::clone(&src), req(all(), true, DrillMode::Refused))
        .await
        .unwrap();
    assert!(refused.preview.contains("REFUSED"), "{}", refused.preview);
    let e = start_here(Arc::clone(&src), req(all(), false, DrillMode::Drop))
        .await
        .unwrap_err();
    assert_eq!((e.code, e.status), (Code::DrillRefused, 409));
    assert!(e.detail.contains("No other node"), "{}", e.detail);
    let nope = DrillTargets::Group {
        group: "nope".into(),
    };
    let e = start_here(Arc::clone(&src), req(nope, true, DrillMode::Drop))
        .await
        .unwrap_err();
    assert_eq!((e.code, e.status), (Code::DrillTargets, 422));
}

// REQ: CLU-014 (owner 2026-10-19) — the REFUSED mode: a target gets REFUSED (EDE 14, "failover
// drill") at once, logged as `drilled`.
#[test]
fn clu_014_refused_mode_answers_refused() {
    use telltale_net::{QueryHandler, RequestMeta, Response, Transport};
    let p = crate::pipeline::tests_support::pipeline_from(&telltale_config::Config::default());
    p.drill.set(
        Targets {
            ips: HashSet::from([ip(14)]),
            refused: true,
            ..Targets::default()
        },
        now_ms() + 60_000,
    );
    let qname = telltale_proto::NameBuf::from_presentation("localhost").unwrap();
    let mut query = [0u8; 512];
    let len = telltale_proto::build_query(
        &mut query,
        7,
        &qname,
        telltale_proto::rtype::A,
        1,
        true,
        None,
    )
    .unwrap();
    let meta = RequestMeta {
        peer: "192.168.1.14:1000".parse().unwrap(),
        local: None,
        transport: Transport::Udp,
        client_id: None,
    };
    let mut out = [0u8; 4096];
    let Response::Ready(answered) =
        crate::pipeline::Handler(Arc::clone(&p)).handle(&query[..len], &meta, &mut out)
    else {
        panic!("REFUSED is an answer");
    };
    let summary = telltale_proto::summarize(&out[..answered]).unwrap();
    assert_eq!(summary.rcode, telltale_proto::rcode::REFUSED);
    assert_eq!(p.drill.dropped.load(Ordering::Relaxed), 1);
}

// REQ: CLU-014 (AC 2) — a restart during a drill cancels it: the window file is removed, the
// node is ready at once, nothing is dropped, and the report says `cancelled`.
#[test]
fn clu_014_restart_cancels() {
    let src = crate::http::tests::sources_in(&tmp());
    let now = now_ms();
    let id = "d1-abcdef01";
    let s = Stored {
        report: DrillReport {
            summary: DrillSummary {
                id: id.into(),
                status: "running".into(),
                ..DrillSummary::default()
            },
            ..DrillReport::default()
        },
        since_ms: now,
        until_ms: now + 60_000,
        ended_ms: None,
        baseline: Vec::new(),
        targets: Vec::new(),
        first_try_ms: None,
        waiting: Vec::new(),
    };
    save(&src, &s);
    src.maintenance
        .start(crate::maintenance::Window {
            until_ms: now + 60_000,
            since_ms: now,
            reason: "failover drill: test".into(),
            by: "alice".into(),
            handover: false,
            drill: Some(id.into()),
        })
        .unwrap();
    assert!(!src.readiness.ready());
    // The process restarts: the maintenance file is read again.
    let dir = std::path::PathBuf::from(src.config.load().node.data_dir.as_str());
    let readiness = Arc::new(crate::readiness::Readiness::ready_now());
    let m = crate::maintenance::Maintenance::open(&dir, Arc::clone(&readiness), None, now + 1_000);
    assert!(readiness.ready(), "ready at once");
    assert!(m.current(now + 1_000).is_none(), "not resumed");
    assert!(!dir.join(crate::maintenance::FILE).exists());
    let src = crate::http::Sources {
        maintenance: Arc::new(m),
        ..crate::http::tests::sources_in(&dir)
    };
    cancelled_at_start(&src);
    assert_eq!(load(&src, id).unwrap().report.summary.status, "cancelled");
    assert_eq!(src.drills.cancelled.load(Ordering::Relaxed), 1);
    let mut w = telltale_telemetry::prom::PromWriter::new();
    render(&src, &mut w);
    let m = w.finish();
    assert!(
        m.contains("telltale_drills_total{result=\"cancelled\"} 1"),
        "{m}"
    );
}

// REQ: CLU-014 (AC 6) — the seen table survives a restart (saved, then folded into a fresh
// one) and honours exclusions (excluded queries never reach the analytics).
#[test]
fn clu_014_seen_table_persists() {
    let src = crate::http::tests::sources_in(&tmp());
    let now_s = now_ms() / 1000;
    src.pipeline
        .telemetry
        .aggregates()
        .seen_mut()
        .add(key(14), now_s);
    save_seen(&src);
    let dir = std::path::PathBuf::from(src.config.load().node.data_dir.as_str());
    let again = crate::http::tests::sources_in(&dir);
    load_seen(&again);
    let rows = seen_rows(&again, 7);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (key_text(&rows[0].key), rows[0].queries),
        ("192.168.1.14".into(), 1)
    );
    let page = affinity_page(
        7,
        vec![
            ("pi".into(), rows),
            (
                "k8s".into(),
                vec![SeenRow {
                    key: key(14),
                    queries: 9,
                    name: Some("laptop".into()),
                }],
            ),
        ],
        Vec::new(),
    );
    let r = &page.items[0];
    assert_eq!(
        (r.queries, r.top_node.as_str(), r.top_share_percent),
        (10, "k8s", 90.0)
    );
    assert_eq!(r.label, "mostly k8s");
    assert_eq!(r.name.as_deref(), Some("laptop"));
    assert!(page.caveat.contains("Run a drill"));
}

// REQ: CLU-014 — reports page newest first with a cursor; IDs are checked before they name a
// file.
#[test]
fn clu_014_pages_and_ids() {
    let s = |id: &str, since: &str| DrillSummary {
        id: id.into(),
        since: since.into(),
        ..DrillSummary::default()
    };
    let p = page(
        vec![
            s("a", "2026-10-19T01:00:00Z"),
            s("b", "2026-10-19T02:00:00Z"),
            s("c", "2026-10-19T03:00:00Z"),
        ],
        2,
        0,
        vec!["pod-1".into()],
    );
    assert_eq!(
        p.items.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
        ["c", "b"]
    );
    assert_eq!(p.next_cursor.as_deref(), Some("2"));
    assert_eq!(p.missing_nodes, ["pod-1"]);
    assert!(valid_id("d1792386720727-0a1b2c3d"));
    assert!(!valid_id("../etc/passwd") && !valid_id("") && !valid_id("a/b"));
    assert_eq!(
        host_ip("https://192.168.3.2:8443"),
        Some("192.168.3.2".parse().unwrap())
    );
    assert_eq!(
        host_ip("https://[fd00::2]:8443/x"),
        Some("fd00::2".parse().unwrap())
    );
}

/// A fresh data directory.
fn tmp() -> std::path::PathBuf {
    let r: u32 = rand::random();
    std::env::temp_dir().join(format!("telltale-drill-{}-{r:08x}", std::process::id()))
}
