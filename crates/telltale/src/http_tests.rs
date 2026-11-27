// REQ: moved out of `http.rs` so the test code is a file of its own (CodeQL ignores test paths).
use std::time::Duration;

use telltale_cache::CachePolicy;
use telltale_telemetry::{Proto, Status};

use super::*;

pub(crate) fn sources() -> Sources {
    let dir = std::env::temp_dir().join(format!(
        "telltale-http-{}-{}",
        std::process::id(),
        crate::maintenance::now_ms()
    ));
    let mut s = sources_in(&dir);
    // Most tests don't care where state goes; keep the default configuration they expect.
    s.config = ArcSwap::from_pointee(telltale_config::Config::default());
    s
}

/// REQ: CLU-014 — sources whose data directory (and configuration's) is `dir`: a second call
/// with the same directory is the node after a restart.
pub(crate) fn sources_in(dir: &std::path::Path) -> Sources {
    let metrics = Arc::new(Metrics::new(2));
    metrics.record(
        Proto::Udp,
        Status::Cached,
        Some(0),
        1,
        Duration::from_micros(80),
    );
    let cache = Arc::new(Cache::new(CachePolicy::default()));
    let readiness = Arc::new(crate::readiness::Readiness::ready_now());
    let _ = std::fs::create_dir_all(dir);
    let mut cfg = telltale_config::Config::default();
    if let Some(d) = dir
        .to_str()
        .and_then(|d| telltale_config::SafeString::new(d).ok())
    {
        cfg.node.data_dir = d;
    }
    Sources {
        identify: Arc::new(crate::identify::Identifier::open(dir)),
        rollout: Arc::default(),
        maintenance: Arc::new(crate::maintenance::Maintenance::open(
            dir,
            Arc::clone(&readiness),
            None,
            0,
        )),
        drills: Arc::default(),
        readiness,
        metrics,
        cache: Arc::clone(&cache),
        pipeline: crate::pipeline::Pipeline::new(
            crate::pipeline::Settings::default(),
            cache,
            Arc::new(Router::default()),
            crate::pipeline::Policy::default(),
        ),
        udp: ArcSwap::from_pointee(Vec::new()),
        tcp: ArcSwap::from_pointee(Vec::new()),
        doh: ArcSwap::from_pointee(Vec::new()),
        doq: ArcSwap::from_pointee(Vec::new()),
        started: Instant::now(),
        lists: ArcSwapOption::empty(),
        qlog: None,
        config: ArcSwap::from_pointee(cfg),
        file_config: ArcSwap::from_pointee(telltale_config::Config::default()),
        managed_base: ArcSwapOption::empty(),
        files_unread: std::sync::atomic::AtomicBool::new(false),
        config_files: Vec::new(),
        update: Arc::new(std::sync::Mutex::new(crate::updates::initial(false))),
        rollups: None,
        tail: None,
        anomalies: None,
        host: Arc::default(),
        cache_history: Arc::default(),
        auth: std::sync::OnceLock::new(),
        identities_applied: std::sync::Mutex::default(),
        alerts: std::sync::Mutex::default(),
        masking: crate::masking::Detector::default(),
        cluster: None,
        ship: Arc::default(),
        git_poke: Arc::default(),
        reload: tokio::sync::mpsc::channel(1).0,
        config_writes: tokio::sync::Mutex::new(()),
        allowed: Vec::new(),
        probes: Arc::default(),
        shadow: Arc::new(crate::shadow::Shadow::new(0, 0)),
        traces: Arc::default(),
    }
}

/// REQ: OPS-006 — the health endpoints through the router: `/healthz` and `/livez` answer as
/// long as the process does; `/readyz` is 503 `starting` until every listener is bound and,
/// for a resolver pod, the cluster's configuration is applied, then 200.
#[tokio::test]
async fn ops_006_health_endpoints() {
    use tower::ServiceExt as _;
    let mut src = sources();
    src.readiness = Arc::new(crate::readiness::Readiness::new(true));
    // The listener answers only `allowed_networks`; the test asks from loopback.
    src.allowed = vec![telltale_config::Cidr::parse("127.0.0.0/8").unwrap()];
    let src = Arc::new(src);
    let get = |path: &'static str| {
        let app = router(Arc::clone(&src));
        async move {
            let req = axum::http::Request::builder()
                .uri(path)
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    40000,
                ))))
                .body(axum::body::Body::empty())
                .unwrap();
            let r = app.oneshot(req).await.unwrap();
            let status = r.status().as_u16();
            let body = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        }
    };
    assert_eq!(get("/healthz").await, (200, "ok\n".into()));
    assert_eq!(get("/livez").await, (200, "ok\n".into()));
    let (status, body) = get("/readyz").await;
    assert_eq!(status, 503, "nothing bound yet: {body}");
    assert!(body.contains("\"ready\":false"), "{body}");
    src.readiness.set_bound();
    assert_eq!(
        get("/readyz").await.0,
        503,
        "bound, still waiting for the configuration"
    );
    src.readiness.set_synced();
    assert_eq!(get("/readyz").await, (200, "{\"ready\":true}\n".into()));
    assert_eq!(get("/healthz").await.0, 200);
}

/// REQ: OPS-010, OPS-006 — `/readyz` is 503 with the reason during maintenance (and the
/// startup view isn't), 200 again after; the maintenance gauges follow.
#[tokio::test]
async fn ops_010_readyz_reasons_and_metrics() {
    let src = Arc::new(sources());
    let ask = |src: &Arc<Sources>, startup: Option<&str>| {
        let src = Arc::clone(src);
        let q = ReadyQuery {
            startup: startup.map(ToOwned::to_owned),
        };
        async move {
            let r = readyz(State(src), axum::extract::Query(q)).await;
            let status = r.status().as_u16();
            let body = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        }
    };
    assert_eq!(ask(&src, None).await, (200, "{\"ready\":true}\n".into()));
    let now = crate::maintenance::now_ms();
    src.maintenance
        .start(crate::maintenance::Window {
            until_ms: now + 60_000,
            since_ms: now,
            reason: "SD card swap".into(),
            by: "alice".into(),
            handover: false,
            drill: None,
        })
        .unwrap();
    assert_eq!(
        ask(&src, None).await,
        (503, "{\"ready\":false,\"reason\":\"maintenance\"}\n".into())
    );
    assert_eq!(
        ask(&src, Some("1")).await.0,
        200,
        "the startup probe passes"
    );
    let text = render(&src);
    assert!(text.contains("telltale_node_maintenance 1"), "{text}");
    assert!(text.contains("telltale_node_maintenance_total 1"));
    src.maintenance.end().unwrap();
    assert_eq!(ask(&src, None).await.0, 200);
    assert!(render(&src).contains("telltale_node_maintenance 0"));
    src.readiness.set_stopping();
    assert_eq!(
        ask(&src, Some("1")).await,
        (
            503,
            "{\"ready\":false,\"reason\":\"shutting_down\"}\n".into()
        )
    );
}

/// REQ: OBS-017 (T11.6) — `/metrics` answers OpenMetrics (ending in `# EOF`) to a scraper
/// that asks for it, the Prometheus text format otherwise or with `exemplars = false`.
#[tokio::test]
async fn obs_017_metrics_negotiates_openmetrics() {
    let src = Arc::new(sources());
    let ask = |src: &Arc<Sources>, accept: Option<&'static str>| {
        let src = Arc::clone(src);
        async move {
            let mut h = header::HeaderMap::new();
            if let Some(a) = accept {
                h.insert(header::ACCEPT, header::HeaderValue::from_static(a));
            }
            let r = metrics(State(src), h).await;
            let ct = r.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .to_owned();
            let body = axum::body::to_bytes(r.into_body(), usize::MAX)
                .await
                .unwrap();
            (ct, String::from_utf8(body.to_vec()).unwrap())
        }
    };
    let om = "application/openmetrics-text;version=1.0.0,text/plain;version=0.0.4;q=0.5";
    let (ct, body) = ask(&src, Some(om)).await;
    assert!(ct.starts_with("application/openmetrics-text"), "{ct}");
    assert!(body.ends_with("# EOF\n"));
    assert!(body.contains("# TYPE telltale_queries counter\n"));
    let (ct, body) = ask(&src, None).await;
    assert_eq!(ct, CONTENT_TYPE);
    assert!(!body.contains("# EOF"));
    let mut cfg = telltale_config::Config::default();
    cfg.telemetry.metrics.exemplars = false;
    src.config.store(Arc::new(cfg));
    assert_eq!(ask(&src, Some(om)).await.0, CONTENT_TYPE);
}

#[test]
fn obs_005_render_includes_core_families() {
    let src = sources();
    let text = render(&src);
    for family in [
        "telltale_build_info",
        "telltale_queries_total",
        "telltale_query_duration_seconds",
        "telltale_cache_hits_total",
        "telltale_upstream_requests_total",
        "telltale_upstream_failures_total",
        "telltale_udp_received_total",
        "telltale_tcp_connections_total",
        "telltale_tcp_stalled_closed_total",
    ] {
        assert!(
            text.contains(&format!("# TYPE {family} ")),
            "missing {family}"
        );
    }
    assert!(text.contains("telltale_queries_total{proto=\"udp\",status=\"cached\"} 1"));
    assert!(text.contains("telltale_local_records 0"));
}

/// REQ: DNS-020 (ADR-039) — connections whose PROXY header named no client address are one
/// counter with a `kind` label, summed over the `tcp`, `dot` and `doh` listeners; with no such
/// connection every kind is there, at 0.
#[test]
fn dns_020_proxy_headers_without_an_address_are_exported_by_kind() {
    use std::sync::atomic::Ordering::Relaxed;
    let src = sources();
    let text = render(&src);
    assert!(
        text.contains("# TYPE telltale_proxy_protocol_no_address_total counter\n"),
        "{text}"
    );
    for kind in ["local", "unspec", "unix"] {
        let series = format!("telltale_proxy_protocol_no_address_total{{kind=\"{kind}\"}}");
        assert_eq!(sample_value(&text, &series), Some(0), "{series}");
    }
    let (tcp, dot, doh) = (
        Arc::new(TcpStats::default()),
        Arc::new(TcpStats::default()),
        Arc::new(DohStats::default()),
    );
    tcp.proxy_no_address.local.fetch_add(2, Relaxed);
    dot.proxy_no_address.unix.fetch_add(1, Relaxed);
    doh.proxy_no_address.local.fetch_add(1, Relaxed);
    doh.proxy_no_address.unspec.fetch_add(4, Relaxed);
    src.tcp.store(Arc::new(vec![tcp, dot]));
    src.doh.store(Arc::new(vec![doh]));
    let text = render(&src);
    for (kind, want) in [("local", 3), ("unspec", 4), ("unix", 1)] {
        let series = format!("telltale_proxy_protocol_no_address_total{{kind=\"{kind}\"}}");
        assert_eq!(sample_value(&text, &series), Some(want), "{series}");
    }
    assert_eq!(
        sample_value(&text, "telltale_proxy_protocol_rejected_total"),
        Some(0)
    );
}

/// REQ: DNS-003, OBS-005 (ADR-194) — the refusals of `doh` listeners behind listed proxies are one
/// counter with a `reason` label, summed over the DoH listeners; with none, both reasons are
/// there, at 0. A refusal is never counted as a kept no-address connection.
#[test]
fn dns_003_forwarded_refusals_are_exported_by_reason() {
    use std::sync::atomic::Ordering::Relaxed;
    let src = sources();
    let text = render(&src);
    assert!(
        text.contains("# TYPE telltale_doh_forwarded_refused_total counter\n"),
        "{text}"
    );
    for reason in ["unlisted_peer", "no_client_address"] {
        let series = format!("telltale_doh_forwarded_refused_total{{reason=\"{reason}\"}}");
        assert_eq!(sample_value(&text, &series), Some(0), "{series}");
    }
    let (a, b) = (Arc::new(DohStats::default()), Arc::new(DohStats::default()));
    a.unlisted_peer.fetch_add(2, Relaxed);
    a.no_client_address.fetch_add(1, Relaxed);
    b.unlisted_peer.fetch_add(5, Relaxed);
    b.no_client_address.fetch_add(3, Relaxed);
    src.doh.store(Arc::new(vec![a, b]));
    let text = render(&src);
    for (reason, want) in [("unlisted_peer", 7), ("no_client_address", 4)] {
        let series = format!("telltale_doh_forwarded_refused_total{{reason=\"{reason}\"}}");
        assert_eq!(sample_value(&text, &series), Some(want), "{series}");
    }
    for kind in ["local", "unspec", "unix"] {
        let series = format!("telltale_proxy_protocol_no_address_total{{kind=\"{kind}\"}}");
        assert_eq!(sample_value(&text, &series), Some(0), "{series}");
    }
}

/// REQ: FLT-003, OBS-011 (review 02-09) — the active filter's lookup mode is a gauge: none
/// without a filter, `walk` for a matcher without the index (as before the index is built, or
/// when the snapshot has too many list combinations for it).
#[test]
fn obs_011_lookup_mode_is_exported() {
    let src = sources();
    assert!(!render(&src).contains("telltale_filter_lookup_mode"));
    let matcher = telltale_filter::matcher::Matcher::new(None).unwrap();
    src.pipeline.set_filter(Some(Arc::new(matcher)));
    let text = render(&src);
    assert!(
        text.contains("telltale_filter_lookup_mode{mode=\"walk\"} 1"),
        "{text}"
    );
    assert!(text.contains("telltale_filter_lookup_mode{mode=\"indexed\"} 0"));
}

#[test]
fn ops_003_masked_client_ips_reach_metrics_and_api() {
    use telltale_telemetry::event::{Name, Record};
    let src = sources();
    assert!(render(&src).contains("telltale_client_ips_masked 0"));
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros())
        .try_into()
        .unwrap_or(0);
    let event = |last: u8| telltale_telemetry::QueryEvent {
        ts_us: now_us,
        client_ip: std::net::Ipv4Addr::new(127, 0, 0, last)
            .to_ipv6_mapped()
            .octets(),
        client_ref: 0,
        group: 0,
        qtype: 1,
        qclass: 1,
        rcode: Some(0),
        status: Status::Forwarded,
        proto: Proto::Udp,
        flags: 0x8180,
        rule: None,
        upstream: 1,
        attempts: 1,
        t_total_us: 100,
        t_upstream_us: 90,
        resp_size: 60,
        answers: 1,
    };
    {
        let mut agg = src.pipeline.telemetry.aggregates();
        for _ in 0..140 {
            agg.record(&Record::Query(event(1), Name::default()));
        }
        agg.record(&Record::Query(event(2), Name::default()));
    }
    assert!(render(&src).contains("telltale_client_ips_masked 1"));
    let m = src.masked_clients().unwrap();
    assert_eq!((m.share_percent, m.queries), (100, 141));
    assert_eq!(m.sources, ["127.0.0.1", "127.0.0.2"]);
}

/// REQ: OBS-002, OBS-005 — rings of threads that share a name (Tokio's workers) are one
/// series each, summed: a label set never repeats within a scrape (Prometheus would keep
/// only the first sample).
#[test]
fn obs_005_ring_series_are_unique_per_thread_name() {
    let hub = telltale_telemetry::Hub::new(1 << 16);
    let ev = telltale_telemetry::QueryEvent {
        ts_us: 1,
        client_ip: [0; 16],
        client_ref: 0,
        group: 0,
        qtype: 1,
        qclass: 1,
        rcode: Some(0),
        status: Status::Cached,
        proto: Proto::Udp,
        flags: 0x8180,
        rule: None,
        upstream: 0,
        attempts: 0,
        t_total_us: 10,
        t_upstream_us: 0,
        resp_size: 60,
        answers: 1,
    };
    let workers: Vec<_> = (0..3)
        .map(|_| {
            let hub = Arc::clone(&hub);
            std::thread::Builder::new()
                .name("twin".into())
                .spawn(move || hub.emit_query(&ev, b"\x01a\x00"))
                .unwrap()
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let mut w = PromWriter::new();
    render_telemetry(&mut w, &hub);
    let text = w.finish();
    assert!(
        text.contains("telltale_telemetry_events_total{ring=\"twin\"} 3"),
        "{text}"
    );
    assert!(
        text.contains("telltale_telemetry_dropped_total{ring=\"twin\"} 0"),
        "{text}"
    );
    assert_eq!(text.matches("ring=\"twin\"").count(), 2, "{text}");
}

// REQ: FLT-004 — an inline list is never fetched, so it reports no last-success time (it would
// trip the "> 48 h" list alert two days after every config edit); its other gauges remain.
#[test]
fn flt_004_inline_lists_report_no_last_success() {
    let meta = |source: &str| ListMeta {
        source: source.into(),
        content_hash: Some("h".into()),
        bytes: 10,
        last_success: Some(1_000),
        last_changed: Some(900),
        ..ListMeta::default()
    };
    let status = vec![
        ("remote".to_owned(), meta("https://example.com/l.txt")),
        ("allowed".to_owned(), meta("inline:0123456789abcdef")),
    ];
    let mut w = PromWriter::new();
    render_list_status(&mut w, &status);
    let text = w.finish();
    assert!(
        text.contains("telltale_list_last_success_timestamp_seconds{list=\"remote\"} 1000"),
        "{text}"
    );
    assert!(
        !text.contains("telltale_list_last_success_timestamp_seconds{list=\"allowed\"}"),
        "{text}"
    );
    for family in [
        "telltale_list_source_bytes",
        "telltale_list_last_change_timestamp_seconds",
        "telltale_list_fetch_consecutive_failures",
    ] {
        assert!(
            text.contains(&format!("{family}{{list=\"allowed\"}}")),
            "{text}"
        );
    }
}

// REQ: FLT-004 (ADR-147) — a list the configuration disables is left out of the `telltale_list_*`
// metrics. Its fetch state is kept (re-enabling needs no download), so without this a list that
// was failing when an operator disabled it kept its frozen failure count and last success in
// `/metrics` until the node restarted, and `TelltaleDNSListStale` kept firing for it. The test
// drives `render` as `/metrics` does: the fetcher holds the list's state, then the configuration
// turns the list off, then on again.
#[test]
fn flt_004_disabled_lists_are_left_out_of_the_list_metrics() {
    use telltale_filter::fetch::{
        Client, FetchSettings, ListSource, ListSpec, Store, SystemResolver,
    };
    let config = |broken_enabled: bool| {
        let toml = format!(
            "[[list]]\nname = \"broken\"\nurl = \"https://example.com/broken.txt\"\n\
             enabled = {broken_enabled}\n\
             [[list]]\nname = \"other\"\nurl = \"https://example.com/other.txt\"\n\
             [[list]]\nname = \"mine\"\nrules = [\"||inline.example^\"]\n"
        );
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config
    };
    let on = config(true);
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    // Two URL lists that have been failing for a long time after a success, as saved on disk.
    for name in ["broken", "other"] {
        store.save_source(name, b"a.example\n").unwrap();
        let meta = ListMeta {
            source: format!("https://example.com/{name}.txt"),
            content_hash: Some("h".into()),
            bytes: 10,
            lines: 1,
            last_attempt: Some(5_000),
            last_success: Some(1_000),
            last_changed: Some(900),
            last_error: Some("connection refused".into()),
            consecutive_failures: 40,
            ..ListMeta::default()
        };
        store.save_meta(name, &meta).unwrap();
    }
    let fetcher = Arc::new(Fetcher::new(
        store,
        Client::new(Arc::new(SystemResolver), &[]).unwrap(),
        FetchSettings::from_config(&on),
    ));
    // `due` loads each enabled list's saved state, as the fetch loop does; the extra spec is a
    // list the configuration doesn't hold, like a blocked service's (`services::expand`).
    let mut specs = ListSpec::from_config(&on);
    specs.push(ListSpec {
        name: "service_x".into(),
        source: ListSource::Inline(vec!["||x.example^".into()]),
        refresh: Duration::from_hours(24),
        max_bytes: 1 << 20,
        enabled: true,
    });
    let _ = fetcher.due(&specs, 1_000_000);
    let src = sources();
    src.lists.store(Some(Arc::new(ListsShared {
        fetcher,
        compiled: std::sync::Mutex::new(None),
    })));
    let list_lines = |src: &Sources, name: &str| -> Vec<String> {
        render(src)
            .lines()
            .filter(|l| l.starts_with("telltale_list_") && l.contains(&format!("list=\"{name}\"")))
            .map(str::to_owned)
            .collect()
    };

    // Enabled: all four families, with the saved values.
    src.config.store(Arc::new(on.clone()));
    let before = list_lines(&src, "broken");
    assert_eq!(before.len(), 4, "{before:?}");
    assert!(
        before.contains(&"telltale_list_fetch_consecutive_failures{list=\"broken\"} 40".into()),
        "{before:?}"
    );
    assert!(
        before
            .contains(&"telltale_list_last_success_timestamp_seconds{list=\"broken\"} 1000".into()),
        "{before:?}"
    );

    // Disabled: nothing for it; every other list, and the one the config doesn't hold, stays.
    src.config.store(Arc::new(config(false)));
    let off = list_lines(&src, "broken");
    assert!(off.is_empty(), "a disabled list still reports: {off:?}");
    for name in ["other", "mine", "service_x"] {
        assert!(
            !list_lines(&src, name).is_empty(),
            "{name} lost its metrics"
        );
    }
    assert_eq!(list_lines(&src, "other").len(), 4);

    // Enabled again: the state the fetcher kept is back, unchanged.
    src.config.store(Arc::new(on));
    assert_eq!(list_lines(&src, "broken"), before);
}

// REQ: FLT-004 — what a list that has never loaded exports: a failure count and no last-success
// time (the chart's `TelltaleDNSListNeverLoaded` reads exactly that pair). A list that succeeded
// once, however long ago, has both.
#[test]
fn flt_004_a_list_that_never_loaded_reports_failures_but_no_last_success() {
    let url = "https://example.com/l.txt".to_owned();
    let status = vec![
        (
            "typo".to_owned(),
            ListMeta {
                source: url.clone(),
                last_attempt: Some(5_000),
                last_error: Some("HTTP 404".into()),
                consecutive_failures: 7,
                ..ListMeta::default()
            },
        ),
        (
            "old".to_owned(),
            ListMeta {
                source: url,
                content_hash: Some("h".into()),
                last_attempt: Some(5_000),
                last_success: Some(10),
                last_error: Some("HTTP 404".into()),
                consecutive_failures: 7,
                ..ListMeta::default()
            },
        ),
    ];
    let mut w = PromWriter::new();
    render_list_status(&mut w, &status);
    let text = w.finish();
    assert!(
        text.contains("telltale_list_fetch_consecutive_failures{list=\"typo\"} 7"),
        "{text}"
    );
    assert!(
        !text.contains("telltale_list_last_success_timestamp_seconds{list=\"typo\"}"),
        "{text}"
    );
    assert!(
        text.contains("telltale_list_fetch_consecutive_failures{list=\"old\"} 7"),
        "{text}"
    );
    assert!(
        text.contains("telltale_list_last_success_timestamp_seconds{list=\"old\"} 10"),
        "{text}"
    );
}

// REQ: CLU-002 (ADR-125) — a node without the router (a resolver pod) names a device by
// what the other nodes' routers know; this node's own sources still come first.
#[test]
fn clu_002_device_names_fall_back_to_the_peers() {
    use crate::devices::{Lease, Names};
    let src = sources();
    let ip = std::net::Ipv4Addr::new(192, 168, 5, 2);
    let lease = |name: &str| Lease {
        mac: String::new(),
        ip,
        hostname: Some(name.into()),
        expires: 0,
        offline: false,
        unsure: false,
        stale: false,
    };
    let name = || crate::api_backend::device_name(&src, ip.to_ipv6_mapped().octets());
    assert_eq!(name(), None);
    src.pipeline.peer_names.store(Arc::new(Names {
        routers: [(ip, lease("k8s"))].into(),
        mdns: std::collections::HashMap::new(),
        vetted: false,
    }));
    assert_eq!(name().as_deref(), Some("k8s"));
    src.pipeline
        .mdns_names
        .store(Arc::new([(ip, lease("k8s-local"))].into()));
    assert_eq!(name().as_deref(), Some("k8s-local"), "own sources first");
}

// REQ: FLT-006, OBS-005 (ADR-183) — `telltale_neighbors` counts the kernel's entries only (the
// routers' and members' are counted apart, by whose router), and the bindings withheld have a
// gauge of their own.
#[test]
fn flt_006_router_macs_metrics() {
    use telltale_policy::MacTable;
    let src = sources();
    let ip = |last: u8| std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, last));
    let mac = |n: u8| [0x02, 0, 0, 0, 0, n];
    let before = render(&src);
    for line in [
        "telltale_neighbors 0\n",
        "telltale_router_macs{source=\"router\"} 0\n",
        "telltale_router_macs{source=\"peer\"} 0\n",
        "telltale_router_macs_unsure 0\n",
    ] {
        assert!(before.contains(line), "{line}: {before}");
    }
    src.pipeline.neighbors.swap(MacTable::from_sources(
        [(ip(1), mac(1)), (ip(2), mac(2)), (ip(3), mac(3))],
        [(ip(4), mac(4)), (ip(5), mac(5))],
        [(ip(6), mac(6))],
        4,
    ));
    let text = render(&src);
    for line in [
        "telltale_neighbors 3\n",
        "telltale_router_macs{source=\"router\"} 2\n",
        "telltale_router_macs{source=\"peer\"} 1\n",
        "telltale_router_macs_unsure 4\n",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
    assert!(
        text.contains("# TYPE telltale_router_macs gauge\n")
            && text.contains("# TYPE telltale_router_macs_unsure gauge\n"),
        "{text}"
    );
    assert!(
        !text.contains("0 is normal"),
        "the neighbor table is read whenever it is on, so 0 is no longer normal: {text}"
    );
}

/// REQ: OBS-005 (issue #108) — a query of group index `group` (the numbering of the policy it
/// was answered under). A block is a quick rule's: its `list` label needs no filter snapshot.
fn group_query(group: u16, status: Status) -> telltale_telemetry::QueryEvent {
    let blocked = status == Status::Blocked;
    telltale_telemetry::QueryEvent {
        ts_us: 1_700_000_000_000_000,
        client_ip: std::net::Ipv4Addr::new(10, 0, 0, 7)
            .to_ipv6_mapped()
            .octets(),
        client_ref: 0,
        group,
        qtype: 1,
        qclass: 1,
        rcode: Some(if blocked { 3 } else { 0 }),
        status,
        proto: Proto::Udp,
        flags: 0x8180,
        rule: blocked.then_some(telltale_telemetry::event::Rule {
            list: 0,
            kind: telltale_telemetry::event::RuleKind::Quick,
            allow: false,
        }),
        upstream: 0,
        attempts: 0,
        t_total_us: 100,
        t_upstream_us: 0,
        resp_size: 60,
        answers: 0,
    }
}

/// Folds `n` queries of the group named `group` (by its index in the current policy, as the
/// query path numbers it) into the aggregates.
fn fold_group(src: &Sources, group: &str, status: Status, n: usize) {
    use telltale_telemetry::event::{Name, Record};
    let g = src
        .pipeline
        .current()
        .policy
        .clients
        .group_id(group)
        .unwrap();
    let mut agg = src.pipeline.telemetry.aggregates();
    for _ in 0..n {
        agg.record(&Record::Query(group_query(g, status), Name::default()));
    }
}

/// Reloads `src`'s pipeline with the configuration `toml` (its groups).
fn reload_groups(src: &Sources, toml: &str) {
    let cfg = telltale_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    src.pipeline.reload(
        Arc::new(Router::default()),
        crate::pipeline::Policy::from_config(&cfg, telltale_policy::LocalData::default()),
    );
}

/// The value of `series` (its name and labels as `/metrics` writes them) in `text`.
fn sample_value(text: &str, series: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
}

/// REQ: OBS-005 (issue #108) — `telltale_group_queries_total` stays with its group's name across
/// a reload. A group added while `default` is implicit takes `default`'s index (0; `default` moves
/// to 1): it starts at zero, and `default` keeps its count and goes on from it.
#[test]
fn obs_005_group_counters_keep_their_name_across_a_reload() {
    let src = sources();
    let default = "telltale_group_queries_total{group=\"default\",status=\"forwarded\"}";
    fold_group(&src, "default", Status::Forwarded, 5);
    assert_eq!(sample_value(&render(&src), default), Some(5));
    reload_groups(&src, "[[group]]\nname = \"aaa-test\"\n");
    let names: Vec<String> = src
        .pipeline
        .current()
        .policy
        .clients
        .groups()
        .iter()
        .map(|g| g.name.to_string())
        .collect();
    assert_eq!(
        names,
        ["aaa-test", "default"],
        "the new group takes index 0"
    );
    let text = render(&src);
    assert_eq!(sample_value(&text, default), Some(5), "{text}");
    assert!(
        !text.contains("telltale_group_queries_total{group=\"aaa-test\""),
        "a new group starts at zero: {text}"
    );
    fold_group(&src, "default", Status::Forwarded, 1);
    let text = render(&src);
    assert_eq!(sample_value(&text, default), Some(6), "{text}");
    assert!(
        !text.contains("telltale_group_queries_total{group=\"aaa-test\""),
        "{text}"
    );
}

/// REQ: OBS-005 (issue #108) — a group a reload removes takes its counts with it: the groups
/// after it keep their own (none gets another group's total), nothing is left under `other`,
/// and a group of that name added back starts at zero.
#[test]
fn obs_005_a_removed_group_lends_no_count() {
    let src = sources();
    let q = |g: &str| format!("telltale_group_queries_total{{group=\"{g}\",status=\"forwarded\"}}");
    reload_groups(
        &src,
        "[[group]]\nname = \"aaa\"\n[[group]]\nname = \"bbb\"\n",
    );
    fold_group(&src, "aaa", Status::Forwarded, 2);
    fold_group(&src, "bbb", Status::Forwarded, 3);
    fold_group(&src, "default", Status::Forwarded, 4);
    reload_groups(&src, "[[group]]\nname = \"bbb\"\n");
    let text = render(&src);
    assert_eq!(sample_value(&text, &q("bbb")), Some(3), "{text}");
    assert_eq!(sample_value(&text, &q("default")), Some(4), "{text}");
    assert!(
        !text.contains("telltale_group_queries_total{group=\"aaa\""),
        "{text}"
    );
    assert!(
        !text.contains("telltale_group_queries_total{group=\"other\""),
        "{text}"
    );
    fold_group(&src, "bbb", Status::Forwarded, 1);
    reload_groups(
        &src,
        "[[group]]\nname = \"aaa\"\n[[group]]\nname = \"bbb\"\n",
    );
    let text = render(&src);
    assert!(
        !text.contains("telltale_group_queries_total{group=\"aaa\""),
        "added back, it starts at zero: {text}"
    );
    assert_eq!(sample_value(&text, &q("bbb")), Some(4), "{text}");
    assert_eq!(sample_value(&text, &q("default")), Some(4), "{text}");
}

/// REQ: OBS-005 (issue #108) — `telltale_blocked_total` (and the `blocked` status of
/// `telltale_group_queries_total`) follows its group to its new index, and ends with a group
/// a reload removes.
#[test]
fn obs_005_blocked_counters_follow_their_group() {
    let src = sources();
    let b = |g: &str| format!("telltale_blocked_total{{group=\"{g}\",list=\"quick\"}}");
    let q = |g: &str| format!("telltale_group_queries_total{{group=\"{g}\",status=\"blocked\"}}");
    reload_groups(&src, "[[group]]\nname = \"kids\"\n");
    fold_group(&src, "kids", Status::Blocked, 2);
    fold_group(&src, "default", Status::Blocked, 3);
    reload_groups(
        &src,
        "[[group]]\nname = \"aaa-test\"\n[[group]]\nname = \"kids\"\n",
    );
    let text = render(&src);
    assert_eq!(sample_value(&text, &b("kids")), Some(2), "{text}");
    assert_eq!(sample_value(&text, &b("default")), Some(3), "{text}");
    assert_eq!(sample_value(&text, &q("kids")), Some(2), "{text}");
    assert_eq!(sample_value(&text, &q("default")), Some(3), "{text}");
    assert!(
        !text.contains("telltale_blocked_total{group=\"aaa-test\""),
        "{text}"
    );
    fold_group(&src, "kids", Status::Blocked, 1);
    assert_eq!(sample_value(&render(&src), &b("kids")), Some(3));
    reload_groups(&src, "[[group]]\nname = \"aaa-test\"\n");
    let text = render(&src);
    assert!(
        !text.contains("telltale_blocked_total{group=\"kids\""),
        "{text}"
    );
    assert!(
        !text.contains("telltale_blocked_total{group=\"aaa-test\""),
        "{text}"
    );
    assert!(
        !text.contains("telltale_blocked_total{group=\"unknown\""),
        "{text}"
    );
    assert_eq!(sample_value(&text, &b("default")), Some(3), "{text}");
}

/// REQ: OBS-005 (issue #108) — `telltale_upstream_duration_seconds` stays with its upstream's
/// name when a reload renumbers the upstreams (an ID is the upstream's place in the
/// configuration, from 1): one added in front starts empty, the others keep their histograms,
/// and one removed takes its histogram along.
#[test]
fn obs_005_upstream_histograms_keep_their_name_across_a_reload() {
    use telltale_telemetry::event::{Record, UpstreamEvent};
    let src = sources();
    let reload = |names: &[&str]| {
        let upstreams: Vec<String> = names
            .iter()
            .map(|n| format!("[[upstream]]\nname = \"{n}\"\nurl = \"udp://192.0.2.1:53\"\n"))
            .collect();
        let members: Vec<String> = names.iter().map(|n| format!("\"{n}\"")).collect();
        let toml = format!(
            "{}[[upstream_group]]\nname = \"default\"\nmembers = [{}]\n",
            upstreams.concat(),
            members.join(", ")
        );
        let cfg = telltale_config::Loader::new()
            .toml_str("t.toml", &toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config;
        src.pipeline.reload(
            Arc::new(Router::from_config(&cfg).unwrap()),
            crate::pipeline::Policy::from_config(&cfg, telltale_policy::LocalData::default()),
        );
    };
    let fold = |name: &str, n: usize| {
        let id = src
            .pipeline
            .current()
            .router
            .upstreams()
            .iter()
            .find(|u| u.name == name)
            .unwrap()
            .id;
        let mut agg = src.pipeline.telemetry.aggregates();
        for _ in 0..n {
            agg.record(&Record::Upstream(UpstreamEvent {
                ts_us: 1_700_000_000_000_000,
                upstream: id,
                latency_us: 1_500,
                ok: true,
                attempts: 1,
            }));
        }
    };
    let count = |text: &str, u: &str| {
        sample_value(
            text,
            &format!(
                "telltale_upstream_duration_seconds_count{{upstream=\"{u}\",protocol=\"udp\"}}"
            ),
        )
    };
    reload(&["a", "b"]);
    fold("a", 2);
    fold("b", 3);
    assert_eq!(count(&render(&src), "a"), Some(2));
    reload(&["c", "a", "b"]);
    let text = render(&src);
    assert_eq!(count(&text, "a"), Some(2), "{text}");
    assert_eq!(count(&text, "b"), Some(3), "{text}");
    assert_eq!(
        count(&text, "c").unwrap_or(0),
        0,
        "a new upstream starts empty: {text}"
    );
    reload(&["c", "b"]);
    let text = render(&src);
    assert_eq!(count(&text, "a"), None, "{text}");
    assert_eq!(count(&text, "b"), Some(3), "{text}");
    assert_eq!(count(&text, "c").unwrap_or(0), 0, "{text}");
    fold("b", 1);
    assert_eq!(count(&render(&src), "b"), Some(4));
}

/// REQ: OBS-005 (issue #108) — a reload that keeps every group's name and place moves no
/// counter, also when the groups' settings change.
#[test]
fn obs_005_unchanged_groups_keep_every_counter() {
    let src = sources();
    let groups = "[[group]]\nname = \"kids\"\n[[group]]\nname = \"default\"\n";
    reload_groups(&src, groups);
    fold_group(&src, "kids", Status::Forwarded, 2);
    fold_group(&src, "kids", Status::Blocked, 1);
    fold_group(&src, "default", Status::Forwarded, 3);
    fold_group(&src, "default", Status::Blocked, 4);
    let series = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|l| {
                l.starts_with("telltale_group_queries_total{")
                    || l.starts_with("telltale_blocked_total{")
            })
            .map(str::to_owned)
            .collect()
    };
    let before = series(&render(&src));
    assert_eq!(before.len(), 6, "{before:?}");
    reload_groups(&src, groups);
    assert_eq!(series(&render(&src)), before, "the same configuration");
    reload_groups(
        &src,
        "[[group]]\nname = \"kids\"\nblock_mode = \"nxdomain\"\npriority = 10\n[[group]]\nname = \"default\"\n",
    );
    assert_eq!(
        series(&render(&src)),
        before,
        "the same groups, other settings"
    );
}
