// REQ: DNS-003, DNS-014, OBS-001 (ADR-194) — a `doh` listener behind a listed proxy that names
// its clients in `X-Forwarded-For`, through the server's own listener code and the real
// pipeline: the forwarded client is the client for the rate limit, the access list and the query
// log. The proxy is this test, connecting from 127.0.0.1 with the upstream client (the probes'
// DoH client) and an `X-Forwarded-For` header per client.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use telltale_proto::{NameBuf, rcode, rtype, summarize};
use telltale_upstream::{Endpoint, Question, TlsOptions, Upstream, UpstreamOptions};

use super::*;

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../telltale-net/testdata")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// A configuration with one TLS `doh` listener on 127.0.0.1 behind the proxy 127.0.0.1 (this
/// test), plus `extra`.
fn config(extra: &str) -> Config {
    let toml = format!(
        "[[listen]]\nproto = \"doh\"\naddr = \"127.0.0.1:0\"\ntls = {{ cert = {:?}, key = {:?} }}\n\
         x_forwarded_for = true\ntrusted_proxies = [\"127.0.0.1/32\"]\nmax_connections_per_address = 0\n{extra}",
        fixture("a.crt"),
        fixture("a.key"),
    );
    Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config
}

/// The node: its pipeline for `cfg` behind its listeners, and the DoH listener's address.
async fn node(cfg: &Config) -> (Listeners, Arc<Pipeline>, SocketAddr) {
    let (local, _) = LocalData::from_config(cfg);
    let p = build_pipeline(
        cfg,
        Arc::new(Cache::new(CachePolicy::default())),
        Arc::new(Router::default()),
        Policy::from_config(cfg, local),
    );
    let mut ls = Listeners {
        udp: Vec::new(),
        streams: Vec::new(),
        workers: 1,
        handler: Arc::new(Handler(Arc::clone(&p))),
        rt: tokio::runtime::Handle::current(),
    };
    ls.apply(&cfg.listen).await.unwrap();
    let addr = match &ls.streams[..] {
        [(_, s @ Stream::Doh(..))] => s.local_addr(),
        _ => panic!("one DoH listener"),
    };
    (ls, p, addr)
}

/// A DoH client that says it forwards for `client`.
fn proxy_for(addr: SocketAddr, client: &str) -> Upstream {
    let ep = Endpoint::parse(&format!("https://{addr}/dns-query")).unwrap();
    let opts = UpstreamOptions {
        timeout: Duration::from_secs(5),
        pool_size: 1,
        tls_insecure_skip_verify: true,
        headers: vec![("X-Forwarded-For".to_owned(), client.to_owned())],
        loop_tag: false,
        ..UpstreamOptions::default()
    };
    Upstream::build(0, "proxy", ep, &opts, &TlsOptions::default()).unwrap()
}

/// `localhost A` through `up`: the answer's rcode and first EDE code.
async fn ask(up: &Upstream) -> (u16, Option<u16>) {
    let q = Question {
        name: NameBuf::from_presentation("localhost").unwrap(),
        qtype: rtype::A,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
        client_subnet: 0,
    };
    let answer = up.exchange(&q, Duration::from_secs(5)).await.unwrap();
    (
        summarize(&answer).unwrap().rcode,
        crate::upstream_checks::first_ede(&answer),
    )
}

/// REQ: DNS-014 (ADR-194, R9) — the rate limit counts each forwarded client on its own: behind
/// one proxy, client A's third query in the window is refused while B and C are answered,
/// whatever the connection's own address. (The clients are in the default allowed networks.)
#[tokio::test]
async fn dns_014_rate_limit_counts_the_forwarded_client() {
    let cfg = config("[ratelimit]\nqueries = 2\nwindow_secs = 60\n");
    let (ls, _p, addr) = node(&cfg).await;
    let (a, b, c) = (
        proxy_for(addr, "192.168.1.7"),
        proxy_for(addr, "192.168.1.8"),
        proxy_for(addr, "fd00::9"),
    );
    assert_eq!(ask(&a).await.0, rcode::NOERROR);
    assert_eq!(ask(&a).await.0, rcode::NOERROR);
    assert_eq!(
        ask(&a).await,
        (rcode::REFUSED, Some(telltale_proto::ede::PROHIBITED)),
        "A's third query: limited, as the forwarded client"
    );
    assert_eq!(ask(&b).await.0, rcode::NOERROR);
    assert_eq!(ask(&c).await.0, rcode::NOERROR);
    assert_eq!(ask(&b).await.0, rcode::NOERROR);
    drop(ls);
}

/// REQ: DNS-014 (ADR-194, R9) — `[access] allowed_networks` applies to the forwarded client:
/// one outside it is refused (EDE 18) whatever the connection's own address; one inside it is
/// answered.
#[tokio::test]
async fn dns_014_access_list_applies_to_the_forwarded_client() {
    let cfg = config("[access]\nallowed_networks = [\"192.168.0.0/16\", \"127.0.0.0/8\"]\n");
    let (ls, _p, addr) = node(&cfg).await;
    assert_eq!(
        ask(&proxy_for(addr, "203.0.113.9")).await,
        (rcode::REFUSED, Some(telltale_proto::ede::PROHIBITED))
    );
    assert_eq!(ask(&proxy_for(addr, "192.168.1.9")).await.0, rcode::NOERROR);
    drop(ls);
}

/// REQ: OBS-001 (ADR-194, R9) — the query log and analytics see the forwarded client: the
/// query event carries its address, not the proxy's.
#[tokio::test]
async fn obs_001_query_log_records_the_forwarded_client() {
    use telltale_telemetry::event::Record;
    let cfg = config("");
    let (ls, p, addr) = node(&cfg).await;
    assert_eq!(ask(&proxy_for(addr, "192.168.1.7")).await.0, rcode::NOERROR);
    assert_eq!(ask(&proxy_for(addr, "fd00::7")).await.0, rcode::NOERROR);
    let mut got = Vec::new();
    p.telemetry.drainer().drain(|r| {
        if let Record::Query(e, _) = r {
            got.push(IpAddr::from(e.client_ip).to_canonical());
        }
    });
    assert_eq!(
        got,
        [
            "192.168.1.7".parse::<IpAddr>().unwrap(),
            "fd00::7".parse::<IpAddr>().unwrap()
        ]
    );
    drop(ls);
}

/// REQ: DNS-003, NFR-002 (ADR-194, R21) — choosing the client from `X-Forwarded-For` allocates
/// nothing, from the header map as the listener reads it and from raw lines, whether it finds
/// a client or refuses.
#[test]
fn dns_003_xff_selector_allocates_nothing() {
    use telltale_net::forwarded::{Network, client};
    let proxies = [
        Network {
            addr: "10.0.5.20".parse().unwrap(),
            prefix: 32,
        },
        Network {
            addr: "2001:db8:5::".parse().unwrap(),
            prefix: 48,
        },
    ];
    let want: IpAddr = "192.0.2.7".parse().unwrap();
    let lines: [&[u8]; 2] = [
        b"198.51.100.1, 203.0.113.9",
        b" 192.0.2.7 ,2001:db8:5::1, 10.0.5.20",
    ];
    let refused: [&[u8]; 1] = [b"10.0.0.1, unknown, 10.0.5.20"];
    // `::http`: the crate (this module also sees the server's own `http` module).
    let mut headers = ::http::HeaderMap::new();
    for l in lines {
        headers.append(
            "x-forwarded-for",
            ::http::HeaderValue::from_bytes(l).unwrap(),
        );
    }
    let from_map = |h: &::http::HeaderMap| {
        client(
            h.get_all("x-forwarded-for")
                .iter()
                .map(::http::HeaderValue::as_bytes),
            &proxies,
        )
    };
    // Warm up.
    assert_eq!(from_map(&headers), Ok(want));
    let info = allocation_counter::measure(|| {
        for _ in 0..1000 {
            assert_eq!(client(lines, &proxies), Ok(want));
            assert!(client(refused, &proxies).is_err());
            assert_eq!(from_map(&headers), Ok(want));
        }
    });
    assert_eq!(info.count_total, 0, "the selector allocated: {info:?}");
}
