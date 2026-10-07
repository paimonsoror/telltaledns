//! REQ: UPS-002, UPS-003, UPS-007, UPS-011 — the router built from configuration (T9.24):
//! stamps become the endpoints they name, routes pick the most specific match by name, query
//! type, and client group, and configuration problems come back as readable errors.

#![allow(clippy::unwrap_used)]

use telltale_proto::{NameBuf, rtype};
use telltale_upstream::{Host, Protocol, Question, Router};

fn config(toml: &str) -> telltale_config::Config {
    telltale_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .map_err(|e| format!("{e:?}"))
        .unwrap()
        .config
}

fn router(toml: &str) -> Result<Router, Vec<String>> {
    Router::from_config(&config(toml))
}

fn b64url(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            s.push(char::from(
                T[usize::try_from((n >> (18 - 6 * i)) & 63).unwrap()],
            ));
        }
    }
    s
}

/// A DoH (0x02), DoT (0x03), or DoQ (0x04) stamp: address, hashes, host[:port], (DoH) path.
fn stamp(kind: u8, addr: &str, hashes: &[[u8; 32]], host: &str, path: Option<&str>) -> String {
    let mut raw = vec![kind];
    raw.extend_from_slice(&0u64.to_le_bytes());
    raw.push(u8::try_from(addr.len()).unwrap());
    raw.extend_from_slice(addr.as_bytes());
    if hashes.is_empty() {
        raw.push(0);
    }
    for (i, h) in hashes.iter().enumerate() {
        raw.push(if i + 1 < hashes.len() { 0x80 | 32 } else { 32 });
        raw.extend_from_slice(h);
    }
    raw.push(u8::try_from(host.len()).unwrap());
    raw.extend_from_slice(host.as_bytes());
    if let Some(p) = path {
        raw.push(u8::try_from(p.len()).unwrap());
        raw.extend_from_slice(p.as_bytes());
    }
    format!("sdns://{}", b64url(&raw))
}

fn q(name: &str, qtype: u16) -> Question {
    Question {
        name: NameBuf::from_presentation(name).unwrap(),
        qtype,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
        client_subnet: 0,
    }
}

/// REQ: UPS-003 (T7.24) — DoH, DoT, and DoQ stamps become the endpoints they name: the pinned
/// address (no bootstrap), the port, the path; HTTP/3 by `http_version`.
#[test]
fn ups_003_stamps_become_endpoints() {
    let doh = stamp(
        0x02,
        "9.9.9.9",
        &[[1; 32]],
        "dns.quad9.net",
        Some("/dns-query"),
    );
    let dot = stamp(0x03, "[2620:fe::fe]:8853", &[], "dns.quad9.net", None);
    let doq = stamp(0x04, "", &[], "dns.adguard-dns.com:853", None);
    let r = router(&format!(
        r#"[[upstream]]
name = "doh"
url = "{doh}"
[[upstream]]
name = "dot"
url = "{dot}"
[[upstream]]
name = "doq"
url = "{doq}"
bootstrap = ["94.140.14.14"]
[[upstream]]
name = "h3"
url = "https://1.1.1.1/dns-query"
http_version = "3"
tls_server_name = "cloudflare-dns.com"
[[upstream_group]]
name = "default"
members = ["doh", "dot", "doq", "h3"]
"#
    ))
    .unwrap();
    let ep = |name: &str| {
        r.upstreams()
            .iter()
            .find(|u| u.name == name)
            .unwrap()
            .endpoint
            .clone()
    };
    let e = ep("doh");
    assert_eq!(
        (e.protocol, e.host, e.port, e.path.as_str()),
        (
            Protocol::Https,
            Host::Ip("9.9.9.9".parse().unwrap()),
            443,
            "/dns-query"
        )
    );
    let e = ep("dot");
    assert_eq!(
        (e.protocol, e.host, e.port),
        (
            Protocol::Tls,
            Host::Ip("2620:fe::fe".parse().unwrap()),
            8853
        )
    );
    let e = ep("doq");
    assert_eq!((e.protocol, e.port), (Protocol::Quic, 853));
    assert!(
        matches!(e.host, Host::Name(_)),
        "no pinned address: the name, through bootstrap"
    );
    assert_eq!(ep("h3").protocol, Protocol::H3);
}

/// REQ: UPS-007 — routes: the most specific suffix wins, then query type and client group
/// narrow; anything else goes to `default`, and says it wasn't routed.
#[test]
fn ups_007_route_selection() {
    let r = router(
        r#"[[upstream]]
name = "a"
url = "udp://127.0.0.1:9"
[[upstream]]
name = "b"
url = "udp://127.0.0.2:9"
[[upstream_group]]
name = "default"
members = ["a"]
[[upstream_group]]
name = "corp"
members = ["b"]
[[upstream_group]]
name = "lab"
members = ["a", "b"]
strategy = "parallel"
[[upstream_group]]
name = "kids"
members = ["b"]
[[route]]
match_suffix = ["example.com"]
upstream_group = "corp"
[[route]]
match_suffix = ["lab.example.com"]
upstream_group = "lab"
[[route]]
match_qtype = ["TXT"]
match_suffix = ["txt.test"]
upstream_group = "lab"
[[route]]
match_group = ["kids"]
upstream_group = "kids"
[[group]]
name = "kids"
networks = ["10.9.0.0/16"]
"#,
    )
    .unwrap();
    let pick = |name: &str, qtype: u16, groups: &[&str]| {
        let s = r.select(&q(name, qtype), groups).unwrap();
        (s.group.name.clone(), s.routed)
    };
    assert_eq!(
        pick("www.example.com", rtype::A, &[]),
        ("corp".into(), true)
    );
    assert_eq!(
        pick("x.lab.example.com", rtype::A, &[]),
        ("lab".into(), true),
        "deeper suffix wins"
    );
    assert_eq!(pick("txt.test", rtype::TXT, &[]), ("lab".into(), true));
    assert_eq!(
        pick("txt.test", rtype::A, &[]),
        ("default".into(), false),
        "qtype doesn't match"
    );
    assert_eq!(
        pick("other.org", rtype::A, &["kids"]),
        ("kids".into(), true),
        "client group"
    );
    assert_eq!(
        pick("other.org", rtype::A, &["default"]),
        ("default".into(), false)
    );
    assert!(r.group("lab").is_some() && r.group("nope").is_none());
    assert_eq!(r.upstreams().len(), 2);
    let v = r
        .select(&q("www.example.com", rtype::A), &[] as &[&str])
        .unwrap()
        .view;
    assert_eq!(r.group_by_view(v).unwrap().name, "corp");
}

/// REQ: UPS-011 (T7.16) — files the configuration names are read when the router is built; a
/// missing or empty one is an error that names the upstream and the file.
#[test]
fn ups_011_tls_files_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    for (field, path, want) in [
        ("tls_ca", dir.path().join("missing.pem"), "missing.pem"),
        ("tls_ca", empty.clone(), "no certificates in it"),
    ] {
        let toml = format!(
            "[[upstream]]\nname = \"x\"\nurl = \"tls://127.0.0.1:853\"\ntls_server_name = \"dns.test\"\n{field} = \"{}\"\n[[upstream_group]]\nname = \"default\"\nmembers = [\"x\"]\n",
            path.display()
        );
        let errs = router(&toml).err().unwrap();
        assert!(
            errs.iter()
                .any(|e| e.contains("upstream `x`") && e.contains(want)),
            "{errs:?}"
        );
    }
}

/// REQ: DNS-015, UPS-010, UPS-003 — the per-upstream options a router builds: ECS (`strip`,
/// a subnet, `client`), a SOCKS5 proxy for UDP, and a DNSCrypt relay; bad ones are errors.
#[test]
fn dns_015_upstream_options() {
    let r = router(
        r#"[[upstream]]
name = "subnet"
url = "udp://127.0.0.1:9"
ecs = "203.0.113.0/24"
[[upstream]]
name = "client"
url = "udp://127.0.0.1:9"
ecs = "client"
[[upstream]]
name = "socks"
url = "udp://127.0.0.1:9"
proxy = "socks5://127.0.0.1:1080"
[[upstream_group]]
name = "default"
members = ["subnet", "client", "socks"]
"#,
    )
    .unwrap();
    let up = |n: &str| r.upstreams().iter().find(|u| u.name == n).unwrap().clone();
    assert!(up("client").ecs_client && !up("subnet").ecs_client);
    assert!(
        r.group("default").unwrap().ecs_client(),
        "the group caches per subnet"
    );
    // A relay on a stamp that isn't DNSCrypt is refused by the configuration check; a bad relay
    // stamp on a DNSCrypt upstream, by the router.
    let dnscrypt = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";
    let errs = router(&format!(
        "[[upstream]]\nname = \"dc\"\nurl = \"{dnscrypt}\"\nrelay = \"sdns://AQAAAA\"\n[[upstream_group]]\nname = \"default\"\nmembers = [\"dc\"]\n"
    ))
    .err()
    .unwrap();
    assert!(errs.iter().any(|e| e.contains("upstream `dc`")), "{errs:?}");
    let ok = router(&format!(
        "[[upstream]]\nname = \"dc\"\nurl = \"{dnscrypt}\"\nrelay = \"203.0.113.7:443\"\n[[upstream_group]]\nname = \"default\"\nmembers = [\"dc\"]\n"
    ));
    assert!(ok.is_ok(), "{:?}", ok.err());
}

/// REQ: UPS-007 (T9.25) — `[[group]] upstreams`: a group's devices go to its upstream group; a
/// device in several goes where its highest-priority group says; a domain route, or a route
/// that names the group, still wins; and an unknown upstream group is a configuration error.
#[test]
fn ups_007_group_upstreams() {
    let r = router(
        r#"[[upstream]]
name = "a"
url = "udp://127.0.0.1:9"
[[upstream_group]]
name = "default"
members = ["a"]
[[upstream_group]]
name = "family"
members = ["a"]
[[upstream_group]]
name = "vpn"
members = ["a"]
[[upstream_group]]
name = "lan"
members = ["a"]
[[route]]
match_suffix = ["home.arpa"]
upstream_group = "lan"
[[route]]
match_group = ["guest"]
match_qtype = ["TXT"]
upstream_group = "lan"
[[group]]
name = "iot"
upstreams = "vpn"
[[group]]
name = "kids"
priority = 10
upstreams = "family"
[[group]]
name = "guest"
upstreams = "vpn"
"#,
    )
    .unwrap();
    let pick = |name: &str, qtype: u16, groups: &[&str]| {
        r.select(&q(name, qtype), groups)
            .unwrap()
            .group
            .name
            .clone()
    };
    assert_eq!(pick("example.org", rtype::A, &["kids"]), "family");
    assert_eq!(pick("example.org", rtype::A, &["iot"]), "vpn");
    assert_eq!(
        pick("example.org", rtype::A, &["iot", "kids"]),
        "family",
        "the higher-priority group"
    );
    assert_eq!(pick("example.org", rtype::A, &[]), "default");
    assert_eq!(
        pick("nas.home.arpa", rtype::A, &["kids"]),
        "lan",
        "a domain route wins"
    );
    assert_eq!(
        pick("example.org", rtype::TXT, &["guest"]),
        "lan",
        "a route naming the group wins"
    );
    assert_eq!(pick("example.org", rtype::A, &["guest"]), "vpn");

    let err = telltale_config::Loader::new()
        .toml_str(
            "t.toml",
            "[[upstream]]\nname = \"a\"\nurl = \"udp://127.0.0.1:9\"\n[[upstream_group]]\nname = \"default\"\nmembers = [\"a\"]\n[[group]]\nname = \"kids\"\nupstreams = \"nope\"\n",
        )
        .env(Vec::<(String, String)>::new())
        .load()
        .err()
        .unwrap();
    let text = format!("{err:?}");
    assert!(
        text.contains("group[0].upstreams") && text.contains("unknown upstream group `nope`"),
        "{text}"
    );
}
