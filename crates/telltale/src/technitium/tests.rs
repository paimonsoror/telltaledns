use serde_json::json;

use super::*;

// Shapes as Technitium 15.6's API returns them, written by hand for these tests.
#[allow(clippy::too_many_lines)] // one server's data
fn export() -> Export {
    let rec = |name: &str, t: &str, ttl: u64, data: Value| json!({"name": name, "type": t, "ttl": ttl, "disabled": false, "rData": data});
    Export {
        version: "15.6".into(),
        settings: json!({
            "version": "15.6",
            "forwarders": ["1.1.1.1:853", "dns.quad9.net (9.9.9.9:853)"],
            "forwarderProtocol": "Tls",
            "concurrentForwarding": true,
            "forwarderConcurrency": 2,
            "enableBlocking": true,
            "blockingType": "NxDomain",
            "blockListUrls": ["https://lists.example/block.txt", "!https://lists.example/allow.txt"],
            "blockingBypassList": ["192.168.1.250"],
            "dnssecValidation": true,
            "qpmPrefixLimitsIPv4": [{"prefix": 32, "udpLimit": 600, "tcpLimit": 600}, {"prefix": 24, "udpLimit": 6000}],
            "saveCache": true,
            "enableDnsOverTls": true,
            "recursion": "AllowOnlyForPrivateNetworks",
            "recursionNetworkACL": [],
            "tsigKeys": [],
            "proxy": null
        }),
        zones: vec![
            Zone {
                name: "home.arpa".into(),
                kind: "Primary".into(),
                disabled: false,
                records: vec![
                    rec("home.arpa", "NS", 14400, json!({"nameServer": "server"})),
                    rec(
                        "home.arpa",
                        "SOA",
                        900,
                        json!({"primaryNameServer": "server"}),
                    ),
                    rec("home.arpa", "TXT", 300, json!({"text": "hello"})),
                    rec(
                        "_sip._udp.home.arpa",
                        "SRV",
                        300,
                        json!({"priority": 0, "weight": 5, "port": 5060, "target": "pbx.home.arpa"}),
                    ),
                    rec(
                        "media.home.arpa",
                        "CNAME",
                        300,
                        json!({"cname": "nas.home.arpa"}),
                    ),
                    rec(
                        "nas.home.arpa",
                        "A",
                        3600,
                        json!({"ipAddress": "192.168.1.10"}),
                    ),
                    rec(
                        "nas.home.arpa",
                        "CAA",
                        3600,
                        json!({"flags": 0, "tag": "issue", "value": "x"}),
                    ),
                    json!({"name": "old.home.arpa", "type": "A", "ttl": 60, "disabled": true, "rData": {"ipAddress": "192.168.1.99"}}),
                ],
            },
            Zone {
                name: "corp.example".into(),
                kind: "Forwarder".into(),
                disabled: false,
                records: vec![
                    rec("corp.example", "SOA", 0, json!({})),
                    rec(
                        "corp.example",
                        "FWD",
                        0,
                        json!({"protocol": "Udp", "forwarder": "10.0.0.53", "priority": 0, "dnssecValidation": false}),
                    ),
                ],
            },
            Zone {
                name: "mirror.example".into(),
                kind: "Secondary".into(),
                disabled: false,
                records: vec![],
            },
        ],
        allowed: vec!["allowed.example".into()],
        blocked: vec!["blocked.example".into()],
        advanced_blocking: Some(json!({
            "enableBlocking": true,
            "localEndPointGroupMap": {"user1.dot.example.com": "kids"},
            "networkGroupMap": {"192.168.10.20": "kids", "0.0.0.0/0": "everyone else", "[::]/0": "everyone else"},
            "groups": [
                {"name": "everyone else", "enableBlocking": true, "blockAsNxDomain": true,
                 "blockingAddresses": ["0.0.0.0", "::"], "allowed": [], "blocked": ["example.com"],
                 "allowListUrls": [], "blockListUrls": ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"],
                 "allowedRegex": [], "blockedRegex": ["^ads\\."], "regexAllowListUrls": [], "regexBlockListUrls": [], "adblockListUrls": []},
                {"name": "kids", "enableBlocking": true, "blockAsNxDomain": false,
                 "blockingAddresses": ["192.168.10.2"], "allowed": [], "blocked": [], "allowListUrls": [],
                 "blockListUrls": [{"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "blockAsNxDomain": false}],
                 "allowedRegex": [], "blockedRegex": [], "regexAllowListUrls": [], "regexBlockListUrls": [], "adblockListUrls": []},
                {"name": "bypass", "enableBlocking": false, "blockAsNxDomain": true, "blockingAddresses": [],
                 "allowed": [], "blocked": [], "allowListUrls": [], "blockListUrls": [], "allowedRegex": [], "blockedRegex": [],
                 "regexAllowListUrls": [], "regexBlockListUrls": [], "adblockListUrls": []}
            ]
        })),
        other_apps: vec!["Query Logs (Sqlite)".into()],
        dhcp: vec![json!({"name": "lan", "enabled": true, "reservedLeases": [
            {"hostName": "printer", "hardwareAddress": "00-11-22-33-44-55", "address": "192.168.1.90", "comments": ""}
        ]})],
    }
}

fn strs(v: &[telltale_config::SafeString]) -> Vec<&str> {
    v.iter().map(telltale_config::SafeString::as_str).collect()
}

// REQ: API-007 — a Technitium setup becomes a configuration that loads, with forwarders,
// zones, forwarder zones, block lists, Advanced Blocking groups, and reservations.
#[test]
#[allow(clippy::too_many_lines)] // one server, checked section by section
fn api_007_technitium_import() {
    let im = convert(&export(), "http://dns.example:5380");
    let cfg = match telltale_config::Loader::new()
        .toml_str("import", im.toml.clone())
        .load()
    {
        Ok(l) => l.config,
        Err(e) => panic!("{e:?}\n{}", im.toml),
    };
    let (_, report) = telltale_policy::LocalData::from_config(&cfg);
    assert_eq!(report.errors, Vec::<String>::new());

    let ups: Vec<(&str, &str, Option<&str>)> = cfg
        .upstream
        .iter()
        .map(|u| {
            (
                u.name.as_str(),
                u.url.as_str(),
                u.tls_server_name.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        ups,
        [
            ("technitium-1", "tls://1.1.1.1:853", None),
            ("technitium-2", "tls://9.9.9.9:853", Some("dns.quad9.net")),
            ("technitium-forward-1-1", "udp://10.0.0.53:53", None),
        ]
    );
    let default = &cfg.upstream_group[0];
    assert_eq!(default.strategy, telltale_config::Strategy::Parallel);
    assert_eq!(default.parallel_fanout, 2);
    assert_eq!(strs(&cfg.route[0].match_suffix), ["corp.example"]);
    assert!(
        cfg.route[0].dnssec_nta,
        "the forwarder zone didn't validate"
    );

    let recs: Vec<(&str, &str, &str)> = cfg
        .record
        .iter()
        .map(|r| (r.name.as_str(), r.rtype.as_str(), r.value.as_str()))
        .collect();
    assert_eq!(
        recs,
        [
            ("home.arpa", "TXT", "hello"),
            ("_sip._udp.home.arpa", "SRV", "0 5 5060 pbx.home.arpa"),
            ("media.home.arpa", "CNAME", "nas.home.arpa"),
            ("nas.home.arpa", "A", "192.168.1.10"),
        ]
    );

    let list = |n: &str| cfg.list.iter().find(|l| l.name.as_str() == n).unwrap();
    assert_eq!(
        list("technitium-allow").kind,
        telltale_config::ListKind::Allow
    );
    assert_eq!(strs(&list("technitium-blocked").rules), ["blocked.example"]);
    assert_eq!(
        strs(&list("technitium-everyone-else-blocked-regex").rules),
        ["/^ads\\./"]
    );
    // One list per URL, shared by the groups that use it.
    assert_eq!(
        cfg.list
            .iter()
            .filter(|l| l.url.as_deref()
                == Some("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"))
            .count(),
        1
    );

    let group = |n: &str| cfg.group.iter().find(|g| g.name.as_str() == n).unwrap();
    let names = |g: &telltale_config::GroupConfig| -> Vec<String> {
        g.lists.iter().flatten().map(ToString::to_string).collect()
    };
    // The catch-all group is `default`; server-wide lists apply to every group.
    let d = group("default");
    assert_eq!(d.block_mode, telltale_config::BlockMode::Nxdomain);
    assert_eq!(
        names(d),
        [
            "technitium-block",
            "technitium-allow",
            "technitium-blocked",
            "technitium-allowed",
            "technitium-hosts",
            "technitium-everyone-else-blocked",
            "technitium-everyone-else-blocked-regex"
        ]
    );
    let kids = group("kids");
    assert!(kids.networks.len() == 1 && kids.networks[0].to_string().starts_with("192.168.10.20"));
    assert_eq!(kids.block_mode, telltale_config::BlockMode::CustomIp);
    assert_eq!(kids.block_ips, ["192.168.10.2".parse::<IpAddr>().unwrap()]);
    assert!(names(kids).contains(&"technitium-hosts".to_owned()));
    assert_eq!(names(group("bypass")), Vec::<String>::new(), "blocking off");
    let bypass = group("technitium-bypass");
    assert_eq!(names(bypass), Vec::<String>::new());
    assert_eq!(bypass.networks.len(), 1);

    assert_eq!(cfg.client[0].name.as_str(), "printer");
    assert_eq!(
        strs(&cfg.client[0].match_keys),
        ["00:11:22:33:44:55", "192.168.1.90"]
    );
    assert_eq!(cfg.dnssec.mode, telltale_config::DnssecMode::Validate);
    assert_eq!(cfg.ratelimit.queries, 600);
    assert!(cfg.cache.persist);

    let notes = im.notes.join("\n");
    for want in [
        "DNS-over-TLS",
        "localEndPointGroupMap",
        "mirror.example is a Secondary zone",
        "1 CAA",
        "1 disabled record",
        "per-list blocking",
        "DHCP server",
        "Query Logs (Sqlite)",
    ] {
        assert!(notes.contains(want), "missing {want} in:\n{notes}");
    }
}

#[test]
fn api_007_technitium_forwarder_formats() {
    let f = |a: &str, p: &str| forwarder_url(a, p);
    assert_eq!(
        f("1.1.1.1", "Udp").unwrap(),
        ("udp://1.1.1.1:53".into(), None)
    );
    assert_eq!(
        f("[2606:4700::1111]:53", "Tcp").unwrap(),
        ("tcp://[2606:4700::1111]:53".into(), None)
    );
    assert_eq!(
        f("cloudflare-dns.com (1.1.1.1:853)", "Tls").unwrap(),
        (
            "tls://1.1.1.1:853".into(),
            Some("cloudflare-dns.com".into())
        )
    );
    assert_eq!(
        f("https://cloudflare-dns.com/dns-query (1.1.1.1)", "Https").unwrap(),
        ("https://cloudflare-dns.com/dns-query".into(), None)
    );
    assert!(f("dns.adguard-dns.com (94.140.14.14:853)", "Quic").is_err());
    assert!(f("dns.example", "Udp").is_err(), "a name with no address");
}

// Concurrent forwarding with one usable forwarder is plain failover (found by the e2e: a
// forwarder given by name only was skipped, leaving one).
#[test]
fn api_007_technitium_one_forwarder_is_not_parallel() {
    let ex = Export {
        settings: json!({"forwarders": ["9.9.9.9", "dns.quad9.net"], "forwarderProtocol": "Udp",
                         "concurrentForwarding": true, "forwarderConcurrency": 2}),
        ..Export::default()
    };
    let im = convert(&ex, "x");
    let cfg = telltale_config::Loader::new()
        .toml_str("import", im.toml)
        .load()
        .unwrap()
        .config;
    assert_eq!(
        cfg.upstream_group[0].strategy,
        telltale_config::Strategy::Failover
    );
    assert!(im.notes.iter().any(|n| n.contains("dns.quad9.net")));
}

// No forwarders (Technitium resolving recursively) and no app: still a loadable config.
#[test]
fn api_007_technitium_minimal() {
    let ex = Export {
        version: "15.6".into(),
        settings: json!({"forwarders": [], "blockListUrls": []}),
        ..Export::default()
    };
    let im = convert(&ex, "x");
    assert!(im.notes.iter().any(|n| n.contains("no forwarders")));
    assert!(
        telltale_config::Loader::new()
            .toml_str("import", im.toml)
            .load()
            .is_ok()
    );
}
