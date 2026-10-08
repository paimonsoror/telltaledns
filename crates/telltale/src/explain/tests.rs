use std::collections::HashMap;
use std::sync::Arc;

use telltale_cache::{Cache, CachePolicy};
use telltale_filter::compile::{CompileOptions, ListData, ListInput, compile};
use telltale_filter::matcher::{Lookup, Matcher};
use telltale_filter::parse::ListOptions;
use telltale_filter::snapshot::Snapshot;
use telltale_net::{QueryHandler, RequestMeta, Response, Transport};
use telltale_policy::LocalData;
use telltale_proto::{EdnsOut, rtype};
use telltale_upstream::Router;

use super::*;
use crate::pipeline::{Handler, Pipeline, Policy, Settings};

const CONFIG: &str = r#"
[access]
allowed_networks = ["10.0.0.0/8", "127.0.0.0/8"]

[[upstream]]
name = "u"
url = "udp://127.0.0.1:9"
[[upstream]]
name = "lan-dns"
url = "udp://127.0.0.1:10"
[[upstream_group]]
name = "default"
members = ["u"]
[[upstream_group]]
name = "lan"
members = ["lan-dns"]
[[route]]
match_suffix = ["corp.example"]
upstream_group = "lan"

[[record]]
name = "nas.home.arpa"
type = "A"
value = "10.0.0.10"

[[list]]
name = "ads"
rules = ["||ads.example.com^", "||tracker.example.net^", "||corp.example^"]
[[list]]
name = "ok"
kind = "allow"
rules = ["ok.tracker.example.net"]
[[list]]
name = "strict"
rules = ["||social.example^"]

[[group]]
name = "default"
lists = ["ads", "ok"]

[[group]]
name = "kids"
lists = ["ads", "ok", "strict"]
block_mode = "nxdomain"
priority = 10

[[client]]
name = "tablet"
match = ["10.0.0.5", "aa:bb:cc:dd:ee:01"]
groups = ["kids"]
"#;

/// A pipeline over `CONFIG` with every list compiled, plus the list sources.
fn setup() -> (Arc<Pipeline>, HashMap<String, Vec<u8>>) {
    setup_with("")
}

/// The same, with `extra` appended to `CONFIG`.
fn setup_with(extra: &str) -> (Arc<Pipeline>, HashMap<String, Vec<u8>>) {
    let cfg = telltale_config::Loader::new()
        .toml_str("t.toml", format!("{CONFIG}{extra}"))
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    let (local, report) = LocalData::from_config(&cfg);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let p = Pipeline::new(
        Settings::default(),
        Arc::new(Cache::new(CachePolicy::default())),
        Arc::new(Router::from_config(&cfg).unwrap()),
        Policy::from_config(&cfg, local),
    );
    let mut sources = HashMap::new();
    let inputs = cfg
        .list
        .iter()
        .map(|l| {
            let text: String = l.rules.iter().flat_map(|r| [r.as_str(), "\n"]).collect();
            sources.insert(l.name.to_string(), text.clone().into_bytes());
            ListInput {
                name: l.name.to_string(),
                options: ListOptions {
                    kind: l.kind,
                    match_mode: l.match_mode,
                },
                source_hash: telltale_filter::fetch::content_hash(text.as_bytes()),
                size: text.len() as u64,
                data: ListData::Bytes(text.into_bytes()),
            }
        })
        .collect();
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("snap");
    compile(inputs, &out, &CompileOptions::default()).unwrap();
    let snap = Arc::new(Snapshot::open(&out).unwrap());
    let m = Matcher::with_lookup(Some(snap), Lookup::Indexed).unwrap();
    p.set_filter(Some(Arc::new(m)));
    (p, sources)
}

fn ask(p: &Pipeline, sources: &HashMap<String, Vec<u8>>, name: &str, client: &str) -> Explanation {
    let req = Request {
        name,
        qtype: rtype::A,
        client: client.parse().unwrap(),
        mac: None,
        client_id: None,
    };
    p.explain(&req, |n| sources.get(n).cloned()).unwrap()
}

/// What the real pipeline does with the same query: answered now (with the response), or
/// deferred to an upstream.
fn served(p: &Arc<Pipeline>, name: &str, client: &str) -> Option<Vec<u8>> {
    let n = NameBuf::from_presentation(name).unwrap();
    let mut q = [0u8; 512];
    let len = build_query(&mut q, 7, &n, rtype::A, 1, true, Some(EdnsOut::new(1232))).unwrap();
    let meta = RequestMeta {
        peer: format!("{client}:1000").parse().unwrap(),
        local: None,
        transport: Transport::Udp,
        client_id: None,
    };
    let mut out = [0u8; 4096];
    match Handler(Arc::clone(p)).handle(&q[..len], &meta, &mut out) {
        Response::Ready(len) => Some(out[..len].to_vec()),
        _ => None,
    }
}

fn contains(msg: &[u8], needle: &[u8]) -> bool {
    msg.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn flt_013_explain_agrees_with_the_pipeline() {
    let (p, sources) = setup();
    let names = [
        "ads.example.com",
        "x.tracker.example.net",
        "ok.tracker.example.net",
        "social.example",
        "www.example.org",
        "nas.home.arpa",
        "host.corp.example",
        "localhost",
    ];
    for client in ["10.0.0.5", "10.0.0.9", "192.0.2.1"] {
        for name in names {
            let e = ask(&p, &sources, name, client);
            let answer = served(&p, name, client);
            let label = format!("{name} from {client}: {:?} ({})", e.outcome, e.summary);
            match e.outcome {
                Outcome::Resolved | Outcome::Allowed => {
                    assert!(
                        answer.is_none(),
                        "{label}: pipeline answered without forwarding"
                    );
                }
                Outcome::Blocked => {
                    let a = answer.unwrap_or_else(|| panic!("{label}: pipeline forwarded"));
                    let list = &e.block.as_ref().unwrap().list;
                    assert!(
                        contains(&a, format!("blocked by list {list}").as_bytes()),
                        "{label}"
                    );
                }
                Outcome::Local | Outcome::Special | Outcome::Refused => {
                    assert!(answer.is_some(), "{label}: pipeline forwarded");
                }
            }
        }
    }
}

#[test]
fn flt_013_explain_names_client_groups_rules_and_route() {
    let (p, sources) = setup();
    // The tablet (kids group) is blocked by `ads`, which also matches for the default group.
    let e = ask(&p, &sources, "x.ads.example.com", "10.0.0.5");
    assert_eq!(e.outcome, Outcome::Blocked);
    assert_eq!(e.client.device.as_deref(), Some("tablet"));
    assert_eq!(e.client.identified_by, "ip");
    assert_eq!(e.client.groups, ["kids"]);
    let block = e.block.as_ref().unwrap();
    assert_eq!(
        (block.list.as_str(), block.mode),
        ("ads", BlockMode::Nxdomain)
    );
    let rule = &e.filter.as_ref().unwrap().rules[0];
    assert!(rule.winner && rule.enabled);
    assert_eq!(rule.name.as_deref(), Some("ads.example.com"));
    assert_eq!(rule.lines[0].line, 1);
    assert_eq!(rule.lines[0].text, "||ads.example.com^");
    assert!(e.route.is_none(), "blocked queries aren't forwarded");

    // The allowlist wins for the tablet; the block rule is listed below it.
    let e = ask(&p, &sources, "ok.tracker.example.net", "10.0.0.5");
    assert_eq!(e.outcome, Outcome::Allowed);
    let rules = &e.filter.as_ref().unwrap().rules;
    assert_eq!((rules[0].list.as_str(), rules[0].winner), ("ok", true));
    assert_eq!((rules[1].list.as_str(), rules[1].winner), ("ads", false));
    assert_eq!(e.route.as_ref().unwrap().group, "default");

    // A name routed to the LAN group, blocked for nobody... except `ads` covers corp.example.
    let e = ask(&p, &sources, "host.corp.example", "10.0.0.9");
    assert_eq!(e.outcome, Outcome::Blocked);
    let e = ask(&p, &sources, "www.example.org", "10.0.0.9");
    assert_eq!(e.outcome, Outcome::Resolved);
    assert_eq!(e.client.identified_by, "default");
    assert_eq!(e.filter.as_ref().unwrap().rules.len(), 0);

    // Recognized by MAC at another address.
    let req = Request {
        name: "social.example",
        qtype: rtype::A,
        client: "10.0.0.77".parse().unwrap(),
        mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
        client_id: None,
    };
    let e = p.explain(&req, |n| sources.get(n).cloned()).unwrap();
    assert_eq!(e.client.identified_by, "neighbor_mac");
    assert_eq!(e.client.mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
    assert_eq!(e.outcome, Outcome::Blocked);

    // Outside allowed_networks.
    assert_eq!(
        ask(&p, &sources, "ads.example.com", "192.0.2.1").outcome,
        Outcome::Refused
    );
    assert_eq!(
        ask(&p, &sources, "nas.home.arpa", "10.0.0.9").outcome,
        Outcome::Local
    );
}

#[test]
fn flt_013_routes_and_pause_are_explained() {
    let (p, sources) = setup();
    // `strict` is only in the kids group: the default group doesn't use it.
    let e = ask(&p, &sources, "social.example", "10.0.0.9");
    assert_eq!(e.outcome, Outcome::Resolved);
    let r = &e.filter.as_ref().unwrap().rules[0];
    assert_eq!((r.list.as_str(), r.enabled), ("strict", false));
    // Pausing the kids group lets the tablet through, and says so.
    let until = unix_now() + 600;
    p.pause.pause_group("kids", until);
    let e = ask(&p, &sources, "social.example", "10.0.0.5");
    assert_eq!(e.outcome, Outcome::Resolved);
    assert_eq!(e.paused_until, Some(until));
    assert!(e.summary.contains("paused"), "{}", e.summary);
    assert!(served(&p, "social.example", "10.0.0.5").is_none());
}

#[test]
fn flt_013_explain_serializes_for_the_api() {
    let (p, sources) = setup();
    let e = ask(&p, &sources, "ads.example.com", "10.0.0.5");
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(v["outcome"], "blocked");
    assert_eq!(v["block"]["mode"], "nxdomain");
    assert_eq!(v["filter"]["rules"][0]["tier"], "block");
    assert_eq!(v["filter"]["rules"][0]["kind"], "domain");
    assert_eq!(v["filter"]["rules"][0]["scope"], "subtree");
    assert_eq!(v["client"]["groups"][0], "kids");
}

#[test]
fn flt_013_bad_names_are_errors() {
    let (p, sources) = setup();
    let req = Request {
        name: &"a".repeat(300),
        qtype: rtype::A,
        client: "10.0.0.5".parse().unwrap(),
        mac: None,
        client_id: None,
    };
    assert!(p.explain(&req, |n| sources.get(n).cloned()).is_err());
}

/// REQ: FLT-005, FLT-013 (T6.12, ADR-067) — explain names the quick rule that decides, before
/// the lists, and agrees with the pipeline.
#[test]
fn flt_005_explain_shows_quick_rules_first() {
    let (p, sources) = setup_with(
        r#"
[[rule]]
id = "tablet-ads"
action = "allow"
domain = "ads.example.com"
devices = ["tablet"]
note = "tablet game"

[[rule]]
id = "kids-org"
action = "block"
domain = "example.org"
groups = ["kids"]
"#,
    );
    let e = ask(&p, &sources, "ads.example.com", "10.0.0.5");
    assert_eq!(e.outcome, Outcome::Allowed, "{}", e.summary);
    assert!(
        e.summary.contains("quick rule (tablet game, for tablet)"),
        "{}",
        e.summary
    );
    assert!(
        served(&p, "ads.example.com", "10.0.0.5").is_none(),
        "the pipeline forwards it too"
    );
    // Another device: the list still blocks.
    assert_eq!(
        ask(&p, &sources, "ads.example.com", "10.0.0.9").outcome,
        Outcome::Blocked
    );

    let e = ask(&p, &sources, "www.example.org", "10.0.0.5");
    assert_eq!(e.outcome, Outcome::Blocked, "{}", e.summary);
    assert!(
        e.block
            .as_ref()
            .unwrap()
            .list
            .starts_with("quick rule: example.org, for kids")
    );
    let answer = served(&p, "www.example.org", "10.0.0.5").expect("the pipeline answers it");
    assert!(contains(&answer, b"quick rule"));
    assert_eq!(
        ask(&p, &sources, "www.example.org", "10.0.0.9").outcome,
        Outcome::Resolved
    );
}

/// REQ: FLT-010, FLT-013 — a block-everything schedule that's on shows up in the
/// explanation, as the pipeline applies it.
#[test]
fn flt_013_schedules_are_explained() {
    let extra = r#"
[[group]]
name = "night"
networks = ["10.0.3.0/24"]
schedules = ["always"]

[[schedule]]
name = "always"
action = "block_all"
tz = "UTC"
window = [{ days = ["daily"], start = "00:00", end = "23:59" }]
"#;
    let (p, sources) = setup_with(extra);
    let cfg = telltale_config::Loader::new()
        .toml_str("t.toml", format!("{CONFIG}{extra}"))
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    let compiled = telltale_config::schedule::compile(&cfg);
    let clients = telltale_policy::ClientTable::from_config(&cfg);
    p.schedules
        .store(Arc::new(crate::pipeline::ScheduleNow::compute(
            &cfg,
            &compiled,
            clients.groups(),
            1_791_237_600, // Monday 2026-10-05 22:00 UTC: inside the window
        )));
    p.set_filter(None);
    let answer = served(&p, "www.example.org", "10.0.3.5").expect("the pipeline blocks it");
    assert!(contains(&answer, b"blocked by schedule always"));
    let e = ask(&p, &sources, "www.example.org", "10.0.3.5");
    assert_eq!(e.outcome, Outcome::Blocked, "{}", e.summary);
    assert!(e.summary.contains("schedule always"), "{}", e.summary);
    // Other groups are unaffected, in both.
    assert!(served(&p, "www.example.org", "10.0.0.9").is_none());
    assert_eq!(
        ask(&p, &sources, "www.example.org", "10.0.0.9").outcome,
        Outcome::Resolved
    );
}

/// REQ: DNS-018, FLT-013 — a name in an authoritative zone is local data in the
/// explanation too, for the groups that see the zone.
#[test]
fn flt_013_zones_are_explained() {
    let extra = r#"
[[group]]
name = "office"
networks = ["10.0.4.0/24"]

[[zone]]
name = "corp.example"
groups = ["office"]
[[zone.record]]
name = "intranet.corp.example"
type = "A"
value = "10.10.0.5"
"#;
    let cfg = telltale_config::Loader::new()
        .toml_str("t.toml", format!("{CONFIG}{extra}"))
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    let (local, _) = LocalData::from_config(&cfg);
    let mut policy = Policy::from_config(&cfg, local);
    policy.zones = Arc::new(crate::server::load_zones(&cfg).unwrap());
    let p = Pipeline::new(
        Settings::default(),
        Arc::new(Cache::new(CachePolicy::default())),
        Arc::new(Router::from_config(&cfg).unwrap()),
        policy,
    );
    let sources = HashMap::new();
    let answer = served(&p, "intranet.corp.example", "10.0.4.5").expect("answered locally");
    assert!(contains(&answer, &[10, 10, 0, 5]));
    let e = ask(&p, &sources, "intranet.corp.example", "10.0.4.5");
    assert_eq!(e.outcome, Outcome::Local, "{}", e.summary);
    // Outside the office the zone isn't visible.
    assert_eq!(
        ask(&p, &sources, "intranet.corp.example", "10.0.0.9").outcome,
        Outcome::Resolved
    );
}

/// REQ: FLT-013, FLT-014, FLT-011 — list `$dnsrewrite` rules (which win over blocking), the
/// group's own rewrites, and safe search are in the explanation, and each outcome agrees with
/// what the pipeline does with the same query: answered locally, or sent on with a CNAME.
#[test]
fn flt_013_rewrites_and_safe_search_are_explained() {
    let extra = r#"
[[list]]
name = "rw"
rules = [
  "||rw.example^$dnsrewrite=192.0.2.55",
  "||both.example^",
  "||both.example^$dnsrewrite=NOERROR;A;192.0.2.66",
  "||nx.example^$dnsrewrite=NXDOMAIN",
  "||cn.example^$dnsrewrite=target.example",
]

[[group]]
name = "home"
networks = ["10.0.6.0/24"]
lists = ["rw"]
safe_search = true
[[group.rewrite]]
domain = "nas.lan.example"
answer = "192.168.1.10"
[[group.rewrite]]
domain = "tv.example"
answer = "cdn.example"
"#;
    let (p, sources) = setup_with(extra);
    let home = "10.0.6.5";
    // (name, outcome, text in the summary, bytes in the pipeline's local answer or None when
    // the query goes on to an upstream with a CNAME)
    let cases: [(&str, Outcome, &str, Option<&[u8]>); 7] = [
        (
            "www.rw.example",
            Outcome::Local,
            "192.0.2.55",
            Some(&[192, 0, 2, 55]),
        ),
        (
            "both.example",
            Outcome::Local,
            "192.0.2.66",
            Some(&[192, 0, 2, 66]),
        ),
        ("nx.example", Outcome::Local, "NXDOMAIN", Some(&[])),
        (
            "cn.example",
            Outcome::Resolved,
            "CNAME target.example",
            None,
        ),
        (
            "nas.lan.example",
            Outcome::Local,
            "192.168.1.10",
            Some(&[192, 168, 1, 10]),
        ),
        ("tv.example", Outcome::Resolved, "CNAME cdn.example", None),
        (
            "www.google.com",
            Outcome::Resolved,
            "forcesafesearch.google.com",
            None,
        ),
    ];
    for (name, outcome, text, local) in cases {
        let e = ask(&p, &sources, name, home);
        assert_eq!(e.outcome, outcome, "{name}: {}", e.summary);
        assert!(e.summary.contains(text), "{name}: {}", e.summary);
        let answer = served(&p, name, home);
        match (local, answer) {
            (Some(bytes), Some(a)) => assert!(
                bytes.is_empty() || contains(&a, bytes),
                "{name}: the pipeline's answer"
            ),
            (None, None) => {}
            (l, a) => panic!(
                "{name}: explain says {outcome:?} but the pipeline gave {a:?} (expected local: {l:?})"
            ),
        }
    }
    // The rcode answer really is NXDOMAIN in the pipeline.
    assert_eq!(served(&p, "nx.example", home).unwrap()[3] & 0x0F, 3);
    // A group without these lists, rewrites, or safe search sees none of it, in both.
    for name in ["www.rw.example", "nas.lan.example", "www.google.com"] {
        let e = ask(&p, &sources, name, "10.0.0.9");
        assert_eq!(e.outcome, Outcome::Resolved, "{name}: {}", e.summary);
        assert!(served(&p, name, "10.0.0.9").is_none(), "{name}");
    }
}
