use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use telltale_config::{ListKind, ListMatch};
use telltale_proto::{NameBuf, rtype};

use super::*;
use crate::compile::{CompileOptions, ListData, ListInput, compile};

fn input(name: &str, kind: ListKind, text: &str) -> ListInput {
    ListInput {
        name: name.into(),
        options: ListOptions {
            kind,
            match_mode: ListMatch::Subtree,
        },
        data: ListData::Bytes(text.as_bytes().to_vec()),
        source_hash: crate::fetch::content_hash(text.as_bytes()),
        size: text.len() as u64,
    }
}

/// Compiles `lists` (IDs in order) with `threads` and returns a matcher.
fn matcher_with(lists: Vec<ListInput>, threads: usize, overlay: Overlay) -> Matcher {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("snap");
    compile(
        lists,
        &out,
        &CompileOptions {
            threads,
            ..CompileOptions::default()
        },
    )
    .unwrap();
    let snap = Arc::new(Snapshot::open(&out).unwrap());
    let lookup = if std::env::var_os("TELLTALE_TEST_WALK").is_some() {
        Lookup::Walk
    } else {
        Lookup::Indexed
    };
    Matcher::with_lookup(Some(snap), overlay, lookup).unwrap()
}

fn wire(name: &str) -> Vec<u8> {
    NameBuf::from_presentation(name).unwrap().as_wire().to_vec()
}

const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

fn decide_full(m: &Matcher, name: &str, qtype: u16, names: &[&str], mask: &ListMask) -> String {
    let client = ClientCtx {
        ip: CLIENT_IP,
        names,
    };
    let mut scratch = Scratch::default();
    match m.decide(&wire(name), qtype, &client, mask, &mut scratch) {
        Decision::None => "none".into(),
        Decision::Allow(a) => format!("allow {}", describe(m, &a)),
        Decision::Block(a) => format!("block {}", describe(m, &a)),
    }
}

fn describe(m: &Matcher, a: &Attribution) -> String {
    let list = m
        .snapshot()
        .and_then(|s| s.list_name(a.list))
        .map_or_else(|| format!("#{}", a.list), str::to_owned);
    let rule = match a.rule {
        RuleRef::Domain { scope, labels } => format!("{scope:?}/{labels}"),
        RuleRef::ModRule { .. } => "mod".into(),
        RuleRef::Regex { .. } => "regex".into(),
    };
    let ov = if a.overlay { " overlay" } else { "" };
    format!("{list} {rule}{ov}")
}

fn decide(m: &Matcher, name: &str) -> String {
    decide_full(m, name, rtype::A, &[], &ListMask::all(8))
}

#[test]
fn flt_003_precedence_table() {
    let m = matcher_with(
        vec![
            input(
                "block",
                ListKind::Block,
                "||ads.example.com^\n||both.example.com^\n||imp.example.com^$important\n\
                 ||tracker.example.net^\n|exact.example.org^\n*.wild.example.org\n||ok.example.com^\n",
            ),
            input(
                "allow",
                ListKind::Allow,
                "both.example.com\nimp.example.com\nimpallow.example.com\n",
            ),
            input(
                "more",
                ListKind::Block,
                "@@||impallow.example.com^$important\n||impallow.example.com^$important\n\
                 ||tracker.example.net^\nsub.ads.example.com\n",
            ),
        ],
        1,
        Overlay::default(),
    );
    let cases = [
        // (name, expected decision with attribution)
        ("ads.example.com", "block block Subtree/3"),
        ("x.y.ads.example.com", "block block Subtree/3"),
        ("example.com", "none"),
        ("notads.example.com", "none"),
        // Tier 3 (allow) beats tier 4 (block).
        ("both.example.com", "allow allow Subtree/3"),
        // Tier 2 (important block) beats tier 3 (allow).
        ("imp.example.com", "block block Subtree/3"),
        // Tier 1 (important allow) beats tier 2.
        ("impallow.example.com", "allow more Subtree/3"),
        // Same tier, two lists: lowest list ID gets the attribution.
        ("tracker.example.net", "block block Subtree/3"),
        // Same tier: the most specific suffix wins attribution.
        ("a.sub.ads.example.com", "block more Subtree/4"),
        // Exact scope: only the name itself.
        ("exact.example.org", "block block Exact/3"),
        ("a.exact.example.org", "none"),
        // Subdomains scope: below the name, not the apex.
        ("wild.example.org", "none"),
        ("a.wild.example.org", "block block Subdomains/3"),
        // Root and odd names never match.
        (".", "none"),
    ];
    let mut failures = Vec::new();
    for (name, want) in cases {
        let got = decide(&m, name);
        if got != want {
            failures.push(format!("{name}: want `{want}`, got `{got}`"));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn flt_005_mask_selects_lists() {
    let m = matcher_with(
        vec![
            input("a", ListKind::Block, "||ads.example.com^\n"),
            input("b", ListKind::Allow, "ads.example.com\n"),
        ],
        1,
        Overlay::default(),
    );
    let mut only_a = ListMask::default();
    only_a.set(0);
    let mut only_b = ListMask::default();
    only_b.set(1);
    assert_eq!(
        decide_full(&m, "ads.example.com", rtype::A, &[], &only_a),
        "block a Subtree/3"
    );
    assert_eq!(
        decide_full(&m, "ads.example.com", rtype::A, &[], &only_b),
        "allow b Subtree/3"
    );
    assert_eq!(
        decide_full(&m, "ads.example.com", rtype::A, &[], &ListMask::default()),
        "none"
    );
    assert_eq!(
        decide_full(&m, "ads.example.com", rtype::A, &[], &ListMask::all(2)),
        "allow b Subtree/3"
    );
}

#[test]
fn flt_001_modifier_rules() {
    let m = matcher_with(
        vec![input(
            "m",
            ListKind::Block,
            "||v6.example.com^$dnstype=AAAA\n||nohttps.example.com^$dnstype=~HTTPS\n\
             ||kids.example.org^$client=192.168.1.0/24|~192.168.1.99\n\
             ||tv.example.org^$client='Living Room TV'\n\
             ||example.edu^$denyallow=mail.example.edu\n\
             ||rewrite.example.com^$dnsrewrite=NOERROR;A;192.0.2.1\n",
        )],
        1,
        Overlay::default(),
    );
    let all = ListMask::all(1);
    let d = |name: &str, qtype: u16, names: &[&str]| decide_full(&m, name, qtype, names, &all);
    assert_eq!(d("v6.example.com", rtype::AAAA, &[]), "block m mod");
    assert_eq!(d("v6.example.com", rtype::A, &[]), "none");
    assert_eq!(d("x.nohttps.example.com", rtype::A, &[]), "block m mod");
    assert_eq!(d("nohttps.example.com", rtype::HTTPS, &[]), "none");
    assert_eq!(
        d("kids.example.org", rtype::A, &[]),
        "block m mod",
        "client in CIDR"
    );
    assert_eq!(
        d("tv.example.org", rtype::A, &["living room tv"]),
        "block m mod"
    );
    assert_eq!(d("tv.example.org", rtype::A, &["laptop"]), "none");
    assert_eq!(d("www.example.edu", rtype::A, &[]), "block m mod");
    assert_eq!(d("mail.example.edu", rtype::A, &[]), "none", "denyallow");
    assert_eq!(
        d("x.mail.example.edu", rtype::A, &[]),
        "none",
        "denyallow subtree"
    );
    assert_eq!(
        d("rewrite.example.com", rtype::A, &[]),
        "none",
        "rewrites aren't blocks"
    );

    // Negated client: the excluded address isn't blocked.
    let client = ClientCtx {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99)),
        names: &[],
    };
    let mut scratch = Scratch::default();
    assert_eq!(
        m.decide(
            &wire("kids.example.org"),
            rtype::A,
            &client,
            &all,
            &mut scratch
        ),
        Decision::None
    );
}

#[test]
fn flt_003_regex_rules() {
    let m = matcher_with(
        vec![
            input(
                "rx",
                ListKind::Block,
                "/^ad[0-9]+\\./\n^track-[a-z]+\\.;querytype=AAAA\n^(.*\\.)?keep\\.example\\.com$;invert\n\
                 ||ad1.example.com^\n",
            ),
            input("allow", ListKind::Allow, "/^ad7\\./\n"),
        ],
        1,
        Overlay::default(),
    );
    let all = ListMask::all(2);
    let d = |name: &str, qtype: u16| decide_full(&m, name, qtype, &[], &all);
    // A domain rule outranks a regex in the same tier.
    assert_eq!(d("ad1.example.com", rtype::A), "block rx Subtree/3");
    assert_eq!(d("ad2.example.com", rtype::A), "block rx regex");
    assert_eq!(d("ad7.example.com", rtype::A), "allow allow regex");
    assert_eq!(d("track-x.example.net", rtype::AAAA), "block rx regex");
    assert_eq!(
        d("track-x.example.net", rtype::A),
        "block rx regex",
        "invert rule applies"
    );
    // The ;invert rule blocks everything except keep.example.com (and its subdomains).
    assert_eq!(d("keep.example.com", rtype::A), "none");
    assert_eq!(d("www.keep.example.com", rtype::A), "none");
    // Regex prefilter: a client without regex lists never runs the regexes.
    assert_eq!(
        decide_full(&m, "ad2.example.com", rtype::A, &[], &ListMask::default()),
        "none"
    );
}

#[test]
fn flt_003_overlay_applies_without_recompiling() {
    let (overlay, stats) = Overlay::build(&[(
        2,
        ListOptions::default(),
        "||new.example.com^\n@@||ads.example.com^\n/^rx[0-9]+\\./\n||mod.example.com^$dnstype=AAAA\n",
    )])
    .unwrap();
    assert_eq!(stats[0].rules, 4);
    let m = matcher_with(
        vec![
            input("block", ListKind::Block, "||ads.example.com^\n"),
            input("other", ListKind::Block, "||unrelated.example.net^\n"),
        ],
        1,
        overlay,
    );
    assert_eq!(decide(&m, "new.example.com"), "block #2 Subtree/3 overlay");
    assert_eq!(decide(&m, "ads.example.com"), "allow #2 Subtree/3 overlay");
    assert_eq!(decide(&m, "rx5.example.org"), "block #2 regex overlay");
    assert_eq!(
        decide_full(&m, "mod.example.com", rtype::AAAA, &[], &ListMask::all(3)),
        "block #2 mod overlay"
    );
    // Overlay rules obey the mask like any list.
    let mut no_overlay = ListMask::all(2);
    no_overlay.words.truncate(1);
    assert_eq!(
        decide_full(&m, "ads.example.com", rtype::A, &[], &no_overlay),
        "block block Subtree/3"
    );
}

#[test]
fn flt_003_sharded_snapshots_decide_identically() {
    let mut text = String::new();
    for i in 0..3000 {
        let _ = writeln!(text, "||n{i}.zone{}.example{}.com^", i % 7, i % 13);
    }
    text.push_str(
        "||com^$important\n@@||safe.zone1.example1.com^$important\n|exact.zone2.example2.com^\n",
    );
    let one = matcher_with(
        vec![input("l", ListKind::Block, &text)],
        1,
        Overlay::default(),
    );
    let three = matcher_with(
        vec![input("l", ListKind::Block, &text)],
        3,
        Overlay::default(),
    );
    assert_eq!(three.snapshot().unwrap().manifest.fst_shards, 3);
    for q in [
        "a.n5.zone5.example5.com",
        "n0.zone0.example0.com",
        "safe.zone1.example1.com",
        "x.safe.zone1.example1.com",
        "exact.zone2.example2.com",
        "x.exact.zone2.example2.com",
        "unlisted.example.com",
        "com",
        "example.net",
    ] {
        assert_eq!(decide(&one, q), decide(&three, q), "{q}");
    }
}

#[test]
fn flt_003_no_snapshot_means_no_decision() {
    let m = Matcher::new(None, Overlay::default()).unwrap();
    assert_eq!(decide(&m, "ads.example.com"), "none");
}

#[test]
fn flt_003_walk_and_index_agree() {
    let mut text = String::new();
    for i in 0..4000 {
        let _ = writeln!(text, "||n{i}.zone{}.example{}.com^", i % 7, i % 13);
    }
    text.push_str("||com^$important\n@@||safe.zone1.example1.com^$important\n|exact.zone2.example2.com^\n*.wild.example.org\n");
    let tmp = tempfile::tempdir().unwrap();
    for threads in [1, 3] {
        let out = tmp.path().join(format!("snap{threads}"));
        compile(
            vec![input("l", ListKind::Block, &text)],
            &out,
            &CompileOptions {
                threads,
                ..CompileOptions::default()
            },
        )
        .unwrap();
        let snap = Arc::new(Snapshot::open(&out).unwrap());
        let walk =
            Matcher::with_lookup(Some(snap.clone()), Overlay::default(), Lookup::Walk).unwrap();
        let idx = Matcher::with_lookup(Some(snap), Overlay::default(), Lookup::Indexed).unwrap();
        assert_eq!(walk.lookup(), Lookup::Walk);
        assert!(idx.index_bytes() > 0);
        for i in 0..4000 {
            for q in [
                format!("n{i}.zone{}.example{}.com", i % 7, i % 13),
                format!("x.n{i}.zone{}.example{}.com", i % 7, i % 13),
                format!("n{i}.other.net"),
                "safe.zone1.example1.com".to_owned(),
                "exact.zone2.example2.com".to_owned(),
                "a.exact.zone2.example2.com".to_owned(),
                "wild.example.org".to_owned(),
                "a.wild.example.org".to_owned(),
            ] {
                assert_eq!(
                    decide(&walk, &q),
                    decide(&idx, &q),
                    "{q} (threads {threads})"
                );
            }
        }
    }
}
