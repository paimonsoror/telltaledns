//! NFR-002 / FLT-003: steady-state filter decisions allocate nothing (blocked, allowed, miss,
//! modifier rules, regexes, overlay), in both lookup modes. Its own test binary so nothing
//! else is counted.

#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use telltale_config::ListKind;
use telltale_filter::compile::{CompileOptions, ListData, ListInput, compile};
use telltale_filter::matcher::{ClientCtx, Decision, ListMask, Lookup, Matcher, Overlay, Scratch};
use telltale_filter::parse::ListOptions;
use telltale_filter::snapshot::Snapshot;
use telltale_proto::{NameBuf, rtype};

fn input(name: &str, kind: ListKind, text: &str) -> ListInput {
    ListInput {
        name: name.into(),
        options: ListOptions {
            kind,
            ..ListOptions::default()
        },
        data: ListData::Bytes(text.as_bytes().to_vec()),
        source_hash: telltale_filter::fetch::content_hash(text.as_bytes()),
        size: text.len() as u64,
    }
}

#[test]
fn nfr_002_filter_decisions_do_not_allocate() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("snap");
    let mut block = (0..5000).fold(String::new(), |mut s, i| {
        let _ = writeln!(s, "||ads{i}.example.com^");
        s
    });
    block.push_str(
        "||v6.example.com^$dnstype=AAAA\n/^track[0-9]+\\./\n||kids.example.org^$client=192.168.1.0/24\n*.wild.example.org\n",
    );
    compile(
        vec![
            input("block", ListKind::Block, &block),
            input("allow", ListKind::Allow, "ads7.example.com\n"),
        ],
        &out,
        &CompileOptions {
            threads: 2,
            ..CompileOptions::default()
        },
    )
    .unwrap();
    let snap = Arc::new(Snapshot::open(&out).unwrap());
    let names: Vec<Vec<u8>> = [
        "x.ads42.example.com",
        "ads7.example.com",
        "unlisted.example.org",
        "v6.example.com",
        "track9.example.net",
        "kids.example.org",
        "a.wild.example.org",
        "manual.example.net",
        "ov3.example.net",
        "a.b.c.d.e.f.g.example.com",
    ]
    .iter()
    .map(|n| NameBuf::from_presentation(n).unwrap().as_wire().to_vec())
    .collect();
    let mask = ListMask::all(3);
    let client = ClientCtx {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        names: &["laptop"],
    };
    for lookup in [Lookup::Walk, Lookup::Indexed] {
        let (overlay, _) = Overlay::build(&[(
            2,
            ListOptions::default(),
            "||manual.example.net^\n/^ov[0-9]+\\./\n",
        )])
        .unwrap();
        let m = Matcher::with_lookup(Some(Arc::clone(&snap)), overlay, lookup).unwrap();
        let mut scratch = Scratch::default();
        // Warm up: the scratch builds its regex caches on first use.
        for n in &names {
            m.decide(n, rtype::AAAA, &client, &mask, &mut scratch);
        }
        let mut blocked = 0;
        let info = allocation_counter::measure(|| {
            for _ in 0..2000 {
                for n in &names {
                    for qtype in [rtype::A, rtype::AAAA] {
                        if matches!(
                            m.decide(n, qtype, &client, &mask, &mut scratch),
                            Decision::Block(_)
                        ) {
                            blocked += 1;
                        }
                    }
                }
            }
        });
        assert_eq!(
            info.count_total, 0,
            "{lookup:?}: decide() allocated: {info:?}"
        );
        assert!(blocked > 0);
    }
}
