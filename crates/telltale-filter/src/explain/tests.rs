use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use telltale_config::{ListKind, ListMatch};
use telltale_proto::{NameBuf, rtype};

use super::*;
use crate::compile::{CompileOptions, ListData, ListInput, compile};
use crate::matcher::{ClientCtx, ListMask, Lookup};
use crate::snapshot::Snapshot;

/// Compiles `lists` and returns the matcher plus the sources by list name.
fn setup(lists: &[(&str, ListKind, &str)]) -> (Matcher, HashMap<String, Vec<u8>>) {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("snap");
    let inputs = lists
        .iter()
        .map(|(name, kind, text)| ListInput {
            name: (*name).into(),
            options: ListOptions {
                kind: *kind,
                match_mode: ListMatch::Subtree,
            },
            data: ListData::Bytes(text.as_bytes().to_vec()),
            source_hash: content_hash(text.as_bytes()),
            size: text.len() as u64,
        })
        .collect();
    compile(inputs, &out, &CompileOptions::default()).unwrap();
    let snap = Arc::new(Snapshot::open(&out).unwrap());
    let m = Matcher::with_lookup(Some(snap), Lookup::Indexed).unwrap();
    let sources = lists
        .iter()
        .map(|(n, _, t)| ((*n).to_owned(), t.as_bytes().to_vec()))
        .collect();
    (m, sources)
}

fn run(
    m: &Matcher,
    sources: &HashMap<String, Vec<u8>>,
    name: &str,
    qtype: u16,
    mask: &ListMask,
) -> Explained {
    let wire = NameBuf::from_presentation(name).unwrap().as_wire().to_vec();
    let client = ClientCtx {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        name: None,
        client_id: None,
    };
    let matches = m.matches(&wire, qtype, &client, mask);
    explain(m, &wire, &matches, |n| sources.get(n).cloned())
}

fn summary(e: &Explained) -> Vec<String> {
    e.rules
        .iter()
        .map(|r| {
            let lines: Vec<String> = r
                .lines
                .iter()
                .map(|l| format!("L{} {}", l.line, l.text))
                .collect();
            format!(
                "{}{} {:?} {:?} {} [{}]",
                if r.winner { "* " } else { "" },
                r.list,
                r.tier,
                r.kind,
                if r.enabled { "on" } else { "off" },
                lines.join("; ")
            )
        })
        .collect()
}

#[test]
fn flt_013_explains_every_matching_rule_with_its_line() {
    let ads = "# ads\n||example.com^\n\n||ads.example.com^\n0.0.0.0 ads.example.com tracker.example.com\n";
    let rx = "! regexes\n/^ads\\./\n||ads.example.com^$dnstype=A\n";
    let ok = "ads.example.com\n";
    let (m, sources) = setup(&[
        ("ads", ListKind::Block, ads),
        ("rx", ListKind::Block, rx),
        ("ok", ListKind::Allow, ok),
    ]);
    let mut mask = ListMask::default();
    mask.set(0);
    mask.set(1);
    let e = run(&m, &sources, "ads.example.com", rtype::A, &mask);
    assert_eq!(
        summary(&e),
        [
            "ok Allow Domain off [L1 ads.example.com]",
            // A list repeating a name (AdBlock line and hosts line) shows both lines.
            "* ads Block Domain on [L4 ||ads.example.com^; L5 0.0.0.0 ads.example.com tracker.example.com]",
            "rx Block Modifier on [L3 ||ads.example.com^$dnstype=A]",
            "ads Block Domain on [L2 ||example.com^]",
            "rx Block Regex on [L2 /^ads\\./]",
        ]
    );
    assert_eq!(e.rules[1].name.as_deref(), Some("ads.example.com"));
    assert_eq!(e.rules[3].name.as_deref(), Some("example.com"));
    assert_eq!(e.notes, Vec::<String>::new());
    assert_eq!(e.snapshot, Some(m.snapshot().unwrap().manifest.version));
}

#[test]
fn flt_013_notes_changed_or_missing_sources() {
    let (m, mut sources) = setup(&[("ads", ListKind::Block, "||ads.example.com^\n")]);
    let all = ListMask::all(1);
    sources.insert("ads".into(), b"# updated\n||ads.example.com^\n".to_vec());
    let e = run(&m, &sources, "ads.example.com", rtype::A, &all);
    assert_eq!(e.rules[0].lines[0].line, 2, "found in the newer copy");
    assert!(
        e.notes[0].contains("changed after snapshot"),
        "{:?}",
        e.notes
    );
    sources.clear();
    let e = run(&m, &sources, "ads.example.com", rtype::A, &all);
    assert!(e.rules[0].lines.is_empty() && e.rules[0].winner);
    assert!(e.notes[0].contains("isn't stored"), "{:?}", e.notes);
}

#[test]
fn flt_013_unmatched_name_explains_nothing() {
    let (m, sources) = setup(&[("ads", ListKind::Block, "||ads.example.com^\n")]);
    let e = run(&m, &sources, "example.org", rtype::A, &ListMask::all(1));
    assert_eq!((e.rules.len(), e.notes.len()), (0, 0));
}
