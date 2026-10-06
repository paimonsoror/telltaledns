use std::fmt::Write as _;
use std::fs;

use telltale_config::{ListKind, ListMatch};

use super::*;
use crate::snapshot::{Class, ScopeTag, Snapshot};

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

fn lists() -> Vec<ListInput> {
    vec![
        input(
            "ads",
            ListKind::Block,
            "0.0.0.0 ads.example.com\n||tracker.example.net^\n|exact.example.org^\n*.wild.example.com\n\
             ||shared.example.com^\n||imp.example.com^$important\n@@||ok.ads.example.com^\n\
             ||v6.example.com^$dnstype=AAAA\n/^ad[0-9]+\\./\n^x[0-9]+\\.example\\.net$;invert\n",
        ),
        input(
            "more",
            ListKind::Block,
            "shared.example.com\n||only-more.example.com^\n||tracker.example.net^$badfilter\n\
             ||v6.example.com^$dnstype=AAAA,badfilter\n",
        ),
        input("allow", ListKind::Allow, "shared.example.com\n"),
    ]
}

fn build(dir: &Path, opts: &CompileOptions) -> (CompileReport, Snapshot) {
    let out = dir.join("v1");
    let report = compile(lists(), &out, opts).unwrap();
    (report, Snapshot::open(&out).unwrap())
}

fn classes(s: &Snapshot, id: u32) -> Vec<(Class, Vec<&str>)> {
    Class::ALL
        .iter()
        .filter_map(|&c| {
            let names: Vec<&str> = (0..3u16)
                .filter(|&l| s.listsets.contains(id, c, l))
                .filter_map(|l| s.list_name(l))
                .collect();
            (!names.is_empty()).then_some((c, names))
        })
        .collect()
}

#[test]
fn flt_003_compile_and_look_up() {
    let tmp = tempfile::tempdir().unwrap();
    let (report, snap) = build(tmp.path(), &CompileOptions::default());

    // Subtree hit on the parent; exact only on the full name; subdomains only below.
    let hits = snap.domain_hits("x.ads.example.com");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "ads.example.com");
    assert_eq!(hits[0].scope, Scope::Subtree);
    assert_eq!(snap.domain_hits("exact.example.org").len(), 1);
    assert_eq!(snap.domain_hits("a.exact.example.org").len(), 0);
    assert_eq!(snap.domain_hits("wild.example.com").len(), 0);
    assert_eq!(
        snap.domain_hits("a.wild.example.com")[0].scope,
        Scope::Subdomains
    );
    assert_eq!(snap.domain_hits("example.com").len(), 0);
    assert_eq!(snap.domain_hits("unrelated.test").len(), 0);

    // One name, several lists and classes, one interned entry.
    let shared = snap.domain_hits("shared.example.com");
    assert_eq!(
        classes(&snap, shared[0].listset),
        vec![
            (Class::Allow, vec!["allow"]),
            (Class::Block, vec!["ads", "more"])
        ]
    );
    let imp = snap.domain_hits("imp.example.com");
    assert_eq!(
        classes(&snap, imp[0].listset),
        vec![(Class::ImportantBlock, vec!["ads"])]
    );
    // `@@` inside a block list is an allow.
    let ok = snap.domain_hits("ok.ads.example.com");
    assert_eq!(ok.len(), 2, "allow on ok.ads + block on ads");
    assert_eq!(
        classes(&snap, ok[1].listset),
        vec![(Class::Allow, vec!["ads"])]
    );

    // $badfilter in list "more" disables the rule in list "ads".
    assert_eq!(snap.domain_hits("tracker.example.net").len(), 0);
    assert_eq!(snap.modrules_for("v6.example.com").len(), 0);
    assert_eq!(report.manifest.stats.badfiltered, 2);

    // Regexes kept with metadata.
    assert_eq!(snap.regexes.len(), 2);
    assert!(snap.regexes.iter().any(|r| r.invert && r.list == 0));

    let st = &report.manifest.stats;
    assert_eq!(
        (st.subtree_names, st.exact_names, st.subdomains_names),
        (5, 1, 1)
    );
    let ads = &st.per_list[0];
    let more = &st.per_list[1];
    // ads: ads, ok.ads, shared, imp, exact, wild (6 names) + 2 regexes; tracker was badfiltered.
    assert_eq!((ads.entries, ads.unique), (8, 5));
    assert_eq!((more.entries, more.unique), (2, 1));
    // REQ: OBS-009 (T7.14) — the overlap matrix: shared.example.com is on all three lists.
    let pair = |a, b| crate::snapshot::ListOverlap { a, b, names: 1 };
    assert_eq!(st.overlap, vec![pair(0, 1), pair(0, 2), pair(1, 2)]);
    assert_eq!(report.parse[0].rules, 10);
}

#[test]
fn flt_003_modifier_rules_are_indexed() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("v1");
    let lists = vec![input(
        "m",
        ListKind::Block,
        "||kids.example.org^$client=192.168.1.0/24|~'Dad laptop'\n||kids.example.org^$dnstype=HTTPS\n\
         ||example.edu^$denyallow=mail.example.edu\n||plain.example.org^\n",
    )];
    compile(lists.clone(), &out, &CompileOptions::default()).unwrap();
    let snap = Snapshot::open(&out).unwrap();
    let kids = snap.modrules_for("kids.example.org");
    assert_eq!(kids.len(), 2);
    assert_eq!(kids[0].client.len(), 2);
    assert!(kids[0].client[1].negated);
    assert_eq!(kids[1].dnstype[0].value, telltale_proto::rtype::HTTPS);
    assert_eq!(kids[0].scope, ScopeTag::Subtree);
    assert_eq!(
        snap.modrules_for("example.edu")[0].denyallow,
        vec!["mail.example.edu"]
    );
    assert_eq!(snap.modrules_for("plain.example.org").len(), 0);
    assert_eq!(snap.domain_hits("plain.example.org").len(), 1);
}

#[test]
fn flt_004_spilling_and_threads_produce_identical_snapshots() {
    let tmp = tempfile::tempdir().unwrap();
    let mut big = (0..60_000).fold(String::new(), |mut s, i| {
        let _ = writeln!(s, "n{i}.example{}.com", i % 97);
        s
    });
    // Problem lines near the end, so their line numbers cross chunk boundaries.
    big.push_str("not valid!\nexample.com##.ad\n");
    let lists = vec![
        input("big", ListKind::Block, &big),
        input(
            "small",
            ListKind::Block,
            "n5.example5.com\n||other.example.net^\n",
        ),
    ];
    let a = compile(
        lists.clone(),
        &tmp.path().join("mem"),
        &CompileOptions::default(),
    )
    .unwrap();
    let b = compile(
        lists,
        &tmp.path().join("spill"),
        &CompileOptions {
            threads: 2,
            memory_budget: 0, // clamped to 1 MiB per sorter → spills
            version: 1,
        },
    )
    .unwrap();
    assert_eq!(a.spilled_runs, 0);
    assert!(b.spilled_runs > 0);
    let blobs = |r: &CompileReport| {
        r.manifest
            .blobs
            .iter()
            .map(|b| (b.name.clone(), b.blake3.clone()))
            .collect::<Vec<_>>()
    };
    // One thread writes one FST per scope, two threads two shards each: different files,
    // identical answers.
    assert_eq!(a.manifest.fst_shards, 1);
    assert_eq!(b.manifest.fst_shards, 2);
    assert_eq!(blobs(&a).len() + 3, blobs(&b).len());
    let (sa, sb) = (
        Snapshot::open(&tmp.path().join("mem")).unwrap(),
        Snapshot::open(&tmp.path().join("spill")).unwrap(),
    );
    for i in (0..60_000).step_by(997) {
        let q = format!("x.n{i}.example{}.com", i % 97);
        let (ha, hb) = (sa.domain_hits(&q), sb.domain_hits(&q));
        assert_eq!(ha.len(), 1, "{q}");
        assert_eq!(ha.len(), hb.len(), "{q}");
        assert_eq!(
            classes(&sa, ha[0].listset),
            classes(&sb, hb[0].listset),
            "{q}"
        );
    }
    assert_eq!(a.manifest.stats.listsets, b.manifest.stats.listsets);
    assert_eq!(a.manifest.stats.subtree_names, 60_001);
    // Chunked parsing (threads = 2 splits `big`) reports the same stats and line numbers.
    assert_eq!(a.parse, b.parse);
    let lines: Vec<u32> = b.parse[0].samples.iter().map(|s| s.line).collect();
    assert_eq!(lines, vec![60_001, 60_002]);
    // No run files or partial directories left behind.
    let mut left: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    assert_eq!(left, vec!["mem", "spill"]);
}

#[test]
fn flt_003_snapshot_integrity_and_atomicity() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("v1");
    compile(lists(), &out, &CompileOptions::default()).unwrap();
    assert!(matches!(
        compile(lists(), &out, &CompileOptions::default()),
        Err(CompileError::Exists(_))
    ));
    // A modified blob is refused.
    let path = out.join(crate::snapshot::LISTSETS);
    let mut data = fs::read(&path).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xff;
    fs::write(&path, data).unwrap();
    let err = Snapshot::open(&out).unwrap_err().to_string();
    assert!(err.contains("doesn't match the manifest"), "{err}");
}

#[test]
fn flt_003_empty_input_compiles() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("v1");
    let r = compile(Vec::new(), &out, &CompileOptions::default()).unwrap();
    assert_eq!(r.manifest.stats.bytes_per_name, 0.0);
    let snap = Snapshot::open(&out).unwrap();
    assert_eq!(snap.domain_hits("ads.example.com").len(), 0);
}

#[test]
fn reversed_keys() {
    assert_eq!(reversed_key("ads.example.com"), b"com.example.ads.");
    assert_eq!(reversed_key("com"), b"com.");
}
