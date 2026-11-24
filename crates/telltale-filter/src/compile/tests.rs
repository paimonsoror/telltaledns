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
            sync: false, // the unsynced path must build the same snapshot
            max_regexes: 1000,
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

/// REQ: FLT-003 — regexes that each fit the engine's size limit but not together are
/// dropped at compile time (and reported), so the snapshot's regex set always builds and
/// the snapshot can be activated.
#[test]
fn flt_003_regex_set_that_only_fails_as_a_whole_is_trimmed() {
    let mut text = String::new();
    for _ in 0..16 {
        let _ = writeln!(text, "(?:[a-z]{{200}}){{200}}");
    }
    text.push_str("^ads[0-9]+\\.\n");
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("v1");
    let report = compile(
        vec![input("rx", ListKind::Block, &text)],
        &out,
        &CompileOptions::default(),
    )
    .unwrap();
    assert!(
        !report.regex_errors.is_empty(),
        "some patterns must be dropped"
    );
    assert!(report.manifest.stats.regexes >= 1, "the small one stays");
    let snap = std::sync::Arc::new(Snapshot::open(&out).unwrap());
    assert!(
        crate::matcher::Matcher::new(Some(snap)).is_ok(),
        "the snapshot must activate"
    );
}

/// REQ: FLT-003 (review 02-08) — a snapshot keeps at most `max_regexes` regex rules (0 = no
/// limit): the ones past it, in list order, are reported with their list and line, counted
/// per list, and left out of the snapshot.
#[test]
fn flt_003_regex_rules_are_capped_and_reported() {
    let lists = || {
        vec![
            input("a", ListKind::Block, "/^a1\\./\n/^a2\\./\n/^a3\\./\n"),
            input("b", ListKind::Block, "||b.example^\n/^b1\\./\n/^b2\\./\n"),
        ]
    };
    let tmp = tempfile::tempdir().unwrap();
    let report = compile(
        lists(),
        &tmp.path().join("capped"),
        &CompileOptions {
            max_regexes: 4,
            ..CompileOptions::default()
        },
    )
    .unwrap();
    let stats = &report.manifest.stats;
    assert_eq!((stats.regexes, stats.regex_rejected), (4, 1));
    assert_eq!(report.regex_errors.len(), 1);
    let (list, line, why) = &report.regex_errors[0];
    assert_eq!(
        (list.as_str(), *line),
        ("b", 3),
        "the last one, in list order"
    );
    assert!(why.contains("max_regexes"), "{why}");
    assert_eq!(stats.per_list[0].regex_skipped, 0);
    assert_eq!(stats.per_list[1].regex_skipped, 1);
    // The kept ones are the first four.
    let snap = Snapshot::open(&tmp.path().join("capped")).unwrap();
    let kept: Vec<&str> = snap.regexes.iter().map(|r| r.pattern.as_str()).collect();
    assert_eq!(kept, ["^a1\\.", "^a2\\.", "^a3\\.", "^b1\\."]);

    let all = compile(
        lists(),
        &tmp.path().join("unlimited"),
        &CompileOptions {
            max_regexes: 0,
            ..CompileOptions::default()
        },
    )
    .unwrap();
    assert_eq!(all.manifest.stats.regexes, 5);
    assert_eq!(all.manifest.stats.regex_rejected, 0);
}

/// REQ: FLT-003 (T10.3, ADR-145) — the matcher handed out before the FSTs are written decides
/// every name exactly as the finished snapshot's matcher does, in memory and with spilled
/// runs on two threads; the finished snapshot is byte-identical to a plain compile's, and
/// reuses the early index.
#[test]
#[allow(clippy::too_many_lines)] // one comparison across two compile modes
fn flt_003_the_live_matcher_decides_like_the_finished_snapshot() {
    use crate::matcher::{ClientCtx, ListMask, Lookup, Scratch};
    let tmp = tempfile::tempdir().unwrap();
    let big = (0..20_000).fold(String::new(), |mut s, i| {
        let _ = writeln!(s, "n{i}.example{}.com", i % 97);
        s
    });
    let mut inputs = lists();
    inputs.push(input("big", ListKind::Block, &big));
    let names: Vec<String> = [
        "ads.example.com",
        "x.ads.example.com",
        "ok.ads.example.com",
        "tracker.example.net",
        "exact.example.org",
        "a.exact.example.org",
        "a.wild.example.com",
        "wild.example.com",
        "shared.example.com",
        "imp.example.com",
        "only-more.example.com",
        "v6.example.com",
        "ad12.example.net",
        "nothing.example",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .chain(
        (0..20_000)
            .step_by(37)
            .map(|i| format!("n{i}.example{}.com", i % 97)),
    )
    .chain((0..500).map(|i| format!("miss{i}.example.com")))
    .collect();
    let client = ClientCtx {
        ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 20)),
        name: None,
        client_id: None,
    };
    let decide = |m: &Matcher, name: &str| {
        let wire = telltale_proto::NameBuf::from_presentation(name).unwrap();
        let mut scratch = Scratch::default();
        format!(
            "{:?}",
            m.decide(wire.as_wire(), 1, &client, &ListMask::all(8), &mut scratch)
        )
    };
    let plain = compile(
        inputs.clone(),
        &tmp.path().join("plain"),
        &CompileOptions::default(),
    )
    .unwrap();
    for (tag, opts) in [
        ("mem", CompileOptions::default()),
        (
            "spill",
            CompileOptions {
                threads: 2,
                memory_budget: 0,
                version: 1,
                sync: false,
                max_regexes: 1000,
            },
        ),
    ] {
        let out = tmp.path().join(tag);
        let mut live: Option<Matcher> = None;
        let report = compile_live(
            inputs.clone(),
            &out,
            &opts,
            Some(|m: Matcher| live = Some(m)),
        )
        .unwrap();
        let live = live.expect("the live matcher was handed out");
        assert!(live.snapshot().unwrap().is_pending());
        assert_eq!(live.lookup(), Lookup::Indexed);
        assert!(
            report
                .timings
                .ready
                .is_some_and(|r| r <= report.timings.total)
        );
        let snap = Arc::new(Snapshot::open(&out).unwrap());
        let finished = Matcher::with_lookup(Some(Arc::clone(&snap)), Lookup::Indexed).unwrap();
        let reused = Matcher::reuse_index(&snap, &live)
            .unwrap()
            .expect("same snapshot: index reused");
        for name in &names {
            let want = decide(&finished, name);
            assert_eq!(decide(&live, name), want, "{tag}: live, {name}");
            assert_eq!(decide(&reused, name), want, "{tag}: reused, {name}");
        }
        if tag == "mem" {
            let blobs = |r: &CompileReport| {
                r.manifest
                    .blobs
                    .iter()
                    .map(|b| (b.name.clone(), b.blake3.clone()))
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                blobs(&report),
                blobs(&plain),
                "the same snapshot as a plain compile"
            );
        }
    }
    // Another snapshot's index isn't reused.
    let other = Arc::new(Snapshot::open(&tmp.path().join("plain")).unwrap());
    let mut live = None;
    compile_live(
        lists(),
        &tmp.path().join("small"),
        &CompileOptions::default(),
        Some(|m: Matcher| live = Some(m)),
    )
    .unwrap();
    assert!(
        Matcher::reuse_index(&other, &live.unwrap())
            .unwrap()
            .is_none()
    );
}

/// What a compile produced, in a form that doesn't depend on how many FST shards it wrote:
/// every scope's (key, list set) entries over all shards in key order, the hash of every
/// other blob, the compile statistics (but `bytes_per_name`, which follows the sizes of the
/// shard files), the parse statistics with their sample lines, and the regex errors.
#[derive(Debug, PartialEq)]
struct Canon {
    domains: [Vec<(Vec<u8>, u64)>; 3],
    blobs: Vec<(String, String)>,
    stats: CompileStats,
    parse: Vec<ParseStats>,
    regex_errors: Vec<(String, u32, String)>,
}

fn canon(report: &CompileReport, dir: &Path) -> Canon {
    use fst::Streamer;
    let snap = Snapshot::open(dir).unwrap();
    let mut domains: [Vec<(Vec<u8>, u64)>; 3] = Default::default();
    for (entries, maps) in domains.iter_mut().zip(&snap.domains) {
        for map in maps {
            let mut stream = map.stream();
            while let Some((key, value)) = stream.next() {
                entries.push((key.to_vec(), value));
            }
        }
        entries.sort();
    }
    let shard_file = |name: &str| {
        crate::snapshot::SCOPE_NAMES
            .iter()
            .any(|s| name.starts_with(&format!("{s}-")))
    };
    let blobs = report
        .manifest
        .blobs
        .iter()
        .filter(|b| !shard_file(&b.name))
        .map(|b| (b.name.clone(), b.blake3.clone()))
        .collect();
    let mut stats = report.manifest.stats.clone();
    stats.bytes_per_name = 0.0;
    Canon {
        domains,
        blobs,
        stats,
        parse: report.parse.clone(),
        regex_errors: report.regex_errors.clone(),
    }
}

/// Compiles `lists` (name, text) with `threads` threads into `dir/<tag>` and returns its
/// canonical form; the snapshot directory is removed again.
fn compile_canon(dir: &Path, tag: &str, lists: &[(&str, &[u8])], threads: usize) -> Canon {
    let inputs = lists
        .iter()
        .map(|(name, text)| ListInput {
            name: (*name).to_owned(),
            options: ListOptions {
                kind: ListKind::Block,
                match_mode: ListMatch::Subtree,
            },
            data: ListData::Bytes(text.to_vec()),
            source_hash: String::new(),
            size: text.len() as u64,
        })
        .collect();
    let out = dir.join(tag);
    let opts = CompileOptions {
        threads,
        sync: false,
        ..CompileOptions::default()
    };
    let report = compile(inputs, &out, &opts).unwrap();
    let c = canon(&report, &out);
    fs::remove_dir_all(&out).unwrap();
    c
}

/// Asserts that every thread count from 2 to 8 compiles `lists` exactly as one thread does.
fn assert_any_thread_count_compiles_alike(
    dir: &Path,
    what: &str,
    lists: &[(&str, &[u8])],
) -> Canon {
    assert_thread_counts_compile_alike(dir, what, lists, 2..=8)
}

/// Asserts that each of `counts` compiles `lists` exactly as one thread does; returns the
/// one-thread compile.
fn assert_thread_counts_compile_alike(
    dir: &Path,
    what: &str,
    lists: &[(&str, &[u8])],
    counts: impl IntoIterator<Item = usize>,
) -> Canon {
    let one = compile_canon(dir, "t1", lists, 1);
    for threads in counts {
        let many = compile_canon(dir, &format!("t{threads}"), lists, threads);
        let at = format!("{what}, {threads} threads");
        assert_eq!(
            many.parse, one.parse,
            "{at}: parse statistics and sample lines"
        );
        assert_eq!(many.stats, one.stats, "{at}: compile statistics");
        assert_eq!(
            many.blobs, one.blobs,
            "{at}: list sets, modifier rules, regexes"
        );
        assert_eq!(many.regex_errors, one.regex_errors, "{at}: regex errors");
        for (scope, (m, o)) in many.domains.iter().zip(&one.domains).enumerate() {
            assert!(
                m == o,
                "{at}: scope {scope} entries differ ({} vs {})",
                m.len(),
                o.len()
            );
        }
        assert!(many == one, "{at}");
    }
    one
}

/// `entries` valid names (`n<i>.example<i % 7>.com`), one per line.
fn entry_lines(entries: usize, prefix: &str) -> String {
    (0..entries).fold(String::new(), |mut s, i| {
        let _ = writeln!(s, "{prefix}{i}.example{}.com", i % 7);
        s
    })
}

/// A comment line of `len` bytes (without its newline).
fn long_comment(len: usize) -> String {
    let mut s = String::from("# ");
    s.push_str(&"x".repeat(len.saturating_sub(2)));
    s
}

const MIB: usize = 1 << 20;

/// REQ: FLT-003 — a large list is cut into line-aligned pieces for the parser threads, for any
/// thread count, when its last line is one comment that runs to the end of the file (with and
/// without a final newline): the compile equals the one-thread compile.
#[test]
fn flt_003_chunked_compile_cuts_at_line_ends_for_any_thread_count() {
    let tmp = tempfile::tempdir().unwrap();
    for final_newline in [true, false] {
        let mut text = entry_lines(300, "n");
        let room = 3 * MIB - text.len() - usize::from(final_newline);
        text.push_str(&long_comment(room));
        if final_newline {
            text.push('\n');
        }
        assert_eq!(text.len(), 3 * MIB);
        let what = format!("300 names then one comment to the end, final newline {final_newline}");
        let one =
            assert_any_thread_count_compiles_alike(tmp.path(), &what, &[("big", text.as_bytes())]);
        let st = &one.parse[0];
        assert_eq!((st.lines, st.rules, st.comments), (301, 300, 1), "{what}");
        assert_eq!(one.stats.subtree_names, 300, "{what}");
    }
}

/// Appends short lines until `text` holds `upto` bytes or more: names
/// (`<prefix><i>.example<i % 7>.com`), each followed by a comment line of about 200 bytes.
fn names_up_to(text: &mut String, upto: usize, prefix: &str) {
    let filler = "c".repeat(200);
    let mut i = 0;
    while text.len() < upto {
        let _ = writeln!(text, "{prefix}{i}.example{}.com\n# {filler}", i % 7);
        i += 1;
    }
}

/// Names up to `before` bytes, one comment line of `long` bytes, names up to 3 MiB less the
/// last line, then `last` (which carries the final newline, if any).
fn around_long_line(before: usize, long: usize, last: &str) -> String {
    let mut text = String::new();
    names_up_to(&mut text, before, "h");
    text.push_str(&long_comment(long));
    text.push('\n');
    names_up_to(&mut text, 3 * MIB - last.len(), "a");
    text.push_str(last);
    text
}

/// The number of lines the parser sees in `text` (a final newline ends the last line).
fn line_count(text: &str) -> u64 {
    text.strip_suffix('\n').unwrap_or(text).split('\n').count() as u64
}

/// REQ: FLT-003 — the same wherever a line longer than a piece lies: in the first third, in
/// the middle third, straddling the last cut, as the whole file (no newline at all), before a
/// few last short lines, with CRLF line ends, and for a list only a little over the 1 MiB
/// share; tiny and empty lists too.
#[test]
fn flt_003_chunked_compile_cuts_at_line_ends_wherever_a_long_line_lies() {
    let tmp = tempfile::tempdir().unwrap();
    let mut just_over_share = String::new();
    names_up_to(&mut just_over_share, 16 << 10, "h");
    just_over_share.push_str(&long_comment(MIB));
    just_over_share.push_str("\nnot valid! tail\n");
    let shapes: Vec<(&str, String)> = vec![
        (
            "a long line in the first third",
            around_long_line(16 << 10, MIB, "tail.example.com\n"),
        ),
        (
            "a long line in the middle third",
            around_long_line(600_000, 1_600_000, "tail.example.com\n"),
        ),
        (
            "a long line straddling the last cut",
            around_long_line(1_580_000, 950_000, "tail.example.com"),
        ),
        ("one line and no newline at all", long_comment(3 * MIB)),
        (
            "a long line, then a few last short lines",
            around_long_line(16 << 10, 3 * MIB - 60_000, "not valid! tail"),
        ),
        (
            "CRLF line ends around a long line",
            around_long_line(16 << 10, 1_600_000, "tail.example.com\n").replace('\n', "\r\n"),
        ),
        ("a little over the 1 MiB share", just_over_share),
    ];
    for (what, text) in &shapes {
        assert!(text.len() > MIB, "{what}");
        let one =
            assert_any_thread_count_compiles_alike(tmp.path(), what, &[("big", text.as_bytes())]);
        assert_eq!(one.parse[0].lines, line_count(text), "{what}");
    }
    // The last short line keeps its line number.
    let (what, text) = &shapes[4];
    let one = compile_canon(tmp.path(), "tail", &[("big", text.as_bytes())], 4);
    let last = u32::try_from(line_count(text)).unwrap();
    let lines: Vec<u32> = one.parse[0].samples.iter().map(|s| s.line).collect();
    assert_eq!(lines, vec![last], "{what}");
    // Lists below the share are never cut.
    for tiny in ["", "\n", "x.example.com", "x.example.com\n", "not valid!\n"] {
        let lists = [("tiny", tiny.as_bytes())];
        assert_thread_counts_compile_alike(tmp.path(), "a tiny list", &lists, [2, 3, 8]);
    }
}

/// A fixed-seed xorshift64 generator (deterministic, no dependency).
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).unwrap()
    }
}

/// A list of about `target` bytes: mostly short lines (rules of every kind, comments, blanks,
/// invalid and unsupported lines, a few with CRLF), sometimes lines of hundreds of KiB, and
/// for some lists one line longer than half the file. The last line is never empty (a lone
/// newline after the last line is a separate case, not covered here).
fn random_list(rng: &mut XorShift, target: usize) -> String {
    let mut text = String::with_capacity(target + 4096);
    let giant_at = (rng.below(3) == 0).then(|| rng.below(target / 2));
    let mut placed = false;
    while text.len() < target {
        if !placed && giant_at.is_some_and(|at| text.len() >= at) {
            placed = true;
            let len = target / 2 + rng.below(target / 4);
            text.push_str(&long_comment(len));
        } else {
            let n = rng.below(5000);
            let m = rng.below(13);
            let line = match rng.below(1000) {
                0..=1 => long_comment(100_000 + rng.below(500_000)),
                2 => format!("bad line {}", "y".repeat(100_000 + rng.below(300_000))),
                3..=299 => format!("n{n}.example{m}.com"),
                300..=399 => format!("0.0.0.0 h{n}.example{m}.net"),
                400..=499 => format!("||a{n}.example{m}.org^"),
                500..=519 => format!("@@||a{n}.example{m}.org^"),
                520..=539 => format!("||m{n}.example.org^$dnstype=AAAA"),
                540..=541 => format!("/^r{n}[0-9]+\\./"),
                542..=559 => format!("||a{n}.example{m}.org^$badfilter"),
                560..=579 => format!("*.w{n}.example.com"),
                580..=599 => format!("|e{n}.example.org^"),
                600..=699 => format!("# comment {n}"),
                700..=749 => format!("! comment {n}"),
                750..=799 => String::new(),
                800..=849 => " \t ".to_owned(),
                850..=899 => format!("not valid! {n}"),
                900..=949 => format!("bad..name{n}"),
                _ => format!("example{n}.com##.ad"),
            };
            text.push_str(&line);
        }
        text.push_str(if rng.below(20) == 0 { "\r\n" } else { "\n" });
    }
    let _ = write!(text, "last{}.example.com", rng.below(100));
    if rng.below(2) == 0 {
        text.push('\n');
    }
    text
}

/// REQ: FLT-003 — over generated lists of 2.1 to 6 MiB with lines of any length and every kind
/// of line, compiling with 2 to 8 threads (cut into line-aligned pieces) gives exactly what one
/// thread gives: the same names and list sets (FST entries over all shards), the same other
/// blobs, statistics, sample lines and line numbers. (Six lists keep it to a few seconds in a
/// debug build; the generator makes as many as asked.)
#[test]
fn flt_003_chunked_compile_equals_single_thread() {
    let tmp = tempfile::tempdir().unwrap();
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    let small: &[u8] = b"n5.example5.com\n||other.example.net^\n||a7.example7.org^\n";
    for case in 0..6 {
        let target = 2_100_000 + rng.below(6 * MIB - 2_100_000);
        let text = random_list(&mut rng, target);
        let what = format!("generated list {case} ({} bytes)", text.len());
        let mut lists = vec![("big", text.as_bytes())];
        if case % 2 == 1 {
            lists.push(("small", small));
        }
        let one = assert_any_thread_count_compiles_alike(tmp.path(), &what, &lists);
        assert_eq!(one.parse[0].lines, line_count(&text), "{what}");
    }
}
