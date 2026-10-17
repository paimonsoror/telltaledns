use super::*;

/// A fresh data directory for one test.
fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tt-ann-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const NOW: u64 = 1_791_072_000_000; // 2026-10-04T00:00:00Z

fn all(a: &Annotations) -> Vec<Annotation> {
    a.read(&AnnotationFilter {
        from_ms: 0,
        to_ms: u64::MAX,
        kinds: Vec::new(),
        limit: usize::MAX,
    })
}

fn count(a: &Annotations, kind: &str) -> u64 {
    a.counts()
        .into_iter()
        .find(|(k, _)| *k == kind)
        .map_or(0, |(_, n)| n)
}

// REQ: OBS-033 — configuration 313 applied from GitOps is one `config.applied` line with its
// sequence and source, on a replica (the manifest's) and on the primary (the publish's); a
// reload that changed nothing, or a version that only carries users and acknowledgements,
// writes none.
#[test]
fn obs_033_config_applied_from_gitops() {
    let d = dir("cfg");
    let a = Annotations::open(&d, NOW);
    // A replica: the manifest names a commit.
    a.set_provenance(Provenance {
        source: "gitops".into(),
        seq: Some(313),
        filter_version: Some(41),
        ..Provenance::default()
    });
    a.reloaded(
        vec!["upstream".into(), "list".into()],
        false,
        || Some(1),
        NOW,
    );
    let lines = all(&a);
    assert_eq!(lines.len(), 1);
    let l = &lines[0];
    assert_eq!(l.kind, "config.applied");
    assert_eq!(l.seq, Some(313));
    assert_eq!(l.source.as_deref(), Some("gitops"));
    assert_eq!(l.actor, None);
    assert_eq!(l.sections, ["upstream", "list"]);
    assert_eq!(
        l.summary,
        "configuration 313 applied (gitops, 2 sections changed, filter snapshot 41)"
    );
    // A version that only carried users and tokens: the reload changed no section.
    a.set_provenance(Provenance {
        source: "cluster".into(),
        seq: Some(314),
        ..Provenance::default()
    });
    a.reloaded(Vec::new(), false, || Some(1), NOW + 1);
    assert_eq!(all(&a).len(), 1, "nothing changed, nothing written");

    // The primary: the reload waits for the publish's sequence; a Git commit makes it gitops.
    a.reloaded(vec!["group".into()], true, || None, NOW + 2);
    assert_eq!(all(&a).len(), 1, "waits for the publish");
    a.published(313, true, NOW + 3);
    let l = all(&a).into_iter().next().unwrap();
    assert_eq!((l.seq, l.source.as_deref()), (Some(313), Some("gitops")));
    a.published(314, false, NOW + 4);
    assert_eq!(
        all(&a).len(),
        2,
        "a publish without a change writes nothing"
    );

    // A standalone node's API write: its version, its author.
    a.set_provenance(Provenance {
        source: "agent".into(),
        actor: Some("agent:bot (owner: admin)".into()),
        seq: Some(7),
        ..Provenance::default()
    });
    a.reloaded(vec!["rules".into()], false, || Some(99), NOW + 5);
    let l = all(&a).into_iter().next().unwrap();
    assert_eq!(l.seq, Some(7));
    assert_eq!(l.actor.as_deref(), Some("agent:bot (owner: admin)"));
    assert_eq!(
        l.summary,
        "configuration 7 applied (agent, 1 section changed)"
    );
    // SIGHUP: the files, and the node's own version.
    a.reloaded(vec!["cache".into()], false, || Some(99), NOW + 6);
    let l = all(&a).into_iter().next().unwrap();
    assert_eq!((l.seq, l.source.as_deref()), (Some(99), Some("file")));
    assert_eq!(count(&a, "config.applied"), 4);
    let _ = std::fs::remove_dir_all(&d);
}

// REQ: OBS-033 — every start writes `node.restarted`; `build.started` only when the build
// differs from the last restart's.
#[test]
fn obs_033_restarts_and_new_builds() {
    let d = dir("start");
    let a = Annotations::open(&d, NOW);
    a.started("0.5.0", "abc", false, NOW);
    // In the order written (a start's two lines share a millisecond).
    let kinds = |a: &Annotations| -> Vec<String> {
        a.lines().unwrap().into_iter().map(|l| l.kind).collect()
    };
    assert_eq!(
        kinds(&a),
        ["build.started", "node.restarted"],
        "first start"
    );
    // Same build again (reopened, as after a restart).
    let a = Annotations::open(&d, NOW + 10);
    a.started("0.5.0", "abc", true, NOW + 10);
    assert_eq!(
        kinds(&a),
        ["build.started", "node.restarted", "node.restarted"],
        "same build: no build.started"
    );
    let last = a.lines().unwrap().pop().unwrap();
    assert_eq!(last.unclean_shutdown, Some(true));
    assert_eq!(last.summary, "node restarted after an unclean stop");
    // A new build.
    a.started("0.5.1", "def", false, NOW + 20);
    let v = a.lines().unwrap();
    assert_eq!(v[3].kind, "build.started");
    assert_eq!(v[3].summary, "build 0.5.1 started (was 0.5.0)");
    assert_eq!(v[4].kind, "node.restarted");
    assert_eq!(v.len(), 5);
    let _ = std::fs::remove_dir_all(&d);
}

// REQ: OBS-033 — 25,000 lines compact to the newest 20,000 at start; lines older than 90 days
// go.
#[test]
fn obs_033_compaction_caps_lines_and_age() {
    let d = dir("cap");
    let mut body = String::new();
    // 10 lines older than 90 days, then 25,000 recent ones.
    for i in 0..10u64 {
        let l = marker("note", NOW - MAX_AGE_MS - 1000 + i, "old");
        body.push_str(&serde_json::to_string(&l).unwrap());
        body.push('\n');
    }
    for i in 0..25_000u64 {
        let l = marker("note", NOW - 25_000 + i, format!("n{i}"));
        body.push_str(&serde_json::to_string(&l).unwrap());
        body.push('\n');
    }
    std::fs::write(d.join(FILE), body).unwrap();
    let a = Annotations::open(&d, NOW);
    let v = all(&a);
    assert_eq!(v.len(), MAX_LINES);
    assert_eq!(v[0].summary, "n24999", "the newest stays");
    assert_eq!(
        v.last().unwrap().summary,
        "n5000",
        "the oldest 5,000 recent ones went"
    );
    assert!(v.iter().all(|l| l.summary != "old"));
    // Only age: a 90-day-old line goes on the next compaction.
    assert_eq!(a.compact(NOW).unwrap(), 0, "nothing more to drop");
    assert_eq!(
        a.compact(NOW + MAX_AGE_MS - 10_000).unwrap(),
        10_000,
        "the half older than 90 days by then"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// REQ: OBS-033, CLU-004 — a data directory that can't be written: one warning, every write
// counted, nothing else affected (the call returns; the reads answer empty).
#[test]
fn obs_033_a_write_error_warns_once() {
    let d = dir("ro");
    // The "data directory" is a file: nothing below it can be created.
    let not_a_dir = d.join("file");
    std::fs::write(&not_a_dir, b"x").unwrap();
    let a = Annotations::open(&not_a_dir, NOW);
    for i in 0..3 {
        assert!(a.append(marker("note", NOW + i, "x")).is_err());
    }
    a.started("0.5.0", "abc", false, NOW + 5);
    assert_eq!(a.failures(), (5, 1), "five failures, one warning");
    assert_eq!(all(&a), Vec::<Annotation>::new());
    assert_eq!(count(&a, "note"), 0, "only written lines count");
    let _ = std::fs::remove_dir_all(&d);
}

// REQ: OBS-033 — `telltale_annotations_total{kind}` counts each written line.
#[test]
fn obs_033_lines_are_counted_per_kind() {
    let d = dir("count");
    let a = Annotations::open(&d, NOW);
    a.record(marker("note", NOW, "a"));
    a.record(marker("note", NOW + 1, "b"));
    a.record(marker("cache.flushed", NOW + 2, "c"));
    assert_eq!(count(&a, "note"), 2);
    assert_eq!(count(&a, "cache.flushed"), 1);
    assert_eq!(count(&a, "config.applied"), 0);
    assert_eq!(a.counts().len(), KINDS.len());
    let _ = std::fs::remove_dir_all(&d);
}

// REQ: OBS-033 — reads filter by window and kind, newest first, up to the limit; a stored
// line never carries a node (the reader labels it).
#[test]
fn obs_033_reads_filter_and_sort() {
    let d = dir("read");
    let a = Annotations::open(&d, NOW);
    a.record(marker("note", NOW + 30, "late note")); // a backdated note written later
    a.record(marker("cache.flushed", NOW + 10, "flush"));
    a.record(Annotation {
        node: Some("pi".into()),
        ..marker("note", NOW + 20, "early note")
    });
    let read = |from, to, kinds: &[&str], limit| -> Vec<String> {
        a.read(&AnnotationFilter {
            from_ms: from,
            to_ms: to,
            kinds: kinds.iter().map(|k| (*k).to_owned()).collect(),
            limit,
        })
        .into_iter()
        .map(|l| l.summary)
        .collect()
    };
    assert_eq!(
        read(0, u64::MAX, &[], 10),
        ["late note", "early note", "flush"]
    );
    assert_eq!(
        read(0, u64::MAX, &["note"], 10),
        ["late note", "early note"]
    );
    assert_eq!(read(NOW + 10, NOW + 30, &[], 10), ["early note", "flush"]);
    assert_eq!(read(0, u64::MAX, &[], 1), ["late note"]);
    assert!(all(&a).iter().all(|l| l.node.is_none()));
    let _ = std::fs::remove_dir_all(&d);
}

// REQ: OBS-033 — breakers: a line when one opens or closes, at most one per upstream per 5
// minutes; a change inside that time is written later if it still holds.
#[test]
fn obs_033_breakers_are_rate_limited() {
    let d = dir("brk");
    let a = Annotations::open(&d, NOW);
    let states = |a: &Annotations| -> Vec<String> {
        let mut v: Vec<String> = all(a)
            .into_iter()
            .map(|l| l.state.unwrap_or_default())
            .collect();
        v.reverse();
        v
    };
    a.breaker("quad9", "closed", NOW);
    assert_eq!(states(&a), Vec::<String>::new(), "closed all along");
    a.breaker("quad9", "open", NOW + 1_000);
    a.breaker("quad9", "closed", NOW + 60_000);
    a.breaker("quad9", "open", NOW + 120_000);
    assert_eq!(states(&a), ["open"], "flapping inside 5 minutes: one line");
    a.breaker("quad9", "closed", NOW + 200_000);
    a.breaker("quad9", "closed", NOW + 301_000);
    assert_eq!(
        states(&a),
        ["open", "closed"],
        "the state that held, once due"
    );
    a.breaker("cloudflare", "open", NOW + 301_500);
    assert_eq!(states(&a).len(), 3, "each upstream on its own");
    assert_eq!(
        all(&a)[0].summary,
        "upstream cloudflare's breaker opened: its answers are failing, other upstreams answer"
    );
    let _ = std::fs::remove_dir_all(&d);
}

fn manifest(
    version: u64,
    lists: &[(&str, &str)],
    names: u64,
) -> telltale_filter::snapshot::Manifest {
    telltale_filter::snapshot::Manifest {
        format: 1,
        version,
        fst_shards: 1,
        created: 0,
        lists: lists
            .iter()
            .enumerate()
            .map(|(i, (n, h))| telltale_filter::snapshot::ManifestList {
                id: u16::try_from(i).unwrap(),
                name: (*n).to_owned(),
                source_hash: (*h).to_owned(),
                kind: telltale_config::ListKind::Block,
                match_mode: telltale_config::ListMatch::Subtree,
            })
            .collect(),
        blobs: Vec::new(),
        stats: telltale_filter::snapshot::CompileStats {
            subtree_names: names,
            ..telltale_filter::snapshot::CompileStats::default()
        },
    }
}

// REQ: OBS-033 — a refresh that changed nothing writes no line; one that did names the lists
// and the blocked names gained.
#[test]
fn obs_033_list_refreshes() {
    let before = manifest(4, &[("ads", "h1"), ("trackers", "h2")], 1000);
    let same = manifest(5, &[("ads", "h1"), ("trackers", "h2")], 1000);
    assert_eq!(lists_line(Some(&before), &same, NOW), None);
    let after = manifest(5, &[("ads", "h9"), ("trackers", "h2")], 1250);
    let l = lists_line(Some(&before), &after, NOW).unwrap();
    assert_eq!(l.kind, "lists.refreshed");
    assert_eq!(l.lists, ["ads"]);
    assert_eq!(l.rules_delta, Some(250));
    assert_eq!(l.filter_version, Some(5));
    assert_eq!(
        l.summary,
        "list ads refreshed: filter snapshot 5 (+250 blocked names)"
    );
    let fewer = manifest(6, &[("ads", "h9")], 900);
    let l = lists_line(Some(&after), &fewer, NOW).unwrap();
    assert_eq!(l.lists, ["trackers"]);
    assert_eq!(l.rules_delta, Some(-350));
    let first = lists_line(None, &before, NOW).unwrap();
    assert_eq!(first.lists, ["ads", "trackers"]);
    assert_eq!(
        first.summary,
        "2 lists refreshed: filter snapshot 4 (+1000 blocked names)"
    );
}

// REQ: OBS-033 — the sections that differ are the configuration's top-level keys.
#[test]
fn obs_033_changed_sections() {
    let a = telltale_config::Config::default();
    let mut b = a.clone();
    assert_eq!(changed_sections(&a, &b), Vec::<String>::new());
    b.cache.persist = !a.cache.persist;
    b.slo.latency_ms += 1;
    assert_eq!(changed_sections(&a, &b), ["cache", "slo"]);
}
