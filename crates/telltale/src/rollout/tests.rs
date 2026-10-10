use telltale_cluster::sync::blob_ref;

use super::*;

fn cfg() -> RolloutConfig {
    RolloutConfig {
        canaries: vec!["ephemeral".into()],
        bake_secs: 60,
        ..RolloutConfig::default()
    }
}

fn sample(node: &str, qps: u64, permille: u32, applied: u64) -> Sample {
    Sample {
        node: node.into(),
        qps,
        servfail_permille: permille,
        ready: true,
        connected: true,
        applied_seq: applied,
        sync_error: None,
        probe_failing: false,
    }
}

fn active(before: Option<f64>) -> Active {
    Active {
        version: (1, 8),
        stable: (1, 7),
        started_ms: 1_000_000,
        bake_secs: 60,
        canaries: vec!["pod-a".into()],
        before_pct: before,
    }
}

/// Feeds `secs` of 5-second ticks from `from_ms` with these samples.
fn feed(g: &mut Guard, from_ms: u64, secs: u64, samples: &[Sample]) -> u64 {
    let mut t = from_ms;
    for _ in 0..secs / 5 {
        t += 5000;
        g.observe(t, samples);
    }
    t
}

// REQ: CLU-013 — AC (8): before and after shares; a SERVFAIL rise past max(before + 2 points,
// servfail_pct) fails the bake; within it passes.
#[test]
fn clu_013_guard_compares_the_share_before_and_during_the_bake() {
    let judged: BTreeSet<String> = ["pod-a".to_owned(), "primary".to_owned()].into();
    let mut g = Guard::default();
    // Before: 1% SERVFAIL at 10 qps per node.
    let t = feed(
        &mut g,
        940_000,
        60,
        &[sample("pod-a", 10, 10, 7), sample("primary", 10, 10, 7)],
    );
    let before = g.pct(&judged, t - 60_000, t);
    assert!((before.unwrap() - 1.0).abs() < 1e-6, "{before:?}");
    let a = active(before);
    // During: the canary at 30% SERVFAIL.
    let end = feed(
        &mut g,
        1_000_000,
        60,
        &[sample("pod-a", 10, 300, 8), sample("primary", 10, 10, 8)],
    );
    let samples = [sample("pod-a", 10, 300, 8), sample("primary", 10, 10, 8)];
    match g.verdict(&a, &cfg(), end, &samples, &judged) {
        Verdict::Fail(r) => {
            assert!(r.after_pct.unwrap() > 10.0);
            assert!(r.answers >= 1000);
            assert!(r.reason.unwrap().contains("SERVFAIL"));
        }
        v => panic!("{v:?}"),
    }
    // Mid-bake, with enough answers: it fails already (the plain nodes never get it).
    match g.verdict(&a, &cfg(), 1_030_000, &samples, &judged) {
        Verdict::Fail(r) => assert!(r.reason.unwrap().contains("SERVFAIL")),
        v => panic!("{v:?}"),
    }
    // Too few answers yet: still baking.
    assert_eq!(
        g.verdict(&a, &cfg(), 1_002_000, &samples, &judged),
        Verdict::Baking
    );
    // A healthy canary passes at the end, and bakes until then.
    let mut ok = Guard::default();
    let end = feed(
        &mut ok,
        1_000_000,
        60,
        &[sample("pod-a", 10, 20, 8), sample("primary", 10, 10, 8)],
    );
    let samples = [sample("pod-a", 10, 20, 8), sample("primary", 10, 10, 8)];
    assert!(matches!(
        ok.verdict(&a, &cfg(), end, &samples, &judged),
        Verdict::Pass(_)
    ));
    assert_eq!(
        ok.verdict(&a, &cfg(), 1_030_000, &samples, &judged),
        Verdict::Baking
    );
}

// REQ: CLU-013 — AC (8): with fewer than 50 answers the bake passes, unless require_traffic,
// which keeps baking until max_bake_secs and then fails.
#[test]
fn clu_013_too_little_traffic_passes_unless_traffic_is_required() {
    let judged: BTreeSet<String> = ["pod-a".to_owned()].into();
    let mut g = Guard::default();
    let samples = [sample("pod-a", 0, 1000, 8)];
    let end = feed(&mut g, 1_000_000, 60, &samples);
    let a = active(None);
    assert!(matches!(
        g.verdict(&a, &cfg(), end, &samples, &judged),
        Verdict::Pass(_)
    ));
    let strict = RolloutConfig {
        require_traffic: true,
        max_bake_secs: 120,
        ..cfg()
    };
    assert_eq!(
        g.verdict(&a, &strict, end, &samples, &judged),
        Verdict::Baking
    );
    let later = feed(&mut g, end, 60, &samples);
    match g.verdict(&a, &strict, later, &samples, &judged) {
        Verdict::Fail(r) => assert!(r.reason.unwrap().contains("answers")),
        v => panic!("{v:?}"),
    }
}

// REQ: CLU-013 — AC (8): immediate failures on a canary that applied the version: not ready
// for 15 s, failing listener checks, gone for a minute; or one that can't apply it.
#[test]
fn clu_013_immediate_failures() {
    let judged: BTreeSet<String> = ["pod-a".to_owned()].into();
    let a = active(None);
    let mut not_ready = sample("pod-a", 10, 0, 8);
    not_ready.ready = false;
    let mut g = Guard::default();
    let t = feed(&mut g, 1_000_000, 20, &[not_ready.clone()]);
    assert!(matches!(
        g.verdict(&a, &cfg(), t, &[not_ready.clone()], &judged),
        Verdict::Fail(_)
    ));
    // Not ready before applying doesn't count.
    let mut g = Guard::default();
    let mut old = not_ready.clone();
    old.applied_seq = 7;
    let t = feed(&mut g, 1_000_000, 20, &[old.clone()]);
    assert_eq!(g.verdict(&a, &cfg(), t, &[old], &judged), Verdict::Baking);

    let mut probe = sample("pod-a", 10, 0, 8);
    probe.probe_failing = true;
    let g = Guard::default();
    match g.verdict(&a, &cfg(), 1_005_000, &[probe], &judged) {
        Verdict::Fail(r) => assert!(r.reason.unwrap().contains("listener")),
        v => panic!("{v:?}"),
    }

    let mut gone = sample("pod-a", 0, 0, 8);
    gone.connected = false;
    let mut g = Guard::default();
    let t = feed(&mut g, 1_000_000, 65, &[gone.clone()]);
    assert!(matches!(
        g.verdict(&a, &cfg(), t, &[gone.clone()], &judged),
        Verdict::Fail(_)
    ));
    let lenient = RolloutConfig {
        fail_on_disconnect: false,
        ..cfg()
    };
    assert!(!matches!(
        g.verdict(&a, &lenient, t, &[gone], &judged),
        Verdict::Fail(_)
    ));

    let mut broken = sample("pod-a", 10, 0, 7);
    broken.sync_error = Some("the reload failed".into());
    let g = Guard::default();
    assert_eq!(
        g.verdict(&a, &cfg(), 1_005_000, &[broken.clone()], &judged),
        Verdict::Baking,
        "a moment to apply"
    );
    assert!(matches!(
        g.verdict(&a, &cfg(), 1_015_000, &[broken], &judged),
        Verdict::Fail(_)
    ));
}

// REQ: CLU-013 — AC (8): who's a canary: by ID, site, or "ephemeral".
#[test]
fn clu_013_canary_selection() {
    let spec = vec!["site:k8s".to_owned(), "abc123".to_owned()];
    assert!(is_canary(&spec, "zzz", "k8s", false));
    assert!(is_canary(&spec, "abc123", "pi", false));
    assert!(!is_canary(&spec, "zzz", "pi", true));
    assert!(is_canary(&["ephemeral".into()], "zzz", "pi", true));
    assert!(!is_canary(&[], "zzz", "k8s", true), "empty: off");
}

fn entry(seq: u64, config: &[u8], shard: &[u8]) -> VersionEntry {
    VersionEntry {
        epoch: 1,
        seq,
        created_ms: seq,
        by: "alice".into(),
        outcome: outcome::STABLE.into(),
        config: blob_ref("config.json", config),
        filter: Some(FilterRef {
            version: seq,
            blobs: vec![blob_ref("subtree-0.fst", shard)],
        }),
        ..VersionEntry::default()
    }
}

// REQ: CLU-013 — AC (8): versions.json keeps the newest `history`, and its blobs are the
// protected set.
#[test]
fn clu_013_version_history_rotates_and_protects_its_blobs() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = Versions::default();
    for seq in 1..=5 {
        v.record(
            entry(seq, format!("{{\"v\":{seq}}}").as_bytes(), b"same shard"),
            3,
        );
    }
    assert_eq!(
        v.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![3, 4, 5]
    );
    v.set_outcome((1, 5), outcome::FAILED, Some(Readings::default()));
    assert_eq!(v.find((1, 5)).unwrap().outcome, "canary_failed");
    v.record(entry(4, b"{\"v\":44}", b"same shard"), 3);
    assert_eq!(
        v.entries.len(),
        3,
        "the same version is replaced, not added"
    );
    let protected = v.protected();
    assert!(
        protected
            .iter()
            .any(|b| b.hash == blob_ref("x", b"{\"v\":3}").hash)
    );
    assert!(
        !protected
            .iter()
            .any(|b| b.hash == blob_ref("x", b"{\"v\":1}").hash)
    );
    v.save(tmp.path()).unwrap();
    assert_eq!(Versions::load(tmp.path()), v);
    let s = State {
        active: Some(active(Some(1.0))),
        pinned: None,
    };
    s.save(tmp.path()).unwrap();
    assert_eq!(State::load(tmp.path()), s);
}

// REQ: CLU-013 — the diff a pinned cluster shows: JSON Patch operations and one sentence per
// section.
#[test]
fn clu_013_the_diff_between_two_versions() {
    let a = serde_json::json!({"list": [{"name": "a"}], "ratelimit": {"queries": 10}});
    let b = serde_json::json!({"list": [{"name": "a"}, {"name": "b"}], "ratelimit": {"queries": 20}, "simulate": {"enabled": false}});
    let ops = json_diff(&a, &b);
    assert_eq!(ops.len(), 3, "{ops:?}");
    assert!(
        ops.iter()
            .any(|o| o["op"] == "replace" && o["path"] == "/list")
    );
    assert!(
        ops.iter()
            .any(|o| o["op"] == "replace" && o["path"] == "/ratelimit/queries")
    );
    assert!(
        ops.iter()
            .any(|o| o["op"] == "add" && o["path"] == "/simulate")
    );
    assert_eq!(
        diff_sentences(&ops),
        vec!["list: changed", "ratelimit: changed", "simulate: added"]
    );
    assert_eq!(json_diff(&a, &a), Vec::<serde_json::Value>::new());
}
