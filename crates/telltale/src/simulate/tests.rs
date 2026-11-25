use std::path::Path;
use std::time::Duration;

use telltale_filter::compile::{CompileOptions, ListData, ListInput, compile};
use telltale_filter::parse::ListOptions;
use telltale_filter::snapshot::Snapshot;
use telltale_store::qlog::{Builder, Settings};
use telltale_telemetry::{Proto, QueryEvent};

use super::*;

const CONFIG: &str = r#"
[access]
allowed_networks = ["10.0.0.0/8"]

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

[[list]]
name = "ads"
rules = ["||ads.example^"]
[[list]]
name = "social"
rules = ["||social.example^"]

[[group]]
name = "kids"
lists = ["ads"]
[[group]]
name = "teens"
lists = ["ads"]
[[group]]
name = "strict"
lists = ["ads", "social"]

[[client]]
name = "tablet"
match = ["10.0.0.5"]
groups = ["kids"]
"#;

/// The base time of every test here: 12:00 UTC, one to two days ago, fixed for the process.
/// It follows the clock because the query log drops segments older than its retention (30
/// days here): a fixed date (2026-10-08) was inside it when written and gone from 2026-11-07,
/// which failed these tests with no change to the code.
fn t0_s() -> u64 {
    static T0: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *T0.get_or_init(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        (now / 86_400 - 2) * 86_400 + 12 * 3_600
    })
}

struct Lab {
    tmp: tempfile::TempDir,
    current: Arc<Config>,
    serving: Arc<Matcher>,
}

fn load(extra: &str, data_dir: &Path) -> Config {
    let toml = format!(
        "[node]\ndata_dir = \"{}\"\n{CONFIG}{extra}",
        data_dir.display()
    );
    telltale_config::Loader::new()
        .toml_str("t.toml", toml)
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config
}

/// Every enabled list of `cfg`, compiled: what the server would be serving.
fn compile_all(cfg: &Config, out: &Path) -> Arc<Matcher> {
    let inputs = enabled_lists(cfg)
        .iter()
        .map(|l| {
            let text: String = l.rules.iter().flat_map(|r| [r.as_str(), "\n"]).collect();
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
    compile(inputs, out, &CompileOptions::default()).unwrap();
    let snap = Arc::new(Snapshot::open(out).unwrap());
    Arc::new(Matcher::with_lookup(Some(snap), Lookup::Indexed).unwrap())
}

impl Lab {
    fn new(extra: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let current = load(extra, tmp.path());
        let serving = compile_all(&current, &tmp.path().join("serving"));
        Self {
            tmp,
            current: Arc::new(current),
            serving,
        }
    }

    fn qlog(&self) -> std::path::PathBuf {
        self.tmp.path().join("qlog")
    }

    fn candidate(&self, extra: &str) -> Config {
        load(extra, self.tmp.path())
    }

    /// A writer on this lab's query log (nothing flushes before it is dropped).
    fn writer(&self) -> Builder {
        Builder::spawn(Settings {
            dir: self.qlog(),
            node: 1,
            privacy: 0,
            flush_interval: Duration::from_secs(3600),
            fsync: false,
            retention_days: 30,
            retention_bytes: u64::MAX,
            rotate_after: None,
        })
        .unwrap()
    }

    /// Logs one query for `name` from `ip` (last octet) at `ts_us` microseconds, as the
    /// pipeline would have (status `blocked` when `blocked`).
    fn log_at(&self, name: &str, ip: u8, ts_us: u64, blocked: bool) {
        let mut b = self.writer();
        let wire = NameBuf::from_presentation(name).unwrap();
        b.push(&event(ts_us, [10, 0, 0, ip], blocked), wire.as_wire());
        drop(b);
    }

    /// Logs `n` queries for `name` from `ip` (last octet), one second apart, ending at
    /// `end_s`, as the pipeline would have (status `blocked` when `blocked`).
    fn log(&self, name: &str, ip: u8, n: u64, end_s: u64, blocked: bool) {
        let mut b = self.writer();
        let wire = NameBuf::from_presentation(name).unwrap();
        for i in 0..n {
            b.push(
                &event((end_s - i) * 1_000_000, [10, 0, 0, ip], blocked),
                wire.as_wire(),
            );
        }
        drop(b);
    }

    fn inputs(&self, candidate: Config, sources: Vec<SideSource>) -> Inputs {
        Inputs {
            current: Arc::clone(&self.current),
            candidate: Arc::new(candidate),
            serving: Some(Arc::clone(&self.serving)),
            sources,
            dirs: vec![self.qlog()],
            window: Window {
                from_us: (t0_s() - 86_400) * 1_000_000,
                to_us: (t0_s() + 1) * 1_000_000,
                max_rows: 2_000_000,
                max_secs: 20,
            },
            label: Box::new(|_| None),
        }
    }

    /// Simulates `candidate` over the log (side lists from their inline rules).
    fn simulate(&self, candidate: Config) -> Tally {
        let sources = inline_sources(&self.current, &candidate);
        run(self.inputs(candidate, sources)).unwrap()
    }
}

fn inline_sources(current: &Config, candidate: &Config) -> Vec<SideSource> {
    changed_lists(current, candidate)
        .into_iter()
        .map(|l| SideSource {
            data: l
                .rules
                .iter()
                .flat_map(|r| [r.as_str(), "\n"])
                .collect::<String>()
                .into_bytes(),
            list: l,
        })
        .collect()
}

/// A logged query from `ip`, logged with the `default` group (as an unknown device's is).
fn event(ts_us: u64, ip: [u8; 4], blocked: bool) -> QueryEvent {
    QueryEvent {
        ts_us,
        client_ip: std::net::Ipv4Addr::from(ip).to_ipv6_mapped().octets(),
        client_ref: 0,
        group: default_gid(),
        qtype: rtype::A,
        qclass: 1,
        rcode: Some(0),
        status: if blocked {
            Status::Blocked
        } else {
            Status::Forwarded
        },
        proto: Proto::Udp,
        flags: 0x8180,
        rule: None,
        upstream: 0,
        attempts: 1,
        t_total_us: 100,
        t_upstream_us: 50,
        resp_size: 64,
        answers: 1,
    }
}

fn default_gid() -> u16 {
    static G: std::sync::OnceLock<u16> = std::sync::OnceLock::new();
    *G.get_or_init(|| {
        let tmp = std::env::temp_dir();
        ClientTable::from_config(&load("", &tmp)).default_group_id()
    })
}

/// The node's part of a simulation once the changed lists' texts are in hand, as `local_part`
/// runs it: the one-at-a-time slot (`Err(busy)` when it's taken), then the replay.
fn run(inputs: Inputs) -> Result<Tally, Problem> {
    let slot = take_slot()?;
    run_holding(&slot, inputs)
}

/// [`run`] for a change to devices only.
fn run_devices_only(inputs: &Inputs) -> Result<Tally, Problem> {
    let slot = take_slot()?;
    devices_only_holding(&slot, inputs)
}

/// The sim tests share the node's one-at-a-time slot: one at a time with every test that may take
/// it (the API-level ones in `api_backend`'s tests too), so `run` here finds it free.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    super::slot_tests()
}

// REQ: OBS-024 — AC (1): a block rule for a name a device asked 40 times reports 40 newly
// blocked queries, one device, that name, and the rule as what decided; the queries of
// other names are unchanged.
#[test]
fn obs_024_a_block_rule_reports_what_it_would_have_blocked() {
    let _s = serial();
    let lab = Lab::new("");
    lab.log("tracker.example", 7, 40, t0_s(), false);
    lab.log("other.example", 8, 10, t0_s() - 100, false);

    for (extra, by) in [
        (
            "[[rule]]\nid = \"r1\"\naction = \"block\"\ndomain = \"tracker.example\"\n",
            "quick rule: tracker.example",
        ),
        (
            "[[list]]\nname = \"new\"\nrules = [\"||tracker.example^\"]\n",
            "new",
        ),
    ] {
        let t = lab.simulate(lab.candidate(extra));
        let s = t.clone().finish(None);
        assert_eq!(s.rows, 50, "{extra}");
        assert_eq!(s.newly_blocked.queries, 40, "{extra}");
        assert_eq!(s.newly_blocked.devices, 1, "{extra}");
        let top = &s.newly_blocked.top_names[0];
        assert_eq!(top.name, "tracker.example");
        assert_eq!(top.queries, 40);
        assert_eq!(top.list.as_deref(), Some(by));
        assert_eq!(s.unchanged, 10);
        assert_eq!(s.newly_allowed.queries + s.changed_route.queries, 0);
        assert_eq!(s.by_device[0].client, "10.0.0.7");
        assert_eq!(s.by_device[0].newly_blocked, 40);
        assert_eq!(s.by_group[0].group, "default");
    }
}

// REQ: OBS-024 — AC (1): an allow rule for a name that was blocked reports it as newly
// allowed with the list that had blocked it.
#[test]
fn obs_024_an_allow_rule_reports_what_it_would_have_let_through() {
    let _s = serial();
    let lab = Lab::new("");
    lab.log("ads.example", 7, 5, t0_s(), true);
    let t = lab.simulate(
        lab.candidate("[[list]]\nname = \"ok\"\nkind = \"allow\"\nrules = [\"ads.example\"]\n"),
    );
    let s = t.finish(None);
    assert_eq!(s.newly_allowed.queries, 5);
    assert_eq!(s.newly_allowed.top_names[0].list.as_deref(), Some("ads"));
    assert_eq!(s.newly_blocked.queries, 0);
}

// REQ: OBS-024 — AC (1): sending a group to another upstream group counts changed routes; a
// change that can't affect anything reports zeros.
#[test]
fn obs_024_route_changes_and_no_op_changes() {
    let _s = serial();
    let lab = Lab::new("");
    lab.log("www.example", 7, 12, t0_s(), false);
    lab.log("ads.example", 7, 3, t0_s() - 50, true);
    lab.log("www.example", 5, 4, t0_s() - 80, false);
    let routed = lab.simulate(
        lab.candidate("[[route]]\nmatch_group = [\"default\"]\nupstream_group = \"lan\"\n"),
    );
    let s = routed.finish(None);
    assert_eq!(
        s.changed_route.queries, 12,
        "the tablet is in kids; blocks stay blocks"
    );
    assert_eq!(
        s.changed_route.top_names[0].list.as_deref(),
        Some("default → lan")
    );
    assert_eq!(s.unchanged, 7);

    let same = lab.simulate(lab.candidate(""));
    let s = same.finish(None);
    assert_eq!(s.rows, 19);
    assert_eq!(s.unchanged, 19);
    assert_eq!(
        s.newly_blocked.queries
            + s.newly_allowed.queries
            + s.changed_route.queries
            + s.changed_answer.queries,
        0
    );
    assert_eq!(s.by_device, Vec::new());

    let alerts = lab.candidate("[alerts]\ninterval_secs = 120\n");
    assert_eq!(mode(&lab.current, &alerts), Mode::NotApplicable);
}

// REQ: DNS-019, OBS-024 (ADR-187) — the simulation decides `resolver.arpa` as the pipeline does:
// with `[special] resolver_arpa` turned off, the logged `_dns.resolver.arpa` queries are forwarded
// instead of answered here (a changed answer); the other names are unchanged.
#[test]
fn dns_019_turning_resolver_arpa_off_is_a_changed_answer() {
    let _s = serial();
    let lab = Lab::new("");
    lab.log("_dns.resolver.arpa", 7, 6, t0_s(), false);
    lab.log("www.example", 7, 4, t0_s() - 50, false);
    let s = lab
        .simulate(lab.candidate("[special]\nresolver_arpa = false\n"))
        .finish(None);
    assert_eq!(s.rows, 10);
    assert_eq!(s.changed_answer.queries, 6);
    assert_eq!(s.unchanged, 4);
    assert_eq!(
        s.newly_blocked.queries + s.newly_allowed.queries + s.changed_route.queries,
        0
    );
}

// REQ: DNS-019, UPS-007, OBS-024 (ADR-187) — the simulation forwards `resolver.arpa` as the
// pipeline does: only for a route for `resolver.arpa` (in any case) or a name below it, and for
// the route's group only when it names one (a changed answer). Any other route (a group's own
// upstreams, `match_group`, `match_qtype`, `.`, `arpa`) moves the device's other names to its
// upstream group (a changed route) and leaves `_dns.resolver.arpa` answered here (unchanged).
#[test]
fn dns_019_simulation_forwards_resolver_arpa_only_by_a_route_for_it_or_below() {
    let _s = serial();
    let lab = Lab::new("");
    // The tablet (10.0.0.5, in kids) and an unknown device (10.0.0.7).
    lab.log("_dns.resolver.arpa", 5, 6, t0_s(), false);
    lab.log("_dns.resolver.arpa", 7, 3, t0_s() - 20, false);
    lab.log("www.example", 5, 4, t0_s() - 40, false);
    lab.log("www.example", 7, 2, t0_s() - 60, false);
    lab.log("8.8.8.8.in-addr.arpa", 7, 1, t0_s() - 80, false);
    // (routes, changed answers, changed routes): of 6 + 3 `_dns.resolver.arpa`, 4 + 2
    // `www.example`, and the device's one public reverse lookup.
    let cases = [
        (
            "the group's own upstreams",
            "[[group]]\nname = \"tv\"\nupstreams = \"lan\"\n\
             [[client]]\nname = \"tv\"\nmatch = [\"10.0.0.7\"]\ngroups = [\"tv\"]\n",
            0,
            3,
        ),
        (
            "a match_group route",
            "[[route]]\nmatch_group = [\"kids\"]\nupstream_group = \"lan\"\n",
            0,
            4,
        ),
        (
            "a match_qtype route",
            "[[route]]\nmatch_qtype = [\"A\"]\nupstream_group = \"lan\"\n",
            0,
            7,
        ),
        (
            "a route for `.`",
            "[[route]]\nmatch_suffix = [\".\"]\nupstream_group = \"lan\"\n",
            0,
            7,
        ),
        (
            "a route for resolver.arpa",
            "[[route]]\nmatch_suffix = [\"Resolver.ARPA.\"]\nupstream_group = \"lan\"\n",
            9,
            0,
        ),
        (
            "a route for _dns.resolver.arpa",
            "[[route]]\nmatch_suffix = [\"_dns.resolver.arpa\"]\nupstream_group = \"lan\"\n",
            9,
            0,
        ),
        (
            "a route for arpa",
            "[[route]]\nmatch_suffix = [\"arpa\"]\nupstream_group = \"lan\"\n",
            0,
            1,
        ),
        (
            "a route for resolver.arpa and the group kids",
            "[[route]]\nmatch_suffix = [\"resolver.arpa\"]\nmatch_group = [\"kids\"]\nupstream_group = \"lan\"\n",
            6,
            0,
        ),
    ];
    let mut wrong = Vec::new();
    for (routes, extra, answers, moved) in cases {
        let s = lab.simulate(lab.candidate(extra)).finish(None);
        let got = (
            s.rows,
            s.changed_answer.queries,
            s.changed_route.queries,
            s.newly_blocked.queries + s.newly_allowed.queries,
        );
        if got != (16, answers, moved, 0) {
            wrong.push(format!(
                "{routes}: (rows, changed answers, changed routes, blocks) {got:?}, expected (16, {answers}, {moved}, 0)"
            ));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

// REQ: OBS-024 — AC (2): only lists the change adds or edits are compiled, into the side
// snapshot; the serving snapshot is untouched, and its old version of an edited (or
// removed) list no longer takes part.
#[test]
fn obs_024_only_changed_lists_are_compiled() {
    let _s = serial();
    let lab = Lab::new("");
    lab.log("ads.example", 7, 6, t0_s(), true);
    lab.log("more.example", 7, 4, t0_s() - 30, false);
    let before = lab.serving.snapshot().unwrap().manifest.clone();

    let added =
        lab.simulate(lab.candidate("[[list]]\nname = \"new\"\nrules = [\"||more.example^\"]\n"));
    assert_eq!(added.side_lists, vec!["new".to_owned()]);

    let edited = lab.current.as_ref().clone();
    let mut edited = edited;
    edited.list[0].rules.push("||more.example^".into());
    assert_eq!(
        changed_lists(&lab.current, &edited)
            .iter()
            .map(|l| l.name.to_string())
            .collect::<Vec<_>>(),
        vec!["ads".to_owned()]
    );
    let t = lab.simulate(edited);
    assert_eq!(t.side_lists, vec!["ads".to_owned()]);
    let s = t.finish(None);
    assert_eq!(s.newly_blocked.queries, 4, "the edited list's new rule");
    assert_eq!(
        s.newly_allowed.queries, 0,
        "its old rules still block, once"
    );

    let mut removed = lab.current.as_ref().clone();
    removed.list.remove(0);
    for g in &mut removed.group {
        if let Some(l) = &mut g.lists {
            l.retain(|n| n.as_str() != "ads");
        }
    }
    let t = lab.simulate(removed);
    assert_eq!(
        t.side_lists,
        Vec::<String>::new(),
        "removing compiles nothing"
    );
    let s = t.finish(None);
    assert_eq!(s.newly_allowed.queries, 6);
    assert_eq!(s.newly_allowed.top_names[0].list.as_deref(), Some("ads"));

    assert_eq!(
        lab.serving.snapshot().unwrap().manifest,
        before,
        "the serving snapshot isn't touched"
    );
    let snaps = lab.tmp.path().join("snapshots");
    let left = std::fs::read_dir(&snaps).map_or(0, Iterator::count);
    assert_eq!(left, 0, "side snapshots are removed");
}

// REQ: OBS-024 — AC (3): one simulation per node; `max_rows` stops at exactly that many rows,
// newest first; `max_secs` is honored.
#[test]
fn obs_024_bounds() {
    let _s = serial();
    let lab = Lab::new("");
    lab.log("old.example", 7, 4000, t0_s() - 2000, false);
    lab.log("new.example", 7, 1000, t0_s(), false);
    let block_new =
        lab.candidate("[[rule]]\nid = \"r\"\naction = \"block\"\ndomain = \"new.example\"\n");

    let held = BusyGuard::take().unwrap();
    let err = run(lab.inputs(block_new.clone(), Vec::new())).unwrap_err();
    assert_eq!(err.code, Code::SimulationBusy);
    assert_eq!(err.status, 409);
    drop(held);

    let mut i = lab.inputs(block_new.clone(), Vec::new());
    i.window.max_rows = 1000;
    let t = run(i).unwrap();
    assert!(t.partial);
    assert_eq!(t.rows, 1000);
    assert_eq!(
        t.classes[0].queries, 1000,
        "the newest 1,000 rows, all new.example"
    );

    // Slow labels (one per device) stand in for a big log.
    let lab2 = Lab::new("");
    {
        let mut b = Builder::spawn(Settings {
            dir: lab2.qlog(),
            node: 1,
            privacy: 0,
            flush_interval: Duration::from_secs(3600),
            fsync: false,
            retention_days: 30,
            retention_bytes: u64::MAX,
            rotate_after: None,
        })
        .unwrap();
        let wire = NameBuf::from_presentation("x.example").unwrap();
        for i in 0..4000u64 {
            let ip = [
                10,
                1,
                u8::try_from(i / 250).unwrap(),
                u8::try_from(i % 250).unwrap(),
            ];
            b.push(&event((t0_s() - i) * 1_000_000, ip, false), wire.as_wire());
        }
    }
    // Every row changes (a block for the name), so every device gets its label.
    let block_x = "[[rule]]\nid = \"x\"\naction = \"block\"\ndomain = \"x.example\"\n";
    let mut i = lab2.inputs(lab2.candidate(block_x), Vec::new());
    i.window.max_secs = 1;
    i.label = Box::new(|_| {
        std::thread::sleep(Duration::from_millis(3));
        None
    });
    let started = Instant::now();
    let t = run(i).unwrap();
    assert!(t.partial);
    assert!(t.rows < 4000);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );

    let w = window(&lab.current.simulate, Some("8d"), None, t0_s()).unwrap_err();
    assert_eq!(w.code, Code::SimulationWindow);
    assert_eq!(w.status, 422);
    assert!(window(&lab.current.simulate, Some("soon"), None, t0_s()).is_err());
    let w = window(&lab.current.simulate, None, Some(t0_s()), t0_s() + 99).unwrap();
    assert_eq!(w.to_us, t0_s() * 1_000_000);
    assert_eq!(w.from_us, (t0_s() - 86_400) * 1_000_000);
}

// REQ: OBS-024 (T13.1) — issue #69: the window `[from, to)` ends at the END of the request's own
// second unless the request names an end, so what was logged a moment ago is replayed (a window
// ending at the start of that second, which it did before, left out every row of the second the
// request arrived in). A named `until` stays exact; the window keeps its length.
#[test]
fn obs_024_the_current_second_is_replayed() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = load("", tmp.path());
    let w = window(&cfg.simulate, None, None, t0_s()).unwrap();
    let inside = |ts_us: u64| w.from_us <= ts_us && ts_us < w.to_us;

    let now_us = t0_s() * 1_000_000;
    assert!(
        inside(now_us + 400_000),
        "{w:?}: a row 0.4 s into the request's second"
    );
    assert!(
        inside(now_us + 999_999),
        "{w:?}: the last microsecond of that second"
    );
    assert!(
        !inside(now_us + 1_000_000),
        "{w:?}: the next second is later than the request"
    );
    assert_eq!(w.to_us, now_us + 1_000_000);
    assert_eq!(
        w.to_us - w.from_us,
        86_400 * 1_000_000,
        "still the default 24 hours"
    );
    assert!(
        !inside(now_us - 86_401 * 1_000_000),
        "{w:?}: a row 24 hours and 1 second before the request"
    );

    let w = window(&cfg.simulate, None, Some(t0_s()), t0_s() + 99).unwrap();
    assert_eq!(w.to_us, now_us, "a named `until` is exact");
    assert_eq!(w.from_us, (t0_s() - 86_400) * 1_000_000);
}

// REQ: OBS-024 (T13.1) — issue #69, through the real query log: one query logged 0.4 s into the
// request's second is counted by a simulation over the default window (no hand-built window, no
// real clock). It is what the UI's `obs_024` end-to-end test depends on: it sends queries, then asks
// for the simulation about a second later, which is the same second in a few percent of runs.
#[test]
fn obs_024_a_row_in_the_requests_own_second_is_counted() {
    let _s = serial();
    let lab = Lab::new("");
    lab.log_at("tracker.example", 7, t0_s() * 1_000_000 + 400_000, false);
    let block =
        lab.candidate("[[rule]]\nid = \"r\"\naction = \"block\"\ndomain = \"tracker.example\"\n");
    let mut i = lab.inputs(block, Vec::new());
    i.window = window(&lab.current.simulate, None, None, t0_s()).unwrap();
    let t = run(i).unwrap();
    assert_eq!(t.rows, 1, "the row in the request's own second");
    assert_eq!(t.classes[0].queries, 1, "newly blocked");
}

// REQ: OBS-024 — AC (4): privacy level 1 can't replay names; a change to devices only still
// gets an answer (unchanged when the new group decides alike, else undetermined).
#[test]
fn obs_024_privacy_level_1() {
    let _s = serial();
    let mut lab = Lab::new("[telemetry.qlog]\nprivacy_level = 1\n");
    lab.log("www.example", 5, 9, t0_s(), false);
    lab.log("www.example", 7, 2, t0_s() - 30, false);
    let list = lab.candidate(
        "[telemetry.qlog]\nprivacy_level = 1\n[[list]]\nname = \"n\"\nrules = [\"x.example\"]\n",
    );
    assert_eq!(
        mode(&lab.current, &list),
        Mode::Unavailable("privacy_level")
    );

    let mut alike = lab.current.as_ref().clone();
    alike.client[0].groups = vec!["teens".into()];
    assert_eq!(mode(&lab.current, &alike), Mode::DevicesOnly);
    let t = run_devices_only(&lab.inputs(alike, Vec::new())).unwrap();
    assert_eq!((t.unchanged, t.undetermined), (11, 0));

    let mut stricter = lab.current.as_ref().clone();
    stricter.client[0].groups = vec!["strict".into()];
    let t = run_devices_only(&lab.inputs(stricter, Vec::new())).unwrap();
    assert_eq!((t.unchanged, t.undetermined), (2, 9));
    let s = t.finish(None);
    assert!(s.notes.contains(&"privacy_level_1_devices_only".to_owned()));

    Arc::make_mut(&mut lab.current).telemetry.qlog.privacy_level = 2;
    let mut any = lab.current.as_ref().clone();
    any.client[0].groups = vec!["teens".into()];
    assert_eq!(mode(&lab.current, &any), Mode::Unavailable("privacy_level"));
    Arc::make_mut(&mut lab.current).simulate.enabled = false;
    assert_eq!(mode(&lab.current, &any), Mode::Unavailable("disabled"));
}

// REQ: OBS-024 — AC (6): the same log gives the same bytes; nodes' tallies merge into what
// one node holding every row would have found (the federation's sum).
#[test]
fn obs_024_deterministic_and_mergeable() {
    let _s = serial();
    let lab = Lab::new("");
    for (i, name) in ["a.example", "b.example", "c.example", "ads.example"]
        .iter()
        .enumerate()
    {
        let i = u8::try_from(i).unwrap();
        lab.log(
            name,
            10 + i,
            7,
            t0_s() - u64::from(i) * 10,
            *name == "ads.example",
        );
    }
    let cand = || {
        lab.candidate(
            "[[list]]\nname = \"n\"\nrules = [\"||a.example^\", \"||b.example^\"]\n\
             [[list]]\nname = \"ok\"\nkind = \"allow\"\nrules = [\"ads.example\"]\n",
        )
    };
    let one = serde_json::to_vec(&lab.simulate(cand()).finish(None)).unwrap();
    let two = serde_json::to_vec(&lab.simulate(cand()).finish(None)).unwrap();
    assert_eq!(one, two);

    // The same rows split over two nodes' logs.
    let other = tempfile::tempdir().unwrap();
    {
        let mut b = Builder::spawn(Settings {
            dir: other.path().to_owned(),
            node: 2,
            privacy: 0,
            flush_interval: Duration::from_secs(3600),
            fsync: false,
            retention_days: 30,
            retention_bytes: u64::MAX,
            rotate_after: None,
        })
        .unwrap();
        let wire = NameBuf::from_presentation("a.example").unwrap();
        for i in 0..5 {
            b.push(
                &event((t0_s() - 500 - i) * 1_000_000, [10, 0, 0, 20], false),
                wire.as_wire(),
            );
        }
    }
    let mut merged = lab.simulate(cand());
    let mut i = lab.inputs(cand(), inline_sources(&lab.current, &cand()));
    i.dirs = vec![other.path().to_owned()];
    merged.merge(run(i).unwrap());
    let mut i = lab.inputs(cand(), inline_sources(&lab.current, &cand()));
    i.dirs.push(other.path().to_owned());
    let both = run(i).unwrap();
    assert_eq!(merged.finish(None), both.finish(None));
}
