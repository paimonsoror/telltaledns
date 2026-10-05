use std::path::Path;
use std::time::Duration;

use telltale_telemetry::{Proto, QueryEvent, Rule, RuleKind, Status};

use super::format::{BLOCK_HEADER, HEADER_LEN};
use super::*;

const HOUR_US: u64 = 3_600_000_000;
/// 2026-10-03 00:00 UTC, in hours.
const BASE_HOUR: u64 = 20_729 * 24;

fn wire(name: &str) -> Vec<u8> {
    let mut w = Vec::new();
    for l in name.split('.').filter(|l| !l.is_empty()) {
        w.push(u8::try_from(l.len()).unwrap());
        w.extend_from_slice(l.as_bytes());
    }
    w.push(0);
    w
}

fn ip(last: u8) -> [u8; 16] {
    std::net::Ipv4Addr::new(192, 168, 1, last)
        .to_ipv6_mapped()
        .octets()
}

fn ev(ts_us: u64, client: u8, status: Status, total_us: u32) -> QueryEvent {
    QueryEvent {
        ts_us,
        client_ip: ip(client),
        client_ref: u32::from(client),
        group: u16::from(client % 3),
        qtype: if client.is_multiple_of(2) { 1 } else { 28 },
        qclass: 1,
        rcode: Some(if status == Status::Blocked { 0 } else { 3 }),
        status,
        proto: Proto::Udp,
        flags: 0x8180,
        rule: (status == Status::Blocked).then_some(Rule {
            list: 4,
            kind: RuleKind::Regex,
            allow: false,
        }),
        upstream: 2,
        attempts: 1,
        t_total_us: total_us,
        t_upstream_us: total_us / 2,
        resp_size: 99,
        answers: 1,
    }
}

fn settings(dir: &Path, privacy: u8) -> Settings {
    Settings {
        dir: dir.to_owned(),
        node: 7,
        privacy,
        flush_interval: Duration::from_secs(3600),
        fsync: false,
        retention_days: 30,
        retention_bytes: u64::MAX,
        rotate_after: None,
    }
}

// REQ: CLU-007 — ship mode closes parts on a timer, so they can be shipped; every row is
// still found across the parts.
#[test]
fn clu_007_rotate_after_closes_parts_on_a_timer() {
    let tmp = tempfile::tempdir().unwrap();
    let mut s = settings(tmp.path(), 0);
    s.rotate_after = Some(Duration::ZERO);
    let mut b = Builder::spawn(s).unwrap();
    for i in 0..3u64 {
        b.push(
            &ev(BASE_HOUR * HOUR_US + i, 1, Status::Forwarded, 100),
            &wire("a.example"),
        );
    }
    drop(b);
    let segs = super::list_segments(tmp.path()).unwrap();
    assert_eq!(segs.len(), 3, "one part per push with a zero interval");
    assert_eq!(all(tmp.path(), &Filter::default()).len(), 3);
}

/// Writes `n` rows per hour for `hours` hours: names cycle through 1000 domains, every 10th
/// row is blocked, clients cycle 1..=20.
fn populate(dir: &Path, privacy: u8, hours: u64, n: u64) {
    let mut b = Builder::spawn(settings(dir, privacy)).unwrap();
    for h in 0..hours {
        for i in 0..n {
            let ts = (BASE_HOUR + h) * HOUR_US + i * (HOUR_US / n);
            let status = if i % 10 == 0 {
                Status::Blocked
            } else {
                Status::Forwarded
            };
            let client = u8::try_from(i % 20).unwrap() + 1;
            let name = format!("www.site{}.example", i % 1000);
            b.push(
                &ev(ts, client, status, u32::try_from(i % 5000).unwrap()),
                &wire(&name),
            );
        }
    }
    let stats = b.stats();
    drop(b); // flushes and writes footers
    assert_eq!(
        stats
            .rows_written
            .load(std::sync::atomic::Ordering::Relaxed),
        hours * n
    );
}

fn all(dir: &Path, f: &Filter) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut cursor = None;
    loop {
        let page = search(dir, f, 1000, cursor).unwrap();
        rows.extend(page.rows);
        match page.next {
            Some(c) => cursor = Some(c),
            None => return rows,
        }
    }
}

#[test]
fn obs_003_written_rows_come_back_newest_first_with_every_field() {
    let tmp = tempfile::tempdir().unwrap();
    populate(tmp.path(), 0, 2, 20_000);
    let page = search(tmp.path(), &Filter::default(), 3, None).unwrap();
    assert_eq!(page.rows.len(), 3);
    assert!(page.rows[0].ts_us > page.rows[1].ts_us, "newest first");
    let r = &page.rows[0];
    let i = 19_999u64;
    assert_eq!(r.name, format!("www.site{}.example", i % 1000));
    assert_eq!(r.ts_us, (BASE_HOUR + 1) * HOUR_US + i * (HOUR_US / 20_000));
    assert_eq!((r.node, r.client_ip, r.client_ref), (7, ip(20), 20));
    assert_eq!(
        (r.qtype, r.qclass, r.rcode, r.status),
        (1, 1, Some(3), Status::Forwarded)
    );
    assert_eq!(
        (r.upstream, r.attempts, r.resp_size, r.answers, r.flags),
        (2, 1, 99, 1, 0x8180)
    );
    assert_eq!((r.t_total_us, r.t_upstream_us), (4999, 2499));
    // Every row, across both hours and many blocks, exactly once.
    let rows = all(tmp.path(), &Filter::default());
    assert_eq!(rows.len(), 40_000);
    assert!(rows.windows(2).all(|w| w[0].ts_us >= w[1].ts_us));
    let blocked = rows.iter().find(|r| r.status == Status::Blocked).unwrap();
    assert_eq!(
        blocked.rule,
        Some(Rule {
            list: 4,
            kind: RuleKind::Regex,
            allow: false
        })
    );
}

#[test]
fn obs_003_filters_match_exactly_what_a_scan_would() {
    let tmp = tempfile::tempdir().unwrap();
    populate(tmp.path(), 0, 2, 20_000);
    let every = all(tmp.path(), &Filter::default());
    let check = |f: Filter, pred: &dyn Fn(&Row) -> bool| {
        let got = all(tmp.path(), &f);
        let want: Vec<&Row> = every.iter().filter(|r| pred(r)).collect();
        assert_eq!(got.len(), want.len(), "{f:?}");
        assert!(got.iter().zip(&want).all(|(a, b)| a == *b), "{f:?}");
        got.len()
    };
    let n = check(
        Filter {
            name: Some(NameMatch::Exact("www.site42.example".into())),
            ..Filter::default()
        },
        &|r| r.name == "www.site42.example",
    );
    assert_eq!(n, 40);
    check(
        Filter {
            name: Some(NameMatch::Substring("site99".into())),
            ..Filter::default()
        },
        &|r| r.name.contains("site99"),
    );
    check(
        Filter {
            name: Some(NameMatch::Suffix("site7.example".into())),
            ..Filter::default()
        },
        &|r| r.name.ends_with("site7.example"),
    );
    check(
        Filter {
            name: Some(NameMatch::Glob("www.site1?.example".into())),
            ..Filter::default()
        },
        &|r| r.name.len() == 18 && r.name.starts_with("www.site1"),
    );
    check(
        Filter {
            name: Some(NameMatch::Regex(r"^www\.site(5|6)00\.".into())),
            ..Filter::default()
        },
        &|r| r.name == "www.site500.example" || r.name == "www.site600.example",
    );
    check(
        Filter {
            client_ip: Some(ip(3)),
            status: vec![Status::Blocked],
            ..Filter::default()
        },
        &|r| r.client_ip == ip(3) && r.status == Status::Blocked,
    );
    check(
        Filter {
            qtype: vec![28],
            rcode: vec![3],
            min_total_us: Some(4990),
            ..Filter::default()
        },
        &|r| r.qtype == 28 && r.rcode == Some(3) && r.t_total_us >= 4990,
    );
    let from = BASE_HOUR * HOUR_US + HOUR_US / 2;
    let to = (BASE_HOUR + 1) * HOUR_US + HOUR_US / 4;
    check(
        Filter {
            from_us: from,
            to_us: to,
            group: Some(1),
            ..Filter::default()
        },
        &|r| r.ts_us >= from && r.ts_us < to && r.group == 1,
    );
    // Nothing matches: every segment is skipped after its dictionary.
    let page = search(
        tmp.path(),
        &Filter {
            name: Some(NameMatch::Substring("nope".into())),
            ..Filter::default()
        },
        10,
        None,
    )
    .unwrap();
    assert_eq!((page.rows.len(), page.stats.blocks_read), (0, 0));
}

#[test]
fn obs_003_rare_names_skip_blocks_by_bloom() {
    let tmp = tempfile::tempdir().unwrap();
    let mut b = Builder::spawn(settings(tmp.path(), 0)).unwrap();
    for i in 0..50_000u64 {
        let name = if i == 31_337 {
            "rare.example".to_owned()
        } else {
            format!("n{}.example", i % 500)
        };
        b.push(
            &ev(BASE_HOUR * HOUR_US + i, 1, Status::Cached, 5),
            &wire(&name),
        );
    }
    drop(b);
    let page = search(
        tmp.path(),
        &Filter {
            name: Some(NameMatch::Exact("rare.example".into())),
            ..Filter::default()
        },
        10,
        None,
    )
    .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert!(page.stats.blocks_total >= 6);
    assert!(page.stats.blocks_read <= 2, "{:?}", page.stats);
}

#[test]
fn obs_003_paging_with_cursors_covers_every_row_once() {
    let tmp = tempfile::tempdir().unwrap();
    populate(tmp.path(), 0, 3, 5_000);
    let f = Filter {
        status: vec![Status::Blocked],
        ..Filter::default()
    };
    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let page = search(tmp.path(), &f, 333, cursor).unwrap();
        seen.extend(page.rows.iter().map(|r| r.ts_us));
        let Some(c) = page.next else { break };
        assert_eq!(Cursor::decode(&c.encode()), Some(c));
        cursor = Some(c);
    }
    assert_eq!(seen.len(), 1500);
    let mut dedup = seen.clone();
    dedup.dedup();
    assert_eq!(dedup.len(), 1500, "no row twice");
    assert_eq!(Cursor::decode("1.2.3"), None);
}

#[test]
fn obs_003_privacy_levels() {
    let tmp = tempfile::tempdir().unwrap();
    populate(tmp.path(), 1, 1, 1000);
    let rows = all(tmp.path(), &Filter::default());
    assert_eq!(rows.len(), 1000);
    assert!(
        rows.iter()
            .all(|r| r.name.starts_with('h') && !r.name.contains("site"))
    );
    assert_eq!(
        rows.iter().filter(|r| r.client_ref == 3).count(),
        50,
        "clients kept"
    );
    // The same name hashes the same way, so grouping still works.
    let names: std::collections::HashSet<_> = rows.iter().map(|r| r.name.clone()).collect();
    assert_eq!(names.len(), 1000);

    let tmp = tempfile::tempdir().unwrap();
    populate(tmp.path(), 2, 1, 1000);
    let rows = all(tmp.path(), &Filter::default());
    assert!(
        rows.iter()
            .all(|r| r.client_ip == [0; 16] && r.client_ref == 0)
    );

    let tmp = tempfile::tempdir().unwrap();
    let mut b = Builder::spawn(settings(tmp.path(), 3)).unwrap();
    b.push(
        &ev(BASE_HOUR * HOUR_US, 1, Status::Cached, 5),
        &wire("a.example"),
    );
    drop(b);
    assert!(
        list_segments(tmp.path()).unwrap().is_empty(),
        "level 3 logs nothing"
    );
}

#[test]
fn obs_003_unfinished_and_damaged_segments_are_still_readable() {
    let tmp = tempfile::tempdir().unwrap();
    populate(tmp.path(), 0, 1, 20_000);
    let (_, path) = list_segments(tmp.path()).unwrap().pop().unwrap();
    let full = std::fs::read(&path).unwrap();
    let (d, rows) = reader::read_all(&full).unwrap();
    assert_eq!((rows, d.name_count()), (20_000, 1000));

    // Footer missing (crash before the hour ended): blocks are found by walking.
    let seg = reader::Segment::open(&path).unwrap();
    let footer_at = seg
        .blocks
        .last()
        .map(|(o, h)| *o + BLOCK_HEADER as u64 + u64::from(h.body_len))
        .unwrap();
    let cut = &full[..usize::try_from(footer_at).unwrap()];
    assert_eq!(reader::read_all(cut).unwrap().1, 20_000);

    // Cut in the middle of the last block: the earlier blocks survive.
    let mid = &full[..usize::try_from(footer_at).unwrap() - 100];
    let (_, survived) = reader::read_all(mid).unwrap();
    assert!(
        survived > 0 && survived < 20_000 && survived % 8192 == 0,
        "{survived}"
    );

    // A flipped byte in a block body fails its checksum, never panics.
    let mut bad = full.clone();
    bad[HEADER_LEN + BLOCK_HEADER + 10] ^= 0xFF;
    assert!(reader::read_all(&bad).is_none());
    std::fs::write(&path, &bad).unwrap();
    assert!(search(tmp.path(), &Filter::default(), 10, None).is_err());
}

#[test]
fn obs_003_retention_by_age_and_size() {
    let tmp = tempfile::tempdir().unwrap();
    populate(tmp.path(), 0, 5, 2000);
    assert_eq!(list_segments(tmp.path()).unwrap().len(), 5);
    // Age: keep the last 2 days' worth relative to "now" = 3 days after the first hour.
    let now = BASE_HOUR + 3 * 24;
    assert_eq!(
        retention::enforce(tmp.path(), now, 2, u64::MAX, None).unwrap(),
        5
    );
    assert_eq!(list_segments(tmp.path()).unwrap().len(), 0);
    assert!(
        std::fs::read_dir(tmp.path()).unwrap().next().is_none(),
        "empty dirs removed"
    );

    populate(tmp.path(), 0, 5, 2000);
    let sizes: Vec<u64> = {
        let mut s = list_segments(tmp.path()).unwrap();
        s.sort();
        s.iter()
            .map(|(_, p)| std::fs::metadata(p).unwrap().len())
            .collect()
    };
    let budget = sizes[3] + sizes[4];
    assert_eq!(
        retention::enforce(tmp.path(), BASE_HOUR, 30, budget, None).unwrap(),
        3
    );
    let mut left = list_segments(tmp.path()).unwrap();
    left.sort();
    assert_eq!(
        left.iter()
            .map(|(id, _)| id.hour - BASE_HOUR)
            .collect::<Vec<_>>(),
        [3, 4]
    );
}

#[test]
fn obs_003_segment_paths_round_trip() {
    for hour in [0u64, BASE_HOUR, BASE_HOUR + 23, 400_000, 1_000_000] {
        let p = segment_path(Path::new("q"), hour, 3, 2);
        let s = p.to_string_lossy().replace('\\', "/");
        let parts: Vec<&str> = s.split('/').collect();
        let days = u64::try_from(days_from_civil(
            parts[1].parse().unwrap(),
            parts[2].parse().unwrap(),
            parts[3].parse().unwrap(),
        ))
        .unwrap();
        assert_eq!(
            parse_id(days * 24, parts[4]),
            Some(SegmentId {
                hour,
                node: 3,
                part: 2
            })
        );
    }
    assert!(segment_path(Path::new("q"), BASE_HOUR, 7, 0).ends_with("2026/10/03/00-7-0.seg"));
}

/// Parallel waves return exactly what one thread does, in order, across pages.
#[test]
fn obs_003_parallel_search_matches_sequential() {
    let tmp = tempfile::tempdir().unwrap();
    populate(tmp.path(), 0, 5, 4_000);
    let filters = [
        Filter::default(),
        Filter {
            status: vec![Status::Blocked],
            ..Filter::default()
        },
        Filter {
            name: Some(NameMatch::Substring("site1".into())),
            client_ip: Some(ip(5)),
            ..Filter::default()
        },
    ];
    for f in &filters {
        let seq = all(tmp.path(), f);
        for threads in [2, 3, 8] {
            let opts = Options {
                threads,
                on_thread_start: None,
            };
            // Tiny pages only where there are few rows (each page is a search).
            let limits: &[usize] = if seq.len() < 1000 {
                &[1, 7, 5000]
            } else {
                &[777, 5000]
            };
            for &limit in limits {
                let mut got = Vec::new();
                let mut cursor = None;
                loop {
                    let page = search_with(tmp.path(), f, limit, cursor, &opts).unwrap();
                    assert!(page.rows.len() <= limit);
                    got.extend(page.rows);
                    match page.next {
                        Some(c) => cursor = Some(c),
                        None => break,
                    }
                }
                assert_eq!(
                    got.len(),
                    seq.len(),
                    "{f:?} threads {threads} limit {limit}"
                );
                assert!(got == seq, "{f:?} threads {threads} limit {limit}");
            }
        }
    }
}
