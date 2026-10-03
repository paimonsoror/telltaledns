//! T3.2 acceptance measurement: query-log search over a 50M-row synthetic dataset
//! (AC: ≤ 2 s on a Pi 4).
//!
//!   `qlog_bench gen <dir> [rows] [hours] [threads]`  write segments (default 50M rows, 720 h)
//!   `qlog_bench search <dir> [threads]`               run the query suite twice, print times
//!
//! Rows look like a home network: 40 clients with Zipf activity, names drawn Zipf from 20k
//! popular domains plus 15% one-off tracking subdomains, a realistic type/status/latency mix,
//! and 20 rows of `needle.example.org` spread over the whole range.

// A benchmark tool, not a runtime path: printing and panicking on setup errors are fine.
#![allow(
    clippy::print_stdout,
    clippy::expect_used,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

use std::path::Path;
use std::time::Instant;

use telltale_store::qlog::{self, Filter, NameMatch, segment_path, writer};
use telltale_telemetry::{Proto, QueryEvent, Status};

const HOUR_US: u64 = 3_600_000_000;
/// First hour of the dataset (2026-09-03 00:00 UTC).
const START_HOUR: u64 = 20_699 * 24;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn unit(&mut self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let x = (self.next() >> 11) as f64 / (1u64 << 53) as f64;
        x
    }
    /// Zipf(s=1)-ish over 0..n via inverse power sampling.
    fn zipf(&mut self, n: u64) -> u64 {
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let i = ((n as f64).powf(self.unit()) as u64).saturating_sub(1);
        i.min(n - 1)
    }
}

fn wire(name: &str) -> Vec<u8> {
    let mut w = Vec::new();
    for l in name.split('.') {
        w.push(u8::try_from(l.len()).unwrap_or(0));
        w.extend_from_slice(l.as_bytes());
    }
    w.push(0);
    w
}

const TLDS: [&str; 5] = ["com", "net", "org", "io", "co.uk"];

fn row(rng: &mut Rng, ts_us: u64, needle: bool) -> (QueryEvent, Vec<u8>) {
    let client = u8::try_from(rng.zipf(40) + 10).unwrap_or(10);
    let name = if needle {
        "needle.example.org".to_owned()
    } else if rng.below(100) < 15 {
        format!(
            "{:012x}.cdn{}.tracker{}.net",
            rng.next() & 0xFFFF_FFFF_FFFF,
            rng.below(20),
            rng.below(300)
        )
    } else {
        let d = rng.zipf(20_000);
        let sub = ["www", "api", "static", "img", "m"][usize::try_from(d % 5).unwrap_or(0)];
        format!(
            "{sub}.domain{d}.{}",
            TLDS[usize::try_from(d % 5).unwrap_or(0)]
        )
    };
    let p = rng.below(1000);
    let qtype = match p {
        0..600 => 1,
        600..900 => 28,
        900..980 => 65,
        980..995 => 12,
        _ => 16,
    };
    let s = rng.below(100);
    let status = match s {
        0..65 => Status::Cached,
        65..90 => Status::Forwarded,
        90..98 => Status::Blocked,
        98 => Status::Local,
        _ => Status::Special,
    };
    let total = match status {
        Status::Forwarded if rng.below(10_000) == 0 => 1_000_000 + rng.below(2_000_000),
        Status::Forwarded => 5_000 + rng.below(75_000),
        _ => 20 + rng.below(80),
    };
    let ev = QueryEvent {
        ts_us,
        client_ip: std::net::Ipv4Addr::new(192, 168, 1, client)
            .to_ipv6_mapped()
            .octets(),
        client_ref: u32::from(client % 12),
        group: u16::from(client % 3),
        qtype,
        qclass: 1,
        rcode: Some(if rng.below(100) < 5 { 3 } else { 0 }),
        status,
        proto: Proto::Udp,
        flags: 0x8180,
        rule: None,
        upstream: if status == Status::Forwarded {
            1 + u16::try_from(rng.below(2)).unwrap_or(0)
        } else {
            0
        },
        attempts: u8::from(status == Status::Forwarded),
        t_total_us: u32::try_from(total).unwrap_or(u32::MAX),
        t_upstream_us: if status == Status::Forwarded {
            u32::try_from(total).unwrap_or(0) - 10
        } else {
            0
        },
        resp_size: 60 + u16::try_from(rng.below(200)).unwrap_or(0),
        answers: 1,
    };
    (ev, wire(&name))
}

fn generate(dir: &Path, rows: u64, hours: u64, threads: u64) {
    let per_hour = rows / hours;
    let t = Instant::now();
    let total_bytes = std::sync::atomic::AtomicU64::new(0);
    std::thread::scope(|s| {
        for w in 0..threads {
            let total_bytes = &total_bytes;
            s.spawn(move || {
                for h in (w..hours).step_by(usize::try_from(threads).unwrap_or(1)) {
                    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (h + 1).wrapping_mul(0xBF58_476D));
                    let hour = START_HOUR + h;
                    let mut v: Vec<(QueryEvent, Vec<u8>)> = (0..per_hour)
                        .map(|i| {
                            let ts = hour * HOUR_US + i * (HOUR_US / per_hour);
                            // 20 needles spread over the range.
                            let needle = i == 7 && h % (hours / 20).max(1) == 0;
                            row(&mut rng, ts, needle)
                        })
                        .collect();
                    v.sort_by_key(|(e, _)| e.ts_us);
                    let bytes = writer::encode_in_memory(&v, hour).expect("encode");
                    let path = segment_path(dir, hour, 0, 0);
                    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
                    std::fs::write(&path, &bytes).expect("write");
                    total_bytes.fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
                }
            });
        }
    });
    let bytes = total_bytes.into_inner();
    #[allow(clippy::cast_precision_loss)]
    let per_row = bytes as f64 / (per_hour * hours) as f64;
    println!(
        "generated {} rows in {hours} segments: {:.1} MiB ({per_row:.1} B/row) in {:.1?}",
        per_hour * hours,
        bytes as f64 / f64::from(1u32 << 20),
        t.elapsed()
    );
}

fn suite(dir: &Path, threads: usize) {
    let opts = qlog::Options {
        threads,
        on_thread_start: None,
    };
    println!("search threads: {threads}");
    let last = (START_HOUR + 720) * HOUR_US;
    let ip = |x: u8| {
        std::net::Ipv4Addr::new(192, 168, 1, x)
            .to_ipv6_mapped()
            .octets()
    };
    let cases: Vec<(&str, Filter, usize)> = vec![
        ("newest 100, no filter", Filter::default(), 100),
        (
            "exact rare name (20 rows in 30 days)",
            Filter {
                name: Some(NameMatch::Exact("needle.example.org".into())),
                ..Filter::default()
            },
            1000,
        ),
        (
            "substring rare (dictionary scan)",
            Filter {
                name: Some(NameMatch::Substring("eedle.exa".into())),
                ..Filter::default()
            },
            1000,
        ),
        (
            "regex, common, newest 100",
            Filter {
                name: Some(NameMatch::Regex(r"^[0-9a-f]{12}\.cdn1\.".into())),
                ..Filter::default()
            },
            100,
        ),
        (
            "client + blocked, newest 1000",
            Filter {
                client_ip: Some(ip(37)),
                status: vec![Status::Blocked],
                ..Filter::default()
            },
            1000,
        ),
        (
            "qtype SRV: no matches, full column scan",
            Filter {
                qtype: vec![33],
                ..Filter::default()
            },
            1000,
        ),
        (
            "latency >= 1 s (block maxima prune)",
            Filter {
                min_total_us: Some(1_000_000),
                ..Filter::default()
            },
            1000,
        ),
        (
            "last 2 h, forwarded >= 50 ms",
            Filter {
                from_us: last - 2 * HOUR_US,
                status: vec![Status::Forwarded],
                min_total_us: Some(50_000),
                ..Filter::default()
            },
            1000,
        ),
    ];
    for round in 1..=2 {
        println!("round {round}:");
        for (label, f, limit) in &cases {
            let t = Instant::now();
            let page = qlog::search_with(dir, f, *limit, None, &opts).expect("search");
            let s = page.stats;
            println!(
                "  {:<42} {:>8.3} s  rows {:>5}  segments {:>3}  blocks read {:>5}/{:<5}  rows scanned {:>9}",
                label,
                t.elapsed().as_secs_f64(),
                page.rows.len(),
                s.segments,
                s.blocks_read,
                s.blocks_total,
                s.rows_scanned
            );
        }
    }
}

/// Where a full pass over the dataset spends its time, stage by stage.
fn phases(dir: &Path) {
    use telltale_store::qlog::format::{COLUMNS, Col};
    use telltale_store::qlog::reader::{Columns, Segment};
    let t = Instant::now();
    let segs = qlog::list_segments(dir).expect("list");
    println!("list {} segments: {:?}", segs.len(), t.elapsed());
    let t = Instant::now();
    let mut opened: Vec<Segment> = segs
        .iter()
        .map(|(_, p)| Segment::open(p).expect("open"))
        .collect();
    let blocks: usize = opened.iter().map(|s| s.blocks.len()).sum();
    println!("open (footers, {blocks} block headers): {:?}", t.elapsed());
    let t = Instant::now();
    let mut names = 0;
    let dicts: Vec<_> = opened
        .iter_mut()
        .map(|s| s.dictionary().expect("dict"))
        .collect();
    for d in &dicts {
        names += d.name_count();
    }
    println!("dictionaries ({names} names): {:?}", t.elapsed());
    let t = Instant::now();
    let finder = memchr::memmem::Finder::new(b"eedle");
    let mut buf = Vec::new();
    let mut hits = 0;
    for d in &dicts {
        for n in d.names() {
            buf.clear();
            buf.extend_from_slice(n);
            hits += usize::from(finder.find(&buf).is_some());
        }
    }
    println!("substring over every name: {:?} ({hits} hits)", t.elapsed());
    let t = Instant::now();
    let mut rows = 0;
    for s in &mut opened {
        for i in 0..s.blocks.len() {
            let mut c = Columns::new(s.blocks[i].1.rows as usize);
            s.load(i, &mut c, &[Col::Qtype]).expect("load");
            rows += c.rows;
        }
    }
    println!("one column of every block ({rows} rows): {:?}", t.elapsed());
    let _ = COLUMNS;
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = Path::new(args.get(2).map_or("/tmp/qlog-bench", String::as_str));
    match args.get(1).map(String::as_str) {
        Some("gen") => {
            let num = |i: usize, d: u64| args.get(i).and_then(|v| v.parse().ok()).unwrap_or(d);
            generate(dir, num(3, 50_000_000), num(4, 720), num(5, 4));
        }
        Some("search") => suite(dir, args.get(3).and_then(|v| v.parse().ok()).unwrap_or(1)),
        Some("phases") => phases(dir),
        _ => eprintln!("usage: qlog_bench gen <dir> [rows] [hours] [threads] | search <dir>"),
    }
}
