//! T2.3 acceptance measurement: bytes per name and compile time (`spec/10` T2.3,
//! `00` §5: ≤ 12 B/domain, ≤ 8 s on a Pi 4 for 1.5–2M domains).
//!
//!   `cargo run --profile bench-fast -p telltale-filter --example compile_bench -- synthetic 1500000 [threads]`
//!   `cargo run --profile bench-fast -p telltale-filter --example compile_bench -- dir bench/lists [threads]`
//!
//! `synthetic` generates three overlapping lists with realistic name shapes (seeded, so runs
//! are comparable). `dir` compiles every `*.txt` in a directory (e.g. downloaded real lists).

#![allow(
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::unwrap_used
)]

use std::fmt::Write as _;
use std::path::Path;
use std::time::Instant;

use telltale_filter::compile::{CompileOptions, ListData, ListInput, compile};
use telltale_filter::fetch::content_hash;
use telltale_filter::parse::ListOptions;

/// xorshift64*: deterministic and dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const TLDS: [&str; 12] = [
    "com", "com", "com", "com", "net", "org", "io", "de", "ru", "info", "xyz", "co.uk",
];
const SUBS: [&str; 10] = [
    "", "", "", "www", "ads", "cdn", "api", "track", "metrics", "static",
];
const SYLLABLES: [&str; 24] = [
    "ad", "ex", "tra", "ck", "on", "lin", "ser", "ve", "me", "tri", "cs", "pix", "el", "ana", "ly",
    "tic", "pro", "mo", "bid", "dsp", "net", "go", "click", "data",
];

/// A pronounceable-ish registrable name plus an optional subdomain, like real lists have.
fn name(rng: &mut Rng, out: &mut String) {
    out.clear();
    let sub = SUBS[rng.below(SUBS.len() as u64) as usize];
    if !sub.is_empty() {
        out.push_str(sub);
        if rng.below(4) == 0 {
            let _ = write!(out, "{}", rng.below(100));
        }
        out.push('.');
    }
    for _ in 0..2 + rng.below(3) {
        out.push_str(SYLLABLES[rng.below(SYLLABLES.len() as u64) as usize]);
    }
    if rng.below(3) == 0 {
        let _ = write!(out, "{}", rng.below(1000));
    }
    out.push('.');
    out.push_str(TLDS[rng.below(TLDS.len() as u64) as usize]);
}

fn synthetic(total: usize) -> Vec<ListInput> {
    // Three lists sharing ~30% of their names, like HaGeZi/OISD/StevenBlack overlap.
    let mut rng = Rng(0x7E11_7A1E);
    let mut lists = vec![String::new(), String::new(), String::new()];
    let mut n = String::new();
    for i in 0..total {
        name(&mut rng, &mut n);
        let target = i % 3;
        let _ = writeln!(lists[target], "{n}");
        if rng.below(10) < 3 {
            let other = (target + 1 + rng.below(2) as usize) % 3;
            let _ = writeln!(lists[other], "||{n}^");
        }
    }
    lists
        .into_iter()
        .enumerate()
        .map(|(i, text)| ListInput {
            name: format!("synthetic-{i}"),
            options: ListOptions::default(),
            source_hash: content_hash(text.as_bytes()),
            size: text.len() as u64,
            data: ListData::Bytes(text.into_bytes()),
        })
        .collect()
}

fn from_dir(dir: &Path) -> Vec<ListInput> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let data = std::fs::read(&p).unwrap();
            ListInput {
                name: p.file_stem().unwrap().to_string_lossy().into_owned(),
                options: ListOptions::default(),
                source_hash: content_hash(&data),
                size: data.len() as u64,
                data: ListData::Bytes(data),
            }
        })
        .collect()
}

fn peak_rss_mib() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kib: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024.0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let threads = args.get(3).and_then(|t| t.parse().ok()).unwrap_or(1);
    let t = Instant::now();
    let inputs = match args.get(1).map(String::as_str) {
        Some("synthetic") => synthetic(
            args.get(2)
                .and_then(|n| n.parse().ok())
                .unwrap_or(1_500_000),
        ),
        Some("dir") => from_dir(Path::new(args.get(2).map_or("bench/lists", String::as_str))),
        _ => {
            eprintln!("usage: compile_bench synthetic <names> [threads] | dir <path> [threads]");
            std::process::exit(2);
        }
    };
    let bytes: u64 = inputs.iter().map(|i| i.size).sum();
    println!(
        "inputs: {} lists, {:.1} MB, prepared in {:.2?}",
        inputs.len(),
        bytes as f64 / 1e6,
        t.elapsed()
    );
    let tmp = tempfile::tempdir().unwrap();
    let report = compile(
        inputs,
        &tmp.path().join("snap"),
        &CompileOptions {
            threads,
            ..CompileOptions::default()
        },
    )
    .unwrap();
    let st = &report.manifest.stats;
    let names = st.subtree_names + st.exact_names + st.subdomains_names;
    println!(
        "names: {names} (subtree {}, exact {}, subdomains {}), list sets {}, regexes {}, modrules {}",
        st.subtree_names, st.exact_names, st.subdomains_names, st.listsets, st.regexes, st.modrules
    );
    for b in &report.manifest.blobs {
        println!("  {:<16} {:>12} bytes", b.name, b.bytes);
    }
    let tm = &report.timings;
    println!(
        "bytes/name: {:.2}   compile: {:.2?} (parse {:.2?}, merge+fst {:.2?}, tables {:.2?})   threads {threads}   spilled runs {}   peak RSS {:.0} MiB",
        st.bytes_per_name,
        tm.total,
        tm.parse,
        tm.merge,
        tm.tables,
        report.spilled_runs,
        peak_rss_mib().unwrap_or(0.0)
    );
    for (i, l) in st.per_list.iter().enumerate() {
        println!(
            "  {:<24} entries {:>9} unique {:>9} invalid {:>6} unsupported {:>6}",
            report.manifest.lists[i].name, l.entries, l.unique, l.invalid, l.unsupported
        );
    }
}
