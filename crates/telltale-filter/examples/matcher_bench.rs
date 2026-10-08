//! T2.4 acceptance measurement: per-lookup latency of `Matcher::decide` (AC: p99 ≤ 1 µs
//! without regexes on x86).
//!
//!   `cargo run --profile bench-fast -p telltale-filter --example matcher_bench -- <lists dir> [threads] [regexes]`
//!
//! Compiles every `*.txt` in the directory, then times 2M lookups one by one over a mix of
//! listed names (blocked), subdomains of listed names, and unlisted names. `regexes` adds
//! that many synthetic Pi-hole regexes to measure the regex path too.

#![allow(
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use telltale_filter::compile::{CompileOptions, ListData, ListInput, compile};
use telltale_filter::fetch::content_hash;
use telltale_filter::matcher::{ClientCtx, Decision, ListMask, Lookup, Matcher, Scratch};
use telltale_filter::parse::{ListOptions, Pattern, parse_list};
use telltale_filter::snapshot::Snapshot;
use telltale_proto::{NameBuf, rtype};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = Path::new(args.get(1).map_or("bench/lists", String::as_str));
    let threads = args.get(2).and_then(|t| t.parse().ok()).unwrap_or(1);
    let regexes: usize = args.get(3).and_then(|t| t.parse().ok()).unwrap_or(0);

    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    files.sort();
    let mut inputs = Vec::new();
    let mut sample: Vec<String> = Vec::new();
    for p in &files {
        let data = std::fs::read(p).unwrap();
        let mut n = 0u64;
        parse_list(&data, ListOptions::default(), |_, r| {
            n += 1;
            if n.is_multiple_of(97)
                && let Pattern::Domain { name, .. } = r.pattern
            {
                sample.push(name);
            }
        });
        inputs.push(ListInput {
            name: p.file_stem().unwrap().to_string_lossy().into_owned(),
            options: ListOptions::default(),
            source_hash: content_hash(&data),
            size: data.len() as u64,
            data: ListData::Bytes(data),
        });
    }
    if regexes > 0 {
        let mut text = String::new();
        for i in 0..regexes {
            let _ = writeln!(text, "^(.+[_.-])?ad{i}x?[0-9]*[_.-]");
        }
        inputs.push(ListInput {
            name: "regexes".into(),
            options: ListOptions::default(),
            source_hash: content_hash(text.as_bytes()),
            size: text.len() as u64,
            data: ListData::Bytes(text.into_bytes()),
        });
    }
    let lists = inputs.len();
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("snap");
    let report = compile(
        inputs,
        &out,
        &CompileOptions {
            threads,
            ..CompileOptions::default()
        },
    )
    .unwrap();
    let st = &report.manifest.stats;
    println!(
        "snapshot: {} names, {} regexes, {} shards, compiled in {:.2?}",
        st.subtree_names + st.exact_names + st.subdomains_names,
        st.regexes,
        report.manifest.fst_shards,
        report.timings.total
    );
    let t = Instant::now();
    let lookup = if std::env::var_os("WALK").is_some() {
        Lookup::Walk
    } else {
        Lookup::Indexed
    };
    let m = Matcher::with_lookup(Some(Arc::new(Snapshot::open(&out).unwrap())), lookup).unwrap();
    println!(
        "load + index + regex build: {:.2?}, index {:.1} MiB",
        t.elapsed(),
        m.index_bytes() as f64 / f64::from(1u32 << 20)
    );

    // Query mix: 1/3 listed, 1/3 subdomains of listed names, 1/3 unlisted.
    let mut queries: Vec<Vec<u8>> = Vec::new();
    for (i, s) in sample.iter().enumerate().take(30_000) {
        let name = match i % 3 {
            0 => s.clone(),
            1 => format!("cdn{i}.{s}"),
            _ => format!("u{i}.notlisted{}.example", i % 1000),
        };
        if let Ok(n) = NameBuf::from_presentation(&name) {
            queries.push(n.as_wire().to_vec());
        }
    }
    let mask = ListMask::all(lists);
    let client = ClientCtx {
        ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
        name: None,
        client_id: None,
    };
    let mut scratch = Scratch::default();
    for q in &queries {
        m.decide(q, rtype::A, &client, &mask, &mut scratch);
    }
    let rounds = 2_000_000 / queries.len().max(1) + 1;
    let mut samples = Vec::with_capacity(rounds * queries.len());
    let mut blocked = 0u64;
    for _ in 0..rounds {
        for q in &queries {
            let t = Instant::now();
            let d = m.decide(q, rtype::A, &client, &mask, &mut scratch);
            samples.push(t.elapsed().as_nanos() as u64);
            blocked += u64::from(matches!(d, Decision::Block(_)));
        }
    }
    // Timer overhead, measured the same way with no work.
    let mut empty = Vec::with_capacity(200_000);
    for _ in 0..200_000 {
        let t = Instant::now();
        empty.push(t.elapsed().as_nanos() as u64);
    }
    empty.sort_unstable();
    samples.sort_unstable();
    let pct = |v: &[u64], p: f64| v[((v.len() as f64 - 1.0) * p) as usize];
    println!(
        "{} lookups ({:.0}% blocked): p50 {} ns, p90 {} ns, p99 {} ns, p99.9 {} ns, max {} ns (timer overhead p50 {} ns)",
        samples.len(),
        100.0 * blocked as f64 / samples.len() as f64,
        pct(&samples, 0.5),
        pct(&samples, 0.9),
        pct(&samples, 0.99),
        pct(&samples, 0.999),
        samples.last().copied().unwrap_or(0),
        pct(&empty, 0.5)
    );
}
