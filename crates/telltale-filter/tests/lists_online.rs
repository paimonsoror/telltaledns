//! REQ: FLT-001 — parse the real published lists (network; run nightly with `--ignored`).
//! These aren't vendored (several are GPL-licensed data, ADR-017), so this test downloads
//! them and checks that each parses with a negligible share of invalid lines.

#![allow(clippy::unwrap_used, clippy::cast_precision_loss, clippy::print_stdout)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use telltale_filter::fetch::{
    Client, FetchSettings, Fetcher, ListSource, ListSpec, Outcome, Store, SystemResolver,
};
use telltale_filter::parse::{ListOptions, parse_list};

const LISTS: &[(&str, &str)] = &[
    (
        "stevenblack",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    (
        "hagezi-pro-adblock",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    ),
    (
        "hagezi-pro-wildcard",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt",
    ),
    (
        "hagezi-pro-onlydomains",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
    ),
    ("oisd-small", "https://small.oisd.nl/"),
    ("oisd-big-domains", "https://big.oisd.nl/domainswild2"),
    (
        "adguard-dns",
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    ),
];

#[tokio::test]
#[ignore = "network: downloads published lists"]
async fn flt_001_real_lists_parse_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let client = Client::new(Arc::new(SystemResolver), &[]).unwrap();
    let settings = FetchSettings {
        concurrency: 4,
        timeout: Duration::from_secs(120),
        retries: 2,
        backoff: Duration::from_secs(2),
        settle: Duration::from_secs(10),
    };
    let fetcher = Arc::new(Fetcher::new(
        Store::open(tmp.path()).unwrap(),
        client,
        settings,
    ));
    let specs: Vec<ListSpec> = LISTS
        .iter()
        .map(|(name, url)| ListSpec {
            name: (*name).to_owned(),
            source: ListSource::Url((*url).to_owned()),
            refresh: Duration::from_hours(24),
            max_bytes: 256 << 20,
        })
        .collect();
    let mut failures = Vec::new();
    for (name, outcome) in fetcher.refresh(&specs).await {
        if let Outcome::Failed(e) = outcome {
            println!("{name}: download failed (skipped): {e}");
            continue;
        }
        let data = fetcher.store().read_source(&name).unwrap();
        let t = Instant::now();
        let stats = parse_list(&data, ListOptions::default(), |_, _| {});
        let elapsed = t.elapsed().as_secs_f64();
        let invalid_pct = 100.0 * stats.invalid as f64 / stats.lines.max(1) as f64;
        println!(
            "{name:<22} {:>8} lines {:>8} rules {:>6} unsupported {:>5} invalid ({invalid_pct:.3}%) {:>6.0} ms {:>5.1} MB/s",
            stats.lines,
            stats.rules,
            stats.unsupported,
            stats.invalid,
            elapsed * 1000.0,
            data.len() as f64 / 1e6 / elapsed
        );
        for s in stats.samples.iter().take(5) {
            println!("    L{} {}: {:?}", s.line, s.reason, s.text);
        }
        if stats.rules == 0 || invalid_pct > 0.1 {
            failures.push(format!(
                "{name}: {} rules, {invalid_pct:.3}% invalid",
                stats.rules
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:?}");
}
