//! REQ: FLT-001 — golden tests: every fixture list → canonical rule dump (`insta` snapshots,
//! `spec/09` §1). Fixtures are synthetic but follow each published format's real shape
//! (ADR-017). Review snapshot changes with `cargo insta review`.

#![allow(clippy::unwrap_used)]

use std::fmt::Write;

use telltale_config::{ListKind, ListMatch};
use telltale_filter::parse::{ListOptions, parse_list};

fn dump(name: &str, opts: ListOptions) -> String {
    let path = format!("{}/tests/fixtures/lists/{name}", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read(&path).unwrap();
    let mut out = String::new();
    let stats = parse_list(&data, opts, |line, rule| {
        writeln!(out, "L{line:<3} {rule}").unwrap();
    });
    writeln!(
        out,
        "\nlines={} rules={} blank={} comments={} ignored={} unsupported={} invalid={}",
        stats.lines,
        stats.rules,
        stats.blank,
        stats.comments,
        stats.ignored,
        stats.unsupported,
        stats.invalid
    )
    .unwrap();
    for s in &stats.samples {
        let kind = if s.unsupported {
            "unsupported"
        } else {
            "invalid"
        };
        writeln!(out, "L{:<3} {kind}: {} <- {:?}", s.line, s.reason, s.text).unwrap();
    }
    out
}

macro_rules! golden {
    ($test:ident, $file:literal) => {
        golden!($test, $file, ListOptions::default());
    };
    ($test:ident, $file:literal, $opts:expr) => {
        #[test]
        fn $test() {
            insta::assert_snapshot!(stringify!($test), dump($file, $opts));
        }
    };
}

golden!(flt_001_hosts, "hosts.txt");
golden!(flt_001_domains, "domains.txt");
golden!(
    flt_002_domains_exact_allow,
    "domains.txt",
    ListOptions {
        kind: ListKind::Allow,
        match_mode: ListMatch::Exact
    }
);
golden!(flt_001_wildcard, "wildcard.txt");
golden!(flt_001_adblock, "adblock.txt");
golden!(flt_001_adguard_dns, "adguard-dns.txt");
golden!(flt_001_pihole_regex, "pihole-regex.txt");
