//! `telltale import zone FILE` (REQ: API-007; T6.4, ADR-041): turns a DNS zone file (RFC 1035
//! master file, as exported by Technitium, BIND, `PowerDNS`, or Pi-hole's local DNS) into
//! `[[record]]` entries, and reports what it couldn't carry over.
//!
//! Supported: `$ORIGIN`, `$TTL`, comments, parentheses across lines, `@`, relative and absolute
//! names, an omitted owner (the previous one), optional TTL and class in either order, and the
//! record types TelltaleDNS serves locally (A, AAAA, CNAME, PTR, TXT, MX, SRV). SOA and NS are
//! skipped (TelltaleDNS answers local names itself), and so is anything else, by type, in the
//! report.

use std::fmt::Write as _;

/// One record in TelltaleDNS form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) name: String,
    pub(crate) rtype: String,
    pub(crate) value: String,
    pub(crate) ttl: Option<u32>,
}

/// What an import produced.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Import {
    pub(crate) origin: String,
    pub(crate) records: Vec<Record>,
    /// Skipped lines, each with the reason (for the report).
    pub(crate) skipped: Vec<String>,
    /// REQ: DNS-018 (T9.18) — the apex's SOA and NS records (type, data tokens): a served
    /// zone answers with them; `telltale import zone` doesn't need them.
    pub(crate) apex: Vec<(String, Vec<String>)>,
}

const SUPPORTED: &[&str] = &["A", "AAAA", "CNAME", "PTR", "TXT", "MX", "SRV"];
const CLASSES: &[&str] = &["IN", "CH", "HS", "CS"];

/// Joins lines inside parentheses and strips comments (outside quotes).
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for raw in text.lines() {
        let mut line = String::new();
        let mut quoted = false;
        for c in raw.chars() {
            match c {
                '"' => {
                    quoted = !quoted;
                    line.push(c);
                }
                ';' if !quoted => break,
                '(' if !quoted => {
                    depth += 1;
                    line.push(' ');
                }
                ')' if !quoted => {
                    depth -= 1;
                    line.push(' ');
                }
                _ => line.push(c),
            }
        }
        if cur.is_empty() {
            cur = line;
        } else {
            cur.push(' ');
            cur.push_str(line.trim());
        }
        if depth <= 0 {
            if !cur.trim().is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            cur.clear();
            depth = 0;
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// Splits on whitespace, keeping quoted strings (with their quotes) together.
fn tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in line.chars() {
        if c == '"' {
            quoted = !quoted;
            cur.push(c);
        } else if c.is_whitespace() && !quoted {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `name` made absolute (no trailing dot): `@` is the origin, relative names get it appended.
fn absolute(name: &str, origin: &str) -> String {
    if name == "@" {
        return origin.to_owned();
    }
    if let Some(n) = name.strip_suffix('.') {
        return n.to_ascii_lowercase();
    }
    if origin.is_empty() {
        name.to_ascii_lowercase()
    } else {
        format!("{}.{origin}", name.to_ascii_lowercase())
    }
}

/// Parses `text`. `origin` (without a trailing dot) applies until a `$ORIGIN` line.
pub(crate) fn parse_zone(text: &str, origin: Option<&str>) -> Import {
    let mut im = Import {
        origin: origin
            .unwrap_or("")
            .trim_end_matches('.')
            .to_ascii_lowercase(),
        ..Import::default()
    };
    let mut default_ttl: Option<u32> = None;
    let mut last_owner = String::new();
    for line in logical_lines(text) {
        let starts_blank = line.starts_with([' ', '\t']);
        let t = tokens(&line);
        let Some(first) = t.first() else { continue };
        match first.to_ascii_uppercase().as_str() {
            "$ORIGIN" => {
                if let Some(o) = t.get(1) {
                    im.origin = absolute(o, &im.origin);
                }
                continue;
            }
            "$TTL" => {
                default_ttl = t.get(1).and_then(|v| v.parse().ok());
                continue;
            }
            "$INCLUDE" | "$GENERATE" => {
                im.skipped
                    .push(format!("{first}: not supported ({})", line.trim()));
                continue;
            }
            _ => {}
        }
        let mut i = 0;
        let owner = if starts_blank {
            last_owner.clone()
        } else {
            i = 1;
            absolute(first, &im.origin)
        };
        last_owner.clone_from(&owner);
        // Optional TTL and class, in either order.
        let mut ttl = default_ttl;
        for _ in 0..2 {
            match t.get(i) {
                Some(x) if x.chars().all(|c| c.is_ascii_digit()) => {
                    ttl = x.parse().ok();
                    i += 1;
                }
                Some(x) if CLASSES.contains(&x.to_ascii_uppercase().as_str()) => i += 1,
                _ => {}
            }
        }
        let Some(rtype) = t.get(i).map(|x| x.to_ascii_uppercase()) else {
            im.skipped
                .push(format!("{owner}: no record type ({})", line.trim()));
            continue;
        };
        let rdata = &t[i + 1..];
        match rtype.as_str() {
            "SOA" | "NS" if owner == im.origin => {
                im.apex.push((rtype.clone(), rdata.to_vec()));
                im.skipped.push(format!(
                    "{owner} {rtype}: not needed (TelltaleDNS answers these names itself)"
                ));
                continue;
            }
            t if !SUPPORTED.contains(&t) => {
                im.skipped.push(format!(
                    "{owner} {rtype}: no local equivalent ({})",
                    rdata.join(" ")
                ));
                continue;
            }
            _ => {}
        }
        let value = value_for(&rtype, rdata, &im.origin);
        match value.filter(|v| !v.is_empty()) {
            Some(value) => im.records.push(Record {
                name: owner,
                rtype,
                value,
                ttl,
            }),
            None => im
                .skipped
                .push(format!("{owner} {rtype}: incomplete ({})", rdata.join(" "))),
        }
    }
    im
}

/// The TelltaleDNS `value` for a record's RDATA tokens (names made absolute).
fn value_for(rtype: &str, rdata: &[String], origin: &str) -> Option<String> {
    let name_at = |k: usize| rdata.get(k).map(|n| absolute(n, origin));
    match rtype {
        "A" | "AAAA" => rdata.first().cloned(),
        "CNAME" | "PTR" => name_at(0),
        "MX" => rdata
            .first()
            .zip(name_at(1))
            .map(|(p, n)| format!("{p} {n}")),
        "SRV" => (rdata.len() >= 4).then(|| {
            format!(
                "{} {} {} {}",
                rdata[0],
                rdata[1],
                rdata[2],
                absolute(&rdata[3], origin)
            )
        }),
        // TXT: the strings joined, quotes removed.
        _ => Some(
            rdata
                .iter()
                .map(|s| s.trim_matches('"'))
                .collect::<String>(),
        ),
    }
}

pub(crate) fn toml_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `[[record]]` TOML for `im`, with a header naming the source and what was skipped.
pub(crate) fn to_toml(im: &Import, source: &str) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Imported from {source} by `telltale import zone`.");
    if !im.origin.is_empty() {
        let _ = writeln!(s, "# Zone: {}", im.origin);
    }
    let _ = writeln!(
        s,
        "# {} records; {} lines skipped:",
        im.records.len(),
        im.skipped.len()
    );
    for k in &im.skipped {
        let _ = writeln!(s, "#   {k}");
    }
    for r in &im.records {
        let _ = writeln!(s, "\n[[record]]");
        let _ = writeln!(s, "name = {}", toml_str(&r.name));
        let _ = writeln!(s, "type = {}", toml_str(&r.rtype));
        let _ = writeln!(s, "value = {}", toml_str(&r.value));
        if let Some(t) = r.ttl {
            let _ = writeln!(s, "ttl = {t}");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // Technitium's export format (the owner's homelab zone, anonymized).
    const TECHNITIUM: &str = "$ORIGIN example.dev.
@                     900       IN  SOA           ns1.cluster. hostadmin 22 900 300 604800 900
@                     14400     IN  NS            ns1.cluster.
argo                  3600      IN  CNAME         ingress
ingress               3600      IN  A             192.168.5.100
nas                   3600      IN  A             192.168.3.3
";

    #[test]
    fn api_007_technitium_export() {
        let im = parse_zone(TECHNITIUM, None);
        assert_eq!(im.origin, "example.dev");
        assert_eq!(
            im.records,
            [
                Record {
                    name: "argo.example.dev".into(),
                    rtype: "CNAME".into(),
                    value: "ingress.example.dev".into(),
                    ttl: Some(3600)
                },
                Record {
                    name: "ingress.example.dev".into(),
                    rtype: "A".into(),
                    value: "192.168.5.100".into(),
                    ttl: Some(3600)
                },
                Record {
                    name: "nas.example.dev".into(),
                    rtype: "A".into(),
                    value: "192.168.3.3".into(),
                    ttl: Some(3600)
                },
            ]
        );
        assert_eq!(im.skipped.len(), 2, "{:?}", im.skipped);
        // The output is a config fragment TelltaleDNS loads.
        let toml = to_toml(&im, "test");
        let cfg = telltale_config::Loader::new()
            .toml_str("import", toml)
            .load()
            .unwrap()
            .config;
        assert_eq!(cfg.record.len(), 3);
        let (_, report) = telltale_policy::LocalData::from_config(&cfg);
        assert_eq!(report.errors, Vec::<String>::new());
    }

    #[test]
    fn api_007_bind_syntax() {
        let bind = r#"$TTL 600
$ORIGIN home.arpa.
@   IN SOA ns1 admin (
        2026100401 ; serial
        3600 900 604800 300 )
    IN NS ns1
    IN MX 10 mail
    IN TXT "v=spf1 " "-all"
ns1 A 192.168.1.2
www IN 120 AAAA fd00::5 ; class before TTL
_sip._udp SRV 0 5 5060 pbx.home.arpa.
pbx A 192.168.1.9
old CAA 0 issue "letsencrypt.org"
$ORIGIN 1.168.192.in-addr.arpa.
9 PTR pbx.home.arpa.
"#;
        let im = parse_zone(bind, None);
        let got: Vec<(String, String, String, Option<u32>)> = im
            .records
            .iter()
            .map(|r| (r.name.clone(), r.rtype.clone(), r.value.clone(), r.ttl))
            .collect();
        let s =
            |a: &str, b: &str, c: &str, t: u32| (a.to_owned(), b.to_owned(), c.to_owned(), Some(t));
        assert_eq!(
            got,
            [
                s("home.arpa", "MX", "10 mail.home.arpa", 600),
                s("home.arpa", "TXT", "v=spf1 -all", 600),
                s("ns1.home.arpa", "A", "192.168.1.2", 600),
                s("www.home.arpa", "AAAA", "fd00::5", 120),
                s("_sip._udp.home.arpa", "SRV", "0 5 5060 pbx.home.arpa", 600),
                s("pbx.home.arpa", "A", "192.168.1.9", 600),
                s("9.1.168.192.in-addr.arpa", "PTR", "pbx.home.arpa", 600),
            ]
        );
        assert!(
            im.skipped.iter().any(|k| k.contains("CAA")),
            "{:?}",
            im.skipped
        );
        assert!(im.skipped.iter().any(|k| k.contains("SOA")));
    }

    #[test]
    fn api_007_origin_flag_and_quotes_in_toml() {
        let im = parse_zone(
            "note TXT \"say \\\"hi\\\"\"\nhost A 10.0.0.1\n",
            Some("lan."),
        );
        assert_eq!(im.records[1].name, "host.lan");
        let toml = to_toml(&im, "x");
        assert!(toml.contains("name = \"note.lan\""));
        assert!(
            telltale_config::Loader::new()
                .toml_str("import", toml)
                .load()
                .is_ok()
        );
    }
}
