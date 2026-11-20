// REQ: OPS-011 (ADR-156) — a package with every kind of secret planted comes out without them at
// every level (scanned raw, as base64, and URL-encoded), names and addresses are gone at strict,
// the same input is the same bytes, the manifest counts what happened, and the size cap holds.

use super::*;
use crate::archive::read_tar_gz;
use crate::classify::known_from_config;
use serde_json::json;
use std::fmt::Write as _;

fn opts(level: Level, key: u8) -> Options {
    Options {
        level,
        key: [key; 32],
        reveal: Vec::new(),
        created_unix: 1_790_000_000,
        created: "2026-11-16T00:00:00Z".to_owned(),
        max_bytes: 20 * 1024 * 1024,
        keyed_labels: false,
    }
}

/// Values that must never appear, in any form, at any level.
const SECRETS: &[&str] = &[
    "hunter2hunter2",
    "oidc-secret-value-123",
    "otlp-header-secret-9",
    "ghp_planted0123456789abcdefghijklmnopqrstu",
    "sk-planted-API-key-0123456789abcdef0123",
    "eyJzdWIiOiJwbGFudGVkLXN1YmplY3QtMDEyMzQ1Njc4OSJ9",
    "c2lnbmF0dXJlLXBsYW50ZWQtMDEyMzQ1Njc4OQ",
    "MIIEvAIBADANBgkqhkiG9w0B",
    "BEGIN PRIVATE KEY",
    "pw@git",
];

const LOG: &str = "2026-11-16T04:56:32Z WARN upstream doh failed for 192.168.1.20 (Living-TV): auth Bearer hunter2hunter2\n\
2026-11-16T04:56:33Z ERROR clone failed https://u:pw@git.acme-dns.net/r.git?access_token=abc with ghp_planted0123456789abcdefghijklmnopqrstu\n\
2026-11-16T04:56:34Z WARN key sk-planted-API-key-0123456789abcdef0123 and jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwbGFudGVkLXN1YmplY3QtMDEyMzQ1Njc4OSJ9.c2lnbmF0dXJlLXBsYW50ZWQtMDEyMzQ1Njc4OQ\n\
2026-11-16T04:56:35Z ERROR -----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0B\n-----END PRIVATE KEY----- on /home/alice/.cache/x by home-pi\n";

fn cfg() -> Value {
    json!({
        "node": { "name": "home-pi", "data_dir": "/home/alice/telltale", "role": "All" },
        "client": [{ "name": "Living-TV", "match": ["192.168.1.20", "id:kids-tablet"], "groups": ["kids"] }],
        "group": [{ "name": "kids", "networks": ["192.168.1.0/24"] }],
        "upstream": [{ "name": "doh", "url": "https://dns.acme-dns.net/dns-query/abc123secretprofile",
                       "headers": { "Authorization": "Bearer hunter2hunter2" } }],
        "auth": { "oidc": { "provider": [{ "id": "idp", "name": "IdP", "issuer": "https://idp.acme-dns.org/realms/me",
                                            "client_id": "cid", "client_secret": "oidc-secret-value-123" }] } },
        "telemetry": { "otlp": { "headers": { "x-key": "otlp-header-secret-9" } } },
        "cache": { "max_ttl": 600 }
    })
}

fn build(level: Level, key: u8) -> Finished {
    let c = cfg();
    let mut p = Package::new(opts(level, key), &known_from_config(&c)).unwrap();
    p.add_config("config/effective.json", "config", &c);
    p.add_text("logs/node.log", "log", LOG, true);
    p.add_plain(
        "node/build.json",
        "node",
        "{\"version\":\"0.7.0\"}".to_owned(),
    );
    p.add_missing("cluster/view.json", "cluster", "timed out after 5 s");
    p.finish()
}

/// Every file of the archive, as text, with the manifest and README (the archive's own).
fn everything(f: &Finished) -> String {
    read_tar_gz(&f.archive)
        .unwrap()
        .into_iter()
        .map(|e| format!("== {}\n{}", e.path, String::from_utf8_lossy(&e.data)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn base64(s: &str) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in s.as_bytes().chunks(3) {
        let n = chunk.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn url_encoded(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[test]
fn ops_011_no_planted_secret_survives_at_any_level() {
    for level in [Level::Strict, Level::Standard, Level::Off] {
        let f = build(level, 1);
        let all = everything(&f);
        for secret in SECRETS {
            for form in [(*secret).to_owned(), base64(secret), url_encoded(secret)] {
                assert!(!all.contains(&form), "{level:?}: {form} survived in\n{all}");
                assert!(!f.map.contains(&form), "{level:?}: {form} in the map");
            }
        }
        // The compressed bytes don't hold them either.
        for secret in SECRETS {
            assert!(
                !f.archive
                    .windows(secret.len())
                    .any(|w| w == secret.as_bytes()),
                "{secret}"
            );
        }
        assert!(
            f.manifest.config_fields_unclassified.is_empty(),
            "{:?}",
            f.manifest.config_fields_unclassified
        );
    }
}

#[test]
fn ops_011_strict_hides_names_and_addresses_and_none_keeps_them() {
    let strict = everything(&build(Level::Strict, 1));
    for gone in [
        "192.168.1.20",
        "Living-TV",
        "home-pi",
        "alice",
        "kids-tablet",
        "acme-dns",
        "abc123secretprofile",
    ] {
        assert!(
            !strict.contains(gone),
            "{gone} survived at strict:\n{strict}"
        );
    }
    for kept in [
        "\"max_ttl\": 600",
        "device-",
        "node-",
        "WARN upstream doh failed",
    ] {
        assert!(strict.contains(kept), "{kept} missing at strict:\n{strict}");
    }
    let open = everything(&build(Level::Off, 1));
    for kept in ["192.168.1.20", "Living-TV", "home-pi", "alice"] {
        assert!(open.contains(kept), "{kept} missing at none:\n{open}");
    }
}

#[test]
fn ops_011_the_same_input_is_the_same_bytes_and_another_key_another_package() {
    let a = build(Level::Strict, 1);
    assert_eq!(a.archive, build(Level::Strict, 1).archive);
    let b = build(Level::Strict, 2);
    assert_ne!(a.archive, b.archive, "the addresses move with the key");
    assert_ne!(everything(&a), everything(&b));
}

#[test]
fn ops_011_the_manifest_lists_every_file_and_its_counts_match_a_recount() {
    let mut p = Package::new(opts(Level::Strict, 1), &Known::new()).unwrap();
    p.add_text(
        "x.log",
        "t",
        "10.0.0.1 10.0.0.2 aa:bb:cc:dd:ee:ff a@b.org and 10.0.0.1 again",
        false,
    );
    p.add_missing("y.json", "slow", "timed out after 5 s");
    let f = p.finish();
    let files: Vec<(&str, Status)> = f
        .manifest
        .files
        .iter()
        .map(|e| (e.path.as_str(), e.status))
        .collect();
    assert_eq!(files, [("x.log", Status::Ok), ("y.json", Status::Missing)]);
    let x = &f.manifest.files[0];
    // Three addresses in the text (one twice), one MAC, one e-mail address.
    assert_eq!(x.redactions.get("address"), Some(&3), "{:?}", x.redactions);
    assert_eq!(x.redactions.get("mac"), Some(&1));
    assert_eq!(x.redactions.get("email"), Some(&1));
    assert_eq!(f.manifest.redactions.get("address"), Some(&3));
    let paths: Vec<String> = read_tar_gz(&f.archive)
        .unwrap()
        .into_iter()
        .map(|e| e.path)
        .collect();
    assert_eq!(
        paths,
        ["MANIFEST.json", "README.txt", "x.log"],
        "a missing file isn't archived"
    );
    assert_eq!(
        f.manifest.files[1].note.as_deref(),
        Some("timed out after 5 s")
    );
}

#[test]
fn ops_011_over_the_cap_the_largest_files_are_cut_and_say_so() {
    let mut o = opts(Level::Strict, 1);
    o.max_bytes = 10_000;
    let mut p = Package::new(o, &Known::new()).unwrap();
    let mut log = String::new();
    for i in 0..2_000 {
        let _ = writeln!(log, "2026-11-16T04:00:00Z WARN line number {i}");
    }
    p.add_text("logs/node.log", "log", &log, true);
    p.add_text("other.txt", "t", &"small file\n".repeat(20), false);
    let f = p.finish();
    let e = f
        .manifest
        .files
        .iter()
        .find(|e| e.path == "logs/node.log")
        .unwrap();
    assert_eq!(e.status, Status::Truncated);
    assert!(
        e.note.as_deref().unwrap().contains("newest"),
        "{:?}",
        e.note
    );
    let files = read_tar_gz(&f.archive).unwrap();
    let kept = files.iter().find(|x| x.path == "logs/node.log").unwrap();
    let text = String::from_utf8_lossy(&kept.data);
    assert!(
        text.ends_with("line number 1999\n"),
        "the newest lines stay"
    );
    assert!(text.starts_with("2026-"), "and it starts on a whole line");
    let total: usize = f.manifest.files.iter().map(|e| e.bytes).sum();
    assert!(total <= 10_000, "{total}");
    let other = f
        .manifest
        .files
        .iter()
        .find(|e| e.path == "other.txt")
        .unwrap();
    assert_eq!(other.status, Status::Ok, "a small file is left whole");
}

#[test]
fn ops_011_reveal_keeps_one_name() {
    let c = cfg();
    let mut o = opts(Level::Strict, 1);
    o.reveal = vec!["home-pi".to_owned()];
    let mut p = Package::new(o, &known_from_config(&c)).unwrap();
    p.add_config("config/effective.json", "config", &c);
    p.add_text("logs/node.log", "log", LOG, true);
    let all = everything(&p.finish());
    assert!(all.contains("home-pi"), "{all}");
    assert!(!all.contains("Living-TV") && !all.contains("192.168.1.20"));
}

#[test]
fn ops_011_the_map_holds_what_the_archive_does_not() {
    let f = build(Level::Strict, 1);
    assert!(f.map.contains("\tLiving-TV\n"), "{}", f.map);
    assert!(f.map.contains("\t192.168.1.20\n"), "{}", f.map);
    assert!(!everything(&f).contains("Living-TV"));
}
