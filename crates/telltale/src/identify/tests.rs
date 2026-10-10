use std::path::Path;
use std::time::Instant;

use serde::Serialize;
use telltale_config::DeviceClass;

use super::score::{Inputs, Level, glob, score, vendor_matches};
use super::*;

fn mac(s: &str) -> [u8; 6] {
    oui::parse_mac(s).unwrap()
}

fn device(mac_text: Option<&str>, names: &[&str], domains: &[&str]) -> Inputs {
    let d = Device {
        key: "192.0.2.1".into(),
        ip: "192.0.2.1".parse().unwrap(),
        mac: mac_text.map(mac),
        names: names.iter().map(|s| (*s).to_owned()).collect(),
        domains: domains.iter().map(|s| (*s).to_owned()).collect(),
    };
    inputs(&d)
}

// REQ: OBS-025 — AC (5): the IEEE table resolves known prefixes, the 28-bit (MA-M) block
// before the 24-bit one; private (locally administered) addresses have no vendor.
#[test]
fn obs_025_oui_resolves_known_prefixes() {
    let cases = [
        ("D0:4D:2C:11:22:33", "roku"),
        ("F0:EE:7A:11:22:33", "apple"),
        ("54:E0:19:11:22:33", "ring"),
        ("78:28:CA:11:22:33", "sonos"),
        ("34:F7:16:11:22:33", "tp-link"),
        ("E4:C7:67:11:22:33", "intel"),
        ("D4:8A:FC:11:22:33", "espressif"),
        ("84:28:59:11:22:33", "amazon"),
        ("44:61:32:11:22:33", "ecobee"),
        ("C8:5C:E2:70:00:01", "synergy systems"),
    ];
    for (m, want) in cases {
        let v = oui::lookup(mac(m)).unwrap_or_default().to_lowercase();
        assert!(v.contains(want), "{m}: {v}");
    }
    // The same 24 bits, another 28-bit block: not the MA-M owner above.
    assert_ne!(
        oui::lookup(mac("C8:5C:E2:A0:00:01")),
        oui::lookup(mac("C8:5C:E2:70:00:01"))
    );
    assert_eq!(
        oui::lookup(mac("3A:11:22:33:44:55")),
        None,
        "private address"
    );
    let (vendors, mam, mal, bytes) = oui::stats();
    assert!(
        vendors > 20_000 && mam > 5_000 && mal > 35_000,
        "{vendors} {mam} {mal}"
    );
    println!("oui.bin: {vendors} vendors, {mam} MA-M, {mal} MA-L, {bytes} bytes");
}

// REQ: OBS-025 — AC (5): the builder is reproducible (same CSV, same bytes) and its output
// reads back.
#[test]
fn obs_025_oui_builder_is_reproducible() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = root.join("presets/build-oui.py");
    let (ma_l, ma_m) = (
        root.join("presets/testdata/oui-sample.csv"),
        root.join("presets/testdata/mam-sample.csv"),
    );
    let tmp = tempfile::tempdir().unwrap();
    let run = |out: &Path| {
        std::process::Command::new("python3")
            .arg("-I")
            .arg(&script)
            .arg(&ma_l)
            .arg(&ma_m)
            .arg("-o")
            .arg(out)
            .output()
    };
    let (a, b) = (tmp.path().join("a.bin"), tmp.path().join("b.bin"));
    let Ok(first) = run(&a) else {
        eprintln!("no python3: builder check skipped");
        return;
    };
    assert!(first.status.success(), "{first:?}");
    assert!(run(&b).unwrap().status.success());
    let (x, y) = (std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    assert_eq!(x, y, "same CSV, same bytes");
    // Readable: the vendors come out normalized and sorted.
    let leaked: &'static [u8] = Box::leak(x.into_boxed_slice());
    assert_eq!(&leaked[..8], b"TTOUI1\0\0");
    let text = String::from_utf8_lossy(leaked);
    assert!(
        text.contains("Apple") && !text.contains("Apple, Inc."),
        "{text}"
    );
    assert!(text.contains("Roku") && !text.contains("Not a prefix"));
}

// REQ: OBS-025 — the shipped catalog: at least 40 signatures, unique, each with a kind.
#[test]
fn obs_025_the_catalog_ships_40_signatures() {
    let n = catalog::check_shipped().unwrap();
    let sigs = catalog::shipped();
    assert_eq!(sigs.len(), n);
    assert!(n >= 40, "{n} signatures");
    let mut ids: Vec<&str> = sigs.iter().map(|s| s.id.as_str()).collect();
    ids.dedup();
    assert_eq!(ids.len(), n, "sorted and unique");
    for s in sigs {
        assert_ne!(s.class, DeviceClass::Unknown, "{}", s.id);
        assert!(!s.domains.is_empty() && s.total_weight > 0.0, "{}", s.id);
    }
}

#[derive(Serialize)]
struct Case {
    device: &'static str,
    guess: score::Guess,
}

/// AC (1): the eight fixture devices, and AC (2)'s ablations.
fn fixture() -> Vec<(&'static str, Inputs)> {
    let apple = ["apple.com", "icloud.com", "mzstatic.com"];
    vec![
        (
            "roku",
            device(
                Some("D0:4D:2C:11:22:33"),
                &[],
                &["roku.com", "rokutime.com"],
            ),
        ),
        (
            "apple-tv",
            device(Some("F0:EE:7A:11:22:33"), &["Apple-TV"], &apple),
        ),
        (
            "ring-camera",
            device(Some("54:E0:19:11:22:33"), &[], &["ring.com"]),
        ),
        (
            "sonos",
            device(
                Some("78:28:CA:11:22:33"),
                &["Sonos-Kitchen"],
                &["sonos.com"],
            ),
        ),
        (
            "kasa-plug",
            device(Some("34:F7:16:11:22:33"), &["HS103"], &["tplinkcloud.com"]),
        ),
        (
            "iphone",
            // Phones use a private address on Wi-Fi: no vendor.
            device(Some("3A:11:22:33:44:55"), &["Pauls-iPhone"], &apple),
        ),
        (
            "windows-laptop",
            device(
                Some("E4:C7:67:11:22:33"),
                &["DESKTOP-4F2K9Q1"],
                &["msftconnecttest.com", "windowsupdate.com", "microsoft.com"],
            ),
        ),
        (
            "unknown-espressif",
            device(Some("D4:8A:FC:11:22:33"), &[], &["ntp.org", "example.com"]),
        ),
        // AC (2): without the MAC, and without the domains.
        (
            "roku-no-mac",
            device(None, &[], &["roku.com", "rokutime.com"]),
        ),
        (
            "roku-no-domains",
            device(Some("D0:4D:2C:11:22:33"), &[], &[]),
        ),
    ]
}

// REQ: OBS-025 — AC (1): the fixture scores byte-identically to the committed golden file
// (CI runs it on x86-64 and arm64).
#[test]
fn obs_025_identities_are_byte_identical_to_the_golden_file() {
    let sigs = catalog::shipped();
    let cases: Vec<Case> = fixture()
        .into_iter()
        .map(|(device, inp)| Case {
            device,
            guess: score(sigs, &inp),
        })
        .collect();
    let got = serde_json::to_string_pretty(&cases).unwrap() + "\n";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/identify-golden.json");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &got).unwrap();
    }
    let want = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        got, want,
        "rerun with UPDATE_GOLDEN=1 only for an intended change"
    );
}

// REQ: OBS-025 — AC (1), (2): the expected products and levels; the MAC raises confidence
// without deciding the product; without domains only the vendor is left.
#[test]
fn obs_025_fixture_products_and_ablations() {
    let sigs = catalog::shipped();
    let g: std::collections::BTreeMap<&str, score::Guess> = fixture()
        .into_iter()
        .map(|(n, inp)| (n, score(sigs, &inp)))
        .collect();
    let want = [
        ("roku", "roku-player", Level::Likely),
        ("apple-tv", "apple-appletv", Level::Likely),
        ("ring-camera", "ring-camera", Level::Likely),
        ("sonos", "sonos-speaker", Level::Likely),
        ("kasa-plug", "kasa-plug", Level::Likely),
        ("iphone", "apple-iphone", Level::Likely),
        ("windows-laptop", "windows-pc", Level::Likely),
    ];
    for (dev, id, level) in want {
        assert_eq!(
            g[dev].product_id.as_deref(),
            Some(id),
            "{dev}: {:?}",
            g[dev]
        );
        assert_eq!(g[dev].level, level, "{dev}: {:?}", g[dev]);
    }
    let unknown = &g["unknown-espressif"];
    assert_eq!(
        (unknown.level, unknown.product.as_deref()),
        (Level::Unknown, None)
    );
    assert!(
        unknown
            .vendor
            .as_deref()
            .unwrap()
            .to_lowercase()
            .contains("espressif")
    );

    let (full, no_mac) = (&g["roku"], &g["roku-no-mac"]);
    assert_eq!(
        no_mac.product_id, full.product_id,
        "same product without the MAC"
    );
    assert!(no_mac.score < full.score);
    let no_domains = &g["roku-no-domains"];
    assert_eq!(no_domains.level, Level::Unknown);
    assert!(no_domains.vendor.as_deref().unwrap().contains("Roku"));
}

// REQ: OBS-025 — a known vendor that isn't the maker halves the score (a Samsung TV running
// the Roku app); a tie with another kind of device isn't "likely".
#[test]
fn obs_025_vendor_penalty_and_ties() {
    let sigs = catalog::shipped();
    // 88:36:6C is TP-Link's: no Roku signature fits a TP-Link MAC well.
    let samsung_tv = device(
        Some("34:F7:16:11:22:33"),
        &[],
        &["roku.com", "rokutime.com"],
    );
    let g = score(sigs, &samsung_tv);
    assert_ne!(g.level, Level::Likely, "{g:?}");
    let apple_only = device(
        Some("F0:EE:7A:11:22:33"),
        &[],
        &["apple.com", "icloud.com", "mzstatic.com"],
    );
    let g = score(sigs, &apple_only);
    assert_eq!(
        g.level,
        Level::Possibly,
        "a tie between Apple devices: {g:?}"
    );
    assert!(g.runner_up.is_some());
}

#[test]
fn obs_025_globs_and_vendor_words() {
    assert!(glob("roku*", "Roku-Living-Room"));
    assert!(glob("*iphone*", "Pauls-iPhone"));
    assert!(glob("c1??*", "C100-cam"));
    assert!(!glob("roku*", "MyRoku"));
    assert!(vendor_matches("ring", "Ring LLC"));
    assert!(!vendor_matches("ring", "Sage Electronic Engineering"));
    assert!(vendor_matches("tp-link", "TP-LINK"));
    assert!(vendor_matches("sony", "Sony Interactive Entertainment"));
}

// REQ: OBS-025 — AC (3), (4): `kind` wins and says so; a group asking for the class is
// suggested unless the device is in it already.
#[test]
fn obs_025_overrides_and_group_suggestions() {
    let o = override_identity("192.0.2.9", DeviceClass::Camera, 1);
    assert_eq!(
        (o.source.as_str(), o.class.as_str()),
        ("override", "camera")
    );
    assert!(o.evidence.is_none());
    let cfg: Config = telltale_config::Loader::new()
        .toml_str(
            "t.toml",
            "[[group]]\nname = \"iot\"\ndevice_classes = [\"camera\", \"plug\"]\n",
        )
        .env(Vec::<(String, String)>::new())
        .load()
        .unwrap()
        .config;
    let none: Vec<Box<str>> = vec!["default".into()];
    let iot: Vec<Box<str>> = vec!["iot".into()];
    assert_eq!(
        suggested_group(&cfg, "camera", &none).as_deref(),
        Some("iot")
    );
    assert_eq!(suggested_group(&cfg, "camera", &iot), None);
    assert_eq!(suggested_group(&cfg, "tv", &none), None);
    assert_eq!(suggested_group(&cfg, "unknown", &none), None);
    // Two groups can't claim one kind.
    let two = telltale_config::Loader::new()
        .toml_str(
            "t.toml",
            "[[group]]\nname = \"a\"\ndevice_classes = [\"camera\"]\n[[group]]\nname = \"b\"\ndevice_classes = [\"camera\"]\n",
        )
        .env(Vec::<(String, String)>::new())
        .load();
    assert!(two.is_err());
}

// REQ: OBS-025 — a local file replaces a shipped signature by `id` and can remove one.
#[test]
fn obs_025_local_signatures_replace_and_remove() {
    let extra = r#"
[[device]]
id = "roku-player"
name = "Our Roku"
class = "tv"
domains = [{ name = "roku.com", weight = 1.0 }]
[[device]]
id = "sonos-speaker"
enabled = false
[[device]]
id = "our-thing"
name = "Our thing"
class = "appliance"
domains = [{ name = "thing.example", weight = 1.0 }]
"#;
    let sigs = catalog::with_extra(Some((extra, "local.toml"))).unwrap();
    let roku = sigs.iter().find(|s| s.id == "roku-player").unwrap();
    assert_eq!(
        (roku.name.as_str(), roku.class),
        ("Our Roku", DeviceClass::Tv)
    );
    assert!(sigs.iter().all(|s| s.id != "sonos-speaker"));
    assert!(sigs.iter().any(|s| s.id == "our-thing"));
    assert!(
        catalog::with_extra(Some((
            "[[device]]\nid = \"x\"\nname = \"x\"\ndomains = [{ name = \"a.b\", weight = 0 }]\n",
            "bad"
        )))
        .is_err()
    );
}

// REQ: OBS-025 — AC (6): per-device state stays within 1 KiB.
#[test]
fn obs_025_per_device_state_is_small() {
    let s = Seen {
        last_s: u64::MAX,
        domains: (0..MAX_DOMAINS)
            .map(|i| format!("{}{i:02}.example", "d".repeat(28)))
            .collect(),
        domains_s: u64::MAX,
    };
    let n = serde_json::to_vec(&s).unwrap().len() + "\"255.255.255.255\":".len();
    assert!(n <= 1024, "{n} bytes");
}

// REQ: OBS-025 — AC (8): two nodes' identities of one device agree after merging (the
// highest score wins, whichever order they arrive in).
#[test]
fn obs_025_merge_keeps_the_highest_confidence() {
    let a = DeviceIdentity {
        client: "192.0.2.5".into(),
        available: true,
        score: 0.5,
        node: Some("pi".into()),
        product_id: Some("roku-player".into()),
        ..DeviceIdentity::default()
    };
    let b = DeviceIdentity {
        score: 0.8,
        node: Some("k8s".into()),
        ..a.clone()
    };
    let one = merge([a.clone(), b.clone()]);
    let two = merge([b.clone(), a.clone()]);
    assert_eq!(one, two);
    assert_eq!(one[0].node.as_deref(), Some("k8s"));
}

// REQ: OBS-025 — AC (7): privacy level 1 (names hashed) or `enabled = false` turns it off, and
// the API says why; identities survive a restart (`devices.json`).
#[test]
fn obs_025_off_at_privacy_level_1_and_kept_across_restarts() {
    let load = |extra: &str| -> Config {
        telltale_config::Loader::new()
            .toml_str("t.toml", extra.to_owned())
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config
    };
    assert_eq!(off_reason(&load("")), None);
    assert_eq!(
        off_reason(&load("[telemetry.qlog]\nprivacy_level = 1\n")),
        Some("privacy_level")
    );
    assert_eq!(
        off_reason(&load("[identify]\nenabled = false\n")),
        Some("disabled")
    );

    let tmp = tempfile::tempdir().unwrap();
    let id = Identifier::open(tmp.path());
    id.set_snapshot(Snapshot {
        reason: Some("privacy_level"),
        ..Snapshot::default()
    });
    let got = id.get("192.0.2.7");
    assert_eq!(
        (got.available, got.reason.as_deref()),
        (false, Some("privacy_level"))
    );
    assert_eq!(id.list(), Vec::new());

    let roku = to_identity(
        "192.0.2.7",
        &score(catalog::shipped(), &fixture()[0].1),
        &fixture()[0].1,
        1,
    );
    id.set_snapshot(Snapshot {
        by_client: [("192.0.2.7".to_owned(), roku.clone())].into(),
        ..Snapshot::default()
    });
    assert_eq!(id.get("192.0.2.7"), roku, "with evidence");
    assert!(
        id.list()[0].evidence.is_none(),
        "the list leaves evidence out"
    );
    assert_eq!(id.get("192.0.2.8").reason.as_deref(), Some("not_seen"));
    id.save();
    let again = Identifier::open(tmp.path());
    assert_eq!(again.get("192.0.2.7"), roku, "back after a restart");
    assert_eq!(again.by_class()["streaming"], 1);
    assert_eq!(
        looks_like(&roku).as_deref(),
        Some("looks like a Roku player")
    );
}

// REQ: OBS-025 — AC (6): a pass over 1,024 devices (with the aggregator's top lists) stays
// under 50 ms in a release build.
#[test]
fn obs_025_a_pass_over_1024_devices_is_fast() {
    use telltale_telemetry::event::{Name, Record};
    use telltale_telemetry::{Proto, QueryEvent, Status};
    let mut agg = Aggregates::new();
    let names = [
        "www.roku.com",
        "api.rokutime.com",
        "a.sonos.com",
        "x.apple.com",
        "ntp.org",
    ];
    for c in 0..64u8 {
        for (i, n) in names.iter().enumerate() {
            let mut wire = Vec::new();
            for l in n.split('.') {
                wire.push(u8::try_from(l.len()).unwrap());
                wire.extend_from_slice(l.as_bytes());
            }
            wire.push(0);
            let e = QueryEvent {
                ts_us: 1_791_460_800_000_000 + u64::try_from(i).unwrap(),
                client_ip: std::net::Ipv4Addr::new(10, 0, 0, c)
                    .to_ipv6_mapped()
                    .octets(),
                client_ref: 0,
                group: 0,
                qtype: 1,
                qclass: 1,
                rcode: Some(0),
                status: Status::Forwarded,
                proto: Proto::Udp,
                flags: 0,
                rule: None,
                upstream: 0,
                attempts: 1,
                t_total_us: 10,
                t_upstream_us: 5,
                resp_size: 60,
                answers: 1,
            };
            agg.record(&Record::Query(e, Name::from_wire(&wire)));
        }
    }
    let sigs = catalog::shipped();
    let started = Instant::now();
    let observed = observe(&agg, 1024);
    let mut devices: Vec<Device> = (0..1024u32)
        .map(|i| {
            let ip: std::net::IpAddr = std::net::Ipv4Addr::from(0x0a00_0000 + i).into();
            let key = ip.to_string();
            let domains = observed.get(&key).map(|o| o.1.clone()).unwrap_or_default();
            Device {
                key,
                ip,
                mac: Some([0xD0, 0x4D, 0x2C, 0, 0, u8::try_from(i % 256).unwrap()]),
                names: vec![format!("device-{i}")],
                domains,
            }
        })
        .collect();
    merge_by_mac(&mut devices);
    let n = devices
        .iter()
        .map(|d| {
            let inp = inputs(d);
            to_identity(&d.key, &score(sigs, &inp), &inp, 1)
        })
        .filter(|i| i.level != "unknown")
        .count();
    let took = started.elapsed();
    println!("1,024 devices in {took:?} ({n} identified)");
    assert!(n > 0);
    if !cfg!(debug_assertions) {
        assert!(took.as_millis() < 50, "{took:?}");
    }
}
