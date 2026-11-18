// REQ: OPS-011 (ADR-172) — a cluster package: each node's part is made and redacted on that node
// under one key, so one device has one label in every node's files and no real value crosses a node
// boundary; a part travels as compressed text; the package lists every node, the ones that didn't
// answer, and refuses what a node must not send.

use super::*;
use crate::archive::read_tar_gz;
use crate::classify::known_from_config;
use crate::package::{Options, Package};
use crate::pseudo::Category;
use serde_json::json;
use std::fmt::Write as _;

fn opts(key: u8) -> Options {
    Options {
        level: Level::Strict,
        key: [key; 32],
        reveal: Vec::new(),
        created_unix: 1_790_000_000,
        created: "2026-11-17T00:00:00Z".to_owned(),
        max_bytes: 1 << 20,
        keyed_labels: true,
    }
}

/// A node's part: its own name, a log that mentions the shared device by name and address.
fn part(node: &str, key: u8, log: &str) -> Part {
    let cfg = json!({
        "node": { "name": node },
        "client": [{ "name": "Living-TV", "match": ["192.168.1.20"] }],
    });
    let mut p = Package::new(opts(key), &known_from_config(&cfg)).unwrap();
    p.add_text("logs/node.log", "log", log, true);
    p.add_json("node/host.json", "node", &json!({ "cpus": 4 }));
    let who = p.redactor().name(Category::Node, node);
    p.finish_part(who)
}

fn text<'a>(entries: &'a [crate::archive::Entry], path: &str) -> &'a str {
    std::str::from_utf8(&entries.iter().find(|e| e.path == path).unwrap().data).unwrap()
}

fn assembled(results: Vec<NodeResult>) -> (Vec<crate::archive::Entry>, serde_json::Value) {
    let done = assemble(
        "2026-11-17T00:00:00Z",
        1_790_000_000,
        Level::Strict,
        1 << 18,
        results,
    );
    (read_tar_gz(&done.archive).unwrap(), done.manifest)
}

#[test]
fn ops_011_a_device_has_one_label_on_every_node_and_no_real_value_leaves_a_node() {
    let a = part(
        "pi-attic",
        7,
        "2026-11-17T01:00:00Z WARN upstream failed for Living-TV 192.168.1.20 on pi-attic\n",
    );
    let b = part(
        "homelab-pod-2",
        7,
        "2026-11-17T01:00:05Z WARN Living-TV (192.168.1.20) timed out on homelab-pod-2\n",
    );
    assert_ne!(a.node, b.node);
    assert!(
        a.node.starts_with("node-") && b.node.starts_with("node-"),
        "{} {}",
        a.node,
        b.node
    );
    let (la, lb) = (&a.files[0].text, &b.files[0].text);
    for t in [la, lb] {
        for real in ["Living-TV", "192.168.1.20", "pi-attic", "homelab-pod-2"] {
            assert!(!t.contains(real), "{real} survived in {t}");
        }
    }
    // The same device wears the same label on both nodes.
    let label = |t: &str| {
        t.split_whitespace()
            .find(|w| w.starts_with("device-"))
            .map(str::to_owned)
    };
    assert!(label(la).is_some());
    assert_eq!(label(la), label(lb));
    // Another key, another label.
    let other = part("pi-attic", 9, "WARN Living-TV is slow\n");
    assert_ne!(label(&other.files[0].text), label(la));
}

#[test]
fn ops_011_a_part_survives_the_wire_and_a_bad_one_is_refused() {
    let p = part("pi-attic", 7, "WARN a\nWARN b\n");
    let wire = p.to_wire();
    assert_eq!(Part::from_wire(&wire).unwrap(), p);
    assert!(Part::from_wire(b"not gzip at all, not even close").is_none());
    let mut bad = wire.clone();
    let last = bad.len() - 5;
    bad[last] ^= 0xff;
    assert!(
        Part::from_wire(&bad).is_none(),
        "a damaged part is not read"
    );
    assert!(
        Part::from_wire(&wire[..wire.len() / 2]).is_none(),
        "a cut one is not read"
    );
    // A part that unpacks to more than the limit is refused, whatever it says it is.
    let big = Part {
        node: "node-x".to_owned(),
        manifest: "{}".to_owned(),
        redactions: BTreeMap::new(),
        files: vec![PartFile {
            path: "a".to_owned(),
            text: "x".repeat(200_000),
        }],
    };
    let wire = big.to_wire();
    assert!(wire.len() < 2_000, "it compresses a lot: {}", wire.len());
    assert!(Part::from_wire_within(&wire, 10_000).is_none());
    assert!(Part::from_wire_within(&wire, 1 << 20).is_some());
}

#[test]
fn ops_011_a_part_is_cut_to_fit_the_wire() {
    let cfg = json!({ "node": { "name": "pi" } });
    let mut p = Package::new(opts(7), &known_from_config(&cfg)).unwrap();
    // Text that doesn't compress: 600 KB of pseudo-random hex lines.
    let mut s = String::new();
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    while s.len() < 600_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let _ = writeln!(s, "{x:016x} {x:016x}");
    }
    p.add_text("logs/node.log", "log", &s, true);
    let (part, wire) = p.finish_part_for_wire("node-1", 100_000);
    assert!(wire.len() <= 100_000, "{}", wire.len());
    assert_eq!(Part::from_wire(&wire).unwrap(), part);
    assert!(
        part.manifest.contains("cut to fit"),
        "the cut is in the part's manifest"
    );
    assert!(part.files[0].text.len() < 600_000);
}

#[test]
fn ops_011_a_cluster_package_lists_every_node_and_names_the_ones_that_are_missing() {
    let a = part("pi-attic", 7, "WARN one\n");
    let b = part("homelab-0", 7, "WARN two\n");
    let mut too_big = part("big-node", 7, "WARN three\n");
    too_big.files[0].text = "x".repeat(600_000);
    let (entries, manifest) = assembled(vec![
        NodeResult::Part(a.clone()),
        NodeResult::Part(b.clone()),
        NodeResult::Missing {
            node: "node-0123abcd".to_owned(),
            why: "did not answer in time".to_owned(),
        },
        NodeResult::Part(too_big),
    ]);
    // The summary, then the nodes' folders.
    assert_eq!(entries[0].path, "MANIFEST.json");
    assert_eq!(entries[1].path, "README.txt");
    assert!(
        entries
            .iter()
            .any(|e| e.path == format!("nodes/{}/logs/node.log", a.node))
    );
    assert!(
        entries
            .iter()
            .any(|e| e.path == format!("nodes/{}/MANIFEST.json", b.node))
    );
    assert_eq!(
        text(&entries, &format!("nodes/{}/logs/node.log", a.node)),
        a.files[0].text
    );
    let nodes = manifest["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 4);
    assert_eq!(nodes[0]["status"], "ok");
    assert_eq!(nodes[0]["files"], 2);
    assert_eq!(nodes[2]["status"], "missing");
    assert_eq!(nodes[2]["note"], "did not answer in time");
    assert_eq!(
        nodes[3]["status"], "missing",
        "a part over its share is left out: {nodes:?}"
    );
    assert!(
        nodes[3]["note"]
            .as_str()
            .unwrap()
            .contains("share of the size cap")
    );
    assert_eq!(manifest["kind"], "cluster");
    let readme = text(&entries, "README.txt");
    assert!(
        readme.contains("did not answer in time") && readme.contains(&a.node),
        "{readme}"
    );
    assert!(!entries.iter().any(|e| e.path.contains("big-node")));
}

#[test]
fn ops_011_a_node_cannot_write_outside_its_folder() {
    let mut p = part("pi-attic", 7, "WARN one\n");
    for bad in [
        "../../etc/passwd",
        "/abs/path",
        ".hidden",
        "a/../../b",
        "..\\..\\windows\\x",
        "C:/windows/x",
        "ok/.git/config",
    ] {
        p.files.push(PartFile {
            path: bad.to_owned(),
            text: "evil".to_owned(),
        });
    }
    p.node = "../evil node".to_owned();
    let (entries, manifest) = assembled(vec![NodeResult::Part(p)]);
    for e in &entries {
        assert!(!e.path.contains(".."), "{}", e.path);
        assert!(
            e.path == "MANIFEST.json" || e.path == "README.txt" || e.path.starts_with("nodes/"),
            "{}",
            e.path
        );
        assert!(!e.path.starts_with("nodes//"), "{}", e.path);
    }
    assert!(
        !entries.iter().any(|e| e.data == b"evil"),
        "no file that wasn't allowed"
    );
    assert!(
        manifest["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str().unwrap().contains("not allowed"))
    );
    assert_eq!(
        manifest["nodes"][0]["files"], 2,
        "only the node's own two files"
    );
}

#[test]
fn ops_011_two_nodes_with_one_name_get_two_folders() {
    let a = part("pi-attic", 7, "WARN one\n");
    let (entries, _) = assembled(vec![
        NodeResult::Part(a.clone()),
        NodeResult::Part(a.clone()),
    ]);
    let dirs: std::collections::BTreeSet<&str> = entries
        .iter()
        .filter_map(|e| {
            e.path
                .strip_prefix("nodes/")
                .and_then(|r| r.split('/').next())
        })
        .collect();
    assert_eq!(dirs.len(), 2, "{dirs:?}");
}
