use super::*;

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/updates")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn test_key() -> String {
    String::from_utf8(fixture("test.pub"))
        .unwrap()
        .trim()
        .to_owned()
}

// REQ: OPS-004 (ADR-046) — a signed index is read; a tampered one, or one signed with another
// key, is rejected.
#[test]
fn ops_004_index_signature_is_checked() {
    let ix = verified(
        &test_key(),
        &fixture("releases.json"),
        &fixture("releases.json.minisig"),
    )
    .unwrap();
    assert_eq!(ix.version, "0.1.0-edge.60");
    assert_eq!(ix.channel, "edge");
    assert!(
        verified(
            &test_key(),
            &fixture("releases-tampered.json"),
            &fixture("releases.json.minisig")
        )
        .is_err()
    );
    // The real release key doesn't vouch for the test index.
    assert!(
        verified(
            RELEASE_KEY,
            &fixture("releases.json"),
            &fixture("releases.json.minisig")
        )
        .is_err()
    );
}

// An older edge build sees the newer one; same version is up to date; a dev build is newer.
#[test]
fn ops_004_versions_compare_within_a_channel() {
    assert_eq!(compare("0.1.0-edge.47", "0.1.0-edge.60"), "available");
    assert_eq!(compare("0.1.0-edge.60", "0.1.0-edge.60"), "up_to_date");
    assert_eq!(compare("0.1.0-edge.61", "0.1.0-edge.60"), "newer");
    assert_eq!(compare("0.1.0", "0.1.1"), "available");
    assert_eq!(compare("0.2.0", "0.1.9"), "newer");
    assert_eq!(
        compare("0.1.0-edge.99", "0.1.0"),
        "available",
        "the release beats its edge builds"
    );
    assert_eq!(compare("dev", "0.1.0-edge.60"), "newer");
}

#[test]
fn ops_004_update_instructions_per_install_type() {
    assert!(how("native", "edge").contains("self-update --channel edge"));
    assert!(how("native", "stable").contains("self-update --restart"));
    assert!(how("container", "edge").contains(":edge"));
    assert!(how("helm", "stable").contains("helm upgrade"));
}
