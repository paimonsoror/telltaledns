//! REQ: NFR-003 (T10.6) — memory safety stays enforced by the build: the workspace forbids
//! `unsafe`, every crate inherits that, and the one crate allowed it (`telltale-net`, for
//! syscalls) denies an `unsafe` block without a `// SAFETY:` comment. Nothing in the sources
//! switches the lint back on.

use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn nfr_003_unsafe_is_forbidden_outside_telltale_net() {
    let root = workspace();
    let top = std::fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest");
    assert!(
        top.contains("unsafe_code = \"forbid\""),
        "the workspace lint table forbids unsafe"
    );
    let mut crates = 0;
    for e in std::fs::read_dir(root.join("crates"))
        .expect("crates/")
        .flatten()
    {
        let name = e.file_name().to_string_lossy().into_owned();
        let manifest =
            std::fs::read_to_string(e.path().join("Cargo.toml")).expect("crate manifest");
        crates += 1;
        if name == "telltale-net" {
            assert!(manifest.contains("unsafe_code = \"allow\""), "{name}");
            assert!(
                manifest.contains("undocumented_unsafe_blocks = \"deny\""),
                "{name}: every unsafe block needs a SAFETY comment"
            );
            continue;
        }
        assert!(
            manifest.contains("[lints]\nworkspace = true"),
            "{name} must inherit the workspace lints (unsafe_code = forbid)"
        );
        let mut files = Vec::new();
        sources(&e.path().join("src"), &mut files);
        for f in files {
            let text = std::fs::read_to_string(&f).unwrap_or_default();
            assert!(
                !text.contains("allow(unsafe_code)"),
                "{} turns unsafe back on",
                f.display()
            );
        }
    }
    assert!(crates >= 14, "found {crates} crates");
}
