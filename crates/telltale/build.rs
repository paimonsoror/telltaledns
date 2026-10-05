//! Build identity (REQ: OPS-004, CLU-010; ADR-046): CI stamps the version, commit, date, and
//! channel through `TELLTALE_BUILD_*` environment variables; a local build is `dev` with the
//! checkout's commit, so it's never mistaken for a release.

use std::process::Command;

fn main() {
    for v in [
        "TELLTALE_BUILD_VERSION",
        "TELLTALE_BUILD_COMMIT",
        "TELLTALE_BUILD_DATE",
        "TELLTALE_BUILD_CHANNEL",
    ] {
        println!("cargo:rerun-if-env-changed={v}");
    }
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    let version = env("TELLTALE_BUILD_VERSION").unwrap_or_else(|| "dev".into());
    let commit = env("TELLTALE_BUILD_COMMIT")
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "--short=7", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        })
        .unwrap_or_else(|| "unknown".into());
    let commit: String = commit.chars().take(12).collect();
    let date = env("TELLTALE_BUILD_DATE").unwrap_or_else(|| "unknown".into());
    let channel = env("TELLTALE_BUILD_CHANNEL").unwrap_or_else(|| "dev".into());
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=TELLTALE_BUILD_VERSION={version}");
    println!("cargo:rustc-env=TELLTALE_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=TELLTALE_BUILD_DATE={date}");
    println!("cargo:rustc-env=TELLTALE_BUILD_CHANNEL={channel}");
    println!("cargo:rustc-env=TELLTALE_BUILD_TARGET={target}");
    println!(
        "cargo:rustc-env=TELLTALE_VERSION_LINE={version} (commit {commit}, built {date}, channel {channel}, {target})"
    );
    // A dev build's commit follows the checkout.
    if std::path::Path::new("../../.git/HEAD").exists() {
        println!("cargo:rerun-if-changed=../../.git/HEAD");
    }
}
