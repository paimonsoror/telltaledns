//! This binary's identity (REQ: OPS-004, CLU-010; ADR-046), stamped at build time by
//! `build.rs`, plus how it was installed (from `TELLTALE_INSTALL`, which the image, the Helm
//! chart, and the systemd unit set).

/// `0.1.0` for a release, `0.1.0-edge.47` for a main build, `dev` for a local build.
pub(crate) const VERSION: &str = env!("TELLTALE_BUILD_VERSION");
pub(crate) const COMMIT: &str = env!("TELLTALE_BUILD_COMMIT");
pub(crate) const DATE: &str = env!("TELLTALE_BUILD_DATE");
/// `stable`, `edge`, or `dev`.
pub(crate) const CHANNEL: &str = env!("TELLTALE_BUILD_CHANNEL");
pub(crate) const TARGET: &str = env!("TELLTALE_BUILD_TARGET");
/// Everything on one line, for `--version`.
pub(crate) const LINE: &str = env!("TELLTALE_VERSION_LINE");

/// `native`, `container`, or `helm`.
pub(crate) fn install_type() -> &'static str {
    match std::env::var("TELLTALE_INSTALL").ok().as_deref() {
        Some("helm") => "helm",
        Some("container") => "container",
        Some("native") => "native",
        _ if std::path::Path::new("/.dockerenv").exists()
            || std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() =>
        {
            "container"
        }
        _ => "native",
    }
}

/// The build as the API shows it.
pub(crate) fn api() -> telltale_api::model::BuildInfo {
    telltale_api::model::BuildInfo {
        version: VERSION.into(),
        commit: COMMIT.into(),
        date: DATE.into(),
        channel: CHANNEL.into(),
        target: TARGET.into(),
        install: install_type().into(),
    }
}
