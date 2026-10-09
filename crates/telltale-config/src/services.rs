//! Blocked services (REQ: FLT-012, `spec/05` §4; T7.9): one-click bundles of block rules
//! (a social network, a game, ...) shipped as data (`presets/services/*.toml`) and compiled into the
//! binary.
//!
//! A group lists the services it blocks (`blocked_services = ["tiktok"]`). [`expand`] adds
//! each service a group uses as an inline block list named `svc-<id>`, which the filter
//! compiles like any list; only the groups that name it get it.

use std::sync::OnceLock;

use serde::Deserialize;

use crate::schema::{Config, FilterList, ListKind, ListMatch};
use crate::types::SafeString;

/// List names beginning with this are blocked services (users' lists can't use it).
pub const PREFIX: &str = "svc-";

const FILES: &[&str] = &[
    include_str!("../../../presets/services/social.toml"),
    include_str!("../../../presets/services/video.toml"),
    include_str!("../../../presets/services/gaming.toml"),
    include_str!("../../../presets/services/messaging.toml"),
];

/// One service.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    /// Lowercase letters and digits, used in `blocked_services`.
    pub id: String,
    pub name: String,
    /// `social`, `video`, `music`, `gaming`, `messaging`, `dating`, `ai`, ...
    pub category: String,
    /// Adblock-style rules (`||domain^`).
    pub rules: Vec<String>,
}

#[derive(Deserialize)]
struct File {
    service: Vec<Service>,
}

/// Every service, in catalog order. A broken data file is a build-time mistake that the tests
/// catch, so it yields an empty catalog rather than a panic.
pub fn catalog() -> &'static [Service] {
    static CATALOG: OnceLock<Vec<Service>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        FILES
            .iter()
            .filter_map(|f| toml::from_str::<File>(f).ok())
            .flat_map(|f| f.service)
            .collect()
    })
}

/// The service with this ID.
pub fn find(id: &str) -> Option<&'static Service> {
    catalog().iter().find(|s| s.id == id)
}

/// The list a service compiles to.
pub fn list_name(id: &str) -> String {
    format!("{PREFIX}{id}")
}

/// The service a list name stands for, if it is one.
pub fn of_list(name: &str) -> Option<&'static Service> {
    name.strip_prefix(PREFIX).and_then(find)
}

/// `cfg` with an inline block list for every service a group blocks (once each, in catalog
/// order so the compiled snapshot doesn't change with group order).
pub fn expand(cfg: &Config) -> Config {
    let mut out = cfg.clone();
    for s in catalog() {
        let used = cfg
            .group
            .iter()
            .any(|g| g.blocked_services.iter().any(|b| b.as_str() == s.id))
            || cfg
                .schedule
                .iter()
                .any(|x| x.services.iter().any(|b| b.as_str() == s.id));
        let name = list_name(&s.id);
        if !used || cfg.list.iter().any(|l| l.name.as_str() == name) {
            continue;
        }
        let (Ok(name), Ok(rules)) = (
            SafeString::new(&name),
            s.rules
                .iter()
                .map(SafeString::new)
                .collect::<Result<Vec<_>, _>>(),
        ) else {
            continue;
        };
        out.list.push(FilterList {
            name,
            url: None,
            path: None,
            rules,
            kind: ListKind::Block,
            match_mode: ListMatch::Subtree,
            enabled: true,
            mode: crate::schema::ListMode::Enforce,
            refresh_secs: None,
            max_bytes: None,
            stale_after_days: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: FLT-012 — the catalog parses, IDs are unique and simple, every rule is `||domain^`.
    #[test]
    fn flt_012_catalog_is_well_formed() {
        assert_eq!(
            FILES
                .iter()
                .filter(|f| toml::from_str::<File>(f).is_err())
                .count(),
            0
        );
        let c = catalog();
        assert!(c.len() >= 25, "{} services", c.len());
        let mut ids: Vec<&str> = c.iter().map(|s| s.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), c.len(), "unique IDs");
        for s in c {
            assert!(
                s.id.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "{}",
                s.id
            );
            assert!(!s.rules.is_empty(), "{}", s.id);
            for r in &s.rules {
                let d = r.strip_prefix("||").and_then(|r| r.strip_suffix('^'));
                assert!(
                    d.is_some_and(|d| d.contains('.') && !d.contains(['/', '*', ' '])),
                    "{}: {r}",
                    s.id
                );
            }
        }
        assert_eq!(
            of_list("svc-tiktok").map(|s| s.name.as_str()),
            Some("TikTok")
        );
        assert!(of_list("tiktok").is_none());
    }
}
