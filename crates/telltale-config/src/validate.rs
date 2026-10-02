//! Semantic validation beyond what serde enforces. Collects *every* problem, each with its path.

use std::collections::HashSet;

use crate::ConfigError;
use crate::schema::{CONFIG_VERSION, Config, HttpVersion, Strategy};

/// URL schemes accepted for upstreams (`spec/04` §2).
pub const UPSTREAM_SCHEMES: &[&str] = &[
    "udp",
    "tcp",
    "tls",
    "https",
    "h3",
    "quic",
    "sdns",
    "recursive",
    "unix",
    "exec",
];

/// Accumulates errors and warnings during validation.
struct Report<'a> {
    errors: &'a mut Vec<ConfigError>,
    warnings: Vec<String>,
}

impl Report<'_> {
    fn err(&mut self, path: impl Into<String>, msg: impl std::fmt::Display) {
        self.errors.push(ConfigError::new(path, msg));
    }
    fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }
}

/// Returns warnings; pushes errors.
pub(crate) fn validate(cfg: &Config, errors: &mut Vec<ConfigError>) -> Vec<String> {
    let mut r = Report {
        errors,
        warnings: Vec::new(),
    };
    node(cfg, &mut r);
    listeners(cfg, &mut r);
    let upstreams = upstreams(cfg, &mut r);
    let groups = groups(cfg, &upstreams, &mut r);
    routes(cfg, &groups, &mut r);
    cache_and_telemetry(cfg, &mut r);
    r.warnings
}

fn node(cfg: &Config, r: &mut Report<'_>) {
    if cfg.config_version != CONFIG_VERSION {
        r.err(
            "config_version",
            format!(
                "unsupported version {} (this build supports {CONFIG_VERSION})",
                cfg.config_version
            ),
        );
    }
    if cfg.node.workers > 1024 {
        r.err("node.workers", "must be at most 1024 (0 = auto)");
    }
    if cfg.node.data_dir.is_empty() {
        r.err("node.data_dir", "must not be empty");
    }
}

fn listeners(cfg: &Config, r: &mut Report<'_>) {
    if cfg.listen.is_empty() {
        r.err("listen", "at least one listener is required");
    }
    let mut seen = HashSet::new();
    for (i, l) in cfg.listen.iter().enumerate() {
        let p = format!("listen[{i}]");
        if !seen.insert((l.proto, l.addr)) {
            r.err(
                &p,
                format!("duplicate listener {:?} on {}", l.proto, l.addr),
            );
        }
        if l.proto.needs_tls() && l.tls.is_none() {
            r.err(
                format!("{p}.tls"),
                "required for dot, doh, doh3, and doq listeners",
            );
        }
        if !l.proto.needs_tls() && l.tls.is_some() {
            r.err(
                format!("{p}.tls"),
                "only valid for dot, doh, doh3, and doq listeners",
            );
        }
        if let Some(path) = &l.path {
            if !l.proto.is_http() {
                r.err(format!("{p}.path"), "only valid for doh and doh3 listeners");
            } else if !path.starts_with('/') {
                r.err(format!("{p}.path"), "must start with `/`");
            }
        }
        if l.proxy_protocol && !l.proto.is_tcp_based() {
            r.err(
                format!("{p}.proxy_protocol"),
                "only valid for tcp, dot, and doh listeners",
            );
        }
    }
}

/// Validates upstreams and returns the set of their names.
fn upstreams<'c>(cfg: &'c Config, r: &mut Report<'_>) -> HashSet<&'c str> {
    let mut names = HashSet::new();
    for (i, u) in cfg.upstream.iter().enumerate() {
        let p = format!("upstream[{i}]");
        if u.name.is_empty() {
            r.err(format!("{p}.name"), "must not be empty");
        } else if !names.insert(u.name.as_str()) {
            r.err(
                format!("{p}.name"),
                format!("duplicate upstream name `{}`", u.name),
            );
        }
        match u.url.split_once("://").map(|(s, _)| s) {
            Some(s) if UPSTREAM_SCHEMES.contains(&s) => {
                if u.http_version != HttpVersion::Auto && s != "https" {
                    r.err(
                        format!("{p}.http_version"),
                        "only valid for https:// upstreams",
                    );
                }
                if s != "https" && s != "h3" && !u.headers.is_empty() {
                    r.err(format!("{p}.headers"), "only valid for DoH upstreams");
                }
            }
            Some(s) => r.err(
                format!("{p}.url"),
                format!(
                    "unsupported scheme `{s}://` (expected one of: {})",
                    UPSTREAM_SCHEMES.join(", ")
                ),
            ),
            None => r.err(
                format!("{p}.url"),
                "must include a scheme, e.g. `udp://9.9.9.9` or `https://dns.quad9.net/dns-query`",
            ),
        }
        if u.weight == 0 {
            r.err(format!("{p}.weight"), "must be at least 1");
        }
        if u.timeout_ms == 0 || u.timeout_ms > 10_000 {
            r.err(format!("{p}.timeout_ms"), "must be between 1 and 10000");
        }
        if u.pool_size == 0 {
            r.err(format!("{p}.pool_size"), "must be at least 1");
        }
        if u.tls_insecure_skip_verify {
            r.warn(format!(
                "{p}.tls_insecure_skip_verify: certificate verification is DISABLED for upstream `{}`",
                u.name
            ));
        }
    }
    if cfg.upstream.is_empty() {
        r.warn("upstream: none configured; only local, blocked, and cached answers can be served");
    }
    names
}

/// Validates upstream groups and returns the set of their names.
fn groups<'c>(cfg: &'c Config, upstreams: &HashSet<&str>, r: &mut Report<'_>) -> HashSet<&'c str> {
    let mut groups = HashSet::new();
    for (i, g) in cfg.upstream_group.iter().enumerate() {
        let p = format!("upstream_group[{i}]");
        if g.name.is_empty() {
            r.err(format!("{p}.name"), "must not be empty");
        } else if !groups.insert(g.name.as_str()) {
            r.err(
                format!("{p}.name"),
                format!("duplicate upstream group `{}`", g.name),
            );
        }
        if g.members.is_empty() {
            r.err(format!("{p}.members"), "must list at least one upstream");
        }
        for (j, m) in g.members.iter().enumerate() {
            if !upstreams.contains(m.as_str()) {
                r.err(
                    format!("{p}.members[{j}]"),
                    format!("unknown upstream `{m}`"),
                );
            }
        }
        if g.strategy == Strategy::Parallel
            && (g.parallel_fanout < 2 || usize::from(g.parallel_fanout) > g.members.len())
        {
            r.err(
                format!("{p}.parallel_fanout"),
                "must be between 2 and the number of members for strategy `parallel`",
            );
        }
    }
    if !cfg.upstream.is_empty() && !groups.contains("default") {
        r.warn(
            "upstream_group: no group named `default`; queries that match no route have no upstream",
        );
    }
    groups
}

fn routes(cfg: &Config, groups: &HashSet<&str>, r: &mut Report<'_>) {
    for (i, route) in cfg.route.iter().enumerate() {
        let p = format!("route[{i}]");
        if !groups.contains(route.upstream_group.as_str()) {
            r.err(
                format!("{p}.upstream_group"),
                format!("unknown upstream group `{}`", route.upstream_group),
            );
        }
        if route.match_suffix.is_empty()
            && route.match_group.is_empty()
            && route.match_qtype.is_empty()
        {
            r.err(
                &p,
                "needs at least one of match_suffix, match_group, match_qtype",
            );
        }
        for (j, s) in route.match_suffix.iter().enumerate() {
            if s.is_empty() || s.len() > 253 || s.contains(' ') {
                r.err(
                    format!("{p}.match_suffix[{j}]"),
                    format!("invalid domain `{s}`"),
                );
            }
        }
    }
}

fn cache_and_telemetry(cfg: &Config, r: &mut Report<'_>) {
    let c = &cfg.cache;
    if c.min_ttl > c.max_ttl {
        r.err("cache.min_ttl", "must not exceed cache.max_ttl");
    }
    if c.prefetch && !(1..=99).contains(&c.prefetch_threshold_pct) {
        r.err("cache.prefetch_threshold_pct", "must be between 1 and 99");
    }
    if c.max_bytes.bytes() < 1024 * 1024 {
        r.err("cache.max_bytes", "must be at least 1MiB");
    }

    let t = &cfg.telemetry;
    if !t.ring_slots.is_power_of_two() || t.ring_slots < 1024 {
        r.err(
            "telemetry.ring_slots",
            "must be a power of two and at least 1024",
        );
    }
    if t.qlog.privacy_level > 3 {
        r.err("telemetry.qlog.privacy_level", "must be 0, 1, 2, or 3");
    }
    if t.qlog.retention_days == 0 {
        r.err("telemetry.qlog.retention_days", "must be at least 1");
    }
    if t.qlog.flush_interval_secs == 0 {
        r.err("telemetry.qlog.flush_interval_secs", "must be at least 1");
    }
}
