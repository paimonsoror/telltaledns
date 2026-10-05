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
    lists(cfg, &mut r);
    clients(cfg, &mut r);
    cache_and_telemetry(cfg, &mut r);
    auth(cfg, &mut r);
    cluster(cfg, &mut r);
    r.warnings
}

// REQ: CLU-001 — the cluster port can't share an address with a listener (both default to
// 8443 for DoH and the cluster channel).
fn cluster(cfg: &Config, r: &mut Report<'_>) {
    if !matches!(cfg.cluster.config_source.as_str(), "file" | "gitops") {
        r.err("cluster.config_source", "must be `file` or `gitops`");
    }
    let Ok(addr) = cfg.cluster.listen.as_str().parse::<std::net::SocketAddr>() else {
        r.err(
            "cluster.listen",
            "must be an address and port, e.g. 0.0.0.0:8443",
        );
        return;
    };
    for (i, l) in cfg.listen.iter().enumerate() {
        if matches!(
            l.proto,
            crate::ListenProto::Tcp | crate::ListenProto::Dot | crate::ListenProto::Doh
        ) && l.addr.port() == addr.port()
        {
            r.warn(format!(
                "cluster.listen: listen[{i}] also uses TCP port {}; the cluster port opens only after `telltale cluster init|join`, and will then fail to bind",
                addr.port()
            ));
        }
    }
}

// REQ: API-003
fn auth(cfg: &Config, r: &mut Report<'_>) {
    let a = &cfg.auth;
    if a.session_ttl_hours == 0 || a.session_ttl_hours > 24 * 366 {
        r.err("auth.session_ttl_hours", "must be 1 to 8784 (a year)");
    }
    if a.session_idle_hours == 0 || a.session_idle_hours > a.session_ttl_hours {
        r.err(
            "auth.session_idle_hours",
            "must be at least 1 and at most auth.session_ttl_hours",
        );
    }
    if a.allow_insecure_basic {
        r.warn("auth.allow_insecure_basic: passwords sent with HTTP Basic cross the network in the clear");
    }
    oidc(&a.oidc, r);
}

// REQ: API-004
fn oidc(o: &crate::OidcConfig, r: &mut Report<'_>) {
    let url = o.public_url.as_str();
    if !o.provider.is_empty() {
        let ok = (url.starts_with("https://") || url.starts_with("http://"))
            && url.split_once("://").is_some_and(|(_, rest)| {
                !rest.is_empty() && !rest.trim_end_matches('/').contains('/')
            });
        if !ok {
            r.err(
                "auth.oidc.public_url",
                "required with providers: the address people open the UI at, like https://dns.example.com (no path)",
            );
        } else if url.starts_with("http://") {
            r.warn("auth.oidc.public_url: plain HTTP; providers may refuse http redirect URIs except for localhost");
        }
    }
    if o.disable_local_login && o.provider.is_empty() {
        r.err(
            "auth.oidc.disable_local_login",
            "needs at least one [[auth.oidc.provider]]: otherwise only break-glass admins could sign in",
        );
    }
    let mut ids = HashSet::new();
    for (n, p) in o.provider.iter().enumerate() {
        let at = format!("auth.oidc.provider[{n}]");
        let id = p.id.as_str();
        if id.is_empty()
            || id.len() > 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            r.err(format!("{at}.id"), "1-32 lowercase letters, digits, or -");
        }
        if !ids.insert(id) {
            r.err(format!("{at}.id"), format!("duplicate provider `{id}`"));
        }
        let issuer = p.issuer.as_str();
        if !(issuer.starts_with("https://") || issuer.starts_with("http://")) {
            r.err(format!("{at}.issuer"), "must be an http(s) URL");
        } else if issuer.starts_with("http://") {
            r.warn(format!(
                "{at}.issuer: plain HTTP is only safe for local testing"
            ));
        }
        if p.client_id.is_empty() {
            r.err(format!("{at}.client_id"), "must not be empty");
        }
        if p.client_secret.is_some() && p.client_secret_file.is_some() {
            r.err(
                format!("{at}.client_secret_file"),
                "set client_secret or client_secret_file, not both",
            );
        }
        if !p.scopes.iter().any(|s| s.as_str() == "openid") {
            r.err(format!("{at}.scopes"), "must include `openid`");
        }
        if p.role.is_empty() && p.default_role.is_none() {
            r.warn(format!(
                "{at}: no [[...role]] rules and no default_role: nobody can sign in with `{id}`"
            ));
        }
    }
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
        r.warn("upstream: none configured; only local, blocked, and cached answers can be served (on a cluster replica, the primary's upstreams apply)");
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

/// Most lists one snapshot can hold: list-ID bitsets are 1024 bits wide (`spec/05` §3.1).
pub const MAX_LISTS: usize = 1024;

/// A list name is a file-name-safe ID.
pub fn valid_list_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

// REQ: FLT-004 — list sources and fetch limits.
fn lists(cfg: &Config, r: &mut Report<'_>) {
    if cfg.list.len() > MAX_LISTS {
        r.err("list", format!("at most {MAX_LISTS} lists are supported"));
    }
    let mut names = HashSet::new();
    for (i, l) in cfg.list.iter().enumerate() {
        let p = format!("list[{i}]");
        let name = l.name.as_str();
        if !valid_list_name(name) {
            r.err(
                format!("{p}.name"),
                "use 1-64 lowercase letters, digits, `-` or `_`",
            );
        } else if !names.insert(name) {
            r.err(format!("{p}.name"), format!("duplicate list name `{name}`"));
        }
        let sources = usize::from(l.url.is_some())
            + usize::from(l.path.is_some())
            + usize::from(!l.rules.is_empty());
        if sources != 1 {
            r.err(&p, "set exactly one of `url`, `path`, or `rules`");
        }
        if let Some(url) = &l.url {
            match url.split_once("://") {
                Some(("https", rest)) if !rest.is_empty() => {}
                Some(("http", rest)) if !rest.is_empty() => r.warn(format!(
                    "{p}.url: plain http can be tampered with in transit; prefer https"
                )),
                _ => r.err(
                    format!("{p}.url"),
                    "must start with `https://` or `http://`",
                ),
            }
        }
        if let Some(path) = &l.path
            && path.is_empty()
        {
            r.err(format!("{p}.path"), "must not be empty");
        }
        if let Some(s) = l.refresh_secs
            && s < 900
        {
            r.err(
                format!("{p}.refresh_secs"),
                "must be at least 900 (15 minutes)",
            );
        }
        if let Some(b) = l.max_bytes
            && !(1024..=1 << 30).contains(&b.bytes())
        {
            r.err(format!("{p}.max_bytes"), "must be between 1KiB and 1GiB");
        }
    }
    let f = &cfg.filter;
    if f.refresh_secs < 900 {
        r.err("filter.refresh_secs", "must be at least 900 (15 minutes)");
    }
    if !(1..=16).contains(&f.fetch_concurrency) {
        r.err("filter.fetch_concurrency", "must be between 1 and 16");
    }
    if f.fetch_timeout_secs < 5 {
        r.err("filter.fetch_timeout_secs", "must be at least 5");
    }
    if f.fetch_retries > 10 {
        r.err("filter.fetch_retries", "must be at most 10");
    }
    if !(1024..=1 << 30).contains(&f.max_list_bytes.bytes()) {
        r.err("filter.max_list_bytes", "must be between 1KiB and 1GiB");
    }
    if f.compile_threads > 64 {
        r.err("filter.compile_threads", "must be at most 64 (0 = auto)");
    }
    if f.compile_memory.bytes() < 16 << 20 {
        r.err("filter.compile_memory", "must be at least 16MiB");
    }
}

/// A client `match` key, parsed (FLT-006).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MatchKey {
    Ip(std::net::IpAddr),
    Cidr(crate::Cidr),
    Mac([u8; 6]),
    ClientId(String),
}

impl MatchKey {
    /// Parses `192.168.1.20`, `10.0.5.0/24`, `aa:bb:cc:dd:ee:ff` (or `-` separated), or
    /// `id:<client-id>` (1–63 of `a-z0-9-`, the DoH path / SNI label form).
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some(id) = s.strip_prefix("id:") {
            let id = id.to_ascii_lowercase();
            if id.is_empty()
                || id.len() > 63
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(format!("client ID `{id}`: use 1-63 of a-z, 0-9, -"));
            }
            return Ok(Self::ClientId(id));
        }
        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        if s.contains('/') {
            return crate::Cidr::parse(s).map(Self::Cidr);
        }
        let parts: Vec<&str> = s.split([':', '-']).collect();
        if parts.len() == 6 {
            let mut mac = [0u8; 6];
            for (i, p) in parts.iter().enumerate() {
                mac[i] = u8::from_str_radix(p, 16)
                    .ok()
                    .filter(|_| p.len() == 2)
                    .ok_or_else(|| format!("invalid MAC `{s}`"))?;
            }
            return Ok(Self::Mac(mac));
        }
        Err(format!("`{s}` is not an IP, CIDR, MAC, or id:<client-id>"))
    }
}

// REQ: FLT-005, FLT-006 — groups, clients, identification.
fn clients(cfg: &Config, r: &mut Report<'_>) {
    let lists: HashSet<&str> = cfg.list.iter().map(|l| l.name.as_str()).collect();
    let mut groups = HashSet::from(["default"]);
    let mut declared = HashSet::new();
    let mut networks: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
    for (i, g) in cfg.group.iter().enumerate() {
        let p = format!("group[{i}]");
        if g.name.is_empty() {
            r.err(format!("{p}.name"), "must not be empty");
        } else if !declared.insert(g.name.as_str()) {
            r.err(format!("{p}.name"), format!("duplicate group `{}`", g.name));
        }
        groups.insert(g.name.as_str());
        for (j, l) in g.lists.iter().flatten().enumerate() {
            if !lists.contains(l.as_str()) {
                r.err(format!("{p}.lists[{j}]"), format!("unknown list `{l}`"));
            }
        }
        // REQ: FLT-008
        match (g.block_mode, g.block_ips.is_empty()) {
            (crate::BlockMode::CustomIp, true) => {
                r.err(
                    format!("{p}.block_ips"),
                    "required for block_mode = \"custom_ip\"",
                );
            }
            (crate::BlockMode::CustomIp, false) | (_, true) => {}
            (_, false) => r.warn(format!(
                "{p}.block_ips: only used with block_mode = \"custom_ip\""
            )),
        }
        if g.block_ttl > 86_400 {
            r.err(format!("{p}.block_ttl"), "must be at most 86400");
        }
        // REQ: FLT-005 (ADR-050)
        if let Some(c) = &g.color
            && !(c.len() == 7
                && c.starts_with('#')
                && c.as_str()[1..].bytes().all(|b| b.is_ascii_hexdigit()))
        {
            r.err(format!("{p}.color"), "must be a color like #3b82f6");
        }
        for (j, n) in g.networks.iter().enumerate() {
            if let Some(other) = networks.insert(n.to_string(), g.name.as_str()) {
                r.err(
                    format!("{p}.networks[{j}]"),
                    format!("{n} is already a network of group `{other}`"),
                );
            }
        }
    }
    if cfg.group.len() > 63 {
        r.err("group", "at most 63 groups (plus `default`)");
    }
    let mut names = HashSet::new();
    let mut keys: std::collections::HashMap<MatchKey, usize> = std::collections::HashMap::new();
    for (i, c) in cfg.client.iter().enumerate() {
        let p = format!("client[{i}]");
        if c.name.is_empty() {
            r.err(format!("{p}.name"), "must not be empty");
        } else if !names.insert(c.name.to_ascii_lowercase()) {
            r.err(
                format!("{p}.name"),
                format!("duplicate client `{}`", c.name),
            );
        }
        if c.match_keys.is_empty() {
            r.err(
                format!("{p}.match"),
                "needs at least one IP, CIDR, MAC, or id:",
            );
        }
        for (j, k) in c.match_keys.iter().enumerate() {
            match MatchKey::parse(k) {
                Err(e) => r.err(format!("{p}.match[{j}]"), e),
                Ok(key) => {
                    if let Some(other) = keys.insert(key, i) {
                        r.err(
                            format!("{p}.match[{j}]"),
                            format!("`{k}` already identifies client[{other}]"),
                        );
                    }
                }
            }
        }
        for (j, g) in c.groups.iter().enumerate() {
            if !groups.contains(g.as_str()) {
                r.err(format!("{p}.groups[{j}]"), format!("unknown group `{g}`"));
            }
        }
    }
    for (i, route) in cfg.route.iter().enumerate() {
        for g in &route.match_group {
            if !groups.contains(g.as_str()) {
                r.warn(format!(
                    "route[{i}].match_group: no group `{g}` is configured"
                ));
            }
        }
    }
    if cfg.clients.neighbor_refresh_secs < 5 {
        r.err("clients.neighbor_refresh_secs", "must be at least 5");
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

    let rl = &cfg.ratelimit;
    if rl.enabled && (rl.queries == 0 || rl.window_secs == 0) {
        r.err(
            "ratelimit",
            "queries and window_secs must be at least 1 when enabled",
        );
    }
    if rl.ipv4_prefix == 0 || rl.ipv4_prefix > 32 {
        r.err("ratelimit.ipv4_prefix", "must be between 1 and 32");
    }
    if rl.ipv6_prefix == 0 || rl.ipv6_prefix > 128 {
        r.err("ratelimit.ipv6_prefix", "must be between 1 and 128");
    }
    if cfg.access.allowed_networks.is_empty() {
        r.err(
            "access.allowed_networks",
            "empty: nobody could query (use [\"0.0.0.0/0\", \"::/0\"] to allow everyone)",
        );
    }
    if cfg.access.allowed_networks.iter().any(|n| n.prefix == 0) {
        r.warn("access.allowed_networks: allows every address; TelltaleDNS is an open resolver if reachable from the internet");
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
