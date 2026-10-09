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
    rules(cfg, &mut r);
    services(cfg, &mut r);
    schedules(cfg, &mut r);
    alerts(cfg, &mut r);
    slo(cfg, &mut r);
    sinks(cfg, &mut r);
    routers(cfg, &mut r);
    rewrites(cfg, &mut r);
    zones(cfg, &mut r);
    otlp(cfg, &mut r);
    cache_and_telemetry(cfg, &mut r);
    auth(cfg, &mut r);
    cluster(cfg, &mut r);
    r.warnings
}

// REQ: UPS-011 (T7.16) — TLS settings only for TLS upstreams; both halves of a client
// certificate; pins that look like base64 SHA-256.
fn upstream_tls(u: &crate::schema::Upstream, s: &str, p: &str, r: &mut Report<'_>) {
    let tls = matches!(s, "tls" | "https" | "h3" | "quic");
    for (set, what) in [
        (!u.spki_pins.is_empty(), "spki_pins"),
        (u.tls_ca.is_some(), "tls_ca"),
        (u.tls_client_cert.is_some(), "tls_client_cert"),
    ] {
        if set && !tls {
            r.err(
                format!("{p}.{what}"),
                "only for TLS upstreams (tls://, https://, h3://, quic://)",
            );
        }
    }
    if u.tls_client_cert.is_some() != u.tls_client_key.is_some() {
        r.err(
            format!("{p}.tls_client_key"),
            "set both tls_client_cert and tls_client_key",
        );
    }
    for (j, pin) in u.spki_pins.iter().enumerate() {
        let ok = pin.len() == 44
            && pin.ends_with('=')
            && pin[..43]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
        if !ok {
            r.err(
                format!("{p}.spki_pins[{j}]"),
                "a base64 SHA-256 (44 characters, ending in =)",
            );
        }
    }
}

// REQ: OBS-010 (T7.13) — event sinks: unique names and what each kind needs.
// REQ: DNS-018 (T7.22) — zones: a valid, unique apex; known groups; records under it.
fn zones(cfg: &Config, r: &mut Report<'_>) {
    let mut apexes = HashSet::new();
    let lower = |s: &str| s.trim_end_matches('.').to_ascii_lowercase();
    for (i, z) in cfg.zone.iter().enumerate() {
        let apex = lower(&z.name);
        if apex.is_empty() || apex.split('.').any(str::is_empty) {
            r.err(format!("zone[{i}].name"), "a domain, e.g. home.example.com");
        }
        let key = (apex.clone(), {
            let mut g: Vec<String> = z
                .groups
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            g.sort();
            g
        });
        if !apexes.insert(key) {
            r.err(
                format!("zone[{i}].name"),
                "the same zone twice for the same groups",
            );
        }
        if z.file.is_none() && z.record.is_empty() {
            r.err(format!("zone[{i}]"), "give a file or records");
        }
        for (j, g) in z.groups.iter().enumerate() {
            if g.as_str() != "default" && !cfg.group.iter().any(|x| x.name == *g) {
                r.err(
                    format!("zone[{i}].groups[{j}]"),
                    format!("no group `{}`", g.as_str()),
                );
            }
        }
        for (j, rec) in z.record.iter().enumerate() {
            let n = lower(rec.name.trim_start_matches("*."));
            if n != apex && !n.ends_with(&format!(".{apex}")) {
                r.err(
                    format!("zone[{i}].record[{j}].name"),
                    format!("not under {apex}"),
                );
            }
        }
    }
}

// REQ: FLT-014, FLT-015 (T7.20) — rewrites and rebinding exceptions are names; a rewrite's
// answer is an address or a name.
fn rewrites(cfg: &Config, r: &mut Report<'_>) {
    let name_ok = |s: &str| {
        let s = s.trim_end_matches('.');
        !s.is_empty()
            && s.len() <= 253
            && s.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && l.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
    };
    for (i, g) in cfg.group.iter().enumerate() {
        for (j, a) in g.rebinding_allow.iter().enumerate() {
            if !name_ok(a) {
                r.err(
                    format!("group[{i}].rebinding_allow[{j}]"),
                    "a domain, e.g. plex.direct",
                );
            }
        }
        // REQ: DNS-016 (T7.21)
        // REQ: DNS-016 (T9.10)
        if !g.dns64 && !g.dns64_exclude.is_empty() {
            r.err(
                format!("group[{i}].dns64_exclude"),
                "only with `dns64 = true`",
            );
        }
        if let Some(p) = g.dns64_prefix
            && (!p.addr.is_ipv6() || p.prefix != 96)
        {
            r.err(
                format!("group[{i}].dns64_prefix"),
                "an IPv6 /96, e.g. 64:ff9b::/96",
            );
        }
        let mut seen = HashSet::new();
        for (j, w) in g.rewrite.iter().enumerate() {
            let d = w.domain.trim_start_matches("*.");
            if !name_ok(d) {
                r.err(
                    format!("group[{i}].rewrite[{j}].domain"),
                    "a domain, or *.domain for every name under it",
                );
            } else if !seen.insert(w.domain.to_ascii_lowercase()) {
                r.err(
                    format!("group[{i}].rewrite[{j}].domain"),
                    "rewritten twice in this group",
                );
            }
            if w.answer.parse::<std::net::IpAddr>().is_err() && !name_ok(&w.answer) {
                r.err(
                    format!("group[{i}].rewrite[{j}].answer"),
                    "an IP address or a domain",
                );
            }
        }
    }
}

// REQ: T8.2 — router integrations: unique names, http(s) URLs, the credentials each kind needs.
fn routers(cfg: &Config, r: &mut Report<'_>) {
    let mut names = HashSet::new();
    for (i, x) in cfg.router.iter().enumerate() {
        let p = format!("router[{i}]");
        if x.name.is_empty() || !names.insert(x.name.as_str()) {
            r.err(format!("{p}.name"), "must be unique and not empty");
        }
        if !(x.url.starts_with("https://") || x.url.starts_with("http://")) {
            r.err(
                format!("{p}.url"),
                "an https:// URL, e.g. https://192.168.1.1",
            );
        }
        match x.kind {
            crate::RouterKind::Unifi => {
                if x.api_key_file.is_none() && (x.username.is_none() || x.password_file.is_none()) {
                    r.err(
                        p.clone(),
                        "UniFi needs api_key_file, or username and password_file",
                    );
                }
            }
            crate::RouterKind::Opnsense => {
                if x.api_key_file.is_none() || x.api_secret_file.is_none() {
                    r.err(p.clone(), "OPNsense needs api_key_file and api_secret_file");
                }
            }
        }
        if x.interval_secs < 30 {
            r.err(format!("{p}.interval_secs"), "at least 30 seconds");
        }
        if x.tls_insecure_skip_verify {
            r.warn(format!("{p}.tls_insecure_skip_verify: the router's certificate isn't checked (prefer tls_ca)"));
        }
    }
}

// REQ: OBS-006 (T7.17) — OTLP: an http(s) endpoint, a sane interval.
fn otlp(cfg: &Config, r: &mut Report<'_>) {
    let o = &cfg.telemetry.otlp;
    if let Some(e) = &o.endpoint
        && !(e.starts_with("http://") || e.starts_with("https://"))
    {
        r.err(
            "telemetry.otlp.endpoint",
            "an http:// or https:// URL, e.g. http://otel-collector:4318",
        );
    }
    if o.interval_secs < 5 {
        r.err("telemetry.otlp.interval_secs", "at least 5 seconds");
    }
    // REQ: OBS-007 (T7.18)
    let d = &cfg.telemetry.dnstap;
    if d.socket.is_some() && d.address.is_some() {
        r.err("telemetry.dnstap", "set socket or address, not both");
    }
    if let Some(a) = &d.address {
        let hp = a.strip_prefix("tcp://").unwrap_or(a);
        if !hp
            .rsplit_once(':')
            .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok())
        {
            r.err("telemetry.dnstap.address", "use tcp://host:port");
        }
    }
    if d.sample_every == 0 {
        r.err("telemetry.dnstap.sample_every", "at least 1 (every query)");
    }
    if d.buffer < 100 {
        r.err("telemetry.dnstap.buffer", "at least 100");
    }
}

fn sinks(cfg: &Config, r: &mut Report<'_>) {
    use crate::SinkKind;
    const STATUSES: &[&str] = &[
        "cached",
        "forwarded",
        "stale",
        "local",
        "special",
        "blocked",
        "refused",
        "rate_limited",
        "malformed",
        "servfail",
        "dropped",
    ];
    let mut names = HashSet::new();
    for (i, s) in cfg.telemetry.sink.iter().enumerate() {
        let p = format!("telemetry.sink[{i}]");
        if s.name.is_empty() || !names.insert(s.name.as_str()) {
            r.err(format!("{p}.name"), "must be unique and not empty");
        }
        match s.kind {
            SinkKind::File => {
                if s.path.as_ref().is_none_or(|x| x.is_empty()) {
                    r.err(format!("{p}.path"), "a file sink needs `path`");
                }
                if s.max_bytes.bytes() < 1024 * 1024 {
                    r.err(format!("{p}.max_bytes"), "at least 1 MiB");
                }
            }
            SinkKind::Syslog => {
                let a = s.address.as_ref().map_or("", |x| x.as_str());
                let ok = a
                    .strip_prefix("udp://")
                    .or_else(|| a.strip_prefix("tcp://"))
                    .or_else(|| a.strip_prefix("tls://"))
                    .is_some_and(|hp| {
                        hp.rsplit_once(':')
                            .is_some_and(|(h, port)| !h.is_empty() && port.parse::<u16>().is_ok())
                    });
                if !ok {
                    r.err(
                        format!("{p}.address"),
                        "use udp://host:port, tcp://host:port, or tls://host:port",
                    );
                }
                // REQ: OBS-010 (T9.11)
                if s.tls_ca.is_some() && !a.starts_with("tls://") {
                    r.err(format!("{p}.tls_ca"), "only for tls:// syslog addresses");
                }
                if s.facility > 23 {
                    r.err(format!("{p}.facility"), "a syslog facility from 0 to 23");
                }
            }
            SinkKind::Webhook => {
                let u = s.url.as_ref().map_or("", |x| x.as_str());
                if !(u.starts_with("https://") || u.starts_with("http://")) {
                    r.err(
                        format!("{p}.url"),
                        "a webhook sink needs an http:// or https:// `url`",
                    );
                }
                if s.batch == 0 || s.batch > 10_000 {
                    r.err(format!("{p}.batch"), "from 1 to 10000");
                }
                if s.flush_secs == 0 {
                    r.err(format!("{p}.flush_secs"), "at least 1");
                }
                // REQ: OBS-010 (T9.11)
                if s.spill_max_bytes.is_some_and(|b| b.bytes() < 1024 * 1024) {
                    r.err(format!("{p}.spill_max_bytes"), "at least 1 MiB");
                }
            }
        }
        if s.spill_max_bytes.is_some() && s.kind != SinkKind::Webhook {
            r.err(format!("{p}.spill_max_bytes"), "only for webhook sinks");
        }
        if s.format == crate::SinkFormat::OtlpLogs && s.kind != SinkKind::Webhook {
            r.err(format!("{p}.format"), "otlp_logs is for webhook sinks");
        }
        if s.max_buffer < 100 {
            r.err(format!("{p}.max_buffer"), "at least 100");
        }
        for (j, st) in s.statuses.iter().enumerate() {
            if !STATUSES.contains(&st.as_str()) {
                r.err(
                    format!("{p}.statuses[{j}]"),
                    format!(
                        "unknown status `{}` (one of {})",
                        st.as_str(),
                        STATUSES.join(", ")
                    ),
                );
            }
        }
    }
}

// REQ: OBS-010 (T7.12) — alerts: unique names, rules sent to destinations that exist,
// http(s) URLs, a sane interval and threshold.
fn alerts(cfg: &Config, r: &mut Report<'_>) {
    let a = &cfg.alerts;
    if a.interval_secs < 5 {
        r.err("alerts.interval_secs", "at least 5 seconds");
    }
    let mut names = HashSet::new();
    for (i, d) in a.destination.iter().enumerate() {
        let p = format!("alerts.destination[{i}]");
        if d.name.is_empty() || !names.insert(d.name.as_str()) {
            r.err(format!("{p}.name"), "must be unique and not empty");
        }
        let u = d.url.as_str();
        if d.kind == crate::schema::AlertKind::Email {
            // REQ: OBS-010 (T9.4)
            if !(u.starts_with("smtp://")
                || u.starts_with("smtps://")
                || u.starts_with("smtp+insecure://"))
            {
                r.err(
                    format!("{p}.url"),
                    "use smtp://host:587 (STARTTLS), smtps://host:465 (TLS), or smtp+insecure://host:port (a local catcher)",
                );
            }
            if d.from.as_ref().is_none_or(|f| !f.as_str().contains('@')) {
                r.err(format!("{p}.from"), "the sender's email address");
            }
            if d.to.is_empty() || d.to.iter().any(|t| !t.as_str().contains('@')) {
                r.err(format!("{p}.to"), "one or more email addresses");
            }
            if d.username.is_some() != d.password_file.is_some() {
                r.err(
                    format!("{p}.password_file"),
                    "username and password_file go together",
                );
            }
            if d.username.is_some() && u.starts_with("smtp+insecure://") {
                r.err(
                    format!("{p}.url"),
                    "a password is never sent unencrypted: use smtp:// or smtps://",
                );
            }
        } else if !(u.starts_with("https://") || u.starts_with("http://")) {
            r.err(format!("{p}.url"), "use an http:// or https:// URL");
        }
    }
    let mut rules = HashSet::new();
    for (i, x) in a.rule.iter().enumerate() {
        let p = format!("alerts.rule[{i}]");
        if x.name.is_empty() || !rules.insert(x.name.as_str()) {
            r.err(format!("{p}.name"), "must be unique and not empty");
        }
        if x.to.is_empty() {
            r.err(format!("{p}.to"), "name at least one destination");
        }
        for (j, t) in x.to.iter().enumerate() {
            if !a.destination.iter().any(|d| d.name == *t) {
                r.err(
                    format!("{p}.to[{j}]"),
                    format!("no destination `{}`", t.as_str()),
                );
            }
        }
        if let Some(t) = x.threshold
            && !(0.0..=100.0).contains(&t)
        {
            r.err(format!("{p}.threshold"), "a percentage from 0 to 100");
        }
    }
}

// REQ: OBS-016 (T11.1) — objectives below 100% (a 100% target leaves no budget to burn), a
// threshold Prometheus can compute too, a window the rollups hold.
fn slo(cfg: &Config, r: &mut Report<'_>) {
    let s = &cfg.slo;
    for (key, t) in [
        ("slo.availability_target", s.availability_target),
        ("slo.latency_target", s.latency_target),
    ] {
        if !(50.0..100.0).contains(&t) {
            r.err(
                key,
                "a percentage from 50 up to (not including) 100, e.g. 99.9",
            );
        }
    }
    if !crate::schema::SLO_LATENCY_MS.contains(&s.latency_ms) {
        r.err(
            "slo.latency_ms",
            format!(
                "one of {} (the /metrics histogram's bucket bounds)",
                crate::schema::SLO_LATENCY_MS
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    if !(1..=90).contains(&s.window_days) {
        r.err("slo.window_days", "from 1 to 90 days");
    }
}

// REQ: FLT-010 (T7.10) — schedules: unique names, known lists and services for their
// action, readable windows, and groups that name schedules that exist.
fn schedules(cfg: &Config, r: &mut Report<'_>) {
    use crate::schema::ScheduleAction;
    let mut names = HashSet::new();
    for (i, s) in cfg.schedule.iter().enumerate() {
        let p = format!("schedule[{i}]");
        if s.name.is_empty() || !names.insert(s.name.as_str()) {
            r.err(format!("{p}.name"), "must be unique and not empty");
        }
        match s.action {
            ScheduleAction::EnableLists if s.lists.is_empty() => {
                r.err(
                    format!("{p}.lists"),
                    "`enable_lists` needs at least one list",
                );
            }
            ScheduleAction::BlockServices if s.services.is_empty() => {
                r.err(
                    format!("{p}.services"),
                    "`block_services` needs at least one service",
                );
            }
            _ => {}
        }
        for (j, l) in s.lists.iter().enumerate() {
            if !cfg.list.iter().any(|x| x.name == *l) {
                r.err(
                    format!("{p}.lists[{j}]"),
                    format!("no list `{}`", l.as_str()),
                );
            }
        }
        for (j, x) in s.services.iter().enumerate() {
            if crate::services::find(x.as_str()).is_none() {
                r.err(
                    format!("{p}.services[{j}]"),
                    format!("no service `{}` (see `telltale services list`)", x.as_str()),
                );
            }
        }
        if s.window.is_empty() {
            r.err(format!("{p}.window"), "needs at least one window");
        }
        for (j, w) in s.window.iter().enumerate() {
            if let Err(e) = crate::schedule::parse_window(w) {
                r.err(format!("{p}.window[{j}]"), e);
            }
        }
        if let Some(tz) = &s.tz
            && let Err(e) = crate::schedule::time_zone(Some(tz.as_str()))
        {
            r.err(format!("{p}.tz"), e);
        }
    }
    for (i, g) in cfg.group.iter().enumerate() {
        for (j, s) in g.schedules.iter().enumerate() {
            if !cfg.schedule.iter().any(|x| x.name == *s) {
                r.err(
                    format!("group[{i}].schedules[{j}]"),
                    format!("no schedule `{}`", s.as_str()),
                );
            }
        }
    }
}

// REQ: FLT-012 (T7.9) — blocked services exist; `svc-` list names are theirs.
fn services(cfg: &Config, r: &mut Report<'_>) {
    for (i, g) in cfg.group.iter().enumerate() {
        for (j, s) in g.blocked_services.iter().enumerate() {
            if crate::services::find(s.as_str()).is_none() {
                r.err(
                    format!("group[{i}].blocked_services[{j}]"),
                    format!("no service `{}` (see `telltale services list`)", s.as_str()),
                );
            }
        }
    }
    for (i, l) in cfg.list.iter().enumerate() {
        if l.name.as_str().starts_with(crate::services::PREFIX) {
            r.err(
                format!("list[{i}].name"),
                format!(
                    "names starting with `{}` are kept for blocked services",
                    crate::services::PREFIX
                ),
            );
        }
    }
}

// REQ: FLT-005 (T6.12, ADR-067) — quick rules: a real domain, known groups, devices that are
// named devices or addresses, a readable expiry, unique IDs, and at most MAX_RULES.
fn rules(cfg: &Config, r: &mut Report<'_>) {
    let groups: HashSet<&str> = cfg
        .group
        .iter()
        .map(|g| g.name.as_str())
        .chain(["default"])
        .collect();
    if cfg.rule.len() > crate::schema::MAX_RULES {
        r.err(
            "rule",
            format!("at most {} quick rules", crate::schema::MAX_RULES),
        );
    }
    let devices: HashSet<String> = cfg
        .client
        .iter()
        .map(|c| c.name.to_ascii_lowercase())
        .collect();
    let mut ids = HashSet::new();
    for (i, rule) in cfg.rule.iter().enumerate() {
        let p = format!("rule[{i}]");
        if rule.id.is_empty() || !ids.insert(rule.id.as_str()) {
            r.err(
                format!("{p}.id"),
                format!("must be unique and not empty (`{}`)", rule.id),
            );
        }
        let d = rule.domain.trim_end_matches('.');
        if d.is_empty()
            || d.len() > 253
            || d.split('.').any(|l| l.is_empty() || l.len() > 63)
            || d.contains(['*', '/', ' '])
        {
            r.err(
                format!("{p}.domain"),
                format!(
                    "`{}` isn't a domain name (subdomains are included; no wildcards)",
                    rule.domain
                ),
            );
        }
        for (j, dev) in rule.devices.iter().enumerate() {
            let known = devices.contains(&dev.to_ascii_lowercase());
            let address = crate::Cidr::parse(dev).is_ok();
            if !known && !address {
                r.err(
                    format!("{p}.devices[{j}]"),
                    format!("`{dev}` is neither a device name nor an IP or CIDR"),
                );
            }
        }
        for (j, g) in rule.groups.iter().enumerate() {
            if !groups.contains(g.as_str()) {
                r.err(format!("{p}.groups[{j}]"), format!("unknown group `{g}`"));
            }
        }
        if let Some(e) = &rule.expires
            && crate::types::parse_rfc3339(e).is_none()
        {
            r.err(
                format!("{p}.expires"),
                format!("`{e}` isn't an RFC 3339 time like 2026-10-05T21:30:00Z"),
            );
        }
    }
}

// REQ: CLU-001 — the cluster port can't share an address with a listener (both default to
// 8443 for DoH and the cluster channel).
fn cluster(cfg: &Config, r: &mut Report<'_>) {
    if !matches!(cfg.cluster.config_source.as_str(), "file" | "gitops") {
        r.err("cluster.config_source", "must be `file` or `gitops`");
    }
    // REQ: CLU-009 — automatic cluster creation and joining (Helm).
    let c = &cfg.cluster;
    if let Some(init) = &c.init {
        if init.advertise.is_empty() {
            r.err(
                "cluster.init.advertise",
                "needs at least one URL peers can reach",
            );
        }
        if !matches!(init.config_authority.as_str(), "api" | "gitops") {
            r.err("cluster.init.config_authority", "must be `api` or `gitops`");
        }
        if c.join_url.is_some() {
            r.err(
                "cluster.join_url",
                "a node either creates a cluster (init) or joins one",
            );
        }
    }
    if c.join_url.is_some() && c.bootstrap_secret_file.is_none() {
        r.err(
            "cluster.join_url",
            "needs bootstrap_secret_file (the shared join secret)",
        );
    }
    if c.ephemeral && c.join_url.is_none() {
        r.warn("cluster.ephemeral only applies when joining with join_url");
    }
    if c.ephemeral_ttl_secs < 60 {
        r.err("cluster.ephemeral_ttl_secs", "must be at least 60");
    }
    // REQ: CLU-003 (ADR-049) — the Git config source.
    if let Some(g) = &c.git {
        let repo = g.repo.as_str();
        let local_http = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|p| repo.starts_with(p));
        if !repo.starts_with("https://") && !local_http {
            r.err(
                "cluster.git.repo",
                "must be an https:// URL (plain http only on this host, for testing)",
            );
        }
        let path = g.path.as_str();
        if path.is_empty() || path.starts_with('/') || path.split('/').any(|p| p == "..") {
            r.err(
                "cluster.git.path",
                "must be a file inside the repository, e.g. telltale/shared.toml",
            );
        }
        if g.git_ref.as_str().is_empty() {
            r.err("cluster.git.ref", "must name a branch, tag, or commit");
        }
        if g.poll_secs < 5 {
            r.err("cluster.git.poll_secs", "must be at least 5");
        }
        if g.require_signed && g.allowed_signers_file.is_none() {
            r.err(
                "cluster.git.allowed_signers_file",
                "require_signed needs the allowed signers",
            );
        }
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
    // REQ: AGT-008 (T7.4) — MCP sign-in uses one of the configured providers.
    if !o.mcp_provider.is_empty() && !o.provider.iter().any(|p| p.id == o.mcp_provider) {
        r.err(
            "auth.oidc.mcp_provider",
            format!(
                "`{}` isn't the id of an [[auth.oidc.provider]]",
                o.mcp_provider.as_str()
            ),
        );
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
        if l.proto == crate::ListenProto::Udp {
            if l.max_connections.is_some() {
                r.err(
                    format!("{p}.max_connections"),
                    "not valid for udp listeners",
                );
            }
            if l.max_connections_per_address.is_some() {
                r.err(
                    format!("{p}.max_connections_per_address"),
                    "not valid for udp listeners",
                );
            }
        }
        if l.max_connections == Some(0) {
            r.err(format!("{p}.max_connections"), "must be at least 1");
        }
    }
}

/// REQ: UPS-003 (T9.9) — relays carry DNSCrypt only.
fn relay(u: &crate::schema::Upstream, scheme: &str, p: &str, r: &mut Report<'_>) {
    let Some(relay) = &u.relay else { return };
    let relay = relay.as_str();
    if scheme != "sdns" {
        r.err(
            format!("{p}.relay"),
            "only for DNSCrypt (sdns://) upstreams",
        );
    } else if !relay.starts_with("sdns://") && relay.parse::<std::net::SocketAddr>().is_err() {
        r.err(
            format!("{p}.relay"),
            "a relay stamp (sdns://…) or ip:port, e.g. 203.0.113.7:443",
        );
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
                // REQ: UPS-011 (T7.16)
                upstream_tls(u, s, &p, r);
                if s != "exec" && !u.args.is_empty() {
                    r.err(format!("{p}.args"), "only valid for exec:// upstreams");
                }
                if (s == "unix" || s == "exec") && !u.url.as_str()[s.len() + 3..].starts_with('/') {
                    r.err(
                        format!("{p}.url"),
                        format!("use an absolute path, e.g. `{s}:///run/plugin`"),
                    );
                }
                // REQ: DNS-015 (T7.23)
                if let Some(e) = &u.ecs
                    && !matches!(e.as_str(), "strip" | "client")
                    && crate::Cidr::parse(e).is_err()
                {
                    r.err(
                        format!("{p}.ecs"),
                        "`strip` (the default: never sent), `client` (each public client's /24 or /56), or a subnet to send instead, e.g. 203.0.113.0/24",
                    );
                }
                // REQ: UPS-010 (T7.16)
                // REQ: UPS-010 (T9.9) — udp:// only through a SOCKS5 proxy's UDP relay.
                let socks = u
                    .proxy
                    .as_ref()
                    .is_some_and(|x| x.as_str().starts_with("socks5://"));
                if u.proxy.is_some()
                    && !matches!(s, "tcp" | "tls" | "https")
                    && !(s == "udp" && socks)
                {
                    r.err(format!("{p}.proxy"), "only for tcp://, tls://, and https:// upstreams, or udp:// through a socks5:// proxy (use tcp:// with an HTTP proxy or Tor)");
                }
                relay(u, s, &p, r);
                // REQ: DNS-012 (T7.15)
                if s != "recursive" && u.recursive != crate::schema::RecursiveConfig::default() {
                    r.err(
                        format!("{p}.recursive"),
                        "only valid for recursive:// upstreams",
                    );
                }
                if s == "recursive" && !matches!(u.url.as_str(), "recursive://" | "recursive:///") {
                    r.err(
                        format!("{p}.url"),
                        "write it as `recursive://` (it starts at the root servers)",
                    );
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
    // REQ: UPS-007 (T9.25) — a client group's own upstream group.
    for (i, g) in cfg.group.iter().enumerate() {
        if let Some(u) = &g.upstreams
            && !groups.contains(u.as_str())
        {
            r.err(
                format!("group[{i}].upstreams"),
                format!("unknown upstream group `{u}`"),
            );
        }
    }
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
    if f.max_invalid_percent > 100 {
        r.err("filter.max_invalid_percent", "must be between 0 and 100");
    }
    if f.max_regexes > 100_000 {
        r.err(
            "filter.max_regexes",
            "must be at most 100000 (0 = no limit)",
        );
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
    if !(512..=4096).contains(&cfg.dns.edns_payload) {
        r.err(
            "dns.edns_payload",
            "must be between 512 and 4096 (the UDP workers' send buffer is 4096 bytes)",
        );
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
    if t.ship.interval_secs < 10 {
        r.err("telemetry.ship.interval_secs", "must be at least 10");
    }
    if t.ship.buffer_bytes.bytes() < 1 << 20 {
        r.err("telemetry.ship.buffer_bytes", "must be at least 1 MiB");
    }
    if t.qlog.flush_interval_secs == 0 {
        r.err("telemetry.qlog.flush_interval_secs", "must be at least 1");
    }
}
