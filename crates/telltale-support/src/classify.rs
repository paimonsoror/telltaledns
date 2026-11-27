//! REQ: OPS-011 (ADR-156) — the effective configuration, redacted by classification that fails
//! closed. Every string field of the configuration's JSON Schema has a class in one table below;
//! numbers, flags, and fixed words (enums) are `plain` by their type. A string field with no class
//! is treated as a secret: dropped, and listed in the manifest as unclassified. A test walks the
//! generated schema and fails when any such field has no class, so a new field can't ship without
//! one. Fields whose names look like credentials are dropped as a second net, whatever the table
//! says.

use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::OnceLock;

use serde_json::{Map, Value};

use crate::pseudo::Category;
use crate::redact::{Known, Redactor};

/// What a configuration field is, and so what happens to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Shown as it is: a fixed word, a time zone, a size, the name of a list or an upstream.
    Plain,
    /// A name of this kind: a pseudonym.
    Name(Category),
    /// A name, or an address or MAC (a client's `match` entry may be either).
    NameOrAddress(Category),
    /// Addresses, host names, and paths: through the text redactor.
    Scan,
    /// A URL: its credentials, path, and query go; its host becomes a pseudonym.
    Url,
    /// Free text and domain lists: omitted at `strict`, redacted otherwise.
    Free,
    /// Never leaves the node.
    Secret,
}

use Category as C;
use Class::{Free, Name, NameOrAddress, Plain, Scan, Secret, Url};

/// Every string-valued field of the configuration, by normalized path (`[]` for a list entry, `{}`
/// for a map key). Fields that are numbers, flags, or fixed words are plain by type and aren't here.
const TABLE: &[(&str, Class)] = &[
    ("access.allowed_networks[]", Scan),
    ("alerts.destination[].from", Scan),
    ("alerts.destination[].name", Plain),
    ("alerts.destination[].password_file", Scan),
    ("alerts.destination[].tls_ca", Scan),
    ("alerts.destination[].to[]", Scan),
    ("alerts.destination[].token_file", Scan),
    ("alerts.destination[].url", Url),
    ("alerts.destination[].username", Secret),
    ("alerts.rule[].name", Plain),
    ("alerts.rule[].to[]", Plain),
    ("anomaly_mute[].devices[]", NameOrAddress(C::Device)),
    ("anomaly_mute[].expires", Plain),
    ("anomaly_mute[].groups[]", Name(C::Group)),
    ("anomaly_mute[].name", Free),
    ("anomaly_mute[].note", Free),
    ("api.listen", Scan),
    ("api.tls.cert", Scan),
    ("api.tls.key", Scan),
    ("api.trusted_proxies[]", Scan),
    ("auth.oidc.allowed_admin_networks[]", Scan),
    ("auth.oidc.mcp_audience", Scan),
    ("auth.oidc.mcp_provider", Plain),
    ("auth.oidc.provider[].client_id", Secret),
    ("auth.oidc.provider[].client_secret", Secret),
    ("auth.oidc.provider[].client_secret_file", Scan),
    ("auth.oidc.provider[].groups_claim", Plain),
    ("auth.oidc.provider[].id", Plain),
    ("auth.oidc.provider[].issuer", Url),
    ("auth.oidc.provider[].name", Plain),
    ("auth.oidc.provider[].role[].group", Free),
    ("auth.oidc.provider[].scopes[]", Plain),
    ("auth.oidc.provider[].username_claim", Plain),
    ("auth.oidc.public_url", Url),
    ("client[].groups[]", Name(C::Group)),
    ("client[].match[]", NameOrAddress(C::Device)),
    ("client[].name", Name(C::Device)),
    ("clients.infrastructure[]", Scan),
    ("clients.trust_edns_mac_from[]", Scan),
    ("cache.max_bytes", Plain),
    ("cluster.bootstrap_secret_file", Scan),
    ("cluster.config_source", Plain),
    ("cluster.git.allowed_signers_file", Scan),
    ("cluster.git.credentials_file", Scan),
    ("cluster.git.max_bytes", Plain),
    ("cluster.git.path", Free),
    ("cluster.git.ref", Free),
    ("cluster.git.repo", Url),
    ("cluster.git.webhook_secret_file", Scan),
    ("cluster.init.advertise[]", Scan),
    ("cluster.init.config_authority", Plain),
    ("cluster.join_url", Url),
    ("cluster.listen", Scan),
    ("cluster.name", Name(C::Cluster)),
    ("cluster.rollout.canaries[]", Name(C::Node)),
    ("cluster.site", Name(C::Cluster)),
    ("dnssec.negative_trust_anchors[]", Free),
    ("dnssec.trust_anchors_file", Scan),
    ("drill.clients[]", NameOrAddress(C::Device)),
    ("drill.group", Name(C::Group)),
    ("drill.nodes[]", Name(C::Node)),
    ("drill.tz", Plain),
    ("exclusions.clients[]", NameOrAddress(C::Device)),
    ("exclusions.names[]", Free),
    ("filter.compile_memory", Plain),
    ("filter.max_list_bytes", Plain),
    ("group[].block_answer_ips[]", Scan),
    ("group[].block_ips[]", Scan),
    ("group[].blocked_services[]", Plain),
    ("group[].color", Plain),
    ("group[].dns64_exclude[]", Scan),
    ("group[].dns64_prefix", Scan),
    ("group[].lists[]", Plain),
    ("group[].name", Name(C::Group)),
    ("group[].networks[]", Scan),
    ("group[].rebinding_allow[]", Free),
    ("group[].rewrite[].answer", Scan),
    ("group[].rewrite[].domain", Free),
    ("group[].schedules[]", Plain),
    ("group[].upstreams", Plain),
    ("identify.signatures_file", Scan),
    ("kubernetes.default_group", Name(C::Group)),
    ("kubernetes.exclude_namespaces[]", Name(C::Namespace)),
    ("kubernetes.label", Plain),
    ("kubernetes.map[].group", Name(C::Group)),
    ("kubernetes.map[].kind", Plain),
    ("kubernetes.map[].name", Name(C::Pod)),
    ("kubernetes.map[].namespace", Name(C::Namespace)),
    ("kubernetes.namespaces[]", Name(C::Namespace)),
    ("list[].max_bytes", Plain),
    ("list[].name", Plain),
    ("list[].path", Scan),
    ("list[].rules[]", Free),
    ("list[].url", Url),
    ("listen[].addr", Scan),
    ("listen[].path", Scan),
    ("listen[].tls.cert", Scan),
    ("listen[].tls.key", Scan),
    // REQ: OPS-011, DNS-003 (ADR-194) — the proxies' addresses, like `api.trusted_proxies[]`.
    ("listen[].trusted_proxies[]", Scan),
    ("local.hosts_files[]", Scan),
    ("node.data_dir", Scan),
    ("node.name", Name(C::Node)),
    ("probe.targets[]", Scan),
    ("ratelimit.exempt[]", Scan),
    ("record[].name", Free),
    ("record[].type", Plain),
    ("record[].value", Free),
    ("route[].match_group[]", Name(C::Group)),
    ("route[].match_qtype[]", Plain),
    ("route[].match_suffix[]", Free),
    ("route[].upstream_group", Plain),
    ("router[].api_key_file", Scan),
    ("router[].api_secret_file", Scan),
    ("router[].name", Plain),
    ("router[].password_file", Scan),
    ("router[].site", Plain),
    ("router[].tls_ca", Scan),
    ("router[].tls_server_name", Scan),
    ("router[].url", Url),
    ("router[].username", Secret),
    ("rule[].created", Plain),
    ("rule[].created_by", Free),
    ("rule[].devices[]", NameOrAddress(C::Device)),
    ("rule[].domain", Free),
    ("rule[].expires", Plain),
    ("rule[].groups[]", Name(C::Group)),
    ("rule[].id", Free),
    ("rule[].note", Free),
    ("schedule[].lists[]", Plain),
    ("schedule[].name", Plain),
    ("schedule[].services[]", Plain),
    ("schedule[].tz", Plain),
    ("schedule[].window[].days[]", Plain),
    ("schedule[].window[].end", Plain),
    ("schedule[].window[].start", Plain),
    ("simulate.default_window", Plain),
    ("telemetry.anomaly.ignore_domains[]", Free),
    ("telemetry.dnstap.address", Scan),
    ("telemetry.dnstap.socket", Scan),
    ("telemetry.internal_names[]", Free),
    ("telemetry.metrics.listen", Scan),
    ("telemetry.otlp.endpoint", Url),
    ("telemetry.otlp.headers", Secret),
    ("telemetry.qlog.retention_bytes", Plain),
    ("telemetry.ship.buffer_bytes", Plain),
    ("telemetry.ship.to", Url),
    ("telemetry.sink[].address", Scan),
    ("telemetry.sink[].max_bytes", Plain),
    ("telemetry.sink[].name", Plain),
    ("telemetry.sink[].path", Scan),
    ("telemetry.sink[].spill_max_bytes", Plain),
    ("telemetry.sink[].statuses[]", Plain),
    ("telemetry.sink[].tls_ca", Scan),
    ("telemetry.sink[].token_file", Scan),
    ("telemetry.sink[].token_scheme", Plain),
    ("telemetry.sink[].url", Url),
    ("updates.index_url", Url),
    ("upstream[].args[]", Secret),
    ("upstream[].bootstrap[]", Scan),
    ("upstream[].ecs", Scan),
    ("upstream[].headers", Secret),
    ("upstream[].labels[]", Free),
    ("upstream[].name", Plain),
    ("upstream[].proxy", Url),
    ("upstream[].recursive.stub_servers[]", Scan),
    ("upstream[].recursive.stub_zone", Free),
    ("upstream[].relay", Url),
    ("upstream[].spki_pins[]", Plain),
    ("upstream[].tls_ca", Scan),
    ("upstream[].tls_client_cert", Scan),
    ("upstream[].tls_client_key", Scan),
    ("upstream[].tls_server_name", Scan),
    ("upstream[].url", Url),
    ("upstream_check.reference", Scan),
    ("upstream_group[].members[]", Plain),
    ("upstream_group[].name", Plain),
    ("zone[].file", Scan),
    ("zone[].groups[]", Name(C::Group)),
    ("zone[].name", Name(C::Zone)),
    ("zone[].record[].name", Free),
    ("zone[].record[].type", Plain),
    ("zone[].record[].value", Free),
];

/// The class of a normalized path, if the table has one.
#[must_use]
pub fn class_of(path: &str) -> Option<Class> {
    TABLE.iter().find(|(p, _)| *p == path).map(|(_, c)| *c)
}

/// The table's paths (the completeness test checks each is a real field).
#[must_use]
pub fn table_paths() -> Vec<&'static str> {
    TABLE.iter().map(|(p, _)| *p).collect()
}

/// What the generated schema says about the configuration's fields.
#[derive(Debug, Default)]
pub struct SchemaInfo {
    /// Every property path, including the ones that hold more fields.
    pub paths: HashSet<String>,
    /// Fields that are numbers, flags, or fixed words: plain by type.
    pub plain: HashSet<String>,
    /// Every other leaf (strings, byte sizes, free-form maps): each needs a class in the table.
    pub needs_class: BTreeSet<String>,
}

#[derive(PartialEq)]
enum Kind {
    Plain,
    Needs,
}

fn deref<'a>(node: &'a Value, defs: &'a Value) -> &'a Value {
    let mut node = node;
    for _ in 0..20 {
        let Some(r) = node.get("$ref").and_then(Value::as_str) else {
            return node;
        };
        let name = r.rsplit('/').next().unwrap_or(r);
        match defs.get(name) {
            Some(next) => node = next,
            None => return node,
        }
    }
    node
}

fn alternatives(node: &Value) -> Option<&Vec<Value>> {
    node.get("anyOf")
        .or_else(|| node.get("oneOf"))
        .and_then(Value::as_array)
}

fn is_null(node: &Value) -> bool {
    node.get("type").and_then(Value::as_str) == Some("null")
}

fn fixed(node: &Value, defs: &Value) -> bool {
    let n = deref(node, defs);
    n.get("enum").is_some()
        || n.get("const").is_some()
        || alternatives(n).is_some_and(|alts| {
            let live: Vec<&Value> = alts.iter().filter(|a| !is_null(a)).collect();
            !live.is_empty() && live.iter().all(|a| fixed(a, defs))
        })
}

fn type_of(node: &Value) -> Option<String> {
    match node.get("type")? {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => {
            let live: Vec<&str> = a
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| *s != "null")
                .collect();
            (live.len() == 1).then(|| live[0].to_owned())
        }
        _ => None,
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

fn leaf(info: &mut SchemaInfo, path: &str, kind: &Kind) {
    match kind {
        Kind::Plain => info.plain.insert(path.to_owned()),
        Kind::Needs => info.needs_class.insert(path.to_owned()),
    };
}

fn collect(node: &Value, defs: &Value, path: &str, info: &mut SchemaInfo) {
    let n = deref(node, defs);
    if let Some(alts) = alternatives(n) {
        let live: Vec<&Value> = alts.iter().filter(|a| !is_null(a)).collect();
        if live.len() == 1 {
            return collect(live[0], defs, path, info);
        }
        let kind = if fixed(n, defs) {
            Kind::Plain
        } else {
            Kind::Needs
        };
        return leaf(info, path, &kind);
    }
    if fixed(n, defs) {
        return leaf(info, path, &Kind::Plain);
    }
    match type_of(n).as_deref() {
        Some("object") => {
            if let Some(props) = n.get("properties").and_then(Value::as_object) {
                for (k, v) in props {
                    let p = join(path, k);
                    info.paths.insert(p.clone());
                    collect(v, defs, &p, info);
                }
            }
            // A map with a typed value is walked; a free-form one (`true`, `{}`) is one leaf.
            match n.get("additionalProperties") {
                Some(extra) if extra.as_object().is_some_and(|o| !o.is_empty()) => {
                    collect(extra, defs, &join(path, "{}"), info);
                }
                _ if n.get("properties").is_none() => leaf(info, path, &Kind::Needs),
                _ => {}
            }
        }
        Some("array") => collect(
            n.get("items").unwrap_or(&Value::Null),
            defs,
            &format!("{path}[]"),
            info,
        ),
        Some("boolean" | "integer" | "number") => leaf(info, path, &Kind::Plain),
        _ => leaf(info, path, &Kind::Needs),
    }
}

/// The schema's field paths, read once from the configuration's generated JSON Schema.
#[must_use]
pub fn schema_info() -> &'static SchemaInfo {
    static INFO: OnceLock<SchemaInfo> = OnceLock::new();
    INFO.get_or_init(|| {
        let schema = serde_json::to_value(telltale_config::json_schema()).unwrap_or(Value::Null);
        let defs = schema
            .get("$defs")
            .or_else(|| schema.get("definitions"))
            .cloned()
            .unwrap_or(Value::Null);
        let mut info = SchemaInfo::default();
        collect(&schema, &defs, "", &mut info);
        info
    })
}

/// A key that looks like a credential: the second net, whatever the table says. `*_file`, `*_path`,
/// and `*_scheme` fields name where a secret is, or how it is sent, and aren't secrets themselves.
fn credential_name(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    if k.ends_with("_file") || k.ends_with("_path") || k.ends_with("_scheme") {
        return false;
    }
    [
        "secret",
        "password",
        "passwd",
        "credential",
        "private",
        "token",
        "apikey",
        "api_key",
        "bearer",
        "cookie",
    ]
    .iter()
    .any(|w| k.contains(w))
}

fn address_like(v: &str) -> bool {
    let head = v.split('/').next().unwrap_or(v);
    head.parse::<IpAddr>().is_ok()
        || (v.len() == 17 && v.bytes().filter(|b| matches!(b, b':' | b'-')).count() == 5)
}

/// The configuration, redacted, and what was dropped.
#[derive(Debug, Clone)]
pub struct ConfigView {
    pub value: Value,
    /// Fields removed as secrets (paths, never values).
    pub dropped: Vec<String>,
    /// String fields the table doesn't know: removed too, and a test should have caught them.
    pub unclassified: Vec<String>,
}

struct Walker<'a> {
    red: &'a mut Redactor,
    dropped: BTreeSet<String>,
    unclassified: BTreeSet<String>,
}

fn child_path(path: &str, key: &str) -> String {
    let p = join(path, key);
    if schema_info().paths.contains(&p) {
        p
    } else {
        join(path, "{}")
    }
}

impl Walker<'_> {
    fn object(&mut self, m: &Map<String, Value>, path: &str) -> Value {
        let mut out = Map::new();
        for (k, v) in m {
            let p = child_path(path, k);
            let guarded = matches!(v, Value::String(_) | Value::Object(_) | Value::Array(_));
            if (guarded && credential_name(k)) || class_of(&p) == Some(Secret) {
                self.dropped.insert(p);
                continue;
            }
            if let Some(shown) = self.value(v, &p) {
                out.insert(k.clone(), shown);
            }
        }
        Value::Object(out)
    }

    fn value(&mut self, v: &Value, path: &str) -> Option<Value> {
        match v {
            Value::Object(m) => Some(self.object(m, path)),
            Value::Array(a) => {
                let p = format!("{path}[]");
                Some(Value::Array(
                    a.iter().filter_map(|x| self.value(x, &p)).collect(),
                ))
            }
            Value::String(s) => self.string(s, path).map(Value::String),
            other => Some(other.clone()),
        }
    }

    fn string(&mut self, s: &str, path: &str) -> Option<String> {
        let class = class_of(path).or_else(|| schema_info().plain.contains(path).then_some(Plain));
        let Some(class) = class else {
            self.unclassified.insert(path.to_owned());
            return None;
        };
        Some(match class {
            Plain => s.to_owned(),
            Name(cat) => self.red.name(cat, s),
            NameOrAddress(cat) => {
                let (prefix, rest) = s.strip_prefix("id:").map_or(("", s), |r| ("id:", r));
                if address_like(rest) {
                    self.red.text(s)
                } else {
                    format!("{prefix}{}", self.red.name(cat, rest))
                }
            }
            Scan => self.red.text(s),
            Url => self.red.url(s),
            Free => self.red.free(s),
            Secret => {
                self.dropped.insert(path.to_owned());
                return None;
            }
        })
    }
}

/// `cfg` (the effective configuration as JSON) redacted by class, at the redactor's level.
pub fn config_view(cfg: &Value, red: &mut Redactor) -> ConfigView {
    let mut w = Walker {
        red,
        dropped: BTreeSet::new(),
        unclassified: BTreeSet::new(),
    };
    let value = match cfg {
        Value::Object(m) => w.object(m, ""),
        other => other.clone(),
    };
    ConfigView {
        value,
        dropped: w.dropped.into_iter().collect(),
        unclassified: w.unclassified.into_iter().collect(),
    }
}

/// The names and the inline secrets of `cfg`, for the redactor's first pass (so a name in the
/// configuration is replaced the same way in a log line).
#[must_use]
pub fn known_from_config(cfg: &Value) -> Known {
    let mut known = Known::new();
    walk_known(cfg, "", &mut known);
    known
}

fn walk_known(v: &Value, path: &str, known: &mut Known) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                let p = child_path(path, k);
                if class_of(&p) == Some(Secret)
                    || (credential_name(k) && !matches!(child, Value::Bool(_) | Value::Number(_)))
                {
                    secrets_in(child, known);
                } else {
                    walk_known(child, &p, known);
                }
            }
        }
        Value::Array(a) => {
            let p = format!("{path}[]");
            for x in a {
                walk_known(x, &p, known);
            }
        }
        Value::String(s) => match class_of(path) {
            Some(Name(cat)) => known.add(cat, s),
            Some(NameOrAddress(cat)) => {
                let rest = s.strip_prefix("id:").unwrap_or(s);
                if !address_like(rest) {
                    known.add(cat, rest);
                }
            }
            _ => {}
        },
        _ => {}
    }
}

fn secrets_in(v: &Value, known: &mut Known) {
    match v {
        Value::String(s) => {
            known.add_secret(s);
            // `Bearer <value>`: the value alone is what shows up in a log.
            if let Some((_, tail)) = s.rsplit_once(char::is_whitespace) {
                known.add_secret(tail);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| secrets_in(x, known)),
        Value::Object(m) => m.values().for_each(|x| secrets_in(x, known)),
        _ => {}
    }
}

#[cfg(test)]
#[path = "classify_tests.rs"]
mod tests;
