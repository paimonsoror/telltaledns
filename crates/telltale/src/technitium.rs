//! `telltale import technitium URL` (REQ: API-007, API-011; T6.4, ADR-062): reads a running
//! Technitium DNS Server through its HTTP API and turns its setup into TelltaleDNS
//! configuration, with a report of what has no equivalent.
//!
//! Read: settings (forwarders, blocking, block-list URLs, DNSSEC, rate limits), zones and
//! their records, forwarder zones (conditional forwarding), the allowed and blocked names,
//! the Advanced Blocking app's groups, and DHCP reservations. Technitium's backup files are a
//! private binary format, so the documented JSON API is the source (ADR-062).

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::import::toml_str;
use crate::pihole::{Imported, mac, one_line, slug, toml_array, unique};

/// One zone and its records (`rData` as Technitium returns it).
#[derive(Debug, Clone, Default)]
pub(crate) struct Zone {
    pub name: String,
    pub kind: String,
    pub disabled: bool,
    pub records: Vec<Value>,
}

/// Everything read from a Technitium server.
#[derive(Debug, Clone, Default)]
pub(crate) struct Export {
    pub version: String,
    pub settings: Value,
    pub zones: Vec<Zone>,
    pub allowed: Vec<String>,
    pub blocked: Vec<String>,
    /// The Advanced Blocking app's configuration, if it's installed.
    pub advanced_blocking: Option<Value>,
    /// Other installed apps, by name.
    pub other_apps: Vec<String>,
    /// DHCP scopes, each with `reservedLeases`.
    pub dhcp: Vec<Value>,
}

/// Most bytes one API response may have.
const MAX_RESPONSE: u64 = 64 << 20;

fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

struct Api {
    client: telltale_filter::fetch::Client,
    base: String,
    token: String,
}

impl Api {
    async fn raw(&self, path: &str, query: &[(&str, &str)]) -> Result<Vec<u8>, String> {
        let mut url = format!("{}/api/{path}?token={}", self.base, encode(&self.token));
        for (k, v) in query {
            let _ = write!(url, "&{k}={}", encode(v));
        }
        let req = http::Request::get(url.as_str())
            .body(Vec::new())
            .map_err(|e| e.to_string())?;
        let resp = tokio::time::timeout(
            Duration::from_secs(30),
            self.client.request(req, MAX_RESPONSE),
        )
        .await
        .map_err(|_| format!("/api/{path}: no answer in 30 s"))?
        .map_err(|e| format!("/api/{path}: {}", e.message))?;
        if !resp.status().is_success() {
            return Err(format!("/api/{path}: HTTP {}", resp.status()));
        }
        Ok(resp.into_body())
    }

    async fn json(&self, path: &str, query: &[(&str, &str)]) -> Result<Value, String> {
        let body = self.raw(path, query).await?;
        let v: Value = serde_json::from_slice(&body).map_err(|e| format!("/api/{path}: {e}"))?;
        if v.get("status").and_then(Value::as_str) != Some("ok") {
            let why = v
                .get("errorMessage")
                .and_then(Value::as_str)
                .unwrap_or("not ok");
            return Err(format!("/api/{path}: {}", one_line(why)));
        }
        Ok(v.get("response").cloned().unwrap_or(Value::Null))
    }

    async fn lines(&self, path: &str) -> Result<Vec<String>, String> {
        let body = self.raw(path, &[]).await?;
        Ok(String::from_utf8_lossy(&body)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect())
    }
}

/// Reads everything the importer uses from the server at `base` (e.g.
/// `http://192.168.1.2:5380`) with an API token.
pub(crate) async fn fetch(base: &str, token: &str) -> Result<Export, String> {
    let client =
        telltale_filter::fetch::Client::new(Arc::new(telltale_filter::fetch::SystemResolver), &[])?;
    let api = Api {
        client,
        base: base.trim_end_matches('/').to_owned(),
        token: token.to_owned(),
    };
    let settings = api.json("settings/get", &[]).await?;
    let mut ex = Export {
        version: settings
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_owned(),
        settings,
        ..Export::default()
    };
    let zones = api.json("zones/list", &[]).await?;
    for z in zones
        .get("zones")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if z.get("internal").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let name = z.get("name").and_then(Value::as_str).unwrap_or_default();
        let records = api
            .json(
                "zones/records/get",
                &[("domain", name), ("zone", name), ("listZone", "true")],
            )
            .await?;
        ex.zones.push(Zone {
            name: name.to_owned(),
            kind: z
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            disabled: z.get("disabled").and_then(Value::as_bool) == Some(true),
            records: records
                .get("records")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        });
    }
    ex.allowed = api.lines("allowed/export").await?;
    ex.blocked = api.lines("blocked/export").await?;
    let apps = api.json("apps/list", &[]).await?;
    for a in apps
        .get("apps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = a.get("name").and_then(Value::as_str).unwrap_or_default();
        if name == "Advanced Blocking" {
            let c = api.json("apps/config/get", &[("name", name)]).await?;
            let text = c.get("config").and_then(Value::as_str).unwrap_or("{}");
            ex.advanced_blocking = Some(
                serde_json::from_str(text)
                    .map_err(|e| format!("Advanced Blocking configuration: {e}"))?,
            );
        } else {
            ex.other_apps.push(name.to_owned());
        }
    }
    // DHCP may be unavailable (no permission); it only names devices, so it's optional.
    if let Ok(scopes) = api.json("dhcp/scopes/list", &[]).await {
        for s in scopes
            .get("scopes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = s.get("name").and_then(Value::as_str).unwrap_or_default();
            if let Ok(mut full) = api.json("dhcp/scopes/get", &[("name", name)]).await {
                if let Some(o) = full.as_object_mut() {
                    o.insert(
                        "enabled".into(),
                        s.get("enabled").cloned().unwrap_or(Value::Bool(false)),
                    );
                }
                ex.dhcp.push(full);
            }
        }
    }
    Ok(ex)
}

fn s<'v>(v: &'v Value, k: &str) -> &'v str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

fn b(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool) == Some(true)
}

fn strs(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    x.as_str()
                        .map(str::to_owned)
                        .or_else(|| x.get("url").and_then(Value::as_str).map(str::to_owned))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A Technitium name-server address (`1.1.1.1`, `1.1.1.1:853`, `[::1]:53`,
/// `dns.quad9.net (9.9.9.9:853)`, `https://host/dns-query (1.1.1.1)`) as an upstream URL and
/// TLS name (DoT and DoQ).
pub(crate) fn forwarder_url(
    addr: &str,
    protocol: &str,
) -> Result<(String, Option<String>), String> {
    let (main, pinned) = match addr.split_once(" (") {
        Some((m, p)) => (m.trim(), Some(p.trim_end_matches(')').trim())),
        None => (addr.trim(), None),
    };
    let (scheme, port) = match protocol.to_ascii_lowercase().as_str() {
        "udp" | "" => ("udp", 53),
        "tcp" => ("tcp", 53),
        "tls" => ("tls", 853),
        // UPS-002 (T7.7) — DNS over QUIC.
        "quic" => ("quic", 853),
        "https" => return Ok((main.to_owned(), None)),
        other => return Err(format!("{other} forwarders aren't supported yet")),
    };
    // host[:port], with IPv6 in brackets.
    let split = |a: &str| -> (String, Option<u16>) {
        if let Some(rest) = a.strip_prefix('[')
            && let Some((h, p)) = rest.split_once(']')
        {
            return (
                h.to_owned(),
                p.strip_prefix(':').and_then(|p| p.parse().ok()),
            );
        }
        match a.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h.to_owned(), p.parse().ok()),
            _ => (a.to_owned(), None),
        }
    };
    let (host, p1) = split(main);
    let (ip, p2) = match pinned {
        Some(p) => split(p),
        None => (host.clone(), p1),
    };
    let port = p2.or(p1).unwrap_or(port);
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| format!("`{}` has no IP address", one_line(addr)))?;
    let hostport = match ip {
        IpAddr::V4(a) => format!("{a}:{port}"),
        IpAddr::V6(a) => format!("[{a}]:{port}"),
    };
    let name =
        (matches!(scheme, "tls" | "quic") && host.parse::<IpAddr>().is_err()).then_some(host);
    Ok((format!("{scheme}://{hostport}"), name))
}

/// A record's value in our `[[record]]` format, or `None` for types we don't serve.
fn record_value(rtype: &str, r: &Value) -> Option<String> {
    let num = |k: &str| r.get(k).and_then(Value::as_u64).map(|n| n.to_string());
    Some(match rtype {
        "A" | "AAAA" => s(r, "ipAddress").to_owned(),
        "CNAME" => s(r, "cname").to_owned(),
        "PTR" => s(r, "ptrName").to_owned(),
        "TXT" => s(r, "text").to_owned(),
        "MX" => format!("{} {}", num("preference")?, s(r, "exchange")),
        "SRV" => format!(
            "{} {} {} {}",
            num("priority")?,
            num("weight")?,
            num("port")?,
            s(r, "target")
        ),
        _ => return None,
    })
}

/// One forwarder of a forwarder zone.
struct Fwd {
    priority: u64,
    url: String,
    sni: Option<String>,
    dnssec: bool,
}

struct List {
    name: String,
    note: String,
    url: Option<String>,
    rules: Vec<String>,
    allow: bool,
}

/// The conversion's state.
struct Builder<'a> {
    ex: &'a Export,
    notes: Vec<String>,
    body: String,
    lists: Vec<List>,
    /// URL (and kind) → list name, so groups share one list per source.
    by_url: BTreeMap<(String, bool), String>,
    list_names: HashSet<String>,
}

impl Builder<'_> {
    fn url_list(&mut self, url: &str, allow: bool, note: &str) -> String {
        if let Some(n) = self.by_url.get(&(url.to_owned(), allow)) {
            return n.clone();
        }
        let tail = url.trim_end_matches('/').rsplit('/').next().unwrap_or("");
        let tail = slug(tail.split('.').next().unwrap_or(tail), 40);
        let base = if tail.is_empty() {
            "technitium".to_owned()
        } else {
            format!("technitium-{tail}")
        };
        let name = self.fresh_name(&base);
        self.by_url.insert((url.to_owned(), allow), name.clone());
        self.lists.push(List {
            name: name.clone(),
            note: note.to_owned(),
            url: Some(url.to_owned()),
            rules: Vec::new(),
            allow,
        });
        name
    }

    fn inline_list(&mut self, base: &str, rules: Vec<String>, allow: bool, note: &str) -> String {
        let name = self.fresh_name(base);
        self.lists.push(List {
            name: name.clone(),
            note: note.to_owned(),
            url: None,
            rules,
            allow,
        });
        name
    }

    fn fresh_name(&mut self, base: &str) -> String {
        let base: String = base.chars().take(60).collect();
        let mut n = base.clone();
        let mut i = 2;
        while !self.list_names.insert(n.clone()) {
            n = format!("{base}-{i}");
            i += 1;
        }
        n
    }

    /// Forwarders → the `default` upstream group.
    fn forwarders(&mut self) -> usize {
        let st = &self.ex.settings;
        let protocol = s(st, "forwarderProtocol");
        let mut members = Vec::new();
        for (i, f) in strs(st, "forwarders").iter().enumerate() {
            match forwarder_url(f, protocol) {
                Ok((url, name)) => {
                    let n = format!("technitium-{}", i + 1);
                    let _ = writeln!(
                        self.body,
                        "\n[[upstream]]\nname = {}\nurl = {}",
                        toml_str(&n),
                        toml_str(&url)
                    );
                    if let Some(sni) = name {
                        let _ = writeln!(self.body, "tls_server_name = {}", toml_str(&sni));
                    }
                    members.push(n);
                }
                Err(e) => self
                    .notes
                    .push(format!("Forwarder `{}`: {e}; not imported.", one_line(f))),
            }
        }
        if members.is_empty() {
            self.notes.push("Technitium resolved names itself (no forwarders). TelltaleDNS forwards: add upstreams, for example from the presets (`docs/running.md`, Upstream presets).".into());
            return 0;
        }
        // Concurrent forwarding asks several forwarders at once and takes the first answer.
        // It needs two forwarders to mean anything (and our `parallel` needs two).
        let concurrent = b(st, "concurrentForwarding") && members.len() >= 2;
        let fanout = st
            .get("forwarderConcurrency")
            .and_then(Value::as_u64)
            .unwrap_or(2)
            .min(members.len() as u64)
            .max(2);
        let _ = writeln!(
            self.body,
            "\n[[upstream_group]]\nname = \"default\"\nmembers = {}\nstrategy = \"{}\"",
            toml_array(&members),
            if concurrent { "parallel" } else { "failover" }
        );
        if concurrent {
            let _ = writeln!(self.body, "parallel_fanout = {fanout}");
        }
        members.len()
    }

    /// Zones: records of primary and forwarder zones, and forwarder zones as routes.
    fn zones(&mut self) -> (usize, usize) {
        let (mut records, mut routes) = (0, 0);
        let mut skipped_types: BTreeMap<String, usize> = BTreeMap::new();
        let mut disabled_records = 0;
        for z in &self.ex.zones {
            if z.disabled {
                self.notes.push(format!(
                    "Zone {} was disabled; not imported.",
                    one_line(&z.name)
                ));
                continue;
            }
            match z.kind.as_str() {
                "Primary" | "Forwarder" => {}
                other => {
                    self.notes.push(format!(
                        "Zone {} is a {} zone (its data comes from another server): add a route to that server, or import its records with `telltale import zone`.",
                        one_line(&z.name),
                        one_line(other)
                    ));
                    continue;
                }
            }
            let mut fwd: Vec<Fwd> = Vec::new();
            for r in &z.records {
                let rtype = s(r, "type");
                let data = r.get("rData").cloned().unwrap_or(Value::Null);
                if b(r, "disabled") {
                    disabled_records += 1;
                    continue;
                }
                match rtype {
                    "SOA" => {}
                    "NS" if s(r, "name").eq_ignore_ascii_case(&z.name) => {}
                    "FWD" => {
                        let target = s(&data, "forwarder");
                        if target == "this-server" {
                            continue;
                        }
                        match forwarder_url(target, s(&data, "protocol")) {
                            Ok((url, sni)) => fwd.push(Fwd {
                                priority: data.get("priority").and_then(Value::as_u64).unwrap_or(0),
                                url,
                                sni,
                                dnssec: b(&data, "dnssecValidation"),
                            }),
                            Err(e) => self.notes.push(format!(
                                "Forwarder for {}: {e}; not imported.",
                                one_line(&z.name)
                            )),
                        }
                    }
                    t => match record_value(t, &data) {
                        Some(v) => {
                            records += 1;
                            self.record(r, t, &v);
                        }
                        None => *skipped_types.entry(t.to_owned()).or_default() += 1,
                    },
                }
            }
            if !fwd.is_empty() {
                routes += 1;
                self.forward_route(&z.name, &mut fwd, routes);
            }
        }
        if !skipped_types.is_empty() {
            let list: Vec<String> = skipped_types
                .iter()
                .map(|(t, n)| format!("{n} {}", one_line(t)))
                .collect();
            self.notes.push(format!(
                "Records of types TelltaleDNS doesn't serve locally were skipped: {}.",
                list.join(", ")
            ));
        }
        if disabled_records > 0 {
            self.notes.push(format!(
                "{disabled_records} disabled record(s) not imported."
            ));
        }
        (records, routes)
    }

    fn record(&mut self, r: &Value, rtype: &str, value: &str) {
        let _ = writeln!(
            self.body,
            "\n[[record]]\nname = {}\ntype = \"{rtype}\"\nvalue = {}",
            toml_str(&s(r, "name").to_ascii_lowercase()),
            toml_str(value)
        );
        if let Some(ttl) = r.get("ttl").and_then(Value::as_u64) {
            let _ = writeln!(self.body, "ttl = {ttl}");
        }
    }

    /// A forwarder zone: its forwarders (by priority) as a group, and a route to it.
    fn forward_route(&mut self, zone: &str, fwd: &mut [Fwd], n: usize) {
        fwd.sort_by_key(|f| f.priority);
        let group = format!("technitium-forward-{n}");
        let mut members = Vec::new();
        for (i, f) in fwd.iter().enumerate() {
            let name = format!("{group}-{}", i + 1);
            let _ = writeln!(
                self.body,
                "\n[[upstream]]\nname = {}\nurl = {}",
                toml_str(&name),
                toml_str(&f.url)
            );
            if let Some(sni) = &f.sni {
                let _ = writeln!(self.body, "tls_server_name = {}", toml_str(sni));
            }
            members.push(name);
        }
        // Validation stays on only when every forwarder of the zone validated.
        let nta = !fwd.iter().all(|f| f.dnssec);
        let _ = writeln!(
            self.body,
            "\n[[upstream_group]]\nname = {g}\nmembers = {m}\n\n[[route]]\nmatch_suffix = {z}\nupstream_group = {g}\ndnssec_nta = {nta}",
            g = toml_str(&group),
            m = toml_array(&members),
            z = toml_array(&[zone.to_ascii_lowercase()]),
        );
    }

    /// Server-wide blocking: block-list URLs (`!` = allow list) and the allowed and blocked
    /// names. Returns the lists every group uses.
    fn server_lists(&mut self) -> Vec<String> {
        let st = &self.ex.settings;
        let mut out = Vec::new();
        for u in strs(st, "blockListUrls") {
            let (url, allow) = match u.strip_prefix('!') {
                Some(rest) => (rest.to_owned(), true),
                None => (u.clone(), false),
            };
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                self.notes.push(format!(
                    "Block list `{}` isn't an http(s) URL; not imported.",
                    one_line(&url)
                ));
                continue;
            }
            out.push(self.url_list(&url, allow, "Technitium block list (Settings → Blocking)"));
        }
        if !self.ex.blocked.is_empty() {
            let rules = self.ex.blocked.clone();
            out.push(self.inline_list(
                "technitium-blocked",
                rules,
                false,
                "Technitium's blocked zones (each blocks the name and its subdomains)",
            ));
        }
        if !self.ex.allowed.is_empty() {
            let rules = self.ex.allowed.clone();
            out.push(self.inline_list(
                "technitium-allowed",
                rules,
                true,
                "Technitium's allowed zones",
            ));
        }
        if st.get("enableBlocking").and_then(Value::as_bool) == Some(false) {
            self.notes
                .push("Blocking was off in Technitium; the imported lists are active.".into());
        }
        out
    }
}

/// Advanced Blocking's networks per group, and the group the catch-all network
/// (`0.0.0.0/0`, `::/0`) points at, which becomes `default`.
fn app_networks(app: &Value) -> (BTreeMap<String, Vec<String>>, Option<String>) {
    let mut nets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut catch_all = None;
    for (net, g) in app
        .get("networkGroupMap")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let g = g.as_str().unwrap_or_default().to_owned();
        let net = net.replace(['[', ']'], "");
        if net == "0.0.0.0/0" || net == "::/0" {
            catch_all = Some(g);
        } else {
            nets.entry(g).or_default().push(net);
        }
    }
    (nets, catch_all)
}

/// A group's `block_mode` (and `block_ips`) lines: NXDOMAIN, or addresses (the unspecified
/// ones are our default null answer).
fn block_mode(nx: bool, addrs: &[String]) -> String {
    if nx {
        return "block_mode = \"nxdomain\"\n".into();
    }
    let ips: Vec<String> = addrs
        .iter()
        .filter_map(|a| a.parse::<IpAddr>().ok())
        .filter(|ip| !ip.is_unspecified())
        .map(|ip| ip.to_string())
        .collect();
    if ips.is_empty() {
        String::new()
    } else {
        format!(
            "block_mode = \"custom_ip\"\nblock_ips = {}\n",
            toml_array(&ips)
        )
    }
}

impl Builder<'_> {
    /// Groups: the Advanced Blocking app's, else just `default`; the server-wide lists apply
    /// to every group. Clients on the blocking bypass list get a group with no lists.
    fn groups(&mut self, server: &[String]) -> usize {
        let st = self.ex.settings.clone();
        let server_mode = match s(&st, "blockingType") {
            "NxDomain" => block_mode(true, &[]),
            "CustomAddress" => block_mode(false, &strs(&st, "customBlockingAddresses")),
            _ => String::new(),
        };
        let mut groups: Vec<(String, Vec<String>, String, Vec<String>)> = Vec::new();
        let mut taken = HashSet::from(["default".to_owned()]);
        let app = self
            .ex
            .advanced_blocking
            .clone()
            .filter(|a| a.get("enableBlocking").and_then(Value::as_bool) != Some(false));
        if self.ex.advanced_blocking.is_some() && app.is_none() {
            self.notes
                .push("The Advanced Blocking app was installed but switched off; its groups aren't imported.".into());
        }
        let mut has_default = false;
        if let Some(app) = &app {
            let (mut nets, catch_all) = app_networks(app);
            if app
                .get("localEndPointGroupMap")
                .and_then(Value::as_object)
                .is_some_and(|m| !m.is_empty())
            {
                self.notes.push("Advanced Blocking groups chosen by the listener or DoH/DoT host name (localEndPointGroupMap) aren't imported; TelltaleDNS picks groups by device and network (and `id:` client IDs).".into());
            }
            for g in app
                .get("groups")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
            {
                let raw = one_line(s(&g, "name"));
                let is_default = catch_all.as_deref() == Some(raw.as_str());
                let name = if is_default {
                    has_default = true;
                    "default".to_owned()
                } else {
                    unique(if raw.is_empty() { "group" } else { &raw }, &mut taken)
                };
                let lists = self.app_group_lists(&g, &name, &raw, server);
                let mode = if g.get("blockAsNxDomain").is_some() {
                    block_mode(b(&g, "blockAsNxDomain"), &strs(&g, "blockingAddresses"))
                } else {
                    server_mode.clone()
                };
                let networks = if is_default {
                    Vec::new()
                } else {
                    nets.remove(&raw).unwrap_or_default()
                };
                groups.push((name, lists, mode, networks));
            }
            for (g, n) in nets {
                self.notes.push(format!(
                    "Networks {} pointed at group `{}`, which doesn't exist; not imported.",
                    n.join(", "),
                    one_line(&g)
                ));
            }
        }
        if !has_default {
            groups.insert(
                0,
                (
                    "default".into(),
                    server.to_vec(),
                    server_mode.clone(),
                    Vec::new(),
                ),
            );
        }
        let bypass = strs(&st, "blockingBypassList");
        if !bypass.is_empty() {
            let n = unique("technitium-bypass", &mut taken);
            self.notes.push(format!(
                "Clients on Technitium's blocking bypass list are in group `{n}`, which has no lists."
            ));
            groups.push((n, Vec::new(), String::new(), bypass));
        }
        let count = groups.len();
        for (name, lists, mode, networks) in groups {
            let mut seen = HashSet::new();
            let lists: Vec<String> = lists
                .into_iter()
                .filter(|l| seen.insert(l.clone()))
                .collect();
            let _ = writeln!(
                self.body,
                "\n[[group]]\nname = {}\nlists = {}",
                toml_str(&name),
                toml_array(&lists)
            );
            self.body.push_str(&mode);
            if !networks.is_empty() {
                let _ = writeln!(self.body, "networks = {}", toml_array(&networks));
            }
        }
        count
    }

    /// An Advanced Blocking group's lists: the server-wide ones, its URL lists (shared with
    /// other groups using the same URL), and its own names and regexes as inline lists.
    fn app_group_lists(
        &mut self,
        g: &Value,
        name: &str,
        raw: &str,
        server: &[String],
    ) -> Vec<String> {
        if g.get("enableBlocking").and_then(Value::as_bool) == Some(false) {
            self.notes.push(format!(
                "Group `{name}` had blocking off in Advanced Blocking: imported with no lists."
            ));
            return Vec::new();
        }
        let mut lists = server.to_vec();
        let note = format!("Advanced Blocking, group {name}");
        for (key, allow) in [
            ("blockListUrls", false),
            ("allowListUrls", true),
            ("adblockListUrls", false),
            ("regexBlockListUrls", false),
            ("regexAllowListUrls", true),
        ] {
            for u in strs(g, key) {
                lists.push(self.url_list(&u, allow, &note));
            }
        }
        if g.get("blockListUrls")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(Value::is_object))
        {
            self.notes.push(format!("Group `{name}`: per-list blocking answers aren't imported; the group's answer applies to every list."));
        }
        let slugged = slug(raw, 30);
        for (key, allow, regex) in [
            ("blocked", false, false),
            ("allowed", true, false),
            ("blockedRegex", false, true),
            ("allowedRegex", true, true),
        ] {
            let mut rules = strs(g, key);
            if regex {
                rules = rules.into_iter().map(|r| format!("/{r}/")).collect();
            }
            if !rules.is_empty() {
                let base = format!(
                    "technitium-{slugged}-{}{}",
                    if allow { "allowed" } else { "blocked" },
                    if regex { "-regex" } else { "" }
                );
                lists.push(self.inline_list(&base, rules, allow, &note));
            }
        }
        lists
    }

    /// Lists go before the groups that name them (any order is valid TOML; this reads better).
    fn lists_toml(&self) -> String {
        let mut out = String::new();
        for l in &self.lists {
            let _ = writeln!(
                out,
                "\n# {}\n[[list]]\nname = {}",
                one_line(&l.note),
                toml_str(&l.name)
            );
            if let Some(u) = &l.url {
                let _ = writeln!(out, "url = {}", toml_str(u));
            }
            if !l.rules.is_empty() {
                let _ = writeln!(out, "rules = {}", toml_array(&l.rules));
            }
            if l.allow {
                let _ = writeln!(out, "kind = \"allow\"");
            }
        }
        out
    }

    /// DHCP reservations → named devices.
    fn devices(&mut self) -> usize {
        let mut names = HashSet::new();
        let mut keys = HashSet::new();
        let mut n = 0;
        let mut active = false;
        for scope in &self.ex.dhcp {
            active |= b(scope, "enabled");
            for r in scope
                .get("reservedLeases")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let m = mac(s(r, "hardwareAddress"));
                let ip = s(r, "address")
                    .parse::<IpAddr>()
                    .ok()
                    .map(|a| a.to_string());
                let k: Vec<String> = [m, ip]
                    .into_iter()
                    .flatten()
                    .filter(|k| keys.insert(k.clone()))
                    .collect();
                if k.is_empty() {
                    continue;
                }
                let host = one_line(s(r, "hostName"));
                let comment = one_line(s(r, "comments"));
                let label = if !host.is_empty() {
                    host
                } else if !comment.is_empty() {
                    comment
                } else {
                    k[0].clone()
                };
                let name = unique(&label, &mut names);
                let _ = writeln!(
                    self.body,
                    "\n[[client]]\nname = {}\nmatch = {}",
                    toml_str(&name),
                    toml_array(&k)
                );
                n += 1;
            }
        }
        if active {
            self.notes.push("Technitium's DHCP server isn't imported; keep DHCP where it is for now. Reservations became named devices.".into());
        }
        n
    }

    /// `[dnssec]`, `[ratelimit]`, `[cache]`, and notes on settings with no equivalent.
    fn scalars(&mut self) -> String {
        let st = &self.ex.settings;
        let mut head = String::new();
        if b(st, "dnssecValidation") {
            let _ = writeln!(head, "\n[dnssec]\nmode = \"validate\"");
        }
        if let Some(limit) = st
            .get("qpmPrefixLimitsIPv4")
            .and_then(Value::as_array)
            .and_then(|a| {
                a.iter()
                    .find(|p| p.get("prefix").and_then(Value::as_u64) == Some(32))
            })
            .and_then(|p| p.get("udpLimit").and_then(Value::as_u64))
        {
            if limit == 0 {
                let _ = writeln!(head, "\n[ratelimit]\nenabled = false");
            } else if limit != 1000 {
                let _ = writeln!(head, "\n[ratelimit]\nqueries = {limit}\nwindow_secs = 60");
            }
            self.notes.push("Rate limits: the per-address limit was imported (queries per minute); Technitium's per-network limits aren't.".into());
        }
        if b(st, "saveCache") {
            let _ = writeln!(head, "\n[cache]\npersist = true");
        }
        let mut served = Vec::new();
        for (k, what) in [
            ("enableDnsOverTls", "DNS-over-TLS"),
            ("enableDnsOverHttps", "DNS-over-HTTPS"),
            ("enableDnsOverQuic", "DNS-over-QUIC"),
            ("enableDnsOverHttp3", "DNS-over-HTTP/3"),
        ] {
            if b(st, k) {
                served.push(what);
            }
        }
        if !served.is_empty() {
            self.notes.push(format!(
                "Technitium served {}: set up `[[listen]]` with your certificate (`docs/running.md`, Encrypted DNS for your devices).",
                served.join(", ")
            ));
        }
        let mut other = Vec::new();
        if s(st, "recursion") != "AllowOnlyForPrivateNetworks"
            || !strs(st, "recursionNetworkACL").is_empty()
        {
            other.push("who may query (recursion, recursionNetworkACL: see `[access]`)");
        }
        if st
            .get("tsigKeys")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
        {
            other.push("TSIG keys");
        }
        if !strs(st, "zoneTransferAllowedNetworks").is_empty() {
            other.push("zone transfers");
        }
        if !st.get("proxy").is_none_or(Value::is_null) {
            other.push("the outgoing proxy");
        }
        if b(st, "eDnsClientSubnet") {
            other.push("EDNS Client Subnet");
        }
        if !other.is_empty() {
            self.notes
                .push(format!("Not imported: {}.", other.join(", ")));
        }
        if !self.ex.other_apps.is_empty() {
            let apps: Vec<String> = self.ex.other_apps.iter().map(|a| one_line(a)).collect();
            self.notes
                .push(format!("Apps not imported: {}.", apps.join(", ")));
        }
        self.notes.push("Listeners, the web service, logging, cache sizes, users, and API tokens aren't imported.".into());
        head
    }
}

/// Maps a Technitium setup onto TelltaleDNS configuration (ADR-062).
pub(crate) fn convert(ex: &Export, source: &str) -> Imported {
    let mut bld = Builder {
        ex,
        notes: Vec::new(),
        body: String::new(),
        lists: Vec::new(),
        by_url: BTreeMap::new(),
        list_names: HashSet::new(),
    };
    let upstreams = bld.forwarders();
    let (records, routes) = bld.zones();
    let server = bld.server_lists();
    let groups_body_start = bld.body.len();
    let groups = bld.groups(&server);
    // Lists are created while groups are built; put them before the groups.
    let lists = bld.lists_toml();
    bld.body.insert_str(groups_body_start, &lists);
    let devices = bld.devices();
    let head = bld.scalars();
    let counts = format!(
        "{upstreams} upstreams, {routes} forwarded zones, {records} records, {} lists, {groups} groups, {devices} devices from DHCP reservations",
        bld.lists.len()
    );
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Imported from {} (Technitium {}) by `telltale import technitium`.",
        one_line(source),
        one_line(&ex.version)
    );
    let _ = writeln!(out, "# {counts}.");
    let _ = writeln!(out, "# Review before use. Notes:");
    for n in &bld.notes {
        let _ = writeln!(out, "#   - {}", one_line(n));
    }
    out.push_str(&head);
    out.push_str(&bld.body);
    Imported {
        toml: out,
        version: "",
        notes: bld.notes,
        counts,
    }
}

#[cfg(test)]
mod tests;
