//! `telltale import pihole PATH` (REQ: API-007; T6.3, ADR-061): turns a Pi-hole setup into a
//! TelltaleDNS configuration, with a report of everything that has no equivalent.
//!
//! Inputs:
//! - a v6 Teleporter zip (`pihole.toml` plus a `gravity.db` of the group tables);
//! - a v5 Teleporter tar.gz (one JSON file per table, `setupVars.conf`, `pihole-FTL.conf`,
//!   `custom.list`, `dnsmasq.d/0[45]-*.conf`);
//! - a directory holding those files (`/etc/pihole`, with `../dnsmasq.d` for v5);
//! - a bare `gravity.db`.
//!
//! The importer reads Pi-hole's documented data formats only (the SQLite schema, the TOML
//! settings, dnsmasq option lines); no Pi-hole code is involved (NFR-006).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use telltale_config::{ListKind, ListMatch};
use telltale_filter::parse::{LineKind, ListOptions, Pattern, parse_line};

use crate::archive;
use crate::import::toml_str;

type Row = Map<String, Value>;

/// The group tables, as rows keyed by column name.
const TABLES: &[&str] = &[
    "group",
    "adlist",
    "adlist_by_group",
    "domainlist",
    "domainlist_by_group",
    "client",
    "client_by_group",
];

/// Setting files, by base name.
const FILES: &[&str] = &[
    "pihole.toml",
    "setupVars.conf",
    "pihole-FTL.conf",
    "custom.list",
    "05-pihole-custom-cname.conf",
    "04-pihole-static-dhcp.conf",
];

/// v5 Teleporter's per-table JSON files; the four domain files hold `domainlist` rows.
const JSON_TABLES: &[(&str, &str, Option<i64>)] = &[
    ("group.json", "group", None),
    ("adlist.json", "adlist", None),
    ("adlist_by_group.json", "adlist_by_group", None),
    ("client.json", "client", None),
    ("client_by_group.json", "client_by_group", None),
    ("domainlist_by_group.json", "domainlist_by_group", None),
    ("whitelist.exact.json", "domainlist", Some(0)),
    ("blacklist.exact.json", "domainlist", Some(1)),
    ("whitelist.regex.json", "domainlist", Some(2)),
    ("blacklist.regex.json", "domainlist", Some(3)),
];

/// What was read from a Pi-hole.
#[derive(Debug, Default)]
pub(crate) struct Source {
    pub files: BTreeMap<String, Vec<u8>>,
    pub tables: BTreeMap<String, Vec<Row>>,
}

fn base(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

impl Source {
    /// Reads `path`: an archive, a `gravity.db`, or a directory.
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let shown = path.display();
        if path.is_dir() {
            return Self::from_dir(path);
        }
        let data = std::fs::read(path).map_err(|e| format!("{shown}: {e}"))?;
        if data.starts_with(b"SQLite format 3\0") {
            return Ok(Self {
                tables: sqlite_tables(path)?,
                ..Self::default()
            });
        }
        let entries = archive::read(&data, |n| {
            let b = base(n);
            FILES.contains(&b) || b == "gravity.db" || JSON_TABLES.iter().any(|t| t.0 == b)
        })
        .map_err(|e| format!("{shown}: {e}"))?;
        Self::from_entries(entries)
    }

    pub(crate) fn from_entries(entries: archive::Entries) -> Result<Self, String> {
        let mut s = Self::default();
        let mut json: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (name, data) in entries {
            let b = base(&name).to_owned();
            if b == "gravity.db" {
                let tmp = TempFile::write(&data)?;
                s.tables = sqlite_tables(&tmp.0)?;
            } else if FILES.contains(&b.as_str()) {
                s.files.insert(b, data);
            } else {
                json.insert(b, data);
            }
        }
        if s.tables.is_empty() {
            s.tables = json_tables(&json)?;
        }
        Ok(s)
    }

    fn from_dir(dir: &Path) -> Result<Self, String> {
        let mut s = Self::default();
        let dirs = [
            dir.to_path_buf(),
            dir.join("dnsmasq.d"),
            dir.join("../dnsmasq.d"),
        ];
        let mut json = BTreeMap::new();
        for d in &dirs {
            for f in FILES.iter().chain(JSON_TABLES.iter().map(|t| &t.0)) {
                if let Ok(data) = std::fs::read(d.join(f)) {
                    if Path::new(f)
                        .extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
                    {
                        json.entry((*f).to_owned()).or_insert(data);
                    } else {
                        s.files.entry((*f).to_owned()).or_insert(data);
                    }
                }
            }
        }
        let db = dir.join("gravity.db");
        s.tables = if db.exists() {
            sqlite_tables(&db)?
        } else {
            json_tables(&json)?
        };
        if s.files.is_empty() && s.tables.is_empty() {
            return Err(format!(
                "{}: no Pi-hole files here (gravity.db, pihole.toml, setupVars.conf)",
                dir.display()
            ));
        }
        Ok(s)
    }

    fn text(&self, name: &str) -> Option<String> {
        self.files
            .get(name)
            .map(|d| String::from_utf8_lossy(d).into_owned())
    }

    fn rows(&self, table: &str) -> &[Row] {
        self.tables.get(table).map_or(&[], Vec::as_slice)
    }
}

/// A private temporary copy of an archived database (SQLite reads files, not memory).
struct TempFile(PathBuf);

impl TempFile {
    fn write(data: &[u8]) -> Result<Self, String> {
        use std::io::Write as _;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let p =
            std::env::temp_dir().join(format!("telltale-import-{}-{nanos}.db", std::process::id()));
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let t = Self(p);
        o.open(&t.0)
            .and_then(|mut f| f.write_all(data))
            .map_err(|e| format!("{}: {e}", t.0.display()))?;
        Ok(t)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn sqlite_tables(path: &Path) -> Result<BTreeMap<String, Vec<Row>>, String> {
    use rusqlite::types::ValueRef;
    let shown = path.display();
    let db = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("{shown}: {e}"))?;
    let mut out = BTreeMap::new();
    for t in TABLES {
        let mut stmt = db
            .prepare(&format!("SELECT * FROM \"{t}\""))
            .map_err(|e| format!("{shown}: table `{t}`: {e} (is this Pi-hole's gravity.db?)"))?;
        let cols: Vec<String> = stmt
            .column_names()
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        let mut rows = stmt.query([]).map_err(|e| format!("{shown}: {e}"))?;
        let mut list = Vec::new();
        while let Some(r) = rows.next().map_err(|e| format!("{shown}: {e}"))? {
            let mut row = Row::new();
            for (i, c) in cols.iter().enumerate() {
                let v = match r.get_ref(i) {
                    Ok(ValueRef::Integer(n)) => Value::from(n),
                    Ok(ValueRef::Real(f)) => Value::from(f),
                    Ok(ValueRef::Text(t)) => Value::from(String::from_utf8_lossy(t).into_owned()),
                    _ => Value::Null,
                };
                row.insert(c.clone(), v);
            }
            list.push(row);
        }
        out.insert((*t).to_owned(), list);
    }
    Ok(out)
}

fn json_tables(files: &BTreeMap<String, Vec<u8>>) -> Result<BTreeMap<String, Vec<Row>>, String> {
    let mut out: BTreeMap<String, Vec<Row>> = BTreeMap::new();
    for (file, table, kind) in JSON_TABLES {
        let Some(data) = files.get(*file) else {
            continue;
        };
        let rows: Vec<Row> = serde_json::from_slice(data).map_err(|e| format!("{file}: {e}"))?;
        for mut r in rows {
            if let Some(k) = kind {
                r.entry("type").or_insert_with(|| Value::from(*k));
            }
            out.entry((*table).to_owned()).or_default().push(r);
        }
    }
    Ok(out)
}

fn int(r: &Row, k: &str) -> Option<i64> {
    match r.get(k)? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(i64::from(*b)),
        _ => None,
    }
}

fn text(r: &Row, k: &str) -> String {
    match r.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// `enabled`, which is on unless it says otherwise.
fn enabled(r: &Row) -> bool {
    int(r, "enabled") != Some(0)
}

/// Item ID → the group IDs it belongs to.
fn membership(rows: &[Row], item: &str) -> BTreeMap<i64, BTreeSet<i64>> {
    let mut m: BTreeMap<i64, BTreeSet<i64>> = BTreeMap::new();
    for r in rows {
        if let (Some(i), Some(g)) = (int(r, item), int(r, "group_id")) {
            m.entry(i).or_default().insert(g);
        }
    }
    m
}

/// One line of user text, safe inside a TOML comment or a name.
pub(crate) fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Pi-hole's settings, from `pihole.toml` (v6) or `setupVars.conf` + friends (v5).
#[derive(Debug, Default)]
struct Settings {
    upstreams: Vec<String>,
    hosts: Vec<String>,
    cnames: Vec<String>,
    /// `enabled,cidr,target[#port],domain`.
    rev_servers: Vec<String>,
    dnssec: bool,
    rate_limit: Option<(u32, u32)>,
    blocking_mode: Option<String>,
    blocking_off: bool,
    dhcp_hosts: Vec<String>,
    dhcp_active: bool,
    /// Settings with no TelltaleDNS equivalent (names only: values may be secrets).
    unmapped: Vec<String>,
}

/// v6 keys the importer maps.
const V6_MAPPED: &[&str] = &[
    "dns.upstreams",
    "dns.hosts",
    "dns.cnameRecords",
    "dns.revServers",
    "dns.dnssec",
    "dns.rateLimit.count",
    "dns.rateLimit.interval",
    "dns.blocking.mode",
    "dns.blocking.active",
    "dhcp.hosts",
    "dhcp.active",
];

fn strings(v: Option<&toml::Value>) -> Vec<String> {
    v.and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn v6_settings(text: &str) -> Result<Settings, String> {
    let t: toml::Table = toml::from_str(text).map_err(|e| format!("pihole.toml: {e}"))?;
    let get = |path: &str| {
        let mut v: Option<&toml::Value> = None;
        for (i, k) in path.split('.').enumerate() {
            v = if i == 0 { t.get(k) } else { v?.get(k) };
        }
        v
    };
    let mut s = Settings {
        upstreams: strings(get("dns.upstreams")),
        hosts: strings(get("dns.hosts")),
        cnames: strings(get("dns.cnameRecords")),
        rev_servers: strings(get("dns.revServers")),
        dnssec: get("dns.dnssec").and_then(toml::Value::as_bool) == Some(true),
        blocking_mode: get("dns.blocking.mode")
            .and_then(toml::Value::as_str)
            .map(str::to_owned),
        blocking_off: get("dns.blocking.active").and_then(toml::Value::as_bool) == Some(false),
        dhcp_hosts: strings(get("dhcp.hosts")),
        dhcp_active: get("dhcp.active").and_then(toml::Value::as_bool) == Some(true),
        ..Settings::default()
    };
    let num = |p: &str| {
        get(p)
            .and_then(toml::Value::as_integer)
            .and_then(|n| u32::try_from(n).ok())
    };
    if let (Some(c), Some(i)) = (num("dns.rateLimit.count"), num("dns.rateLimit.interval")) {
        s.rate_limit = Some((c, i));
    }
    // Pi-hole marks every setting that differs from its default with `### CHANGED`.
    // The marker ends the value, so for a multi-line array it's on the closing line.
    let mut section = String::new();
    let mut key = String::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(h) = l.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            h.trim().clone_into(&mut section);
            continue;
        }
        if let Some((k, _)) = l.split_once('=')
            && !k.trim().is_empty()
            && k.trim()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            key = format!("{section}.{}", k.trim());
        }
        if l.contains("### CHANGED") && !V6_MAPPED.contains(&key.as_str()) {
            s.unmapped.push(key.clone());
        }
    }
    Ok(s)
}

fn key_values(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

/// v5 keys the importer maps (or that only describe the old install).
const V5_MAPPED: &[&str] = &[
    "DNSSEC",
    "REV_SERVER",
    "REV_SERVER_CIDR",
    "REV_SERVER_TARGET",
    "REV_SERVER_DOMAIN",
    "CONDITIONAL_FORWARDING",
    "CONDITIONAL_FORWARDING_IP",
    "CONDITIONAL_FORWARDING_DOMAIN",
    "CONDITIONAL_FORWARDING_REVERSE",
    "BLOCKING_ENABLED",
    "DHCP_ACTIVE",
    "RATE_LIMIT",
    "BLOCKINGMODE",
    // The old install's own plumbing.
    "PIHOLE_INTERFACE",
    "IPV4_ADDRESS",
    "IPV6_ADDRESS",
    "INSTALL_WEB_SERVER",
    "INSTALL_WEB_INTERFACE",
    "LIGHTTPD_ENABLED",
    "MACVENDORDB",
    "LOCAL_IPV4",
];

fn v5_settings(src: &Source) -> Settings {
    let setup = key_values(&src.text("setupVars.conf").unwrap_or_default());
    let ftl = key_values(&src.text("pihole-FTL.conf").unwrap_or_default());
    let on = |k: &str| setup.get(k).is_some_and(|v| v == "true");
    let mut s = Settings {
        dnssec: on("DNSSEC"),
        blocking_off: setup.get("BLOCKING_ENABLED").is_some_and(|v| v == "false"),
        dhcp_active: on("DHCP_ACTIVE"),
        blocking_mode: ftl.get("BLOCKINGMODE").cloned(),
        ..Settings::default()
    };
    // PIHOLE_DNS_1, _2, ... in order.
    let mut dns: Vec<(u32, &String)> = setup
        .iter()
        .filter_map(|(k, v)| Some((k.strip_prefix("PIHOLE_DNS_")?.parse().ok()?, v)))
        .collect();
    dns.sort();
    s.upstreams = dns.into_iter().map(|(_, v)| v.clone()).collect();
    if let (Some(cidr), Some(target)) =
        (setup.get("REV_SERVER_CIDR"), setup.get("REV_SERVER_TARGET"))
    {
        s.rev_servers.push(format!(
            "{},{cidr},{target},{}",
            on("REV_SERVER"),
            setup.get("REV_SERVER_DOMAIN").map_or("", String::as_str)
        ));
    } else if let Some(target) = setup.get("CONDITIONAL_FORWARDING_IP") {
        // Before Pi-hole 5.3: a reverse zone name instead of a CIDR.
        let zone = setup
            .get("CONDITIONAL_FORWARDING_REVERSE")
            .map_or("", String::as_str);
        s.rev_servers.push(format!(
            "{},zone:{zone},{target},{}",
            on("CONDITIONAL_FORWARDING"),
            setup
                .get("CONDITIONAL_FORWARDING_DOMAIN")
                .map_or("", String::as_str)
        ));
    }
    if let Some((c, i)) = ftl.get("RATE_LIMIT").and_then(|v| v.split_once('/'))
        && let (Ok(c), Ok(i)) = (c.trim().parse(), i.trim().parse())
    {
        s.rate_limit = Some((c, i));
    }
    let lines = |f: &str| -> Vec<String> {
        src.text(f)
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect()
    };
    s.hosts = lines("custom.list");
    s.cnames = lines("05-pihole-custom-cname.conf")
        .into_iter()
        .filter_map(|l| l.strip_prefix("cname=").map(str::to_owned))
        .collect();
    s.dhcp_hosts = lines("04-pihole-static-dhcp.conf")
        .into_iter()
        .filter_map(|l| l.strip_prefix("dhcp-host=").map(str::to_owned))
        .collect();
    for (file, kv) in [("setupVars.conf", &setup), ("pihole-FTL.conf", &ftl)] {
        for k in kv.keys() {
            if !V5_MAPPED.contains(&k.as_str()) && !k.starts_with("PIHOLE_DNS_") {
                s.unmapped.push(format!("{file}: {k}"));
            }
        }
    }
    s
}

/// `ip[#port]` → a `udp://` URL, and whether it's this machine.
fn upstream_url(s: &str) -> Option<(String, bool)> {
    let (host, port) = match s.rsplit_once('#') {
        Some((h, p)) => (h, p.trim().parse::<u16>().ok()?),
        None => (s, 53),
    };
    let ip: IpAddr = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()?;
    let url = match ip {
        IpAddr::V4(a) => format!("udp://{a}:{port}"),
        IpAddr::V6(a) => format!("udp://[{a}]:{port}"),
    };
    Some((url, ip.is_loopback()))
}

/// The reverse zones covering `cidr` (a /23 is two /24 zones).
pub(crate) fn reverse_zones(cidr: &str) -> Result<Vec<String>, String> {
    let bad = || format!("`{cidr}` isn't a network like 192.168.1.0/24");
    let (a, len) = cidr.split_once('/').ok_or_else(bad)?;
    let len: usize = len.trim().parse().map_err(|_| bad())?;
    let ip: IpAddr = a.trim().parse().map_err(|_| bad())?;
    // Labels are octets (IPv4) or nibbles (IPv6), most significant first.
    let (labels, unit, suffix, hex): (Vec<u8>, usize, &str, bool) = match ip {
        IpAddr::V4(v) => (v.octets().to_vec(), 8, "in-addr.arpa", false),
        IpAddr::V6(v) => (
            v.octets().iter().flat_map(|b| [b >> 4, b & 15]).collect(),
            4,
            "ip6.arpa",
            true,
        ),
    };
    if len < unit || len > labels.len() * unit {
        return Err(bad());
    }
    let k = len.div_ceil(unit);
    let free = k * unit - len;
    let last = labels[k - 1] & !((1u8 << free) - 1);
    let show = |b: u8| if hex { format!("{b:x}") } else { b.to_string() };
    Ok((0..1u16 << free)
        .filter_map(|i| u8::try_from(i).ok())
        .map(|i| {
            let mut parts: Vec<String> = labels[..k - 1].iter().map(|&b| show(b)).collect();
            parts.push(show(last + i));
            parts.reverse();
            format!("{}.{suffix}", parts.join("."))
        })
        .collect())
}

/// A list name (`[a-z0-9_-]`, at most 64) from free text.
pub(crate) fn slug(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    out.truncate(max);
    out.trim_end_matches('-').to_owned()
}

pub(crate) fn unique(name: &str, taken: &mut HashSet<String>) -> String {
    let mut n = name.to_owned();
    let mut i = 2;
    while !taken.insert(n.to_ascii_lowercase()) {
        n = format!("{name} ({i})");
        i += 1;
    }
    n
}

/// A MAC in `aa:bb:cc:dd:ee:ff` form.
pub(crate) fn mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    (parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit())))
    .then(|| parts.join(":").to_ascii_lowercase())
}

struct List {
    name: String,
    note: String,
    url: Option<String>,
    path: Option<String>,
    rules: Vec<String>,
    kind: ListKind,
    exact: bool,
    enabled: bool,
}

struct Client {
    name: String,
    keys: Vec<String>,
    groups: Vec<String>,
}

/// The result: a TOML configuration and what didn't carry over.
#[derive(Debug)]
pub(crate) struct Imported {
    pub toml: String,
    pub version: &'static str,
    pub notes: Vec<String>,
    pub counts: String,
}

/// Maps a Pi-hole setup onto TelltaleDNS configuration (ADR-061).
pub(crate) fn convert(src: &Source, source_name: &str) -> Result<Imported, String> {
    let (version, settings) = match src.text("pihole.toml") {
        Some(t) => ("v6", v6_settings(&t)?),
        None if src.files.contains_key("setupVars.conf") || !src.tables.is_empty() => {
            ("v5", v5_settings(src))
        }
        None => return Err("no Pi-hole settings or group tables found".into()),
    };
    let mut b = Builder::new(src, settings);
    let upstreams = b.upstreams();
    let forwards = b.forwards();
    let records = b.records();
    b.groups();
    b.adlists();
    b.domains();
    b.write_lists();
    let none_group = b.write_groups();
    b.clients(none_group.as_deref());
    let reservations = b.reservations();
    b.write_clients();
    let head = b.scalars();
    let counts = format!(
        "{upstreams} upstreams, {forwards} forwarded domains, {records} records, {} lists, {} groups, {} devices ({reservations} from DHCP reservations)",
        b.lists.len(),
        b.group_names.len() + usize::from(none_group.is_some()),
        b.clients.len(),
    );
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Imported from {} (Pi-hole {version}) by `telltale import pihole`.",
        one_line(source_name)
    );
    let _ = writeln!(out, "# {counts}.");
    let _ = writeln!(out, "# Review before use. Notes:");
    for n in &b.notes {
        let _ = writeln!(out, "#   - {}", one_line(n));
    }
    out.push_str(&head);
    out.push_str(&b.body);
    Ok(Imported {
        toml: out,
        version,
        notes: b.notes,
        counts,
    })
}

/// The conversion's state: each step appends TOML to `body` and notes to `notes`.
struct Builder<'a> {
    src: &'a Source,
    s: Settings,
    notes: Vec<String>,
    body: String,
    /// Pi-hole group ID → our group name (0 is Pi-hole's Default → `default`).
    group_names: BTreeMap<i64, String>,
    group_off: BTreeSet<i64>,
    group_taken: HashSet<String>,
    group_lists: BTreeMap<i64, Vec<String>>,
    lists: Vec<List>,
    clients: Vec<Client>,
    client_names: HashSet<String>,
    keys_seen: HashSet<String>,
}

fn kind_of(t: i64) -> ListKind {
    // Domain types: 0 exact allow, 1 exact deny, 2 regex allow, 3 regex deny.
    if t % 2 == 0 {
        ListKind::Allow
    } else {
        ListKind::Block
    }
}

impl<'a> Builder<'a> {
    fn new(src: &'a Source, s: Settings) -> Self {
        Self {
            src,
            s,
            notes: Vec::new(),
            body: String::new(),
            group_names: BTreeMap::from([(0, "default".to_owned())]),
            group_off: BTreeSet::new(),
            group_taken: HashSet::from(["default".to_owned()]),
            group_lists: BTreeMap::new(),
            lists: Vec::new(),
            clients: Vec::new(),
            client_names: HashSet::new(),
            keys_seen: HashSet::new(),
        }
    }

    /// Upstreams in the `default` group; Pi-hole asks the fastest of its servers.
    fn upstreams(&mut self) -> usize {
        let mut members = Vec::new();
        for (i, u) in self.s.upstreams.iter().enumerate() {
            let Some((url, local)) = upstream_url(u) else {
                self.notes.push(format!(
                    "Upstream `{}` isn't an IP address; add it by hand.",
                    one_line(u)
                ));
                continue;
            };
            let name = format!("pihole-{}", i + 1);
            let _ = writeln!(
                self.body,
                "\n[[upstream]]\nname = {}\nurl = {}",
                toml_str(&name),
                toml_str(&url)
            );
            if local {
                self.notes.push(format!(
                    "Upstream {u} runs on the Pi-hole machine itself (often unbound): keep it running next to TelltaleDNS, which reaches it at the same address when they share a machine. Or let TelltaleDNS resolve from the root servers itself: `url = \"recursive://\"` (`docs/running.md`, Recursive resolution)."
                ));
            }
            members.push(name);
        }
        if !members.is_empty() {
            let _ = writeln!(
                self.body,
                "\n[[upstream_group]]\nname = \"default\"\nmembers = {}\nstrategy = \"fastest\"",
                toml_array(&members)
            );
        }
        members.len()
    }

    /// Conditional forwarding ("rev servers"): `enabled,network,target[#port],domain`.
    fn forwards(&mut self) -> usize {
        let mut n = 0;
        for r in &self.s.rev_servers {
            let f: Vec<&str> = r.split(',').map(str::trim).collect();
            let [on, net, target, rest @ ..] = f.as_slice() else {
                self.notes.push(format!(
                    "Conditional forwarding `{}` isn't in a known form.",
                    one_line(r)
                ));
                continue;
            };
            if *on != "true" {
                self.notes.push(format!(
                    "Conditional forwarding to {target} for {net} was switched off; not imported."
                ));
                continue;
            }
            let Some((url, _)) = upstream_url(target) else {
                self.notes.push(format!(
                    "Conditional forwarding target `{}` isn't an IP address.",
                    one_line(target)
                ));
                continue;
            };
            let mut suffixes: Vec<String> = rest
                .first()
                .filter(|d| !d.is_empty())
                .map(|d| d.to_ascii_lowercase())
                .into_iter()
                .collect();
            match net.strip_prefix("zone:") {
                Some(z) if !z.is_empty() => {
                    suffixes.push(z.trim_end_matches('.').to_ascii_lowercase());
                }
                Some(_) => {}
                None => match reverse_zones(net) {
                    Ok(z) => suffixes.extend(z),
                    Err(e) => self.notes.push(format!(
                        "Conditional forwarding: {e}; reverse lookups not routed."
                    )),
                },
            }
            if suffixes.is_empty() {
                continue;
            }
            n += 1;
            let _ = writeln!(
                self.body,
                "\n[[upstream]]\nname = {g}\nurl = {u}\n\n[[upstream_group]]\nname = {g}\nmembers = [{g}]\n\n[[route]]\nmatch_suffix = {s}\nupstream_group = {g}\ndnssec_nta = true",
                g = toml_str(&format!("pihole-forward-{n}")),
                u = toml_str(&url),
                s = toml_array(&suffixes)
            );
        }
        n
    }

    /// Local DNS (`IP name...`) and CNAME (`alias[,alias...],target[,ttl]`) records.
    fn records(&mut self) -> usize {
        let mut records: Vec<(String, &str, String, Option<u32>)> = Vec::new();
        let clean = |n: &str| n.trim_end_matches('.').to_ascii_lowercase();
        for h in &self.s.hosts {
            let mut it = h.split_whitespace();
            let Some(ip) = it.next().and_then(|a| a.parse::<IpAddr>().ok()) else {
                self.notes.push(format!(
                    "Local DNS entry `{}` has no valid address.",
                    one_line(h)
                ));
                continue;
            };
            let rtype = if ip.is_ipv4() { "A" } else { "AAAA" };
            records.extend(it.map(|name| (clean(name), rtype, ip.to_string(), None)));
        }
        for c in &self.s.cnames {
            let mut f: Vec<&str> = c.split(',').map(str::trim).collect();
            let ttl = f.last().and_then(|t| t.parse::<u32>().ok());
            if ttl.is_some() {
                f.pop();
            }
            let Some((target, aliases)) = f.split_last().filter(|(_, a)| !a.is_empty()) else {
                self.notes
                    .push(format!("CNAME `{}` isn't in a known form.", one_line(c)));
                continue;
            };
            records.extend(
                aliases
                    .iter()
                    .map(|a| (clean(a), "CNAME", clean(target), ttl)),
            );
        }
        let mut seen = HashSet::new();
        records.retain(|r| seen.insert(r.clone()));
        let mut kept = 0;
        for (name, rtype, value, ttl) in &records {
            if telltale_filter::parse::normalize(name).is_err() {
                self.notes.push(format!(
                    "Local name `{}` isn't a valid DNS name.",
                    one_line(name)
                ));
                continue;
            }
            kept += 1;
            let _ = writeln!(
                self.body,
                "\n[[record]]\nname = {}\ntype = \"{rtype}\"\nvalue = {}",
                toml_str(name),
                toml_str(value)
            );
            if let Some(t) = ttl {
                let _ = writeln!(self.body, "ttl = {t}");
            }
        }
        kept
    }

    fn groups(&mut self) {
        for g in self.src.rows("group") {
            let Some(id) = int(g, "id") else { continue };
            if !enabled(g) {
                self.group_off.insert(id);
            }
            if id != 0 {
                let n = one_line(&text(g, "name"));
                let n = if n.is_empty() {
                    format!("group {id}")
                } else {
                    n
                };
                let n = unique(&n, &mut self.group_taken);
                self.group_names.insert(id, n);
            }
        }
        self.group_lists = self
            .group_names
            .keys()
            .map(|&id| (id, Vec::new()))
            .collect();
    }

    fn assign(&mut self, list: &str, groups: &BTreeSet<i64>) {
        for g in groups {
            if let Some(l) = self.group_lists.get_mut(g) {
                l.push(list.to_owned());
            }
        }
    }

    /// Adlists → URL (or file) lists in the groups Pi-hole assigned them to.
    fn adlists(&mut self) {
        let adlist_groups = membership(self.src.rows("adlist_by_group"), "adlist_id");
        let mut unused = 0;
        for a in self.src.rows("adlist") {
            let Some(id) = int(a, "id") else { continue };
            let Some(groups) = adlist_groups.get(&id).filter(|g| !g.is_empty()) else {
                unused += 1;
                continue;
            };
            let address = text(a, "address");
            let (url, path) = if let Some(p) = address.strip_prefix("file://") {
                (None, Some(p.to_owned()))
            } else if address.starts_with("https://") || address.starts_with("http://") {
                (Some(address.clone()), None)
            } else {
                self.notes.push(format!(
                    "Adlist `{}` isn't a URL or file; not imported.",
                    one_line(&address)
                ));
                continue;
            };
            let tail = address
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or("");
            let tail = slug(tail.split('.').next().unwrap_or(tail), 40);
            let name = if tail.is_empty() {
                format!("pihole-{id}")
            } else {
                format!("pihole-{id}-{tail}")
            };
            self.assign(&name, groups);
            let comment = one_line(&text(a, "comment"));
            self.lists.push(List {
                name,
                note: if comment.is_empty() {
                    format!("Pi-hole adlist {id}")
                } else {
                    format!("Pi-hole adlist {id}: {comment}")
                },
                url,
                path,
                rules: Vec::new(),
                // v6: type 1 is an allowlist ("antigravity").
                kind: if int(a, "type") == Some(1) {
                    ListKind::Allow
                } else {
                    ListKind::Block
                },
                exact: false,
                enabled: enabled(a),
            });
        }
        if unused > 0 {
            self.notes.push(format!(
                "{unused} adlist(s) belonged to no group (unused in Pi-hole); not imported."
            ));
        }
    }

    /// Domain entries → inline lists, one per (type, set of groups).
    fn domains(&mut self) {
        let domain_groups = membership(self.src.rows("domainlist_by_group"), "domainlist_id");
        let mut buckets: BTreeMap<(i64, BTreeSet<i64>), Vec<String>> = BTreeMap::new();
        let (mut off, mut orphan) = (0, 0);
        for d in self.src.rows("domainlist") {
            let (Some(id), Some(t)) = (int(d, "id"), int(d, "type")) else {
                continue;
            };
            if !enabled(d) {
                off += 1;
                continue;
            }
            let Some(groups) = domain_groups.get(&id).filter(|g| !g.is_empty()) else {
                orphan += 1;
                continue;
            };
            let domain = one_line(&text(d, "domain"));
            match domain_rule(&domain, t) {
                Ok(rule) => buckets.entry((t, groups.clone())).or_default().push(rule),
                Err(why) => self
                    .notes
                    .push(format!("Domain entry `{domain}` can't be used: {why}.")),
            }
        }
        if off > 0 {
            self.notes
                .push(format!("{off} switched-off domain entr(ies) not imported."));
        }
        if orphan > 0 {
            self.notes.push(format!(
                "{orphan} domain entr(ies) belonged to no group (unused in Pi-hole); not imported."
            ));
        }
        let mut per_type: BTreeMap<i64, usize> = BTreeMap::new();
        for ((t, groups), rules) in buckets {
            let base = match t {
                0 => "pihole-allow-exact",
                1 => "pihole-deny-exact",
                2 => "pihole-allow-regex",
                _ => "pihole-deny-regex",
            };
            let n = per_type.entry(t).or_default();
            *n += 1;
            let name = if *n == 1 {
                base.to_owned()
            } else {
                format!("{base}-{n}")
            };
            let who: Vec<&str> = groups
                .iter()
                .filter_map(|g| self.group_names.get(g).map(String::as_str))
                .collect();
            let note = format!("Pi-hole domains for group(s): {}", who.join(", "));
            self.assign(&name, &groups);
            self.lists.push(List {
                name,
                note,
                url: None,
                path: None,
                rules,
                kind: kind_of(t),
                exact: t < 2,
                enabled: true,
            });
        }
    }

    fn write_lists(&mut self) {
        for l in &self.lists {
            let b = &mut self.body;
            let _ = writeln!(
                b,
                "\n# {}\n[[list]]\nname = {}",
                one_line(&l.note),
                toml_str(&l.name)
            );
            if let Some(u) = &l.url {
                let _ = writeln!(b, "url = {}", toml_str(u));
            }
            if let Some(p) = &l.path {
                let _ = writeln!(b, "path = {}", toml_str(p));
            }
            if !l.rules.is_empty() {
                let _ = writeln!(b, "rules = {}", toml_array(&l.rules));
            }
            if l.kind == ListKind::Allow {
                let _ = writeln!(b, "kind = \"allow\"");
            }
            if l.exact {
                let _ = writeln!(b, "match = \"exact\"");
            }
            if !l.enabled {
                let _ = writeln!(b, "enabled = false");
            }
        }
    }

    /// Groups with exactly their Pi-hole lists and blocking mode. Returns the group for
    /// clients in no Pi-hole group, if any are.
    fn write_groups(&mut self) -> Option<String> {
        let block_mode = match self.s.blocking_mode.as_deref() {
            None | Some("NULL") => None,
            Some("NX" | "NXDOMAIN") => Some("nxdomain"),
            Some("NODATA") => Some("nodata"),
            Some(m) => {
                self.notes.push(format!(
                    "Blocking mode {} (answers with an IP) isn't imported; blocked names get 0.0.0.0 / ::.",
                    one_line(m)
                ));
                None
            }
        };
        if self.s.blocking_off {
            self.notes
                .push("Blocking was paused in Pi-hole; the imported lists are active.".into());
        }
        // Clients in no group get no lists in Pi-hole.
        let client_groups = membership(self.src.rows("client_by_group"), "client_id");
        let needs_none = self.src.rows("client").iter().any(|c| {
            int(c, "id").is_some_and(|id| client_groups.get(&id).is_none_or(BTreeSet::is_empty))
        });
        let none_group = needs_none.then(|| unique("pihole-no-group", &mut self.group_taken));
        for (id, name) in &self.group_names {
            let ls = if self.group_off.contains(id) {
                self.notes.push(format!(
                    "Group `{name}` was switched off in Pi-hole: imported with no lists."
                ));
                Vec::new()
            } else {
                self.group_lists.get(id).cloned().unwrap_or_default()
            };
            let _ = writeln!(
                self.body,
                "\n[[group]]\nname = {}\nlists = {}",
                toml_str(name),
                toml_array(&ls)
            );
            if let Some(m) = block_mode {
                let _ = writeln!(self.body, "block_mode = \"{m}\"");
            }
        }
        if let Some(n) = &none_group {
            self.notes.push(format!(
                "Some Pi-hole clients were in no group (nothing blocked for them): they're in `{n}`, which has no lists."
            ));
            let _ = writeln!(
                self.body,
                "\n# Pi-hole clients in no group: nothing is blocked for them.\n[[group]]\nname = {}\nlists = []",
                toml_str(n)
            );
        }
        none_group
    }

    fn clients(&mut self, none_group: Option<&str>) {
        let client_groups = membership(self.src.rows("client_by_group"), "client_id");
        for c in self.src.rows("client") {
            let Some(id) = int(c, "id") else { continue };
            let raw = text(c, "ip");
            let key = if let Some(m) = mac(&raw) {
                m
            } else if raw.parse::<IpAddr>().is_ok() || telltale_config::Cidr::parse(&raw).is_ok() {
                raw.clone()
            } else {
                let how = if raw.starts_with(':') {
                    "network interface"
                } else {
                    "host name"
                };
                self.notes.push(format!(
                    "Client `{}` is matched by {how} in Pi-hole; TelltaleDNS matches by address. Add its IP, network, or MAC.",
                    one_line(&raw)
                ));
                continue;
            };
            if !self.keys_seen.insert(key.clone()) {
                continue;
            }
            let comment = one_line(&text(c, "comment"));
            let name = unique(
                if comment.is_empty() { &raw } else { &comment },
                &mut self.client_names,
            );
            let mut groups: Vec<String> = client_groups
                .get(&id)
                .into_iter()
                .flatten()
                .filter_map(|g| self.group_names.get(g).cloned())
                .collect();
            if groups.is_empty() {
                groups.extend(none_group.map(str::to_owned));
            }
            if groups == ["default"] {
                groups.clear();
            }
            self.clients.push(Client {
                name,
                keys: vec![key],
                groups,
            });
        }
    }

    /// DHCP reservations name devices: their MAC and IP join a matching client, or become a
    /// new one named by the host name.
    fn reservations(&mut self) -> usize {
        let mut n = 0;
        for h in &self.s.dhcp_hosts {
            let (keys, host) = dhcp_host(h);
            if keys.is_empty() {
                continue;
            }
            n += 1;
            if let Some(c) = self
                .clients
                .iter_mut()
                .find(|c| c.keys.iter().any(|k| keys.contains(k)))
            {
                for k in keys {
                    if self.keys_seen.insert(k.clone()) {
                        c.keys.push(k);
                    }
                }
                continue;
            }
            let fresh: Vec<String> = keys
                .into_iter()
                .filter(|k| self.keys_seen.insert(k.clone()))
                .collect();
            let Some(first) = fresh.first() else { continue };
            let name = unique(
                &one_line(host.as_deref().unwrap_or(first)),
                &mut self.client_names,
            );
            self.clients.push(Client {
                name,
                keys: fresh,
                groups: Vec::new(),
            });
        }
        if self.s.dhcp_active {
            self.notes.push("Pi-hole's DHCP server isn't imported: TelltaleDNS leaves DHCP to your router (or Pi-hole). Reservations became named devices.".into());
        }
        n
    }

    fn write_clients(&mut self) {
        for c in &self.clients {
            let _ = writeln!(
                self.body,
                "\n[[client]]\nname = {}\nmatch = {}",
                toml_str(&c.name),
                toml_array(&c.keys)
            );
            if !c.groups.is_empty() {
                let _ = writeln!(self.body, "groups = {}", toml_array(&c.groups));
            }
        }
    }

    /// `[dnssec]` and `[ratelimit]` (they go first in the file), and the closing notes.
    fn scalars(&mut self) -> String {
        let mut head = String::new();
        if self.s.dnssec {
            let _ = writeln!(head, "\n[dnssec]\nmode = \"validate\"");
        }
        if let Some((count, interval)) = self.s.rate_limit
            && (count, interval) != (1000, 60)
        {
            if count == 0 || interval == 0 {
                let _ = writeln!(head, "\n[ratelimit]\nenabled = false");
            } else {
                let _ = writeln!(
                    head,
                    "\n[ratelimit]\nqueries = {count}\nwindow_secs = {interval}"
                );
            }
        }
        if !self.s.unmapped.is_empty() {
            let keys: Vec<String> = self.s.unmapped.iter().map(|k| one_line(k)).collect();
            self.notes.push(format!(
                "Pi-hole settings with no TelltaleDNS equivalent (not imported): {}.",
                keys.join(", ")
            ));
        }
        self.notes
            .push("Query history, the admin password, and API tokens aren't imported.".into());
        head
    }
}

/// A Pi-hole domain entry as a list rule our parser accepts, or why it can't be one.
fn domain_rule(domain: &str, t: i64) -> Result<String, String> {
    let opts = ListOptions {
        kind: kind_of(t),
        match_mode: if t < 2 {
            ListMatch::Exact
        } else {
            ListMatch::Subtree
        },
    };
    let mut parsed = Vec::new();
    let mut rule = domain.to_owned();
    let mut kind = parse_line(&rule, opts, &mut parsed);
    // A regex without metacharacters would read as a plain name: make it a /regex/.
    if t >= 2
        && !matches!(
            parsed.first().map(|r| &r.pattern),
            Some(Pattern::Regex { .. })
        )
    {
        rule = format!("/{domain}/");
        parsed.clear();
        kind = parse_line(&rule, opts, &mut parsed);
    }
    match kind {
        LineKind::Rules(_) => Ok(rule),
        other => Err(format!("{other:?}")),
    }
}

/// A dnsmasq `dhcp-host` value: its MAC and IP as client keys, and its host name.
fn dhcp_host(h: &str) -> (Vec<String>, Option<String>) {
    let (mut m, mut ip, mut host) = (None, None, None);
    for f in h.split(',').map(str::trim) {
        if let Some(x) = mac(f) {
            m = Some(x);
        } else if let Ok(a) = f.trim_matches(['[', ']']).parse::<IpAddr>() {
            ip = Some(a.to_string());
        } else if !f.is_empty()
            && !f.contains(':')
            && f != "infinite"
            && !f
                .trim_end_matches(['s', 'm', 'h', 'd', 'w'])
                .bytes()
                .all(|b| b.is_ascii_digit())
        {
            host = Some(f.to_owned());
        }
    }
    ([m, ip].into_iter().flatten().collect(), host)
}

pub(crate) fn toml_array(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|s| toml_str(s))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

#[cfg(test)]
mod tests;
