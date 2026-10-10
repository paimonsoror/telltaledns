//! Device identification (REQ: OBS-025; ADR-117, `docs/design/device-identification.md`):
//! what kind of device each address is, guessed from its MAC vendor (the IEEE registry,
//! [`oui`]), the names it announces (router DHCP, mDNS), and the registrable domains it talks
//! to, scored against a shipped catalog of signatures ([`catalog`], [`score`]).
//!
//! It runs on a thread of its own at background priority, every 10 minutes (the first pass a
//! minute after start, and sooner when the API asks for identities older than 15 seconds), over
//! the devices seen in the last day. Inputs come from what is already kept: the aggregator's
//! per-client top domains, the neighbor table, the router and mDNS names; a device the
//! aggregator doesn't hold gets one query-log read (at most 8 per pass). Nothing here touches
//! the query path, and nothing acts on a guess: it suggests a name and, when a group asks for
//! that kind of device, a group. `[[client]] kind` overrides it.

pub(crate) mod catalog;
pub(crate) mod oui;
pub(crate) mod score;

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use telltale_api::model::{DeviceIdentity, IdentityEvidence, IdentityRunnerUp, MatchedDomain};
use telltale_config::{Config, DeviceClass};
use telltale_telemetry::agg::{Aggregates, HourSel, TopKind};

use self::score::{Guess, Inputs};

/// `<data_dir>/devices.json`: the devices seen and their identities, so a restart doesn't
/// blank the Clients page.
pub(crate) const FILE: &str = "devices.json";
const FIRST_PASS: Duration = Duration::from_secs(60);
const PASS_EVERY: Duration = Duration::from_secs(600);
/// Identities older than this are refreshed when the API asks (a pass costs milliseconds).
const FRESH: Duration = Duration::from_secs(15);
/// Devices not seen for a day are forgotten.
const SEEN_FOR_S: u64 = 86_400;
/// Per device: at most this many domains, each at most this long (≤ 1 KiB of state).
pub(crate) const MAX_DOMAINS: usize = 20;
const MAX_DOMAIN_LEN: usize = 40;
/// Query-log reads per pass, for devices the aggregator doesn't hold, and how long their
/// domains count before another read.
const LOG_PER_PASS: usize = 8;
const LOG_REFRESH_S: u64 = 6 * 3600;
const PERSIST_EVERY_S: u64 = 3600;

/// What is kept per device between passes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Seen {
    /// Last seen (Unix seconds).
    pub(crate) last_s: u64,
    /// Its registrable domains, heaviest first (at most [`MAX_DOMAINS`]).
    #[serde(default)]
    pub(crate) domains: Vec<String>,
    /// When `domains` was last refreshed.
    #[serde(default)]
    pub(crate) domains_s: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Persisted {
    seen: BTreeMap<String, Seen>,
    identities: Vec<DeviceIdentity>,
}

/// The latest pass.
#[derive(Debug, Default)]
pub(crate) struct Snapshot {
    /// Why there are no identities (`disabled`, `privacy_level`).
    pub(crate) reason: Option<&'static str>,
    /// By device (its address as the query log shows it), with evidence.
    pub(crate) by_client: BTreeMap<String, DeviceIdentity>,
    /// When it was made (`None`: loaded from disk, or not yet).
    pub(crate) at: Option<Instant>,
}

/// The identifier: state, the latest identities, and its counters.
#[derive(Debug)]
pub(crate) struct Identifier {
    dir: PathBuf,
    seen: Mutex<BTreeMap<String, Seen>>,
    current: ArcSwap<Snapshot>,
    wake: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    last_persist_s: AtomicU64,
    pub(crate) runs: AtomicU64,
    pub(crate) micros: AtomicU64,
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn octets(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// `ads.example.co.uk` → `example.co.uk` (the anomaly engine's eTLD+1 rules).
pub(crate) fn registrable(dotted: &str) -> Option<String> {
    let mut wire = Vec::with_capacity(dotted.len() + 2);
    for l in dotted.trim_end_matches('.').split('.') {
        if l.is_empty() || l.len() > 63 {
            return None;
        }
        wire.push(u8::try_from(l.len()).ok()?);
        wire.extend_from_slice(l.as_bytes());
    }
    wire.push(0);
    telltale_telemetry::anomaly::registrable(&wire)
}

/// Registrable domains from `(name, count)` pairs, heaviest first (then by name), capped.
pub(crate) fn top_registrable(names: impl IntoIterator<Item = (String, u64)>) -> Vec<String> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for (n, c) in names {
        if let Some(r) = registrable(&n).filter(|r| r.len() <= MAX_DOMAIN_LEN) {
            *counts.entry(r).or_default() += c;
        }
    }
    let mut v: Vec<(String, u64)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.into_iter().take(MAX_DOMAINS).map(|(n, _)| n).collect()
}

/// The devices the aggregator saw lately, with the domains it keeps for them.
fn observe(agg: &Aggregates, max: usize) -> BTreeMap<String, (IpAddr, Vec<String>)> {
    let mut out: BTreeMap<String, (IpAddr, Vec<String>)> = BTreeMap::new();
    for sel in [HourSel::Previous, HourSel::Current] {
        for c in agg.clients_with_domains(sel) {
            let ip = Ipv6Addr::from(c).to_canonical();
            let key = telltale_telemetry::agg::client_text(c);
            let names = agg
                .top_client_domains_in(sel, c, 100)
                .into_iter()
                .map(|t| (t.key, t.count));
            let e = out.entry(key).or_insert_with(|| (ip, Vec::new()));
            let mut all: Vec<(String, u64)> = e.1.iter().map(|d| (d.clone(), 1)).collect();
            all.extend(names);
            e.1 = top_registrable(all);
        }
        for t in agg.top_names(TopKind::Clients, sel, max) {
            if let Ok(ip) = t.key.parse::<IpAddr>() {
                out.entry(t.key).or_insert_with(|| (ip, Vec::new()));
            }
        }
    }
    out
}

/// A device's inputs before scoring: its address, MAC (if known), names, and domains.
#[derive(Debug, Clone)]
pub(crate) struct Device {
    pub(crate) key: String,
    pub(crate) ip: IpAddr,
    pub(crate) mac: Option<[u8; 6]>,
    pub(crate) names: Vec<String>,
    pub(crate) domains: Vec<String>,
}

/// Devices with the same MAC (IPv4 and IPv6 of one device) share names and domains.
pub(crate) fn merge_by_mac(devices: &mut [Device]) {
    let mut by_mac: HashMap<[u8; 6], (Vec<String>, Vec<String>)> = HashMap::new();
    for d in devices.iter() {
        if let Some(m) = d.mac {
            let e = by_mac.entry(m).or_default();
            e.0.extend(d.names.iter().cloned());
            e.1.extend(d.domains.iter().cloned());
        }
    }
    for d in devices.iter_mut() {
        if let Some((names, domains)) = d.mac.and_then(|m| by_mac.get(&m)) {
            d.names.clone_from(names);
            d.domains.clone_from(domains);
        }
    }
}

/// The device's inputs for scoring.
pub(crate) fn inputs(d: &Device) -> Inputs {
    Inputs {
        vendor: d.mac.and_then(oui::lookup).map(str::to_owned),
        // A private (locally administered) address has no registry prefix to show.
        mac_prefix: d.mac.filter(|m| m[0] & 0x02 == 0).map(oui::prefix_text),
        names: d.names.clone(),
        domains: d.domains.clone(),
    }
    .normalized()
}

/// A guess as the API shows it.
pub(crate) fn to_identity(key: &str, g: &Guess, inp: &Inputs, at_s: u64) -> DeviceIdentity {
    DeviceIdentity {
        client: key.to_owned(),
        available: true,
        reason: None,
        product: g.product.clone(),
        product_id: g.product_id.clone(),
        class: g.class.as_str().to_owned(),
        level: g.level.as_str().to_owned(),
        score: (g.score * 1000.0).round() / 1000.0,
        vendor: g.vendor.clone(),
        suggested_group: None,
        source: "inferred".to_owned(),
        computed_at: Some(telltale_api::time::format_us(
            at_s.saturating_mul(1_000_000),
        )),
        node: None,
        evidence: Some(IdentityEvidence {
            domains: g
                .domains
                .iter()
                .map(|(n, w)| MatchedDomain {
                    name: n.clone(),
                    weight: *w,
                })
                .collect(),
            mac_prefix: g.mac_prefix.clone(),
            matched_name: g.matched_name.clone(),
            names: inp.names.clone(),
            seen_domains: inp.domains.clone(),
            runner_up: g.runner_up.as_ref().map(|(id, name, s)| IdentityRunnerUp {
                product: name.clone(),
                product_id: id.clone(),
                score: (s * 1000.0).round() / 1000.0,
            }),
        }),
    }
}

/// `[[client]] kind`: what the device was set to be, instead of a guess.
pub(crate) fn override_identity(key: &str, kind: DeviceClass, at_s: u64) -> DeviceIdentity {
    DeviceIdentity {
        client: key.to_owned(),
        available: true,
        reason: None,
        product: None,
        product_id: None,
        class: kind.as_str().to_owned(),
        level: if kind == DeviceClass::Unknown {
            "unknown"
        } else {
            "likely"
        }
        .to_owned(),
        score: 1.0,
        vendor: None,
        suggested_group: None,
        source: "override".to_owned(),
        computed_at: Some(telltale_api::time::format_us(
            at_s.saturating_mul(1_000_000),
        )),
        node: None,
        evidence: None,
    }
}

/// The group whose `device_classes` lists `class`, unless the device is in it already.
pub(crate) fn suggested_group(cfg: &Config, class: &str, in_groups: &[Box<str>]) -> Option<String> {
    let class = DeviceClass::parse(class).filter(|c| *c != DeviceClass::Unknown)?;
    let g = cfg
        .group
        .iter()
        .find(|g| g.device_classes.contains(&class))?;
    (!in_groups.iter().any(|x| **x == *g.name.as_str())).then(|| g.name.to_string())
}

/// The catalog in effect: the shipped one plus `[identify] signatures_file`.
pub(crate) fn load_catalog(cfg: &Config) -> (Vec<catalog::Signature>, Option<String>) {
    let path = cfg.identify.signatures_file.as_str();
    if path.is_empty() {
        return (catalog::shipped().to_vec(), None);
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return (catalog::shipped().to_vec(), Some(format!("{path}: {e}"))),
    };
    match catalog::with_extra(Some((&text, path))) {
        Ok(v) => (v, None),
        Err(e) => (catalog::shipped().to_vec(), Some(e)),
    }
}

/// One device's registrable domains from the query log over the last day (newest first, at
/// most 2,000 rows).
fn domains_from_log(dirs: &[PathBuf], ip: IpAddr, now_s: u64) -> Vec<String> {
    let filter = telltale_store::qlog::Filter {
        from_us: now_s.saturating_sub(SEEN_FOR_S).saturating_mul(1_000_000),
        client_ip: Some(octets(ip)),
        ..telltale_store::qlog::Filter::default()
    };
    let opts = telltale_store::qlog::Options {
        threads: 1,
        on_thread_start: Some(telltale_net::background_thread),
    };
    let mut names: Vec<(String, u64)> = Vec::new();
    for dir in dirs {
        if let Ok(page) = telltale_store::qlog::search_with(dir, &filter, 2000, None, &opts) {
            names.extend(page.rows.into_iter().map(|r| (r.name, 1)));
        }
    }
    top_registrable(names)
}

impl Identifier {
    /// Loads `<data_dir>/devices.json` if there is one.
    pub(crate) fn open(data_dir: &Path) -> Self {
        let file: Persisted = std::fs::read(data_dir.join(FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let by_client = file
            .identities
            .into_iter()
            .map(|i| (i.client.clone(), i))
            .collect();
        Self {
            dir: data_dir.to_owned(),
            seen: Mutex::new(file.seen),
            current: ArcSwap::from_pointee(Snapshot {
                reason: None,
                by_client,
                at: None,
            }),
            wake: Mutex::new(None),
            last_persist_s: AtomicU64::new(now_s()),
            runs: AtomicU64::new(0),
            micros: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_snapshot(&self, s: Snapshot) {
        self.current.store(Arc::new(s));
    }

    pub(crate) fn snapshot(&self) -> Arc<Snapshot> {
        self.current.load_full()
    }

    /// Asks for a pass now when the latest is older than 15 seconds (never waits for it).
    pub(crate) fn nudge(&self) {
        if self.current.load().at.is_some_and(|t| t.elapsed() < FRESH) {
            return;
        }
        if let Some(tx) = self
            .wake
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            let _ = tx.send(());
        }
    }

    /// Starts the identifier's thread (background priority).
    pub(crate) fn spawn(self: &Arc<Self>, src: Arc<crate::http::Sources>) {
        match catalog::check_shipped() {
            Ok(n) => {
                let (vendors, mid, large, _) = oui::stats();
                tracing::debug!(
                    signatures = n,
                    vendors,
                    prefixes = mid + large,
                    "device identification ready"
                );
            }
            Err(e) => tracing::warn!("device signatures: {e}"),
        }
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        *self.wake.lock().unwrap_or_else(PoisonError::into_inner) = Some(tx);
        let me = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("telltale-identify".into())
            .spawn(move || {
                telltale_net::background_thread();
                let mut wait = FIRST_PASS;
                // Woken early, or on time; ends when the identifier is dropped.
                while let Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                    rx.recv_timeout(wait)
                {
                    while rx.try_recv().is_ok() {}
                    me.pass(&src, now_s());
                    wait = PASS_EVERY;
                }
            });
        if let Err(e) = spawned {
            tracing::warn!("device identification couldn't start: {e}");
        }
    }

    /// One pass over the devices seen in the last day.
    #[allow(clippy::too_many_lines)] // gather, score, store
    pub(crate) fn pass(&self, src: &crate::http::Sources, now: u64) {
        let started = Instant::now();
        let cfg = src.config.load_full();
        if let Some(r) = off_reason(&cfg) {
            self.current.store(Arc::new(Snapshot {
                reason: Some(r),
                by_client: BTreeMap::new(),
                at: Some(Instant::now()),
            }));
            return;
        }
        let max = usize::try_from(cfg.identify.max_clients).unwrap_or(1024);
        let observed = observe(&src.pipeline.telemetry.aggregates(), max);
        let routers = src.pipeline.router_leases.load_full();
        let mdns = src.pipeline.mdns_names.load_full();
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        for (key, (_, domains)) in &observed {
            let s = seen.entry(key.clone()).or_default();
            s.last_s = now;
            if !domains.is_empty() {
                s.domains.clone_from(domains);
                s.domains_s = now;
            }
        }
        for ip in routers.keys().chain(mdns.keys()) {
            let key = telltale_telemetry::agg::client_text(octets(IpAddr::V4(*ip)));
            seen.entry(key).or_default().last_s = now;
        }
        seen.retain(|_, s| s.last_s + SEEN_FOR_S >= now);
        if seen.len() > max {
            let mut by_age: Vec<(u64, String)> =
                seen.iter().map(|(k, s)| (s.last_s, k.clone())).collect();
            by_age.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
            for (_, k) in by_age.into_iter().skip(max) {
                seen.remove(&k);
            }
        }
        // Devices the aggregator holds no domains for: a few query-log reads, stalest first.
        let mut stale: Vec<(u64, String)> = seen
            .iter()
            .filter(|(k, s)| {
                observed.get(*k).is_none_or(|o| o.1.is_empty()) && s.domains_s + LOG_REFRESH_S < now
            })
            .map(|(k, s)| (s.domains_s, k.clone()))
            .collect();
        stale.sort();
        let dirs = crate::simulate::log_dirs(&cfg);
        for (_, key) in stale.into_iter().take(LOG_PER_PASS) {
            let Ok(ip) = key.parse::<IpAddr>() else {
                continue;
            };
            let domains = domains_from_log(&dirs, ip, now);
            if let Some(s) = seen.get_mut(&key) {
                s.domains = domains;
                s.domains_s = now;
            }
        }
        let mut devices: Vec<Device> = seen
            .iter()
            .filter_map(|(k, s)| {
                let ip = k.parse::<IpAddr>().ok()?;
                let v4 = match ip.to_canonical() {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(_) => None,
                };
                let lease = |l: &crate::devices::Leases| v4.and_then(|a| l.get(&a).cloned());
                let (r, m) = (lease(&routers), lease(&mdns));
                let mac = src
                    .pipeline
                    .neighbors
                    .get(ip.to_canonical())
                    .or_else(|| r.as_ref().and_then(|l| oui::parse_mac(&l.mac)))
                    .or_else(|| m.as_ref().and_then(|l| oui::parse_mac(&l.mac)));
                let names = [r, m]
                    .into_iter()
                    .flatten()
                    .filter_map(|l| l.hostname)
                    .collect();
                Some(Device {
                    key: k.clone(),
                    ip,
                    mac,
                    names,
                    domains: s.domains.clone(),
                })
            })
            .collect();
        let snapshot_seen = seen.clone();
        drop(seen);
        merge_by_mac(&mut devices);
        let (sigs, problem) = load_catalog(&cfg);
        if let Some(p) = problem {
            tracing::warn!("device signatures: {p} (using the shipped ones)");
        }
        let dynamic = src.pipeline.current();
        let clients = &dynamic.policy.clients;
        let mut by_client = BTreeMap::new();
        for d in &devices {
            let ident = clients.identify(d.ip, None, None, &src.pipeline.neighbors);
            let kind = clients
                .client(ident)
                .and_then(|c| cfg.client.iter().find(|x| x.name.as_str() == &*c.name))
                .and_then(|c| c.kind);
            let mut identity = if let Some(k) = kind {
                override_identity(&d.key, k, now)
            } else {
                let inp = inputs(d);
                to_identity(&d.key, &score::score(&sigs, &inp), &inp, now)
            };
            identity.suggested_group =
                suggested_group(&cfg, &identity.class, clients.group_names(ident));
            by_client.insert(d.key.clone(), identity);
        }
        self.current.store(Arc::new(Snapshot {
            reason: None,
            by_client,
            at: Some(Instant::now()),
        }));
        self.runs.fetch_add(1, Ordering::Relaxed);
        self.micros.fetch_add(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        if self.last_persist_s.load(Ordering::Relaxed) + PERSIST_EVERY_S <= now {
            self.persist(&snapshot_seen);
            self.last_persist_s.store(now, Ordering::Relaxed);
        }
    }

    /// Writes `devices.json` (atomically: a temporary file, then a rename).
    fn persist(&self, seen: &BTreeMap<String, Seen>) {
        let file = Persisted {
            seen: seen.clone(),
            identities: self.current.load().by_client.values().cloned().collect(),
        };
        let Ok(bytes) = serde_json::to_vec(&file) else {
            return;
        };
        let tmp = self.dir.join(format!("{FILE}.tmp"));
        if std::fs::write(&tmp, bytes)
            .and_then(|()| std::fs::rename(&tmp, self.dir.join(FILE)))
            .is_err()
        {
            tracing::debug!("couldn't save {FILE}");
        }
    }

    /// Saves the state now (at shutdown).
    pub(crate) fn save(&self) {
        let seen = self
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        self.persist(&seen);
    }

    /// Every identity, without evidence; or why there are none.
    pub(crate) fn list(&self) -> Vec<DeviceIdentity> {
        self.nudge();
        let s = self.current.load();
        s.by_client
            .values()
            .map(|i| DeviceIdentity {
                evidence: None,
                ..i.clone()
            })
            .collect()
    }

    /// One device's identity (by address), with evidence.
    pub(crate) fn get(&self, client: &str) -> DeviceIdentity {
        self.nudge();
        let s = self.current.load();
        if let Some(r) = s.reason {
            return unavailable(client, r);
        }
        let key = client.parse::<IpAddr>().map_or_else(
            |_| client.to_owned(),
            |ip| telltale_telemetry::agg::client_text(octets(ip)),
        );
        s.by_client
            .get(&key)
            .cloned()
            .unwrap_or_else(|| unavailable(&key, "not_seen"))
    }

    /// Devices per class (`telltale_devices_by_class`).
    pub(crate) fn by_class(&self) -> BTreeMap<&'static str, u64> {
        let mut m: BTreeMap<&'static str, u64> =
            DeviceClass::ALL.iter().map(|c| (c.as_str(), 0)).collect();
        for i in self.current.load().by_client.values() {
            if let Some(c) = DeviceClass::parse(&i.class) {
                *m.entry(c.as_str()).or_default() += 1;
            }
        }
        m
    }

    /// `/metrics`: devices by class, passes, and their time.
    pub(crate) fn render(&self, w: &mut telltale_telemetry::prom::PromWriter) {
        w.family(
            "telltale_devices_by_class",
            "gauge",
            "Devices this node saw in the last day, by what they look like (unknown when there's no good guess).",
        );
        for (class, n) in self.by_class() {
            w.sample("telltale_devices_by_class", &[("class", class)], n);
        }
        w.family(
            "telltale_identify_runs_total",
            "counter",
            "Device identification passes since start.",
        )
        .sample(
            "telltale_identify_runs_total",
            &[],
            self.runs.load(Ordering::Relaxed),
        );
        #[allow(clippy::cast_precision_loss)] // seconds for a dashboard
        let secs = self.micros.load(Ordering::Relaxed) as f64 / 1e6;
        w.family(
            "telltale_identify_duration_seconds",
            "summary",
            "Time spent identifying devices since start.",
        )
        .sample("telltale_identify_duration_seconds_sum", &[], secs)
        .sample(
            "telltale_identify_duration_seconds_count",
            &[],
            self.runs.load(Ordering::Relaxed),
        );
    }
}

/// "looks like a Roku player" for a guess that's at least `possibly`, "is set as a camera"
/// for an override; `None` otherwise (for alert and anomaly texts).
pub(crate) fn looks_like(i: &DeviceIdentity) -> Option<String> {
    if !i.available || i.level == "unknown" {
        return None;
    }
    if i.source == "override" {
        return Some(format!("is set as a {}", i.class));
    }
    let p = i.product.as_deref()?;
    let article = if p.starts_with(['A', 'E', 'I', 'O', 'U', 'a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    };
    Some(format!("looks like {article} {p}"))
}

/// Why identification doesn't run: switched off, or a query-log privacy level that hashes
/// names (REQ: OBS-025, AC 7).
pub(crate) fn off_reason(cfg: &Config) -> Option<&'static str> {
    if !cfg.identify.enabled {
        Some("disabled")
    } else if cfg.telemetry.qlog.privacy_level >= 1 {
        Some("privacy_level")
    } else {
        None
    }
}

/// An identity that couldn't be worked out, and why.
pub(crate) fn unavailable(client: &str, reason: &str) -> DeviceIdentity {
    DeviceIdentity {
        client: client.to_owned(),
        available: false,
        reason: Some(reason.to_owned()),
        class: "unknown".to_owned(),
        level: "unknown".to_owned(),
        source: "inferred".to_owned(),
        ..DeviceIdentity::default()
    }
}

/// REQ: OBS-025 — identities from several nodes, one per device: the highest score wins;
/// on a tie, the one with MAC evidence (that node saw the device directly), then the node
/// name (deterministic).
pub(crate) fn merge(all: impl IntoIterator<Item = DeviceIdentity>) -> Vec<DeviceIdentity> {
    let rank = |i: &DeviceIdentity| {
        (
            i.available,
            i.source == "override",
            i.score.to_bits(),
            i.vendor.is_some(),
        )
    };
    let mut best: BTreeMap<String, DeviceIdentity> = BTreeMap::new();
    for i in all {
        match best.get(&i.client) {
            Some(b)
                if rank(b) > rank(&i)
                    || (rank(b) == rank(&i) && b.node.as_deref() <= i.node.as_deref()) => {}
            _ => {
                best.insert(i.client.clone(), i);
            }
        }
    }
    best.into_values().collect()
}

#[cfg(test)]
mod tests;
