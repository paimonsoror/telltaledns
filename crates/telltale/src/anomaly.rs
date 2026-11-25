//! The device anomaly engine in the server (REQ: OBS-013; `spec/06` §7.1, ADR-043): fed by the
//! aggregator thread through a telemetry [`Sink`], persisted to `<data_dir>/anomaly.json` every
//! hour and on shutdown, so a restart (or a pod reschedule with its volume) keeps each device's
//! learned baseline instead of starting the learning period over. Never on the query path;
//! a failure to load or save only costs history, never answers.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use telltale_config::{AnomalyKind, AnomalySensitivity, Cidr, Config};
use telltale_telemetry::anomaly::{
    Engine, Finding, Kind, MuteTable, PairRhythm, RHYTHM_BINS, Sensitivity, Settings,
};
use telltale_telemetry::event::Record;
use telltale_telemetry::ring::Sink;
use tracing::{info, warn};

/// How often the state is written.
const SAVE_EVERY: Duration = Duration::from_secs(3600);

/// The engine, shared by the aggregator sink and the API.
#[derive(Debug)]
pub(crate) struct Anomalies {
    engine: Mutex<Engine>,
    path: PathBuf,
}

fn settings(cfg: &Config) -> Settings {
    let a = &cfg.telemetry.anomaly;
    Settings {
        learning_days: a.learning_days,
        sensitivity: match a.sensitivity {
            AnomalySensitivity::Low => Sensitivity::Low,
            AnomalySensitivity::Normal => Sensitivity::Normal,
            AnomalySensitivity::High => Sensitivity::High,
        },
        max_clients: usize::try_from(a.max_clients).unwrap_or(usize::MAX),
        ignore_domains: a
            .ignore_domains
            .iter()
            .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
            .collect(),
        nxdomain_per_minute: a.nxdomain_per_minute.max(1),
        nxdomain_percent: a.nxdomain_percent.min(100),
    }
}

/// REQ: OBS-038 (ADR-161) — a mute's kind, as the engine names it.
const fn kind(k: AnomalyKind) -> Kind {
    match k {
        AnomalyKind::RateSpike => Kind::RateSpike,
        AnomalyKind::DomainVolume => Kind::DomainVolume,
        AnomalyKind::Drift => Kind::Drift,
        AnomalyKind::Beacon => Kind::Beacon,
        AnomalyKind::NxdomainStorm => Kind::NxdomainStorm,
        AnomalyKind::Dga => Kind::Dga,
        AnomalyKind::ChattyLoop => Kind::ChattyLoop,
        AnomalyKind::ReverseSweep => Kind::ReverseSweep,
    }
}

/// A network as the engine matches it: the v4-mapped form, the prefix over 128 bits.
fn mapped(c: &Cidr) -> ([u8; 16], u8) {
    match c.addr {
        std::net::IpAddr::V4(a) => (a.to_ipv6_mapped().octets(), 96 + c.prefix),
        std::net::IpAddr::V6(a) => (a.octets(), c.prefix),
    }
}

/// REQ: OBS-038 — the mutes of `cfg`, with device names and groups resolved to networks.
fn mute_table(cfg: &Config) -> MuteTable {
    let mut t = MuteTable::default();
    for m in telltale_config::mute::resolve(cfg) {
        let kinds: Vec<Kind> = m.kinds.iter().map(|k| kind(*k)).collect();
        t.add(&m.name, m.nets.iter().map(mapped), &kinds, m.expires_unix);
    }
    t
}

impl Anomalies {
    /// The engine for `cfg`, with saved state when there is some. `None` when disabled or the
    /// query-log privacy level hides names (1 and above: findings name domains and devices,
    /// and the DGA score would read hashed names as random; review 04-04, `spec/06` §7.1).
    pub(crate) fn start(cfg: &Config) -> Option<Arc<Self>> {
        if !cfg.telemetry.anomaly.enabled || cfg.telemetry.qlog.privacy_level >= 1 {
            return None;
        }
        let path = PathBuf::from(cfg.node.data_dir.as_str()).join("anomaly.json");
        let engine = match std::fs::read(&path) {
            Ok(b) => match serde_json::from_slice::<Engine>(&b) {
                Ok(mut e) => {
                    e.repair();
                    e.set_settings(settings(cfg));
                    info!(devices = e.clients(), "anomaly baselines loaded");
                    e
                }
                Err(e) => {
                    warn!("anomaly state unreadable ({e}); devices learn again");
                    Engine::new(settings(cfg))
                }
            },
            Err(_) => Engine::new(settings(cfg)),
        };
        let mut engine = engine;
        engine.set_mutes(mute_table(cfg));
        Some(Arc::new(Self {
            engine: Mutex::new(engine),
            path,
        }))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Engine> {
        self.engine.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// REQ: OBS-031 — findings, newest first, each beacon with its pair's rhythm at report time.
    pub(crate) fn findings_with_rhythm(&self) -> Vec<(Finding, Option<[u16; RHYTHM_BINS]>)> {
        let e = self.lock();
        e.findings()
            .iter()
            .rev()
            .map(|f| (f.clone(), e.beacon_rhythm(f)))
            .collect()
    }

    /// REQ: OBS-031 — a device's tracked pairs with their rhythms.
    pub(crate) fn rhythm(&self, client: [u8; 16]) -> Vec<PairRhythm> {
        self.lock().rhythm(client)
    }

    /// REQ: OBS-009 (T7.14) — first-seen domains since `since` (Unix seconds), newest first,
    /// at most `limit`.
    pub(crate) fn new_domains(
        &self,
        since: u64,
        limit: usize,
    ) -> Vec<telltale_telemetry::anomaly::NewDomain> {
        self.lock()
            .new_domains()
            .rev()
            .take_while(|d| d.ts_s >= since)
            .take(limit)
            .cloned()
            .collect()
    }

    /// REQ: OBS-010 (T9.5) — devices first seen since `since` (Unix seconds).
    pub(crate) fn new_clients(&self, since: u64) -> Vec<([u8; 16], u64)> {
        self.lock().new_clients(since)
    }

    /// Findings so far by kind, devices with state, and devices evicted (for `/metrics`).
    pub(crate) fn counters(&self) -> (Vec<(Kind, u64)>, usize, u64) {
        let e = self.lock();
        let totals = Kind::ALL
            .iter()
            .map(|k| (*k, e.total.get(k).copied().unwrap_or(0)))
            .collect();
        (totals, e.clients(), e.evicted)
    }

    /// REQ: OBS-038 — findings a mute matched when they were created, by kind (for `/metrics`).
    pub(crate) fn muted_totals(&self) -> Vec<(Kind, u64)> {
        let e = self.lock();
        Kind::ALL
            .iter()
            .map(|k| (*k, e.total_muted.get(k).copied().unwrap_or(0)))
            .collect()
    }

    /// Applies new settings and mutes (a reload); learned state is kept.
    pub(crate) fn reconfigure(&self, cfg: &Config) {
        let mut e = self.lock();
        e.set_settings(settings(cfg));
        e.set_mutes(mute_table(cfg));
    }

    /// Writes the state atomically (temp file + rename).
    pub(crate) fn save(&self) {
        let json = match serde_json::to_vec(&*self.lock()) {
            Ok(j) => j,
            Err(e) => {
                warn!("anomaly state not saved: {e}");
                return;
            }
        };
        let tmp = self.path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, json).and_then(|()| std::fs::rename(&tmp, &self.path))
        {
            warn!("anomaly state not saved to {}: {e}", self.path.display());
        }
    }

    /// The aggregator's sink.
    pub(crate) fn sink(self: &Arc<Self>) -> AnomalySink {
        AnomalySink {
            shared: Arc::clone(self),
            saved: Instant::now(),
        }
    }
}

/// Feeds query events to the engine on the aggregator thread.
pub(crate) struct AnomalySink {
    shared: Arc<Anomalies>,
    saved: Instant,
}

impl Sink for AnomalySink {
    fn record(&mut self, r: &Record) {
        if let Record::Query(e, name) = r {
            // REQ: OBS-031 — microseconds: the rhythm counts gaps in milliseconds.
            self.shared
                .lock()
                .observe_query(e.ts_us, e.client_ip, name.as_wire(), e.rcode);
        }
    }

    /// REQ: FLT-017 — baselines, findings, and rhythms per workload, not per pod: the engine
    /// takes the analytics' view (keyed, briefly held for unknown addresses), not the log's.
    fn record_log(&mut self, _r: &Record) {}

    fn record_analytics(&mut self, keyed: &Record) {
        self.record(keyed);
    }

    fn tick(&mut self, now: Instant) {
        if now.duration_since(self.saved) >= SAVE_EVERY {
            self.saved = now;
            self.shared.save();
        }
    }
}

impl Drop for AnomalySink {
    fn drop(&mut self) {
        self.shared.save();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obs_013_state_is_saved_and_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.node.data_dir = telltale_config::SafeString::new(dir.path().to_str().unwrap()).unwrap();
        let a = Anomalies::start(&cfg).unwrap();
        a.lock()
            .observe(1_790_000_000, [9; 16], b"\x01a\x07example\x00");
        a.save();
        let b = Anomalies::start(&cfg).unwrap();
        assert_eq!(b.counters().1, 1, "the device's state came back");
        // Privacy levels that hide names: no engine (review 04-04).
        for level in [1, 2, 3] {
            cfg.telemetry.qlog.privacy_level = level;
            assert!(Anomalies::start(&cfg).is_none(), "level {level}");
        }
    }

    // REQ: OBS-038 (ADR-186) — every kind the engine reports can be named in a mute, and the
    // mute means that kind (the configuration and the engine each have their own enum).
    #[test]
    fn obs_038_config_and_engine_kinds_agree() {
        for k in Kind::ALL {
            let a: AnomalyKind = serde_json::from_value(serde_json::json!(k.label()))
                .unwrap_or_else(|e| panic!("{}: {e}", k.label()));
            assert_eq!(kind(a), k, "{}", k.label());
            assert_eq!(a.label(), k.label());
        }
    }

    // REQ: OBS-009, OBS-037 (ADR-186, ADR-152) — the anomaly engine and the resolver each have a
    // check for reverse names of private addresses (the telemetry crate doesn't depend on the
    // resolver's): they answer alike at every edge of every range.
    #[test]
    fn obs_009_the_sweep_and_the_resolver_agree_on_private_reverse_names() {
        use telltale_policy::{Special, classify};
        use telltale_proto::{NameBuf, build_query, parse_query, rtype};
        use telltale_telemetry::internal::InternalNames;
        let v4 = |a: &str| format!("{a}.in-addr.arpa");
        // 32 nibbles, least significant first: zeros, then the most significant ones given.
        let v6 = |top: &str| {
            let n = top.split('.').count();
            format!("{}{top}.ip6.arpa", "0.".repeat(32 - n))
        };
        let mut corpus: Vec<(String, bool)> = [
            ("1.0.15.172", false),
            ("1.0.16.172", true),
            ("1.0.31.172", true),
            ("1.0.32.172", false),
            ("1.0.63.100", false),
            ("1.0.64.100", true),
            ("1.0.127.100", true),
            ("1.0.128.100", false),
            ("1.0.0.10", true),
            ("1.0.0.11", false),
            ("1.1.168.192", true),
            ("1.1.169.192", false),
            ("1.1.254.169", true),
            ("1.1.0.127", true),
            ("1.1.1.0", true),
            ("8.8.8.8", false),
            ("1.1.1.1", false),
            ("4.3.2.1", false),
            ("1.113.0.203", false),
            ("10", true),
            ("168.192", true),
            ("b._dns-sd._udp.0.1.168.192", true),
        ]
        .iter()
        .map(|(a, want)| (v4(a), *want))
        .collect();
        corpus.push(("in-addr.arpa".into(), false));
        // Upper case (both read lowercased names), and labels that only end in the zone's bytes
        // (a length byte inside them): not under `in-addr.arpa` or `ip6.arpa`.
        corpus.push(("1.0.0.10.IN-ADDR.ARPA".into(), true));
        corpus.push(("1.0.0.10.x\\007in-addr.arpa".into(), false));
        corpus.push(("1.d.f.x\\003ip6.arpa".into(), false));
        for (top, want) in [
            ("b.f", false),
            ("c.f", true),
            ("d.f", true),
            ("0.e.f", false),
            ("7.e.f", false),
            ("8.e.f", true),
            ("b.e.f", true),
            ("c.e.f", false),
        ] {
            corpus.push((v6(top), want));
        }
        corpus.push((format!("1.{}ip6.arpa", "0.".repeat(31)), true)); // ::1
        corpus.push((format!("2.{}ip6.arpa", "0.".repeat(31)), false)); // ::2
        let engine = InternalNames::default();
        for (name, want) in &corpus {
            let mut buf = [0u8; 512];
            let n = NameBuf::from_presentation(name).unwrap();
            let len = build_query(&mut buf, 1, &n, rtype::A, 1, true, None).unwrap();
            let q = parse_query(&buf[..len]).unwrap();
            let resolver = classify(&q, &telltale_config::SpecialConfig::default())
                == Some(Special::PrivatePtr);
            let sweep = engine.is_internal(q.qname.as_wire());
            assert_eq!(resolver, sweep, "the two checks disagree on {name}");
            assert_eq!(resolver, *want, "{name}");
        }
    }
}
