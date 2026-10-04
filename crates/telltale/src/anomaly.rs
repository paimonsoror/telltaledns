//! The device anomaly engine in the server (REQ: OBS-013; `spec/06` §7.1, ADR-043): fed by the
//! aggregator thread through a telemetry [`Sink`], persisted to `<data_dir>/anomaly.json` every
//! hour and on shutdown, so a restart (or a pod reschedule with its volume) keeps each device's
//! learned baseline instead of starting the learning period over. Never on the query path;
//! a failure to load or save only costs history, never answers.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use telltale_config::{AnomalySensitivity, Config};
use telltale_telemetry::anomaly::{Engine, Finding, Kind, Sensitivity, Settings};
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
    }
}

impl Anomalies {
    /// The engine for `cfg`, with saved state when there is some. `None` when disabled or the
    /// query-log privacy level hides names (3).
    pub(crate) fn start(cfg: &Config) -> Option<Arc<Self>> {
        if !cfg.telemetry.anomaly.enabled || cfg.telemetry.qlog.privacy_level >= 3 {
            return None;
        }
        let path = PathBuf::from(cfg.node.data_dir.as_str()).join("anomaly.json");
        let engine = match std::fs::read(&path) {
            Ok(b) => match serde_json::from_slice::<Engine>(&b) {
                Ok(mut e) => {
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
        Some(Arc::new(Self {
            engine: Mutex::new(engine),
            path,
        }))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Engine> {
        self.engine.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Findings, newest first.
    pub(crate) fn findings(&self) -> Vec<Finding> {
        let mut v = self.lock().findings().to_vec();
        v.reverse();
        v
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

    /// Applies new settings (a reload); learned state is kept.
    pub(crate) fn reconfigure(&self, cfg: &Config) {
        self.lock().set_settings(settings(cfg));
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
            self.shared
                .lock()
                .observe(e.ts_us / 1_000_000, e.client_ip, name.as_wire());
        }
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
        // Privacy level 3 hides names: no engine.
        cfg.telemetry.qlog.privacy_level = 3;
        assert!(Anomalies::start(&cfg).is_none());
    }
}
