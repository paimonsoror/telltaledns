//! Upstream transports, pools, strategies, health checks, and breakers.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2 and `spec/04`.
//!
//! - [`Upstream`]: one server and its [`health::Health`] (EWMA, rolling window, breaker).
//! - [`Group`]: members + a strategy; [`Group::resolve`] retries within a time budget and
//!   hedges slow attempts (ADR-013).
//! - [`Router`]: picks a group per query (suffix / client group / qtype routes).

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

mod bootstrap;
mod conn;
pub mod dnssec;
mod doh;
mod doh3;
mod doq;
mod endpoint;
mod group;
pub mod health;
pub mod presets;
mod router;
mod tls;
mod upstream;

use std::sync::Arc;
use std::time::{Duration, Instant};

pub use bootstrap::Bootstrap;
pub use endpoint::{Endpoint, Host, Protocol};
pub use group::{Answer, Group, ResolveError, Strategy};
pub use router::{Router, Selection, parse_qtype};
pub use tls::TlsOptions;
pub use upstream::{
    ExchangeError, Question, Upstream, UpstreamOptions, encode_query, is_own_loop_tag,
    matches_query, set_node_tag,
};

/// Total time budget per client query (`spec/02` §8.3).
pub const DEFAULT_BUDGET: Duration = Duration::from_secs(2);

/// Interval for active health checks (`spec/04` §5).
pub const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Periodically probes upstreams that haven't been used recently (root NS query), so a
/// recovered or idle upstream's health stays current. Runs until the task is aborted.
pub async fn active_health_checks(upstreams: Vec<Arc<Upstream>>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let probe = Question {
        name: telltale_proto::NameBuf::default(),
        qtype: telltale_proto::rtype::NS,
        qclass: telltale_proto::class::IN,
        dnssec_ok: false,
        checking_disabled: false,
    };
    loop {
        tick.tick().await;
        let now = Instant::now();
        for up in &upstreams {
            let idle = up
                .health
                .last_used()
                .is_none_or(|t| now.duration_since(t) >= interval);
            if idle {
                let up = Arc::clone(up);
                tokio::spawn(async move {
                    let _ = up.exchange(&probe, up.attempt_timeout()).await;
                });
            }
        }
    }
}
