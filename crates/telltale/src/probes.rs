//! REQ: OBS-020 (T11.3, ADR-107, `spec/06` §9) — synthetic probes: every `[probe]
//! interval_secs`, this node asks each of its own DNS listeners a question through the
//! listener's protocol (UDP, TCP, DoT, DoH, DoH3, DoQ), plus any extra `[probe] targets` (a load
//! balancer's address), and reads each TLS listener's certificate expiry from its file.
//!
//! A probe is a real client of the listener (the upstream client, with certificate checks off
//! since it connects by IP), so it proves the whole path: socket, TLS, HTTP/2 or QUIC, the
//! pipeline. It asks `probe.telltale.invalid`, which special-name handling answers NXDOMAIN
//! without an upstream; any well-formed answer is a success. The telemetry thread keeps those
//! queries out of the query log and analytics (`Record::is_probe`), and probes skip dnstap. They
//! still count in `telltale_queries_total` like any query (a handful a minute).
//!
//! Runs on the runtime as its own task, a round at a time with a timeout per probe; DNS never
//! waits for it.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use telltale_api::model::ProbeResult;
use telltale_config::{Config, ListenProto};

/// The question every probe asks (see `telltale_telemetry::event::PROBE_NAME`).
pub(crate) const PROBE_QNAME: &str = "probe.telltale.invalid";
/// Failures in a row that degrade the health level and fire `probe_failing`.
pub(crate) const FAILING_AFTER: u32 = 2;

/// One thing to probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// The URL the probe connects to (the upstream client's syntax).
    pub(crate) url: String,
    pub(crate) proto: &'static str,
    pub(crate) listener: bool,
    /// The listener's certificate file, for its expiry.
    pub(crate) cert: Option<String>,
    /// Why it isn't probed.
    pub(crate) skipped: Option<&'static str>,
}

/// The listener's address as a client reaches it: a wildcard bind is asked on loopback.
fn reachable(addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, addr.port())
}

/// What to probe for `cfg`: its listeners, then the extra targets.
pub(crate) fn targets(cfg: &Config) -> Vec<Target> {
    let mut out: Vec<Target> = Vec::new();
    for l in &cfg.listen {
        let (scheme, proto) = match l.proto {
            ListenProto::Udp => ("udp", "udp"),
            ListenProto::Tcp => ("tcp", "tcp"),
            ListenProto::Dot => ("tls", "dot"),
            ListenProto::Doh => ("https", "doh"),
            ListenProto::Doh3 => ("h3", "doh3"),
            ListenProto::Doq => ("quic", "doq"),
        };
        let path = match l.proto {
            ListenProto::Doh | ListenProto::Doh3 => {
                l.path.as_deref().unwrap_or("/dns-query").to_owned()
            }
            _ => String::new(),
        };
        let url = format!("{scheme}://{}{path}", reachable(l.addr));
        if out.iter().any(|t| t.url == url) {
            continue;
        }
        out.push(Target {
            url,
            proto,
            listener: true,
            cert: l
                .tls
                .as_ref()
                .filter(|_| l.proto.needs_tls())
                .map(|t| t.cert.to_string()),
            skipped: l
                .proxy_protocol
                .then_some("it requires a PROXY protocol header, which probes don't send"),
        });
    }
    for t in &cfg.probe.targets {
        let Ok((scheme, _, _)) = telltale_config::probe_target(t) else {
            continue;
        };
        let proto = match scheme {
            "udp" => "udp",
            "tcp" => "tcp",
            "tls" => "dot",
            "https" => "doh",
            "h3" => "doh3",
            _ => "doq",
        };
        out.push(Target {
            url: t.to_string(),
            proto,
            listener: false,
            cert: None,
            skipped: None,
        });
    }
    out
}

/// Asks `url` the probe question once; the time it took, or why it failed.
async fn ask(url: &str, timeout: Duration) -> Result<Duration, String> {
    use telltale_upstream::{Endpoint, Question, TlsOptions, Upstream, UpstreamOptions};
    let ep = Endpoint::parse(url)?;
    let opts = UpstreamOptions {
        timeout,
        pool_size: 1,
        idle_timeout: Duration::from_secs(1),
        // It connects by IP to this node's own listener; the certificate's expiry is checked
        // from its file instead.
        tls_insecure_skip_verify: true,
        self_probe: true,
        ..UpstreamOptions::default()
    };
    let up = Upstream::build(0, "probe", ep, &opts, &TlsOptions::default())?;
    let q = Question {
        name: telltale_proto::NameBuf::from_presentation(PROBE_QNAME).map_err(|e| e.to_string())?,
        qtype: telltale_proto::rtype::A,
        qclass: 1,
        dnssec_ok: false,
        checking_disabled: false,
        client_subnet: 0,
    };
    let start = Instant::now();
    match tokio::time::timeout(
        timeout + Duration::from_millis(500),
        up.exchange(&q, timeout),
    )
    .await
    {
        Ok(Ok(_)) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out".to_owned()),
    }
}

/// A certificate file's expiry: (Unix seconds, days left), or why it can't be read.
pub(crate) fn cert_expiry(path: &str, now: u64) -> Result<(u64, i64), String> {
    let pem = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let (left, _) = telltale_cluster::pki::validity(&pem).map_err(|e| e.to_string())?;
    Ok((now.saturating_add_signed(left), left.div_euclid(86_400)))
}

/// The probes' latest results and failure counts, for the API, health, alerts, and metrics.
#[derive(Debug, Default)]
pub(crate) struct Probes {
    latest: Mutex<Vec<ProbeResult>>,
    /// Failures since start, by target.
    failures: Mutex<BTreeMap<String, u64>>,
}

impl Probes {
    pub(crate) fn results(&self) -> Vec<ProbeResult> {
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn failures_total(&self, target: &str) -> u64 {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(target)
            .copied()
            .unwrap_or(0)
    }

    fn clear(&self) {
        self.latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Folds one round's outcomes into the results (`outcomes` in `targets` order).
    pub(crate) fn record(
        &self,
        targets: &[Target],
        outcomes: Vec<Option<Result<Duration, String>>>,
        now: u64,
    ) {
        let mut latest = self.latest.lock().unwrap_or_else(PoisonError::into_inner);
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let previous: Vec<ProbeResult> = std::mem::take(&mut *latest);
        for (t, outcome) in targets.iter().zip(outcomes) {
            let before = previous.iter().find(|p| p.target == t.url);
            let mut r = ProbeResult {
                node: None,
                target: t.url.clone(),
                proto: t.proto.to_owned(),
                listener: t.listener,
                checked_unix_seconds: now,
                last_ok_unix_seconds: before.and_then(|b| b.last_ok_unix_seconds),
                skipped: t.skipped.map(str::to_owned),
                ..ProbeResult::default()
            };
            match outcome {
                Some(Ok(took)) => {
                    r.ok = true;
                    r.latency_ms = Some((took.as_secs_f64() * 100_000.0).round() / 100.0);
                    r.last_ok_unix_seconds = Some(now);
                }
                Some(Err(e)) => {
                    r.error = Some(e);
                    r.consecutive_failures = before
                        .map_or(0, |b| b.consecutive_failures)
                        .saturating_add(1);
                    *failures.entry(t.url.clone()).or_default() += 1;
                }
                None => {}
            }
            if let Some(path) = &t.cert {
                match cert_expiry(path, now) {
                    Ok((at, days)) => {
                        r.cert_expires_unix_seconds = Some(at);
                        r.cert_days_left = Some(days);
                    }
                    Err(e) => r.cert_error = Some(e),
                }
            }
            latest.push(r);
        }
    }

    /// One round: every target at once, each within the timeout.
    async fn round(&self, cfg: &Config) {
        let targets = targets(cfg);
        let timeout = Duration::from_millis(u64::from(cfg.probe.timeout_ms));
        let mut set = tokio::task::JoinSet::new();
        for (i, t) in targets.iter().enumerate() {
            if t.skipped.is_none() {
                let url = t.url.clone();
                set.spawn(async move { (i, ask(&url, timeout).await) });
            }
        }
        let mut outcomes: Vec<Option<Result<Duration, String>>> = vec![None; targets.len()];
        while let Some(done) = set.join_next().await {
            if let Ok((i, r)) = done
                && let Some(slot) = outcomes.get_mut(i)
            {
                *slot = Some(r);
            }
        }
        self.record(&targets, outcomes, crate::pipeline::unix_now());
    }
}

/// Starts the probes: a round every `[probe] interval_secs` once the listeners are bound,
/// following configuration reloads, until `stop`.
pub(crate) fn spawn(src: Arc<crate::http::Sources>, mut stop: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        loop {
            let cfg = src.config.load_full();
            if !cfg.probe.enabled {
                src.probes.clear();
            } else if src.readiness.serving() {
                // REQ: OPS-010 — probes keep measuring during maintenance.
                src.probes.round(&cfg).await;
            }
            let wait = Duration::from_secs(u64::from(cfg.probe.interval_secs.max(5)));
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                _ = stop.wait_for(|s| *s) => return,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> Config {
        telltale_config::Loader::new()
            .toml_str("t.toml", toml)
            .env(Vec::<(String, String)>::new())
            .load()
            .unwrap()
            .config
    }

    // REQ: OBS-020 — what gets probed: each listener on the address a client reaches (loopback
    // for a wildcard bind), DoH on its path, PROXY-protocol listeners skipped, extra targets
    // after; the same address once.
    #[test]
    fn obs_020_targets_follow_the_listeners() {
        let c = cfg(r#"
[[listen]]
proto = "udp"
addr = "0.0.0.0:5353"
[[listen]]
proto = "udp"
addr = "[::]:5353"
[[listen]]
proto = "tcp"
addr = "192.168.1.2:53"
proxy_protocol = true
[[listen]]
proto = "doh"
addr = "0.0.0.0:443"
tls = { cert = "/etc/telltale/cert.pem", key = "/etc/telltale/key.pem" }
[probe]
targets = ["udp://192.168.5.112:53"]
"#);
        let t = targets(&c);
        let urls: Vec<&str> = t.iter().map(|t| t.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "udp://127.0.0.1:5353",
                "udp://[::1]:5353",
                "tcp://192.168.1.2:53",
                "https://127.0.0.1:443/dns-query",
                "udp://192.168.5.112:53"
            ]
        );
        assert!(t[2].skipped.is_some(), "PROXY protocol");
        assert_eq!(t[3].proto, "doh");
        assert_eq!(t[3].cert.as_deref(), Some("/etc/telltale/cert.pem"));
        assert!(!t[4].listener);
    }

    // REQ: OBS-020 — failures in a row count up and reset on success; the last success and the
    // failures since start are kept; an unreadable certificate says why.
    #[test]
    fn obs_020_results_track_failures() {
        let p = Probes::default();
        let t = vec![Target {
            url: "tls://127.0.0.1:853".into(),
            proto: "dot",
            listener: true,
            cert: Some("/nonexistent/cert.pem".into()),
            skipped: None,
        }];
        p.record(&t, vec![Some(Ok(Duration::from_millis(3)))], 100);
        p.record(&t, vec![Some(Err("timed out".into()))], 130);
        p.record(&t, vec![Some(Err("timed out".into()))], 160);
        let r = &p.results()[0];
        assert_eq!((r.ok, r.consecutive_failures), (false, 2));
        assert_eq!(r.last_ok_unix_seconds, Some(100));
        assert!(r.cert_error.as_deref().unwrap().contains("/nonexistent"));
        assert_eq!(p.failures_total("tls://127.0.0.1:853"), 2);
        p.record(&t, vec![Some(Ok(Duration::from_millis(4)))], 190);
        let r = &p.results()[0];
        assert_eq!(
            (r.ok, r.consecutive_failures, r.latency_ms),
            (true, 0, Some(4.0))
        );
    }

    // REQ: OBS-020 — a real probe of a real listener, end to end over UDP, and a closed port
    // fails.
    #[tokio::test]
    async fn obs_020_a_probe_gets_an_answer() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                // NXDOMAIN, as the special-name handling answers.
                buf[2] |= 0x80;
                buf[3] = (buf[3] & 0xF0) | 3;
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        });
        let took = ask(&format!("udp://{addr}"), Duration::from_secs(2)).await;
        assert!(took.is_ok(), "{took:?}");
        let closed = ask("tcp://127.0.0.1:9", Duration::from_millis(300)).await;
        assert!(closed.is_err());
    }
}
