//! Live tail (REQ: OBS-008, `spec/06` §6, ADR-032): query events fan out from the aggregator
//! thread to subscribers of `GET /api/v1/queries/stream`.
//!
//! The aggregator hands every drained record to [`TailSink`], which copies query events into
//! a broadcast channel only while someone listens (no subscriber: one atomic load per event).
//! The query path is untouched. Each subscriber's task filters raw events, applies its rate
//! cap, formats the matches as API rows, and reports what it skipped (`rate`, or `lag` when
//! it fell behind the channel). The query-log privacy level applies here too: level 1 hides
//! names, level 2 also clients, level 3 turns the tail off.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use telltale_api::model::{NameMatch, TailDropped, TailItem, TailParams};
use telltale_api::problem::Problem;
use telltale_telemetry::Status;
use telltale_telemetry::event::{QueryEvent, Record};
use telltale_telemetry::ring::Sink;
use tokio::sync::{broadcast, mpsc};

/// Events buffered per subscriber before it counts as lagging.
const CHANNEL: usize = 4096;
/// Concurrent live tails per node.
pub(crate) const MAX_SUBSCRIBERS: usize = 16;
const DEFAULT_RATE: u32 = 500;

/// One query, as broadcast (privacy already applied).
#[derive(Debug)]
pub(crate) struct TailEvent {
    pub(crate) ev: QueryEvent,
    /// Wire-format name.
    pub(crate) name: Box<[u8]>,
}

/// The node's live-tail hub.
#[derive(Debug)]
pub(crate) struct Tail {
    tx: broadcast::Sender<Arc<TailEvent>>,
    privacy: u8,
    subscribers: Arc<AtomicUsize>,
}

impl Tail {
    /// `None` at privacy level 3 (nothing about queries may be shown).
    pub(crate) fn new(privacy: u8) -> Option<Arc<Self>> {
        (privacy < 3).then(|| {
            Arc::new(Self {
                tx: broadcast::channel(CHANNEL).0,
                privacy,
                subscribers: Arc::new(AtomicUsize::new(0)),
            })
        })
    }

    pub(crate) fn sink(&self) -> TailSink {
        TailSink {
            tx: self.tx.clone(),
            privacy: self.privacy,
        }
    }

    /// A receiver plus a slot guard, or `None` at the subscriber cap.
    pub(crate) fn subscribe(&self) -> Option<(broadcast::Receiver<Arc<TailEvent>>, Slot)> {
        let n = self.subscribers.fetch_add(1, Ordering::AcqRel);
        if n >= MAX_SUBSCRIBERS {
            self.subscribers.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some((self.tx.subscribe(), Slot(Arc::clone(&self.subscribers))))
    }
}

/// Frees a subscriber slot when the stream ends.
#[derive(Debug)]
pub(crate) struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Runs on the aggregator thread.
#[derive(Debug)]
pub(crate) struct TailSink {
    tx: broadcast::Sender<Arc<TailEvent>>,
    privacy: u8,
}

impl Sink for TailSink {
    fn record(&mut self, r: &Record) {
        let Record::Query(e, name) = r else {
            return;
        };
        if self.tx.receiver_count() == 0 {
            return;
        }
        let mut ev = *e;
        if self.privacy >= 2 {
            ev.client_ip = [0; 16];
            ev.client_ref = 0;
        }
        let name = if self.privacy >= 1 {
            telltale_store::qlog::hidden_name(name.as_wire())
        } else {
            name.as_wire().into()
        };
        let _ = self.tx.send(Arc::new(TailEvent { ev, name }));
    }
}

/// Feeds several sinks (the query log and the live tail).
pub(crate) struct Fanout(pub(crate) Vec<Box<dyn Sink>>);

impl Sink for Fanout {
    fn record(&mut self, r: &Record) {
        for s in &mut self.0 {
            s.record(r);
        }
    }
    fn tick(&mut self, now: Instant) {
        for s in &mut self.0 {
            s.tick(now);
        }
    }
}

/// The aggregator's sink: the query log, the live tail, both, or neither.
pub(crate) fn combine(qlog: Option<Box<dyn Sink>>, tail: Option<&Tail>) -> Option<Box<dyn Sink>> {
    let mut sinks: Vec<Box<dyn Sink>> = qlog.into_iter().collect();
    if let Some(t) = tail {
        sinks.push(Box::new(t.sink()));
    }
    match sinks.len() {
        0 | 1 => sinks.pop(),
        _ => Some(Box::new(Fanout(sinks))),
    }
}
/// A subscriber's filters, resolved once.
#[derive(Debug, Default)]
pub(crate) struct Filter {
    name: Option<(NameMatch, String)>,
    client: Option<[u8; 16]>,
    group: Option<u16>,
    statuses: Vec<Status>,
    qtypes: Vec<u16>,
    upstream: Option<u16>,
    min_us: u32,
    pub(crate) rate: u32,
}

impl Filter {
    /// Validates `p`; `groups` are the configured group names by index.
    pub(crate) fn parse(p: &TailParams, groups: &[String]) -> Result<Self, Problem> {
        let csv = |v: &Option<String>| -> Vec<String> {
            v.as_deref()
                .unwrap_or("")
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        };
        let name = match (&p.name, p.name_match.unwrap_or_default()) {
            (None, _) => None,
            (Some(_), NameMatch::Regex) => {
                return Err(
                    Problem::invalid("`match=regex` isn't available for the live tail")
                        .hint("Use substring, exact, suffix, or glob (* and ?)."),
                );
            }
            (Some(n), m) => Some((m, n.trim().trim_end_matches('.').to_ascii_lowercase())),
        };
        let client = match &p.client {
            None => None,
            Some(c) => Some(mapped(c.parse::<IpAddr>().map_err(|_| {
                Problem::invalid(format!("`client`: `{c}` is not an IP address"))
            })?)),
        };
        let group = match &p.group {
            None => None,
            Some(g) => Some(
                groups
                    .iter()
                    .position(|x| x == g)
                    .and_then(|i| u16::try_from(i).ok())
                    .ok_or_else(|| {
                        Problem::invalid(format!("`group`: no group named `{g}`"))
                            .hint("See GET /api/v1/groups.")
                    })?,
            ),
        };
        let statuses = csv(&p.status)
            .iter()
            .map(|s| {
                Status::ALL
                    .into_iter()
                    .find(|x| x.label() == s)
                    .ok_or_else(|| Problem::invalid(format!("`status`: unknown status `{s}`")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let qtypes = csv(&p.qtype)
            .iter()
            .map(|t| {
                telltale_proto::rtype::from_name(&t.to_ascii_uppercase())
                    .ok_or_else(|| Problem::invalid(format!("`qtype`: unknown type `{t}`")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            name,
            client,
            group,
            statuses,
            qtypes,
            upstream: p.upstream,
            min_us: p.min_latency_ms.unwrap_or(0).saturating_mul(1000),
            rate: p.rate.unwrap_or(DEFAULT_RATE),
        })
    }

    /// uf is scratch space reused across calls (no allocation per event).
    pub(crate) fn matches(&self, t: &TailEvent, buf: &mut String) -> bool {
        let e = &t.ev;
        if self.client.is_some_and(|c| c != e.client_ip)
            || self.group.is_some_and(|g| g != e.group)
            || (!self.statuses.is_empty() && !self.statuses.contains(&e.status))
            || (!self.qtypes.is_empty() && !self.qtypes.contains(&e.qtype))
            || self.upstream.is_some_and(|u| u != e.upstream)
            || e.t_total_us < self.min_us
        {
            return false;
        }
        let Some((m, want)) = &self.name else {
            return true;
        };
        lower_dotted(&t.name, buf);
        let name = buf.as_str();
        match m {
            NameMatch::Substring => name.contains(want.as_str()),
            NameMatch::Exact => name == want,
            NameMatch::Suffix => name == want || name.ends_with(&format!(".{want}")),
            NameMatch::Glob => glob(want.as_bytes(), name.as_bytes()),
            NameMatch::Regex => false,
        }
    }
}

/// Wire name → lowercase presentation form in `out` (no trailing dot).
fn lower_dotted(wire: &[u8], out: &mut String) {
    out.clear();
    let mut pos = 0;
    while let Some(&len) = wire.get(pos) {
        if len == 0 {
            break;
        }
        let label = wire
            .get(pos + 1..pos + 1 + usize::from(len))
            .unwrap_or_default();
        if !out.is_empty() {
            out.push('.');
        }
        out.extend(label.iter().map(|b| char::from(b.to_ascii_lowercase())));
        pos += 1 + usize::from(len);
    }
}

fn mapped(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// `*` (any run) and `?` (one character) over the whole name.
fn glob(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i, mut star, mut mark) = (0, 0, None, 0);
    while i < s.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == s[i]) {
            p += 1;
            i += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = Some(p);
            mark = i;
            p += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    pat[p..].iter().all(|&c| c == b'*')
}

/// Runs one subscriber until its client disconnects. `row` formats a matching event.
pub(crate) fn spawn_subscriber(
    mut events: broadcast::Receiver<Arc<TailEvent>>,
    slot: Slot,
    filter: Filter,
    row: impl Fn(&TailEvent) -> telltale_api::model::QueryRow + Send + 'static,
) -> mpsc::Receiver<TailItem> {
    let (tx, rx) = mpsc::channel(256);
    tokio::spawn(async move {
        let _slot = slot;
        let mut budget = f64::from(filter.rate);
        let mut refilled = Instant::now();
        let (mut by_rate, mut by_lag) = (0u64, 0u64);
        let mut scratch = String::with_capacity(256);
        let mut report = tokio::time::interval(Duration::from_secs(1));
        report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = tx.closed() => break,
                r = events.recv() => match r {
                    Ok(t) => {
                        if !filter.matches(&t, &mut scratch) {
                            continue;
                        }
                        let now = Instant::now();
                        let rate = f64::from(filter.rate);
                        budget = (budget + now.duration_since(refilled).as_secs_f64() * rate).min(rate);
                        refilled = now;
                        if budget < 1.0 {
                            by_rate += 1;
                            continue;
                        }
                        budget -= 1.0;
                        match tx.try_send(TailItem::Query(Box::new(row(&t)))) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => by_lag += 1,
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => by_lag += n,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = report.tick() => {
                    for (n, reason) in [(&mut by_rate, "rate"), (&mut by_lag, "lag")] {
                        if *n > 0 {
                            let item = TailItem::Dropped(TailDropped { dropped: *n, reason: reason.to_owned() });
                            if tx.try_send(item).is_ok() {
                                *n = 0;
                            }
                        }
                    }
                }
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use telltale_telemetry::Proto;

    use super::*;

    fn wire(name: &str) -> Box<[u8]> {
        let mut w = Vec::new();
        for l in name.split('.') {
            w.push(u8::try_from(l.len()).unwrap());
            w.extend_from_slice(l.as_bytes());
        }
        w.push(0);
        w.into()
    }

    fn event(name: &str, status: Status, ms: u32) -> TailEvent {
        TailEvent {
            ev: QueryEvent {
                ts_us: 1,
                client_ip: mapped("192.168.1.20".parse().unwrap()),
                client_ref: 0,
                group: 1,
                qtype: 28,
                qclass: 1,
                rcode: Some(0),
                status,
                proto: Proto::Udp,
                flags: 0,
                rule: None,
                upstream: 2,
                attempts: 1,
                t_total_us: ms * 1000,
                t_upstream_us: 0,
                resp_size: 60,
                answers: 1,
            },
            name: wire(name),
        }
    }

    fn params(f: impl FnOnce(&mut TailParams)) -> TailParams {
        let mut p = TailParams::default();
        f(&mut p);
        p
    }

    #[test]
    fn obs_008_filters() {
        let groups = vec!["default".to_owned(), "kids".to_owned()];
        let e = event("ads.Example.com", Status::Blocked, 5);
        let ok = |p: TailParams| {
            Filter::parse(&p, &groups)
                .unwrap()
                .matches(&e, &mut String::new())
        };
        assert!(ok(TailParams::default()));
        assert!(ok(params(|p| p.name = Some("example".into()))));
        assert!(ok(params(|p| {
            p.name = Some("example.com".into());
            p.name_match = Some(NameMatch::Suffix);
        })));
        assert!(!ok(params(|p| {
            p.name = Some("example.com".into());
            p.name_match = Some(NameMatch::Exact);
        })));
        assert!(ok(params(|p| {
            p.name = Some("*.example.c?m".into());
            p.name_match = Some(NameMatch::Glob);
        })));
        assert!(ok(params(|p| p.status = Some("forwarded, blocked".into()))));
        assert!(!ok(params(|p| p.status = Some("cached".into()))));
        assert!(ok(params(|p| p.qtype = Some("aaaa".into()))));
        assert!(ok(params(|p| p.group = Some("kids".into()))));
        assert!(!ok(params(|p| p.group = Some("default".into()))));
        assert!(ok(params(|p| p.client = Some("192.168.1.20".into()))));
        assert!(!ok(params(|p| p.client = Some("192.168.1.21".into()))));
        assert!(ok(params(|p| p.upstream = Some(2))));
        assert!(ok(params(|p| p.min_latency_ms = Some(5))));
        assert!(!ok(params(|p| p.min_latency_ms = Some(6))));
        for bad in [
            params(|p| p.status = Some("nope".into())),
            params(|p| p.group = Some("nope".into())),
            params(|p| p.client = Some("nope".into())),
            params(|p| p.qtype = Some("NOPE".into())),
            params(|p| {
                p.name = Some("x".into());
                p.name_match = Some(NameMatch::Regex);
            }),
        ] {
            assert!(Filter::parse(&bad, &groups).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn obs_008_glob() {
        assert!(glob(b"*", b"anything"));
        assert!(glob(b"a?c", b"abc"));
        assert!(!glob(b"a?c", b"abbc"));
        assert!(glob(b"*.ads.*", b"x.ads.example"));
        assert!(!glob(b"*.ads", b"ads"));
    }

    // REQ: OBS-008 — privacy levels apply to the tail; nothing is sent without subscribers;
    // the subscriber cap holds.
    #[test]
    fn obs_008_privacy_and_subscriber_cap() {
        assert!(Tail::new(3).is_none(), "level 3: no tail at all");
        let tail = Tail::new(2).unwrap();
        let mut sink = tail.sink();
        let rec = |e: &TailEvent| {
            Record::Query(e.ev, telltale_telemetry::event::Name::from_wire(&e.name))
        };
        let e = event("secret.example", Status::Forwarded, 1);
        sink.record(&rec(&e)); // no subscriber: dropped silently
        let (mut rx, slot) = tail.subscribe().unwrap();
        sink.record(&rec(&e));
        let got = rx.try_recv().unwrap();
        assert_eq!(got.ev.client_ip, [0; 16], "level 2 hides clients");
        assert!(
            !telltale_telemetry::event::dotted(&got.name).contains("secret"),
            "level 1+ hides names"
        );
        assert!(rx.try_recv().is_err(), "the earlier event wasn't queued");
        let mut slots = vec![slot];
        while let Some((_, s)) = tail.subscribe() {
            slots.push(s);
        }
        assert_eq!(slots.len(), MAX_SUBSCRIBERS);
        slots.pop();
        assert!(tail.subscribe().is_some(), "a freed slot can be reused");
    }
}
