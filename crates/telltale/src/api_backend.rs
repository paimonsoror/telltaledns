//! The `telltale_api::Backend` implementation: the API's view of this server (REQ: API-001,
//! API-002). Reads only shared state that already exists for `/metrics` and the pipeline;
//! nothing here sits on the query path.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use telltale_api::Backend;
use telltale_api::model::{
    ClientInfo, ExplainBlock, ExplainClient, ExplainFilter, ExplainLine, ExplainParams,
    ExplainRoute, ExplainRule, Explanation, GroupInfo, Hour, LatencyBy, LatencyRow, ListInfo,
    NameMatch, QueryPage, QueryParams, QueryRow, ScanStats, Step, SystemInfo, TimeBucket, TopItem,
    TopKind, UpstreamInfo,
};
use telltale_api::problem::Problem;
use telltale_api::time::format_us;
use telltale_store::qlog;
use telltale_telemetry::agg::{HourSel, LatencyKey, Percentiles, Resolution};
use telltale_telemetry::{N_RCODE, Path as AnswerPath, Proto, QTYPES, Status};
use telltale_upstream::health::Breaker;

use crate::http::Sources;

/// The API backend over the server's shared state.
#[derive(Debug)]
pub(crate) struct ApiBackend {
    pub(crate) src: Arc<Sources>,
}

/// A serde enum's wire name (`BlockMode::NullIp` → `null_ip`), so API strings never drift
/// from config and explain output.
fn label<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_owned))
        .unwrap_or_default()
}

const RCODES: [&str; 16] = [
    "NOERROR",
    "FORMERR",
    "SERVFAIL",
    "NXDOMAIN",
    "NOTIMP",
    "REFUSED",
    "YXDOMAIN",
    "YXRRSET",
    "NXRRSET",
    "NOTAUTH",
    "NOTZONE",
    "DSOTYPENI",
    "RCODE12",
    "RCODE13",
    "RCODE14",
    "RCODE15",
];

fn rcode_name(rc: u8) -> String {
    RCODES
        .get(usize::from(rc))
        .map_or_else(|| format!("RCODE{rc}"), |s| (*s).to_owned())
}

fn rcode_value(name: &str) -> Option<u8> {
    let up = name.trim().to_ascii_uppercase();
    RCODES
        .iter()
        .position(|r| *r == up)
        .and_then(|i| u8::try_from(i).ok())
        .or_else(|| up.strip_prefix("RCODE").and_then(|n| n.parse().ok()))
}

fn qtype_name(t: u16) -> String {
    QTYPES
        .iter()
        .find(|(v, _)| *v == t)
        .map_or_else(|| format!("TYPE{t}"), |(_, n)| (*n).to_owned())
}

#[allow(clippy::cast_precision_loss)]
fn ms(us: u64) -> f64 {
    (us as f64 / 10.0).round() / 100.0
}

fn mapped(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn hour(h: Hour) -> HourSel {
    match h {
        Hour::Current => HourSel::Current,
        Hour::Previous => HourSel::Previous,
    }
}

fn latency_row(key: String, p: Percentiles) -> LatencyRow {
    LatencyRow {
        key,
        count: p.count,
        p50_ms: ms(p.p50),
        p90_ms: ms(p.p90),
        p99_ms: ms(p.p99),
        p999_ms: ms(p.p999),
        max_ms: ms(p.max),
    }
}

/// Comma-separated values, trimmed, empty ones dropped.
fn csv(v: Option<&String>) -> Vec<String> {
    v.map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_owned)
            .collect()
    })
    .unwrap_or_default()
}

impl ApiBackend {
    /// List names of the active snapshot, by list ID.
    fn list_names(&self) -> Vec<String> {
        self.src
            .pipeline
            .filter
            .load()
            .as_ref()
            .and_then(|f| f.matcher.snapshot().cloned())
            .map(|s| s.manifest.lists.iter().map(|l| l.name.clone()).collect())
            .unwrap_or_default()
    }
}

fn qlog_filter(q: &QueryParams, from_us: u64, to_us: u64) -> Result<qlog::Filter, Problem> {
    let name = q
        .name
        .clone()
        .map(|n| match q.name_match.unwrap_or_default() {
            NameMatch::Substring => qlog::NameMatch::Substring(n),
            NameMatch::Exact => qlog::NameMatch::Exact(n),
            NameMatch::Suffix => qlog::NameMatch::Suffix(n),
            NameMatch::Glob => qlog::NameMatch::Glob(n),
            NameMatch::Regex => qlog::NameMatch::Regex(n),
        });
    let client_ip = match &q.client {
        None => None,
        Some(c) => Some(mapped(c.parse::<IpAddr>().map_err(|_| {
            Problem::invalid(format!("`client`: `{c}` is not an IP address"))
        })?)),
    };
    let status = csv(q.status.as_ref())
        .iter()
        .map(|s| {
            Status::ALL
                .into_iter()
                .find(|x| x.label() == s)
                .ok_or_else(|| {
                    let all: Vec<&str> = Status::ALL.iter().map(|x| x.label()).collect();
                    Problem::invalid(format!("`status`: unknown `{s}`"))
                        .hint(format!("One or more of: {}.", all.join(", ")))
                })
        })
        .collect::<Result<_, _>>()?;
    let qtype = csv(q.qtype.as_ref())
        .iter()
        .map(|t| {
            telltale_proto::rtype::from_name(t)
                .ok_or_else(|| Problem::invalid(format!("`qtype`: unknown type `{t}`")))
        })
        .collect::<Result<_, _>>()?;
    let rcode = csv(q.rcode.as_ref())
        .iter()
        .map(|r| {
            rcode_value(r).ok_or_else(|| {
                Problem::invalid(format!("`rcode`: unknown `{r}`"))
                    .hint("Use names such as NOERROR, NXDOMAIN, SERVFAIL, REFUSED.")
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(qlog::Filter {
        from_us,
        to_us,
        name,
        client_ip,
        status,
        qtype,
        rcode,
        upstream: q.upstream,
        min_total_us: q.min_latency_ms.map(|v| v.saturating_mul(1000)),
        ..qlog::Filter::default()
    })
}

impl Backend for ApiBackend {
    fn system_info(&self) -> SystemInfo {
        let cfg = self.src.config.load();
        let snap = self
            .src
            .pipeline
            .filter
            .load()
            .as_ref()
            .and_then(|f| f.matcher.snapshot().cloned());
        let node = if cfg.node.name.is_empty() {
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|h| h.trim().to_owned())
                .unwrap_or_default()
        } else {
            cfg.node.name.to_string()
        };
        let started_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros())
            .saturating_sub(self.src.started.elapsed().as_micros());
        SystemInfo {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            node,
            role: label(&cfg.node.role),
            uptime_seconds: self.src.started.elapsed().as_secs(),
            started_at: format_us(u64::try_from(started_us).unwrap_or(0)),
            listeners: cfg
                .listen
                .iter()
                .map(|l| format!("{}://{}", label(&l.proto), l.addr))
                .collect(),
            query_log: self.src.qlog.is_some(),
            filter_snapshot: snap.as_ref().map(|s| s.manifest.version),
            filter_names: snap.as_ref().map_or(0, |s| {
                let st = &s.manifest.stats;
                st.subtree_names + st.exact_names + st.subdomains_names
            }),
        }
    }

    fn timeseries(&self, step: Step, from_s: u64, to_s: u64) -> Vec<TimeBucket> {
        let res = match step {
            Step::Second => Resolution::Second,
            Step::Minute => Resolution::Minute,
        };
        let series = self
            .src
            .pipeline
            .telemetry
            .aggregates()
            .series(res, from_s, to_s);
        series
            .into_iter()
            .map(|(start, c)| {
                let mut b = TimeBucket {
                    start_unix_seconds: start,
                    total: c.total,
                    upstream_queries: c.upstreams.iter().sum(),
                    upstream_failures: c.upstream_failures,
                    ..TimeBucket::default()
                };
                for (i, s) in Status::ALL.iter().enumerate() {
                    if c.status[i] > 0 {
                        b.by_status.insert(s.label().to_owned(), c.status[i]);
                    }
                }
                for (i, n) in c.qtype.iter().enumerate() {
                    if *n > 0 {
                        let key = QTYPES.get(i).map_or("other", |(_, name)| name);
                        b.by_qtype.insert(key.to_owned(), *n);
                    }
                }
                for (i, n) in c.rcode.iter().enumerate() {
                    if *n > 0 {
                        let key = if i == N_RCODE - 1 {
                            "other".to_owned()
                        } else {
                            rcode_name(u8::try_from(i).unwrap_or(u8::MAX))
                        };
                        b.by_rcode.insert(key, *n);
                    }
                }
                b
            })
            .collect()
    }

    fn top(&self, kind: TopKind, h: Hour, limit: usize, client: Option<IpAddr>) -> Vec<TopItem> {
        let agg = self.src.pipeline.telemetry.aggregates();
        let tops = match (kind, client) {
            (TopKind::Domains, Some(ip)) => agg.top_client_domains(mapped(ip), limit),
            (k, _) => {
                let k = match k {
                    TopKind::Domains => telltale_telemetry::agg::TopKind::Domains,
                    TopKind::Blocked => telltale_telemetry::agg::TopKind::Blocked,
                    TopKind::Nxdomain => telltale_telemetry::agg::TopKind::Nxdomain,
                    TopKind::Clients => telltale_telemetry::agg::TopKind::Clients,
                };
                agg.top_names(k, hour(h), limit)
            }
        };
        drop(agg);
        let policy = &self.src.pipeline.current().policy;
        tops.into_iter()
            .map(|t| {
                // Clients get their configured device name when they have one.
                let name = (kind == TopKind::Clients)
                    .then(|| t.key.parse::<IpAddr>().ok())
                    .flatten()
                    .and_then(|ip| {
                        let id =
                            policy
                                .clients
                                .identify(ip, None, None, &self.src.pipeline.neighbors);
                        policy.clients.client(id).map(|c| c.name.to_string())
                    });
                TopItem {
                    key: t.key,
                    name,
                    count: t.count,
                    error_bound: t.error,
                }
            })
            .collect()
    }

    fn latency(&self, by: LatencyBy, h: Hour) -> Vec<LatencyRow> {
        let sel = hour(h);
        let agg = self.src.pipeline.telemetry.aggregates();
        let mut rows = Vec::new();
        match by {
            LatencyBy::Path => {
                for p in AnswerPath::ALL {
                    for proto in Proto::ALL {
                        if let Some(v) = agg.latency(LatencyKey::Total(p, proto), sel) {
                            rows.push(latency_row(format!("{}/{}", p.label(), proto.label()), v));
                        }
                    }
                }
            }
            LatencyBy::Qtype => {
                for i in 0..=QTYPES.len() {
                    if let Some(v) = agg.latency(LatencyKey::Qtype(i), sel) {
                        let key = QTYPES.get(i).map_or("other", |(_, n)| n);
                        rows.push(latency_row(key.to_owned(), v));
                    }
                }
            }
            LatencyBy::Stage => {
                if let Some(v) = agg.latency(LatencyKey::StageUpstream, sel) {
                    rows.push(latency_row("upstream".to_owned(), v));
                }
            }
            LatencyBy::Upstream => {
                let router = Arc::clone(&self.src.pipeline.current().router);
                for u in router.upstreams() {
                    if let Some(v) = agg.latency(LatencyKey::Upstream(u.id), sel) {
                        rows.push(latency_row(u.name.clone(), v));
                    }
                }
            }
        }
        rows
    }

    fn queries(
        &self,
        q: &QueryParams,
        from_us: u64,
        to_us: u64,
        limit: usize,
    ) -> Result<QueryPage, Problem> {
        if self.src.qlog.is_none() {
            return Err(
                Problem::unavailable("the query log is off on this node").hint(
                    "Enable it with [telemetry.qlog] enabled = true (and privacy_level below 3).",
                ),
            );
        }
        let filter = qlog_filter(q, from_us, to_us)?;
        let cursor = match &q.cursor {
            None => None,
            Some(c) => Some(qlog::Cursor::decode(c).ok_or_else(|| {
                Problem::invalid("`cursor`: not a cursor from this API")
                    .hint("Pass the nextCursor value from the previous page unchanged.")
            })?),
        };
        let dir = Path::new(self.src.config.load().node.data_dir.as_str()).join("qlog");
        let opts = qlog::Options {
            threads: std::thread::available_parallelism().map_or(1, |n| n.get().min(4)),
            on_thread_start: Some(telltale_net::background_thread),
        };
        let page = qlog::search_with(&dir, &filter, limit, cursor, &opts)
            .map_err(|e| Problem::internal(format!("query log: {e}")))?;
        let lists = self.list_names();
        let policy = &self.src.pipeline.current().policy;
        let clients = policy.clients.clients();
        let groups = policy.clients.groups();
        let items = page
            .rows
            .iter()
            .map(|r| QueryRow {
                time: format_us(r.ts_us),
                ts_unix_micros: r.ts_us,
                client: telltale_telemetry::agg::client_text(r.client_ip),
                client_name: r
                    .client_ref
                    .checked_sub(1)
                    .and_then(|i| clients.get(i as usize))
                    .map(|c| c.name.to_string()),
                group: groups.get(usize::from(r.group)).map(|g| g.name.to_string()),
                name: r.name.clone(),
                qtype: qtype_name(r.qtype),
                status: r.status.label().to_owned(),
                rcode: r.rcode.map(rcode_name),
                proto: r.proto.label().to_owned(),
                list: r.rule.map(|x| {
                    lists
                        .get(usize::from(x.list))
                        .cloned()
                        .unwrap_or_else(|| format!("#{}", x.list))
                }),
                rule: r
                    .rule
                    .map(|x| if x.allow { "allow" } else { x.kind.label() }.to_owned()),
                total_ms: ms(u64::from(r.t_total_us)),
                upstream_ms: ms(u64::from(r.t_upstream_us)),
                response_bytes: r.resp_size,
                answers: r.answers,
            })
            .collect();
        Ok(QueryPage {
            items,
            next_cursor: page.next.map(|c| c.encode()),
            scanned: ScanStats {
                segments: page.stats.segments,
                blocks_read: page.stats.blocks_read,
                blocks_total: page.stats.blocks_total,
                rows_scanned: page.stats.rows_scanned,
            },
        })
    }

    fn explain(&self, p: &ExplainParams) -> Result<Explanation, Problem> {
        let qtype_text = p.qtype.clone().unwrap_or_else(|| "A".to_owned());
        let qtype = telltale_proto::rtype::from_name(&qtype_text)
            .ok_or_else(|| Problem::invalid(format!("`qtype`: unknown type `{qtype_text}`")))?;
        let client: IpAddr = p
            .client
            .as_deref()
            .unwrap_or("127.0.0.1")
            .parse()
            .map_err(|_| Problem::invalid("`client` is not an IP address"))?;
        let mac = match p.mac.as_deref().map(telltale_config::MatchKey::parse) {
            None => None,
            Some(Ok(telltale_config::MatchKey::Mac(m))) => Some(m),
            Some(_) => {
                return Err(Problem::invalid("`mac` is not a MAC address")
                    .hint("Use the form aa:bb:cc:dd:ee:ff."));
            }
        };
        let req = crate::explain::Request {
            name: &p.name,
            qtype,
            client,
            mac,
            client_id: None,
        };
        let cfg = self.src.config.load();
        let e = self
            .src
            .pipeline
            .explain(&req, crate::lists::source_reader(&cfg))
            .map_err(|e| Problem::invalid(e).hint("Pass a domain name such as ads.example.com."))?;
        Ok(Explanation {
            name: e.name,
            qtype: qtype_name(e.qtype),
            client: ExplainClient {
                ip: e.client.ip.to_string(),
                mac: e.client.mac,
                device: e.client.device,
                identified_by: e.client.identified_by.to_owned(),
                groups: e.client.groups,
            },
            outcome: label(&e.outcome),
            summary: e.summary,
            block: e.block.map(|b| ExplainBlock {
                list: b.list,
                mode: label(&b.mode),
                ttl_seconds: b.ttl,
                ede_code: b.ede_code,
            }),
            paused_until_unix_seconds: e.paused_until,
            filter: e.filter.map(|f| ExplainFilter {
                snapshot: f.snapshot,
                rules: f
                    .rules
                    .into_iter()
                    .map(|r| ExplainRule {
                        list: r.list,
                        tier: label(&r.tier),
                        kind: label(&r.kind),
                        scope: r.scope.map(|s| label(&s)),
                        name: r.name,
                        enabled: r.enabled,
                        winner: r.winner,
                        lines: r
                            .lines
                            .into_iter()
                            .map(|l| ExplainLine {
                                line: l.line,
                                text: l.text,
                            })
                            .collect(),
                    })
                    .collect(),
                notes: f.notes,
            }),
            route: e.route.map(|r| ExplainRoute {
                group: r.group,
                routed: r.routed,
            }),
            notes: e.notes,
        })
    }

    fn lists(&self) -> Vec<ListInfo> {
        let cfg = self.src.config.load();
        let shared = self.src.lists.load_full();
        let status = shared
            .as_ref()
            .map(|l| l.fetcher.status())
            .unwrap_or_default();
        let compiled = shared.as_ref().and_then(|l| {
            l.compiled
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map(|c| c.manifest.clone())
        });
        cfg.list
            .iter()
            .map(|l| {
                let meta = status.iter().find(|(n, _)| *n == *l.name).map(|(_, m)| m);
                let entries = compiled.as_ref().map_or(0, |m| {
                    m.lists
                        .iter()
                        .position(|x| x.name == *l.name)
                        .and_then(|i| m.stats.per_list.get(i))
                        .map_or(0, |s| s.entries)
                });
                let source = l
                    .url
                    .as_ref()
                    .or(l.path.as_ref())
                    .map_or_else(|| "inline".to_owned(), ToString::to_string);
                let state = match meta {
                    Some(m) if m.last_error.is_some() && !m.has_content() => "failed",
                    Some(m) if m.has_content() => "ok",
                    _ => "pending",
                };
                ListInfo {
                    name: l.name.to_string(),
                    kind: label(&l.kind),
                    enabled: l.enabled,
                    source,
                    state: state.to_owned(),
                    error: meta.and_then(|m| m.last_error.clone()),
                    bytes: meta.map_or(0, |m| m.bytes),
                    lines: meta.map_or(0, |m| m.lines),
                    entries,
                    last_checked_unix_seconds: meta.and_then(|m| m.last_attempt),
                    last_changed_unix_seconds: meta.and_then(|m| m.last_changed),
                }
            })
            .collect()
    }

    fn groups(&self) -> Vec<GroupInfo> {
        let now = crate::pipeline::unix_now();
        let pauses = self.src.pipeline.pause.active(now);
        let global = pauses.iter().find(|(g, _)| g.is_none()).map(|(_, u)| *u);
        let policy = &self.src.pipeline.current().policy;
        policy
            .clients
            .groups()
            .iter()
            .map(|g| GroupInfo {
                name: g.name.to_string(),
                priority: g.priority,
                lists: g
                    .lists
                    .as_ref()
                    .map(|l| l.iter().map(ToString::to_string).collect()),
                block_mode: label(&g.block.mode),
                block_ttl_seconds: g.block.ttl,
                paused_until_unix_seconds: pauses
                    .iter()
                    .find(|(n, _)| n.as_deref() == Some(&*g.name))
                    .map(|(_, u)| *u)
                    .max(global),
            })
            .collect()
    }

    fn clients(&self) -> Vec<ClientInfo> {
        self.src
            .config
            .load()
            .client
            .iter()
            .map(|c| ClientInfo {
                name: c.name.to_string(),
                matches: c.match_keys.iter().map(ToString::to_string).collect(),
                groups: c.groups.iter().map(ToString::to_string).collect(),
            })
            .collect()
    }

    fn upstreams(&self) -> Vec<UpstreamInfo> {
        let cfg = self.src.config.load();
        let router = Arc::clone(&self.src.pipeline.current().router);
        router
            .upstreams()
            .iter()
            .map(|u| {
                let h = u.health.snapshot();
                UpstreamInfo {
                    id: u.id,
                    name: u.name.clone(),
                    endpoint: u.endpoint.to_string(),
                    groups: cfg
                        .upstream_group
                        .iter()
                        .filter(|g| g.members.iter().any(|m| **m == *u.name))
                        .map(|g| g.name.to_string())
                        .collect(),
                    breaker: match h.breaker {
                        Breaker::Closed => "closed",
                        Breaker::HalfOpen => "half_open",
                        Breaker::Open => "open",
                    }
                    .to_owned(),
                    requests: h.requests,
                    failures: h.failures,
                    latency_ewma_ms: h.ewma.map_or(0.0, |d| {
                        ms(u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
                    }),
                }
            })
            .collect()
    }
}
