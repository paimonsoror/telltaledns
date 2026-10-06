//! REQ: AGT-012 (T8.4, ADR-082) — runs `vqlog` plans (parsed in `telltale_api::vqlog`)
//! over the query log: the conditions narrow the qlog search where they can (time, one name,
//! one client, group, status, qtype, rcode, upstream, minimum latency) and are all checked on
//! every row it returns, then rows are grouped and aggregated in memory.
//!
//! Bounded: refused above `MAX_ESTIMATED` rows by the header-only estimate; stops (marked
//! truncated) after `MAX_MATCHED` matching rows, `MAX_GROUPS` groups, or `DEADLINE`. Search
//! threads run at background priority like every query-log search.

use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use telltale_api::model::{VqlogCost, VqlogResult};
use telltale_api::problem::Problem;
use telltale_api::vqlog::{Agg, Cond, Field, Key, Metric, Op, Query, glob_match};
use telltale_store::qlog;
use telltale_telemetry::{Proto, Status};

/// Refused above this many rows (the estimate).
const MAX_ESTIMATED: u64 = 100_000_000;
/// Stops after this many matching rows.
const MAX_MATCHED: u64 = 2_000_000;
const MAX_GROUPS: usize = 100_000;
const DEADLINE: Duration = Duration::from_secs(25);
const PAGE: usize = 20_000;

/// What the plan needs from the server.
pub(crate) struct Ctx<'a> {
    /// Group names by index.
    pub(crate) groups: Vec<String>,
    /// Upstream names by ID.
    pub(crate) upstreams: HashMap<u16, String>,
    pub(crate) client_name: &'a dyn Fn([u8; 16]) -> Option<String>,
    pub(crate) qtype_name: fn(u16) -> String,
    pub(crate) rcode_name: fn(u8) -> String,
    pub(crate) rcode_value: fn(&str) -> Option<u8>,
}

/// A condition, resolved.
#[derive(Debug)]
enum Pred {
    Name {
        op: Op,
        values: Vec<String>,
    },
    Client {
        neg: bool,
        nets: Vec<([u8; 16], u8)>,
    },
    Group {
        neg: bool,
        set: Vec<u16>,
    },
    Status {
        neg: bool,
        set: Vec<Status>,
    },
    Qtype {
        neg: bool,
        set: Vec<u16>,
    },
    Rcode {
        neg: bool,
        set: Vec<Option<u8>>,
    },
    Upstream {
        neg: bool,
        set: Vec<u16>,
    },
    Proto {
        neg: bool,
        set: Vec<Proto>,
    },
    Latency {
        upstream: bool,
        op: Op,
        us: u64,
    },
}

fn in_net(ip: &[u8; 16], (net, bits): &([u8; 16], u8)) -> bool {
    let bits = usize::from(*bits);
    let (full, rest) = (bits / 8, bits % 8);
    if ip[..full] != net[..full] {
        return false;
    }
    rest == 0 || {
        let mask = 0xffu8 << (8 - rest);
        ip[full] & mask == net[full] & mask
    }
}

impl Pred {
    fn matches(&self, r: &qlog::Row) -> bool {
        let pick = |neg: bool, hit: bool| hit != neg;
        match self {
            Self::Name { op, values } => {
                let n = r.name.as_str();
                match op {
                    Op::Eq | Op::In => values.iter().any(|v| v == n),
                    Op::Ne | Op::NotIn => !values.iter().any(|v| v == n),
                    Op::Glob => values.iter().any(|v| glob_match(v, n)),
                    Op::Has => values.iter().any(|v| n.contains(v.as_str())),
                    Op::Under => values.iter().any(|v| {
                        n == v
                            || (n.len() > v.len()
                                && n.ends_with(v.as_str())
                                && n.as_bytes()[n.len() - v.len() - 1] == b'.')
                    }),
                    Op::Gt | Op::Ge | Op::Lt | Op::Le => false,
                }
            }
            Self::Client { neg, nets } => pick(*neg, nets.iter().any(|n| in_net(&r.client_ip, n))),
            Self::Group { neg, set } => pick(*neg, set.contains(&r.group)),
            Self::Status { neg, set } => pick(*neg, set.contains(&r.status)),
            Self::Qtype { neg, set } => pick(*neg, set.contains(&r.qtype)),
            Self::Rcode { neg, set } => pick(*neg, set.contains(&r.rcode)),
            Self::Upstream { neg, set } => pick(*neg, set.contains(&r.upstream)),
            Self::Proto { neg, set } => pick(*neg, set.contains(&r.proto)),
            Self::Latency { upstream, op, us } => {
                let v = u64::from(if *upstream {
                    r.t_upstream_us
                } else {
                    r.t_total_us
                });
                match op {
                    Op::Gt => v > *us,
                    Op::Ge => v >= *us,
                    Op::Lt => v < *us,
                    Op::Le => v <= *us,
                    _ => false,
                }
            }
        }
    }
}

fn bad(field: Field, v: &str, hint: impl Into<String>) -> Problem {
    Problem::invalid(format!("`q`: {}: unknown `{v}`", field.label())).hint(hint)
}

fn client_net(v: &str) -> Option<([u8; 16], u8)> {
    let (ip, bits) = match v.split_once('/') {
        Some((ip, b)) => (ip, Some(b.parse::<u8>().ok()?)),
        None => (v, None),
    };
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let b = bits.unwrap_or(32);
            (b <= 32).then(|| (v4.to_ipv6_mapped().octets(), b + 96))
        }
        IpAddr::V6(v6) => {
            let b = bits.unwrap_or(128);
            (b <= 128).then_some((v6.octets(), b))
        }
    }
}

/// Resolves one condition against this server's names.
#[allow(clippy::too_many_lines)] // one arm per field
fn resolve(c: &Cond, ctx: &Ctx<'_>) -> Result<Pred, Problem> {
    let neg = !c.op.positive();
    Ok(match c.field {
        Field::Name => Pred::Name {
            op: c.op,
            values: c.values.iter().map(|v| v.trim_end_matches('.').to_ascii_lowercase()).collect(),
        },
        Field::Client => Pred::Client {
            neg,
            nets: c
                .values
                .iter()
                .map(|v| {
                    client_net(v).ok_or_else(|| {
                        bad(Field::Client, v, "Use the device's address or a CIDR (192.168.1.0/24); get_client_profile gives a named device's address.")
                    })
                })
                .collect::<Result<_, _>>()?,
        },
        Field::Group => Pred::Group {
            neg,
            set: c
                .values
                .iter()
                .map(|v| {
                    ctx.groups
                        .iter()
                        .position(|g| g.eq_ignore_ascii_case(v))
                        .and_then(|i| u16::try_from(i).ok())
                        .ok_or_else(|| bad(Field::Group, v, format!("Groups: {}.", ctx.groups.join(", "))))
                })
                .collect::<Result<_, _>>()?,
        },
        Field::Status => Pred::Status {
            neg,
            set: c
                .values
                .iter()
                .map(|v| {
                    Status::ALL.into_iter().find(|s| s.label().eq_ignore_ascii_case(v)).ok_or_else(|| {
                        let all: Vec<&str> = Status::ALL.iter().map(|s| s.label()).collect();
                        bad(Field::Status, v, format!("Statuses: {}.", all.join(", ")))
                    })
                })
                .collect::<Result<_, _>>()?,
        },
        Field::Qtype => Pred::Qtype {
            neg,
            set: c
                .values
                .iter()
                .map(|v| telltale_proto::rtype::from_name(v).ok_or_else(|| bad(Field::Qtype, v, "Types such as A, AAAA, HTTPS, TXT.")))
                .collect::<Result<_, _>>()?,
        },
        Field::Rcode => Pred::Rcode {
            neg,
            set: c
                .values
                .iter()
                .map(|v| {
                    if v.eq_ignore_ascii_case("none") {
                        return Ok(None);
                    }
                    (ctx.rcode_value)(v)
                        .map(Some)
                        .ok_or_else(|| bad(Field::Rcode, v, "Codes such as NOERROR, NXDOMAIN, SERVFAIL, REFUSED, or none (no answer)."))
                })
                .collect::<Result<_, _>>()?,
        },
        Field::Upstream => Pred::Upstream {
            neg,
            set: c
                .values
                .iter()
                .map(|v| {
                    ctx.upstreams
                        .iter()
                        .find(|(_, n)| n.eq_ignore_ascii_case(v))
                        .map(|(id, _)| *id)
                        .or_else(|| v.parse().ok())
                        .ok_or_else(|| {
                            let mut all: Vec<&str> = ctx.upstreams.values().map(String::as_str).collect();
                            all.sort_unstable();
                            bad(Field::Upstream, v, format!("Upstreams: {}.", all.join(", ")))
                        })
                })
                .collect::<Result<_, _>>()?,
        },
        Field::Proto => Pred::Proto {
            neg,
            set: c
                .values
                .iter()
                .map(|v| {
                    Proto::ALL
                        .into_iter()
                        .find(|p| p.label().eq_ignore_ascii_case(v))
                        .ok_or_else(|| bad(Field::Proto, v, "udp, tcp, dot, doh, or doq."))
                })
                .collect::<Result<_, _>>()?,
        },
        Field::Latency | Field::UpstreamLatency => {
            let ms: f64 = c.values.first().and_then(|v| v.parse().ok()).unwrap_or(0.0);
            Pred::Latency {
                upstream: c.field == Field::UpstreamLatency,
                op: c.op,
                // Sub-microsecond precision is meaningless here.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                us: (ms.max(0.0) * 1000.0).round() as u64,
            }
        }
    })
}

/// The search filter: the parts of the conditions the qlog index can use.
fn pushdown(preds: &[Pred], from_us: u64, to_us: u64) -> qlog::Filter {
    let mut f = qlog::Filter {
        from_us,
        to_us,
        ..qlog::Filter::default()
    };
    for p in preds {
        match p {
            Pred::Name { op, values } if f.name.is_none() && values.len() == 1 => {
                let v = values[0].clone();
                f.name = match op {
                    Op::Eq | Op::In => Some(qlog::NameMatch::Exact(v)),
                    Op::Glob => Some(qlog::NameMatch::Glob(v)),
                    Op::Has => Some(qlog::NameMatch::Substring(v)),
                    Op::Under => Some(qlog::NameMatch::Suffix(v)),
                    _ => None,
                };
            }
            Pred::Client { neg: false, nets } if nets.len() == 1 && nets[0].1 == 128 => {
                f.client_ip = Some(nets[0].0);
            }
            Pred::Group { neg: false, set } if set.len() == 1 => f.group = Some(set[0]),
            Pred::Status { neg: false, set } => f.status.clone_from(set),
            Pred::Qtype { neg: false, set } => f.qtype.clone_from(set),
            Pred::Rcode { neg: false, set } if set.iter().all(Option::is_some) => {
                f.rcode = set.iter().flatten().copied().collect();
            }
            Pred::Upstream { neg: false, set } if set.len() == 1 => f.upstream = Some(set[0]),
            Pred::Latency {
                upstream: false,
                op: op @ (Op::Gt | Op::Ge),
                us,
            } => {
                let min = if *op == Op::Gt { us + 1 } else { *us };
                f.min_total_us = Some(u32::try_from(min).unwrap_or(u32::MAX));
            }
            _ => {}
        }
    }
    f
}

/// A grouping value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Kv {
    Time(u64),
    Str(String),
    Ip([u8; 16]),
    N(u16),
    Rc(Option<u8>),
    St(u8),
    Pr(u8),
}

fn key_of(r: &qlog::Row, k: Key) -> Kv {
    match k {
        Key::Name => Kv::Str(r.name.clone()),
        Key::Domain => Kv::Str(
            telltale_proto::NameBuf::from_presentation(&r.name)
                .ok()
                .and_then(|n| telltale_telemetry::anomaly::registrable(n.as_wire()))
                .unwrap_or_else(|| r.name.clone()),
        ),
        Key::Client => Kv::Ip(r.client_ip),
        Key::Group => Kv::N(r.group),
        Key::Status => Kv::St(r.status as u8),
        Key::Qtype => Kv::N(r.qtype),
        Key::Rcode => Kv::Rc(r.rcode),
        Key::Upstream => Kv::N(r.upstream),
        Key::Proto => Kv::Pr(r.proto as u8),
    }
}

fn metric_of(r: &qlog::Row, m: Metric) -> u64 {
    match m {
        Metric::Latency => u64::from(r.t_total_us),
        Metric::UpstreamLatency => u64::from(r.t_upstream_us),
        Metric::Answers => u64::from(r.answers),
        Metric::Bytes => u64::from(r.resp_size),
    }
}

/// One aggregate's running state.
#[derive(Debug, Clone)]
enum Acc {
    Count,
    Distinct(HashSet<u64>),
    Sum(u64),
    Min(u64),
    Max(u64),
    Samples(Vec<u32>),
}

impl Acc {
    fn new(a: Agg) -> Self {
        match a {
            Agg::Count => Self::Count,
            Agg::Distinct(_) => Self::Distinct(HashSet::new()),
            Agg::Avg(_) => Self::Sum(0),
            Agg::Min(_) => Self::Min(u64::MAX),
            Agg::Max(_) => Self::Max(0),
            Agg::Pct(..) => Self::Samples(Vec::new()),
        }
    }
    fn add(&mut self, a: Agg, r: &qlog::Row) {
        match (self, a) {
            (Self::Distinct(set), Agg::Distinct(k)) => {
                let mut h = DefaultHasher::new();
                key_of(r, k).hash(&mut h);
                set.insert(h.finish());
            }
            (Self::Sum(s), Agg::Avg(m)) => *s = s.saturating_add(metric_of(r, m)),
            (Self::Min(v), Agg::Min(m)) => *v = (*v).min(metric_of(r, m)),
            (Self::Max(v), Agg::Max(m)) => *v = (*v).max(metric_of(r, m)),
            (Self::Samples(s), Agg::Pct(_, m)) => {
                s.push(u32::try_from(metric_of(r, m)).unwrap_or(u32::MAX));
            }
            _ => {}
        }
    }
    /// The value (latencies in ms), for sorting and output.
    #[allow(clippy::cast_precision_loss)] // counts and microseconds well below 2^52
    fn value(&mut self, a: Agg, count: u64) -> Option<f64> {
        let ms = |m: Metric, v: f64| {
            if matches!(m, Metric::Latency | Metric::UpstreamLatency) {
                (v / 10.0).round() / 100.0
            } else {
                v
            }
        };
        match (self, a) {
            (Self::Count, _) => Some(count as f64),
            (Self::Distinct(s), _) => Some(s.len() as f64),
            (Self::Sum(s), Agg::Avg(m)) => {
                (count > 0).then(|| ms(m, (*s as f64 / count as f64 * 100.0).round() / 100.0))
            }
            (Self::Min(v), Agg::Min(m)) => (count > 0).then(|| ms(m, *v as f64)),
            (Self::Max(v), Agg::Max(m)) => (count > 0).then(|| ms(m, *v as f64)),
            (Self::Samples(s), Agg::Pct(p, m)) => {
                if s.is_empty() {
                    return None;
                }
                s.sort_unstable();
                // Nearest rank.
                let rank = (usize::from(p) * s.len()).div_ceil(100);
                Some(ms(m, f64::from(s[rank.clamp(1, s.len()) - 1])))
            }
            _ => None,
        }
    }
}

struct Group {
    count: u64,
    accs: Vec<Acc>,
}

/// Runs (or, with `dry_run`, only estimates) `q` over the query logs in `dirs`.
#[allow(clippy::too_many_lines)] // one linear pipeline: estimate, scan, aggregate, shape
pub(crate) fn run(
    q: &Query,
    from_us: u64,
    to_us: u64,
    dirs: &[PathBuf],
    ctx: &Ctx<'_>,
    dry_run: bool,
    opts: &qlog::Options,
) -> Result<VqlogResult, Problem> {
    let started = Instant::now();
    let preds: Vec<Pred> = q
        .conds
        .iter()
        .map(|c| resolve(c, ctx))
        .collect::<Result<_, _>>()?;
    // REQ: AGT-012 (T9.12) — `or` groups: checked per row (only the plain conditions are
    // pushed into the index search).
    let any_of: Vec<Vec<Vec<Pred>>> = q
        .any_of
        .iter()
        .map(|g| {
            g.iter()
                .map(|alt| alt.iter().map(|c| resolve(c, ctx)).collect())
                .collect()
        })
        .collect::<Result<_, _>>()?;
    let filter = pushdown(&preds, from_us, to_us);
    let mut cost = VqlogCost::default();
    for d in dirs {
        let e = qlog::estimate(d, &filter).map_err(|e| Problem::invalid(format!("`q`: {e}")))?;
        cost.estimated_rows += e.rows;
        cost.segments += e.segments;
        cost.blocks += e.blocks;
    }
    let mut out = VqlogResult {
        query: q.to_string(),
        columns: columns(q),
        source: "querylog".to_owned(),
        ..VqlogResult::default()
    };
    if cost.estimated_rows > MAX_ESTIMATED {
        return Err(Problem::invalid(format!(
            "`q`: this would read up to {} logged queries (the limit is {MAX_ESTIMATED})",
            cost.estimated_rows
        ))
        .hint("Narrow the time (from -1d), or filter by status, client, group, or one name."));
    }
    if dry_run {
        cost.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        out.cost = cost;
        return Ok(out);
    }
    let mut groups: HashMap<Vec<Kv>, Group> = HashMap::new();
    let mut reason: Option<String> = None;
    let bucket_us = q.bucket_secs.map(|b| b.saturating_mul(1_000_000));
    'dirs: for d in dirs {
        let mut cursor = None;
        loop {
            let page = qlog::search_with(d, &filter, PAGE, cursor, opts)
                .map_err(|e| Problem::internal(format!("query log: {e}")))?;
            cost.rows_scanned += page.stats.rows_scanned as u64;
            for r in &page.rows {
                if !preds.iter().all(|p| p.matches(r))
                    || !any_of
                        .iter()
                        .all(|g| g.iter().any(|alt| alt.iter().all(|p| p.matches(r))))
                {
                    continue;
                }
                let mut key = Vec::with_capacity(q.keys.len() + 1);
                if let Some(b) = bucket_us {
                    key.push(Kv::Time(r.ts_us / b * b));
                }
                key.extend(q.keys.iter().map(|k| key_of(r, *k)));
                if !groups.contains_key(&key) && groups.len() >= MAX_GROUPS {
                    reason.get_or_insert_with(|| {
                        format!("more than {MAX_GROUPS} groups: the rest were left out")
                    });
                    continue;
                }
                let g = groups.entry(key).or_insert_with(|| Group {
                    count: 0,
                    accs: q.aggs.iter().map(|a| Acc::new(*a)).collect(),
                });
                g.count += 1;
                for (acc, a) in g.accs.iter_mut().zip(&q.aggs) {
                    acc.add(*a, r);
                }
                cost.rows_matched += 1;
                if cost.rows_matched >= MAX_MATCHED {
                    reason = Some(format!(
                        "stopped after {MAX_MATCHED} matching queries (the newest)"
                    ));
                    break 'dirs;
                }
            }
            if started.elapsed() > DEADLINE {
                reason = Some(format!(
                    "stopped after {} s (the newest queries)",
                    DEADLINE.as_secs()
                ));
                break 'dirs;
            }
            match page.next {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
    }
    Ok(finish(q, groups, ctx, out, cost, reason, started))
}

/// The table from the groups: sorted, limited, labeled.
fn finish(
    q: &Query,
    mut groups: HashMap<Vec<Kv>, Group>,
    ctx: &Ctx<'_>,
    mut out: VqlogResult,
    mut cost: VqlogCost,
    reason: Option<String>,
    started: Instant,
) -> VqlogResult {
    // A plain total is one row, even with nothing matched.
    if groups.is_empty() && q.keys.is_empty() && q.bucket_secs.is_none() {
        groups.insert(
            Vec::new(),
            Group {
                count: 0,
                accs: q.aggs.iter().map(|a| Acc::new(*a)).collect(),
            },
        );
    }
    out.groups = groups.len() as u64;
    let mut rows: Vec<(Vec<Kv>, Vec<Option<f64>>)> = groups
        .into_iter()
        .map(|(k, mut g)| {
            let vals = g
                .accs
                .iter_mut()
                .zip(&q.aggs)
                .map(|(acc, a)| acc.value(*a, g.count))
                .collect();
            (k, vals)
        })
        .collect();
    let (sort_col, desc) = q.sort_by();
    let cols = q.columns();
    let key_cols = cols.len() - q.aggs.len();
    let idx = cols.iter().position(|c| *c == sort_col).unwrap_or(key_cols);
    rows.sort_by(|a, b| {
        let o = if idx < key_cols {
            a.0[idx].cmp(&b.0[idx])
        } else {
            let (x, y) = (a.1[idx - key_cols], b.1[idx - key_cols]);
            x.unwrap_or(f64::MIN).total_cmp(&y.unwrap_or(f64::MIN))
        };
        // Ties: by the keys, so results are stable.
        let o = if desc { o.reverse() } else { o };
        o.then_with(|| a.0.cmp(&b.0))
    });
    rows.truncate(q.limit);
    let mut key_kinds: Vec<Option<Key>> = Vec::new();
    if q.bucket_secs.is_some() {
        key_kinds.push(None);
    }
    key_kinds.extend(q.keys.iter().map(|k| Some(*k)));
    out.rows = rows
        .into_iter()
        .map(|(keys, vals)| {
            let mut row = Vec::new();
            for (kv, kind) in keys.iter().zip(&key_kinds) {
                label(kv, *kind, ctx, &mut row);
            }
            row.extend(
                vals.into_iter()
                    .map(|v| v.map_or(Value::Null, |x| json!(x))),
            );
            row
        })
        .collect();
    cost.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    out.cost = cost;
    out.truncated = reason.is_some();
    out.truncated_reason = reason;
    out
}

/// REQ: AGT-012 (T9.12) — the rollup breakdown that can answer `q`, if any: counts only,
/// no `or`, buckets of whole hours, and at most one of status, qtype, rcode, proto, and
/// group across the key and the conditions (`=`, `!=`, `in`, `not in`). `Some(None)` is a
/// plain count.
#[allow(clippy::option_option)] // `None`: it doesn't fit; `Some(None)`: a plain count
pub(crate) fn rollup_dim(q: &Query) -> Option<Option<Key>> {
    if q.aggs != [Agg::Count]
        || !q.any_of.is_empty()
        || q.bucket_secs.is_some_and(|b| !b.is_multiple_of(3600))
        || q.keys.len() > 1
    {
        return None;
    }
    let dim_of = |f: Field| match f {
        Field::Status => Some(Key::Status),
        Field::Qtype => Some(Key::Qtype),
        Field::Rcode => Some(Key::Rcode),
        Field::Proto => Some(Key::Proto),
        Field::Group => Some(Key::Group),
        _ => None,
    };
    let mut dim = match q.keys.first() {
        Some(k @ (Key::Status | Key::Qtype | Key::Rcode | Key::Proto | Key::Group)) => Some(*k),
        Some(_) => return None,
        None => None,
    };
    for c in &q.conds {
        let d = dim_of(c.field)?;
        if !matches!(c.op, Op::Eq | Op::Ne | Op::In | Op::NotIn) || dim.is_some_and(|x| x != d) {
            return None;
        }
        // Only the query types the rollups count by name.
        if d == Key::Qtype
            && !c.values.iter().all(|v| {
                telltale_telemetry::QTYPES
                    .iter()
                    .any(|(_, n)| n.eq_ignore_ascii_case(v))
            })
        {
            return None;
        }
        dim = Some(d);
    }
    Some(dim)
}

/// One rollup bucket's columns for the breakdown `dim`: label, key, count.
fn rollup_columns(
    dim: Option<Key>,
    c: &telltale_telemetry::agg::Counts,
    ctx: &Ctx<'_>,
) -> Vec<(String, Kv, u32)> {
    match dim {
        None => vec![(String::new(), Kv::Str(String::new()), c.total)],
        Some(Key::Status) => Status::ALL
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let n = c.status.get(i).copied().unwrap_or(0);
                (
                    s.label().to_owned(),
                    Kv::St(u8::try_from(i).unwrap_or(u8::MAX)),
                    n,
                )
            })
            .collect(),
        Some(Key::Qtype) => {
            let mut v: Vec<(String, Kv, u32)> = telltale_telemetry::QTYPES
                .iter()
                .enumerate()
                .map(|(i, (code, name))| {
                    (
                        (*name).to_owned(),
                        Kv::N(*code),
                        c.qtype.get(i).copied().unwrap_or(0),
                    )
                })
                .collect();
            v.push((
                "other".to_owned(),
                Kv::Str("other".to_owned()),
                c.qtype.last().copied().unwrap_or(0),
            ));
            v
        }
        Some(Key::Rcode) => c
            .rcode
            .iter()
            .enumerate()
            .map(|(i, n)| match u8::try_from(i) {
                Ok(rc) if i + 1 < c.rcode.len() => ((ctx.rcode_name)(rc), Kv::Rc(Some(rc)), *n),
                _ => ("other".to_owned(), Kv::Str("other".to_owned()), *n),
            })
            .collect(),
        Some(Key::Proto) => Proto::ALL
            .iter()
            .enumerate()
            .map(|(i, p)| {
                (
                    p.label().to_owned(),
                    Kv::Pr(*p as u8),
                    c.proto.get(i).copied().unwrap_or(0),
                )
            })
            .collect(),
        Some(_) => c
            .named_groups
            .iter()
            .map(|g| (g.name.to_string(), Kv::Str(g.name.to_string()), g.total))
            .collect(),
    }
}

/// REQ: AGT-012 (T9.12) — `q` answered from rollup buckets (`(start seconds, counts)`, an
/// hour or a day each) instead of the query log, for windows longer than the log keeps.
pub(crate) fn run_rollups(
    q: &Query,
    dim: Option<Key>,
    buckets: &[(u64, telltale_telemetry::agg::Counts)],
    ctx: &Ctx<'_>,
) -> Result<VqlogResult, Problem> {
    let started = Instant::now();
    // The conditions name real values (the same errors as over the query log).
    for c in &q.conds {
        resolve(c, ctx)?;
    }
    let keep = |label: &str| {
        q.conds.iter().all(|c| {
            let hit = c.values.iter().any(|v| v.eq_ignore_ascii_case(label));
            if c.op.positive() { hit } else { !hit }
        })
    };
    let mut groups: HashMap<Vec<Kv>, Group> = HashMap::new();
    let bucket_us = q.bucket_secs.map(|b| b.saturating_mul(1_000_000));
    let mut matched = 0u64;
    for (start, c) in buckets {
        let columns = rollup_columns(dim, c, ctx);
        let mut time = Vec::new();
        if let Some(b) = bucket_us {
            let us = start.saturating_mul(1_000_000);
            time.push(Kv::Time(us / b * b));
        }
        for (label, kv, n) in columns {
            if n == 0 || (dim.is_some() && !keep(&label)) {
                continue;
            }
            let mut key = time.clone();
            if !q.keys.is_empty() {
                key.push(kv);
            }
            let g = groups.entry(key).or_insert_with(|| Group {
                count: 0,
                accs: q.aggs.iter().map(|a| Acc::new(*a)).collect(),
            });
            g.count += u64::from(n);
            matched += u64::from(n);
        }
    }
    let out = VqlogResult {
        query: q.to_string(),
        columns: columns(q),
        source: "rollups".to_owned(),
        ..VqlogResult::default()
    };
    let cost = VqlogCost {
        rows_matched: matched,
        ..VqlogCost::default()
    };
    Ok(finish(q, groups, ctx, out, cost, None, started))
}

/// The output columns: a `client` key is followed by `clientName`.
fn columns(q: &Query) -> Vec<String> {
    let mut v = Vec::new();
    for c in q.columns() {
        let client = c == "client";
        v.push(c);
        if client {
            v.push("clientName".to_owned());
        }
    }
    v
}

fn label(kv: &Kv, kind: Option<Key>, ctx: &Ctx<'_>, row: &mut Vec<Value>) {
    let v = match (kv, kind) {
        (Kv::Time(us), _) => json!(qlog::format_ts(*us)),
        (Kv::Str(s), _) => json!(s),
        (Kv::Ip(ip), _) => {
            row.push(json!(telltale_telemetry::agg::client_text(*ip)));
            (ctx.client_name)(*ip).map_or(Value::Null, |n| json!(n))
        }
        (Kv::N(g), Some(Key::Group)) => json!(
            ctx.groups
                .get(usize::from(*g))
                .cloned()
                .unwrap_or_else(|| format!("#{g}"))
        ),
        (Kv::N(u), Some(Key::Upstream)) => {
            if *u == 0 {
                Value::Null
            } else {
                json!(
                    ctx.upstreams
                        .get(u)
                        .cloned()
                        .unwrap_or_else(|| format!("#{u}"))
                )
            }
        }
        (Kv::N(t), _) => json!((ctx.qtype_name)(*t)),
        (Kv::Rc(rc), _) => rc.map_or_else(|| json!("none"), |rc| json!((ctx.rcode_name)(rc))),
        (Kv::St(s), _) => json!(Status::ALL.get(usize::from(*s)).map_or("?", |s| s.label())),
        (Kv::Pr(p), _) => json!(Proto::from_u8(*p).map_or("?", Proto::label)),
    };
    row.push(v);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use telltale_api::vqlog::parse;
    use telltale_store::qlog::{Builder, Settings};
    use telltale_telemetry::QueryEvent;

    use super::*;

    const HOUR_US: u64 = 3_600_000_000;
    const BASE: u64 = 20_729 * 24 * HOUR_US;

    fn wire(name: &str) -> Vec<u8> {
        telltale_proto::NameBuf::from_presentation(name)
            .unwrap()
            .as_wire()
            .to_vec()
    }

    /// Row `i`, one a second: even rows are blocked `ads.tracker.example`, odd ones forwarded
    /// `www.site.example` through upstream 1; clients .10–.12 in turn; every 4th is AAAA;
    /// latency `i` ms.
    fn ev(i: u64) -> QueryEvent {
        let client = u8::try_from(i % 3).unwrap();
        QueryEvent {
            ts_us: BASE + i * 1_000_000,
            client_ip: std::net::Ipv4Addr::new(192, 168, 1, 10 + client)
                .to_ipv6_mapped()
                .octets(),
            client_ref: u32::from(client),
            group: 0,
            qtype: if i.is_multiple_of(4) { 28 } else { 1 },
            qclass: 1,
            rcode: Some(0),
            status: if i.is_multiple_of(2) {
                Status::Blocked
            } else {
                Status::Forwarded
            },
            proto: Proto::Udp,
            flags: 0x8180,
            rule: None,
            upstream: u16::from(i % 2 == 1),
            attempts: 1,
            t_total_us: u32::try_from(i * 1000).unwrap(),
            t_upstream_us: 0,
            resp_size: 60,
            answers: 1,
        }
    }

    fn log() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let mut b = Builder::spawn(Settings {
            dir: tmp.path().to_owned(),
            node: 1,
            privacy: 0,
            flush_interval: Duration::from_secs(3600),
            fsync: false,
            retention_days: 30,
            retention_bytes: u64::MAX,
            rotate_after: None,
        })
        .unwrap();
        for i in 0..600 {
            let name = if i % 2 == 0 {
                "ads.tracker.example"
            } else {
                "www.site.example"
            };
            b.push(&ev(i), &wire(name));
        }
        drop(b); // flushes and writes footers
        tmp
    }

    fn ask(dir: &std::path::Path, text: &str) -> Result<VqlogResult, Problem> {
        let name = |ip: [u8; 16]| (ip[15] == 10).then(|| "desk".to_owned());
        let ctx = Ctx {
            groups: vec!["default".into(), "kids".into()],
            upstreams: HashMap::from([(1, "quad9".to_owned())]),
            client_name: &name,
            qtype_name: crate::api_backend::qtype_name,
            rcode_name: crate::api_backend::rcode_name,
            rcode_value: crate::api_backend::rcode_value,
        };
        let q = parse(text).unwrap();
        run(
            &q,
            BASE,
            BASE + 2 * HOUR_US,
            &[dir.to_owned()],
            &ctx,
            false,
            &qlog::Options::default(),
        )
    }

    /// REQ: AGT-012 — top-K, filters, percentiles, labels, and the plain total.
    #[test]
    fn agt_012_vqlog_runs() {
        let tmp = log();
        let r = ask(tmp.path(), "where status = blocked | top 5 name").unwrap();
        assert_eq!(r.columns, vec!["name", "count"]);
        assert_eq!(
            r.rows,
            vec![vec![json!("ads.tracker.example"), json!(300.0)]]
        );
        assert_eq!(r.cost.rows_matched, 300);
        assert!(r.cost.estimated_rows >= 300);

        let r = ask(
            tmp.path(),
            "by client | stats count, p50(latency), max(latency) | sort client asc",
        )
        .unwrap();
        assert_eq!(
            r.columns,
            vec![
                "client",
                "clientName",
                "count",
                "p50(latency)",
                "max(latency)"
            ]
        );
        assert_eq!(r.rows.len(), 3);
        assert_eq!(r.rows[0][0], json!("192.168.1.10"));
        assert_eq!(r.rows[0][1], json!("desk"));
        assert_eq!(r.rows[1][1], Value::Null);
        assert_eq!(r.rows[0][2], json!(200.0));
        assert_eq!(
            r.rows[0][4],
            json!(597.0),
            "i = 597 ms is the largest i ≡ 0 (mod 3)"
        );

        let r = ask(tmp.path(), "where name under site.example and qtype != AAAA and latency >= 100 | by upstream, qtype").unwrap();
        assert_eq!(r.rows, vec![vec![json!("quad9"), json!("A"), json!(250.0)]]);

        let r = ask(
            tmp.path(),
            "where name ~ \"*.tracker.*\" and client in (192.168.1.0/30, 10.0.0.1)",
        )
        .unwrap();
        assert_eq!(r.rows, vec![vec![json!(0.0)]], "no client in that range");
        let r = ask(tmp.path(), "where client in (192.168.1.8/30)").unwrap();
        assert_eq!(r.rows, vec![vec![json!(400.0)]], ".10 and .11");

        let r = ask(tmp.path(), "bucket 5m | stats count, distinct(client)").unwrap();
        assert_eq!(r.columns, vec!["time", "count", "distinct(client)"]);
        assert_eq!(r.rows.len(), 2);
        assert_eq!(r.rows[0][1], json!(300.0));
        assert_eq!(r.rows[0][2], json!(3.0));

        // REQ: AGT-012 (T9.12) — `or`: blocked (even i) and (.10 (i ≡ 0 mod 3) or a site
        // name (odd i)) is i ≡ 0 mod 6; a bare `or` is the union.
        let r = ask(
            tmp.path(),
            "where status = blocked and (client = 192.168.1.10 or name under site.example)",
        )
        .unwrap();
        assert_eq!(r.rows, vec![vec![json!(100.0)]]);
        let r = ask(
            tmp.path(),
            "where client = 192.168.1.10 or name under site.example",
        )
        .unwrap();
        assert_eq!(r.rows, vec![vec![json!(400.0)]], "200 + 300 - 100");

        let r = ask(tmp.path(), "by domain, status | stats count").unwrap();
        assert_eq!(r.rows.len(), 2);
        assert!(
            r.rows
                .iter()
                .any(|x| x[0] == json!("tracker.example") && x[1] == json!("blocked"))
        );
    }

    /// REQ: AGT-012 (T9.12) — what the rollups can answer, and the answers: counts by one
    /// breakdown, filtered on it, in day buckets.
    #[test]
    fn agt_012_vqlog_rollups() {
        use telltale_telemetry::agg::{Counts, NamedGroup};
        let dim = |t: &str| rollup_dim(&parse(t).unwrap());
        assert_eq!(
            dim("from -90d | where status = blocked | bucket 1d | stats count"),
            Some(Some(Key::Status))
        );
        assert_eq!(dim("from -90d | by qtype"), Some(Some(Key::Qtype)));
        assert_eq!(dim("from -90d"), Some(None));
        for no in [
            "top 5 name",
            "where status = blocked and group = kids",
            "where status = blocked | by group",
            "bucket 5m",
            "where qtype = DS",
            "stats p95(latency)",
            "where status = blocked or status = refused",
            "where client = 10.0.0.1",
        ] {
            assert_eq!(dim(no), None, "{no}");
        }
        let day = |total: u32, blocked: u32, cached: u32, a: u32, kids: u32| {
            let mut c = Counts {
                total,
                ..Counts::default()
            };
            c.status[5] = blocked;
            c.status[0] = cached;
            c.qtype[0] = a;
            c.qtype[1] = total - a;
            c.named_groups = vec![
                NamedGroup {
                    name: "default".into(),
                    total: total - kids,
                    blocked: 0,
                },
                NamedGroup {
                    name: "kids".into(),
                    total: kids,
                    blocked,
                },
            ];
            c
        };
        let buckets = vec![(0, day(10, 3, 7, 6, 4)), (86_400, day(20, 5, 15, 12, 0))];
        let name = |_: [u8; 16]| None;
        let ctx = Ctx {
            groups: vec!["default".into(), "kids".into()],
            upstreams: HashMap::new(),
            client_name: &name,
            qtype_name: crate::api_backend::qtype_name,
            rcode_name: crate::api_backend::rcode_name,
            rcode_value: crate::api_backend::rcode_value,
        };
        let ask = |t: &str| {
            let q = parse(t).unwrap();
            run_rollups(&q, rollup_dim(&q).unwrap(), &buckets, &ctx).unwrap()
        };
        let r = ask("from -90d | where status = blocked | bucket 1d | stats count");
        assert_eq!(r.source, "rollups");
        assert_eq!(r.columns, vec!["time", "count"]);
        assert_eq!(
            r.rows.iter().map(|x| x[1].clone()).collect::<Vec<_>>(),
            vec![json!(3.0), json!(5.0)]
        );
        let r = ask("from -90d | by status");
        assert_eq!(
            r.rows,
            vec![
                vec![json!("cached"), json!(22.0)],
                vec![json!("blocked"), json!(8.0)]
            ]
        );
        let r = ask("from -90d | where qtype in (A) | stats count");
        assert_eq!(r.rows, vec![vec![json!(18.0)]]);
        let r = ask("from -90d | where group != kids | by group");
        assert_eq!(r.rows, vec![vec![json!("default"), json!(26.0)]]);
        assert_eq!(ask("from -90d").rows, vec![vec![json!(30.0)]]);
        // A value it doesn't know is the same 400 as over the query log.
        let q = parse("from -90d | where status = blokced").unwrap();
        assert!(run_rollups(&q, rollup_dim(&q).unwrap(), &buckets, &ctx).is_err());
    }

    /// REQ: AGT-012 — names it doesn't know are 400s with the choices; a dry run only
    /// estimates.
    #[test]
    fn agt_012_vqlog_errors_and_dry_run() {
        let tmp = log();
        let e = ask(tmp.path(), "where group = teens").unwrap_err();
        assert!(
            e.detail.contains("teens") && e.hint.as_deref().unwrap_or("").contains("kids"),
            "{e:?}"
        );
        assert!(ask(tmp.path(), "where client = nas").is_err());
        assert!(ask(tmp.path(), "where status = bogus").is_err());
        let name = |_: [u8; 16]| None;
        let ctx = Ctx {
            groups: vec![],
            upstreams: HashMap::new(),
            client_name: &name,
            qtype_name: crate::api_backend::qtype_name,
            rcode_name: crate::api_backend::rcode_name,
            rcode_value: crate::api_backend::rcode_value,
        };
        let q = parse("top 3 name").unwrap();
        let r = run(
            &q,
            BASE,
            0,
            &[tmp.path().to_owned()],
            &ctx,
            true,
            &qlog::Options::default(),
        )
        .unwrap();
        assert!(r.rows.is_empty() && r.cost.rows_scanned == 0 && r.cost.estimated_rows >= 600);
    }
}
