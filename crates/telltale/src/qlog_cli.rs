//! `telltale qlog search`: read the query log offline (OBS-003). The API's `GET /queries`
//! (T3.4) returns the same rows.

use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

use serde::Serialize;
use telltale_store::qlog::{self, Cursor, Filter, NameMatch, Row};
use telltale_telemetry::{QTYPES, Status};

/// Search options from the command line.
#[derive(Debug, Default)]
pub(crate) struct Args {
    pub(crate) name: Option<String>,
    /// How to read `name`: substring (default), exact, suffix, glob, or regex.
    pub(crate) mode: String,
    pub(crate) client: Option<IpAddr>,
    pub(crate) status: Vec<String>,
    pub(crate) qtype: Vec<String>,
    pub(crate) since_secs: Option<u64>,
    pub(crate) min_ms: Option<u32>,
    pub(crate) limit: usize,
    pub(crate) cursor: Option<String>,
    pub(crate) json: bool,
}

/// One row as printed with `--json` (and, later, by the API).
#[derive(Debug, Serialize)]
struct JsonRow<'a> {
    time: String,
    ts_us: u64,
    client: String,
    name: &'a str,
    qtype: String,
    status: &'static str,
    rcode: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    list: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<&'static str>,
    total_us: u32,
    upstream_us: u32,
}

fn status_of(s: &str) -> Result<Status, String> {
    Status::ALL
        .into_iter()
        .find(|x| x.label() == s)
        .ok_or_else(|| {
            let all: Vec<&str> = Status::ALL.iter().map(|x| x.label()).collect();
            format!("unknown status `{s}` (one of {})", all.join(", "))
        })
}

fn qtype_text(t: u16) -> String {
    QTYPES
        .iter()
        .find(|(v, _)| *v == t)
        .map_or_else(|| format!("TYPE{t}"), |(_, n)| (*n).to_owned())
}

pub(crate) fn run(
    cfg: &telltale_config::Config,
    a: &Args,
    out: &mut dyn Write,
) -> Result<(), String> {
    let dir = Path::new(cfg.node.data_dir.as_str()).join("qlog");
    let now_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    let name = a.name.clone().map(|n| match a.mode.as_str() {
        "exact" => Ok(NameMatch::Exact(n)),
        "suffix" => Ok(NameMatch::Suffix(n)),
        "glob" => Ok(NameMatch::Glob(n)),
        "regex" => Ok(NameMatch::Regex(n)),
        "" | "substring" => Ok(NameMatch::Substring(n)),
        m => Err(format!("unknown --match `{m}`")),
    });
    let filter = Filter {
        from_us: a
            .since_secs
            .map_or(0, |s| now_us.saturating_sub(s * 1_000_000)),
        to_us: 0,
        name: name.transpose()?,
        client_ip: a.client.map(|ip| match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        }),
        status: a
            .status
            .iter()
            .map(|s| status_of(s))
            .collect::<Result<_, _>>()?,
        qtype: a
            .qtype
            .iter()
            .map(|t| {
                telltale_proto::rtype::from_name(t).ok_or_else(|| format!("unknown type `{t}`"))
            })
            .collect::<Result<_, _>>()?,
        min_total_us: a.min_ms.map(|ms| ms.saturating_mul(1000)),
        ..Filter::default()
    };
    let cursor = match &a.cursor {
        Some(c) => Some(Cursor::decode(c).ok_or("invalid --cursor")?),
        None => None,
    };
    // Up to 4 threads, each at idle priority: on a Pi that also answers DNS, a search only
    // uses CPU the resolver doesn't need (ADR-027).
    let opts = qlog::Options {
        threads: std::thread::available_parallelism().map_or(1, |n| n.get().min(4)),
        on_thread_start: Some(telltale_net::background_thread),
    };
    let page =
        qlog::search_with(&dir, &filter, a.limit, cursor, &opts).map_err(|e| e.to_string())?;
    // List names from the newest snapshot (rows store list IDs).
    let lists: Vec<String> = crate::lists::newest_matcher(cfg)
        .ok()
        .flatten()
        .and_then(|m| {
            m.snapshot()
                .map(|s| s.manifest.lists.iter().map(|l| l.name.clone()).collect())
        })
        .unwrap_or_default();
    let io = |e: std::io::Error| e.to_string();
    for r in &page.rows {
        let row = json_row(r, &lists);
        if a.json {
            let line = serde_json::to_string(&row).map_err(|e| e.to_string())?;
            writeln!(out, "{line}").map_err(io)?;
        } else {
            let why = match (&row.list, row.rule) {
                (Some(l), Some(k)) => format!("  [{k} rule in {l}]"),
                _ => String::new(),
            };
            writeln!(
                out,
                "{}  {:<15} {:<6} {:<40} {:<10} {:>7} µs{why}",
                row.time, row.client, row.qtype, row.name, row.status, row.total_us
            )
            .map_err(io)?;
        }
    }
    let s = page.stats;
    let more = page
        .next
        .map_or_else(String::new, |c| format!("; more: --cursor {}", c.encode()));
    eprintln!(
        "{} rows ({} segments, {} of {} blocks read, {} rows scanned){more}",
        page.rows.len(),
        s.segments,
        s.blocks_read,
        s.blocks_total,
        s.rows_scanned
    );
    Ok(())
}

fn json_row<'a>(r: &'a Row, lists: &[String]) -> JsonRow<'a> {
    JsonRow {
        time: qlog::format_ts(r.ts_us),
        ts_us: r.ts_us,
        client: telltale_telemetry::agg::client_text(r.client_ip),
        name: &r.name,
        qtype: qtype_text(r.qtype),
        status: r.status.label(),
        rcode: r.rcode,
        list: r.rule.map(|x| {
            lists
                .get(usize::from(x.list))
                .cloned()
                .unwrap_or_else(|| format!("#{}", x.list))
        }),
        rule: r
            .rule
            .map(|x| if x.allow { "allow" } else { x.kind.label() }),
        total_us: r.t_total_us,
        upstream_us: r.t_upstream_us,
    }
}
