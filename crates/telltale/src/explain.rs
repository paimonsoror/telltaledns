//! Explain (FLT-013): why a name is or isn't blocked for a client, and where it would go.
//!
//! Walks the query pipeline's stages (`spec/03` §3) with the pipeline's own helpers, on a
//! real parsed query, so the explanation can't drift from what the server does. Used by
//! `telltale explain`; from M3 also by `GET /api/v1/explain` and the `explain_decision` MCP
//! tool (`spec/05` §5, `spec/13`).

use std::net::IpAddr;

use serde::Serialize;
use telltale_config::BlockMode;
use telltale_filter::explain::{Explained, explain as explain_rules};
use telltale_filter::matcher::{ClientCtx, Tier};
use telltale_policy::{ClientTable, IdSource, Neighbors, Pause, Special};
use telltale_proto::{NameBuf, build_query, class, parse_query};
use telltale_upstream::Question;

use crate::pipeline::{Dynamic, FilterState, unix_now};

/// What to explain.
#[derive(Debug, Clone)]
pub(crate) struct Request<'a> {
    pub(crate) name: &'a str,
    pub(crate) qtype: u16,
    pub(crate) client: IpAddr,
    /// The device's MAC, as the neighbor table would report it.
    pub(crate) mac: Option<[u8; 6]>,
    /// A DoH/DoT client ID.
    pub(crate) client_id: Option<&'a str>,
}

/// What the server would do with the query, and why.
#[derive(Debug, Serialize)]
pub(crate) struct Explanation {
    pub(crate) name: String,
    pub(crate) qtype: u16,
    pub(crate) client: ClientInfo,
    pub(crate) outcome: Outcome,
    /// One sentence for people.
    pub(crate) summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) block: Option<BlockInfo>,
    /// Blocking is paused for this client until this time (unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) paused_until: Option<u64>,
    /// Every matching rule, in precedence order. `None` until a filter snapshot is loaded.
    pub(crate) filter: Option<Explained>,
    /// The upstream group a forwarded query goes to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) route: Option<RouteInfo>,
    pub(crate) notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    /// The client is outside `allowed_networks`.
    Refused,
    /// ANY, or a special-use name (`spec/04` §6) answered without forwarding.
    Special,
    /// Answered from local records (DNS-010).
    Local,
    /// A block rule wins.
    Blocked,
    /// An allow rule wins; resolved normally.
    Allowed,
    /// No rule applies (or blocking is paused); resolved normally.
    Resolved,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClientInfo {
    pub(crate) ip: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mac: Option<String>,
    /// The configured client it was recognized as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) device: Option<String>,
    pub(crate) identified_by: &'static str,
    /// Highest priority first; the first one's settings apply.
    pub(crate) groups: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BlockInfo {
    pub(crate) list: String,
    pub(crate) mode: BlockMode,
    pub(crate) ttl: u32,
    pub(crate) ede_code: u16,
}

#[derive(Debug, Serialize)]
pub(crate) struct RouteInfo {
    pub(crate) group: String,
    /// An explicit `[[route]]` matched (not just the default group).
    pub(crate) routed: bool,
}

fn source_name(s: IdSource) -> &'static str {
    match s {
        IdSource::ClientId => "client_id",
        IdSource::EdnsMac => "edns_mac",
        IdSource::NeighborMac => "neighbor_mac",
        IdSource::Ip => "ip",
        IdSource::Cidr => "cidr",
        IdSource::Default => "default",
    }
}

fn mac_text(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// The pipeline state an explanation reads.
pub(crate) struct State<'a> {
    pub(crate) dynamic: &'a Dynamic,
    pub(crate) filter: Option<&'a FilterState>,
    pub(crate) neighbors: &'a Neighbors,
    pub(crate) pause: &'a Pause,
}

/// Explains `req` against `st`, reading list sources through `source(list name)`.
// REQ: FLT-013
pub(crate) fn explain(
    st: &State<'_>,
    req: &Request<'_>,
    source: impl Fn(&str) -> Option<Vec<u8>>,
) -> Result<Explanation, String> {
    let name = NameBuf::from_presentation(req.name).map_err(|e| format!("name: {e}"))?;
    let mut buf = [0u8; 512];
    let len = build_query(&mut buf, 0, &name, req.qtype, class::IN, true, None)
        .map_err(|_| "name too long".to_owned())?;
    let q =
        parse_query(&buf[..len]).map_err(|_| "cannot build a query for this name".to_owned())?;
    let policy = &st.dynamic.policy;
    // The filter's client table is the one its masks were built for (they match after a
    // reload; before the first snapshot only the policy's exists).
    let clients: &ClientTable = st.filter.map_or(&policy.clients, |f| &f.clients);
    let given;
    let neighbors = match req.mac {
        Some(mac) => {
            given = Neighbors::default();
            given.replace([(req.client, mac)]);
            &given
        }
        None => st.neighbors,
    };
    let ident = clients.identify(req.client, req.client_id, None, neighbors);
    let device = clients.client(ident).map(|c| c.name.to_string());
    let mut e = Explanation {
        name: q.qname.display().to_string(),
        qtype: req.qtype,
        client: ClientInfo {
            ip: req.client,
            mac: req.mac.or_else(|| neighbors.get(req.client)).map(mac_text),
            device: device.clone(),
            identified_by: source_name(ident.source),
            groups: clients
                .group_names(ident)
                .iter()
                .map(ToString::to_string)
                .collect(),
        },
        outcome: Outcome::Resolved,
        summary: String::new(),
        block: None,
        paused_until: None,
        filter: None,
        route: None,
        notes: Vec::new(),
    };

    let special = match answered_early(policy, &q, req.client) {
        Ok(special) => special,
        Err((outcome, summary)) => {
            e.outcome = outcome;
            e.summary = summary;
            return Ok(e);
        }
    };

    // Step 6: the filter.
    let group = clients.primary_group(ident);
    let mut winner = None;
    match st.filter {
        Some(f) => {
            let ctx = ClientCtx {
                ip: req.client,
                name: device.as_deref(),
                client_id: req.client_id,
            };
            let wire = q.qname.as_wire();
            let matches = f.matcher.matches(wire, q.qtype, &ctx, f.mask(ident));
            let explained = explain_rules(&f.matcher, wire, &matches, source);
            winner = explained
                .rules
                .iter()
                .find(|r| r.winner)
                .map(|r| (r.tier, r.list.clone()));
            e.filter = Some(explained);
        }
        None => e
            .notes
            .push("no filter snapshot is loaded yet, so nothing is blocked".into()),
    }
    if decide(&mut e, winner, group, st.pause) {
        return Ok(e);
    }

    // Step 7+: where a forwarded query goes.
    let groups = clients.group_names(ident);
    let selection = st.dynamic.router.select(&Question::from_query(&q), groups);
    // Same rules as the pipeline's `resolve_or_defer`.
    if special == Some(Special::PrivatePtr) && !selection.as_ref().is_some_and(|s| s.routed) {
        e.outcome = Outcome::Special;
        e.summary = "private reverse lookup with no [[route]] for it: NXDOMAIN without forwarding (RFC 6303)".into();
    } else if let Some(sel) = selection {
        e.route = Some(RouteInfo {
            group: sel.group.name.clone(),
            routed: sel.routed,
        });
    } else {
        e.notes
            .push("no upstream group serves this query: answered REFUSED".into());
    }
    if st.filter.is_some() {
        e.notes.push(
            "CNAME targets in the upstream answer are checked too (FLT-007); explain a target name to see its rules"
                .into(),
        );
    }
    Ok(e)
}

/// `spec/03` §3 steps 2–5 (access, ANY, special names, local records): the outcome if one
/// of them answers, else the special-name class to continue with. Rate limiting depends on
/// the moment, not the name, so it isn't explained.
fn answered_early(
    policy: &crate::pipeline::Policy,
    q: &telltale_proto::Query<'_>,
    client: IpAddr,
) -> Result<Option<Special>, (Outcome, String)> {
    if !telltale_policy::is_allowed(&policy.allowed, client) {
        return Err((
            Outcome::Refused,
            format!("{client} is outside allowed_networks: REFUSED"),
        ));
    }
    if q.is_any() {
        return Err((
            Outcome::Special,
            "ANY queries get the minimal RFC 8482 answer".into(),
        ));
    }
    let special = telltale_policy::classify(q, &policy.special);
    let text = match special {
        Some(Special::Refused) => "special-use query: REFUSED without forwarding",
        Some(Special::Nxdomain) => "special-use name: NXDOMAIN without forwarding",
        Some(Special::Localhost) => "localhost: answered with loopback addresses",
        _ => {
            // Local records are authoritative.
            let mut out = [0u8; 4096];
            if policy.local.answer(q, &mut out, None).is_some() {
                return Err((Outcome::Local, "answered from local records".into()));
            }
            return Ok(special);
        }
    };
    Err((Outcome::Special, text.into()))
}

/// Sets the outcome from the winning rule and any pause. True if the query is blocked.
fn decide(
    e: &mut Explanation,
    winner: Option<(Tier, String)>,
    group: &telltale_policy::Group,
    pause: &Pause,
) -> bool {
    let now = unix_now();
    if pause.is_paused(&group.name, || now) {
        e.paused_until = pause
            .active(now)
            .into_iter()
            .filter(|(g, _)| g.as_deref().is_none_or(|g| *g == *group.name))
            .map(|(_, until)| until)
            .max();
    }
    match (winner, e.paused_until) {
        (Some((Tier::ImportantBlock | Tier::Block, list)), None) => {
            e.outcome = Outcome::Blocked;
            e.summary = format!(
                "blocked by list {list} for group {}: answered {}",
                group.name,
                block_answer_text(group.block.mode)
            );
            e.block = Some(BlockInfo {
                list,
                mode: group.block.mode,
                ttl: group.block.ttl,
                ede_code: group.block.ede_code,
            });
            return true;
        }
        (Some((_, list)), None) => {
            e.outcome = Outcome::Allowed;
            e.summary = format!("allowed by list {list}; resolved normally");
        }
        (Some(_), Some(_)) => {
            e.summary = format!(
                "a rule matches, but blocking is paused for group {}; resolved normally",
                group.name
            );
        }
        (None, _) => {
            e.summary = "no rule applies; resolved normally".into();
        }
    }
    false
}
fn block_answer_text(mode: BlockMode) -> &'static str {
    match mode {
        BlockMode::NullIp => "0.0.0.0 / ::",
        BlockMode::Nxdomain => "NXDOMAIN",
        BlockMode::Nodata => "NODATA",
        BlockMode::Refused => "REFUSED",
        BlockMode::CustomIp => "the group's block_ips",
    }
}

/// `telltale explain`: explains a query offline, from the config and the data directory
/// (newest snapshot, stored list sources, and the kernel neighbor table).
pub(crate) fn run_cli(
    cfg: &telltale_config::Config,
    req: &Request<'_>,
    qtype_text: &str,
    json: bool,
    out: &mut dyn std::io::Write,
) -> Result<(), String> {
    let (router, policy) = crate::server::build_dynamic(cfg, None).map_err(|e| e.join("; "))?;
    let uses_macs = policy.clients.uses_macs();
    let pipeline = crate::pipeline::Pipeline::new(
        crate::pipeline::Settings::default(),
        std::sync::Arc::new(telltale_cache::Cache::new(
            telltale_cache::CachePolicy::default(),
        )),
        router,
        policy,
    );
    let matcher = crate::lists::newest_matcher(cfg)?;
    let snapshot_loaded = matcher.is_some();
    if let Some(m) = matcher {
        pipeline.set_filter(Some(std::sync::Arc::new(m)));
    }
    if uses_macs
        && req.mac.is_none()
        && let Ok(n) = telltale_net::neighbors()
    {
        pipeline
            .neighbors
            .replace(n.into_iter().map(|x| (x.ip, x.mac)));
    }
    let mut e = pipeline.explain(req, crate::lists::source_reader(cfg))?;
    if !snapshot_loaded && !cfg.list.is_empty() {
        e.notes.push(
            "no snapshot in the data directory: run `telltale lists fetch` and `telltale lists compile`, or start the server"
                .into(),
        );
    }
    let io = |err: std::io::Error| err.to_string();
    if json {
        let text = serde_json::to_string_pretty(&e).map_err(|err| err.to_string())?;
        return writeln!(out, "{text}").map_err(io);
    }
    render(&e, qtype_text, out).map_err(io)
}

fn tier_text(t: Tier) -> &'static str {
    match t {
        Tier::ImportantAllow => "allow!",
        Tier::ImportantBlock => "block!",
        Tier::Allow => "allow",
        Tier::Block => "block",
    }
}

/// Human-readable form of an explanation.
fn render(e: &Explanation, qtype: &str, out: &mut dyn std::io::Write) -> std::io::Result<()> {
    writeln!(
        out,
        "{} {} from {}",
        e.name,
        qtype.to_ascii_uppercase(),
        e.client.ip
    )?;
    let who = match (&e.client.device, &e.client.mac) {
        (Some(d), Some(m)) => format!("{d} ({m}, identified by {})", e.client.identified_by),
        (Some(d), None) => format!("{d} (identified by {})", e.client.identified_by),
        (None, _) => "unknown device".to_owned(),
    };
    writeln!(
        out,
        "client   {who}; groups: {}",
        e.client.groups.join(", ")
    )?;
    let outcome = match e.outcome {
        Outcome::Refused => "REFUSED",
        Outcome::Special => "SPECIAL",
        Outcome::Local => "LOCAL",
        Outcome::Blocked => "BLOCKED",
        Outcome::Allowed => "ALLOWED",
        Outcome::Resolved => "RESOLVED",
    };
    writeln!(out, "outcome  {outcome}: {}", e.summary)?;
    if let Some(until) = e.paused_until {
        writeln!(
            out,
            "paused   blocking paused for {} more seconds",
            until.saturating_sub(unix_now())
        )?;
    }
    if let Some(f) = &e.filter {
        match (f.snapshot, f.rules.is_empty()) {
            (Some(v), true) => writeln!(out, "rules    none match (snapshot {v})")?,
            (v, false) => {
                let v = v.map_or_else(String::new, |v| format!("snapshot {v}, "));
                writeln!(
                    out,
                    "rules    {v}in precedence order (* decides, - list not used by this client)"
                )?;
                for r in &f.rules {
                    let mark = if r.winner {
                        "*"
                    } else if r.enabled {
                        " "
                    } else {
                        "-"
                    };
                    let what = match (&r.name, r.scope) {
                        (Some(n), Some(s)) => format!("{n} ({})", scope_text(s)),
                        (None, Some(s)) => format!("modifier rule ({})", scope_text(s)),
                        _ => "regex".to_owned(),
                    };
                    writeln!(
                        out,
                        "  {mark} {:<6} {:<20} {what}",
                        tier_text(r.tier),
                        r.list
                    )?;
                    for l in &r.lines {
                        writeln!(out, "             {}:{}  {}", r.list, l.line, l.text)?;
                    }
                }
            }
            (None, true) => {}
        }
    }
    if let Some(r) = &e.route {
        let how = if r.routed { "by [[route]]" } else { "default" };
        writeln!(out, "route    upstream group {} ({how})", r.group)?;
    }
    for n in &e.notes {
        writeln!(out, "note     {n}")?;
    }
    Ok(())
}

fn scope_text(s: telltale_filter::parse::Scope) -> &'static str {
    match s {
        telltale_filter::parse::Scope::Subtree => "and subdomains",
        telltale_filter::parse::Scope::Exact => "exact",
        telltale_filter::parse::Scope::Subdomains => "subdomains only",
    }
}

#[cfg(test)]
mod tests;
