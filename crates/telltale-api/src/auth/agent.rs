//! Agent principals (REQ: AGT-004, AGT-005, AGT-009; ADR-064).
//!
//! An agent token is an API token with `kind = agent`: fine-grained scopes instead of a role,
//! an optional client-group restriction, and a request rate limit. Agents may use only the
//! routes listed in [`required`] (deny by default), must say why on every change
//! (`X-Telltale-Reason`), and are refused cluster-wide while `[agents] enabled = false`.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, PoisonError};

use axum::http::Method;

use super::Role;
use crate::problem::{Code, Problem};

/// Every scope an agent token can hold, with what it allows.
pub const SCOPES: &[(&str, &str)] = &[
    (
        "analytics:read",
        "statistics, top lists, latency, anomalies, explain, cluster status",
    ),
    (
        "querylog:read",
        "the query log and live tail (who asked for what)",
    ),
    (
        "config:read",
        "lists, groups, devices, upstreams, local names, forwarded domains",
    ),
    (
        "config:write:clients",
        "create, rename, regroup, and delete devices",
    ),
    (
        "config:write:records",
        "add, change, and remove local names",
    ),
    ("config:write:forwards", "send domains to other servers"),
    (
        "config:write:rules",
        "allow or block a domain for some devices or groups (quick rules)",
    ),
    (
        "config:write:upstreams",
        "add, change, and remove upstreams and upstream groups",
    ),
    ("config:write:lists", "add, change, and remove filter lists"),
    (
        "config:write:alerts",
        "add, change, test, and remove alert destinations and rules",
    ),
    (
        "config:write:groups",
        "add, change, and remove client groups",
    ),
    (
        "config:write:ratelimit",
        "change the per-client rate limit, or go back to the config file's",
    ),
    (
        "config:write:exclusions",
        "change which names and devices are kept out of the query log and analytics",
    ),
    (
        "config:write:simulate",
        "change the change-simulation settings (on/off, bounds, plans simulating by default)",
    ),
    ("ops:pause", "pause and resume blocking"),
    ("ops:cache", "flush the cache"),
    (
        "ops:anomalies",
        "acknowledge device anomalies (and take it back)",
    ),
    (
        "ops:maintenance",
        "start and end node maintenance (at most two hours)",
    ),
    ("cluster:admin", "promote a node to primary"),
];

/// What an agent token gets when none are named: read-only, without the query log.
pub const DEFAULT_SCOPES: &[&str] = &["analytics:read", "config:read"];

/// The role a scope needs from the token's owner (a token never exceeds its owner).
fn scope_role(scope: &str) -> Role {
    if scope == "cluster:admin" {
        Role::Admin
    } else if scope.starts_with("config:write:") || scope.starts_with("ops:") {
        Role::Operator
    } else {
        Role::Viewer
    }
}

/// Parses requested scopes: known names only; `config:write:*` means every write area.
pub fn parse_scopes(list: &[String]) -> Result<BTreeSet<String>, Problem> {
    let mut out = BTreeSet::new();
    for s in list {
        let s = s.trim();
        if s == "config:write:*" {
            out.extend(
                SCOPES
                    .iter()
                    .filter(|(n, _)| n.starts_with("config:write:"))
                    .map(|(n, _)| (*n).to_owned()),
            );
        } else if SCOPES.iter().any(|(n, _)| *n == s) {
            out.insert(s.to_owned());
        } else {
            let known: Vec<&str> = SCOPES.iter().map(|(n, _)| *n).collect();
            return Err(Problem::invalid(format!("unknown scope `{s}`"))
                .hint(format!("Scopes: {}.", known.join(", "))));
        }
    }
    if out.is_empty() {
        return Err(Problem::invalid("an agent token needs at least one scope"));
    }
    Ok(out)
}

/// The highest role any of `scopes` needs.
pub fn implied_role(scopes: &BTreeSet<String>) -> Role {
    scopes
        .iter()
        .map(|s| scope_role(s))
        .max()
        .unwrap_or(Role::Viewer)
}

/// What a route needs from an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Any agent (its own identity).
    Any,
    Scope(&'static str),
    /// Not for agents: users, tokens, passwords, backups, the audit log.
    Forbidden,
}

/// The scope an agent needs for `method path` (REQ: AGT-004). Deny by default.
pub fn required(method: &Method, path: &str) -> Need {
    let p = path.trim_end_matches('/');
    let read = *method == Method::GET || *method == Method::HEAD;
    let write = *method == Method::PUT || *method == Method::DELETE;
    let under = |prefix: &str| {
        p.strip_prefix(prefix)
            .is_some_and(|r| r.starts_with('/') && r.len() > 1)
    };
    if read {
        match p {
            "/api/v1/auth/me" | "/api/v1/auth/status" | "/mcp" | "/api/v1/plans" => {
                return Need::Any;
            }
            "/api/v1/system/info"
            | "/api/v1/system/health"
            | "/api/v1/system/probes"
            | "/api/v1/cluster"
            | "/api/v1/explain"
            | "/api/v1/cache/stats"
            | "/api/v1/cache/lookup"
            | "/api/v1/cache/entries"
            | "/api/v1/blocking" => {
                return Need::Scope("analytics:read");
            }
            // REQ: AGT-012 — vqlog reads the query log row by row (by client and name).
            "/api/v1/queries" | "/api/v1/queries/stream" | "/api/v1/analytics/vqlog" => {
                return Need::Scope("querylog:read");
            }
            "/api/v1/lists"
            | "/api/v1/services"
            | "/api/v1/groups"
            | "/api/v1/clients"
            | "/api/v1/upstreams"
            | "/api/v1/records"
            | "/api/v1/zones"
            | "/api/v1/alerts"
            | "/api/v1/forwards"
            | "/api/v1/rules"
            | "/api/v1/config/entries" => {
                return Need::Scope("config:read");
            }
            _ if under("/api/v1/stats") || under("/api/v1/analytics") => {
                return Need::Scope("analytics:read");
            }
            _ => {}
        }
    }
    if write {
        if under("/api/v1/clients") {
            return Need::Scope("config:write:clients");
        }
        if under("/api/v1/records") {
            return Need::Scope("config:write:records");
        }
        if under("/api/v1/forwards") {
            return Need::Scope("config:write:forwards");
        }
        if under("/api/v1/rules") {
            return Need::Scope("config:write:rules");
        }
        // T7.5 (ADR-069)
        if under("/api/v1/upstreams") || under("/api/v1/upstream-groups") {
            return Need::Scope("config:write:upstreams");
        }
        if under("/api/v1/lists") {
            return Need::Scope("config:write:lists");
        }
        // Schedules are group settings (FLT-010, T9.7).
        if under("/api/v1/groups") || under("/api/v1/schedules") {
            return Need::Scope("config:write:groups");
        }
        // REQ: OBS-010 (T9.6)
        if under("/api/v1/alerts") {
            return Need::Scope("config:write:alerts");
        }
        // REQ: DNS-014 (review 01 q1)
        if under("/api/v1/ratelimit") {
            return Need::Scope("config:write:ratelimit");
        }
        // REQ: OBS-022 (T12.1)
        if under("/api/v1/exclusions") {
            return Need::Scope("config:write:exclusions");
        }
        // REQ: OBS-024 (T13.1)
        if under("/api/v1/simulate-settings") {
            return Need::Scope("config:write:simulate");
        }
        // REQ: OPS-010 — ending maintenance (starting it is a POST).
        if *method == Method::DELETE && maintenance_path(p) {
            return Need::Scope("ops:maintenance");
        }
    }
    if *method == Method::POST
        && let Some(need) = post_need(p)
    {
        return need;
    }
    Need::Forbidden
}

/// REQ: OPS-010 — `/api/v1/nodes/{id}/maintenance`.
fn maintenance_path(p: &str) -> bool {
    p.strip_prefix("/api/v1/nodes/")
        .and_then(|r| r.strip_suffix("/maintenance"))
        .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

/// What a `POST` to `p` needs: tests, MCP, and the immediate operations.
fn post_need(p: &str) -> Option<Need> {
    Some(match p {
        // REQ: OPS-010 — maintenance is an immediate op (agents at most two hours).
        _ if maintenance_path(p) => Need::Scope("ops:maintenance"),
        _ if p.starts_with("/api/v1/alerts/destinations/") && p.ends_with("/test") => {
            Need::Scope("config:write:alerts")
        }
        // REQ: API-002 (T9.12) — checks need the scope that saves the entry.
        "/api/v1/checks/upstream" => Need::Scope("config:write:upstreams"),
        "/api/v1/checks/list" => Need::Scope("config:write:lists"),
        // MCP: each tool's REST calls are checked on their own (ADR-065).
        "/mcp" => Need::Any,
        // REQ: AGT-004 (T6.13) — flushing the cache is an immediate low-risk op (spec/13 §3).
        "/api/v1/cache/flush" => Need::Scope("ops:cache"),
        // REQ: AGT-004 (T7.1) — pausing blocking is another (at most 60 minutes).
        "/api/v1/blocking/pause" | "/api/v1/blocking/resume" => Need::Scope("ops:pause"),
        // REQ: OBS-014 — acknowledging anomalies is an immediate, reversible op.
        "/api/v1/analytics/anomalies/acknowledge" | "/api/v1/analytics/anomalies/unacknowledge" => {
            Need::Scope("ops:anomalies")
        }
        "/api/v1/cluster/promote" => Need::Scope("cluster:admin"),
        // REQ: OBS-024 — a simulation reads the query log (and, for a whole configuration,
        // `config:read`: checked by the route).
        "/api/v1/simulate" => Need::Scope("querylog:read"),
        _ => return None,
    })
}

/// Routes a group-restricted agent may use; each of them narrows to the group (ADR-064).
pub fn group_aware(method: &Method, path: &str) -> bool {
    let p = path.trim_end_matches('/');
    let read = *method == Method::GET || *method == Method::HEAD;
    match p {
        "/api/v1/auth/me"
        | "/api/v1/auth/status"
        | "/api/v1/queries"
        | "/api/v1/stats/top"
        | "/api/v1/clients" => read,
        "/mcp" => true,
        _ => {
            (*method == Method::PUT || *method == Method::DELETE)
                && p.strip_prefix("/api/v1/clients/")
                    .is_some_and(|n| !n.is_empty())
        }
    }
}

/// The kill switch and rate limits, updated from `[agents]` on every config change.
#[derive(Debug)]
pub struct Policy {
    enabled: AtomicBool,
    /// REQ: AGT-007 — `[agents] require_approval`: plans wait for an operator.
    require_approval: AtomicBool,
    rate_per_minute: AtomicU32,
    /// Token ID → (requests left, last refill in ms).
    buckets: Mutex<HashMap<String, (f64, u64)>>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            require_approval: AtomicBool::new(false),
            rate_per_minute: AtomicU32::new(120),
            buckets: Mutex::new(HashMap::new()),
        }
    }
}

impl Policy {
    pub fn set(&self, enabled: bool, rate_per_minute: u32) {
        self.enabled.store(enabled, Ordering::Relaxed);
        self.rate_per_minute
            .store(rate_per_minute.max(1), Ordering::Relaxed);
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_require_approval(&self, on: bool) {
        self.require_approval.store(on, Ordering::Relaxed);
    }

    pub fn require_approval(&self) -> bool {
        self.require_approval.load(Ordering::Relaxed)
    }

    /// Takes one request from the token's bucket; `Err(seconds)` to wait when it's empty.
    pub fn take(&self, token: &str, own_rate: Option<u32>, now_ms: u64) -> Result<(), u64> {
        let rate = f64::from(
            own_rate
                .unwrap_or_else(|| self.rate_per_minute.load(Ordering::Relaxed))
                .max(1),
        );
        let mut b = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if b.len() > 10_000 {
            b.clear();
        }
        let (left, last) = b.entry(token.to_owned()).or_insert((rate, now_ms));
        #[allow(clippy::cast_precision_loss)] // milliseconds since the last request
        let refill = now_ms.saturating_sub(*last) as f64 / 60_000.0 * rate;
        *left = (*left + refill).min(rate);
        *last = now_ms;
        if *left >= 1.0 {
            *left -= 1.0;
            Ok(())
        } else {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // small, positive
            let wait = ((1.0 - *left) * 60.0 / rate).ceil() as u64;
            Err(wait.max(1))
        }
    }
}

/// Checks an agent's request (REQ: AGT-004, AGT-009); `Ok` lets it through.
/// `charge_at_ms`: take one request from the token's rate-limit bucket at that time; `None`
/// for the REST calls the MCP server makes for a tool (the `/mcp` request paid).
pub fn check(
    policy: &Policy,
    grant: &super::AgentGrant,
    token_id: &str,
    method: &Method,
    path: &str,
    reason: Option<&str>,
    charge_at_ms: Option<u64>,
) -> Result<(), Problem> {
    if !policy.enabled() {
        return Err(
            Problem::new(Code::Forbidden, "agents are switched off on this cluster")
                .hint("An admin turned them off with [agents] enabled = false."),
        );
    }
    if let Some(now_ms) = charge_at_ms
        && let Err(wait) = policy.take(token_id, grant.rate_per_minute, now_ms)
    {
        return Err(Problem::new(
            Code::RateLimited,
            format!("this agent token is over its request rate; try again in {wait} s"),
        )
        .retry_after(wait));
    }
    match required(method, path) {
        Need::Forbidden => {
            return Err(Problem::new(
                Code::Forbidden,
                format!("agent tokens can't use {method} {path}"),
            )
            .hint("Users, tokens, passwords, backups, and the audit log are for people."));
        }
        Need::Scope(s) if !grant.scopes.contains(s) => {
            return Err(Problem::new(
                Code::Forbidden,
                format!("this needs the `{s}` scope"),
            )
            .hint("Create an agent token with that scope (POST /api/v1/tokens with kind = agent)."));
        }
        Need::Any | Need::Scope(_) => {}
    }
    if let Some(g) = &grant.group
        && !group_aware(method, path)
    {
        return Err(Problem::new(
            Code::Forbidden,
            format!("a token restricted to group `{g}` can't use {method} {path}"),
        )
        .hint("Restricted tokens can read the query log, top lists, and devices, and change devices, for their group."));
    }
    // MCP messages are POSTs, but the tools are read-only (their REST calls are GETs).
    // REQ: OBS-024 — nor does a simulation change anything.
    let changes = !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
        && !matches!(path.trim_end_matches('/'), "/mcp" | "/api/v1/simulate");
    if changes && reason.is_none_or(|r| r.trim().is_empty()) {
        return Err(
            Problem::invalid("agents must say why they change something").hint(
                "Send the reason in the X-Telltale-Reason header; it goes into the audit log.",
            ),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(scopes: &[&str], group: Option<&str>) -> super::super::AgentGrant {
        super::super::AgentGrant {
            token_name: "helper".into(),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            group: group.map(str::to_owned),
            rate_per_minute: None,
            client: None,
        }
    }

    // REQ: AGT-004 — routes map to scopes; everything else is refused (deny by default).
    #[test]
    fn agt_004_scope_map_denies_by_default() {
        use Need::{Any, Forbidden, Scope};
        let g = Method::GET;
        assert_eq!(
            required(&g, "/api/v1/stats/summary"),
            Scope("analytics:read")
        );
        assert_eq!(required(&g, "/api/v1/queries"), Scope("querylog:read"));
        // REQ: AGT-012 — vqlog reads the query log.
        assert_eq!(
            required(&g, "/api/v1/analytics/vqlog"),
            Scope("querylog:read")
        );
        assert_eq!(required(&g, "/api/v1/clients"), Scope("config:read"));
        assert_eq!(
            required(&Method::PUT, "/api/v1/clients/tv"),
            Scope("config:write:clients")
        );
        assert_eq!(
            required(&Method::DELETE, "/api/v1/records/nas.lan"),
            Scope("config:write:records")
        );
        assert_eq!(
            required(&Method::POST, "/api/v1/cluster/promote"),
            Scope("cluster:admin")
        );
        assert_eq!(required(&g, "/api/v1/auth/me"), Any);
        for (m, p) in [
            (Method::GET, "/api/v1/users"),
            (Method::POST, "/api/v1/tokens"),
            (Method::GET, "/api/v1/tokens"),
            (Method::GET, "/api/v1/backup"),
            (Method::GET, "/api/v1/audit"),
            (Method::POST, "/api/v1/auth/password"),
            (Method::PUT, "/api/v1/clients"),
            (Method::GET, "/api/v1/stats"),
            (Method::GET, "/api/v1/something-new"),
        ] {
            assert_eq!(required(&m, p), Forbidden, "{m} {p}");
        }
    }

    /// REQ: AGT-004 (T6.12) — quick rules: reading needs `config:read`, changing needs
    /// `config:write:rules`.
    #[test]
    fn agt_004_quick_rule_routes_need_their_scope() {
        use Need::{Forbidden, Scope};
        assert_eq!(
            required(&Method::GET, "/api/v1/rules"),
            Scope("config:read")
        );
        assert_eq!(
            required(&Method::PUT, "/api/v1/rules/r1"),
            Scope("config:write:rules")
        );
        assert_eq!(
            required(&Method::DELETE, "/api/v1/rules/r1"),
            Scope("config:write:rules")
        );
        assert_eq!(required(&Method::PUT, "/api/v1/rules"), Forbidden);
    }

    /// REQ: AGT-004 (T6.13) — looking at the cache is analytics; flushing needs `ops:cache`.
    #[test]
    fn agt_004_cache_routes_need_their_scope() {
        use Need::Scope;
        assert_eq!(
            required(&Method::GET, "/api/v1/cache/stats"),
            Scope("analytics:read")
        );
        assert_eq!(
            required(&Method::GET, "/api/v1/cache/lookup"),
            Scope("analytics:read")
        );
        assert_eq!(
            required(&Method::POST, "/api/v1/cache/flush"),
            Scope("ops:cache")
        );
        // T7.1 — pausing blocking needs ops:pause; reading it is analytics.
        assert_eq!(
            required(&Method::POST, "/api/v1/blocking/pause"),
            Scope("ops:pause")
        );
        assert_eq!(
            required(&Method::POST, "/api/v1/blocking/resume"),
            Scope("ops:pause")
        );
        assert_eq!(
            required(&Method::GET, "/api/v1/blocking"),
            Scope("analytics:read")
        );
        // T6.15 — the top entries are analytics too.
        assert_eq!(
            required(&Method::GET, "/api/v1/cache/entries"),
            Scope("analytics:read")
        );
    }

    /// REQ: OBS-014, OBS-015, AGT-004 — acknowledging anomalies needs `ops:anomalies`;
    /// reading health and anomalies is analytics.
    #[test]
    fn obs_014_anomaly_and_health_routes_need_their_scope() {
        use Need::{Forbidden, Scope};
        for p in [
            "/api/v1/analytics/anomalies/acknowledge",
            "/api/v1/analytics/anomalies/unacknowledge",
        ] {
            assert_eq!(required(&Method::POST, p), Scope("ops:anomalies"), "{p}");
        }
        assert_eq!(
            required(&Method::GET, "/api/v1/analytics/anomalies"),
            Scope("analytics:read")
        );
        assert_eq!(
            required(&Method::GET, "/api/v1/system/health"),
            Scope("analytics:read")
        );
        assert_eq!(
            required(&Method::POST, "/api/v1/analytics/anomalies"),
            Forbidden
        );
        assert_eq!(
            implied_role(&parse_scopes(&["ops:anomalies".into()]).unwrap()),
            Role::Operator
        );
    }

    /// REQ: OPS-010, AGT-004 — starting and ending maintenance need `ops:maintenance` (an
    /// operator scope); other paths under `/nodes` stay forbidden.
    #[test]
    fn ops_010_maintenance_routes_need_their_scope() {
        use Need::{Forbidden, Scope};
        for m in [Method::POST, Method::DELETE] {
            assert_eq!(
                required(&m, "/api/v1/nodes/local/maintenance"),
                Scope("ops:maintenance"),
                "{m}"
            );
            assert_eq!(
                required(&m, "/api/v1/nodes/pi/maintenance"),
                Scope("ops:maintenance")
            );
        }
        for (m, p) in [
            (Method::PUT, "/api/v1/nodes/pi/maintenance"),
            (Method::POST, "/api/v1/nodes//maintenance"),
            (Method::POST, "/api/v1/nodes/a/b/maintenance"),
            (Method::DELETE, "/api/v1/nodes/pi"),
        ] {
            assert_eq!(required(&m, p), Forbidden, "{m} {p}");
        }
        assert_eq!(
            implied_role(&parse_scopes(&["ops:maintenance".into()]).unwrap()),
            Role::Operator
        );
    }

    /// REQ: OBS-024 — the simulation settings need their own write scope; a simulation needs
    /// the query log.
    #[test]
    fn obs_024_simulation_routes_need_their_scope() {
        use Need::{Forbidden, Scope};
        for m in [Method::PUT, Method::DELETE] {
            assert_eq!(
                required(&m, "/api/v1/simulate-settings/default"),
                Scope("config:write:simulate"),
                "{m}"
            );
        }
        assert_eq!(
            required(&Method::POST, "/api/v1/simulate"),
            Scope("querylog:read")
        );
        assert_eq!(required(&Method::GET, "/api/v1/simulate"), Forbidden);
        assert_eq!(
            implied_role(&parse_scopes(&["config:write:simulate".into()]).unwrap()),
            Role::Operator
        );
    }

    #[test]
    fn agt_004_scopes_parse_and_imply_roles() {
        let s = parse_scopes(&["config:write:*".into(), "analytics:read".into()]).unwrap();
        assert_eq!(
            s.len(),
            12,
            "eleven write areas (clients, records, forwards, rules, upstreams, lists, groups, alerts, ratelimit, exclusions, simulate) + analytics"
        );
        assert!(s.contains("config:write:upstreams") && s.contains("config:write:lists"));
        assert!(s.contains("config:write:rules"));
        assert_eq!(implied_role(&s), Role::Operator);
        assert_eq!(
            implied_role(&parse_scopes(&["cluster:admin".into()]).unwrap()),
            Role::Admin
        );
        assert!(parse_scopes(&["root".into()]).is_err());
        assert!(parse_scopes(&[]).is_err());
    }

    // REQ: AGT-009 — the kill switch, rate limits, required reasons, group restriction.
    #[test]
    fn agt_009_guardrails() {
        let p = Policy::default();
        let g = grant(&["analytics:read", "config:write:clients"], None);
        let get = |path: &str| check(&p, &g, "t1", &Method::GET, path, None, Some(0));
        assert!(get("/api/v1/stats/summary").is_ok());
        assert!(get("/api/v1/queries").is_err(), "no querylog:read");
        assert!(
            check(
                &p,
                &g,
                "t1",
                &Method::PUT,
                "/api/v1/clients/tv",
                None,
                Some(0)
            )
            .is_err(),
            "no reason"
        );
        assert!(
            check(
                &p,
                &g,
                "t1",
                &Method::PUT,
                "/api/v1/clients/tv",
                Some("rename the TV"),
                Some(0)
            )
            .is_ok()
        );
        p.set(false, 120);
        assert!(get("/api/v1/stats/summary").is_err(), "switched off");
        p.set(true, 2);
        let fresh = grant(&["analytics:read"], None);
        let charged = |at: Option<u64>| {
            check(
                &p,
                &fresh,
                "t2",
                &Method::GET,
                "/api/v1/stats/summary",
                None,
                at,
            )
        };
        let r = |ms| charged(Some(ms));
        assert!(r(0).is_ok() && r(0).is_ok());
        assert!(r(0).is_err(), "over 2 per minute");
        // The REST calls behind an MCP tool call don't take from the bucket (review 06-04).
        assert!(charged(None).is_ok(), "in-process calls aren't charged");
        assert!(r(30_000).is_ok(), "refilled after 30 s");
        let restricted = grant(&["querylog:read", "analytics:read"], Some("kids"));
        let rr = |path: &str| {
            check(
                &Policy::default(),
                &restricted,
                "t3",
                &Method::GET,
                path,
                None,
                Some(0),
            )
        };
        assert!(rr("/api/v1/queries").is_ok());
        assert!(rr("/api/v1/stats/summary").is_err(), "no group view");
        assert!(
            rr("/api/v1/analytics/vqlog").is_err(),
            "vqlog has no group view"
        );
    }
}
