//! Router integrations (REQ: API-010 naming sources, M8 "router integrations"; T8.2): device
//! names and addresses read from the router's DHCP, so devices show up by name without
//! TelltaleDNS running DHCP itself.
//! - **UniFi** (UniFi OS consoles: UDM, UCG, Cloud Key Gen2+; and the classic Network
//!   application): the active clients (`stat/sta`), then the offline clients it still knows
//!   (v2 `clients/history`, `rest/user`), named by their UniFi alias, else their host name.
//!   An API key (`X-API-KEY`), or a local username and password.
//! - **OPNsense**: the DHCP leases (Dnsmasq, Kea, or ISC, whichever the box runs), with an
//!   API key and secret.
//! - **FRITZ!Box** (config file only): the TR-064 Hosts entries in `client_subnets`; read by
//!   full cluster members, not resolver pods.
//!
//! Polled every `interval_secs`; the result replaces that router's part of the lease view
//! the naming falls back to (after configured device names and TelltaleDNS's own DHCP).
//! Never on the DNS path; a router that's down keeps its last answer and is logged.

mod fritzbox;

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use serde_json::Value;
use telltale_config::{RouterConfig, RouterKind};
use tracing::{debug, info, warn};

use crate::devices::{Lease, Leases};

/// How often the routers in effect are compared with the ones last read (ADR-181).
const CHANGE_CHECK: Duration = Duration::from_secs(5);

/// Most bytes one answer may have.
const MAX_ANSWER: u64 = 16 << 20;

/// What a router reported, one entry per device.
pub(crate) type Seen = Vec<Device>;

/// One device a router reported: (MAC, IPv4 address, name).
pub(crate) type Device = (String, Ipv4Addr, Option<String>);

/// REQ: T8.2 (ADR-166) — most offline clients one UniFi poll keeps (most recently seen first),
/// whatever `offline_days` says: they ride in every node's answer to `devices.names` (about
/// 130 bytes each, against the cluster channel's 1 MiB frame) and sit in memory on every node.
pub(crate) const OFFLINE_MAX: usize = 1024;

/// What one poll of a router found: the devices it reports now, and (UniFi) the offline clients
/// it remembers, kept apart because only the first are "seen" (ADR-166).
pub(crate) struct Polled {
    pub(crate) now: Seen,
    pub(crate) offline: Seen,
    /// REQ: FLT-006 (ADR-183) — UniFi: the MACs of connected clients whose address isn't
    /// `ip` (UniFi gave `last_ip` or `fixed_ip`): the client is connected, but where it is now
    /// isn't known, so that address can't identify a device. Empty for other routers.
    pub(crate) not_current: HashSet<String>,
}

impl Polled {
    /// A router that only reports what it has now (OPNsense).
    fn now(now: Seen) -> Self {
        Self {
            now,
            offline: Seen::new(),
            not_current: HashSet::new(),
        }
    }
}

/// REQ: FLT-006 (ADR-183) — a router that hasn't answered for more than this many seconds
/// (on the node's monotonic clock) has its bindings marked `unsure`: its last answer may no
/// longer say who holds an address.
pub(crate) const STALE_AFTER_S: u64 = 900;

/// REQ: FLT-006 (ADR-183) — the longest a router that feeds identification waits between reads,
/// in seconds: 10 minutes, so what an answer says is never more than about that old when the next
/// one replaces it (silence alone doesn't bound the age of an answer from a router read once an
/// hour), and a read that fails (asked again every 15 s) has the rest of the 15 minutes of
/// [`STALE_AFTER_S`] to succeed before the router counts as silent and every address it gave is
/// withheld on this node and on the members.
pub(crate) const IDENTIFY_POLL_MAX_S: u32 = 600;

/// REQ: FLT-006 (ADR-183) — how long to wait before reading the routers again: `interval` (the
/// shortest `interval_secs`, at least 30), or 15 s while one is failing, and, while the routers
/// feed identification (`identifies`: a device is named by its MAC and `router_macs` is on), at
/// most [`IDENTIFY_POLL_MAX_S`].
pub(crate) fn next_poll_secs(failing: bool, interval: u32, identifies: bool) -> u32 {
    let base = if failing { interval.min(15) } else { interval };
    if identifies {
        base.min(IDENTIFY_POLL_MAX_S)
    } else {
        base
    }
}

/// REQ: FLT-006 (ADR-183) — whether this node's routers feed identification now: a device is
/// named by its MAC and `[clients] router_macs` is on.
fn feeds_identification(sources: &crate::http::Sources) -> bool {
    let state = sources.pipeline.current();
    state.policy.clients.router_macs() && state.policy.clients.uses_macs()
}

/// REQ: FLT-006 (ADR-183) — the routers silent for more than [`STALE_AFTER_S`] seconds at `now`,
/// given when each last answered (both on the monotonic clock, in seconds). Saturating: a
/// `last` after `now` is not stale, and never panics.
pub(crate) fn stale_routers(last_ok: &HashMap<String, u64>, now: u64) -> HashSet<String> {
    last_ok
        .iter()
        .filter(|(_, last)| now.saturating_sub(**last) > STALE_AFTER_S)
        .map(|(name, _)| name.clone())
        .collect()
}

fn secret(path: Option<&telltale_config::SafeString>) -> Result<Option<String>, String> {
    path.map(|p| {
        std::fs::read_to_string(p.as_str())
            .map(|s| s.trim().to_owned())
            .map_err(|e| {
                // REQ: T8.2 (ADR-181) — after a restore elsewhere or a failover the key isn't
                // on this node: say so, and what puts it back for either kind of router.
                if e.kind() == std::io::ErrorKind::NotFound {
                    format!(
                        "{}: the key file isn't on this node (put the file there; for a router made in the UI, enter the key again on the node that takes configuration changes)",
                        p.as_str()
                    )
                } else {
                    format!("{}: {e}", p.as_str())
                }
            })
    })
    .transpose()
}

/// REQ: API-002, T8.2 (ADR-181) — the routers this node holds back (a key file it won't send for
/// them), by name, with why: each is logged when it is first held or its reason changes, not at
/// every round. Returns the ones to log.
fn held_now(
    held: &mut HashMap<String, String>,
    now: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let fresh: Vec<(String, String)> = now
        .iter()
        .filter(|(n, why)| held.get(n) != Some(why))
        .cloned()
        .collect();
    *held = now.into_iter().collect();
    fresh
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(
                    T[usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0)],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// One HTTP exchange; the JSON body and the response headers.
async fn call(
    client: &telltale_filter::fetch::Client,
    req: http::Request<Vec<u8>>,
) -> Result<(http::StatusCode, http::HeaderMap, Value), String> {
    let url = req.uri().to_string();
    let resp = tokio::time::timeout(Duration::from_secs(15), client.request(req, MAX_ANSWER))
        .await
        .map_err(|_| format!("{url}: timed out"))?
        .map_err(|e| format!("{url}: {}", e.message))?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body();
    let v = serde_json::from_slice(&body).unwrap_or(Value::Null);
    Ok((status, headers, v))
}

/// The `name=value` pairs of every `Set-Cookie`.
fn cookies(h: &http::HeaderMap) -> String {
    h.get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|c| c.split(';').next())
        .collect::<Vec<_>>()
        .join("; ")
}

/// The client objects of a UniFi answer: `data` in the classic API, a bare array in v2.
fn unifi_rows(v: &Value) -> &[Value] {
    v.get("data")
        .and_then(Value::as_array)
        .or_else(|| v.as_array())
        .map_or(&[], Vec::as_slice)
}

/// One UniFi client object: its MAC, IPv4 address (current, else last, else reserved), and
/// name (the UniFi alias, else the host name).
fn unifi_client(c: &Value) -> Option<Device> {
    let mac = c.get("mac")?.as_str()?.to_ascii_lowercase();
    // A `fixed_ip` counts only while the reservation is on (`use_fixedip`); UniFi keeps the
    // field after it's turned off.
    let fixed = c
        .get("use_fixedip")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let ip: Ipv4Addr = ["ip", "last_ip", "fixed_ip"]
        .iter()
        .filter(|k| **k != "fixed_ip" || fixed)
        .filter_map(|k| c.get(*k).and_then(Value::as_str))
        .find_map(|s| s.parse().ok())?;
    let name = ["name", "hostname"]
        .iter()
        .filter_map(|k| c.get(*k).and_then(Value::as_str))
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_owned);
    Some((mac, ip, name))
}

/// UniFi clients in a `stat/sta` (or `rest/user`) answer.
pub(crate) fn unifi_clients(v: &Value) -> Seen {
    unifi_rows(v).iter().filter_map(unifi_client).collect()
}

/// UniFi's known clients that aren't connected now (v2 `clients/history`, `rest/user`): only
/// those with a name, the most recently seen first, at most [`OFFLINE_MAX`]. REQ: T8.2
/// (ADR-166): a row last seen before `not_before` (Unix seconds) is dropped; one with no date
/// can't be judged and stays (the cap bounds those).
pub(crate) fn unifi_known(v: &Value, not_before: u64) -> Seen {
    let mut rows: Vec<(u64, Device)> = unifi_rows(v)
        .iter()
        .filter_map(|c| {
            let seen = c.get("last_seen").and_then(Value::as_u64);
            if seen.is_some_and(|t| t < not_before) {
                return None;
            }
            let client = unifi_client(c)?;
            client.2.is_some().then_some((seen.unwrap_or(0), client))
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.0));
    rows.truncate(OFFLINE_MAX);
    rows.into_iter().map(|(_, c)| c).collect()
}

/// REQ: T8.2 — the connected clients, then the known ones UniFi has names for, so an offline
/// device's queries still show its name. A connected client keeps its address; a known one
/// only names it when it has none, and adds a device only for an address no one else holds
/// (an offline device's last address may since have gone to another one), and for at most
/// [`OFFLINE_MAX`] devices.
pub(crate) fn unifi_merge(mut active: Seen, known: Seen) -> Seen {
    let mut macs: HashMap<String, usize> = active
        .iter()
        .enumerate()
        .map(|(i, c)| (c.0.clone(), i))
        .collect();
    let mut ips: std::collections::HashSet<Ipv4Addr> = active.iter().map(|c| c.1).collect();
    let mut added = 0;
    for (mac, ip, name) in known {
        if let Some(&i) = macs.get(&mac) {
            if let Some(c) = active.get_mut(i)
                && c.2.is_none()
            {
                c.2 = name;
            }
            continue;
        }
        if added >= OFFLINE_MAX || !ips.insert(ip) {
            continue;
        }
        macs.insert(mac.clone(), active.len());
        active.push((mac, ip, name));
        added += 1;
    }
    active
}

/// REQ: T8.2 (ADR-166) — [`unifi_merge`], with the offline devices it appended (after the
/// connected ones, which keep their order) set apart.
pub(crate) fn unifi_split(active: Seen, known: Seen) -> Polled {
    let connected = active.len();
    let mut now = unifi_merge(active, known);
    let offline = now.split_off(connected);
    Polled {
        now,
        offline,
        not_current: HashSet::new(),
    }
}

/// REQ: FLT-006 (ADR-183) — the MACs (lower case) of the clients in a `stat/sta` answer that have
/// no current IPv4 address: a row with a `mac` whose `ip` is missing or isn't an IPv4 address.
/// [`unifi_client`] still gives such a client the address from `last_ip` (or a reservation), which
/// is where it was, not necessarily where it is, so it can name that address but not identify
/// a device there.
pub(crate) fn unifi_not_current(v: &Value) -> HashSet<String> {
    unifi_rows(v)
        .iter()
        .filter_map(|c| {
            let mac = c.get("mac")?.as_str()?.to_ascii_lowercase();
            let current = c
                .get("ip")
                .and_then(Value::as_str)
                .is_some_and(|s| s.parse::<Ipv4Addr>().is_ok());
            (!current).then_some(mac)
        })
        .collect()
}

/// OPNsense leases in a search answer (Dnsmasq, Kea, or ISC field names).
pub(crate) fn opnsense_leases(v: &Value) -> Seen {
    let Some(rows) = v.get("rows").and_then(Value::as_array) else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|r| {
            let ip: Ipv4Addr = r.get("address")?.as_str()?.parse().ok()?;
            let mac = r
                .get("mac")
                .or_else(|| r.get("hwaddr"))?
                .as_str()?
                .to_ascii_lowercase();
            let name = ["hostname", "client_hostname", "descr"]
                .iter()
                .filter_map(|k| r.get(*k).and_then(Value::as_str))
                .map(str::trim)
                .find(|s| !s.is_empty() && *s != "*")
                .map(str::to_owned);
            Some((mac, ip, name))
        })
        .collect()
}

/// `s` as one path segment: every byte but the unreserved ones (letters, digits, `-._~`)
/// percent-encoded.
fn path_segment(s: &str) -> String {
    s.bytes().fold(String::new(), |mut out, b| {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("%{b:02X}"));
        }
        out
    })
}

/// How to reach a UniFi Network API once signed in: the path prefix (`/proxy/network` on
/// UniFi OS consoles) and the header that authenticates (`x-api-key`, or the login cookie).
struct UnifiSession<'a> {
    base: &'a str,
    site: &'a str,
    prefix: &'static str,
    auth: (&'static str, String),
    /// `offline_days` of the router's settings (0: connected clients only).
    offline_days: u32,
}

impl UnifiSession<'_> {
    /// `GET` one path under the site; the JSON answer, or why not.
    async fn get(
        &self,
        client: &telltale_filter::fetch::Client,
        path: &str,
    ) -> Result<Value, String> {
        // REQ: T8.2 (ADR-181) — security F6: the site goes into the path template only, as one
        // percent-encoded segment, never into the address.
        let url = format!(
            "{}{}{}",
            self.base,
            self.prefix,
            path.replace("{site}", &path_segment(self.site))
        );
        let req = http::Request::get(url.as_str())
            .header(self.auth.0, self.auth.1.as_str())
            .header("accept", "application/json")
            .body(Vec::new())
            .map_err(|e| e.to_string())?;
        let (status, _, v) = call(client, req).await?;
        if status.is_success() {
            Ok(v)
        } else {
            Err(format!("{url}: HTTP {status}"))
        }
    }

    /// The connected clients (`stat/sta`), then the known clients that are offline and were seen
    /// within `offline_days`, so their names still show (none when it's 0). The known clients
    /// are best effort: a console that can't list them (an older Network application has no v2
    /// API) gives just the connected ones.
    async fn clients(&self, client: &telltale_filter::fetch::Client) -> Result<Polled, String> {
        let sta = self.get(client, "/api/s/{site}/stat/sta").await?;
        let active = unifi_clients(&sta);
        // REQ: FLT-006 (ADR-183) — which of them have no current address.
        let not_current = unifi_not_current(&sta);
        if self.offline_days == 0 {
            return Ok(Polled {
                not_current,
                ..Polled::now(active)
            });
        }
        // REQ: T8.2 (ADR-166) — the window goes to the console (it filters the history before
        // answering) and is applied to every row that has a date.
        let days = u64::from(self.offline_days);
        let not_before = crate::pipeline::unix_now().saturating_sub(days * 86_400);
        let mut known = Seen::new();
        for path in [
            // The clients the console remembers within the window, with their last address
            // (Network 7+).
            format!(
                "/v2/api/site/{{site}}/clients/history?onlyNonBlocked=true&includeUnifiDevices=false&withinHours={}",
                days * 24
            ),
            // The configured clients: aliases and fixed addresses.
            "/api/s/{site}/rest/user".to_owned(),
        ] {
            match self.get(client, &path).await {
                Ok(v) => known.extend(unifi_known(&v, not_before)),
                Err(e) => debug!(error = %e, "router integration: UniFi known clients"),
            }
        }
        Ok(Polled {
            not_current,
            ..unifi_split(active, known)
        })
    }
}

/// One poll of a UniFi console or Network application.
async fn poll_unifi(
    client: &telltale_filter::fetch::Client,
    c: &RouterConfig,
) -> Result<Polled, String> {
    let base = c.url.trim_end_matches('/');
    let site = c.site.as_deref().unwrap_or("default");
    if let Some(key) = secret(c.api_key_file.as_ref())? {
        let s = UnifiSession {
            base,
            site,
            prefix: "/proxy/network",
            auth: ("x-api-key", key),
            offline_days: c.offline_days,
        };
        return s.clients(client).await;
    }
    let user = c
        .username
        .as_deref()
        .ok_or("set api_key_file, or username and password_file")?;
    let pass = secret(c.password_file.as_ref())?.ok_or("set password_file")?;
    let body =
        serde_json::json!({"username": user, "password": pass, "remember": false}).to_string();
    // UniFi OS consoles first, then the classic Network application.
    for (login, prefix) in [("/api/auth/login", "/proxy/network"), ("/api/login", "")] {
        let req = http::Request::post(format!("{base}{login}"))
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .body(body.clone().into_bytes())
            .map_err(|e| e.to_string())?;
        let (status, headers, _) = call(client, req).await?;
        if status == http::StatusCode::NOT_FOUND {
            continue;
        }
        if !status.is_success() {
            return Err(format!(
                "{base}{login}: HTTP {status} (check the username and password)"
            ));
        }
        let s = UnifiSession {
            base,
            site,
            prefix,
            auth: ("cookie", cookies(&headers)),
            offline_days: c.offline_days,
        };
        return s.clients(client).await;
    }
    Err(format!(
        "{base}: neither a UniFi OS console nor a Network application"
    ))
}

/// One poll of an OPNsense box.
async fn poll_opnsense(
    client: &telltale_filter::fetch::Client,
    c: &RouterConfig,
) -> Result<Polled, String> {
    let base = c.url.trim_end_matches('/');
    let key = secret(c.api_key_file.as_ref())?.ok_or("set api_key_file")?;
    let sec = secret(c.api_secret_file.as_ref())?.ok_or("set api_secret_file")?;
    let auth = format!("Basic {}", base64(format!("{key}:{sec}").as_bytes()));
    let mut last = String::new();
    for path in [
        "/api/dnsmasq/leases/search",
        "/api/kea/leases4/search",
        "/api/dhcpv4/leases/searchLease",
    ] {
        let req = http::Request::get(format!("{base}{path}"))
            .header("authorization", auth.as_str())
            .header("accept", "application/json")
            .body(Vec::new())
            .map_err(|e| e.to_string())?;
        let (status, _, v) = call(client, req).await?;
        if status.is_success() && v.get("rows").is_some() {
            return Ok(Polled::now(opnsense_leases(&v)));
        }
        if status == http::StatusCode::UNAUTHORIZED || status == http::StatusCode::FORBIDDEN {
            return Err(format!(
                "{base}: HTTP {status} (check the API key and its privileges)"
            ));
        }
        last = format!("{base}{path}: HTTP {status}");
    }
    Err(format!("no DHCP lease API answered ({last})"))
}

/// REQ: FLT-006 (ADR-183) — the addresses whose binding to a MAC can't be trusted to identify a
/// device, from the fresh routers' connected clients, MACs compared as parsed bytes:
/// - an address that more than one MAC is reported at (by two routers, or two rows of one);
/// - every address of a MAC that is reported at two or more addresses (a range extender or a
///   bridge that shares its MAC);
/// - an address UniFi gave a connected client from its last-known address (`not_current`).
///
/// A stale router's data marks nothing (it is no longer trusted at all: see `rebuild`).
fn unsure_addresses(
    parts: &HashMap<String, Polled>,
    order: &[&String],
    stale: &HashSet<String>,
) -> HashSet<Ipv4Addr> {
    use crate::identify::oui::parse_mac;
    let fresh = || order.iter().filter(|n| !stale.contains(n.as_str()));
    // Per address: the first MAC reported (one that doesn't parse counts as its own text, so it
    // still disagrees with another MAC) and whether a different one was reported too. Per MAC: its
    // first address and whether it was reported at another. One small entry each, not a set.
    let mut at: HashMap<Ipv4Addr, (Result<[u8; 6], String>, bool)> = HashMap::new();
    let mut of: HashMap<[u8; 6], (Ipv4Addr, bool)> = HashMap::new();
    let mut unsure = HashSet::new();
    for name in fresh() {
        let p = &parts[*name];
        let not_current: HashSet<[u8; 6]> =
            p.not_current.iter().filter_map(|m| parse_mac(m)).collect();
        for d in &p.now {
            let parsed = parse_mac(&d.0);
            let key = parsed.ok_or_else(|| d.0.trim().to_ascii_lowercase());
            match at.entry(d.1) {
                Entry::Occupied(mut e) => {
                    if e.get().0 != key {
                        e.get_mut().1 = true;
                    }
                }
                Entry::Vacant(e) => {
                    e.insert((key, false));
                }
            }
            if let Some(mac) = parsed {
                match of.entry(mac) {
                    Entry::Occupied(mut e) => {
                        if e.get().0 != d.1 {
                            e.get_mut().1 = true;
                        }
                    }
                    Entry::Vacant(e) => {
                        e.insert((d.1, false));
                    }
                }
                if not_current.contains(&mac) {
                    unsure.insert(d.1);
                }
            }
        }
    }
    unsure.extend(
        at.iter()
            .filter(|(_, (_, differs))| *differs)
            .map(|(ip, _)| *ip),
    );
    for name in fresh() {
        for d in &parts[*name].now {
            if parse_mac(&d.0).is_some_and(|mac| of.get(&mac).is_some_and(|(_, many)| *many)) {
                unsure.insert(d.1);
            }
        }
    }
    unsure
}

/// REQ: FLT-006 (ADR-183) — how many of a router's rows carry a MAC that can't identify a device
/// (empty, all zero, multicast, or in a form that isn't read): such an address is withheld from
/// identification, and the device falls back to its address, by design.
pub(crate) fn unusable_macs(seen: &[Device]) -> usize {
    seen.iter()
        .filter(|d| crate::devices::usable_mac(&d.0).is_none())
        .count()
}

/// The leases view from every router's last answer. REQ: T8.2 (ADR-166) — an offline client
/// only names an address no router reports as connected, and is marked, so it isn't "seen".
///
/// REQ: FLT-006 (ADR-183) — the order between routers is fixed, not the `HashMap`'s: stale
/// routers (silent more than [`STALE_AFTER_S`]) by name, then fresh ones by name, and a later
/// router names an address over an earlier one (within one router a later row still does for a
/// connected client, and the first for an offline one, the most recently seen). A binding is
/// marked `unsure` when [`unsure_addresses`] says so, and every connected lease a stale router
/// gives is (and is marked `stale` too): it still names the address, but a device there is not
/// identified by it, and the MAC it names is not counted at that address by anything fresh.
fn rebuild(parts: &HashMap<String, Polled>, view: &ArcSwap<Leases>, stale: &HashSet<String>) {
    let lease = |d: &Device, offline: bool| Lease {
        mac: d.0.clone(),
        ip: d.1,
        hostname: d.2.clone(),
        expires: 0,
        offline,
        unsure: false,
        stale: false,
    };
    let mut order: Vec<&String> = parts.keys().collect();
    order.sort_by(|a, b| (!stale.contains(*a), *a).cmp(&(!stale.contains(*b), *b)));
    let mut m = Leases::new();
    // Addresses whose winning (last) connected row is a stale router's.
    let mut from_stale: HashSet<Ipv4Addr> = HashSet::new();
    for name in &order {
        let is_stale = stale.contains(name.as_str());
        for d in &parts[*name].now {
            m.insert(d.1, lease(d, false));
            if is_stale {
                from_stale.insert(d.1);
            } else {
                from_stale.remove(&d.1);
            }
        }
    }
    let unsure = unsure_addresses(parts, &order, stale);
    for (ip, l) in &mut m {
        // A stale router's row is `stale` as well as `unsure`: still withheld on this node, but a
        // MAC seen only there is not "a MAC at another address" for anything fresh (D5).
        l.stale = from_stale.contains(ip);
        l.unsure = unsure.contains(ip) || l.stale;
    }
    // Offline clients name only an address no router has connected; the router that comes last
    // in `order` wins, as for connected ones, and within one router the first row does.
    for name in order.iter().rev() {
        for d in &parts[*name].offline {
            m.entry(d.1).or_insert_with(|| lease(d, true));
        }
    }
    view.store(Arc::new(m));
}

/// Why this router's answers aren't authenticated, and the fix; `None` when they are.
fn unauthenticated(r: &RouterConfig) -> Option<(&'static str, &'static str)> {
    if r.url.starts_with("http://") {
        Some((
            "this router is read over plain http://",
            "use an https:// url with tls_ca, keep the route to it private",
        ))
    } else if r.tls_insecure_skip_verify {
        Some((
            "this router's certificate isn't checked (tls_insecure_skip_verify)",
            "set tls_ca (and tls_server_name)",
        ))
    } else {
        None
    }
}

/// Polls every `[[router]]` until `stop`. `resolver_pod`: a Helm resolver pod, which has the
/// routers' settings but not their key files (ADR-120), logs its failures as info; the
/// controller, which serves the names in the UI, warns.
#[allow(clippy::too_many_lines)] // one round: which routers to hold back, the polls, the wait
pub(crate) async fn run(
    sources: Arc<crate::http::Sources>,
    view: Arc<ArcSwap<Leases>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    resolver_pod: bool,
) {
    let routers_now = || sources.config.load().router.clone();
    let resolver: Arc<dyn telltale_filter::fetch::Resolve> =
        Arc::new(telltale_filter::fetch::SystemResolver);
    let mut parts: HashMap<String, Polled> = HashMap::new();
    // REQ: FLT-006 (ADR-183) — when each router last answered, in seconds on this task's
    // monotonic clock (never the wall clock, which can step), and how stale that makes it.
    let started = std::time::Instant::now();
    let mono = || started.elapsed().as_secs();
    let mut last_ok: HashMap<String, u64> = HashMap::new();
    let mut failing: HashMap<String, bool> = HashMap::new();
    let mut held: HashMap<String, String> = HashMap::new();
    let mut warned_tls: HashSet<String> = HashSet::new();
    let mut warned_junk: HashSet<String> = HashSet::new();
    // REQ: API-002, T8.2 (ADR-181) — F5: the routers the last sweep of key files saw.
    let mut swept_for: Option<Vec<RouterConfig>> = None;
    // The routers last read: one removed, or now pointing at another device (type, address,
    // site), drops its answer, so no names linger from a router that's gone (ADR-181). Other
    // changes (credentials, TLS, timing) keep it until the next answer replaces it.
    let mut read_with: Vec<RouterConfig> = Vec::new();
    loop {
        let routers = routers_now();
        // REQ: API-002, T8.2 (ADR-181) — F5: at start, and after each change of the routers in
        // effect (a write, a reload, a replicated version, a failover), the key files this node
        // wrote that nothing names any more are removed; one that couldn't run yet (the state
        // database not open) is tried again at the next check (correctness F3).
        if swept_for.as_ref() != Some(&routers) && crate::router_secrets::sweep(&sources).await {
            swept_for = Some(routers.clone());
        }
        let same_device = |a: &RouterConfig, b: &RouterConfig| {
            a.name == b.name && a.kind == b.kind && a.url == b.url && a.site == b.site
        };
        let kept = |n: &str| {
            routers
                .iter()
                .any(|r| r.name.as_str() == n && read_with.iter().any(|w| same_device(w, r)))
        };
        parts.retain(|n, _| kept(n));
        last_ok.retain(|n, _| kept(n));
        failing.retain(|n, _| kept(n));
        read_with.clone_from(&routers);
        let interval = routers
            .iter()
            .map(|r| r.interval_secs.max(30))
            .min()
            .unwrap_or(300);
        // REQ: API-002, T8.2 (ADR-181) — the use-time rule, worked out for this round: a router
        // whose key file this node won't send for it isn't polled, and keeps no names. If the
        // check can't run, none with a key file is polled (fails closed).
        let check = {
            let s = Arc::clone(&sources);
            tokio::task::spawn_blocking(move || crate::router_secrets::UseCheck::load(&s))
                .await
                .unwrap_or_default()
        };
        let refused: Vec<(String, String)> = routers
            .iter()
            .filter_map(|r| check.refused(r).map(|why| (r.name.to_string(), why)))
            .collect();
        // Review round 2, R1: a warning on a replica too (once per router and reason): its
        // Routers page shows the primary's status, so the log is where it says what it does. A
        // Helm resolver pod has no keys by design (ADR-120): information there.
        for (name, why) in held_now(&mut held, refused) {
            if resolver_pod {
                info!(router = %name, reason = %why, "router integration: not read on this node");
            } else {
                warn!(router = %name, reason = %why, "router integration: not read on this node");
            }
        }
        for r in &routers {
            if held.contains_key(r.name.as_str()) {
                parts.remove(r.name.as_str());
                last_ok.remove(r.name.as_str());
                failing.remove(r.name.as_str());
                continue;
            }
            // REQ: T8.2, CLU-009 (ADR-189) — one box isn't polled by every resolver pod; the
            // names it gives come from a full member (`devices.names`).
            if resolver_pod && r.kind == RouterKind::Fritzbox {
                continue;
            }
            let client = if r.tls_insecure_skip_verify {
                telltale_filter::fetch::Client::insecure(Arc::clone(&resolver))
            } else if let Some(p) = &r.tls_ca {
                telltale_filter::fetch::Client::with_ca_file(Arc::clone(&resolver), p.as_str())
            } else {
                telltale_filter::fetch::Client::new(Arc::clone(&resolver), &[])
            };
            // Like a failed poll, a TLS setting that can't load (a node without the CA file, ADR-120)
            // is logged once until it works.
            let client = match client {
                Ok(c) => c,
                Err(e) => {
                    if !failing.get(r.name.as_str()).copied().unwrap_or(false) {
                        if resolver_pod {
                            info!(router = %r.name, error = %e, "router integration: TLS settings (not on this resolver pod; the controller reads the router)");
                        } else {
                            warn!(router = %r.name, error = %e, "router integration: TLS settings");
                        }
                    }
                    failing.insert(r.name.to_string(), true);
                    continue;
                }
            };
            // REQ: T8.2 — a console whose certificate names something other than `url`'s host.
            let client = client.with_server_name(
                r.tls_server_name
                    .as_ref()
                    .map(telltale_config::SafeString::as_str),
            );
            let result = match r.kind {
                RouterKind::Unifi => poll_unifi(&client, r).await,
                RouterKind::Opnsense => poll_opnsense(&client, r).await,
                RouterKind::Fritzbox => fritzbox::poll(&client, r).await,
            };
            let was_failing = failing.get(r.name.as_str()).copied().unwrap_or(false);
            match result {
                Ok(seen) => {
                    if was_failing || !parts.contains_key(r.name.as_str()) {
                        info!(router = %r.name, devices = seen.now.len(), offline = seen.offline.len(), "router integration: devices read");
                    }
                    // REQ: FLT-006 (ADR-183, ADR-189) — a router whose answer can't be trusted
                    // (plain HTTP, or a certificate that isn't checked) now decides which
                    // named device an address is: said once per router.
                    if let Some((why, fix)) = unauthenticated(r)
                        && feeds_identification(&sources)
                        && warned_tls.insert(r.name.to_string())
                    {
                        warn!(router = %r.name, "router integration: {why}, and its client list now decides which named device an address is, so anything posing as it could give a device another's rules; {fix}, or `[clients] router_macs = false`");
                    }
                    // REQ: FLT-006 (ADR-183) — rows whose MAC can't identify a device withhold
                    // their address: said once per router, so the fallback can be explained.
                    if feeds_identification(&sources) && !warned_junk.contains(r.name.as_str()) {
                        let unusable = unusable_macs(&seen.now);
                        if unusable > 0 {
                            warned_junk.insert(r.name.to_string());
                            info!(router = %r.name, rows = unusable, of = seen.now.len(), "router integration: some devices have a MAC address that can't identify a device (empty, all zero, multicast, or in a form TelltaleDNS doesn't read); those addresses are not recognized by MAC, by design: a device there is recognized by its address or network instead");
                        }
                    }
                    parts.insert(r.name.to_string(), seen);
                    last_ok.insert(r.name.to_string(), mono());
                    failing.insert(r.name.to_string(), false);
                }
                Err(e) => {
                    if !was_failing {
                        if resolver_pod {
                            info!(router = %r.name, error = %e, "router integration failed on this resolver pod (the controller reads the router)");
                        } else {
                            warn!(router = %r.name, error = %e, "router integration failed (keeping its last answer)");
                        }
                    }
                    failing.insert(r.name.to_string(), true);
                }
            }
        }
        rebuild(&parts, &view, &stale_routers(&last_ok, mono()));
        // A router that failed (it may still be booting) is asked again soon.
        let any_failing = failing.values().any(|f| *f);
        // REQ: T8.2 (ADR-181) — until the next read, or sooner when the routers change.
        // REQ: FLT-006 (ADR-183) — and, while this node's routers feed identification, within 15
        // minutes whatever `interval_secs` says (also when a device named by its MAC appears
        // during a long wait): an answer older than that doesn't say who holds an address.
        let waited_from = tokio::time::Instant::now();
        loop {
            let wait = Duration::from_secs(u64::from(next_poll_secs(
                any_failing,
                interval,
                feeds_identification(&sources),
            )));
            let left = (waited_from + wait).saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            tokio::select! {
                _ = stop.changed() => return,
                () = tokio::time::sleep(CHANGE_CHECK.min(left)) => {}
            }
            // A sweep that couldn't run yet is tried again at each check, without a new round of
            // polls (correctness F3; cheap while the state database isn't open).
            if swept_for.as_ref() != Some(&read_with)
                && crate::router_secrets::sweep(&sources).await
            {
                swept_for = Some(read_with.clone());
            }
            if routers_now() != read_with {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: T8.2 — UniFi's client list: the alias wins over the host name; clients without
    /// an IPv4 address are skipped.
    #[test]
    fn unifi_clients_named() {
        let v = serde_json::json!({"meta": {"rc": "ok"}, "data": [
            {"mac": "AA:BB:CC:00:00:01", "ip": "192.168.1.20", "hostname": "android-123", "name": "Kitchen tablet"},
            {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.1.21", "hostname": "roku"},
            {"mac": "aa:bb:cc:00:00:03", "hostname": "no-ip"},
            {"mac": "aa:bb:cc:00:00:04", "last_ip": "192.168.1.22", "name": ""}
        ]});
        assert_eq!(
            unifi_clients(&v),
            vec![
                (
                    "aa:bb:cc:00:00:01".into(),
                    Ipv4Addr::new(192, 168, 1, 20),
                    Some("Kitchen tablet".into())
                ),
                (
                    "aa:bb:cc:00:00:02".into(),
                    Ipv4Addr::new(192, 168, 1, 21),
                    Some("roku".into())
                ),
                (
                    "aa:bb:cc:00:00:04".into(),
                    Ipv4Addr::new(192, 168, 1, 22),
                    None
                ),
            ]
        );
    }

    /// REQ: T8.2 — UniFi's offline known clients keep their names: v2 history (a bare array)
    /// and `rest/user` give the named ones, most recently seen first; a connected client keeps
    /// its address and only takes a name it lacks; an offline client never takes an address a
    /// connected one holds.
    #[test]
    fn unifi_offline_clients_named() {
        let active = unifi_clients(&serde_json::json!({"data": [
            {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.20", "name": "Kitchen tablet"},
            {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.1.21"}
        ]}));
        let history = serde_json::json!([
            {"mac": "aa:bb:cc:00:00:10", "last_ip": "192.168.1.30", "hostname": "old-laptop", "last_seen": 100},
            {"mac": "AA:BB:CC:00:00:11", "last_ip": "192.168.1.30", "name": "Work laptop", "last_seen": 200},
            {"mac": "aa:bb:cc:00:00:12", "last_ip": "192.168.1.20", "name": "Old phone", "last_seen": 300},
            {"mac": "aa:bb:cc:00:00:13", "last_ip": "192.168.1.31", "last_seen": 400},
            {"mac": "aa:bb:cc:00:00:02", "last_ip": "192.168.1.21", "name": "Living room TV"},
            {"hostname": "phone", "fixed_ip": "192.168.1.62", "use_fixedip": false, "last_ip": "192.168.1.63",
             "mac": "aa:bb:cc:00:00:17", "display_name": "Spare phone", "name": "Spare phone",
             "last_seen": 150, "status": "offline", "type": "WIRELESS", "fingerprint": {"has_override": false}}
        ]);
        let users = serde_json::json!({"meta": {"rc": "ok"}, "data": [
            {"mac": "aa:bb:cc:00:00:14", "fixed_ip": "192.168.1.40", "use_fixedip": true, "name": "Printer"},
            {"mac": "aa:bb:cc:00:00:15", "name": "No address"},
            {"mac": "aa:bb:cc:00:00:16", "fixed_ip": "192.168.1.41", "use_fixedip": false, "name": "Reservation off"}
        ]});
        let mut known = unifi_known(&history, 0);
        known.extend(unifi_known(&users, 0));
        assert_eq!(
            unifi_merge(active, known),
            vec![
                (
                    "aa:bb:cc:00:00:01".into(),
                    Ipv4Addr::new(192, 168, 1, 20),
                    Some("Kitchen tablet".into())
                ),
                (
                    "aa:bb:cc:00:00:02".into(),
                    Ipv4Addr::new(192, 168, 1, 21),
                    Some("Living room TV".into())
                ),
                (
                    "aa:bb:cc:00:00:11".into(),
                    Ipv4Addr::new(192, 168, 1, 30),
                    Some("Work laptop".into())
                ),
                (
                    "aa:bb:cc:00:00:17".into(),
                    Ipv4Addr::new(192, 168, 1, 63),
                    Some("Spare phone".into())
                ),
                (
                    "aa:bb:cc:00:00:14".into(),
                    Ipv4Addr::new(192, 168, 1, 40),
                    Some("Printer".into())
                ),
            ]
        );
    }

    /// REQ: T8.2 (ADR-166) — `offline_days`: a row last seen before the window is dropped, one with
    /// no date stays, the most recently seen come first, and no more than `OFFLINE_MAX` are kept.
    #[test]
    fn unifi_known_window_and_cap() {
        let rows = serde_json::json!([
            {"mac": "aa:bb:cc:00:01:01", "last_ip": "10.0.1.1", "name": "recent", "last_seen": 2_000_000},
            {"mac": "aa:bb:cc:00:01:02", "last_ip": "10.0.1.2", "name": "old", "last_seen": 1_000_000},
            {"mac": "aa:bb:cc:00:01:03", "last_ip": "10.0.1.3", "name": "undated"},
            {"mac": "aa:bb:cc:00:01:04", "last_ip": "10.0.1.4", "name": "newest", "last_seen": 2_500_000},
        ]);
        let names = |s: Seen| s.into_iter().filter_map(|d| d.2).collect::<Vec<_>>();
        assert_eq!(
            names(unifi_known(&rows, 0)),
            ["newest", "recent", "old", "undated"]
        );
        assert_eq!(
            names(unifi_known(&rows, 1_500_000)),
            ["newest", "recent", "undated"]
        );
        // A site that remembers thousands: the most recent ones.
        let many: Vec<Value> = (0..2 * OFFLINE_MAX)
            .map(|i| {
                serde_json::json!({
                    "mac": format!("02:00:00:00:{:02x}:{:02x}", i / 256, i % 256),
                    "last_ip": format!("10.1.{}.{}", i / 250, i % 250 + 1),
                    "name": format!("c{i}"),
                    "last_seen": 1_000 + i,
                })
            })
            .collect();
        let known = unifi_known(&Value::Array(many), 0);
        assert_eq!(known.len(), OFFLINE_MAX);
        let newest = format!("c{}", 2 * OFFLINE_MAX - 1);
        assert_eq!(known[0].2.as_deref(), Some(newest.as_str()));
    }

    /// REQ: T8.2 (ADR-166) — a poll's connected clients (named from the history when they lack a
    /// name) stay apart from the offline ones, and the offline ones are capped.
    #[test]
    fn unifi_split_keeps_offline_apart_and_capped() {
        let ip = |n: u32| Ipv4Addr::from(0x0a00_0000 + n);
        let active: Seen = vec![("aa:aa:aa:00:00:01".into(), ip(1), None)];
        let mut known: Seen = vec![("aa:aa:aa:00:00:01".into(), ip(1), Some("TV".into()))];
        known.extend((2..3000_u32).map(|n| {
            (
                format!("bb:00:00:00:{:02x}:{:02x}", n / 256, n % 256),
                ip(n),
                Some(format!("off{n}")),
            )
        }));
        let polled = unifi_split(active, known);
        assert_eq!(
            polled.now,
            vec![("aa:aa:aa:00:00:01".to_owned(), ip(1), Some("TV".to_owned()))]
        );
        assert_eq!(polled.offline.len(), OFFLINE_MAX);
        assert_eq!(polled.offline[0].2.as_deref(), Some("off2"));
    }

    /// REQ: T8.2 (ADR-166) — an offline client names an address, marked as offline, only where no
    /// router reports a connected device; connected ones are not marked.
    #[test]
    fn offline_clients_never_replace_a_connected_device() {
        let dev = |mac: &str, ip: [u8; 4], name: &str| -> Device {
            (mac.to_owned(), Ipv4Addr::from(ip), Some(name.to_owned()))
        };
        let mut parts = HashMap::new();
        parts.insert(
            "udm".to_owned(),
            Polled {
                now: vec![dev("aa:00:00:00:00:01", [10, 0, 0, 5], "Desk")],
                offline: vec![dev("aa:00:00:00:00:02", [10, 0, 0, 9], "Old phone")],
                not_current: HashSet::new(),
            },
        );
        parts.insert(
            "other".to_owned(),
            Polled {
                now: Seen::new(),
                offline: vec![dev("aa:00:00:00:00:03", [10, 0, 0, 5], "Gone laptop")],
                not_current: HashSet::new(),
            },
        );
        let view = ArcSwap::from_pointee(Leases::new());
        rebuild(&parts, &view, &HashSet::new());
        let leases = view.load_full();
        let desk = &leases[&Ipv4Addr::new(10, 0, 0, 5)];
        assert_eq!(
            (desk.hostname.as_deref(), desk.offline),
            (Some("Desk"), false)
        );
        let phone = &leases[&Ipv4Addr::new(10, 0, 0, 9)];
        assert_eq!(
            (phone.hostname.as_deref(), phone.offline),
            (Some("Old phone"), true)
        );
    }

    /// REQ: API-002, T8.2 (ADR-181) — a router held back is logged when it is first held and when
    /// its reason changes, not at every round; one no longer held is forgotten, so it is logged
    /// again if it is held again.
    #[test]
    fn api_002_a_held_router_is_logged_once_per_reason() {
        let mut held = HashMap::new();
        let v = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
                .collect()
        };
        assert_eq!(
            held_now(&mut held, v(&[("evil", "a")])),
            v(&[("evil", "a")])
        );
        assert_eq!(held_now(&mut held, v(&[("evil", "a")])), v(&[]));
        assert_eq!(
            held_now(&mut held, v(&[("evil", "b")])),
            v(&[("evil", "b")])
        );
        assert_eq!(held_now(&mut held, v(&[])), v(&[]));
        assert_eq!(
            held_now(&mut held, v(&[("evil", "b")])),
            v(&[("evil", "b")])
        );
    }

    /// REQ: T8.2 — OPNsense leases, whichever DHCP server answered.
    #[test]
    fn opnsense_leases_any_backend() {
        let isc = serde_json::json!({"rows": [{"address": "10.0.0.5", "mac": "00:11:22:33:44:55", "hostname": "nas"}]});
        let kea = serde_json::json!({"rows": [{"address": "10.0.0.6", "hwaddr": "00:11:22:33:44:66", "hostname": "*"}]});
        assert_eq!(
            opnsense_leases(&isc),
            vec![(
                "00:11:22:33:44:55".into(),
                Ipv4Addr::new(10, 0, 0, 5),
                Some("nas".into())
            )]
        );
        assert_eq!(
            opnsense_leases(&kea),
            vec![("00:11:22:33:44:66".into(), Ipv4Addr::new(10, 0, 0, 6), None)]
        );
        assert_eq!(base64(b"key:secret"), "a2V5OnNlY3JldA==");
    }

    fn dev(mac: &str, ip: [u8; 4], name: &str) -> Device {
        (mac.to_owned(), Ipv4Addr::from(ip), Some(name.to_owned()))
    }

    fn polled(now: Vec<Device>) -> Polled {
        Polled {
            now,
            offline: Seen::new(),
            not_current: HashSet::new(),
        }
    }

    fn parts(routers: Vec<(&str, Polled)>) -> HashMap<String, Polled> {
        routers
            .into_iter()
            .map(|(name, p)| (name.to_owned(), p))
            .collect()
    }

    /// The view `rebuild` makes of `parts`, with `stale` routers.
    fn view_of(parts: &HashMap<String, Polled>, stale: &[&str]) -> Leases {
        let view = ArcSwap::from_pointee(Leases::new());
        let stale: HashSet<String> = stale.iter().map(|s| (*s).to_owned()).collect();
        rebuild(parts, &view, &stale);
        (**view.load()).clone()
    }

    /// The lease at `ip` and whether it can identify a device.
    fn at(v: &Leases, ip: [u8; 4]) -> (Option<String>, bool, bool) {
        let l = &v[&Ipv4Addr::from(ip)];
        (
            l.hostname.clone(),
            l.unsure,
            crate::devices::eligible(l).is_some(),
        )
    }

    /// REQ: FLT-006 (ADR-183) — routers that give one address different MACs (or two rows of one
    /// router that do) leave it `unsure`: it still names the address, and identifies nothing.
    /// The same MAC written two ways (`:` and `-`, any case) is the same MAC.
    #[test]
    fn flt_006_routers_disagreeing_on_an_address_mark_it_unsure() {
        let p = parts(vec![
            (
                "udm",
                polled(vec![
                    dev("aa:bb:cc:00:00:01", [10, 0, 0, 5], "Desk"),
                    dev("aa:bb:cc:00:00:02", [10, 0, 0, 6], "Phone"),
                    dev("aa:bb:cc:00:00:03", [10, 0, 0, 7], "TV"),
                    dev("aa:bb:cc:00:00:04", [10, 0, 0, 8], "Old"),
                    dev("aa:bb:cc:00:00:05", [10, 0, 0, 8], "New"),
                ]),
            ),
            (
                "opn",
                polled(vec![
                    dev("aa:bb:cc:00:00:09", [10, 0, 0, 5], "Other"),
                    dev("aa-bb-cc-00-00-03", [10, 0, 0, 7], "TV"),
                ]),
            ),
        ]);
        let v = view_of(&p, &[]);
        // Two routers, two MACs.
        assert!(at(&v, [10, 0, 0, 5]).1);
        assert!(!at(&v, [10, 0, 0, 5]).2);
        // One MAC, one address: sure.
        assert_eq!(at(&v, [10, 0, 0, 6]), (Some("Phone".into()), false, true));
        // The same MAC in two spellings is not a disagreement.
        assert_eq!(at(&v, [10, 0, 0, 7]), (Some("TV".into()), false, true));
        // Two rows of one router.
        assert!(at(&v, [10, 0, 0, 8]).1);
        assert!(!at(&v, [10, 0, 0, 8]).2);
    }

    /// REQ: FLT-006 (ADR-183) — UniFi gives a connected client without a current `ip` the address
    /// it had (`last_ip`): that names the address, but a device there can't be identified by it.
    #[test]
    fn flt_006_unifi_client_without_a_current_address_is_unsure() {
        let sta = serde_json::json!({"data": [
            {"mac": "AA:BB:CC:00:00:01", "ip": "192.168.1.20", "name": "Desk"},
            {"mac": "AA:BB:CC:00:00:02", "last_ip": "192.168.1.21", "name": "Phone"},
            {"mac": "aa:bb:cc:00:00:03", "ip": "", "last_ip": "192.168.1.22", "name": "TV"},
            {"mac": "aa:bb:cc:00:00:04", "ip": "fe80::1", "fixed_ip": "192.168.1.23",
             "use_fixedip": true, "name": "NAS"}
        ]});
        let not_current = unifi_not_current(&sta);
        let mut listed: Vec<&str> = not_current.iter().map(String::as_str).collect();
        listed.sort_unstable();
        assert_eq!(
            listed,
            [
                "aa:bb:cc:00:00:02",
                "aa:bb:cc:00:00:03",
                "aa:bb:cc:00:00:04"
            ]
        );
        let p = parts(vec![(
            "udm",
            Polled {
                now: unifi_clients(&sta),
                offline: Seen::new(),
                not_current,
            },
        )]);
        let v = view_of(&p, &[]);
        assert_eq!(
            at(&v, [192, 168, 1, 20]),
            (Some("Desk".into()), false, true),
            "a client with a current address"
        );
        for (ip, name) in [(21, "Phone"), (22, "TV"), (23, "NAS")] {
            assert_eq!(
                at(&v, [192, 168, 1, ip]),
                (Some(name.into()), true, false),
                "{name} names its address, and identifies nothing there"
            );
        }
    }

    /// REQ: FLT-006, CLU-002 (ADR-183) — the rows a silent router still lists say so, on this node
    /// and, in the answer a member gives, on the others: `stale` (written only when true, so an
    /// earlier node reads the old form plus a field it ignores) next to `unsure`. A node that
    /// reads it counts them toward nothing and withholds nothing for them; the node that owns the
    /// router keeps the address withheld.
    #[test]
    fn flt_006_a_stale_routers_rows_say_so_on_the_wire() {
        let p = parts(vec![
            (
                "udm",
                polled(vec![dev("aa:bb:cc:00:00:01", [10, 0, 0, 5], "Desk")]),
            ),
            (
                "opn",
                polled(vec![dev("aa:bb:cc:00:00:02", [10, 0, 0, 6], "Phone")]),
            ),
        ]);
        let v = view_of(&p, &["udm"]);
        let wire = |ip: [u8; 4]| serde_json::to_value(&v[&Ipv4Addr::from(ip)]).unwrap();
        let stale = wire([10, 0, 0, 5]);
        assert_eq!(stale["unsure"], true, "{stale}");
        assert_eq!(stale["stale"], true, "{stale}");
        let fresh = wire([10, 0, 0, 6]);
        assert!(
            fresh.get("stale").is_none() && fresh.get("unsure").is_none(),
            "{fresh}"
        );
    }

    /// REQ: FLT-006 (ADR-183) — a router silent for more than 900 seconds is stale: its bindings
    /// are `unsure`, and an address another (fresh) router reports is the fresh one's.
    #[test]
    fn flt_006_a_router_silent_for_15_minutes_is_unsure() {
        let last_ok: HashMap<String, u64> =
            [("udm".to_owned(), 100), ("opn".to_owned(), 900)].into();
        assert!(stale_routers(&last_ok, 100 + STALE_AFTER_S).is_empty());
        assert_eq!(
            stale_routers(&last_ok, 100 + STALE_AFTER_S + 1),
            HashSet::from(["udm".to_owned()])
        );
        assert_eq!(
            stale_routers(&last_ok, 900 + STALE_AFTER_S + 1).len(),
            2,
            "both, later"
        );

        let p = parts(vec![
            (
                "udm",
                polled(vec![
                    dev("aa:bb:cc:00:00:01", [10, 0, 0, 5], "Desk (stale)"),
                    dev("aa:bb:cc:00:00:02", [10, 0, 0, 6], "Phone"),
                ]),
            ),
            (
                "opn",
                polled(vec![dev(
                    "aa:bb:cc:00:00:07",
                    [10, 0, 0, 5],
                    "Desk (fresh)",
                )]),
            ),
        ]);
        // Both fresh: .6 is sure (the two routers disagree about .5, which is not this test's).
        let fresh = view_of(&p, &[]);
        assert_eq!(
            at(&fresh, [10, 0, 0, 6]),
            (Some("Phone".into()), false, true)
        );
        assert!(at(&fresh, [10, 0, 0, 5]).1);
        // udm silent: its lease at .6 is unsure; .5 is the fresh router's, and sure.
        let stale = view_of(&p, &["udm"]);
        assert_eq!(
            at(&stale, [10, 0, 0, 6]),
            (Some("Phone".into()), true, false)
        );
        assert_eq!(
            at(&stale, [10, 0, 0, 5]),
            (Some("Desk (fresh)".into()), false, true),
            "a fresh router's binding for the same address is the one shown, and sure"
        );
        // The stale router's other MAC at .5 is no disagreement: stale data marks nothing.
        let alone = parts(vec![(
            "udm",
            polled(vec![dev("aa:bb:cc:00:00:01", [10, 0, 0, 5], "Desk")]),
        )]);
        assert!(at(&view_of(&alone, &["udm"]), [10, 0, 0, 5]).1);
        assert!(!at(&view_of(&alone, &[]), [10, 0, 0, 5]).1);
    }

    /// REQ: FLT-006 (ADR-183) — silence is counted on a monotonic clock with saturating
    /// arithmetic: a "last answer" after "now" (a clock that stepped) neither panics nor makes a
    /// router stale.
    #[test]
    fn flt_006_silence_survives_a_clock_step() {
        let last_ok: HashMap<String, u64> = [
            ("a".to_owned(), 5_000),
            ("b".to_owned(), u64::MAX),
            ("c".to_owned(), 0),
        ]
        .into();
        let at_1000 = stale_routers(&last_ok, 1_000);
        assert!(at_1000.contains("c"), "silent since 0");
        assert!(!at_1000.contains("a"), "a last answered after now");
        assert!(!at_1000.contains("b"), "b last answered far after now");
        assert!(stale_routers(&last_ok, 0).is_empty());
        assert_eq!(
            stale_routers(&last_ok, u64::MAX),
            HashSet::from(["a".to_owned(), "c".to_owned()]),
            "only the routers that really are silent"
        );
    }

    /// REQ: FLT-006 (ADR-183) — what the view says doesn't depend on the order a `HashMap` of
    /// routers happens to iterate in: stale routers by name, then fresh ones by name, a later
    /// router naming an address over an earlier one (and, within one router, a later row for a
    /// connected client, the first for an offline one, as before).
    #[test]
    fn flt_006_rebuild_is_deterministic() {
        for round in 0..32 {
            // A fresh map each time, with its own random hasher; the insertion order varies too.
            let mut routers = vec![
                (
                    "a-fresh",
                    Polled {
                        now: vec![dev("aa:bb:cc:00:00:01", [10, 0, 0, 5], "from a")],
                        offline: vec![
                            dev("aa:bb:cc:00:00:11", [10, 0, 0, 9], "a first"),
                            dev("aa:bb:cc:00:00:12", [10, 0, 0, 9], "a second"),
                        ],
                        not_current: HashSet::new(),
                    },
                ),
                (
                    "b-fresh",
                    Polled {
                        now: vec![
                            dev("aa:bb:cc:00:00:01", [10, 0, 0, 5], "from b first"),
                            dev("aa:bb:cc:00:00:01", [10, 0, 0, 5], "from b last"),
                        ],
                        offline: vec![dev("aa:bb:cc:00:00:13", [10, 0, 0, 9], "b offline")],
                        not_current: HashSet::new(),
                    },
                ),
                (
                    "z-stale",
                    polled(vec![dev(
                        "aa:bb:cc:00:00:01",
                        [10, 0, 0, 5],
                        "from z (stale)",
                    )]),
                ),
            ];
            if round % 2 == 1 {
                routers.reverse();
            }
            let p: HashMap<String, Polled> = parts(routers);
            let v = view_of(&p, &["z-stale"]);
            assert_eq!(
                v[&Ipv4Addr::new(10, 0, 0, 5)].hostname.as_deref(),
                Some("from b last"),
                "round {round}: a fresh router beats a stale one, the later name the earlier, the last row the first"
            );
            let off = &v[&Ipv4Addr::new(10, 0, 0, 9)];
            assert_eq!(
                (off.hostname.as_deref(), off.offline),
                (Some("b offline"), true),
                "round {round}"
            );
        }
        // Within one router the first offline row (the most recently seen) names the address.
        let one = parts(vec![(
            "a",
            Polled {
                now: Seen::new(),
                offline: vec![
                    dev("aa:bb:cc:00:00:11", [10, 0, 0, 9], "newest"),
                    dev("aa:bb:cc:00:00:12", [10, 0, 0, 9], "older"),
                ],
                not_current: HashSet::new(),
            },
        )]);
        assert_eq!(
            view_of(&one, &[])[&Ipv4Addr::new(10, 0, 0, 9)]
                .hostname
                .as_deref(),
            Some("newest")
        );
    }

    /// REQ: FLT-006 (ADR-183) — one MAC at two or more addresses (a range extender or a bridge
    /// shares its MAC) identifies a device at none of them: every one of its addresses is
    /// `unsure`, across rows and across fresh routers; another device's address is not.
    #[test]
    fn flt_006_one_mac_at_two_addresses_does_not_identify() {
        let p = parts(vec![
            (
                "udm",
                polled(vec![
                    dev("aa:bb:cc:00:00:01", [10, 0, 0, 5], "Extender"),
                    dev("AA:BB:CC:00:00:01", [10, 0, 0, 6], "Behind it"),
                    dev("aa:bb:cc:00:00:02", [10, 0, 0, 7], "Phone"),
                    dev("aa:bb:cc:00:00:03", [10, 0, 0, 8], "Moved"),
                ]),
            ),
            (
                "opn",
                polled(vec![dev("aa-bb-cc-00-00-03", [10, 0, 0, 9], "Moved (opn)")]),
            ),
        ]);
        let v = view_of(&p, &[]);
        for ip in [5, 6, 8, 9] {
            let (_, unsure, can) = at(&v, [10, 0, 0, ip]);
            assert!(unsure && !can, "10.0.0.{ip}");
        }
        assert_eq!(at(&v, [10, 0, 0, 7]), (Some("Phone".into()), false, true));
        // A stale router's second address for a MAC isn't counted against a fresh router.
        let mixed = parts(vec![
            (
                "udm",
                polled(vec![dev("aa:bb:cc:00:00:01", [10, 0, 0, 5], "old address")]),
            ),
            (
                "opn",
                polled(vec![dev("aa:bb:cc:00:00:01", [10, 0, 0, 6], "new address")]),
            ),
        ]);
        let v = view_of(&mixed, &["udm"]);
        assert_eq!(
            at(&v, [10, 0, 0, 6]),
            (Some("new address".into()), false, true)
        );
        assert!(
            at(&v, [10, 0, 0, 5]).1,
            "and the stale one is unsure by itself"
        );
    }

    /// REQ: FLT-006 (ADR-183) — silence isn't age: a router read once an hour is never silent, yet
    /// what it says can be an hour old. So while the routers feed identification they are read at
    /// least every 10 minutes (600 s), whatever `interval_secs` is (and only then: a node that
    /// identifies no device by MAC reads at the configured pace), so that a read that fails is asked
    /// again, every 15 s, well inside the 15 minutes (900 s) after which an answer is stale.
    #[test]
    fn flt_006_a_router_read_less_often_than_15_minutes_does_not_identify() {
        // `interval_secs = 3600`: the effective pace is 600 s while they identify, 3600 s otherwise.
        assert_eq!(next_poll_secs(false, 3600, true), 600);
        assert_eq!(next_poll_secs(false, 3600, false), 3600);
        // A shorter interval is kept; a failing router is still asked again at once.
        assert_eq!(next_poll_secs(false, 300, true), 300);
        assert_eq!(next_poll_secs(false, 900, true), 600);
        assert_eq!(next_poll_secs(true, 3600, true), 15);
        assert_eq!(next_poll_secs(true, 3600, false), 15);
        assert_eq!(u64::from(IDENTIFY_POLL_MAX_S), 600);
        assert_eq!(STALE_AFTER_S, 900, "the staleness bound is unchanged");
        assert!(
            u64::from(IDENTIFY_POLL_MAX_S) + 15 * 5 <= STALE_AFTER_S,
            "at least five retries fit between the longest wait and the bound"
        );
        // And a binding older than that is unsure: the router that gave it is stale at 901 s.
        let last_ok: HashMap<String, u64> = [("udm".to_owned(), 0)].into();
        assert!(stale_routers(&last_ok, STALE_AFTER_S).is_empty());
        assert!(stale_routers(&last_ok, STALE_AFTER_S + 1).contains("udm"));
        let p = parts(vec![(
            "udm",
            polled(vec![dev("aa:bb:cc:00:00:01", [10, 0, 0, 5], "Desk")]),
        )]);
        assert_eq!(
            at(&view_of(&p, &[]), [10, 0, 0, 5]),
            (Some("Desk".into()), false, true)
        );
        assert_eq!(
            at(&view_of(&p, &["udm"]), [10, 0, 0, 5]),
            (Some("Desk".into()), true, false)
        );
    }

    /// REQ: FLT-006 (ADR-183) — a router's rows whose MAC can't identify a device (empty, all zero,
    /// multicast, a form that isn't read) are counted, for the log line that says once per router
    /// why those addresses fall back.
    #[test]
    fn flt_006_rows_whose_mac_cannot_identify_are_counted() {
        let rows = vec![
            dev("aa:bb:cc:00:00:01", [10, 0, 0, 5], "ok"),
            dev("AA-BB-CC-00-00-02", [10, 0, 0, 6], "ok too"),
            dev("", [10, 0, 0, 7], "empty"),
            dev("00:00:00:00:00:00", [10, 0, 0, 8], "zero"),
            dev("01:00:5e:00:00:01", [10, 0, 0, 9], "multicast"),
            dev("aabb.ccdd.eeff", [10, 0, 0, 10], "dotted"),
        ];
        assert_eq!(unusable_macs(&rows), 4);
        assert_eq!(unusable_macs(&rows[..2]), 0);
        assert_eq!(unusable_macs(&Seen::new()), 0);
    }
}
