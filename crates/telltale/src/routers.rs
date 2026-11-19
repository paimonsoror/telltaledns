//! Router integrations (REQ: API-010 naming sources, M8 "router integrations"; T8.2): device
//! names and addresses read from the router's DHCP, so devices show up by name without
//! TelltaleDNS running DHCP itself.
//! - **UniFi** (UniFi OS consoles: UDM, UCG, Cloud Key Gen2+; and the classic Network
//!   application): the active clients (`stat/sta`), then the offline clients it still knows
//!   (v2 `clients/history`, `rest/user`), named by their UniFi alias, else their host name.
//!   An API key (`X-API-KEY`), or a local username and password.
//! - **OPNsense**: the DHCP leases (Dnsmasq, Kea, or ISC, whichever the box runs), with an
//!   API key and secret.
//! - **MikroTik** (RouterOS v7, ADR-177): the DHCP server's leases over the REST API
//!   (`/rest/ip/dhcp-server/lease`), with a (read-only) RouterOS user. The bound leases are the
//!   connected devices; a static lease that isn't bound now is an offline one, named by its
//!   comment, else the host name the device last sent.
//!
//! Polled every `interval_secs`; the result replaces that router's part of the lease view
//! the naming falls back to (after configured device names and TelltaleDNS's own DHCP).
//! Never on the DNS path; a router that's down keeps its last answer and is logged.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use serde_json::Value;
use telltale_config::{RouterConfig, RouterKind};
use tracing::{debug, info, warn};

use crate::devices::{Lease, Leases};

/// How often the routers in effect are compared with the ones last read (ADR-176).
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

/// What one poll of a router found: the devices it reports now, and (UniFi, MikroTik) the offline clients
/// it remembers, kept apart because only the first are "seen" (ADR-166).
pub(crate) struct Polled {
    pub(crate) now: Seen,
    pub(crate) offline: Seen,
}

impl Polled {
    /// A router that only reports what it has now (OPNsense).
    fn now(now: Seen) -> Self {
        Self {
            now,
            offline: Seen::new(),
        }
    }
}

fn secret(path: Option<&telltale_config::SafeString>) -> Result<Option<String>, String> {
    path.map(|p| {
        std::fs::read_to_string(p.as_str())
            .map(|s| s.trim().to_owned())
            .map_err(|e| format!("{}: {e}", p.as_str()))
    })
    .transpose()
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

/// REQ: T8.2 — the connected clients, then the known ones the router has names for (UniFi,
/// MikroTik), so an offline
/// device's queries still show its name. A connected client keeps its address; a known one
/// only names it when it has none, and adds a device only for an address no one else holds
/// (an offline device's last address may since have gone to another one), and for at most
/// [`OFFLINE_MAX`] devices.
pub(crate) fn merge_known(mut active: Seen, known: Seen) -> Seen {
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

/// REQ: T8.2 (ADR-166) — [`merge_known`], with the offline devices it appended (after the
/// connected ones, which keep their order) set apart.
pub(crate) fn split_known(active: Seen, known: Seen) -> Polled {
    let connected = active.len();
    let mut now = merge_known(active, known);
    let offline = now.split_off(connected);
    Polled { now, offline }
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
        let url = format!("{}{}{path}", self.base, self.prefix).replace("{site}", self.site);
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
        let active = unifi_clients(&self.get(client, "/api/s/{site}/stat/sta").await?);
        if self.offline_days == 0 {
            return Ok(Polled::now(active));
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
        Ok(split_known(active, known))
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

/// A RouterOS duration (`1w2d3h4m5s`, with `ms` parts ignored; or the older `hh:mm:ss`) in
/// seconds; `None` for `never` or anything else.
pub(crate) fn routeros_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.contains(':') {
        let mut total = 0_u64;
        for part in s.split(':') {
            total = total
                .checked_mul(60)?
                .checked_add(part.parse::<u64>().ok()?)?;
        }
        return Some(total);
    }
    let (mut total, mut n, mut any) = (0_u64, None::<u64>, false);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(d) = c.to_digit(10) {
            n = Some(n.unwrap_or(0).checked_mul(10)?.checked_add(u64::from(d))?);
            continue;
        }
        let v = n.take()?;
        let unit = match c {
            'w' => 604_800,
            'd' => 86_400,
            'h' => 3_600,
            's' => 1,
            'm' if chars.peek() == Some(&'s') => {
                chars.next();
                0
            }
            'm' => 60,
            _ => return None,
        };
        total = total.checked_add(v.checked_mul(unit)?)?;
        any = true;
    }
    (any && n.is_none()).then_some(total)
}

/// A RouterOS REST field: every value comes as a string.
fn ros<'a>(l: &'a Value, k: &str) -> Option<&'a str> {
    l.get(k).and_then(Value::as_str)
}

/// REQ: T8.2 (ADR-177) — MikroTik's DHCP leases (`GET /rest/ip/dhcp-server/lease`, a bare array):
/// the bound ones are connected; the static ones that aren't bound, with a name, last seen within
/// `max_age` seconds (`None`: none of them), are the offline devices it knows, most recently seen
/// first, at most [`OFFLINE_MAX`]. Disabled leases are skipped. A lease is named by its comment
/// (its first line), else the host name the device sent.
pub(crate) fn mikrotik_leases(v: &Value, max_age: Option<u64>) -> Polled {
    let rows = v.as_array().map_or(&[][..], Vec::as_slice);
    let mut now = Seen::new();
    let mut known: Vec<(u64, Device)> = Vec::new();
    for l in rows {
        if ros(l, "disabled") == Some("true") {
            continue;
        }
        let bound = ros(l, "status") == Some("bound");
        let pick = |keys: &[&str]| {
            keys.iter()
                .filter_map(|k| ros(l, k))
                .map(str::trim)
                .find(|s| !s.is_empty())
        };
        // A bound lease's `active-*` fields are what the device has now; `address` may be a
        // pool's name on a dynamic lease.
        let (ip, mac) = if bound {
            (
                pick(&["active-address", "address"]),
                pick(&["active-mac-address", "mac-address"]),
            )
        } else {
            (pick(&["address"]), pick(&["mac-address"]))
        };
        let Some(ip) = ip.and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
            continue;
        };
        let Some(mac) = mac.filter(|m| m.len() == 17) else {
            continue;
        };
        if ip.is_unspecified() {
            continue;
        }
        let name = [
            ros(l, "comment").and_then(|c| c.lines().next()),
            ros(l, "host-name"),
        ]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_owned);
        let dev = (mac.to_ascii_lowercase(), ip, name);
        if bound {
            now.push(dev);
            continue;
        }
        let Some(max_age) = max_age else { continue };
        if ros(l, "dynamic") == Some("true") || dev.2.is_none() {
            continue;
        }
        // Never seen (`never`): it can't be judged and stays, last (the cap bounds those).
        let ago = ros(l, "last-seen").and_then(routeros_secs);
        if ago.is_some_and(|a| a > max_age) {
            continue;
        }
        known.push((ago.unwrap_or(u64::MAX), dev));
    }
    known.sort_by_key(|k| k.0);
    known.truncate(OFFLINE_MAX);
    split_known(now, known.into_iter().map(|(_, d)| d).collect())
}

/// One poll of a MikroTik router (RouterOS v7.1+, the `www-ssl` or `www` service).
async fn poll_mikrotik(
    client: &telltale_filter::fetch::Client,
    c: &RouterConfig,
) -> Result<Polled, String> {
    let base = c.url.trim_end_matches('/');
    let user = c
        .username
        .as_deref()
        .ok_or("set username and password_file")?;
    let pass = secret(c.password_file.as_ref())?.ok_or("set password_file")?;
    let auth = format!("Basic {}", base64(format!("{user}:{pass}").as_bytes()));
    // Only the fields used, so a router with thousands of leases answers less.
    let url = format!(
        "{base}/rest/ip/dhcp-server/lease?.proplist=address,active-address,mac-address,active-mac-address,host-name,comment,status,dynamic,disabled,last-seen"
    );
    let req = http::Request::get(url.as_str())
        .header("authorization", auth.as_str())
        .header("accept", "application/json")
        .body(Vec::new())
        .map_err(|e| e.to_string())?;
    let (status, _, v) = call(client, req).await?;
    if status == http::StatusCode::UNAUTHORIZED || status == http::StatusCode::FORBIDDEN {
        return Err(format!(
            "{base}: HTTP {status} (check the username, the password, and that the user's group has the read, api and rest-api policies)"
        ));
    }
    if status == http::StatusCode::NOT_FOUND {
        return Err(format!(
            "{base}/rest: HTTP 404 (the REST API needs RouterOS v7.1 or later)"
        ));
    }
    if !status.is_success() || !v.is_array() {
        return Err(format!("{base}/rest/ip/dhcp-server/lease: HTTP {status}"));
    }
    let max_age = (c.offline_days > 0).then(|| u64::from(c.offline_days) * 86_400);
    Ok(mikrotik_leases(&v, max_age))
}

/// The leases view from every router's last answer. REQ: T8.2 (ADR-166) — an offline client
/// only names an address no router reports as connected, and is marked, so it isn't "seen".
fn rebuild(parts: &HashMap<String, Polled>, view: &ArcSwap<Leases>) {
    let lease = |d: &Device, offline: bool| Lease {
        mac: d.0.clone(),
        ip: d.1,
        hostname: d.2.clone(),
        expires: 0,
        offline,
    };
    let mut m = Leases::new();
    for p in parts.values() {
        for d in &p.now {
            m.insert(d.1, lease(d, false));
        }
    }
    for p in parts.values() {
        for d in &p.offline {
            m.entry(d.1).or_insert_with(|| lease(d, true));
        }
    }
    view.store(Arc::new(m));
}

/// Polls every `[[router]]` until `stop`. `resolver_pod`: a Helm resolver pod, which has the
/// routers' settings but not their key files (ADR-120), logs its failures as info; the
/// controller, which serves the names in the UI, warns.
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
    let mut failing: HashMap<String, bool> = HashMap::new();
    // The routers last read: one removed, or now pointing at another device (type, address,
    // site), drops its answer, so no names linger from a router that's gone (ADR-176). Other
    // changes (credentials, TLS, timing) keep it until the next answer replaces it.
    let mut read_with: Vec<RouterConfig> = Vec::new();
    loop {
        let routers = routers_now();
        let same_device = |a: &RouterConfig, b: &RouterConfig| {
            a.name == b.name && a.kind == b.kind && a.url == b.url && a.site == b.site
        };
        let kept = |n: &str| {
            routers
                .iter()
                .any(|r| r.name.as_str() == n && read_with.iter().any(|w| same_device(w, r)))
        };
        parts.retain(|n, _| kept(n));
        failing.retain(|n, _| kept(n));
        read_with.clone_from(&routers);
        let interval = routers
            .iter()
            .map(|r| r.interval_secs.max(30))
            .min()
            .unwrap_or(300);
        for r in &routers {
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
                RouterKind::Mikrotik => poll_mikrotik(&client, r).await,
            };
            let was_failing = failing.get(r.name.as_str()).copied().unwrap_or(false);
            match result {
                Ok(seen) => {
                    if was_failing || !parts.contains_key(r.name.as_str()) {
                        info!(router = %r.name, devices = seen.now.len(), offline = seen.offline.len(), "router integration: devices read");
                    }
                    parts.insert(r.name.to_string(), seen);
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
        rebuild(&parts, &view);
        // A router that failed (it may still be booting) is asked again soon.
        let wait = if failing.values().any(|f| *f) {
            interval.min(15)
        } else {
            interval
        };
        // REQ: T8.2 (ADR-176) — until the next read, or sooner when the routers change.
        let until = tokio::time::Instant::now() + Duration::from_secs(u64::from(wait));
        while tokio::time::Instant::now() < until {
            tokio::select! {
                _ = stop.changed() => return,
                () = tokio::time::sleep(CHANGE_CHECK.min(until - tokio::time::Instant::now())) => {}
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
            merge_known(active, known),
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
    fn split_known_keeps_offline_apart_and_capped() {
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
        let polled = split_known(active, known);
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
            },
        );
        parts.insert(
            "other".to_owned(),
            Polled {
                now: Seen::new(),
                offline: vec![dev("aa:00:00:00:00:03", [10, 0, 0, 5], "Gone laptop")],
            },
        );
        let view = ArcSwap::from_pointee(Leases::new());
        rebuild(&parts, &view);
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

    /// REQ: T8.2 (ADR-177) — RouterOS durations, both spellings; `never` is no date.
    #[test]
    fn routeros_durations() {
        assert_eq!(
            routeros_secs("1w2d3h4m5s"),
            Some(604_800 + 2 * 86_400 + 3 * 3_600 + 245)
        );
        assert_eq!(routeros_secs("5m33s"), Some(333));
        assert_eq!(routeros_secs("2s340ms"), Some(2));
        assert_eq!(routeros_secs("01:02:03"), Some(3_723));
        assert_eq!(routeros_secs("never"), None);
        assert_eq!(routeros_secs(""), None);
        assert_eq!(routeros_secs("5"), None);
    }

    /// REQ: T8.2 (ADR-177) — MikroTik leases: bound ones are connected (their active address and
    /// MAC), named by the comment over the host name; a static lease not bound now is offline,
    /// kept when named and seen within the window (or never seen), never over a connected
    /// device's address; dynamic leases that aren't bound, and disabled ones, are skipped.
    #[test]
    fn mikrotik_leases_bound_and_static() {
        let v = serde_json::json!([
            {".id": "*1", "address": "192.168.88.10", "active-address": "192.168.88.10",
             "mac-address": "AA:BB:CC:00:00:01", "active-mac-address": "AA:BB:CC:00:00:01",
             "host-name": "android-1", "comment": "Kitchen tablet\nsecond line", "status": "bound",
             "dynamic": "false", "disabled": "false", "last-seen": "12s"},
            {".id": "*2", "address": "pool1", "active-address": "192.168.88.200",
             "mac-address": "aa:bb:cc:00:00:02", "active-mac-address": "aa:bb:cc:00:00:02",
             "host-name": "roku", "status": "bound", "dynamic": "true", "disabled": "false"},
            {".id": "*3", "address": "192.168.88.20", "mac-address": "aa:bb:cc:00:00:03",
             "comment": "Printer", "status": "waiting", "dynamic": "false", "disabled": "false",
             "last-seen": "2d4h"},
            {".id": "*4", "address": "192.168.88.21", "mac-address": "aa:bb:cc:00:00:04",
             "host-name": "old-laptop", "status": "waiting", "dynamic": "false",
             "disabled": "false", "last-seen": "9w"},
            {".id": "*5", "address": "192.168.88.22", "mac-address": "aa:bb:cc:00:00:05",
             "status": "waiting", "dynamic": "false", "disabled": "false", "last-seen": "1h"},
            {".id": "*6", "address": "192.168.88.23", "mac-address": "aa:bb:cc:00:00:06",
             "comment": "Spare phone", "status": "waiting", "dynamic": "false",
             "disabled": "false", "last-seen": "never"},
            {".id": "*7", "address": "192.168.88.10", "mac-address": "aa:bb:cc:00:00:07",
             "comment": "Moved away", "status": "waiting", "dynamic": "false",
             "disabled": "false", "last-seen": "1d"},
            {".id": "*8", "address": "192.168.88.24", "mac-address": "aa:bb:cc:00:00:08",
             "comment": "Turned off", "status": "waiting", "dynamic": "false",
             "disabled": "true", "last-seen": "1h"},
            {".id": "*9", "address": "192.168.88.25", "mac-address": "aa:bb:cc:00:00:09",
             "host-name": "expired", "status": "waiting", "dynamic": "true",
             "disabled": "false", "last-seen": "1h"}
        ]);
        let dev = |m: &str, ip: [u8; 4], n: &str| -> Device {
            (m.to_owned(), Ipv4Addr::from(ip), Some(n.to_owned()))
        };
        let p = mikrotik_leases(&v, Some(30 * 86_400));
        assert_eq!(
            p.now,
            vec![
                dev("aa:bb:cc:00:00:01", [192, 168, 88, 10], "Kitchen tablet"),
                dev("aa:bb:cc:00:00:02", [192, 168, 88, 200], "roku"),
            ]
        );
        assert_eq!(
            p.offline,
            vec![
                dev("aa:bb:cc:00:00:03", [192, 168, 88, 20], "Printer"),
                dev("aa:bb:cc:00:00:06", [192, 168, 88, 23], "Spare phone"),
            ]
        );
        // `offline_days = 0`: only the connected devices.
        let p = mikrotik_leases(&v, None);
        assert_eq!((p.now.len(), p.offline.len()), (2, 0));
        // Not a lease list (an error object): nothing.
        let p = mikrotik_leases(&serde_json::json!({"error": 401}), Some(1));
        assert_eq!((p.now.len(), p.offline.len()), (0, 0));
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
}
