//! Iterative resolver (REQ: DNS-012, UPS-012; `spec/03` §6; T7.15).
//!
//! Resolves from the root servers down, the way `unbound` does for a Pi-hole, so TelltaleDNS
//! needs no forwarder: `url = "recursive://"` makes it an upstream like any other.
//! - **QNAME minimization** (RFC 9156, relaxed): each server sees only one more label than
//!   it needs (`com` for the root, `example.com` for `com`), asked as `A`; a minimized query
//!   that fails (NXDOMAIN, errors) falls back to the full name.
//! - **Spoofing defenses:** a random port and ID per query (RFC 5452), records accepted only
//!   in the answering server's bailiwick, glue only for server names under the referring
//!   zone, and optional 0x20 letter-case randomization (servers that don't echo the case are
//!   remembered and asked without it).
//! - **Server choice** by smoothed RTT; a timeout or lame answer moves to the next server.
//!   A server slower than usual is hedged: the next one is asked too, and the first useful
//!   answer wins (T9.8).
//! - **Root priming** (RFC 8109, T9.8): the root servers' current names and addresses are
//!   asked of the built-in hints once, then cached like any zone cut (and asked again a day
//!   later), so a changed root server address doesn't need a new build.
//! - **Limits:** 16 CNAME/DNAME hops, 32 referrals per lookup, at most 4 nested lookups for
//!   server names, and 96 queries per client question.
//! - **Caches:** zone cuts with their server addresses and server-name addresses (bounded,
//!   TTL-capped); final answers go to the server's answer cache like any upstream's.
//!
//! DNSSEC: with DO set, signatures, DS sets, and NSEC/NSEC3 proofs are passed through, so the
//! validator above (DNS-011) checks the chain from the root's trust anchor.

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]

mod cache;
pub mod msg;
mod net;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::{Duration, Instant};

use telltale_proto::{HEADER_LEN, NameBuf, rcode, read_name, rtype};
use tracing::debug;

use crate::cache::Caches;
use crate::msg::{Outcome, Rr};
pub use net::NetError;

/// The root servers (IANA root hints, `named.root`): IPv4, then IPv6.
pub const ROOT_HINTS_V4: [[u8; 4]; 13] = [
    [198, 41, 0, 4],
    [170, 247, 170, 2],
    [192, 33, 4, 12],
    [199, 7, 91, 13],
    [192, 203, 230, 10],
    [192, 5, 5, 241],
    [192, 112, 36, 4],
    [198, 97, 190, 53],
    [192, 36, 148, 17],
    [192, 58, 128, 30],
    [193, 0, 14, 129],
    [199, 7, 83, 42],
    [202, 12, 27, 33],
];
pub const ROOT_HINTS_V6: [&str; 13] = [
    "2001:503:ba3e::2:30",
    "2801:1b8:10::b",
    "2001:500:2::c",
    "2001:500:2d::d",
    "2001:500:a8::e",
    "2001:500:2f::f",
    "2001:500:12::d0d",
    "2001:500:1::53",
    "2001:7fe::53",
    "2001:503:c27::2:30",
    "2001:7fd::1",
    "2001:500:9f::42",
    "2001:dc3::35",
];

const MAX_CNAME: u32 = 16;
const MAX_REFERRALS: u32 = 32;
const MAX_DEPTH: u8 = 4;
const MAX_QUERIES: u32 = 96;
/// Minimized steps before the rest of the name is sent at once (RFC 9156 §2.3).
const MAX_MINIMIZE: usize = 10;
/// Servers tried for one question before giving up.
const MAX_TRIES: usize = 4;

/// Resolver settings (`[[upstream]]` with `url = "recursive://"`).
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // independent on/off switches, not a state machine
pub struct Settings {
    /// RFC 9156 QNAME minimization (on by default).
    pub qname_minimization: bool,
    /// 0x20 letter-case randomization (off by default: a few servers don't echo the case).
    pub case_randomization: bool,
    /// Ask servers over IPv6 too (off by default: many home networks have no IPv6 route).
    pub ipv6: bool,
    /// The root servers to start from.
    pub roots: Vec<IpAddr>,
    /// The port servers listen on (53; tests use another).
    pub port: u16,
    /// The most a single server is waited for.
    pub server_timeout: Duration,
    /// REQ: DNS-012 (T9.8) — RFC 8109 root priming (on by default).
    pub prime: bool,
    /// Ask the next server too when one is slower than usual (on by default).
    pub hedge: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            qname_minimization: true,
            case_randomization: false,
            ipv6: false,
            roots: ROOT_HINTS_V4.iter().map(|a| IpAddr::from(*a)).collect(),
            port: 53,
            server_timeout: Duration::from_millis(1200),
            prime: true,
            hedge: true,
        }
    }
}

impl Settings {
    /// The default settings, with the IPv6 root addresses added when `ipv6`.
    #[must_use]
    pub fn with_ipv6(mut self, ipv6: bool) -> Self {
        self.ipv6 = ipv6;
        if ipv6 {
            self.roots.extend(
                ROOT_HINTS_V6
                    .iter()
                    .filter_map(|a| a.parse::<IpAddr>().ok()),
            );
        }
        self
    }
}

/// Why a question couldn't be resolved (it becomes SERVFAIL).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("no server for {0} answered usefully")]
    NoServer(String),
    #[error("too many referrals, CNAMEs, or queries (a loop or a misconfigured zone)")]
    Limit,
    #[error("malformed question")]
    Question,
}

/// The work one client question may cause.
#[derive(Debug, Default)]
struct Work {
    queries: u32,
}

impl Work {
    fn spend(&mut self) -> Result<(), Error> {
        self.queries += 1;
        if self.queries > MAX_QUERIES {
            Err(Error::Limit)
        } else {
            Ok(())
        }
    }
}

/// A resolution's result: RCODE, the answer section, the authority section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub rcode: u16,
    pub answer: Vec<Rr>,
    pub authority: Vec<Rr>,
}

type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The resolver. Share one per upstream (it holds the caches).
#[derive(Debug)]
pub struct Recursor {
    settings: Settings,
    caches: Caches,
    /// When priming was last tried (it's not tried again for a minute after a failure).
    primed_at: parking_lot::Mutex<Option<Instant>>,
}

/// `name` cut to its last `n` labels.
fn suffix(name: &NameBuf, n: usize) -> NameBuf {
    let total = name.label_count();
    let wire = name.as_wire();
    let mut pos = 0usize;
    for _ in 0..total.saturating_sub(n) {
        pos += 1 + usize::from(wire[pos]);
    }
    let mut out = NameBuf::default();
    let _ = read_name(wire, pos, &mut out);
    out
}

impl Recursor {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            caches: Caches::default(),
            primed_at: parking_lot::Mutex::new(None),
        }
    }

    /// REQ: DNS-012 (T9.8) — RFC 8109: asks the hints for the root's NS set and its
    /// addresses (the glue in the same answer, else a lookup of the names), and caches it as
    /// the root zone cut. Quiet on failure: the hints keep working.
    async fn prime(&self, work: &mut Work) {
        let root = NameBuf::default();
        if !self.settings.prime || self.caches.closest(&root, false).is_some() {
            return;
        }
        {
            let mut at = self.primed_at.lock();
            if at.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
                return;
            }
            *at = Some(Instant::now());
        }
        for (ip, _, _) in self
            .caches
            .order(&self.settings.roots)
            .into_iter()
            .take(MAX_TRIES)
        {
            if work.spend().is_err() {
                return;
            }
            let addr = SocketAddr::new(ip, self.settings.port);
            let Ok(resp) = net::ask(
                addr,
                &root,
                rtype::NS,
                false,
                false,
                self.settings.server_timeout,
            )
            .await
            else {
                continue;
            };
            let Some(p) = msg::parse(&resp) else { continue };
            let ns: Vec<&Rr> = p
                .answer
                .iter()
                .filter(|r| r.rtype == rtype::NS && r.name.is_root())
                .collect();
            if ns.is_empty() {
                continue;
            }
            let ttl = ns.iter().map(|r| r.ttl).min().unwrap_or(86_400);
            let names: Vec<NameBuf> = ns.iter().filter_map(|r| r.target()).collect();
            let glue: Vec<(NameBuf, IpAddr)> = p
                .additional
                .iter()
                .filter(|r| names.contains(&r.name))
                .filter_map(|r| r.addr().map(|a| (r.name, a)))
                .collect();
            let addrs = self.delegation(&root, &names, &glue, work, 0).await;
            if addrs.is_empty() {
                continue;
            }
            debug!(servers = addrs.len(), "root priming");
            self.caches.put_zone(root, names, addrs, ttl);
            return;
        }
    }

    /// Zone cuts cached (metrics, tests).
    pub fn cached_zones(&self) -> usize {
        self.caches.zones()
    }

    /// Answers the client `query` (wire format: one question, maybe OPT): the full response,
    /// with the query's ID and question, RA set.
    pub async fn answer(&self, query: &[u8]) -> Result<Vec<u8>, Error> {
        let mut name = NameBuf::default();
        let end = telltale_proto::read_name_uncompressed(query, HEADER_LEN, &mut name)
            .map_err(|_| Error::Question)?;
        let qtype = query
            .get(end..end + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .ok_or(Error::Question)?;
        let header = telltale_proto::Header::parse(query).ok_or(Error::Question)?;
        let opt_at = end + 4;
        let dnssec_ok = header.arcount > 0 && query.get(opt_at + 7).is_some_and(|b| b & 0x80 != 0);
        let mut work = Work::default();
        self.prime(&mut work).await;
        let r = self.lookup(name, qtype, dnssec_ok, &mut work, 0).await?;
        msg::encode(query, r.rcode, &r.answer, &r.authority).ok_or(Error::Question)
    }

    /// Resolves `name`/`qtype` from the closest known zone cut.
    pub async fn resolve(
        &self,
        name: NameBuf,
        qtype: u16,
        dnssec_ok: bool,
    ) -> Result<Resolved, Error> {
        let mut work = Work::default();
        self.prime(&mut work).await;
        self.lookup(name, qtype, dnssec_ok, &mut work, 0).await
    }

    #[allow(clippy::too_many_lines)] // one state machine: referrals, minimization, chasing
    fn lookup<'a>(
        &'a self,
        name: NameBuf,
        qtype: u16,
        dnssec_ok: bool,
        work: &'a mut Work,
        depth: u8,
    ) -> Boxed<'a, Result<Resolved, Error>> {
        Box::pin(async move {
            let mut answer: Vec<Rr> = Vec::new();
            let mut current = name;
            let mut hops = 0u32;
            'chase: loop {
                let (mut zone, mut servers) = self
                    .start(&current, qtype == rtype::DS, work, depth)
                    .await?;
                let mut minimize = self.settings.qname_minimization;
                let mut labels = zone.label_count() + 1;
                let mut steps = 0usize;
                let mut referrals = 0u32;
                loop {
                    let full = !minimize || labels >= current.label_count();
                    let (qn, qt) = if full {
                        (current, qtype)
                    } else {
                        (suffix(&current, labels), rtype::A)
                    };
                    let outcome = match self
                        .ask(&servers, &qn, qt, dnssec_ok && full, &zone, work)
                        .await
                    {
                        Ok((o, _)) => o,
                        Err(Error::Limit) => return Err(Error::Limit),
                        // Relaxed mode: servers that fail a minimized query get the full one.
                        Err(_) if !full => {
                            minimize = false;
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    match outcome {
                        Outcome::Referral {
                            child,
                            ns,
                            glue,
                            ttl,
                            ds,
                        } => {
                            referrals += 1;
                            if referrals > MAX_REFERRALS {
                                return Err(Error::Limit);
                            }
                            if qtype == rtype::DS && full && child == current {
                                // The parent answered with a delegation to the very name: it
                                // has no DS for it (an unsigned delegation, or one it omits).
                                if !ds.is_empty() {
                                    answer.extend(ds);
                                    return Ok(Resolved {
                                        rcode: rcode::NOERROR,
                                        answer,
                                        authority: Vec::new(),
                                    });
                                }
                            }
                            let addrs = self.delegation(&child, &ns, &glue, work, depth).await;
                            self.caches.put_zone(child, ns, addrs.clone(), ttl);
                            if addrs.is_empty() {
                                return Err(Error::NoServer(child.display().to_string()));
                            }
                            debug!(zone = %child.display(), servers = addrs.len(), "referral");
                            zone = child;
                            servers = addrs;
                            labels = zone.label_count() + 1;
                        }
                        // REQ: DNS-012 — RFC 9156: a minimized query only finds the next cut.
                        _ if !full => {
                            match outcome {
                                Outcome::NoData { .. } | Outcome::Answer { .. } => {
                                    steps += 1;
                                    labels = if steps >= MAX_MINIMIZE {
                                        current.label_count()
                                    } else {
                                        labels + 1
                                    };
                                }
                                // Relaxed mode: NXDOMAIN or anything odd → ask the full name.
                                _ => minimize = false,
                            }
                        }
                        Outcome::Answer { records, next } => {
                            answer.extend(records);
                            match next {
                                Some(t) => {
                                    hops += 1;
                                    if hops > MAX_CNAME || answer.len() > 64 {
                                        return Err(Error::Limit);
                                    }
                                    current = t;
                                    continue 'chase;
                                }
                                None => {
                                    return Ok(Resolved {
                                        rcode: rcode::NOERROR,
                                        answer,
                                        authority: Vec::new(),
                                    });
                                }
                            }
                        }
                        Outcome::NoData { chain, authority } => {
                            answer.extend(chain);
                            return Ok(Resolved {
                                rcode: rcode::NOERROR,
                                answer,
                                authority,
                            });
                        }
                        Outcome::NxDomain { chain, authority } => {
                            answer.extend(chain);
                            return Ok(Resolved {
                                rcode: rcode::NXDOMAIN,
                                answer,
                                authority,
                            });
                        }
                        Outcome::Lame => return Err(Error::NoServer(zone.display().to_string())),
                    }
                }
            }
        })
    }

    /// Where to start for `name`: the deepest cached zone cut with addresses (resolving its
    /// server names when it has none), else the root.
    async fn start(
        &self,
        name: &NameBuf,
        parent_only: bool,
        work: &mut Work,
        depth: u8,
    ) -> Result<(NameBuf, Vec<IpAddr>), Error> {
        let mut at = *name;
        let mut skip = parent_only;
        loop {
            match self.caches.closest(&at, skip) {
                Some((zone, d)) if !d.addrs.is_empty() => return Ok((zone, self.usable(&d.addrs))),
                Some((zone, d)) => {
                    let addrs = self.delegation(&zone, &d.ns, &[], work, depth).await;
                    if !addrs.is_empty() {
                        self.caches.add_zone_addrs(&zone, &addrs);
                        return Ok((zone, addrs));
                    }
                    if zone.is_root() {
                        break;
                    }
                    // Try the next cut up.
                    at = zone;
                    skip = true;
                }
                None => break,
            }
        }
        Ok((NameBuf::default(), self.settings.roots.clone()))
    }

    fn usable(&self, addrs: &[IpAddr]) -> Vec<IpAddr> {
        addrs
            .iter()
            .copied()
            .filter(|a| self.settings.ipv6 || a.is_ipv4())
            .collect()
    }

    /// Addresses for a zone's servers: glue first, then cached addresses, then (if neither)
    /// a lookup of the server names, stopping at the first that resolves.
    async fn delegation(
        &self,
        child: &NameBuf,
        ns: &[NameBuf],
        glue: &[(NameBuf, IpAddr)],
        work: &mut Work,
        depth: u8,
    ) -> Vec<IpAddr> {
        let mut addrs: Vec<IpAddr> = glue
            .iter()
            .map(|(_, a)| *a)
            .filter(|a| self.settings.ipv6 || a.is_ipv4())
            .collect();
        for n in ns {
            if let Some(a) = self.caches.addrs(n) {
                addrs.extend(self.usable(&a));
            }
        }
        addrs.sort_unstable();
        addrs.dedup();
        if !addrs.is_empty() || depth >= MAX_DEPTH {
            return addrs;
        }
        for n in ns {
            // A server inside the zone it serves needs glue; without it, it's unreachable.
            if n.is_subdomain_of(child) {
                continue;
            }
            let mut found = Vec::new();
            let types: &[u16] = if self.settings.ipv6 {
                &[rtype::A, rtype::AAAA]
            } else {
                &[rtype::A]
            };
            for &t in types {
                if let Ok(r) = self.lookup(*n, t, false, work, depth + 1).await {
                    let ttl = r.answer.iter().map(|x| x.ttl).min().unwrap_or(300);
                    let a: Vec<IpAddr> = r.answer.iter().filter_map(Rr::addr).collect();
                    if !a.is_empty() {
                        self.caches.put_addrs(*n, a.clone(), ttl);
                        found.extend(a);
                    }
                }
            }
            if !found.is_empty() {
                return found;
            }
        }
        Vec::new()
    }

    /// Asks `servers` (fastest first) until one gives a usable answer for `zone`. A server
    /// slower than its usual (1.5 × its smoothed RTT, at least 150 ms) is hedged: the next one
    /// is asked as well, and the first usable answer wins (T9.8).
    async fn ask(
        &self,
        servers: &[IpAddr],
        qn: &NameBuf,
        qt: u16,
        dnssec_ok: bool,
        zone: &NameBuf,
        work: &mut Work,
    ) -> Result<(Outcome, IpAddr), Error> {
        let order: Vec<_> = self
            .caches
            .order(servers)
            .into_iter()
            .take(MAX_TRIES)
            .collect();
        let mut i = 0;
        while i < order.len() {
            let (ip, srtt_us, no_case) = order[i];
            work.spend()?;
            let first = self.try_server(ip, srtt_us, no_case, qn, qt, dnssec_ok, zone);
            tokio::pin!(first);
            let next = order.get(i + 1).copied().filter(|_| self.settings.hedge);
            let Some((ip2, srtt2, no_case2)) = next else {
                if let Some(o) = first.await {
                    return Ok(o);
                }
                i += 1;
                continue;
            };
            let hedge_after = srtt_us.map_or(Duration::from_millis(400), |s| {
                (Duration::from_micros(u64::from(s)) * 3 / 2).max(Duration::from_millis(150))
            });
            tokio::select! {
                r = &mut first => {
                    if let Some(o) = r {
                        return Ok(o);
                    }
                    // Failed quickly: the next server, hedged in turn.
                    i += 1;
                    continue;
                }
                () = tokio::time::sleep(hedge_after) => {}
            }
            // REQ: DNS-012 (T9.8) — slower than usual: ask the next server as well.
            work.spend()?;
            let second = self.try_server(ip2, srtt2, no_case2, qn, qt, dnssec_ok, zone);
            tokio::pin!(second);
            let won = tokio::select! {
                r = &mut first => match r {
                    Some(o) => Some(o),
                    None => second.await,
                },
                r = &mut second => match r {
                    Some(o) => Some(o),
                    None => first.await,
                },
            };
            if let Some(o) = won {
                return Ok(o);
            }
            i += 2;
        }
        Err(Error::NoServer(zone.display().to_string()))
    }

    /// One server, once (twice when it breaks 0x20): its usable outcome, or `None`. Records
    /// the server's RTT or timeout.
    #[allow(clippy::too_many_arguments)]
    async fn try_server(
        &self,
        ip: IpAddr,
        srtt_us: Option<u32>,
        no_case: bool,
        qn: &NameBuf,
        qt: u16,
        dnssec_ok: bool,
        zone: &NameBuf,
    ) -> Option<(Outcome, IpAddr)> {
        let timeout = match srtt_us {
            None => self.settings.server_timeout,
            Some(s) => (Duration::from_micros(u64::from(s)) * 3 + Duration::from_millis(100))
                .clamp(Duration::from_millis(250), self.settings.server_timeout),
        };
        let addr = SocketAddr::new(ip, self.settings.port);
        let mix = self.settings.case_randomization && !no_case;
        let t0 = Instant::now();
        let mut res = net::ask(addr, qn, qt, dnssec_ok, mix, timeout).await;
        if res == Err(NetError::CaseMismatch) {
            // REQ: DNS-012 — 0x20: this server changes the case; ask it plainly.
            self.caches.no_case(ip);
            res = net::ask(addr, qn, qt, dnssec_ok, false, timeout).await;
        }
        let Ok(resp) = res else {
            self.caches.record(ip, None, timeout);
            return None;
        };
        self.caches.record(ip, Some(t0.elapsed()), timeout);
        let p = msg::parse(&resp)?;
        let o = msg::classify(&p, qn, qt, zone);
        (o != Outcome::Lame).then_some((o, ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_012_suffix() {
        let n = NameBuf::from_presentation("a.b.example.com").unwrap();
        assert_eq!(
            suffix(&n, 2),
            NameBuf::from_presentation("example.com").unwrap()
        );
        assert_eq!(suffix(&n, 0), NameBuf::default());
        assert_eq!(suffix(&n, 9), n);
    }
}
