//! Local DNS records, answered authoritatively before the cache (REQ: DNS-010, `spec/03` §3.5).
//!
//! Records come from `[[record]]` entries and hosts files. Lookup is allocation-free: an exact
//! map keyed by the lowercase wire name, then wildcard entries (`*.parent`) found by walking up
//! the name's labels. Names that aren't local fall through to the rest of the pipeline.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use telltale_config::Config;
use telltale_proto::{EdnsOut, NameBuf, Query, ResponseBuilder, rcode, rtype};

/// Max CNAME hops followed inside local data.
const MAX_CHASE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rr {
    rtype: u16,
    ttl: u32,
    rdata: Box<[u8]>,
    /// Target for CNAME records, for chasing within local data.
    target: Option<NameBuf>,
}

/// All local records.
#[derive(Debug, Default, Clone)]
pub struct LocalData {
    exact: HashMap<Box<[u8]>, Vec<Rr>>,
    /// Keyed by the parent name of `*.parent`.
    wildcard: HashMap<Box<[u8]>, Vec<Rr>>,
    count: usize,
}

/// Problems loading local data: hard errors and skipped lines.
#[derive(Debug, Default)]
pub struct LoadReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

fn parse_name(s: &str) -> Result<NameBuf, String> {
    NameBuf::from_presentation(s.trim()).map_err(|e| format!("invalid name `{s}`: {e}"))
}

/// Encodes a record value into wire RDATA.
/// (type, RDATA, CNAME target)
type Encoded = (u16, Vec<u8>, Option<NameBuf>);

fn encode(rt: &str, value: &str) -> Result<Encoded, String> {
    let v = value.trim();
    let mut parts = v.split_whitespace();
    let mut next_u16 = |what: &str| -> Result<u16, String> {
        parts
            .next()
            .ok_or_else(|| format!("missing {what}"))?
            .parse::<u16>()
            .map_err(|_| format!("invalid {what}"))
    };
    Ok(match rt.to_ascii_uppercase().as_str() {
        "A" => {
            let ip: Ipv4Addr = v
                .parse()
                .map_err(|_| format!("`{v}` is not an IPv4 address"))?;
            (rtype::A, ip.octets().to_vec(), None)
        }
        "AAAA" => {
            let ip: Ipv6Addr = v
                .parse()
                .map_err(|_| format!("`{v}` is not an IPv6 address"))?;
            (rtype::AAAA, ip.octets().to_vec(), None)
        }
        "CNAME" => {
            let n = parse_name(v)?;
            (rtype::CNAME, n.as_wire().to_vec(), Some(n))
        }
        "PTR" => (rtype::PTR, parse_name(v)?.as_wire().to_vec(), None),
        "TXT" => {
            if v.is_empty() {
                return Err("TXT value must not be empty".into());
            }
            let mut rd = Vec::with_capacity(v.len() + v.len() / 255 + 1);
            for chunk in v.as_bytes().chunks(255) {
                rd.push(u8::try_from(chunk.len()).unwrap_or(u8::MAX)); // chunks are <= 255
                rd.extend_from_slice(chunk);
            }
            (rtype::TXT, rd, None)
        }
        "MX" => {
            let pref = next_u16("preference")?;
            let exch = parse_name(parts.next().ok_or("missing exchange")?)?;
            let mut rd = pref.to_be_bytes().to_vec();
            rd.extend_from_slice(exch.as_wire());
            (rtype::MX, rd, None)
        }
        "SRV" => {
            let (prio, weight, port) = (
                next_u16("priority")?,
                next_u16("weight")?,
                next_u16("port")?,
            );
            let target = parse_name(parts.next().ok_or("missing target")?)?;
            let mut rd = Vec::new();
            for x in [prio, weight, port] {
                rd.extend_from_slice(&x.to_be_bytes());
            }
            rd.extend_from_slice(target.as_wire());
            (rtype::SRV, rd, None)
        }
        other => {
            return Err(format!(
                "unsupported record type `{other}` (A, AAAA, CNAME, PTR, TXT, MX, SRV)"
            ));
        }
    })
}

/// `192.168.1.10` → `10.1.168.192.in-addr.arpa`; IPv6 → nibble form under `ip6.arpa`.
pub fn reverse_name(ip: IpAddr) -> NameBuf {
    let text = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for b in v6.octets().iter().rev() {
                let _ = write!(s, "{:x}.{:x}.", b & 0xF, b >> 4);
            }
            s.push_str("ip6.arpa");
            s
        }
    };
    NameBuf::from_presentation(&text).unwrap_or_default()
}

impl LocalData {
    /// Builds from `[[record]]` entries and `[local] hosts_files`.
    pub fn from_config(cfg: &Config) -> (Self, LoadReport) {
        let mut data = Self::default();
        let mut report = LoadReport::default();
        let ttl_default = cfg.local.default_ttl;
        for (i, r) in cfg.record.iter().enumerate() {
            let path = format!("record[{i}]");
            if let Err(e) = data.add(&r.name, &r.rtype, &r.value, r.ttl.unwrap_or(ttl_default)) {
                report.errors.push(format!("{path}: {e}"));
            }
        }
        for file in &cfg.local.hosts_files {
            match std::fs::read_to_string(file.as_str()) {
                Ok(text) => data.add_hosts(&text, file.as_str(), ttl_default, &mut report),
                Err(e) => report
                    .errors
                    .push(format!("local.hosts_files: {file}: {e}")),
            }
        }
        if cfg.local.auto_ptr {
            data.generate_ptrs(ttl_default);
        }
        (data, report)
    }

    /// Adds one record. Enforces CNAME exclusivity (RFC 1034 §3.6.2).
    pub fn add(&mut self, name: &str, rt: &str, value: &str, ttl: u32) -> Result<(), String> {
        let (wild, owner) = match name.trim().strip_prefix("*.") {
            Some(rest) => (true, parse_name(rest)?),
            None if name.trim() == "*" => return Err("`*` alone is not a valid name".into()),
            None => (false, parse_name(name)?),
        };
        let (rtype, rdata, target) = encode(rt, value)?;
        let map = if wild {
            &mut self.wildcard
        } else {
            &mut self.exact
        };
        let list = map.entry(owner.as_wire().into()).or_default();
        let has_cname = list.iter().any(|r| r.rtype == rtype::CNAME);
        if (rtype == rtype::CNAME && !list.is_empty()) || (rtype != rtype::CNAME && has_cname) {
            return Err(format!(
                "`{name}`: a CNAME cannot coexist with other records for the same name"
            ));
        }
        let rr = Rr {
            rtype,
            ttl,
            rdata: rdata.into(),
            target,
        };
        if !list.contains(&rr) {
            list.push(rr);
            self.count += 1;
        }
        Ok(())
    }

    /// Imports `IP name [alias...]` lines. Skips blocklist-style entries (0.0.0.0, ::) and
    /// loopback, which aren't hosts on your network.
    pub fn add_hosts(&mut self, text: &str, origin: &str, ttl: u32, report: &mut LoadReport) {
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            let mut tok = line.split_whitespace();
            let Some(ip_s) = tok.next() else { continue };
            let Ok(ip) = ip_s.parse::<IpAddr>() else {
                report
                    .warnings
                    .push(format!("{origin}:{}: not an IP address, skipped", n + 1));
                continue;
            };
            if ip.is_unspecified() || ip.is_loopback() {
                continue;
            }
            let rt = if ip.is_ipv4() { "A" } else { "AAAA" };
            for host in tok {
                if let Err(e) = self.add(host, rt, ip_s, ttl) {
                    report.warnings.push(format!("{origin}:{}: {e}", n + 1));
                }
            }
        }
    }

    /// Adds a PTR for every exact A/AAAA record whose reverse name has no PTR yet.
    fn generate_ptrs(&mut self, ttl: u32) {
        let mut ptrs: Vec<(NameBuf, NameBuf)> = Vec::new();
        for (owner, rrs) in &self.exact {
            let mut name = NameBuf::default();
            if telltale_proto::read_name_uncompressed(owner, 0, &mut name).is_err() {
                continue;
            }
            for rr in rrs {
                let ip = match (rr.rtype, rr.rdata.len()) {
                    (rtype::A, 4) => IpAddr::V4(Ipv4Addr::new(
                        rr.rdata[0],
                        rr.rdata[1],
                        rr.rdata[2],
                        rr.rdata[3],
                    )),
                    (rtype::AAAA, 16) => {
                        let mut o = [0u8; 16];
                        o.copy_from_slice(&rr.rdata);
                        IpAddr::V6(Ipv6Addr::from(o))
                    }
                    _ => continue,
                };
                ptrs.push((reverse_name(ip), name));
            }
        }
        // Deterministic: the alphabetically first name wins for each address.
        ptrs.sort_by(|a, b| a.1.as_wire().cmp(b.1.as_wire()));
        for (rev, target) in ptrs {
            let list = self.exact.entry(rev.as_wire().into()).or_default();
            if list.iter().all(|r| r.rtype != rtype::PTR) {
                list.push(Rr {
                    rtype: rtype::PTR,
                    ttl,
                    rdata: target.as_wire().into(),
                    target: None,
                });
                self.count += 1;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Records for `name`: exact match first, then the closest wildcard. Allocation-free.
    fn lookup(&self, name: &NameBuf) -> Option<&[Rr]> {
        if self.exact.is_empty() && self.wildcard.is_empty() {
            return None;
        }
        let wire = name.as_wire();
        if let Some(v) = self.exact.get(wire) {
            return Some(v);
        }
        if self.wildcard.is_empty() {
            return None;
        }
        // Walk parents: a.b.c → b.c → c → root.
        let mut pos = 0;
        while pos < wire.len() && wire[pos] != 0 {
            pos += 1 + usize::from(wire[pos]);
            if let Some(v) = self.wildcard.get(&wire[pos..]) {
                return Some(v);
            }
        }
        None
    }

    /// REQ: DNS-018 — some name below `name` has records (an empty non-terminal exists).
    pub fn has_below(&self, name: &NameBuf) -> bool {
        let suffix = name.as_wire();
        self.exact.keys().chain(self.wildcard.keys()).any(|k| {
            k.len() > suffix.len() && k.ends_with(suffix) && {
                // `suffix` must start on a label boundary of `k`.
                let start = k.len() - suffix.len();
                let mut pos = 0;
                while pos < start {
                    pos += 1 + usize::from(k[pos]);
                }
                pos == start
            }
        })
    }

    /// Answers `q` from local data, or returns `None` if the name isn't local.
    /// AA=1; CNAMEs are followed within local data; NODATA when the name exists without the
    /// requested type.
    pub fn answer(
        &self,
        q: &Query<'_>,
        out: &mut [u8],
        edns: Option<EdnsOut<'_>>,
    ) -> Option<usize> {
        let rrs = self.lookup(&q.qname)?;
        let mut b = ResponseBuilder::new(q, out, rcode::NOERROR).ok()?;
        b.authoritative(true);
        let mut wrote = false;
        let mut current: &[Rr] = rrs;
        let mut owner: Option<NameBuf> = None;
        for _ in 0..=MAX_CHASE {
            let cname = current.iter().find(|r| r.rtype == rtype::CNAME);
            match cname {
                Some(c) if q.qtype != rtype::CNAME => {
                    b.answer_rdata(owner.as_ref(), rtype::CNAME, c.ttl, &c.rdata)
                        .ok()?;
                    wrote = true;
                    let target = c.target?;
                    match self.lookup(&target) {
                        Some(next) => {
                            owner = Some(target);
                            current = next;
                        }
                        None => break, // target is elsewhere: the client resolves it
                    }
                }
                _ => {
                    for r in current.iter().filter(|r| r.rtype == q.qtype) {
                        b.answer_rdata(owner.as_ref(), r.rtype, r.ttl, &r.rdata)
                            .ok()?;
                        wrote = true;
                    }
                    break;
                }
            }
        }
        if !wrote {
            // NODATA: the name exists locally but has no record of this type.
            let ttl = rrs.iter().map(|r| r.ttl).min().unwrap_or(300);
            b.authority_soa(ttl).ok()?;
        }
        b.finish(edns).ok()
    }
}

#[cfg(test)]
#[allow(clippy::type_complexity, clippy::assert_is_empty)]
mod tests {
    use std::net::Ipv4Addr;

    use telltale_proto::{Section, build_query, records, summarize};

    use super::*;

    fn data() -> LocalData {
        let mut d = LocalData::default();
        d.add("nas.home.arpa", "A", "192.168.1.10", 300).unwrap();
        d.add("nas.home.arpa", "AAAA", "fd00::10", 300).unwrap();
        d.add("files.home.arpa", "CNAME", "nas.home.arpa", 60)
            .unwrap();
        d.add("ext.home.arpa", "CNAME", "example.com", 60).unwrap();
        d.add("*.dev.home.arpa", "A", "192.168.1.20", 30).unwrap();
        d.add("home.arpa", "MX", "10 mail.home.arpa", 300).unwrap();
        d.add("_sip._udp.home.arpa", "SRV", "0 5 5060 pbx.home.arpa", 300)
            .unwrap();
        d.add("home.arpa", "TXT", "v=spf1 -all", 300).unwrap();
        d.generate_ptrs(300);
        d
    }

    fn ask(d: &LocalData, name: &str, qtype: u16) -> Option<(u16, Vec<(u16, Vec<u8>)>, bool)> {
        let mut qb = [0u8; 512];
        let n = NameBuf::from_presentation(name).unwrap();
        let len = build_query(&mut qb, 1, &n, qtype, 1, true, None).unwrap();
        let q = telltale_proto::parse_query(&qb[..len]).unwrap();
        let mut out = [0u8; 1500];
        let rlen = d.answer(&q, &mut out, None)?;
        let resp = &out[..rlen];
        let s = summarize(resp).unwrap();
        let ans = records(resp)
            .unwrap()
            .map(Result::unwrap)
            .filter(|r| r.section == Section::Answer)
            .map(|r| (r.rtype, r.rdata(resp).to_vec()))
            .collect();
        Some((s.rcode, ans, s.header.flags.aa()))
    }

    #[test]
    fn dns_010_exact_records_answered_authoritatively() {
        let d = data();
        let (rc, ans, aa) = ask(&d, "NAS.home.arpa", rtype::A).unwrap();
        assert_eq!((rc, aa), (rcode::NOERROR, true));
        assert_eq!(
            ans,
            vec![(rtype::A, Ipv4Addr::new(192, 168, 1, 10).octets().to_vec())]
        );
        let (_, ans, _) = ask(&d, "nas.home.arpa", rtype::AAAA).unwrap();
        assert_eq!(ans[0].0, rtype::AAAA);
        assert!(
            ask(&d, "unknown.home.arpa", rtype::A).is_none(),
            "non-local names fall through"
        );
    }

    #[test]
    fn dns_010_nodata_for_missing_type() {
        let (rc, ans, _) = ask(&data(), "nas.home.arpa", rtype::TXT).unwrap();
        assert_eq!(rc, rcode::NOERROR);
        assert!(ans.is_empty());
    }

    #[test]
    fn dns_010_cname_chased_locally_or_left_to_client() {
        let d = data();
        let (_, ans, _) = ask(&d, "files.home.arpa", rtype::A).unwrap();
        assert_eq!(
            ans.iter().map(|a| a.0).collect::<Vec<_>>(),
            vec![rtype::CNAME, rtype::A]
        );
        let (_, ans, _) = ask(&d, "ext.home.arpa", rtype::A).unwrap();
        assert_eq!(
            ans.iter().map(|a| a.0).collect::<Vec<_>>(),
            vec![rtype::CNAME]
        );
    }

    #[test]
    fn dns_010_wildcards_match_names_below() {
        let d = data();
        assert!(ask(&d, "app.dev.home.arpa", rtype::A).is_some());
        assert!(ask(&d, "a.b.dev.home.arpa", rtype::A).is_some());
        assert!(
            ask(&d, "dev.home.arpa", rtype::A).is_none(),
            "wildcard doesn't match its parent"
        );
    }

    #[test]
    fn dns_010_auto_ptr_mx_srv_txt() {
        let d = data();
        let (_, ans, _) = ask(&d, "10.1.168.192.in-addr.arpa", rtype::PTR).unwrap();
        assert_eq!(
            ans[0].1,
            NameBuf::from_presentation("nas.home.arpa")
                .unwrap()
                .as_wire()
        );
        let v6 = reverse_name("fd00::10".parse().unwrap());
        assert!(v6.display().to_string().ends_with(".0.0.d.f.ip6.arpa"));
        let (_, ans, _) = ask(&d, "home.arpa", rtype::MX).unwrap();
        assert_eq!(&ans[0].1[..2], &10u16.to_be_bytes());
        let (_, ans, _) = ask(&d, "_sip._udp.home.arpa", rtype::SRV).unwrap();
        assert_eq!(&ans[0].1[4..6], &5060u16.to_be_bytes());
        let (_, ans, _) = ask(&d, "home.arpa", rtype::TXT).unwrap();
        assert_eq!(&ans[0].1[1..], b"v=spf1 -all");
    }

    #[test]
    fn dns_010_validation() {
        let mut d = LocalData::default();
        assert!(d.add("x.lan", "A", "not-an-ip", 60).is_err());
        assert!(d.add("x.lan", "BOGUS", "1", 60).is_err());
        assert!(d.add("*", "A", "10.0.0.1", 60).is_err());
        d.add("c.lan", "CNAME", "x.lan", 60).unwrap();
        assert!(
            d.add("c.lan", "A", "10.0.0.1", 60).is_err(),
            "CNAME exclusivity"
        );
        assert!(d.add("x.lan", "SRV", "1 2 notaport t.lan", 60).is_err());
    }

    #[test]
    fn dns_010_hosts_file_import() {
        let mut d = LocalData::default();
        let mut report = LoadReport::default();
        d.add_hosts(
            "# comment\n127.0.0.1 localhost\n0.0.0.0 ads.example\n192.168.1.5 printer printer.lan # trailing\nbogus line\n",
            "hosts",
            120,
            &mut report,
        );
        assert!(ask(&d, "printer", rtype::A).is_some());
        assert!(ask(&d, "printer.lan", rtype::A).is_some());
        assert!(ask(&d, "localhost", rtype::A).is_none(), "loopback skipped");
        assert!(
            ask(&d, "ads.example", rtype::A).is_none(),
            "blocklist-style 0.0.0.0 skipped"
        );
        assert_eq!(report.warnings.len(), 1);
    }
}
