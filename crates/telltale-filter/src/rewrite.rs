//! REQ: FLT-014 (T9.20) — `$dnsrewrite` values in filter lists (AdGuard syntax): the answer a
//! matching rule puts in place of the real one.
//!
//! Supported: `$dnsrewrite=1.2.3.4` / `=2001:db8::1` (an address), `=other.example` (a CNAME),
//! `=NXDOMAIN` / `=REFUSED` / `=SERVFAIL` (an rcode), and the full form `RCODE;TYPE;VALUE` for
//! `NOERROR;A;…`, `NOERROR;AAAA;…`, `NOERROR;CNAME;…`, `NOERROR;;` (an empty answer), and
//! `NXDOMAIN;;` and the like. Other record types (MX, TXT, HTTPS, …) are unsupported. An
//! exception (`@@…$dnsrewrite`, with or without a value) turns rewrites off for its names.

use std::net::IpAddr;

use telltale_proto::rcode;

/// What one `$dnsrewrite` rule does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteAction {
    /// Answer with this rcode and no records (`NOERROR` here means an empty answer).
    Rcode(u16),
    /// An address record (A or AAAA by its family).
    Addr(IpAddr),
    /// A CNAME to this name (resolved like any name).
    Cname(String),
}

/// The answer a list rewrite gives, for one question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListRewrite {
    /// No records, with this rcode (NOERROR: the name exists, but not with this type).
    Rcode(u16),
    Cname(String),
    /// Addresses of the asked family.
    Addrs(Vec<IpAddr>),
}

fn rcode_named(s: &str) -> Option<u16> {
    match s.to_ascii_uppercase().as_str() {
        "NOERROR" => Some(rcode::NOERROR),
        "NXDOMAIN" => Some(rcode::NXDOMAIN),
        "REFUSED" => Some(rcode::REFUSED),
        "SERVFAIL" => Some(rcode::SERVFAIL),
        _ => None,
    }
}

fn hostname(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.');
    (!s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        }))
    .then(|| s.to_ascii_lowercase())
}

/// Parses a `$dnsrewrite` value; `None` when it isn't supported (or isn't valid).
pub fn parse(value: &str) -> Option<RewriteAction> {
    let v = value.trim();
    let Some((code, rest)) = v.split_once(';') else {
        // Shorthand: an rcode keyword, an address, or a host name.
        if let Some(rc) = rcode_named(v).filter(|rc| *rc != rcode::NOERROR) {
            return Some(RewriteAction::Rcode(rc));
        }
        if let Ok(ip) = v.parse::<IpAddr>() {
            return Some(RewriteAction::Addr(ip));
        }
        return hostname(v).map(RewriteAction::Cname);
    };
    let rc = rcode_named(code)?;
    let (rtype, value) = rest.split_once(';').unwrap_or((rest, ""));
    match (rc, rtype.trim().to_ascii_uppercase().as_str(), value.trim()) {
        (_, "", "") => Some(RewriteAction::Rcode(rc)),
        (rcode::NOERROR, "A", v) => v
            .parse::<std::net::Ipv4Addr>()
            .ok()
            .map(|a| RewriteAction::Addr(a.into())),
        (rcode::NOERROR, "AAAA", v) => v
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|a| RewriteAction::Addr(a.into())),
        (rcode::NOERROR, "CNAME", v) => hostname(v).map(RewriteAction::Cname),
        _ => None,
    }
}

/// REQ: FLT-014 (T9.20) — the answer for `qtype` from the actions of every rewrite rule that
/// applies, in precedence order: an rcode wins, then the first CNAME, then every address of
/// the asked family (none: an empty NOERROR, since the name is rewritten for another type).
pub fn combine(actions: &[&RewriteAction], qtype: u16) -> ListRewrite {
    use telltale_proto::rtype;
    if let Some(RewriteAction::Rcode(rc)) = actions
        .iter()
        .find(|a| matches!(a, RewriteAction::Rcode(rc) if *rc != rcode::NOERROR))
    {
        return ListRewrite::Rcode(*rc);
    }
    if let Some(RewriteAction::Cname(n)) = actions
        .iter()
        .find(|a| matches!(a, RewriteAction::Cname(_)))
    {
        return ListRewrite::Cname(n.clone());
    }
    let addrs: Vec<IpAddr> = actions
        .iter()
        .filter_map(|a| match a {
            RewriteAction::Addr(ip) => Some(*ip),
            _ => None,
        })
        .filter(|ip| {
            matches!(
                (ip, qtype),
                (IpAddr::V4(_), rtype::A) | (IpAddr::V6(_), rtype::AAAA)
            )
        })
        .collect();
    if addrs.is_empty() {
        ListRewrite::Rcode(rcode::NOERROR)
    } else {
        ListRewrite::Addrs(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_proto::rtype;

    /// REQ: FLT-014 (T9.20) — the forms AdGuard documents, and what isn't supported.
    #[test]
    fn flt_014_dnsrewrite_values() {
        let ip = |s: &str| RewriteAction::Addr(s.parse().unwrap());
        assert_eq!(parse("1.2.3.4"), Some(ip("1.2.3.4")));
        assert_eq!(parse("2001:db8::1"), Some(ip("2001:db8::1")));
        assert_eq!(
            parse("Example.ORG."),
            Some(RewriteAction::Cname("example.org".into()))
        );
        assert_eq!(parse("REFUSED"), Some(RewriteAction::Rcode(rcode::REFUSED)));
        assert_eq!(parse("NOERROR;A;192.0.2.1"), Some(ip("192.0.2.1")));
        assert_eq!(parse("noerror;aaaa;::1"), Some(ip("::1")));
        assert_eq!(
            parse("NOERROR;CNAME;safe.example"),
            Some(RewriteAction::Cname("safe.example".into()))
        );
        assert_eq!(
            parse("NXDOMAIN;;"),
            Some(RewriteAction::Rcode(rcode::NXDOMAIN))
        );
        assert_eq!(
            parse("NOERROR;;"),
            Some(RewriteAction::Rcode(rcode::NOERROR))
        );
        for bad in [
            "NOERROR;MX;10 mail.example",
            "NOERROR;A;not-an-ip",
            "NOERROR;A;::1",
            "BOGUS;A;1.2.3.4",
            "a b",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }

    /// REQ: FLT-014 (T9.20) — combining: rcode, then CNAME, then the family's addresses.
    #[test]
    fn flt_014_dnsrewrite_combine() {
        let a1 = parse("1.2.3.4").unwrap();
        let a2 = parse("5.6.7.8").unwrap();
        let v6 = parse("::1").unwrap();
        let cname = parse("x.example").unwrap();
        let nx = parse("NXDOMAIN;;").unwrap();
        let ips = |v: &[&str]| ListRewrite::Addrs(v.iter().map(|s| s.parse().unwrap()).collect());
        assert_eq!(
            combine(&[&a1, &a2, &v6], rtype::A),
            ips(&["1.2.3.4", "5.6.7.8"])
        );
        assert_eq!(combine(&[&a1, &v6], rtype::AAAA), ips(&["::1"]));
        assert_eq!(
            combine(&[&a1], rtype::AAAA),
            ListRewrite::Rcode(rcode::NOERROR)
        );
        assert_eq!(
            combine(&[&a1, &cname], rtype::A),
            ListRewrite::Cname("x.example".into())
        );
        assert_eq!(
            combine(&[&cname, &nx], rtype::A),
            ListRewrite::Rcode(rcode::NXDOMAIN)
        );
    }
}
