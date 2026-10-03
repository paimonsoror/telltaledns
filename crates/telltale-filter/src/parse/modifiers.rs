//! AdBlock/AdGuard DNS rule modifiers (`$important,dnstype=AAAA,...`), `spec/05` §2–3.3.

use std::fmt;

use super::name::normalize;

/// A value that can be excluded with `~` (`dnstype=~AAAA`, `client=~10.0.0.5`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Negatable<T> {
    pub value: T,
    pub negated: bool,
}

/// Modifiers a rule may carry. Rules with any other modifier are reported as unsupported
/// rather than applied without it: dropping a restriction would block more than intended.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Modifiers {
    /// `$important`: wins over non-important allow rules (`spec/05` §1 tiers 1–2).
    pub important: bool,
    /// `$badfilter`: disables the identical rule without this modifier (resolved at compile).
    pub badfilter: bool,
    /// `$client=`: client names, IPs, or CIDRs; resolved to client IDs at compile time.
    pub client: Vec<Negatable<String>>,
    /// `$dnstype=` or Pi-hole `;querytype=`: query types the rule applies to (empty = all).
    pub dnstype: Vec<Negatable<u16>>,
    /// `$denyallow=`: subdomains excluded from a blocking rule.
    pub denyallow: Vec<String>,
    /// `$dnsrewrite=` (P1): kept verbatim for the compiler.
    pub dnsrewrite: Option<String>,
}

impl Modifiers {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Parses the text after `$`. Errors are `(unsupported, reason)`: `true` for valid syntax we
/// don't implement, `false` for malformed input.
pub(super) fn parse(text: &str) -> Result<Modifiers, (bool, String)> {
    let mut m = Modifiers::default();
    for part in split_unquoted(text, ',') {
        let part = part.trim();
        let (key, value) = match part.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim())),
            None => (part, None),
        };
        match (key, value) {
            ("important", None) => m.important = true,
            ("badfilter", None) => m.badfilter = true,
            ("client", Some(v)) if !v.is_empty() => {
                for item in split_unquoted(v, '|') {
                    let (negated, item) = negation(item.trim());
                    let value = unquote(item);
                    if value.is_empty() {
                        return Err((false, "empty $client value".into()));
                    }
                    m.client.push(Negatable { value, negated });
                }
            }
            ("dnstype", Some(v)) if !v.is_empty() => {
                for item in v.split('|') {
                    let (negated, name) = negation(item.trim());
                    let value = telltale_proto::rtype::from_name(name)
                        .ok_or_else(|| (false, format!("unknown query type `{name}`")))?;
                    m.dnstype.push(Negatable { value, negated });
                }
            }
            ("denyallow", Some(v)) if !v.is_empty() => {
                for item in v.split('|') {
                    let item = item.trim();
                    if item.starts_with('~') {
                        return Err((false, "$denyallow values can't be negated".into()));
                    }
                    let name = normalize(item)
                        .map_err(|e| (false, format!("$denyallow `{item}`: {e}")))?;
                    m.denyallow.push(name);
                }
            }
            ("dnsrewrite", Some(v)) if !v.is_empty() => m.dnsrewrite = Some(v.to_owned()),
            ("important" | "badfilter", Some(_)) => {
                return Err((false, format!("${key} takes no value")));
            }
            ("client" | "dnstype" | "denyallow" | "dnsrewrite", _) => {
                return Err((false, format!("${key} needs a value")));
            }
            ("", _) => return Err((false, "empty modifier".into())),
            _ => return Err((true, format!("modifier ${key} is not supported"))),
        }
    }
    Ok(m)
}

fn negation(s: &str) -> (bool, &str) {
    s.strip_prefix('~')
        .map_or((false, s), |rest| (true, rest.trim()))
}

/// Splits on `sep` outside single/double quotes, honoring backslash escapes.
fn split_unquoted(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '\'' | '"' if quote == Some(c) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(c),
            c if c == sep && quote.is_none() => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// Strips surrounding quotes and backslash escapes (`'Frank\'s laptop'` → `Frank's laptop`).
fn unquote(s: &str) -> String {
    let inner = s
        .strip_prefix('\'')
        .and_then(|r| r.strip_suffix('\''))
        .or_else(|| s.strip_prefix('"').and_then(|r| r.strip_suffix('"')))
        .unwrap_or(s);
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

impl fmt::Display for Modifiers {
    /// Canonical form: fixed key order, values in input order.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        if self.important {
            parts.push("important".into());
        }
        if self.badfilter {
            parts.push("badfilter".into());
        }
        let neg = |n: bool| if n { "~" } else { "" };
        if !self.client.is_empty() {
            let v: Vec<String> = self
                .client
                .iter()
                .map(|c| format!("{}'{}'", neg(c.negated), c.value.replace('\'', "\\'")))
                .collect();
            parts.push(format!("client={}", v.join("|")));
        }
        if !self.dnstype.is_empty() {
            let v: Vec<String> = self
                .dnstype
                .iter()
                .map(|t| format!("{}{}", neg(t.negated), qtype_name(t.value)))
                .collect();
            parts.push(format!("dnstype={}", v.join("|")));
        }
        if !self.denyallow.is_empty() {
            parts.push(format!("denyallow={}", self.denyallow.join("|")));
        }
        if let Some(r) = &self.dnsrewrite {
            parts.push(format!("dnsrewrite={r}"));
        }
        write!(f, "{}", parts.join(","))
    }
}

fn qtype_name(t: u16) -> String {
    use telltale_proto::rtype;
    match t {
        rtype::A => "A".into(),
        rtype::AAAA => "AAAA".into(),
        rtype::CNAME => "CNAME".into(),
        rtype::HTTPS => "HTTPS".into(),
        rtype::SVCB => "SVCB".into(),
        rtype::MX => "MX".into(),
        rtype::TXT => "TXT".into(),
        rtype::PTR => "PTR".into(),
        rtype::SRV => "SRV".into(),
        rtype::NS => "NS".into(),
        rtype::SOA => "SOA".into(),
        rtype::ANY => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flt_001_modifiers() {
        let m =
            parse("important,dnstype=A|~AAAA,denyallow=Good.example.com|cdn.example.net").unwrap();
        assert!(m.important);
        assert_eq!(m.dnstype.len(), 2);
        assert!(m.dnstype[1].negated);
        assert_eq!(m.denyallow, vec!["good.example.com", "cdn.example.net"]);
        assert_eq!(
            m.to_string(),
            "important,dnstype=A|~AAAA,denyallow=good.example.com|cdn.example.net"
        );

        let m = parse(r"client='Frank\'s laptop'|192.168.1.0/24|~'TV, living room'").unwrap();
        let names: Vec<_> = m.client.iter().map(|c| c.value.as_str()).collect();
        assert_eq!(
            names,
            ["Frank's laptop", "192.168.1.0/24", "TV, living room"]
        );
        assert!(m.client[2].negated);

        assert!(parse("third-party").unwrap_err().0, "unsupported");
        assert!(parse("ctag=device_tv").unwrap_err().0);
        assert!(!parse("dnstype=BOGUS").unwrap_err().0, "malformed");
        assert!(!parse("important=1").unwrap_err().0);
        assert!(!parse("client=").unwrap_err().0);
        assert!(!parse("denyallow=~a.com").unwrap_err().0);
        assert!(!parse("important,,").unwrap_err().0);
    }
}
