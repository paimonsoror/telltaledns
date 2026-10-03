//! Domain normalization for list entries (`spec/05` §3.1): lowercase, IDNA → punycode,
//! no trailing dot, valid labels.

/// Why a name was rejected.
pub type NameError = &'static str;

/// Normalizes a list entry to lowercase ASCII presentation form without the trailing dot.
///
/// Labels may contain letters, digits, `-`, and `_` (real lists contain `_`-names such as
/// tracking SRV-style hosts). A name that is an IPv4 address is rejected: blocking by
/// address is the response IP filter's job (FLT-015), not a domain rule's.
pub fn normalize(raw: &str) -> Result<String, NameError> {
    let s = raw.strip_suffix('.').unwrap_or(raw);
    if s.is_empty() {
        return Err("empty name");
    }
    let ascii = if s.is_ascii() {
        s.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii(s).map_err(|_| "invalid internationalized name")?
    };
    validate(&ascii)?;
    Ok(ascii)
}

fn validate(s: &str) -> Result<(), NameError> {
    if s.len() > 253 {
        return Err("name longer than 253 characters");
    }
    let mut all_numeric = true;
    let mut labels = 0;
    for label in s.split('.') {
        labels += 1;
        if label.is_empty() {
            return Err("empty label");
        }
        if label.len() > 63 {
            return Err("label longer than 63 characters");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err("invalid character in name");
        }
        all_numeric &= label.bytes().all(|b| b.is_ascii_digit());
    }
    if all_numeric && labels == 4 {
        return Err("IP address, not a name");
    }
    Ok(())
}

/// Names hosts files map to themselves; they are not blocklist entries.
pub(super) fn is_hosts_boilerplate(name: &str) -> bool {
    matches!(
        name,
        "localhost"
            | "localhost.localdomain"
            | "local"
            | "broadcasthost"
            | "ip6-localhost"
            | "ip6-loopback"
            | "ip6-localnet"
            | "ip6-mcastprefix"
            | "ip6-allnodes"
            | "ip6-allrouters"
            | "ip6-allhosts"
            | "0.0.0.0"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flt_001_normalization() {
        assert_eq!(normalize("Ads.Example.COM.").unwrap(), "ads.example.com");
        assert_eq!(
            normalize("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(
            normalize("_dmarc.example.com").unwrap(),
            "_dmarc.example.com"
        );
        assert_eq!(normalize("com").unwrap(), "com");
        assert!(normalize("").is_err());
        assert!(normalize(".").is_err());
        assert!(normalize("a..b").is_err());
        assert!(normalize("a b.com").is_err());
        assert!(normalize("ads.example.com/path").is_err());
        assert!(normalize(&format!("{}.com", "a".repeat(64))).is_err());
        assert!(normalize(&["abcdefghi"; 26].join(".")).is_err());
        assert_eq!(normalize("1.2.3.4"), Err("IP address, not a name"));
        assert!(normalize("1.2.3.4.in-addr.arpa").is_ok());
        assert!(normalize("123.example").is_ok());
    }
}
