//! Protocol constants (IANA DNS parameters).

/// Resource record types used on the hot path.
pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const HINFO: u16 = 13;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const DNAME: u16 = 39;
    pub const OPT: u16 = 41;
    pub const DS: u16 = 43;
    pub const RRSIG: u16 = 46;
    pub const NSEC: u16 = 47;
    pub const DNSKEY: u16 = 48;
    pub const NSEC3: u16 = 50;
    pub const SVCB: u16 = 64;
    pub const HTTPS: u16 = 65;
    pub const ANY: u16 = 255;
    pub const CAA: u16 = 257;

    /// Parses a type mnemonic (`AAAA`, case-insensitive) or the RFC 3597 `TYPEnnn` form.
    /// Off the hot path: config, routes, and list modifiers.
    pub fn from_name(s: &str) -> Option<u16> {
        let up = s.trim().to_ascii_uppercase();
        Some(match up.as_str() {
            "A" => A,
            "NS" => NS,
            "CNAME" => CNAME,
            "SOA" => SOA,
            "PTR" => PTR,
            "HINFO" => HINFO,
            "MX" => MX,
            "TXT" => TXT,
            "AAAA" => AAAA,
            "SRV" => SRV,
            "DNAME" => DNAME,
            "DS" => DS,
            "RRSIG" => RRSIG,
            "NSEC" => NSEC,
            "DNSKEY" => DNSKEY,
            "NSEC3" => NSEC3,
            "SVCB" => SVCB,
            "HTTPS" => HTTPS,
            "ANY" => ANY,
            "CAA" => CAA,
            other => other.strip_prefix("TYPE")?.parse().ok()?,
        })
    }
}

/// Classes.
pub mod class {
    pub const IN: u16 = 1;
    pub const CH: u16 = 3;
    pub const ANY: u16 = 255;
}

/// Opcodes.
pub mod opcode {
    pub const QUERY: u8 = 0;
}

/// Response codes. Values above 15 need an OPT record (extended RCODE).
pub mod rcode {
    pub const NOERROR: u16 = 0;
    pub const FORMERR: u16 = 1;
    pub const SERVFAIL: u16 = 2;
    pub const NXDOMAIN: u16 = 3;
    pub const NOTIMP: u16 = 4;
    pub const REFUSED: u16 = 5;
    pub const BADVERS: u16 = 16;
}

/// EDNS option codes.
pub mod opt {
    /// EDNS Client Subnet (RFC 7871).
    pub const ECS: u16 = 8;
    /// DNS Cookie (RFC 7873).
    pub const COOKIE: u16 = 10;
    /// Padding (RFC 7830).
    pub const PADDING: u16 = 12;
    /// Extended DNS Error (RFC 8914).
    pub const EDE: u16 = 15;
    /// dnsmasq `add-mac` client MAC address (local-use range).
    pub const DNSMASQ_MAC: u16 = 65001;
    /// TelltaleDNS loop-detection tag carrying the node ID (`spec/04` §7, local-use range).
    pub const TELLTALE_LOOP: u16 = 65429;
}

/// Extended DNS Error info codes (RFC 8914 §4). REQ: DNS-013.
pub mod ede {
    pub const OTHER: u16 = 0;
    pub const STALE_ANSWER: u16 = 3;
    pub const DNSSEC_BOGUS: u16 = 6;
    pub const SIGNATURE_EXPIRED: u16 = 7;
    pub const DNSKEY_MISSING: u16 = 9;
    pub const NOT_READY: u16 = 14;
    pub const BLOCKED: u16 = 15;
    pub const CENSORED: u16 = 16;
    pub const FILTERED: u16 = 17;
    pub const PROHIBITED: u16 = 18;
    pub const NO_REACHABLE_AUTHORITY: u16 = 22;
    pub const NETWORK_ERROR: u16 = 23;
}

/// Classic (non-EDNS) DNS-over-UDP message limit.
pub const MIN_UDP_PAYLOAD: u16 = 512;
/// Default advertised EDNS UDP payload size (DNS Flag Day 2020). REQ: DNS-005.
pub const DEFAULT_EDNS_PAYLOAD: u16 = 1232;
