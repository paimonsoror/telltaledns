//! Validated scalar types shared by the config schema.

use std::borrow::Cow;
use std::fmt;
use std::ops::Deref;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A string that contains no control characters (newlines, tabs, NUL, DEL, ...).
///
/// REQ: 08 §6 — config values with newlines/control characters are rejected at the schema
/// layer, which closes the newline-injection class of bugs at the source.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SafeString(String);

impl SafeString {
    /// Validates and wraps `s`.
    pub fn new(s: impl Into<String>) -> Result<Self, String> {
        let s = s.into();
        if let Some(c) = s.chars().find(|c| c.is_control()) {
            return Err(format!(
                "control character U+{:04X} is not allowed",
                u32::from(c)
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for SafeString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SafeString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SafeString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for SafeString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&'static str> for SafeString {
    /// For compile-time constants only; panics in debug builds on control characters.
    fn from(s: &'static str) -> Self {
        debug_assert!(!s.chars().any(char::is_control));
        Self(s.to_owned())
    }
}

impl Serialize for SafeString {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SafeString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SafeString::new(s).map_err(de::Error::custom)
    }
}

impl JsonSchema for SafeString {
    fn schema_name() -> Cow<'static, str> {
        "SafeString".into()
    }
    fn inline_schema() -> bool {
        true
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]*$"
        })
    }
}

/// A byte count, written either as an integer (`33554432`) or with a unit
/// (`"32MiB"`, `"2 GiB"`, `"500MB"`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteSize(pub u64);

const KIB: u64 = 1024;
const MIB: u64 = KIB * 1024;
const GIB: u64 = MIB * 1024;
const TIB: u64 = GIB * 1024;

impl ByteSize {
    pub const fn mib(n: u64) -> Self {
        Self(n * MIB)
    }
    pub const fn gib(n: u64) -> Self {
        Self(n * GIB)
    }
    pub const fn bytes(self) -> u64 {
        self.0
    }

    /// Parses `"123"`, `"64KiB"`, `"32 MiB"`, `"2GiB"`, `"500MB"` (decimal units are powers of 1000).
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let (num, unit) = s.split_at(split);
        if num.is_empty() {
            return Err(format!(
                "invalid size `{s}`: expected a number with optional unit"
            ));
        }
        let n: u64 = num
            .parse()
            .map_err(|e| format!("invalid size `{s}`: {e}"))?;
        let mult = match unit.trim() {
            "" | "B" => 1,
            "KiB" | "K" | "k" => KIB,
            "MiB" | "M" => MIB,
            "GiB" | "G" => GIB,
            "TiB" | "T" => TIB,
            "KB" | "kB" => 1_000,
            "MB" => 1_000_000,
            "GB" => 1_000_000_000,
            "TB" => 1_000_000_000_000,
            other => {
                return Err(format!(
                    "invalid size unit `{other}` (use B, KiB, MiB, GiB, TiB, KB, MB, GB, TB)"
                ));
            }
        };
        n.checked_mul(mult)
            .map(Self)
            .ok_or_else(|| format!("size `{s}` overflows u64"))
    }
}

impl fmt::Debug for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.0;
        for (unit, size) in [("TiB", TIB), ("GiB", GIB), ("MiB", MIB), ("KiB", KIB)] {
            if n != 0 && n.is_multiple_of(size) {
                return write!(f, "{}{unit}", n / size);
            }
        }
        write!(f, "{n}B")
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = ByteSize;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a byte count (integer) or a size string like \"32MiB\"")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<ByteSize, E> {
                Ok(ByteSize(v))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<ByteSize, E> {
                u64::try_from(v)
                    .map(ByteSize)
                    .map_err(|_| E::custom("size must not be negative"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<ByteSize, E> {
                ByteSize::parse(v).map_err(E::custom)
            }
        }
        d.deserialize_any(V)
    }
}

impl JsonSchema for ByteSize {
    fn schema_name() -> Cow<'static, str> {
        "ByteSize".into()
    }
    fn inline_schema() -> bool {
        true
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Byte count: an integer, or a string with a unit such as \"32MiB\".",
            "oneOf": [
                { "type": "integer", "minimum": 0 },
                { "type": "string", "pattern": "^\\s*[0-9]+\\s*(B|K|k|KiB|M|MiB|G|GiB|T|TiB|KB|kB|MB|GB|TB)?\\s*$" }
            ]
        })
    }
}

/// An IP network (`192.168.0.0/16`, `fd00::/8`, or a bare address = host route).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    pub addr: std::net::IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: std::net::IpAddr = a
            .parse()
            .map_err(|_| format!("`{s}` is not an IP network"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|v| *v <= max)
                .ok_or_else(|| format!("`{s}`: prefix must be 0–{max}"))?,
            None => max,
        };
        Ok(Self { addr, prefix })
    }

    /// True if `ip` is inside this network (IPv4-mapped IPv6 addresses count as IPv4).
    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        use std::net::IpAddr;
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

impl fmt::Debug for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Serialize for Cidr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Cidr::parse(&s).map_err(de::Error::custom)
    }
}

impl JsonSchema for Cidr {
    fn schema_name() -> Cow<'static, str> {
        "Cidr".into()
    }
    fn inline_schema() -> bool {
        true
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "description": "IP network, e.g. \"192.168.0.0/16\" or \"fd00::/8\" (a bare address means a single host)."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_014_cidr_parse_and_contains() {
        let n = Cidr::parse("192.168.0.0/16").unwrap();
        assert!(n.contains("192.168.44.1".parse().unwrap()));
        assert!(!n.contains("192.169.0.1".parse().unwrap()));
        assert!(
            n.contains("::ffff:192.168.1.1".parse().unwrap()),
            "v4-mapped counts"
        );
        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        assert!(
            Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
        assert_eq!(Cidr::parse("10.1.2.3").unwrap().prefix, 32);
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("nope/8").is_err());
    }

    #[test]
    fn ops_005_safe_string_rejects_control_chars() {
        assert!(SafeString::new("ok value").is_ok());
        assert!(SafeString::new("bad\nvalue").is_err());
        assert!(SafeString::new("bad\u{7f}").is_err());
        assert!(SafeString::new("tab\there").is_err());
    }

    #[test]
    fn ops_005_byte_size_parse_and_display() {
        assert_eq!(ByteSize::parse("32MiB").unwrap(), ByteSize::mib(32));
        assert_eq!(ByteSize::parse("2 GiB").unwrap(), ByteSize::gib(2));
        assert_eq!(ByteSize::parse("1024").unwrap(), ByteSize(1024));
        assert_eq!(ByteSize::parse("5MB").unwrap(), ByteSize(5_000_000));
        assert!(ByteSize::parse("MiB").is_err());
        assert!(ByteSize::parse("3 parsecs").is_err());
        assert!(ByteSize::parse("99999999999999999999").is_err());
        assert_eq!(ByteSize::mib(32).to_string(), "32MiB");
        assert_eq!(ByteSize(1000).to_string(), "1000B");
    }
}

/// REQ: FLT-005 (T6.12) — an RFC 3339 time (`2026-10-05T21:30:00Z`, `…+02:00`, fractional
/// seconds allowed) as Unix seconds. `None` if it isn't one.
pub fn parse_rfc3339(text: &str) -> Option<i64> {
    let text = text.trim();
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't' | b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = text.get(range)?;
        digits
            .bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| digits.parse().ok())
            .flatten()
    };
    let year = num(0..4)?;
    let month = num(5..7)?;
    let day = num(8..10)?;
    let hour = num(11..13)?;
    let minute = num(14..16)?;
    let second = num(17..19)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = &text[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &frac[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        zone if zone.len() == 6
            && matches!(zone.as_bytes()[0], b'+' | b'-')
            && zone.as_bytes()[3] == b':' =>
        {
            let hours: i64 = zone[1..3].parse().ok()?;
            let minutes: i64 = zone[4..6].parse().ok()?;
            let total = hours * 3600 + minutes * 60;
            if zone.starts_with('-') { -total } else { total }
        }
        _ => return None,
    };
    // Days from the civil date (Howard Hinnant's algorithm).
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year.div_euclid(400);
    let year_of_era = shifted_year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

#[cfg(test)]
mod rfc3339_tests {
    use super::parse_rfc3339;

    #[test]
    fn flt_005_rfc3339_times() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-10-05T21:30:00Z"), Some(1_791_235_800));
        assert_eq!(
            parse_rfc3339("2026-10-05T23:30:00+02:00"),
            Some(1_791_235_800)
        );
        assert_eq!(
            parse_rfc3339("2026-10-05T21:30:00.123Z"),
            Some(1_791_235_800)
        );
        assert_eq!(parse_rfc3339("2024-02-29T12:00:00Z"), Some(1_709_208_000));
        for bad in [
            "",
            "2026-10-05",
            "2026-13-05T00:00:00Z",
            "2026-10-05T21:30:00",
            "tomorrow",
            "2026-10-05T21:30:00+0200",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }
}
