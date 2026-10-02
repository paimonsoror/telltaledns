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

#[cfg(test)]
mod tests {
    use super::*;

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
