//! Domain names in wire format: parsing (with compression), normalization, hashing, display.
//!
//! REQ: `spec/03` §2 — the qname is normalized to lowercase into a stack buffer (max 255
//! bytes) and hashed once; cache, filter, and telemetry reuse that hash.

use std::fmt;

use xxhash_rust::xxh3::xxh3_64_with_seed;

use crate::ParseError;

/// Maximum encoded name length, including length bytes and the root label (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;
/// Maximum label length.
pub const MAX_LABEL_LEN: usize = 63;
/// Bound on compression-pointer hops (a valid name has at most 127 labels).
const MAX_POINTER_HOPS: usize = 127;

/// An uncompressed, lowercase, wire-format name on the stack (e.g. `\x03www\x07example\x03com\x00`).
#[derive(Clone, Copy)]
pub struct NameBuf {
    buf: [u8; MAX_NAME_LEN],
    len: u8,
}

impl Default for NameBuf {
    /// The root name (`.`).
    fn default() -> Self {
        Self {
            buf: [0; MAX_NAME_LEN],
            len: 1,
        }
    }
}

impl PartialEq for NameBuf {
    fn eq(&self, other: &Self) -> bool {
        self.as_wire() == other.as_wire()
    }
}
impl Eq for NameBuf {}

impl std::hash::Hash for NameBuf {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_wire().hash(state);
    }
}

impl NameBuf {
    /// Wire-format bytes, ending with the root label (0).
    pub fn as_wire(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }

    /// Encoded length in bytes (1 for the root).
    pub fn wire_len(&self) -> usize {
        usize::from(self.len)
    }

    pub fn is_root(&self) -> bool {
        self.len == 1
    }

    /// Iterates labels from left to right (`www`, `example`, `com`), without the root.
    pub fn labels(&self) -> Labels<'_> {
        Labels {
            wire: self.as_wire(),
            pos: 0,
        }
    }

    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// Seeded 64-bit hash of the normalized name. Use one random seed per process so
    /// remote clients can't precompute colliding names.
    pub fn hash64(&self, seed: u64) -> u64 {
        xxh3_64_with_seed(self.as_wire(), seed)
    }

    /// True if `self` equals `suffix` or is below it, comparing whole labels
    /// (`a.example.com` is under `example.com`; `badexample.com` is not).
    pub fn is_subdomain_of(&self, suffix: &NameBuf) -> bool {
        let (me, sfx) = (self.as_wire(), suffix.as_wire());
        if sfx.len() > me.len() {
            return false;
        }
        let start = me.len() - sfx.len();
        if me[start..] != *sfx {
            return false;
        }
        // `start` must sit on a label boundary.
        let mut pos = 0;
        while pos < start {
            pos += 1 + usize::from(me[pos]);
        }
        pos == start
    }

    /// Parses presentation format (`www.Example.com`, `example.com.`, `.`) and lowercases it.
    /// Supports `\.` and `\DDD` escapes.
    pub fn from_presentation(s: &str) -> Result<Self, ParseError> {
        let mut out = NameBuf {
            buf: [0; MAX_NAME_LEN],
            len: 0,
        };
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes == b"." {
            return Ok(Self::default());
        }
        let mut pos = 0usize; // write position
        let mut label_start = 0usize;
        let mut label_len = 0usize;
        let mut i = 0usize;
        let push = |out: &mut NameBuf, pos: &mut usize, b: u8| -> Result<(), ParseError> {
            if *pos >= MAX_NAME_LEN - 1 {
                return Err(ParseError::NameTooLong);
            }
            out.buf[*pos] = b;
            *pos += 1;
            Ok(())
        };
        push(&mut out, &mut pos, 0)?; // placeholder for the first label length
        while i < bytes.len() {
            let c = bytes[i];
            if c == b'.' {
                if label_len == 0 {
                    return Err(ParseError::EmptyLabel);
                }
                out.buf[label_start] =
                    u8::try_from(label_len).map_err(|_| ParseError::LabelTooLong)?;
                label_start = pos;
                label_len = 0;
                i += 1;
                if i == bytes.len() {
                    break; // trailing dot
                }
                push(&mut out, &mut pos, 0)?;
                continue;
            }
            let b = if c == b'\\' {
                let rest = &bytes[i + 1..];
                match rest {
                    [d0, d1, d2, ..]
                        if d0.is_ascii_digit() && d1.is_ascii_digit() && d2.is_ascii_digit() =>
                    {
                        let v = u16::from(d0 - b'0') * 100
                            + u16::from(d1 - b'0') * 10
                            + u16::from(d2 - b'0');
                        i += 4;
                        u8::try_from(v).map_err(|_| ParseError::BadEscape)?
                    }
                    [e, ..] => {
                        i += 2;
                        *e
                    }
                    [] => return Err(ParseError::BadEscape),
                }
            } else {
                i += 1;
                c
            };
            label_len += 1;
            if label_len > MAX_LABEL_LEN {
                return Err(ParseError::LabelTooLong);
            }
            push(&mut out, &mut pos, b.to_ascii_lowercase())?;
        }
        if label_len > 0 {
            out.buf[label_start] = u8::try_from(label_len).map_err(|_| ParseError::LabelTooLong)?;
            // `push` keeps pos <= MAX_NAME_LEN - 1, so the root byte always fits.
            out.buf[pos] = 0;
            pos += 1;
        } else {
            // Trailing dot: the placeholder written after the last label is the root.
            pos = label_start + 1;
            out.buf[label_start] = 0;
        }
        out.len = u8::try_from(pos).map_err(|_| ParseError::NameTooLong)?;
        Ok(out)
    }

    /// Presentation-format display (no trailing dot; the root is `.`).
    pub fn display(&self) -> DisplayName<'_> {
        DisplayName(self.as_wire())
    }
}

impl fmt::Debug for NameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NameBuf({})", self.display())
    }
}

/// Iterator over the labels of an uncompressed wire name.
#[derive(Debug, Clone)]
pub struct Labels<'a> {
    wire: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(*self.wire.get(self.pos)?);
        if len == 0 {
            return None;
        }
        let label = self.wire.get(self.pos + 1..self.pos + 1 + len)?;
        self.pos += 1 + len;
        Some(label)
    }
}

/// Reads the (possibly compressed) name at `pos` in `msg` into `out`, lowercased.
///
/// Returns the offset just past the name *as it appears at `pos`* (i.e. after the first
/// compression pointer, if any). Pointers must point strictly backwards, which rules out loops.
pub fn read_name(msg: &[u8], pos: usize, out: &mut NameBuf) -> Result<usize, ParseError> {
    read_name_inner(msg, pos, out, true)
}

/// Like [`read_name`] but rejects compression pointers (used for the question of a query,
/// where there is nothing earlier in the message to point to).
pub fn read_name_uncompressed(
    msg: &[u8],
    pos: usize,
    out: &mut NameBuf,
) -> Result<usize, ParseError> {
    read_name_inner(msg, pos, out, false)
}

fn read_name_inner(
    msg: &[u8],
    mut pos: usize,
    out: &mut NameBuf,
    allow_ptr: bool,
) -> Result<usize, ParseError> {
    let mut w = 0usize;
    let mut end: Option<usize> = None;
    let mut hops = 0usize;
    loop {
        let len = *msg.get(pos).ok_or(ParseError::Truncated)?;
        match len & 0xC0 {
            0x00 => {
                let len = usize::from(len);
                if len == 0 {
                    if w + 1 > MAX_NAME_LEN {
                        return Err(ParseError::NameTooLong);
                    }
                    out.buf[w] = 0;
                    out.len = u8::try_from(w + 1).map_err(|_| ParseError::NameTooLong)?;
                    return Ok(end.unwrap_or(pos + 1));
                }
                let label = msg
                    .get(pos + 1..pos + 1 + len)
                    .ok_or(ParseError::Truncated)?;
                // +1 for this length byte, +1 reserved for the root label.
                if w + 1 + len + 1 > MAX_NAME_LEN {
                    return Err(ParseError::NameTooLong);
                }
                out.buf[w] = len as u8; // len <= 63 (top two bits clear)
                for (dst, src) in out.buf[w + 1..w + 1 + len].iter_mut().zip(label) {
                    *dst = src.to_ascii_lowercase();
                }
                w += 1 + len;
                pos += 1 + len;
            }
            0xC0 => {
                if !allow_ptr {
                    return Err(ParseError::UnexpectedPointer);
                }
                let lo = *msg.get(pos + 1).ok_or(ParseError::Truncated)?;
                let target = (usize::from(len & 0x3F) << 8) | usize::from(lo);
                if target >= pos {
                    return Err(ParseError::BadPointer);
                }
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return Err(ParseError::BadPointer);
                }
                end.get_or_insert(pos + 2);
                pos = target;
            }
            // 0x40 (extended label types, RFC 6891 §5) and 0x80 are not supported.
            _ => return Err(ParseError::BadLabelType),
        }
    }
}

/// Returns the offset just past the (possibly compressed) name at `pos`, validating framing
/// but not following pointers.
pub fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize, ParseError> {
    let start = pos;
    loop {
        let len = *msg.get(pos).ok_or(ParseError::Truncated)?;
        match len & 0xC0 {
            0x00 if len == 0 => return Ok(pos + 1),
            0x00 => {
                pos += 1 + usize::from(len);
                if pos - start > MAX_NAME_LEN {
                    return Err(ParseError::NameTooLong);
                }
            }
            0xC0 => {
                if pos + 1 >= msg.len() {
                    return Err(ParseError::Truncated);
                }
                return Ok(pos + 2);
            }
            _ => return Err(ParseError::BadLabelType),
        }
    }
}

/// Displays an uncompressed wire name in presentation format, escaping as RFC 4343 requires.
#[derive(Clone, Copy)]
pub struct DisplayName<'a>(pub &'a [u8]);

impl fmt::Display for DisplayName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let labels = Labels {
            wire: self.0,
            pos: 0,
        };
        let mut first = true;
        for label in labels {
            if !first {
                f.write_str(".")?;
            }
            first = false;
            for &b in label {
                match b {
                    b'.' | b'\\' | b'"' | b'(' | b')' | b';' | b'@' | b'$' => {
                        write!(f, "\\{}", char::from(b))?;
                    }
                    0x21..=0x7E => write!(f, "{}", char::from(b))?,
                    _ => write!(f, "\\{b:03}")?,
                }
            }
        }
        if first {
            f.write_str(".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for DisplayName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{self}\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NameBuf {
        NameBuf::from_presentation(s).unwrap()
    }

    #[test]
    fn dns_005_presentation_roundtrip() {
        assert_eq!(
            n("WWW.Example.COM").as_wire(),
            b"\x03www\x07example\x03com\x00"
        );
        assert_eq!(n("example.com."), n("example.com"));
        assert!(n(".").is_root());
        assert_eq!(n(".").display().to_string(), ".");
        assert_eq!(n("a\\.b.c").display().to_string(), "a\\.b.c");
        assert_eq!(n("a\\032b").display().to_string(), "a\\032b");
        assert_eq!(n("www.example.com").label_count(), 3);
        assert!(NameBuf::from_presentation("a..b").is_err());
        assert!(NameBuf::from_presentation(&"a".repeat(64)).is_err());
        let long = vec!["abcdefghi"; 26].join(".");
        assert!(NameBuf::from_presentation(&long).is_err());
    }

    #[test]
    fn dns_005_subdomain_matching_is_label_aligned() {
        let sfx = n("example.com");
        assert!(n("example.com").is_subdomain_of(&sfx));
        assert!(n("a.b.example.com").is_subdomain_of(&sfx));
        assert!(!n("badexample.com").is_subdomain_of(&sfx));
        assert!(!n("com").is_subdomain_of(&sfx));
        assert!(n("anything").is_subdomain_of(&n(".")));
    }

    #[test]
    fn dns_005_compression_pointers() {
        // header(12) + "\x07example\x03com\x00" at 12, then "\x03www" + ptr to 12
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(b"\x07Example\x03com\x00");
        let www = msg.len();
        msg.extend_from_slice(b"\x03WWW\xC0\x0C");
        let mut out = NameBuf::default();
        let end = read_name(&msg, www, &mut out).unwrap();
        assert_eq!(end, msg.len());
        assert_eq!(out, n("www.example.com"));
        assert_eq!(skip_name(&msg, www).unwrap(), msg.len());
        assert_eq!(
            read_name_uncompressed(&msg, www, &mut out),
            Err(ParseError::UnexpectedPointer)
        );
    }

    #[test]
    fn dns_019_pointer_loops_and_forward_pointers_rejected() {
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(b"\xC0\x0C"); // points to itself
        let mut out = NameBuf::default();
        assert_eq!(read_name(&msg, 12, &mut out), Err(ParseError::BadPointer));
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(b"\xC0\x20"); // forward
        assert_eq!(read_name(&msg, 12, &mut out), Err(ParseError::BadPointer));
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(b"\x40abc\x00"); // extended label type
        assert_eq!(read_name(&msg, 12, &mut out), Err(ParseError::BadLabelType));
    }

    #[test]
    fn dns_019_overlong_names_rejected() {
        let mut msg = vec![0u8; 12];
        for _ in 0..5 {
            msg.push(63);
            msg.extend_from_slice(&[b'a'; 63]);
        }
        msg.push(0);
        let mut out = NameBuf::default();
        assert_eq!(read_name(&msg, 12, &mut out), Err(ParseError::NameTooLong));
    }

    #[test]
    fn dns_005_hash_is_seeded_and_case_insensitive() {
        let a = n("Example.COM");
        let b = n("example.com");
        assert_eq!(a.hash64(1), b.hash64(1));
        assert_ne!(a.hash64(1), a.hash64(2));
    }
}
