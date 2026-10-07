//! Zero-copy DNS wire parser/writer for the hot path.
//!
//! Part of TelltaleDNS. See `spec/02-architecture.md` §2, `spec/03` §2 and §7, ADR-002.
//!
//! Everything here works on borrowed byte slices and caller-provided output buffers: no
//! function allocates (REQ: NFR-002). Full record decoding (DNSSEC, zone files) is left to
//! `hickory-proto` off the hot path.
//!
//! Typical cache-hit flow:
//! ```
//! use telltale_proto::{build_query, parse_query, NameBuf, rtype};
//! let mut buf = [0u8; 512];
//! let name = NameBuf::from_presentation("example.com").unwrap();
//! let len = build_query(&mut buf, 7, &name, rtype::A, 1, true, None).unwrap();
//! let q = parse_query(&buf[..len]).unwrap();
//! assert_eq!(q.qname, name);
//! let key_hash = q.qname.hash64(0x5eed);
//! # let _ = key_hash;
//! ```

// REQ: NFR-003 — no unsafe outside telltale-net.
#![forbid(unsafe_code)]
// Wire code casts masked or range-checked values between integer widths constantly; each
// such cast below operates on a value already bounded by a mask, a length check, or the
// 64 KiB DNS message limit.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]

mod build;
pub mod consts;
mod edns;
pub mod header;
mod name;
mod query;
mod record;
mod writer;

pub use build::build_query;
pub use consts::{DEFAULT_EDNS_PAYLOAD, MIN_UDP_PAYLOAD, class, ede, opcode, opt, rcode, rtype};
pub use edns::{Edns, EdnsOut, OptionIter};
pub use header::{FlagBit, Flags, HEADER_LEN, Header};
pub use name::{
    DisplayName, Labels, MAX_LABEL_LEN, MAX_NAME_LEN, NameBuf, read_name, read_name_uncompressed,
    skip_name,
};
pub use query::{Query, QueryError, parse_query};
pub use record::{
    Record, RecordIter, ResponseSummary, Section, patch_ttls, patch_ttls_packed, records, set_ttls,
    set_ttls_packed, summarize,
};
pub use writer::{
    BufferTooSmall, ResponseBuilder, Writer, append_opt, badvers_from_raw, error_from_raw,
    response_edns, truncate_for_udp, ttl_at, udp_limit,
};

/// Why a message (or part of it) could not be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("message truncated")]
    Truncated,
    #[error("name longer than 255 bytes")]
    NameTooLong,
    #[error("label longer than 63 bytes")]
    LabelTooLong,
    #[error("empty label")]
    EmptyLabel,
    #[error("invalid escape in name")]
    BadEscape,
    #[error("unsupported label type")]
    BadLabelType,
    #[error("invalid compression pointer")]
    BadPointer,
    #[error("compression pointer in the question")]
    UnexpectedPointer,
    #[error("QDCOUNT must be 1")]
    QuestionCount,
    #[error("misplaced or duplicate OPT record")]
    BadOpt,
    #[error("malformed EDNS option")]
    BadOption,
}

#[inline]
pub(crate) fn be16(msg: &[u8], at: usize) -> Option<u16> {
    let b = msg.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

#[inline]
pub(crate) fn be32(msg: &[u8], at: usize) -> Option<u32> {
    let b = msg.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}
