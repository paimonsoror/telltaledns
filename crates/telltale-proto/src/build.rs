//! Building outbound queries (upstream client, health checks, tests).

use crate::consts::rtype;
use crate::edns::EdnsOut;
use crate::header::{FlagBit, Flags, Header};
use crate::name::NameBuf;
use crate::writer::{BufferTooSmall, Writer};

/// Writes a standard query for `name`/`qtype`/`qclass` into `out` and returns its length.
pub fn build_query(
    out: &mut [u8],
    id: u16,
    name: &NameBuf,
    qtype: u16,
    qclass: u16,
    recursion_desired: bool,
    edns: Option<EdnsOut<'_>>,
) -> Result<usize, BufferTooSmall> {
    let mut w = Writer::new(out);
    w.bytes(
        &Header {
            id,
            flags: Flags(0).with(FlagBit::Rd, recursion_desired),
            qdcount: 1,
            arcount: u16::from(edns.is_some()),
            ..Header::default()
        }
        .to_bytes(),
    )?;
    w.bytes(name.as_wire())?;
    w.u16(qtype)?;
    w.u16(qclass)?;
    if let Some(e) = edns {
        w.u8(0)?;
        w.u16(rtype::OPT)?;
        w.u16(e.udp_payload)?;
        w.u8(0)?;
        w.u8(0)?;
        w.u16(if e.dnssec_ok { 0x8000 } else { 0 })?;
        w.u16(0)?;
    }
    Ok(w.pos())
}
