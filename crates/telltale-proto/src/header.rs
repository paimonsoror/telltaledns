//! The 12-byte DNS message header (RFC 1035 §4.1.1).

pub const HEADER_LEN: usize = 12;

const QR: u16 = 0x8000;
const AA: u16 = 0x0400;
const TC: u16 = 0x0200;
const RD: u16 = 0x0100;
const RA: u16 = 0x0080;
const AD: u16 = 0x0020;
const CD: u16 = 0x0010;

/// Header flag word (everything between ID and QDCOUNT).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags(pub u16);

impl Flags {
    pub const fn qr(self) -> bool {
        self.0 & QR != 0
    }
    pub const fn opcode(self) -> u8 {
        ((self.0 >> 11) & 0xF) as u8
    }
    pub const fn aa(self) -> bool {
        self.0 & AA != 0
    }
    pub const fn tc(self) -> bool {
        self.0 & TC != 0
    }
    pub const fn rd(self) -> bool {
        self.0 & RD != 0
    }
    pub const fn ra(self) -> bool {
        self.0 & RA != 0
    }
    pub const fn ad(self) -> bool {
        self.0 & AD != 0
    }
    pub const fn cd(self) -> bool {
        self.0 & CD != 0
    }
    /// Low 4 bits of the RCODE (the high bits live in OPT).
    pub const fn rcode(self) -> u8 {
        (self.0 & 0xF) as u8
    }

    #[must_use]
    pub const fn with(self, bit: FlagBit, on: bool) -> Self {
        let m = bit as u16;
        Self(if on { self.0 | m } else { self.0 & !m })
    }
    #[must_use]
    pub const fn with_opcode(self, op: u8) -> Self {
        Self((self.0 & !0x7800) | (((op as u16) & 0xF) << 11))
    }
    #[must_use]
    pub const fn with_rcode(self, rc: u8) -> Self {
        Self((self.0 & !0xF) | ((rc as u16) & 0xF))
    }
}

/// Single-bit header flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FlagBit {
    Qr = QR,
    Aa = AA,
    Tc = TC,
    Rd = RD,
    Ra = RA,
    Ad = AD,
    Cd = CD,
}

/// A decoded header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: Flags,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    /// Decodes the first 12 bytes of `msg`, or `None` if it is shorter.
    pub fn parse(msg: &[u8]) -> Option<Self> {
        let h = msg.get(..HEADER_LEN)?;
        let w = |i: usize| u16::from_be_bytes([h[i], h[i + 1]]);
        Some(Self {
            id: w(0),
            flags: Flags(w(2)),
            qdcount: w(4),
            ancount: w(6),
            nscount: w(8),
            arcount: w(10),
        })
    }

    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        for (i, v) in [
            self.id,
            self.flags.0,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        ]
        .into_iter()
        .enumerate()
        {
            b[i * 2..i * 2 + 2].copy_from_slice(&v.to_be_bytes());
        }
        b
    }
}

/// Reads the message ID (0 if the buffer is too short).
pub fn id(msg: &[u8]) -> u16 {
    match msg {
        [a, b, ..] => u16::from_be_bytes([*a, *b]),
        _ => 0,
    }
}

/// Overwrites the message ID in place (no-op if the buffer is too short).
/// Used on every cache hit: cached responses are stored with ID 0.
pub fn set_id(msg: &mut [u8], id: u16) {
    if let Some(b) = msg.get_mut(..2) {
        b.copy_from_slice(&id.to_be_bytes());
    }
}

/// Reads the flag word.
pub fn flags(msg: &[u8]) -> Flags {
    match msg {
        [_, _, a, b, ..] => Flags(u16::from_be_bytes([*a, *b])),
        _ => Flags(0),
    }
}

/// Overwrites the flag word in place.
pub fn set_flags(msg: &mut [u8], f: Flags) {
    if let Some(b) = msg.get_mut(2..4) {
        b.copy_from_slice(&f.0.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_005_header_roundtrip_and_flags() {
        let h = Header {
            id: 0xBEEF,
            flags: Flags(0)
                .with(FlagBit::Qr, true)
                .with(FlagBit::Rd, true)
                .with(FlagBit::Cd, true)
                .with_opcode(2)
                .with_rcode(3),
            qdcount: 1,
            ancount: 2,
            nscount: 3,
            arcount: 4,
        };
        let b = h.to_bytes();
        let back = Header::parse(&b).unwrap();
        assert_eq!(back, h);
        assert!(back.flags.qr() && back.flags.rd() && back.flags.cd());
        assert!(!back.flags.ra() && !back.flags.aa() && !back.flags.tc());
        assert_eq!(back.flags.opcode(), 2);
        assert_eq!(back.flags.rcode(), 3);
        assert!(Header::parse(&b[..11]).is_none());
    }

    #[test]
    fn dns_006_set_id_in_place() {
        let mut b = Header::default().to_bytes();
        set_id(&mut b, 0x1234);
        assert_eq!(id(&b), 0x1234);
        set_id(&mut [0u8; 1], 7); // must not panic
    }
}
