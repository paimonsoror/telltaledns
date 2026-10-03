//! EDNS(0) OPT pseudo-record (RFC 6891). REQ: DNS-005.

use crate::ParseError;
use crate::consts::{MIN_UDP_PAYLOAD, opt};

/// A parsed OPT record from a query, borrowing its options from the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edns<'a> {
    /// Requestor's UDP payload size, raised to 512 if smaller (RFC 6891 §6.2.5).
    pub udp_payload: u16,
    /// Upper 8 bits of the extended RCODE.
    pub ext_rcode: u8,
    pub version: u8,
    /// DNSSEC OK bit.
    pub dnssec_ok: bool,
    /// Raw option bytes (sequence of code/length/value), already validated for framing.
    pub options: &'a [u8],
}

impl<'a> Edns<'a> {
    /// Parses the OPT fixed fields: `class` = UDP size, `ttl` = ext-rcode/version/flags.
    pub(crate) fn from_parts(class: u16, ttl: u32, rdata: &'a [u8]) -> Result<Self, ParseError> {
        validate_options(rdata)?;
        let [ext_rcode, version, flags_hi, _] = ttl.to_be_bytes();
        Ok(Self {
            udp_payload: class.max(MIN_UDP_PAYLOAD),
            ext_rcode,
            version,
            dnssec_ok: flags_hi & 0x80 != 0,
            options: rdata,
        })
    }

    /// Iterates `(code, value)` pairs.
    pub fn iter(&self) -> OptionIter<'a> {
        OptionIter { rest: self.options }
    }

    /// Value of the first option with `code`.
    pub fn option(&self, code: u16) -> Option<&'a [u8]> {
        self.iter().find(|(c, _)| *c == code).map(|(_, v)| v)
    }

    /// EDNS Client Subnet option value (RFC 7871).
    pub fn client_subnet(&self) -> Option<&'a [u8]> {
        self.option(opt::ECS)
    }

    /// DNS cookie option value (RFC 7873).
    pub fn cookie(&self) -> Option<&'a [u8]> {
        self.option(opt::COOKIE)
    }

    /// Client MAC from dnsmasq's `add-mac` option (6 bytes), for client identification (FLT-006).
    pub fn client_mac(&self) -> Option<[u8; 6]> {
        self.option(opt::DNSMASQ_MAC)
            .and_then(|v| <[u8; 6]>::try_from(v).ok())
    }

    /// TelltaleDNS loop-detection tag, if present (`spec/04` §7).
    pub fn loop_tag(&self) -> Option<&'a [u8]> {
        self.option(opt::TELLTALE_LOOP)
    }
}

impl<'a> IntoIterator for &Edns<'a> {
    type Item = (u16, &'a [u8]);
    type IntoIter = OptionIter<'a>;
    fn into_iter(self) -> OptionIter<'a> {
        self.iter()
    }
}

/// Iterator over EDNS options (`code`, `value`).
#[derive(Clone, Debug)]
pub struct OptionIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for OptionIter<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let (code, len, rest) = match self.rest {
            [c0, c1, l0, l1, rest @ ..] => (
                u16::from_be_bytes([*c0, *c1]),
                usize::from(u16::from_be_bytes([*l0, *l1])),
                rest,
            ),
            _ => return None,
        };
        let value = rest.get(..len)?;
        self.rest = &rest[len..];
        Some((code, value))
    }
}

fn validate_options(mut rdata: &[u8]) -> Result<(), ParseError> {
    while !rdata.is_empty() {
        let [_, _, l0, l1, rest @ ..] = rdata else {
            return Err(ParseError::BadOption);
        };
        let len = usize::from(u16::from_be_bytes([*l0, *l1]));
        rdata = rest.get(len..).ok_or(ParseError::BadOption)?;
    }
    Ok(())
}

/// EDNS parameters for a response we write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdnsOut<'a> {
    /// Our advertised UDP payload size (DNS-005, default 1232).
    pub udp_payload: u16,
    pub dnssec_ok: bool,
    /// Extended DNS Error to attach: info code + UTF-8 extra text (RFC 8914). REQ: DNS-013.
    pub ede: Option<(u16, &'a str)>,
}

impl EdnsOut<'_> {
    pub const fn new(udp_payload: u16) -> Self {
        Self {
            udp_payload,
            dnssec_ok: false,
            ede: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_005_option_iteration_and_validation() {
        let rdata = [
            0x00, 0x0A, 0x00, 0x02, 0xAB, 0xCD, // cookie
            0xFD, 0xE9, 0x00, 0x06, 1, 2, 3, 4, 5, 6, // dnsmasq MAC
        ];
        let e = Edns::from_parts(4096, 0x0000_8000, &rdata).unwrap();
        assert!(e.dnssec_ok);
        assert_eq!(e.udp_payload, 4096);
        assert_eq!(e.cookie(), Some(&[0xAB, 0xCD][..]));
        assert_eq!(e.client_mac(), Some([1, 2, 3, 4, 5, 6]));
        assert_eq!(e.client_subnet(), None);
        assert_eq!(e.iter().count(), 2);
        assert_eq!(
            Edns::from_parts(512, 0, &[0, 8, 0, 9, 1]),
            Err(ParseError::BadOption)
        );
        assert_eq!(Edns::from_parts(100, 0, &[]).unwrap().udp_payload, 512);
    }
}
