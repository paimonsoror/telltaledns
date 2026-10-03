//! Zero-copy query parsing for the hot path (`spec/03` §2).

use crate::consts::{opcode, rtype};
use crate::edns::Edns;
use crate::header::{HEADER_LEN, Header};
use crate::name::{NameBuf, read_name_uncompressed, skip_name};
use crate::{ParseError, be16, be32};

/// A parsed client query. Borrows the receive buffer; the qname is copied (lowercased) to the stack.
#[derive(Clone, Copy, Debug)]
pub struct Query<'a> {
    pub msg: &'a [u8],
    pub header: Header,
    /// Lowercased question name.
    pub qname: NameBuf,
    pub qtype: u16,
    pub qclass: u16,
    /// Offset just past the question; `msg[12..question_end]` is the question as sent
    /// (original case, which responses must echo for 0x20-randomizing clients).
    pub question_end: usize,
    pub edns: Option<Edns<'a>>,
}

impl<'a> Query<'a> {
    /// The question section bytes exactly as the client sent them.
    pub fn question_bytes(&self) -> &'a [u8] {
        &self.msg[HEADER_LEN..self.question_end]
    }

    pub fn is_any(&self) -> bool {
        self.qtype == rtype::ANY
    }
}

/// Why a query was rejected, and what to do about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryError {
    /// Not answerable at all (no full header, or QR=1). Drop silently (DNS-019).
    Drop,
    /// Opcode we don't implement: answer NOTIMP.
    NotImp,
    /// Malformed: answer FORMERR.
    FormErr(ParseError),
    /// EDNS version > 0: answer BADVERS with an OPT of version 0 (RFC 6891 §6.1.3).
    BadVers,
}

/// Parses a client query.
///
/// REQ: DNS-005 (EDNS), DNS-019 (cheap rejection of malformed packets).
/// Rejects: short packets and QR=1 (drop), opcode != QUERY (NOTIMP), QDCOUNT != 1,
/// bad names, compression in the question, multiple or misplaced OPT (FORMERR).
pub fn parse_query(msg: &[u8]) -> Result<Query<'_>, QueryError> {
    let header = Header::parse(msg).ok_or(QueryError::Drop)?;
    if header.flags.qr() {
        return Err(QueryError::Drop);
    }
    if header.flags.opcode() != opcode::QUERY {
        return Err(QueryError::NotImp);
    }
    if header.qdcount != 1 {
        return Err(QueryError::FormErr(ParseError::QuestionCount));
    }
    let mut qname = NameBuf::default();
    let pos = read_name_uncompressed(msg, HEADER_LEN, &mut qname).map_err(QueryError::FormErr)?;
    let qtype = be16(msg, pos).ok_or(QueryError::FormErr(ParseError::Truncated))?;
    let qclass = be16(msg, pos + 2).ok_or(QueryError::FormErr(ParseError::Truncated))?;
    let question_end = pos + 4;

    let edns = find_opt(msg, &header, question_end).map_err(QueryError::FormErr)?;
    if let Some(e) = &edns
        && e.version != 0
    {
        return Err(QueryError::BadVers);
    }
    Ok(Query {
        msg,
        header,
        qname,
        qtype,
        qclass,
        question_end,
        edns,
    })
}

/// Walks the answer/authority/additional sections (normally empty except OPT in a query)
/// and returns the OPT record if present.
fn find_opt<'a>(
    msg: &'a [u8],
    header: &Header,
    mut pos: usize,
) -> Result<Option<Edns<'a>>, ParseError> {
    let an_ns = usize::from(header.ancount) + usize::from(header.nscount);
    let total = an_ns + usize::from(header.arcount);
    let mut found = None;
    for i in 0..total {
        let name_start = pos;
        pos = skip_name(msg, pos)?;
        let rtype = be16(msg, pos).ok_or(ParseError::Truncated)?;
        let class = be16(msg, pos + 2).ok_or(ParseError::Truncated)?;
        let ttl = be32(msg, pos + 4).ok_or(ParseError::Truncated)?;
        let rdlen = usize::from(be16(msg, pos + 8).ok_or(ParseError::Truncated)?);
        let rdata = msg
            .get(pos + 10..pos + 10 + rdlen)
            .ok_or(ParseError::Truncated)?;
        pos += 10 + rdlen;
        if rtype == rtype::OPT {
            // RFC 6891 §6.1.1: one OPT, in the additional section, owned by the root.
            if i < an_ns || msg.get(name_start) != Some(&0) || found.is_some() {
                return Err(ParseError::BadOpt);
            }
            found = Some(Edns::from_parts(class, ttl, rdata)?);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::build_query;
    use crate::edns::EdnsOut;

    fn q(name: &str, qtype: u16, edns: Option<EdnsOut<'_>>) -> Vec<u8> {
        let mut buf = [0u8; 512];
        let n = NameBuf::from_presentation(name).unwrap();
        let len = build_query(&mut buf, 0x4242, &n, qtype, 1, true, edns).unwrap();
        buf[..len].to_vec()
    }

    #[test]
    fn dns_005_parse_query_with_edns() {
        let mut e = EdnsOut::new(1232);
        e.dnssec_ok = true;
        let msg = q("WwW.Example.com", rtype::AAAA, Some(e));
        let query = parse_query(&msg).unwrap();
        assert_eq!(query.header.id, 0x4242);
        assert!(query.header.flags.rd());
        assert_eq!(query.qname.display().to_string(), "www.example.com");
        assert_eq!(query.qtype, rtype::AAAA);
        let edns = query.edns.unwrap();
        assert_eq!(edns.udp_payload, 1232);
        assert!(edns.dnssec_ok);
        assert_eq!(query.question_bytes().len(), 17 + 4);
    }

    #[test]
    fn dns_019_rejections() {
        let good = q("example.com", rtype::A, None);
        assert_eq!(parse_query(&good[..11]).unwrap_err(), QueryError::Drop);

        let mut resp = good.clone();
        resp[2] |= 0x80; // QR
        assert_eq!(parse_query(&resp).unwrap_err(), QueryError::Drop);

        let mut notify = good.clone();
        notify[2] |= 4 << 3; // opcode NOTIFY
        assert_eq!(parse_query(&notify).unwrap_err(), QueryError::NotImp);

        let mut two_q = good.clone();
        two_q[5] = 2;
        assert!(matches!(parse_query(&two_q), Err(QueryError::FormErr(_))));

        let cut = &good[..good.len() - 1];
        assert!(matches!(parse_query(cut), Err(QueryError::FormErr(_))));
    }

    #[test]
    fn dns_005_badvers_and_duplicate_opt() {
        let mut msg = q("example.com", rtype::A, Some(EdnsOut::new(1232)));
        // OPT TTL field: ext-rcode(1) version(1) flags(2); the OPT RR is the last 11 bytes.
        let ver = msg.len() - 11 + 1 + 2 + 2 + 1;
        msg[ver] = 1;
        assert_eq!(parse_query(&msg).unwrap_err(), QueryError::BadVers);

        let mut dup = q("example.com", rtype::A, Some(EdnsOut::new(1232)));
        let opt = dup[dup.len() - 11..].to_vec();
        dup.extend_from_slice(&opt);
        dup[11] = 2; // ARCOUNT
        assert_eq!(
            parse_query(&dup).unwrap_err(),
            QueryError::FormErr(ParseError::BadOpt)
        );
    }
}
