//! The per-query pipeline (`spec/03` §3), shared by every transport.
//!
//! Current stage: parse + reject (DNS-019) + respond. Policy, filtering, cache, and upstream
//! stages plug in here as M1/M2 tasks land; until then every well-formed query is answered
//! REFUSED with EDE 14 (Not Ready) so clients fail over to another resolver immediately.

use std::net::SocketAddr;

use telltale_net::{Datagram, DatagramHandler, Replier, StreamHandler};
use telltale_proto::{
    DEFAULT_EDNS_PAYLOAD, QueryError, ResponseBuilder, badvers_from_raw, ede, error_from_raw,
    parse_query, rcode, response_edns, truncate_for_udp, udp_limit,
};

/// Pipeline settings derived from config.
#[derive(Debug, Clone)]
pub(crate) struct Pipeline {
    /// Our advertised EDNS UDP payload size (DNS-005).
    pub(crate) edns_payload: u16,
}

impl Default for Pipeline {
    fn default() -> Self {
        Self {
            edns_payload: DEFAULT_EDNS_PAYLOAD,
        }
    }
}

impl Pipeline {
    /// Handles one query; writes the response into `out` and returns its length, or `None` to
    /// drop. `udp` selects truncation to the client's UDP limit.
    pub(crate) fn handle(&self, req: &[u8], out: &mut [u8], udp: bool) -> Option<usize> {
        let q = match parse_query(req) {
            Ok(q) => q,
            Err(QueryError::Drop) => return None,
            Err(QueryError::NotImp) => return error_from_raw(req, rcode::NOTIMP, out),
            Err(QueryError::FormErr(_)) => return error_from_raw(req, rcode::FORMERR, out),
            Err(QueryError::BadVers) => return badvers_from_raw(req, self.edns_payload, out),
        };
        let edns = response_edns(
            &q,
            self.edns_payload,
            Some((ede::NOT_READY, "resolver starting")),
        );
        let len = ResponseBuilder::new(&q, out, rcode::REFUSED)
            .ok()?
            .finish(edns)
            .ok()?;
        Some(if udp {
            truncate_for_udp(out, len, udp_limit(q.edns.as_ref(), self.edns_payload))
        } else {
            len
        })
    }
}

impl DatagramHandler for Pipeline {
    fn handle(&self, dgram: &Datagram<'_>, out: &mut [u8], _replier: &Replier) -> Option<usize> {
        Pipeline::handle(self, dgram.data, out, true)
    }
}

impl StreamHandler for Pipeline {
    fn handle(&self, req: &[u8], _peer: SocketAddr, out: &mut [u8]) -> Option<usize> {
        Pipeline::handle(self, req, out, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_proto::{EdnsOut, NameBuf, build_query, rtype, summarize};

    #[test]
    fn dns_019_pipeline_rejects_and_refuses_cleanly() {
        let p = Pipeline::default();
        let mut q = [0u8; 512];
        let name = NameBuf::from_presentation("example.com").unwrap();
        let n = build_query(
            &mut q,
            9,
            &name,
            rtype::A,
            1,
            true,
            Some(EdnsOut::new(1232)),
        )
        .unwrap();
        let mut out = [0u8; 4096];
        let len = p.handle(&q[..n], &mut out, true).unwrap();
        let s = summarize(&out[..len]).unwrap();
        assert_eq!(s.rcode, rcode::REFUSED);
        assert!(s.opt_off.is_some(), "EDE requires OPT for EDNS clients");

        assert_eq!(p.handle(&q[..5], &mut out, true), None, "runt dropped");
        let mut notify = q;
        notify[2] |= 4 << 3;
        let len = p.handle(&notify[..n], &mut out, true).unwrap();
        assert_eq!(summarize(&out[..len]).unwrap().rcode, rcode::NOTIMP);

        // EDNS version 1 → BADVERS (extended RCODE 16) in an OPT of version 0.
        let mut v1 = q;
        v1[n - 11 + 6] = 1;
        let len = p.handle(&v1[..n], &mut out, true).unwrap();
        assert_eq!(summarize(&out[..len]).unwrap().rcode, rcode::BADVERS);
    }
}
