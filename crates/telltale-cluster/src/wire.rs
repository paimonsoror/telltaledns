//! Node-to-node messages (REQ: CLU-001, CLU-010; `spec/12` §3): protobuf (`prost`), each frame
//! a 4-byte big-endian length then the encoded [`Frame`]. Fields are only ever added (never
//! renumbered), so version N and N-1 interoperate: unknown fields are ignored.

use prost::Message;

/// The protocol version this build speaks (CLU-010). Raised when a message changes meaning,
/// not when fields are added.
pub const PROTOCOL: u32 = 1;

/// Whether a peer's protocol works with ours: N and N-1 interoperate (`spec/12` §9), so a
/// rolling upgrade never splits the cluster. Further apart, the stream is refused.
pub fn protocol_compatible(peer: u32) -> bool {
    peer.abs_diff(PROTOCOL) <= 1
}
/// Largest frame accepted (snapshot manifests arrive later; blobs go over their own requests).
pub const MAX_FRAME: usize = 1 << 20;

/// The first message on a stream, both ways.
#[derive(Clone, PartialEq, Message)]
pub struct Hello {
    #[prost(uint32, tag = "1")]
    pub protocol: u32,
    #[prost(string, tag = "2")]
    pub cluster_id: String,
    #[prost(string, tag = "3")]
    pub node_id: String,
    #[prost(string, tag = "4")]
    pub version: String,
    #[prost(string, tag = "5")]
    pub site: String,
    #[prost(bool, tag = "6")]
    pub eligible: bool,
    #[prost(string, repeated, tag = "7")]
    pub advertise: Vec<String>,
    /// The highest epoch this node has seen (CLU-005).
    #[prost(uint64, tag = "8")]
    pub epoch: u64,
    /// The config version it has applied (CLU-003).
    #[prost(uint64, tag = "9")]
    pub applied_seq: u64,
    #[prost(bool, tag = "10")]
    pub primary: bool,
    /// How this node's own configuration is managed: `gitops` or `file` (ADR-048).
    #[prost(string, tag = "11")]
    pub config_source: String,
}

/// A federated read (CLU-002, T5.6): `kind` names the call, `body` carries its arguments
/// (JSON). Answered on the same stream with the same `id`.
#[derive(Clone, PartialEq, Message)]
pub struct RpcRequest {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(string, tag = "2")]
    pub kind: String,
    #[prost(bytes = "vec", tag = "3")]
    pub body: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RpcResponse {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    /// Empty on success.
    #[prost(string, tag = "2")]
    pub error: String,
    #[prost(bytes = "vec", tag = "3")]
    pub body: Vec<u8>,
}

/// The cluster CA key, from the primary to an eligible node (ADR-051).
#[derive(Clone, PartialEq, Message)]
pub struct KeyShare {
    #[prost(string, tag = "1")]
    pub ca_key_pem: String,
}

/// Sent every few seconds both ways; its absence marks a peer down.
#[derive(Clone, PartialEq, Message)]
pub struct Heartbeat {
    /// Sender's clock (Unix ms), for lag display only.
    #[prost(uint64, tag = "1")]
    pub ts_ms: u64,
    #[prost(uint64, tag = "2")]
    pub epoch: u64,
    #[prost(uint64, tag = "3")]
    pub applied_seq: u64,
    /// Queries per second over the last minute (CLU-008).
    #[prost(uint64, tag = "4")]
    pub qps: u64,
    /// The `ts_ms` of the last heartbeat received from this peer, echoed back, and how long
    /// ago it arrived: the peer computes the round-trip time from them.
    #[prost(uint64, tag = "5")]
    pub echo_ms: u64,
    #[prost(uint32, tag = "6")]
    pub echo_delay_ms: u32,
    /// Serving DNS: listeners bound and not shutting down.
    #[prost(bool, tag = "7")]
    pub ready: bool,
    /// SERVFAIL answers per thousand over the last minute.
    #[prost(uint32, tag = "8")]
    pub servfail_permille: u32,
    /// Upstream p90 this hour, in microseconds.
    #[prost(uint64, tag = "9")]
    pub p90_us: u64,
    #[prost(uint64, tag = "10")]
    pub uptime_s: u64,
}

/// A signed cluster manifest (CLU-003, `crate::sync`): the primary sends it on connect and
/// whenever it changes.
#[derive(Clone, PartialEq, Message)]
pub struct ManifestMsg {
    #[prost(bytes = "vec", tag = "1")]
    pub json: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub sig: Vec<u8>,
}

/// One message on a stream.
#[derive(Clone, PartialEq, Message)]
pub struct Frame {
    #[prost(oneof = "Body", tags = "1, 2, 3, 4, 5, 6")]
    pub body: Option<Body>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Body {
    #[prost(message, tag = "1")]
    Hello(Hello),
    #[prost(message, tag = "2")]
    Heartbeat(Heartbeat),
    #[prost(message, tag = "3")]
    Manifest(ManifestMsg),
    #[prost(message, tag = "4")]
    KeyShare(KeyShare),
    #[prost(message, tag = "5")]
    RpcRequest(RpcRequest),
    #[prost(message, tag = "6")]
    RpcResponse(RpcResponse),
}

/// A frame with its length prefix.
pub fn encode(f: &Frame) -> Vec<u8> {
    let body = f.encode_to_vec();
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Splits complete frames off the front of `buf` (incomplete bytes stay for the next read).
pub fn decode_all(buf: &mut Vec<u8>) -> Result<Vec<Frame>, String> {
    let mut out = Vec::new();
    while let Some(len) = buf.first_chunk::<4>().map(|b| u32::from_be_bytes(*b)) {
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if len > MAX_FRAME {
            return Err(format!("frame of {len} bytes is over the limit"));
        }
        if buf.len() < 4 + len {
            break;
        }
        let f = Frame::decode(&buf[4..4 + len]).map_err(|e| format!("bad frame: {e}"))?;
        buf.drain(..4 + len);
        out.push(f);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: CLU-010 — N and N-1 interoperate both ways; two versions apart don't.
    #[test]
    fn clu_010_protocols_one_version_apart_interoperate() {
        assert!(protocol_compatible(PROTOCOL));
        assert!(protocol_compatible(PROTOCOL + 1));
        assert!(protocol_compatible(PROTOCOL - 1));
        assert!(!protocol_compatible(PROTOCOL + 2));
    }

    #[test]
    fn clu_010_frames_round_trip_in_pieces() {
        let hello = Frame {
            body: Some(Body::Hello(Hello {
                protocol: PROTOCOL,
                cluster_id: "c".into(),
                node_id: "n1".into(),
                version: "0.1.0".into(),
                site: "k8s".into(),
                eligible: true,
                advertise: vec!["https://10.0.0.1:8443".into()],
                epoch: 3,
                applied_seq: 9,
                primary: false,
                config_source: String::new(),
            })),
        };
        let hb = Frame {
            body: Some(Body::Heartbeat(Heartbeat {
                ts_ms: 1,
                epoch: 3,
                applied_seq: 9,
                qps: 42,
                ..Heartbeat::default()
            })),
        };
        let mut wire = encode(&hello);
        wire.extend(encode(&hb));
        // Fed byte by byte, frames come out whole and in order.
        let mut buf = Vec::new();
        let mut got = Vec::new();
        for b in wire {
            buf.push(b);
            got.extend(decode_all(&mut buf).unwrap());
        }
        assert_eq!(got, [hello, hb]);
        assert_eq!(buf, Vec::<u8>::new());
        // A huge length is refused before any allocation.
        let mut bad = (u32::MAX).to_be_bytes().to_vec();
        assert!(decode_all(&mut bad).is_err());
    }

    #[test]
    fn clu_010_unknown_fields_are_ignored() {
        // A newer peer's Heartbeat with an extra field 99 still decodes.
        let mut body = Heartbeat {
            ts_ms: 5,
            epoch: 1,
            applied_seq: 2,
            qps: 3,
            ..Heartbeat::default()
        }
        .encode_to_vec();
        body.extend_from_slice(&[0x98, 0x06, 0x07]); // field 99, varint 7
        assert_eq!(Heartbeat::decode(&body[..]).unwrap().qps, 3);
    }
}
