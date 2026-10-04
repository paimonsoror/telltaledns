//! Join tokens (REQ: CLU-001; `spec/12` §3): `tt_join_<base64url JSON>` holding the cluster ID,
//! the CA fingerprint the joining node pins, the URLs to try, a 256-bit secret, and an expiry.
//! The primary keeps only a hash of the secret.

use serde::{Deserialize, Serialize};

use crate::pki::hex;

pub const PREFIX: &str = "tt_join_";

/// A join token's contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub v: u8,
    pub cluster_id: String,
    pub cluster_name: String,
    /// SHA-256 of the CA certificate (hex).
    pub ca_fp: String,
    /// Cluster URLs to try, e.g. `https://192.168.3.2:8443`.
    pub urls: Vec<String>,
    /// The secret (hex, 32 bytes).
    pub secret: String,
    /// Expiry (Unix seconds).
    pub exp: u64,
}

impl Token {
    pub fn encode(&self) -> String {
        format!(
            "{PREFIX}{}",
            b64url(serde_json::to_string(self).unwrap_or_default().as_bytes())
        )
    }

    pub fn decode(s: &str) -> Result<Self, String> {
        let body = s
            .trim()
            .strip_prefix(PREFIX)
            .ok_or("not a TelltaleDNS join token (it starts with tt_join_)")?;
        let json = b64url_decode(body).ok_or("the token is damaged (bad base64)")?;
        let t: Self =
            serde_json::from_slice(&json).map_err(|e| format!("the token is damaged: {e}"))?;
        if t.v != 1 {
            return Err(format!("token version {} isn't supported", t.v));
        }
        Ok(t)
    }

    /// The hash the primary stores and compares (SHA-256 of the secret, hex).
    pub fn secret_hash(secret_hex: &str) -> String {
        hex(ring::digest::digest(&ring::digest::SHA256, secret_hex.as_bytes()).as_ref())
    }
}

/// A random 32-byte secret, hex.
pub fn new_secret() -> String {
    let mut b = [0u8; 32];
    rand::fill(&mut b);
    hex(&b)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            s.push(char::from(
                ALPHABET[usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0)],
            ));
        }
    }
    s
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| {
        ALPHABET
            .iter()
            .position(|a| *a == c)
            .and_then(|p| u32::try_from(p).ok())
    };
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.trim_end_matches('=').as_bytes().chunks(4) {
        let mut acc = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            acc |= val(*c)? << (18 - 6 * i);
        }
        let b = acc.to_be_bytes();
        match chunk.len() {
            4 => out.extend_from_slice(&b[1..4]),
            3 => out.extend_from_slice(&b[1..3]),
            2 => out.push(b[1]),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clu_001_tokens_round_trip_and_reject_garbage() {
        let t = Token {
            v: 1,
            cluster_id: "c1".into(),
            cluster_name: "home".into(),
            ca_fp: "ab".repeat(32),
            urls: vec!["https://192.168.3.2:8443".into()],
            secret: new_secret(),
            exp: 1_790_000_000,
        };
        let s = t.encode();
        assert!(s.starts_with("tt_join_"));
        assert!(!s.contains(['+', '/', '=']), "URL-safe and unpadded");
        assert_eq!(Token::decode(&s).unwrap(), t);
        assert!(Token::decode("tt_join_!!!").is_err());
        assert!(Token::decode("vgl_join_abc").is_err());
        assert_ne!(new_secret(), new_secret());
        assert_eq!(Token::secret_hash(&t.secret).len(), 64);
    }
}
