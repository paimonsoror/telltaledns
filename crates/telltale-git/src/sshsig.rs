//! SSH commit signatures (`git config gpg.format ssh`): the SSHSIG format, Ed25519 keys only,
//! checked against an allowed-signers list (`<principal> ssh-ed25519 <base64> [comment]`).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

fn take_string<'a>(b: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let len: [u8; 4] = b
        .get(..4)
        .ok_or("truncated signature")?
        .try_into()
        .map_err(|_| "sig")?;
    let n = u32::from_be_bytes(len) as usize;
    let s = b.get(4..4 + n).ok_or("truncated signature")?;
    *b = &b[4 + n..];
    Ok(s)
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(s);
}

/// Allowed signers: the public key blobs (`ssh-ed25519` only) and their principals.
#[derive(Debug, Clone, Default)]
pub struct AllowedSigners(Vec<(String, Vec<u8>)>);

impl AllowedSigners {
    /// Parses an allowed-signers file. Lines with other key types are skipped.
    pub fn parse(text: &str) -> Self {
        let mut v = Vec::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.split_whitespace();
            let (Some(who), Some(kind), Some(b64)) = (it.next(), it.next(), it.next()) else {
                continue;
            };
            if kind == "ssh-ed25519"
                && let Ok(blob) = STANDARD.decode(b64)
            {
                v.push((who.to_owned(), blob));
            }
        }
        Self(v)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Verifies an armored SSH signature over `payload` (namespace `git`). Returns the
    /// signer's principal.
    pub fn verify(&self, armored: &str, payload: &[u8]) -> Result<String, String> {
        let b64: String = armored
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let raw = STANDARD
            .decode(b64.trim())
            .map_err(|_| "signature isn't base64")?;
        let mut b = raw.as_slice();
        if b.get(..6) != Some(b"SSHSIG") {
            return Err("not an SSH signature (only SSH signatures are supported)".into());
        }
        b = &b[6..];
        let _version = b.get(..4).ok_or("truncated signature")?;
        b = &b[4..];
        let key = take_string(&mut b)?;
        let namespace = take_string(&mut b)?;
        let reserved = take_string(&mut b)?;
        let hash_alg = take_string(&mut b)?;
        let mut sig = take_string(&mut b)?;
        if namespace != b"git" {
            return Err("the signature isn't for git".into());
        }
        let who = self
            .0
            .iter()
            .find(|(_, k)| k.as_slice() == key)
            .map(|(w, _)| w.clone())
            .ok_or("signed by a key that isn't allowed")?;
        let mut kb = key;
        if take_string(&mut kb)? != b"ssh-ed25519" {
            return Err("only ssh-ed25519 keys are supported".into());
        }
        let pk = take_string(&mut kb)?;
        if take_string(&mut sig)? != b"ssh-ed25519" {
            return Err("only ssh-ed25519 signatures are supported".into());
        }
        let sig = take_string(&mut sig)?;
        let digest = match hash_alg {
            b"sha512" => ring::digest::digest(&ring::digest::SHA512, payload),
            b"sha256" => ring::digest::digest(&ring::digest::SHA256, payload),
            _ => return Err("unsupported signature hash".into()),
        };
        let mut signed = b"SSHSIG".to_vec();
        put_string(&mut signed, namespace);
        put_string(&mut signed, reserved);
        put_string(&mut signed, hash_alg);
        put_string(&mut signed, digest.as_ref());
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pk)
            .verify(&signed, sig)
            .map_err(|_| "the signature doesn't verify".to_owned())?;
        Ok(who)
    }
}
