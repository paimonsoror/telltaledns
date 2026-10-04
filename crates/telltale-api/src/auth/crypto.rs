//! Credential primitives (`spec/08` §6): Argon2id passwords (m=19 MiB, t=2, p=1), random
//! 256-bit secrets stored only as BLAKE3 hashes, constant-time comparison, TOTP (RFC 6238),
//! and recovery codes.

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Passwords: at least this long (NIST SP 800-63B allows 8; 10 for an admin surface), at most
/// this long (Argon2 cost doesn't depend on length, but bodies are bounded).
pub const MIN_PASSWORD: usize = 10;
pub const MAX_PASSWORD: usize = 256;

/// Argon2id with the `spec/08` §6 parameters (argon2's defaults: m=19 MiB, t=2, p=1).
fn argon() -> Argon2<'static> {
    Argon2::default()
}

/// PHC-format hash of a password. Slow by design (tens of ms; ~0.3 s on a Pi): call from a
/// blocking thread.
pub fn hash_password(password: &str) -> Result<String, String> {
    argon()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| format!("password hashing failed: {e}"))
}

/// Checks a password against a PHC hash (constant-time inside argon2).
pub fn verify_password(password: &str, hash: &str) -> bool {
    argon().verify_password(password.as_bytes(), hash).is_ok()
}

/// Accepts only an Argon2id PHC string (`$argon2id$v=19$m=...`), e.g. from
/// `telltale auth hash-password`.
pub fn check_phc(hash: &str) -> Result<(), crate::problem::Problem> {
    match argon2::password_hash::phc::PasswordHash::new(hash.trim()) {
        Ok(h) if h.algorithm.as_str() == "argon2id" => Ok(()),
        _ => Err(crate::problem::Problem::invalid(
            "the password hash must be an Argon2id PHC string ($argon2id$v=19$...)",
        )
        .hint("Generate one with `telltale auth hash-password`.")),
    }
}

/// A valid hash nobody's password matches, verified for unknown usernames so a failed login
/// takes the same time whether or not the user exists.
pub fn dummy_verify(password: &str) {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let h = DUMMY.get_or_init(|| hash_password("telltale-dummy-password").unwrap_or_default());
    let _ = verify_password(password, h);
}

/// 32 random bytes, URL-safe base64 (43 characters).
pub fn random_secret() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

/// 12 random bytes, URL-safe base64 (16 characters): token IDs.
pub fn random_id() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 12]>())
}

/// What a stored secret is compared by.
pub fn secret_hash(secret: &str) -> Vec<u8> {
    blake3::hash(secret.as_bytes()).as_bytes().to_vec()
}

/// Constant-time equality of two hashes or tokens.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// RFC 4648 base32, no padding (authenticator apps take TOTP secrets this way).
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buf >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buf << (5 - bits)) & 31) as usize]));
    }
    out
}

/// A new 160-bit TOTP secret (RFC 4226 recommends 160 bits).
pub fn new_totp_secret() -> Vec<u8> {
    rand::random::<[u8; 20]>().to_vec()
}

/// `otpauth://` URL for authenticator apps (6 digits, 30 s, SHA-1: what every app supports).
pub fn otpauth_url(issuer: &str, username: &str, secret: &[u8]) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect::<String>()
    };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        enc(issuer),
        enc(username),
        base32(secret),
        enc(issuer)
    )
}

/// The time step a TOTP code is valid for at `now` (±1 step of clock skew), if any.
pub fn totp_step(secret: &[u8], code: &str, now: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let totp = totp_rs::Builder::new()
        .with_secret(secret.to_vec())
        .with_skew(1)
        .build()
        .ok()?;
    totp.check(code, now)
}

/// Ten single-use recovery codes (`xxxxx-xxxxx`, base32 lowercase) and their hashes.
pub fn recovery_codes() -> (Vec<String>, Vec<Vec<u8>>) {
    (0..10)
        .map(|_| {
            let raw = base32(&rand::random::<[u8; 7]>()).to_ascii_lowercase();
            let code = format!("{}-{}", &raw[..5], &raw[5..10]);
            let hash = recovery_hash(&code);
            (code, hash)
        })
        .unzip()
}

/// Hash of a recovery code as typed (case, spaces, and dashes don't matter).
pub fn recovery_hash(code: &str) -> Vec<u8> {
    let norm: String = code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    secret_hash(&norm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_003_password_hashes_verify_and_use_spec_parameters() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{h}");
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("correct horse batterY", &h));
        assert!(!verify_password("x", "not a hash"));
        assert_ne!(
            hash_password("same").unwrap(),
            hash_password("same").unwrap(),
            "salted"
        );
    }

    #[test]
    fn api_003_secrets_and_encodings() {
        assert_eq!(random_secret().len(), 43);
        assert_eq!(random_id().len(), 16);
        assert!(ct_eq(&secret_hash("a"), &secret_hash("a")));
        assert!(!ct_eq(&secret_hash("a"), &secret_hash("b")));
        // RFC 4648 test vectors.
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"f"), "MY");
        let url = otpauth_url("TelltaleDNS", "ana maria", b"12345678901234567890");
        assert_eq!(
            url,
            "otpauth://totp/TelltaleDNS:ana%20maria?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=TelltaleDNS&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn api_003_totp_matches_rfc6238_and_allows_one_step_of_skew() {
        // RFC 6238 appendix B, SHA-1, 8 digits: 94287082 at T=59 → the 6-digit code is 287082.
        let secret = b"12345678901234567890";
        assert_eq!(totp_step(secret, "287082", 59), Some(1));
        assert_eq!(totp_step(secret, "287082", 89), Some(1), "one step late");
        assert_eq!(totp_step(secret, "287082", 200), None, "too late");
        assert_eq!(totp_step(secret, "28708", 59), None);
        assert_eq!(totp_step(secret, "abcdef", 59), None);
    }

    #[test]
    fn api_003_recovery_codes_are_single_format_and_normalized() {
        let (codes, hashes) = recovery_codes();
        assert_eq!((codes.len(), hashes.len()), (10, 10));
        assert!(
            codes
                .iter()
                .all(|c| c.len() == 11 && c.as_bytes()[5] == b'-')
        );
        let typed = codes[0].to_ascii_uppercase().replace('-', " ");
        assert_eq!(recovery_hash(&typed), hashes[0]);
    }
}
