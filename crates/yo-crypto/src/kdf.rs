//! Key derivation: Argon2id for passphrases, HKDF-SHA256, HMAC tags.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{CryptoError, Key32};

/// Argon2id cost parameters, stored next to the salt in the keyfile so they
/// can be raised later without breaking old installs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// 64 MiB, 3 passes — roughly half a second on a laptop.
    pub const DEFAULT: KdfParams = KdfParams { m_kib: 64 * 1024, t: 3, p: 1 };
    /// Only for tests: fast and weak.
    pub const INSECURE_TEST: KdfParams = KdfParams { m_kib: 64, t: 1, p: 1 };
}

pub fn argon2id(passphrase: &[u8], salt: &[u8], p: KdfParams) -> Result<Key32, CryptoError> {
    let params = Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(out)
}

/// HKDF-SHA256 expand to a 32-byte key.
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key32 {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, out.as_mut()).expect("32 bytes is a valid HKDF output length");
    out
}

pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

pub fn hmac_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon_deterministic() {
        let a = argon2id(b"pw", b"saltsaltsaltsalt", KdfParams::INSECURE_TEST).unwrap();
        let b = argon2id(b"pw", b"saltsaltsaltsalt", KdfParams::INSECURE_TEST).unwrap();
        let c = argon2id(b"pX", b"saltsaltsaltsalt", KdfParams::INSECURE_TEST).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }

    #[test]
    fn hmac_tags() {
        let t = hmac(b"k", b"alice");
        assert!(hmac_verify(b"k", b"alice", &t));
        assert!(!hmac_verify(b"k", b"bob", &t));
    }
}
