//! XChaCha20-Poly1305 with a random 192-bit nonce: `nonce || ciphertext+tag`.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};

use crate::{CryptoError, random};

const NONCE: usize = 24;

pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce: [u8; NONCE] = random();
    let ct = cipher
        .encrypt(&nonce.into(), Payload { msg: plaintext, aad })
        .expect("xchacha encryption cannot fail for in-memory buffers");
    let mut out = Vec::with_capacity(NONCE + ct.len());
    out.extend_from_slice(&nonce);
    out.extend(ct);
    out
}

pub fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < NONCE + 16 {
        return Err(CryptoError::Decrypt);
    }
    let (nonce, ct) = sealed.split_at(NONCE);
    let nonce: [u8; NONCE] = nonce.try_into().map_err(|_| CryptoError::Decrypt)?;
    XChaCha20Poly1305::new(key.into())
        .decrypt(&nonce.into(), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_aad_binding() {
        let k = [1u8; 32];
        let s = seal(&k, b"row:1", b"secret");
        assert_eq!(open(&k, b"row:1", &s).unwrap(), b"secret");
        assert!(open(&k, b"row:2", &s).is_err(), "moved row must not decrypt");
        assert!(open(&[2u8; 32], b"row:1", &s).is_err());
        let mut t = s.clone();
        *t.last_mut().unwrap() ^= 1;
        assert!(open(&k, b"row:1", &t).is_err());
    }
}
