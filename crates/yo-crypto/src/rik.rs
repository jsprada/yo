//! Relationship Identity Keys.
//!
//! Every contact relationship gets a brand-new Ed25519 key pair. Its public
//! half is what the other person pins during `yo add`; it signs the device
//! list of my inbox for that relationship, and it authorizes `yo burn`.
//! Nothing ties the RIKs of two different relationships together.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use yo_proto::InboxId;
use zeroize::Zeroizing;

use crate::{CryptoError, random};

pub struct Rik(SigningKey);

impl Rik {
    pub fn generate() -> Self {
        let seed = Zeroizing::new(random::<32>());
        Rik(SigningKey::from_bytes(&seed))
    }

    pub fn from_secret(secret: &[u8; 32]) -> Self {
        Rik(SigningKey::from_bytes(secret))
    }

    pub fn secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn inbox(&self) -> InboxId {
        InboxId::from_rik(&self.public())
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.0.sign(msg).to_bytes().to_vec()
    }
}

/// Verify an Ed25519 signature (strict: rejects malleable / weak keys).
pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| CryptoError::BadKey)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| CryptoError::BadSignature)?;
    key.verify_strict(msg, &Signature::from_bytes(&sig)).map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify() {
        let k = Rik::generate();
        let s = k.sign(b"hello");
        verify(&k.public(), b"hello", &s).unwrap();
        assert!(verify(&k.public(), b"hellO", &s).is_err());
        let k2 = Rik::from_secret(&k.secret());
        assert_eq!(k2.public(), k.public());
        assert_ne!(Rik::generate().public(), k.public());
    }
}
