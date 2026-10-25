//! The keyfile holds the data key (DK) wrapped under a key derived from the
//! passphrase with Argon2id. Changing the passphrase only re-wraps the DK.

use serde::{Deserialize, Serialize};
use yo_crypto::kdf::{KdfParams, argon2id};
use yo_crypto::{Key32, Zeroizing, aead, random, random_key};

use crate::{Result, StoreError};

const AAD: &[u8] = b"yo/keyfile/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyFile {
    pub version: u8,
    pub kdf: KdfParams,
    pub salt: [u8; 16],
    pub wrapped_dk: Vec<u8>,
}

impl KeyFile {
    /// Create a keyfile with a fresh random data key.
    pub fn create(passphrase: &str, kdf: KdfParams) -> Result<(KeyFile, Key32)> {
        let dk = random_key();
        let kf = Self::wrap(passphrase, kdf, &dk)?;
        Ok((kf, dk))
    }

    fn wrap(passphrase: &str, kdf: KdfParams, dk: &Key32) -> Result<KeyFile> {
        let salt: [u8; 16] = random();
        let kek = argon2id(passphrase.as_bytes(), &salt, kdf)?;
        Ok(KeyFile { version: 1, kdf, salt, wrapped_dk: aead::seal(&kek, AAD, dk.as_ref()) })
    }

    pub fn unlock(&self, passphrase: &str) -> Result<Key32> {
        let kek = argon2id(passphrase.as_bytes(), &self.salt, self.kdf)?;
        let dk = Zeroizing::new(aead::open(&kek, AAD, &self.wrapped_dk).map_err(|_| StoreError::WrongPassphrase)?);
        let arr: [u8; 32] = dk.as_slice().try_into().map_err(|_| StoreError::Corrupt("keyfile".into()))?;
        Ok(Zeroizing::new(arr))
    }

    /// Re-wrap the same DK under a new passphrase.
    pub fn rewrap(&self, old: &str, new: &str) -> Result<KeyFile> {
        let dk = self.unlock(old)?;
        Self::wrap(new, self.kdf, &dk)
    }

    pub fn load(path: &std::path::Path) -> Result<KeyFile> {
        let text = std::fs::read(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => StoreError::NotInitialized,
            _ => e.into(),
        })?;
        serde_json::from_slice(&text).map_err(|e| StoreError::Corrupt(e.to_string()))
    }

    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let text = serde_json::to_vec_pretty(self).expect("serializable");
        crate::write_private(path, &text)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_unlock_rewrap() {
        let (kf, dk) = KeyFile::create("correct horse", KdfParams::INSECURE_TEST).unwrap();
        assert_eq!(*kf.unlock("correct horse").unwrap(), *dk);
        assert!(matches!(kf.unlock("wrong"), Err(StoreError::WrongPassphrase)));
        let kf2 = kf.rewrap("correct horse", "battery staple").unwrap();
        assert_eq!(*kf2.unlock("battery staple").unwrap(), *dk);
        assert!(kf2.unlock("correct horse").is_err());
    }
}
