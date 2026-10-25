//! Identifiers that are visible to the server.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{b32, from_b32};

/// Address of one side of one relationship on the server.
///
/// It is `SHA-256(domain || RIK public key)`, so an inbox ID commits to the
/// relationship identity key that controls it and the server cannot swap
/// that key for another one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InboxId(pub [u8; 32]);

impl InboxId {
    pub fn from_rik(rik_public: &[u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(b"yo/inbox/v1");
        h.update(rik_public);
        InboxId(h.finalize().into())
    }
}

/// A device, identified by the hash of its TLS client certificate's public key.
///
/// The server derives this from the mTLS handshake, so a device can never
/// claim to be another device.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 16]);

impl DeviceId {
    pub fn from_spki_hash(spki_hash: &[u8; 32]) -> Self {
        let mut id = [0u8; 16];
        id.copy_from_slice(&spki_hash[..16]);
        DeviceId(id)
    }

    /// Short form shown to users (first 8 base32 characters).
    pub fn short(&self) -> String {
        b32(&self.0)[..8].to_string()
    }
}

macro_rules! id_fmt {
    ($t:ty, $n:expr) => {
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&b32(&self.0))
            }
        }
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($t), &b32(&self.0)[..8])
            }
        }
        impl FromStr for $t {
            type Err = &'static str;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let v = from_b32(s).ok_or("invalid base32")?;
                let a: [u8; $n] = v.try_into().map_err(|_| "wrong length")?;
                Ok(Self(a))
            }
        }
    };
}
id_fmt!(InboxId, 32);
id_fmt!(DeviceId, 16);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbox_roundtrip() {
        let id = InboxId::from_rik(&[7u8; 32]);
        let s = id.to_string();
        assert_eq!(s.parse::<InboxId>().unwrap(), id);
        assert_ne!(InboxId::from_rik(&[8u8; 32]), id);
    }
}
