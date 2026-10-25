//! Signed device lists and signed one-time keys.

use vodozemac::{Ed25519PublicKey, Ed25519Signature};
use yo_proto::InboxId;
use yo_proto::msg::{DeviceEntry, DeviceList, SignedDeviceList, SignedPreKey};

use crate::rik::{Rik, verify};
use crate::CryptoError;

pub fn sign_list(rik: &Rik, list: DeviceList) -> SignedDeviceList {
    let sig = rik.sign(&list.signing_bytes());
    SignedDeviceList { list, rik: rik.public(), sig }
}

/// Check that a device list is signed by the key that owns its inbox, and —
/// when we have pinned a key for that inbox — that it is the pinned key.
pub fn verify_list(signed: &SignedDeviceList, pinned_rik: Option<&[u8; 32]>) -> Result<(), CryptoError> {
    if InboxId::from_rik(&signed.rik) != signed.list.inbox {
        return Err(CryptoError::WrongIdentity);
    }
    if let Some(p) = pinned_rik {
        if p != &signed.rik {
            return Err(CryptoError::WrongIdentity);
        }
    }
    verify(&signed.rik, &signed.list.signing_bytes(), &signed.sig)?;
    for d in &signed.list.devices {
        if yo_proto::DeviceId::from_spki_hash(&d.tls_spki) != d.device {
            return Err(CryptoError::WrongIdentity);
        }
    }
    Ok(())
}

/// Verify a claimed one-time key against the device's Olm signing key.
pub fn verify_prekey(inbox: &InboxId, device: &DeviceEntry, key: &SignedPreKey) -> Result<(), CryptoError> {
    let pk = Ed25519PublicKey::from_slice(&device.ed25519).map_err(|_| CryptoError::BadKey)?;
    let sig = Ed25519Signature::from_slice(&key.sig).map_err(|_| CryptoError::BadSignature)?;
    pk.verify(&SignedPreKey::signing_bytes(inbox, &key.curve25519, key.fallback), &sig)
        .map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yo_proto::DeviceId;

    fn entry() -> DeviceEntry {
        let spki = [5u8; 32];
        DeviceEntry {
            device: DeviceId::from_spki_hash(&spki),
            curve25519: [1; 32],
            ed25519: [2; 32],
            tls_spki: spki,
            added_at: 0,
        }
    }

    #[test]
    fn signed_list_checks() {
        let rik = Rik::generate();
        let list = DeviceList { inbox: rik.inbox(), version: 1, devices: vec![entry()] };
        let signed = sign_list(&rik, list.clone());
        verify_list(&signed, Some(&rik.public())).unwrap();
        verify_list(&signed, None).unwrap();

        // A different identity (e.g. the server's own key) is rejected.
        let mallory = Rik::generate();
        assert!(verify_list(&signed, Some(&mallory.public())).is_err());
        let forged = sign_list(&mallory, list.clone());
        assert!(verify_list(&forged, Some(&rik.public())).is_err());
        assert!(verify_list(&forged, None).is_err(), "inbox does not match signer");

        // Tampering with the list after signing is rejected.
        let mut tampered = signed.clone();
        tampered.list.devices.push(entry());
        assert!(verify_list(&tampered, None).is_err());
    }
}
