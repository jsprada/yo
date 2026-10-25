//! What is inside an end-to-end-encrypted envelope.

use serde::{Deserialize, Serialize};
use yo_proto::InboxId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payload {
    pub uuid: [u8; 16],
    pub sent_at: u64,
    pub body: Body,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Body {
    Text {
        text: String,
        reply_to: Option<[u8; 16]>,
    },
    /// "Destroy this conversation." Signed by the sender's RIK over
    /// `(inbox, ts)` so it can be verified with only the pinned key.
    Burn {
        inbox: InboxId,
        ts: u64,
        sig: Vec<u8>,
    },
    /// Sync between my own devices (only accepted on the Myself relationship).
    Sync(SyncEvent),
    /// "My identity key for this conversation is now `new_rik`." Signed by
    /// the old key the contact has pinned (`sig_old`) and by the new key
    /// (`sig_new`, proof of possession). SECURITY_REVIEW.md L-3.
    Rekey {
        old_inbox: InboxId,
        new_rik: [u8; 32],
        ts: u64,
        sig_old: Vec<u8>,
        sig_new: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncEvent {
    ContactAdded(ContactSecret),
    Renamed {
        inbox: InboxId,
        nickname: String,
    },
    /// One of my devices rotated a relationship's identity key: adopt it.
    Rekeyed(RekeySecret),
}

/// The new secret for a re-keyed relationship, identified by its old inbox.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RekeySecret {
    pub old_inbox: InboxId,
    pub new_rik_secret: [u8; 32],
}

impl Drop for RekeySecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.new_rik_secret);
    }
}

/// What one of my devices needs to join a relationship.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactSecret {
    pub nickname: String,
    pub rik_secret: [u8; 32],
    pub peer_rik: [u8; 32],
    pub verified: bool,
    pub created_at: u64,
}

impl Drop for ContactSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.rik_secret);
    }
}

/// Exchanged during `yo add` (sealed with the PAKE key).
#[derive(Serialize, Deserialize)]
pub struct AddPayload {
    pub rik: [u8; 32],
}

/// Sent by an existing device to a new one during `yo link`.
#[derive(Serialize, Deserialize)]
pub struct LinkPayload {
    pub self_rik_secret: [u8; 32],
    pub contacts: Vec<ContactSecret>,
}

impl Drop for LinkPayload {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.self_rik_secret);
    }
}

/// Sent by the new device during `yo link` (informational).
#[derive(Serialize, Deserialize)]
pub struct LinkHello {
    pub device: yo_proto::DeviceId,
}

pub fn burn_signing_bytes(inbox: &InboxId, ts: u64) -> Vec<u8> {
    let mut out = b"yo/burn/v1".to_vec();
    out.extend_from_slice(&inbox.0);
    out.extend_from_slice(&ts.to_be_bytes());
    out
}

pub fn rekey_signing_bytes(old_inbox: &InboxId, new_rik: &[u8; 32], ts: u64) -> Vec<u8> {
    let mut out = b"yo/rekey/v1".to_vec();
    out.extend_from_slice(&old_inbox.0);
    out.extend_from_slice(new_rik);
    out.extend_from_slice(&ts.to_be_bytes());
    out
}

pub fn new_uuid() -> [u8; 16] {
    yo_crypto::random()
}
