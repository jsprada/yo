//! Plaintext shapes of the encrypted records.

use serde::{Deserialize, Serialize};
use yo_crypto::rik::Rik;
use yo_proto::InboxId;
use yo_proto::msg::DeviceEntry;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelKind {
    /// The relationship between my own devices (used for sync).
    Myself,
    Contact,
}

/// Everything about one relationship except its Olm state. Sealed with DK.
#[derive(Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub kind: RelKind,
    /// Local name for the contact. Never leaves my devices.
    pub nickname: String,
    /// My Relationship Identity Key (secret half) for this contact.
    pub rik_secret: [u8; 32],
    /// Relationship Storage Key: encrypts this relationship's rows.
    pub rsk: [u8; 32],
    /// The contact's RIK, pinned during `yo add`.
    pub peer_rik: Option<[u8; 32]>,
    /// True when keys were exchanged with an invite code (or safety words
    /// were compared).
    pub verified: bool,
    pub created_at: u64,
    /// Last accepted version of each side's device list (anti-rollback).
    pub my_list_version: u64,
    pub peer_list_version: u64,
    /// Cached, already-verified device lists.
    pub my_devices: Vec<DeviceEntry>,
    pub peer_devices: Vec<DeviceEntry>,
    /// When this device's current Olm fallback key for the relationship was
    /// generated; rotated by the client (SECURITY_REVIEW.md, M-3).
    #[serde(default)]
    pub fallback_at: u64,
}

impl Drop for Bundle {
    fn drop(&mut self) {
        self.rik_secret.zeroize();
        self.rsk.zeroize();
    }
}

impl Bundle {
    pub fn rik(&self) -> Rik {
        Rik::from_secret(&self.rik_secret)
    }

    pub fn my_inbox(&self) -> InboxId {
        self.rik().inbox()
    }

    pub fn peer_inbox(&self) -> Option<InboxId> {
        self.peer_rik.as_ref().map(InboxId::from_rik)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    In,
    Out,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageKind {
    Text,
    /// Something yo! itself reports, e.g. "alice burned this conversation".
    Notice,
}

/// One message as stored locally. Sealed with the relationship's RSK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMessage {
    pub uuid: [u8; 16],
    pub direction: Direction,
    pub kind: MessageKind,
    pub sent_at: u64,
    pub received_at: u64,
    pub body: String,
    pub reply_to: Option<[u8; 16]>,
}

impl Drop for StoredMessage {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}
