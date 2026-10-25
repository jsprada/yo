//! Requests, responses and server-pushed events.
//!
//! The connection is strictly request → response. After `Subscribe`, the
//! server may additionally push [`Event`]s between responses, so clients read
//! [`ServerFrame`]s.

use serde::{Deserialize, Serialize};

use crate::{DeviceId, InboxId};

/// One of my devices in a relationship inbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntry {
    /// Derived from `tls_spki`; how the server routes envelopes to the device.
    pub device: DeviceId,
    /// Olm identity key of this device's per-relationship Olm account.
    pub curve25519: [u8; 32],
    /// Olm signing key of the same account (signs one-time keys).
    pub ed25519: [u8; 32],
    /// SHA-256 of the device's TLS client certificate public key.
    pub tls_spki: [u8; 32],
    pub added_at: u64,
}

/// The full set of devices behind one inbox, with an anti-rollback version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceList {
    pub inbox: InboxId,
    pub version: u64,
    pub devices: Vec<DeviceEntry>,
}

impl DeviceList {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = b"yo/device-list/v1".to_vec();
        out.extend(postcard::to_stdvec(self).expect("serializable"));
        out
    }
}

/// A [`DeviceList`] signed by the relationship identity key (RIK) that owns
/// the inbox. `InboxId::from_rik(rik) == list.inbox` must hold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDeviceList {
    pub list: DeviceList,
    pub rik: [u8; 32],
    pub sig: Vec<u8>,
}

/// A one-time (or fallback) Olm key, signed by the device's Olm Ed25519 key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPreKey {
    pub curve25519: [u8; 32],
    pub fallback: bool,
    pub sig: Vec<u8>,
}

impl SignedPreKey {
    pub fn signing_bytes(inbox: &InboxId, curve25519: &[u8; 32], fallback: bool) -> Vec<u8> {
        let mut out = b"yo/prekey/v1".to_vec();
        out.extend_from_slice(&inbox.0);
        out.extend_from_slice(curve25519);
        out.push(fallback as u8);
        out
    }
}

/// Request to permanently delete an inbox (part of `yo burn`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteInbox {
    pub inbox: InboxId,
    pub ts: u64,
    pub rik: [u8; 32],
    pub sig: Vec<u8>,
}

impl DeleteInbox {
    pub fn signing_bytes(inbox: &InboxId, ts: u64) -> Vec<u8> {
        let mut out = b"yo/delete-inbox/v1".to_vec();
        out.extend_from_slice(&inbox.0);
        out.extend_from_slice(&ts.to_be_bytes());
        out
    }
}

/// A device's revocation authority: the public key that is allowed to
/// deregister it from the server. A device binds this to itself (over its
/// mTLS identity) once, at setup. See SECURITY_REVIEW.md L-3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindRevocation {
    pub authority: [u8; 32],
    pub sig: Vec<u8>,
    /// When replacing an existing authority: the *current* authority's
    /// signature over the same bytes, proving the holder of the old key
    /// approves the new one.
    #[serde(default)]
    pub prev_sig: Option<Vec<u8>>,
}

impl BindRevocation {
    pub fn signing_bytes(device: &DeviceId, authority: &[u8; 32]) -> Vec<u8> {
        let mut out = b"yo/bind-revocation/v1".to_vec();
        out.extend_from_slice(&device.0);
        out.extend_from_slice(authority);
        out
    }
}

/// Deregister a device, signed by that device's bound revocation authority.
/// Lets another of your devices turn off a lost one's access even though the
/// lost device will not cooperate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deregister {
    pub device: DeviceId,
    pub ts: u64,
    pub authority: [u8; 32],
    pub sig: Vec<u8>,
}

impl Deregister {
    pub fn signing_bytes(device: &DeviceId, ts: u64) -> Vec<u8> {
        let mut out = b"yo/deregister/v1".to_vec();
        out.extend_from_slice(&device.0);
        out.extend_from_slice(&ts.to_be_bytes());
        out
    }
}

/// Ciphertext addressed to one device of an inbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutEnvelope {
    pub device: DeviceId,
    pub blob: Vec<u8>,
}

/// Ciphertext delivered to a device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub id: u64,
    pub inbox: InboxId,
    pub sender: DeviceId,
    /// True when the sender is itself a member of `inbox` — i.e. a copy of
    /// something one of *my own* devices sent. Used for the unread counter.
    pub from_member: bool,
    pub ts: u64,
    pub blob: Vec<u8>,
}

/// Which participant of an invite mailbox a message belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    /// The side that opened the mailbox and displayed the code.
    Opener,
    /// The side that typed the code in.
    Joiner,
}

impl Side {
    pub fn other(self) -> Side {
        match self {
            Side::Opener => Side::Joiner,
            Side::Joiner => Side::Opener,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// First request on every connection.
    Hello {
        version: u16,
        token: Option<String>,
    },
    /// Create an inbox or replace its device list (join / remove device).
    PutDeviceList(SignedDeviceList),
    GetDeviceList {
        inbox: InboxId,
    },
    /// Replace this device's published one-time keys in `inbox`.
    PublishKeys {
        inbox: InboxId,
        one_time: Vec<SignedPreKey>,
        fallback: Option<SignedPreKey>,
    },
    /// Number of unclaimed one-time keys this device has left in `inbox`.
    KeyCount {
        inbox: InboxId,
    },
    /// Take one one-time key (or the fallback key) of `device` in `inbox`.
    ClaimKey {
        inbox: InboxId,
        device: DeviceId,
    },
    Send {
        inbox: InboxId,
        envelopes: Vec<OutEnvelope>,
    },
    Fetch,
    Ack {
        ids: Vec<u64>,
    },
    /// Ask the server to push new envelopes as [`Event::Envelope`].
    Subscribe,
    DeleteInbox(DeleteInbox),
    MailboxOpen,
    MailboxJoin {
        nameplate: u32,
    },
    MailboxPut {
        nameplate: u32,
        side: Side,
        msg: Vec<u8>,
    },
    /// Long-poll for message number `index` written by the *other* side.
    MailboxGet {
        nameplate: u32,
        side: Side,
        index: u32,
    },
    MailboxClose {
        nameplate: u32,
    },
    /// Keep-alive; answered with `Ok`.
    Ping,
    /// Bind this device's revocation authority (idempotent; first write wins).
    BindRevocation(BindRevocation),
    /// Deregister a device using its bound revocation authority.
    Deregister(Deregister),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    BadRequest,
    /// Device is not registered and the server requires a token.
    RegistrationRequired,
    Unauthorized,
    NotFound,
    /// The inbox was deleted with `yo burn`.
    Burned,
    /// Stale device list or version conflict — refetch and retry.
    Conflict,
    RateLimited,
    VersionMismatch,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Hello { version: u16, device: DeviceId },
    DeviceList(Option<SignedDeviceList>),
    Key(Option<SignedPreKey>),
    KeyCount(u32),
    Envelopes(Vec<Envelope>),
    Nameplate(u32),
    MailboxMsg(Option<Vec<u8>>),
    Error { code: ErrorCode, message: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    Envelope(Envelope),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerFrame {
    Response(Response),
    Event(Event),
}
