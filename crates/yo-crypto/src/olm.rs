//! End-to-end encryption with Olm (X3DH-style 3DH handshake + Double
//! Ratchet), implemented by the audited `vodozemac` crate.
//!
//! One [`OlmState`] exists per (device, relationship): a device never reuses
//! Olm identity keys between two contacts.

use serde::{Deserialize, Serialize};
use vodozemac::Curve25519PublicKey;
use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};
use yo_proto::InboxId;
use yo_proto::msg::{DeviceEntry, SignedPreKey};
use zeroize::Zeroizing;

use crate::CryptoError;

/// Olm sessions kept per remote device. When both sides start a session at
/// the same time we briefly have two; old ones are pruned beyond this.
const MAX_SESSIONS_PER_DEVICE: usize = 4;

fn config() -> SessionConfig {
    SessionConfig::version_1()
}

/// What actually travels (inside an envelope) between two devices.
#[derive(Serialize, Deserialize)]
struct WireCipher {
    /// Sender's Olm Curve25519 identity key. Not trusted on its own: a
    /// message only decrypts with a session shared with that key.
    sender: [u8; 32],
    kind: u8,
    body: Vec<u8>,
}

pub struct OlmState {
    account: Account,
    /// `(remote Curve25519 key, session)`, oldest first.
    sessions: Vec<([u8; 32], Session)>,
}

#[derive(Serialize, Deserialize)]
struct Pickle {
    account: AccountPickle,
    sessions: Vec<([u8; 32], SessionPickle)>,
}

impl Default for OlmState {
    fn default() -> Self {
        Self::new()
    }
}

impl OlmState {
    pub fn new() -> Self {
        OlmState { account: Account::new(), sessions: Vec::new() }
    }

    /// Serialize all secret state. The caller must encrypt the result.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let p = Pickle {
            account: self.account.pickle(),
            sessions: self.sessions.iter().map(|(r, s)| (*r, s.pickle())).collect(),
        };
        Zeroizing::new(serde_json::to_vec(&p).expect("pickle serializes"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let p: Pickle = serde_json::from_slice(bytes).map_err(|e| CryptoError::Serde(e.to_string()))?;
        Ok(OlmState {
            account: Account::from_pickle(p.account),
            sessions: p.sessions.into_iter().map(|(r, s)| (r, Session::from_pickle(s))).collect(),
        })
    }

    pub fn curve25519(&self) -> [u8; 32] {
        self.account.curve25519_key().to_bytes()
    }

    pub fn ed25519(&self) -> [u8; 32] {
        *self.account.ed25519_key().as_bytes()
    }

    pub fn device_entry(&self, tls_spki: [u8; 32], added_at: u64) -> DeviceEntry {
        DeviceEntry {
            device: yo_proto::DeviceId::from_spki_hash(&tls_spki),
            curve25519: self.curve25519(),
            ed25519: self.ed25519(),
            tls_spki,
            added_at,
        }
    }

    /// Generate `count` fresh signed one-time keys, plus (when `new_fallback`)
    /// a new fallback key that is used once the one-time keys run out.
    pub fn prekeys(
        &mut self,
        inbox: &InboxId,
        count: usize,
        new_fallback: bool,
    ) -> (Vec<SignedPreKey>, Option<SignedPreKey>) {
        self.account.generate_one_time_keys(count);
        let sign = |acct: &Account, k: Curve25519PublicKey, fallback: bool| {
            let curve = k.to_bytes();
            let sig = acct.sign(SignedPreKey::signing_bytes(inbox, &curve, fallback));
            SignedPreKey { curve25519: curve, fallback, sig: sig.to_bytes().to_vec() }
        };
        let otks = self
            .account
            .one_time_keys()
            .into_values()
            .map(|k| sign(&self.account, k, false))
            .collect();
        let fallback = if new_fallback {
            self.account.generate_fallback_key();
            self.account.fallback_key().into_values().next().map(|k| sign(&self.account, k, true))
        } else {
            None
        };
        self.account.mark_keys_as_published();
        (otks, fallback)
    }

    pub fn has_session(&self, remote: &[u8; 32]) -> bool {
        self.sessions.iter().any(|(r, _)| r == remote)
    }

    /// Start a new outbound session with a remote device using one of its
    /// (already signature-verified) one-time keys.
    pub fn start_session(&mut self, remote: &[u8; 32], one_time_key: &[u8; 32]) -> Result<(), CryptoError> {
        let session = self
            .account
            .create_outbound_session(
                config(),
                Curve25519PublicKey::from_bytes(*remote),
                Curve25519PublicKey::from_bytes(*one_time_key),
            )
            .map_err(|e| CryptoError::Olm(e.to_string()))?;
        self.push_session(*remote, session);
        Ok(())
    }

    fn push_session(&mut self, remote: [u8; 32], session: Session) {
        self.sessions.push((remote, session));
        let mut count = self.sessions.iter().filter(|(r, _)| *r == remote).count();
        while count > MAX_SESSIONS_PER_DEVICE {
            let oldest = self.sessions.iter().position(|(r, _)| *r == remote).expect("counted");
            self.sessions.remove(oldest);
            count -= 1;
        }
    }

    /// Mark session `i` as the most recently used one (it moves to the end).
    fn touch(&mut self, i: usize) {
        let s = self.sessions.remove(i);
        self.sessions.push(s);
    }

    /// Encrypt for `remote` with the most recently used session.
    pub fn encrypt(&mut self, remote: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let (_, session) = self
            .sessions
            .iter_mut()
            .rev()
            .find(|(r, _)| r == remote)
            .ok_or(CryptoError::NoSession)?;
        let msg = session.encrypt(plaintext).map_err(|e| CryptoError::Olm(e.to_string()))?;
        let (kind, body) = msg.to_parts();
        let wire = WireCipher { sender: self.curve25519(), kind: kind as u8, body };
        Ok(postcard::to_stdvec(&wire).expect("serializable"))
    }

    /// Decrypt a message. Returns the sender's Curve25519 key — authenticated
    /// by the fact that the message decrypted with a session bound to it.
    pub fn decrypt(&mut self, wire: &[u8]) -> Result<([u8; 32], Zeroizing<Vec<u8>>), CryptoError> {
        let w: WireCipher = postcard::from_bytes(wire).map_err(|e| CryptoError::Serde(e.to_string()))?;
        let msg = OlmMessage::from_parts(w.kind as usize, &w.body).map_err(|e| CryptoError::Olm(e.to_string()))?;
        let remote = w.sender;

        if let OlmMessage::PreKey(pre) = &msg {
            let sid = pre.session_id();
            if let Some(i) = self.sessions.iter().position(|(r, s)| *r == remote && s.session_id() == sid) {
                let pt = self.sessions[i].1.decrypt(&msg).map_err(|e| CryptoError::Olm(e.to_string()))?;
                self.touch(i);
                return Ok((remote, Zeroizing::new(pt)));
            }
            let res = self
                .account
                .create_inbound_session(config(), Curve25519PublicKey::from_bytes(remote), pre)
                .map_err(|e| CryptoError::Olm(e.to_string()))?;
            self.push_session(remote, res.session);
            return Ok((remote, Zeroizing::new(res.plaintext)));
        }

        for i in (0..self.sessions.len()).rev() {
            if self.sessions[i].0 != remote {
                continue;
            }
            if let Ok(pt) = self.sessions[i].1.decrypt(&msg) {
                self.touch(i);
                return Ok((remote, Zeroizing::new(pt)));
            }
        }
        Err(CryptoError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::verify_prekey;

    fn pair() -> (OlmState, OlmState, InboxId) {
        (OlmState::new(), OlmState::new(), InboxId([3; 32]))
    }

    #[test]
    fn conversation_roundtrip_and_pickle() {
        let (mut a, mut b, inbox) = pair();
        let (otks, fb) = b.prekeys(&inbox, 5, true);
        assert_eq!(otks.len(), 5);
        assert!(fb.is_some());
        let entry = b.device_entry([9; 32], 0);
        verify_prekey(&inbox, &entry, &otks[0]).unwrap();

        a.start_session(&b.curve25519(), &otks[0].curve25519).unwrap();
        let m1 = a.encrypt(&b.curve25519(), b"hi bob").unwrap();
        let (from, pt) = b.decrypt(&m1).unwrap();
        assert_eq!(from, a.curve25519());
        assert_eq!(&pt[..], b"hi bob");

        // Persist and restore both sides mid-conversation.
        let mut a = OlmState::from_bytes(&a.to_bytes()).unwrap();
        let mut b = OlmState::from_bytes(&b.to_bytes()).unwrap();

        let r = b.encrypt(&a.curve25519(), b"hey alice").unwrap();
        assert_eq!(&a.decrypt(&r).unwrap().1[..], b"hey alice");

        // Out-of-order delivery.
        let x = a.encrypt(&b.curve25519(), b"one").unwrap();
        let y = a.encrypt(&b.curve25519(), b"two").unwrap();
        assert_eq!(&b.decrypt(&y).unwrap().1[..], b"two");
        assert_eq!(&b.decrypt(&x).unwrap().1[..], b"one");

        // Replays are rejected.
        assert!(b.decrypt(&x).is_err());
    }

    #[test]
    fn simultaneous_sessions_converge() {
        let (mut a, mut b, inbox) = pair();
        let (a_otk, _) = a.prekeys(&inbox, 1, true);
        let (b_otk, _) = b.prekeys(&inbox, 1, true);
        a.start_session(&b.curve25519(), &b_otk[0].curve25519).unwrap();
        b.start_session(&a.curve25519(), &a_otk[0].curve25519).unwrap();
        let ma = a.encrypt(&b.curve25519(), b"from a").unwrap();
        let mb = b.encrypt(&a.curve25519(), b"from b").unwrap();
        assert_eq!(&b.decrypt(&ma).unwrap().1[..], b"from a");
        assert_eq!(&a.decrypt(&mb).unwrap().1[..], b"from b");
        // After both prekey messages, replies work in both directions.
        for _ in 0..3 {
            let m = a.encrypt(&b.curve25519(), b"ping").unwrap();
            assert_eq!(&b.decrypt(&m).unwrap().1[..], b"ping");
            let m = b.encrypt(&a.curve25519(), b"pong").unwrap();
            assert_eq!(&a.decrypt(&m).unwrap().1[..], b"pong");
        }
    }

    #[test]
    fn stranger_cannot_decrypt() {
        let (mut a, mut b, inbox) = pair();
        let mut eve = OlmState::new();
        let (otks, _) = b.prekeys(&inbox, 1, true);
        a.start_session(&b.curve25519(), &otks[0].curve25519).unwrap();
        let m = a.encrypt(&b.curve25519(), b"secret").unwrap();
        assert!(eve.decrypt(&m).is_err());
        assert!(b.decrypt(&m).is_ok());
    }
}
