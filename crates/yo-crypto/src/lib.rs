//! Cryptography for yo!.
//!
//! * [`aead`]    — XChaCha20-Poly1305 sealing used for everything at rest.
//! * [`kdf`]     — Argon2id passphrase hashing, HKDF and HMAC lookup tags.
//! * [`rik`]     — per-contact Relationship Identity Keys (Ed25519).
//! * [`devices`] — signing / verifying device lists and one-time keys.
//! * [`olm`]     — end-to-end sessions (Olm Double Ratchet via `vodozemac`).
//! * [`invite`]  — invite codes and the SPAKE2 key exchange.
//! * [`safety`]  — safety words for out-of-band verification.

pub mod aead;
pub mod devices;
pub mod invite;
pub mod kdf;
pub mod olm;
pub mod rik;
pub mod safety;

pub use zeroize::Zeroizing;

/// A 256-bit secret key that is wiped from memory when dropped.
pub type Key32 = Zeroizing<[u8; 32]>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption failed (wrong key or tampered data)")]
    Decrypt,
    #[error("invalid signature")]
    BadSignature,
    #[error("invalid key")]
    BadKey,
    #[error("device list does not belong to the expected identity")]
    WrongIdentity,
    #[error("device list version went backwards (possible replay)")]
    Rollback,
    #[error("no session with that device")]
    NoSession,
    #[error("olm: {0}")]
    Olm(String),
    #[error("invite code is malformed")]
    BadCode,
    #[error("the other side used a different code")]
    CodeMismatch,
    #[error("kdf: {0}")]
    Kdf(String),
    #[error("serialization: {0}")]
    Serde(String),
}

/// Fill `N` bytes from the operating system CSPRNG.
pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS random number generator unavailable");
    out
}

/// A fresh random 256-bit key.
pub fn random_key() -> Key32 {
    Zeroizing::new(random::<32>())
}
