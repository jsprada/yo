//! Wire protocol shared by the `yo` client and `yo-server`.
//!
//! Everything that crosses the network is defined here: identifiers, request
//! and response types, framing, padding, the invite-code wordlist and the TLS
//! (mTLS + pinning) configuration helpers.

pub mod frame;
pub mod ids;
pub mod msg;
pub mod pad;
pub mod tls;
pub mod words;

pub use ids::{DeviceId, InboxId};

/// Wire protocol version. Bumped on incompatible changes.
pub const PROTOCOL_VERSION: u16 = 1;

/// ALPN identifier negotiated during the TLS handshake.
pub const ALPN: &[u8] = b"yo/1";

/// Default TCP port for `yo-server`.
pub const DEFAULT_PORT: u16 = 7443;

/// Largest frame accepted on the wire (2 MiB).
pub const MAX_FRAME: usize = 2 * 1024 * 1024;

/// Current UNIX time in seconds.
pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Lowercase, unpadded base32 — used for every human-visible identifier.
pub fn b32(bytes: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(bytes).to_ascii_lowercase()
}

/// Decode [`b32`] output (case-insensitive).
pub fn from_b32(s: &str) -> Option<Vec<u8>> {
    data_encoding::BASE32_NOPAD.decode(s.trim().to_ascii_uppercase().as_bytes()).ok()
}
