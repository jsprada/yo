//! Invite codes and the SPAKE2 password-authenticated key exchange.
//!
//! A code looks like `7-crossbow-marble-tundra`: a short mailbox number
//! ("nameplate") plus three words from the EFF short list (~31 bits). Both
//! people run SPAKE2 with the code as the password through a relay mailbox on
//! the server. Someone who does not know the code (including the server) gets
//! exactly one guess before the mailbox is destroyed, and SPAKE2 reveals
//! nothing about the code to an observer.

use spake2::{Ed25519Group, Identity, Password, Spake2};
use yo_proto::msg::Side;
use yo_proto::words;

use crate::kdf::{hkdf, hmac, hmac_verify};
use crate::{CryptoError, Key32, aead};

/// What an invite code is for. Codes for one purpose never work for the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// `yo add` — exchange relationship keys with a contact.
    AddContact,
    /// `yo link` — move account secrets to a new device of mine.
    LinkDevice,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Purpose::AddContact => b"yo/add/v1",
            Purpose::LinkDevice => b"yo/link/v1",
        }
    }
}

pub const CODE_WORDS: usize = 3;

/// Build a code string for a nameplate with fresh random words.
pub fn new_code(nameplate: u32) -> String {
    let mut parts = vec![nameplate.to_string()];
    for _ in 0..CODE_WORDS {
        // Rejection sampling for an unbiased index into 1296 words.
        let idx = loop {
            let r = u16::from_le_bytes(crate::random::<2>()) as usize;
            if r < 1296 * 50 {
                break r % 1296;
            }
        };
        parts.push(words::word(idx).to_string());
    }
    parts.join("-")
}

/// Parse and normalize a code typed by a human: case, spaces and extra
/// dashes are forgiven. Returns `(nameplate, normalized_code)`.
pub fn parse_code(input: &str) -> Result<(u32, String), CryptoError> {
    let lower = input.trim().to_ascii_lowercase();
    let parts: Vec<&str> = lower
        .split(|c: char| c == '-' || c.is_whitespace())
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() != 1 + CODE_WORDS {
        return Err(CryptoError::BadCode);
    }
    let nameplate: u32 = parts[0].parse().map_err(|_| CryptoError::BadCode)?;
    if !parts[1..].iter().all(|w| words::contains(w)) {
        return Err(CryptoError::BadCode);
    }
    Ok((nameplate, parts.join("-")))
}

pub struct Pake {
    state: Spake2<Ed25519Group>,
    purpose: Purpose,
}

/// Begin the exchange. Send the returned bytes to the other side.
pub fn start(code: &str, purpose: Purpose) -> (Pake, Vec<u8>) {
    let (state, msg) = Spake2::<Ed25519Group>::start_symmetric(&Password::new(code.as_bytes()), &Identity::new(purpose.label()));
    (Pake { state, purpose }, msg)
}

impl Pake {
    pub fn finish(self, peer_msg: &[u8]) -> Result<PakeKeys, CryptoError> {
        let shared = self.state.finish(peer_msg).map_err(|_| CryptoError::CodeMismatch)?;
        let k = |info: &[u8]| hkdf(&shared, self.purpose.label(), info);
        Ok(PakeKeys {
            confirm_opener: k(b"confirm/opener"),
            confirm_joiner: k(b"confirm/joiner"),
            seal_opener: k(b"seal/opener"),
            seal_joiner: k(b"seal/joiner"),
        })
    }
}

pub struct PakeKeys {
    confirm_opener: Key32,
    confirm_joiner: Key32,
    seal_opener: Key32,
    seal_joiner: Key32,
}

impl PakeKeys {
    fn keys(&self, side: Side) -> (&Key32, &Key32) {
        match side {
            Side::Opener => (&self.confirm_opener, &self.seal_opener),
            Side::Joiner => (&self.confirm_joiner, &self.seal_joiner),
        }
    }

    /// Key-confirmation tag proving `side` derived the same key.
    pub fn confirm(&self, side: Side) -> [u8; 32] {
        hmac(self.keys(side).0.as_ref(), b"yo key confirmation")
    }

    pub fn check_confirm(&self, side: Side, tag: &[u8]) -> Result<(), CryptoError> {
        if hmac_verify(self.keys(side).0.as_ref(), b"yo key confirmation", tag) {
            Ok(())
        } else {
            Err(CryptoError::CodeMismatch)
        }
    }

    pub fn seal(&self, side: Side, plaintext: &[u8]) -> Vec<u8> {
        aead::seal(self.keys(side).1, b"yo/invite-payload", plaintext)
    }

    pub fn open(&self, side: Side, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        aead::open(self.keys(side).1, b"yo/invite-payload", sealed).map_err(|_| CryptoError::CodeMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        let c = new_code(42);
        let (n, norm) = parse_code(&c.to_uppercase().replace('-', " ")).unwrap();
        assert_eq!(n, 42);
        assert_eq!(norm, c);
        assert!(parse_code("42-notaword-acorn-acid").is_err());
        assert!(parse_code("42-acorn").is_err());
        assert!(parse_code("x-acorn-acid-acre").is_err());
    }

    fn exchange(code_a: &str, code_b: &str, pa: Purpose, pb: Purpose) -> Result<(), CryptoError> {
        let (a, ma) = start(code_a, pa);
        let (b, mb) = start(code_b, pb);
        let ka = a.finish(&mb)?;
        let kb = b.finish(&ma)?;
        // Joiner confirms first, opener checks, then the reverse.
        ka.check_confirm(Side::Joiner, &kb.confirm(Side::Joiner))?;
        kb.check_confirm(Side::Opener, &ka.confirm(Side::Opener))?;
        let sealed = kb.seal(Side::Joiner, b"payload");
        assert_eq!(ka.open(Side::Joiner, &sealed)?, b"payload");
        Ok(())
    }

    #[test]
    fn pake_right_and_wrong_code() {
        let code = new_code(1);
        exchange(&code, &code, Purpose::AddContact, Purpose::AddContact).unwrap();
        let other = new_code(1);
        assert!(exchange(&code, &other, Purpose::AddContact, Purpose::AddContact).is_err());
        assert!(exchange(&code, &code, Purpose::AddContact, Purpose::LinkDevice).is_err());
    }
}
