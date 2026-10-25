//! Safety words: six words both people can compare (in person or on the
//! phone) to confirm nobody sits in the middle of their relationship.

use sha2::{Digest, Sha256};
use yo_proto::words;

pub const SAFETY_WORDS: usize = 6;

/// Words derived from both relationship identity keys. Symmetric: both
/// sides compute the same words regardless of argument order.
pub fn safety_words(mine: &[u8; 32], theirs: &[u8; 32]) -> Vec<&'static str> {
    let (lo, hi) = if mine <= theirs { (mine, theirs) } else { (theirs, mine) };
    let mut h = Sha256::new();
    h.update(b"yo/safety-words/v1");
    h.update(lo);
    h.update(hi);
    let digest = h.finalize();
    digest
        .chunks(4)
        .take(SAFETY_WORDS)
        .map(|c| words::word(u32::from_le_bytes(c.try_into().expect("4 bytes")) as usize))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_and_distinct() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(safety_words(&a, &b), safety_words(&b, &a));
        assert_eq!(safety_words(&a, &b).len(), 6);
        assert_ne!(safety_words(&a, &b), safety_words(&a, &[3u8; 32]));
    }
}
