//! The EFF short wordlist (1296 words, ~10.3 bits each), used for invite
//! codes and safety words. Words are short, distinct and easy to say aloud.

use std::sync::OnceLock;

const RAW: &str = include_str!("../data/words.txt");

pub fn list() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| RAW.lines().map(str::trim).filter(|w| !w.is_empty()).collect())
}

pub fn word(index: usize) -> &'static str {
    let l = list();
    l[index % l.len()]
}

pub fn contains(w: &str) -> bool {
    list().binary_search(&w).is_ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn sorted_and_complete() {
        let l = super::list();
        assert_eq!(l.len(), 1296);
        assert!(l.windows(2).all(|w| w[0] < w[1]));
        assert!(super::contains("acorn"));
    }
}
