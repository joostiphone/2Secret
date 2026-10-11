//! The EFF large wordlist (7,776 words, ~12.9 bits of entropy per word).
//!
//! Source: Electronic Frontier Foundation, "EFF's New Wordlists for Random
//! Passphrases" (2016), licensed under CC BY 3.0 US.
//! <https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases>

use std::sync::OnceLock;

const RAW: &str = include_str!("eff_large_wordlist.txt");

/// All 7,776 words.
pub fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| RAW.lines().map(str::trim).filter(|w| !w.is_empty()).collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn wordlist_is_complete_and_unique() {
        let w = super::words();
        assert_eq!(w.len(), 7776);
        let mut sorted = w.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 7776);
    }
}
