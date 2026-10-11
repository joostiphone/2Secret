//! Password, passphrase and PIN generator.
//!
//! All randomness comes from the operating system CSPRNG (`OsRng`, which maps
//! to `crypto.getRandomValues` in browsers). Characters and words are chosen
//! uniformly (`gen_range` uses rejection sampling, so there is no modulo bias).

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::wordlist;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/~";
const AMBIGUOUS: &str = "Il1O0o|`'\"";

pub const MIN_LENGTH: usize = 4;
pub const MAX_LENGTH: usize = 128;
pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 20;

/// Which kind of secret to generate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratorKind {
    /// Random characters.
    #[default]
    Random,
    /// Random words from the EFF wordlist.
    Memorable,
    /// Digits only.
    Pin,
}

/// Generator settings (also persisted as a user preference).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneratorOptions {
    pub kind: GeneratorKind,
    /// Characters (random), words (memorable) or digits (PIN).
    pub length: usize,
    pub words: usize,
    pub pin_length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            kind: GeneratorKind::Random,
            length: 20,
            words: 5,
            pin_length: 6,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        }
    }
}

impl GeneratorOptions {
    pub fn random(length: usize) -> Self {
        Self {
            kind: GeneratorKind::Random,
            length,
            ..Default::default()
        }
    }

    pub fn memorable(words: usize) -> Self {
        Self {
            kind: GeneratorKind::Memorable,
            words,
            ..Default::default()
        }
    }

    pub fn pin(length: usize) -> Self {
        Self {
            kind: GeneratorKind::Pin,
            pin_length: length,
            ..Default::default()
        }
    }

    fn character_sets(&self) -> Vec<Vec<char>> {
        let filter = |set: &str| -> Vec<char> {
            set.chars()
                .filter(|c| !self.avoid_ambiguous || !AMBIGUOUS.contains(*c))
                .collect()
        };
        let mut sets = Vec::new();
        if self.lowercase {
            sets.push(filter(LOWER));
        }
        if self.uppercase {
            sets.push(filter(UPPER));
        }
        if self.digits {
            sets.push(filter(DIGITS));
        }
        if self.symbols {
            sets.push(filter(SYMBOLS));
        }
        if sets.is_empty() {
            sets.push(filter(LOWER));
        }
        sets
    }

    /// Theoretical entropy of a generated secret in bits.
    pub fn entropy_bits(&self) -> f64 {
        match self.kind {
            GeneratorKind::Random => {
                let pool: usize = self.character_sets().iter().map(|s| s.len()).sum();
                self.length.clamp(MIN_LENGTH, MAX_LENGTH) as f64 * (pool as f64).log2()
            }
            GeneratorKind::Memorable => {
                let words = self.words.clamp(MIN_WORDS, MAX_WORDS) as f64;
                let mut bits = words * (wordlist::words().len() as f64).log2();
                if self.include_number {
                    bits += (10f64).log2() + words.log2();
                }
                bits
            }
            GeneratorKind::Pin => self.pin_length.clamp(MIN_LENGTH, 32) as f64 * 10f64.log2(),
        }
    }

    /// Generate a secret with these options.
    pub fn generate(&self) -> String {
        match self.kind {
            GeneratorKind::Random => generate_password(self),
            GeneratorKind::Memorable => generate_passphrase(self),
            GeneratorKind::Pin => generate_pin(self.pin_length),
        }
    }
}

/// Random character password that contains at least one character from each
/// selected class.
pub fn generate_password(opts: &GeneratorOptions) -> String {
    let length = opts.length.clamp(MIN_LENGTH, MAX_LENGTH);
    let sets = opts.character_sets();
    let pool: Vec<char> = sets.iter().flatten().copied().collect();
    let mut rng = OsRng;
    loop {
        let candidate: Vec<char> = (0..length).map(|_| pool[rng.gen_range(0..pool.len())]).collect();
        // Rejection sampling keeps the distribution uniform over all valid
        // passwords instead of forcing characters into fixed positions.
        if length < sets.len() || sets.iter().all(|set| candidate.iter().any(|c| set.contains(c))) {
            return candidate.into_iter().collect();
        }
    }
}

/// Memorable passphrase like `correct-horse-battery-staple`.
pub fn generate_passphrase(opts: &GeneratorOptions) -> String {
    let count = opts.words.clamp(MIN_WORDS, MAX_WORDS);
    let list = wordlist::words();
    let mut rng = OsRng;
    let mut words: Vec<String> = (0..count)
        .map(|_| {
            let w = list[rng.gen_range(0..list.len())];
            if opts.capitalize {
                let mut c = w.chars();
                match c.next() {
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    None => String::new(),
                }
            } else {
                w.to_string()
            }
        })
        .collect();
    if opts.include_number {
        let i = rng.gen_range(0..words.len());
        let digit = rng.gen_range(0..10);
        words[i].push_str(&digit.to_string());
    }
    words.join(&opts.separator)
}

/// Numeric PIN.
pub fn generate_pin(length: usize) -> String {
    let length = length.clamp(MIN_LENGTH, 32);
    let mut rng = OsRng;
    (0..length)
        .map(|_| char::from(b'0' + rng.gen_range(0..10u8)))
        .collect()
}

/// Shuffle helper used by tests and import tooling.
pub fn shuffle<T>(v: &mut [T]) {
    v.shuffle(&mut OsRng);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_password_respects_options() {
        for _ in 0..200 {
            let pw = generate_password(&GeneratorOptions::random(12));
            assert_eq!(pw.chars().count(), 12);
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()));
            assert!(pw.chars().any(|c| SYMBOLS.contains(c)));
        }
        let opts = GeneratorOptions {
            symbols: false,
            uppercase: false,
            avoid_ambiguous: true,
            length: 64,
            ..Default::default()
        };
        let pw = generate_password(&opts);
        assert!(pw.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert!(!pw.contains('l') && !pw.contains('1') && !pw.contains('0') && !pw.contains('o'));
    }

    #[test]
    fn passphrase() {
        let opts = GeneratorOptions {
            capitalize: true,
            include_number: true,
            separator: ".".into(),
            ..GeneratorOptions::memorable(4)
        };
        let p = opts.generate();
        assert_eq!(p.split('.').count(), 4);
        assert!(p.chars().any(|c| c.is_ascii_digit()));
        assert!(p.split('.').all(|w| w.chars().next().unwrap().is_uppercase()));
        assert!(opts.entropy_bits() > 51.0);
    }

    #[test]
    fn pin() {
        let p = generate_pin(6);
        assert_eq!(p.len(), 6);
        assert!(p.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(generate_pin(1).len(), MIN_LENGTH);
    }

    #[test]
    fn entropy() {
        let e = GeneratorOptions::random(20).entropy_bits();
        assert!(e > 120.0 && e < 135.0, "{e}");
        assert!((GeneratorOptions::memorable(5).entropy_bits() - 64.6).abs() < 0.5);
    }

    #[test]
    fn no_duplicates() {
        let a = generate_password(&GeneratorOptions::random(20));
        let b = generate_password(&GeneratorOptions::random(20));
        assert_ne!(a, b);
    }
}
