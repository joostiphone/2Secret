//! Password strength estimation (zxcvbn) for the generator, the editor and
//! Watchtower.

use serde::{Deserialize, Serialize};

/// Strength classification, 0 (terrible) to 4 (fantastic).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrengthLevel {
    Terrible,
    Weak,
    Fair,
    Good,
    Fantastic,
}

impl StrengthLevel {
    pub fn from_score(score: u8) -> Self {
        match score {
            0 => StrengthLevel::Terrible,
            1 => StrengthLevel::Weak,
            2 => StrengthLevel::Fair,
            3 => StrengthLevel::Good,
            _ => StrengthLevel::Fantastic,
        }
    }

    pub fn score(&self) -> u8 {
        *self as u8
    }

    pub fn id(&self) -> &'static str {
        match self {
            StrengthLevel::Terrible => "terrible",
            StrengthLevel::Weak => "weak",
            StrengthLevel::Fair => "fair",
            StrengthLevel::Good => "good",
            StrengthLevel::Fantastic => "fantastic",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            StrengthLevel::Terrible => "Terrible",
            StrengthLevel::Weak => "Weak",
            StrengthLevel::Fair => "Fair",
            StrengthLevel::Good => "Good",
            StrengthLevel::Fantastic => "Fantastic",
        }
    }
}

/// Result of a strength estimate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Strength {
    pub level: StrengthLevel,
    /// log10 of the estimated number of guesses.
    pub guesses_log10: f64,
    /// Approximate entropy in bits (log2 of the guesses).
    pub bits: f64,
    /// Human readable time to crack offline with a slow hash (10k guesses/s).
    pub crack_time: String,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

/// Estimate the strength of a password. `user_inputs` (name, e-mail, site)
/// are penalised when they appear in the password.
pub fn estimate(password: &str, user_inputs: &[&str]) -> Strength {
    if password.is_empty() {
        return Strength {
            level: StrengthLevel::Terrible,
            guesses_log10: 0.0,
            bits: 0.0,
            crack_time: "instantly".into(),
            warning: None,
            suggestions: vec![],
        };
    }
    let entropy = zxcvbn::zxcvbn(password, user_inputs);
    let mut score: u8 = entropy.score().into();
    let guesses_log10 = entropy.guesses_log10().max(0.0);
    let bits = guesses_log10 * std::f64::consts::LOG2_10;
    // zxcvbn reports "4" from 10^10 guesses on; reserve "fantastic" for
    // secrets that are genuinely out of reach (>= 10^18 guesses, ~60 bits,
    // which with Argon2id-protected storage means millennia of cracking).
    if score == 4 && guesses_log10 < 18.0 {
        score = 3;
    }
    let (warning, suggestions) = match entropy.feedback() {
        Some(fb) => (
            fb.warning().map(|w| w.to_string()),
            fb.suggestions().iter().map(|s| s.to_string()).collect(),
        ),
        None => (None, vec![]),
    };
    Strength {
        level: StrengthLevel::from_score(score),
        guesses_log10,
        bits,
        crack_time: entropy
            .crack_times()
            .offline_slow_hashing_1e4_per_second()
            .to_string(),
        warning,
        suggestions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels() {
        assert_eq!(estimate("password", &[]).level, StrengthLevel::Terrible);
        assert!(estimate("password", &[]).warning.is_some());
        assert!(estimate("Tr0ub4dor&3", &[]).level <= StrengthLevel::Good);
        let strong = estimate("vY8#qL2!mZ9@wX4$kR7^", &[]);
        assert_eq!(strong.level, StrengthLevel::Fantastic);
        assert!(strong.bits > 60.0);
        let pass = estimate("cobweb-unsaddle-scuba-gravel-banister", &[]);
        assert!(pass.level >= StrengthLevel::Good, "{pass:?}");
        assert!(estimate("jan.jansen1985", &["jan.jansen"]).level <= StrengthLevel::Fair);
        assert_eq!(estimate("", &[]).level, StrengthLevel::Terrible);
    }
}
