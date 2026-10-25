//! Keep secrets out of what the model reads: the values an agent ran a
//! command with are replaced by their references in the command's output.

/// Longest output (per stream) returned to the model.
pub const MAX_OUTPUT: usize = 64 * 1024;

/// Values shorter than this are not replaced: they would hit ordinary text
/// everywhere (and a 3-character secret is no secret).
const MIN_LEN: usize = 4;

/// Replace every occurrence of a secret value, also percent-encoded as in a
/// URL, by `«reference»`. Longer values first, so a value that contains
/// another is replaced whole.
pub fn scrub(text: &str, secrets: &[(String, String)]) -> String {
    let mut pairs: Vec<(&str, &str)> =
        secrets.iter().filter(|(_, v)| v.chars().count() >= MIN_LEN).map(|(r, v)| (r.as_str(), v.as_str())).collect();
    pairs.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    let mut out = text.to_string();
    for (reference, value) in pairs {
        let marker = format!("\u{AB}{reference}\u{BB}");
        out = out.replace(value, &marker);
        let encoded = percent_encode(value);
        if encoded != value {
            out = out.replace(&encoded, &marker);
        }
    }
    out
}

/// Cut text to [`MAX_OUTPUT`] bytes (at a character boundary); says whether it did.
pub fn truncate(text: &str) -> (String, bool) {
    if text.len() <= MAX_OUTPUT {
        return (text.to_string(), false);
    }
    let mut end = MAX_OUTPUT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}\n… [truncated]", &text[..end]), true)
}

/// URL percent-encoding of everything but unreserved characters.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(r, v)| (r.to_string(), v.to_string())).collect()
    }

    #[test]
    fn replaces_values_and_encoded_values() {
        let s = secrets(&[("2s://Db/password", "p@ss w0rd!"), ("2s://Db/user", "appuser")]);
        let out = scrub("postgres://appuser:p@ss w0rd!@db postgres://appuser:p%40ss%20w0rd%21@db", &s);
        assert_eq!(
            out,
            "postgres://«2s://Db/user»:«2s://Db/password»@db postgres://«2s://Db/user»:«2s://Db/password»@db"
        );
        assert!(!out.contains("w0rd"));
    }

    #[test]
    fn longer_values_first_and_short_ones_skipped() {
        let s = secrets(&[("2s://A/x", "secret"), ("2s://B/y", "secret-longer"), ("2s://C/z", "ab")]);
        assert_eq!(scrub("secret-longer secret ab", &s), "«2s://B/y» «2s://A/x» ab");
    }

    #[test]
    fn truncates_at_a_boundary() {
        let (short, cut) = truncate("abc");
        assert!(!cut && short == "abc");
        let long = "é".repeat(MAX_OUTPUT);
        let (out, cut) = truncate(&long);
        assert!(cut);
        assert!(out.ends_with("[truncated]"));
        assert!(out.len() < MAX_OUTPUT + 32);
    }
}
