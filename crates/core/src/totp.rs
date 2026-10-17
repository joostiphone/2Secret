//! Time-based one-time passwords (RFC 6238 / RFC 4226), including Steam Guard.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

/// A parsed TOTP configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct Totp {
    secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub steam: bool,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl Drop for Totp {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

fn decode_base32(s: &str) -> Result<Vec<u8>> {
    let cleaned: String =
        s.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '=').flat_map(|c| c.to_uppercase()).collect();
    if cleaned.is_empty() {
        return Err(Error::invalid("empty TOTP secret"));
    }
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    spec.check_trailing_bits = false;
    let enc = spec.encoding().expect("valid base32 specification");
    enc.decode(cleaned.as_bytes()).map_err(|_| Error::invalid("the TOTP secret is not valid base32"))
}

fn encode_base32(bytes: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(bytes)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Totp {
    /// Parse an `otpauth://totp/...` URI, a `steam://SECRET` URI or a bare
    /// base32 secret.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let mut totp = Totp {
            secret: Vec::new(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            steam: false,
            issuer: None,
            account: None,
        };
        let lower = input.to_lowercase();
        if lower.starts_with("steam://") {
            totp.secret = decode_base32(&input["steam://".len()..])?;
            totp.steam = true;
            totp.digits = 5;
            return Ok(totp);
        }
        if lower.starts_with("otpauth://") {
            let after = &input["otpauth://".len()..];
            let (kind, rest) = after.split_once('/').ok_or_else(|| Error::invalid("malformed otpauth URI"))?;
            if !kind.eq_ignore_ascii_case("totp") {
                return Err(Error::Unsupported(format!("OTP type '{kind}' (only TOTP is supported)")));
            }
            let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
            let label = percent_decode(label);
            if let Some((issuer, account)) = label.split_once(':') {
                totp.issuer = Some(issuer.trim().to_string()).filter(|s| !s.is_empty());
                totp.account = Some(account.trim().to_string()).filter(|s| !s.is_empty());
            } else if !label.is_empty() {
                totp.account = Some(label);
            }
            let mut secret = None;
            for pair in query.split('&') {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                let v = percent_decode(v);
                match k.to_lowercase().as_str() {
                    "secret" => secret = Some(v),
                    "algorithm" => {
                        totp.algorithm = match v.to_uppercase().as_str() {
                            "SHA1" => Algorithm::Sha1,
                            "SHA256" => Algorithm::Sha256,
                            "SHA512" => Algorithm::Sha512,
                            other => return Err(Error::Unsupported(format!("TOTP algorithm {other}"))),
                        }
                    }
                    "digits" => {
                        totp.digits = v.parse().map_err(|_| Error::invalid("invalid TOTP digits"))?;
                    }
                    "period" => {
                        totp.period = v.parse().map_err(|_| Error::invalid("invalid TOTP period"))?;
                    }
                    "issuer" if !v.is_empty() => totp.issuer = Some(v),
                    "encoder" if v.eq_ignore_ascii_case("steam") => {
                        totp.steam = true;
                        totp.digits = 5;
                    }
                    _ => {}
                }
            }
            totp.secret = decode_base32(&secret.ok_or_else(|| Error::invalid("the otpauth URI has no secret"))?)?;
        } else {
            totp.secret = decode_base32(input)?;
        }
        if !(6..=10).contains(&totp.digits) && !totp.steam {
            return Err(Error::invalid("TOTP codes must have 6 to 10 digits"));
        }
        if totp.period == 0 || totp.period > 3600 {
            return Err(Error::invalid("invalid TOTP period"));
        }
        Ok(totp)
    }

    /// The shared secret.
    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }

    fn hmac(&self, counter: u64) -> Vec<u8> {
        let msg = counter.to_be_bytes();
        macro_rules! run {
            ($t:ty) => {{
                let mut mac = Hmac::<$t>::new_from_slice(&self.secret).expect("HMAC accepts any key length");
                mac.update(&msg);
                mac.finalize().into_bytes().to_vec()
            }};
        }
        match self.algorithm {
            Algorithm::Sha1 => run!(sha1::Sha1),
            Algorithm::Sha256 => run!(sha2::Sha256),
            Algorithm::Sha512 => run!(sha2::Sha512),
        }
    }

    /// The code valid at UNIX time `ts`.
    pub fn code_at(&self, ts: i64) -> String {
        let counter = (ts.max(0) as u64) / self.period;
        let hash = self.hmac(counter);
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        let bin = ((hash[offset] as u32 & 0x7f) << 24)
            | ((hash[offset + 1] as u32) << 16)
            | ((hash[offset + 2] as u32) << 8)
            | (hash[offset + 3] as u32);
        if self.steam {
            let mut v = bin;
            let mut out = String::new();
            for _ in 0..5 {
                out.push(STEAM_ALPHABET[(v as usize) % STEAM_ALPHABET.len()] as char);
                v /= STEAM_ALPHABET.len() as u32;
            }
            return out;
        }
        let modulo = 10u64.pow(self.digits);
        format!("{:0width$}", bin as u64 % modulo, width = self.digits as usize)
    }

    /// Current code and the number of seconds it stays valid.
    pub fn now(&self) -> (String, u64) {
        let ts = crate::util::now();
        (self.code_at(ts), self.seconds_remaining(ts))
    }

    pub fn seconds_remaining(&self, ts: i64) -> u64 {
        self.period - (ts.max(0) as u64 % self.period)
    }

    /// Canonical `otpauth://` URI.
    pub fn to_uri(&self) -> String {
        let label = match (&self.issuer, &self.account) {
            (Some(i), Some(a)) => format!("{}:{}", percent_encode(i), percent_encode(a)),
            (None, Some(a)) => percent_encode(a),
            (Some(i), None) => percent_encode(i),
            (None, None) => "2Secret".into(),
        };
        let mut uri = format!(
            "otpauth://totp/{label}?secret={}&algorithm={}&digits={}&period={}",
            encode_base32(&self.secret),
            self.algorithm.name(),
            self.digits,
            self.period
        );
        if let Some(i) = &self.issuer {
            uri.push_str(&format!("&issuer={}", percent_encode(i)));
        }
        if self.steam {
            uri.push_str("&encoder=steam");
        }
        uri
    }

    /// Format a code for display: `123 456`.
    pub fn format_code(code: &str) -> String {
        if code.len() == 6 || code.len() == 8 {
            let (a, b) = code.split_at(code.len() / 2);
            format!("{a} {b}")
        } else {
            code.to_string()
        }
    }
}

/// Is this value something [`Totp::parse`] accepts?
pub fn is_valid(input: &str) -> bool {
    Totp::parse(input).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B test vectors.
    #[test]
    fn rfc6238_vectors() {
        let sha1 = encode_base32(b"12345678901234567890");
        let sha256 = encode_base32(b"12345678901234567890123456789012");
        let sha512 = encode_base32(b"1234567890123456789012345678901234567890123456789012345678901234");
        let cases: [(i64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (ts, e1, e256, e512) in cases {
            let t1 = Totp::parse(&format!("otpauth://totp/x?secret={sha1}&digits=8")).unwrap();
            let t256 = Totp::parse(&format!("otpauth://totp/x?secret={sha256}&digits=8&algorithm=SHA256")).unwrap();
            let t512 = Totp::parse(&format!("otpauth://totp/x?secret={sha512}&digits=8&algorithm=SHA512")).unwrap();
            assert_eq!(t1.code_at(ts), e1);
            assert_eq!(t256.code_at(ts), e256);
            assert_eq!(t512.code_at(ts), e512);
        }
    }

    #[test]
    fn parse_variants() {
        let t = Totp::parse("JBSW Y3DP EHPK 3PXP").unwrap();
        assert_eq!(t.digits, 6);
        assert_eq!(t.code_at(0).len(), 6);
        let uri = "otpauth://totp/ACME%20Co:john@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&period=60";
        let t = Totp::parse(uri).unwrap();
        assert_eq!(t.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(t.account.as_deref(), Some("john@example.com"));
        assert_eq!(t.period, 60);
        let again = Totp::parse(&t.to_uri()).unwrap();
        assert_eq!(again, t);
        assert!(Totp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(Totp::parse("not base32 !!").is_err());
        assert!(Totp::parse("otpauth://totp/x").is_err());
    }

    #[test]
    fn steam() {
        let t = Totp::parse("steam://JBSWY3DPEHPK3PXP").unwrap();
        let code = t.code_at(1_700_000_000);
        assert_eq!(code.len(), 5);
        assert!(code.bytes().all(|b| STEAM_ALPHABET.contains(&b)));
    }

    #[test]
    fn remaining() {
        let t = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(t.seconds_remaining(60), 30);
        assert_eq!(t.seconds_remaining(61), 29);
        assert_eq!(Totp::format_code("123456"), "123 456");
    }
}
