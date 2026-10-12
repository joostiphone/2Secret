//! Small helpers shared by the whole crate.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;

/// Current UNIX time in seconds. Works on native targets and in the browser.
pub fn now() -> i64 {
    web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Current UNIX time in milliseconds.
pub fn now_millis() -> i64 {
    web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// A new random (version 4) UUID, rendered lowercase with hyphens.
pub fn new_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes).into_uuid().to_string()
}

/// Fill a fixed-size array with cryptographically secure random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

pub fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn unb64(data: &str) -> crate::Result<Vec<u8>> {
    STANDARD.decode(data.trim()).map_err(|e| crate::Error::invalid(format!("invalid base64: {e}")))
}

pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn unb64url(data: &str) -> crate::Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(data.trim()).map_err(|e| crate::Error::invalid(format!("invalid base64: {e}")))
}

/// Lowercase hexadecimal encoding.
pub fn hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

/// Normalise an e-mail address for use in key derivation and lookups.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Format a UNIX timestamp as `YYYY-MM-DD HH:MM` (UTC).
pub fn format_timestamp(ts: i64) -> String {
    let (y, m, d, hh, mm, _) = civil_from_unix(ts);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}")
}

/// Format a UNIX timestamp as `YYYY-MM-DD` (UTC).
pub fn format_date(ts: i64) -> String {
    let (y, m, d, ..) = civil_from_unix(ts);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Convert a UNIX timestamp to (year, month, day, hour, minute, second) in UTC.
pub fn civil_from_unix(ts: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // Howard Hinnant's days_from_civil inverse.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, (secs / 3600) as u32, ((secs % 3600) / 60) as u32, (secs % 60) as u32)
}

/// Convert a civil date (UTC midnight) to a UNIX timestamp.
pub fn unix_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe - 719_468) * 86_400
}

/// Parse dates such as `2024-05-17`, `2024-05-17T10:00:00Z` or a UNIX timestamp.
pub fn parse_date(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(n) = s.parse::<i64>() {
        // Heuristic: values that large are milliseconds or microseconds.
        return Some(if n > 100_000_000_000_000 {
            n / 1_000_000
        } else if n > 100_000_000_000 {
            n / 1000
        } else {
            n
        });
    }
    let date = s.get(0..10)?;
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let mut ts = unix_from_civil(y, m, d);
    if let Some(time) = s.get(11..19) {
        let mut t = time.split(':');
        if let (Some(h), Some(mi), Some(se)) = (t.next(), t.next(), t.next()) {
            if let (Ok(h), Ok(mi), Ok(se)) = (h.parse::<i64>(), mi.parse::<i64>(), se.parse::<i64>()) {
                ts += h * 3600 + mi * 60 + se;
            }
        }
    }
    Some(ts)
}

/// Extract the registrable-ish host of a URL for display and matching.
/// `https://www.example.com/login` becomes `example.com`.
pub fn url_host(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let with_scheme = if raw.contains("://") { raw.to_string() } else { format!("https://{raw}") };
    let parsed = url::Url::parse(&with_scheme).ok()?;
    let host = parsed.host_str()?.to_lowercase();
    Some(host.strip_prefix("www.").unwrap_or(&host).to_string())
}

/// The registrable domain of a host according to the Public Suffix List:
/// `login.example.co.uk` becomes `example.co.uk`, while `alice.github.io`
/// stays `alice.github.io` (every GitHub Pages site belongs to someone else).
/// IP addresses and single-label hosts are returned unchanged.
pub fn base_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') {
        return host;
    }
    psl::domain_str(&host).unwrap_or(&host).to_string()
}

fn parse_web_url(raw: &str) -> Option<url::Url> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let with_scheme = if raw.contains("://") { raw.to_string() } else { format!("https://{raw}") };
    url::Url::parse(&with_scheme).ok().filter(|u| u.host_str().is_some())
}

/// Does a stored item URL match the page the user is on? The page must be on
/// the same registrable domain (Public Suffix List), use the same port if the
/// item names one, and must not downgrade an `https` item to plain `http`.
pub fn url_matches(item_url: &str, page_url: &str) -> bool {
    let (Some(item), Some(page)) = (parse_web_url(item_url), parse_web_url(page_url)) else {
        return false;
    };
    if !matches!(page.scheme(), "https" | "http") || (item.scheme() == "https" && page.scheme() != "https") {
        return false;
    }
    if item.port().is_some() && item.port_or_known_default() != page.port_or_known_default() {
        return false;
    }
    let (Some(a), Some(b)) = (item.host_str(), page.host_str()) else { return false };
    let (a, b) = (a.to_lowercase(), b.to_lowercase());
    a == b || base_domain(&a) == base_domain(&b)
}

/// Where an item's credentials may be filled: the browser extension checks
/// the page and every frame against these rules at the moment of filling.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FillRule {
    /// Registrable domain; the page host must equal it or be a subdomain.
    pub domain: String,
    /// The item's URL is `https`, so plain `http` pages are refused.
    pub https: bool,
    /// The item's URL names this port explicitly.
    pub port: Option<u16>,
}

/// Fill rules for an item's URLs (same semantics as [`url_matches`]).
pub fn fill_rules(item_urls: &[String]) -> Vec<FillRule> {
    let mut out: Vec<FillRule> = item_urls
        .iter()
        .filter_map(|u| parse_web_url(u))
        .filter(|u| matches!(u.scheme(), "https" | "http"))
        .filter_map(|u| {
            Some(FillRule {
                domain: base_domain(&u.host_str()?.to_lowercase()),
                https: u.scheme() == "https",
                port: u.port(),
            })
        })
        .collect();
    out.sort_by(|a, b| (&a.domain, a.https, a.port).cmp(&(&b.domain, b.https, b.port)));
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_roundtrip() {
        for ts in [0i64, 951_782_400, 1_700_000_000, 4_102_444_800] {
            let (y, m, d, hh, mm, ss) = civil_from_unix(ts);
            let back = unix_from_civil(y, m, d) + (hh * 3600 + mm * 60 + ss) as i64;
            assert_eq!(ts, back);
        }
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(format_timestamp(1_700_000_000), "2023-11-14 22:13");
    }

    #[test]
    fn url_matching() {
        assert!(url_matches("https://github.com/login", "https://github.com/session"));
        assert!(url_matches("github.com", "https://gist.github.com/x"));
        assert!(url_matches("https://login.example.co.uk", "https://www.example.co.uk"));
        // Different owners under a public suffix.
        assert!(!url_matches("https://alice.github.io", "https://mallory.github.io"));
        assert!(!url_matches("https://example.co.uk", "https://other.co.uk"));
        // No downgrade to http, no lookalikes, no other schemes.
        assert!(!url_matches("https://bank.example", "http://bank.example"));
        assert!(url_matches("http://router.local", "http://router.local/admin"));
        assert!(!url_matches("https://github.com", "https://github.com.evil.example"));
        assert!(!url_matches("https://github.com", "https://evil.example/?github.com"));
        assert!(!url_matches("https://github.com", "file:///github.com"));
        // Ports and IP addresses.
        assert!(!url_matches("https://192.168.1.1:8443", "https://192.168.1.1"));
        assert!(url_matches("https://192.168.1.1:8443", "https://192.168.1.1:8443/x"));
        assert!(!url_matches("https://10.0.0.1", "https://10.0.0.2"));
        assert_eq!(
            fill_rules(&["https://www.github.com/login".into(), "gist.github.com".into(), "ftp://x.org".into()]),
            vec![FillRule { domain: "github.com".into(), https: true, port: None }]
        );
        assert_eq!(fill_rules(&["http://10.0.0.1:8080".into()])[0].port, Some(8080));
    }

    #[test]
    fn parse_dates() {
        assert_eq!(parse_date("1970-01-02"), Some(86_400));
        assert_eq!(parse_date("2023-11-14T22:13:20Z"), Some(1_700_000_000));
        assert_eq!(parse_date("1700000000000"), Some(1_700_000_000));
        assert_eq!(parse_date("garbage"), None);
    }

    #[test]
    fn hosts_and_matching() {
        assert_eq!(url_host("https://www.Example.com/login").as_deref(), Some("example.com"));
        assert_eq!(url_host("accounts.google.com").as_deref(), Some("accounts.google.com"));
        assert_eq!(base_domain("accounts.google.com"), "google.com");
        assert_eq!(base_domain("www.bbc.co.uk"), "bbc.co.uk");
        assert!(url_matches("https://github.com", "https://gist.github.com/x"));
        assert!(!url_matches("https://github.com", "https://gitlab.com"));
    }

    #[test]
    fn ids_are_unique_uuids() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert!(uuid::Uuid::parse_str(&a).is_ok());
    }
}
