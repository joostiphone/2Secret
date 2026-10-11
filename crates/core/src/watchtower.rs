//! Watchtower: a security audit of all items.
//!
//! Detects weak, reused and old passwords, logins on unencrypted (`http://`)
//! sites, expiring or expired cards and documents, and – when the client opts
//! in – passwords found in public data breaches via the Have I Been Pwned
//! k-anonymity API (only the first five characters of the SHA-1 hash ever
//! leave the device).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::item::{FieldKind, Item};
use crate::strength::{estimate, StrengthLevel};
use crate::util::{civil_from_unix, now, parse_date, unix_from_civil};

/// Passwords unchanged for longer than this are reported as old.
pub const OLD_PASSWORD_DAYS: i64 = 3 * 365;
/// Expiry warnings start this many days in advance.
pub const EXPIRY_WARNING_DAYS: i64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueKind {
    /// Found in a known data breach (most severe).
    Breached,
    Weak,
    Reused,
    Expired,
    InsecureWebsite,
    ExpiringSoon,
    Old,
}

impl IssueKind {
    pub const ALL: [IssueKind; 7] = [
        IssueKind::Breached,
        IssueKind::Weak,
        IssueKind::Reused,
        IssueKind::Expired,
        IssueKind::InsecureWebsite,
        IssueKind::ExpiringSoon,
        IssueKind::Old,
    ];

    pub fn id(&self) -> &'static str {
        match self {
            IssueKind::Breached => "breached",
            IssueKind::Weak => "weak",
            IssueKind::Reused => "reused",
            IssueKind::Expired => "expired",
            IssueKind::InsecureWebsite => "insecure_website",
            IssueKind::ExpiringSoon => "expiring_soon",
            IssueKind::Old => "old",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            IssueKind::Breached => "Compromised passwords",
            IssueKind::Weak => "Weak passwords",
            IssueKind::Reused => "Reused passwords",
            IssueKind::Expired => "Expired items",
            IssueKind::InsecureWebsite => "Unsecured websites",
            IssueKind::ExpiringSoon => "Expiring soon",
            IssueKind::Old => "Old passwords",
        }
    }

    /// Penalty used for the overall score.
    fn weight(&self) -> f64 {
        match self {
            IssueKind::Breached => 1.0,
            IssueKind::Weak => 0.7,
            IssueKind::Reused => 0.6,
            IssueKind::Expired => 0.3,
            IssueKind::InsecureWebsite => 0.3,
            IssueKind::ExpiringSoon => 0.1,
            IssueKind::Old => 0.2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Issue {
    pub kind: IssueKind,
    pub item_id: String,
    pub vault_id: String,
    pub title: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub issues: Vec<Issue>,
    /// 0 – 1000, higher is better.
    pub score: u32,
    pub items_checked: usize,
    pub passwords_checked: usize,
    pub breach_check_done: bool,
}

impl Report {
    pub fn count(&self, kind: IssueKind) -> usize {
        self.issues.iter().filter(|i| i.kind == kind).count()
    }

    pub fn of_kind(&self, kind: IssueKind) -> Vec<&Issue> {
        self.issues.iter().filter(|i| i.kind == kind).collect()
    }

    pub fn for_item(&self, item_id: &str) -> Vec<&Issue> {
        self.issues.iter().filter(|i| i.item_id == item_id).collect()
    }

    /// Textual rating of the score.
    pub fn rating(&self) -> &'static str {
        match self.score {
            900.. => "fantastic",
            750..=899 => "very_good",
            600..=749 => "good",
            400..=599 => "fair",
            _ => "poor",
        }
    }
}

/// Parse an expiry value (`MM/YYYY`, `MM/YY`, `YYYY-MM-DD`, `YYYYMM`) to the
/// UNIX time at which it is expired.
pub fn parse_expiry(value: &str) -> Option<i64> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    let end_of_month = |y: i64, m: u32| -> Option<i64> {
        if !(1..=12).contains(&m) {
            return None;
        }
        let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
        Some(unix_from_civil(ny, nm, 1))
    };
    if let Some((m, y)) = v.split_once('/') {
        let m: u32 = m.trim().parse().ok()?;
        let mut y: i64 = y.trim().parse().ok()?;
        if y < 100 {
            y += 2000;
        }
        return end_of_month(y, m);
    }
    if v.len() == 6 && v.chars().all(|c| c.is_ascii_digit()) {
        let y: i64 = v[..4].parse().ok()?;
        let m: u32 = v[4..].parse().ok()?;
        return end_of_month(y, m);
    }
    parse_date(v).map(|ts| ts + 86_400)
}

/// When does this item expire, if ever?
pub fn item_expiry(item: &Item) -> Option<i64> {
    const KEYS: [&str; 4] = ["expiry", "expiry_date", "expires", "valid_until"];
    item.fields
        .iter()
        .filter(|f| KEYS.contains(&f.id.as_str()) || (f.kind == FieldKind::MonthYear && f.label.to_lowercase().contains("expir")))
        .find_map(|f| parse_expiry(&f.value))
}

/// Run all offline checks. `breached` maps item ids to breach counts from a
/// previous [`hibp_range_count`] run (pass an empty map to skip).
pub fn analyze<'a>(
    items: impl IntoIterator<Item = (&'a str, &'a Item)>,
    breached: &HashMap<String, u64>,
    at: Option<i64>,
) -> Report {
    let at = at.unwrap_or_else(now);
    let items: Vec<(&str, &Item)> = items.into_iter().filter(|(_, i)| !i.is_trashed()).collect();
    let mut report = Report {
        items_checked: items.len(),
        breach_check_done: !breached.is_empty(),
        ..Default::default()
    };

    let mut by_password: HashMap<&str, Vec<(&str, &Item)>> = HashMap::new();
    let mut penalty = 0.0;
    let mut weighted_items = 0.0;

    for (vault_id, item) in &items {
        let mut found: Vec<(IssueKind, String)> = Vec::new();
        let mut push = |kind: IssueKind, detail: String| found.push((kind, detail));
        let mut item_penalty: f64 = 0.0;

        if let Some(pw) = item.password() {
            report.passwords_checked += 1;
            by_password.entry(pw).or_default().push((vault_id, item));
            let mut inputs: Vec<&str> = vec![item.title.as_str()];
            if let Some(u) = item.username() {
                inputs.push(u);
            }
            let s = estimate(pw, &inputs);
            if s.level <= StrengthLevel::Weak {
                push(IssueKind::Weak, format!("{} – crackable in {}", s.level.label(), s.crack_time));
                item_penalty = item_penalty.max(IssueKind::Weak.weight());
            }
            if let Some(count) = breached.get(&item.id) {
                push(IssueKind::Breached, format!("seen {count} times in data breaches"));
                item_penalty = item_penalty.max(IssueKind::Breached.weight());
            }
            let changed = item.password_changed_at.unwrap_or(item.created_at);
            if changed > 0 && at - changed > OLD_PASSWORD_DAYS * 86_400 {
                let years = (at - changed) / (365 * 86_400);
                push(IssueKind::Old, format!("unchanged for more than {years} years"));
                item_penalty = item_penalty.max(IssueKind::Old.weight());
            }
        }

        if item.password().is_some() {
            if let Some(url) = item.urls.iter().find(|u| u.trim().to_lowercase().starts_with("http://")) {
                let host = crate::util::url_host(url).unwrap_or_default();
                if host != "localhost" && !host.starts_with("127.") && !host.starts_with("192.168.") && !host.starts_with("10.") {
                    push(IssueKind::InsecureWebsite, url.clone());
                    item_penalty = item_penalty.max(IssueKind::InsecureWebsite.weight());
                }
            }
        }

        if let Some(expiry) = item_expiry(item) {
            let (y, m, d, ..) = civil_from_unix(expiry - 86_400);
            if expiry <= at {
                push(IssueKind::Expired, format!("expired on {y:04}-{m:02}-{d:02}"));
                item_penalty = item_penalty.max(IssueKind::Expired.weight());
            } else if expiry - at < EXPIRY_WARNING_DAYS * 86_400 {
                push(IssueKind::ExpiringSoon, format!("expires on {y:04}-{m:02}-{d:02}"));
                item_penalty = item_penalty.max(IssueKind::ExpiringSoon.weight());
            }
        }

        for (kind, detail) in found {
            report.issues.push(Issue {
                kind,
                item_id: item.id.clone(),
                vault_id: vault_id.to_string(),
                title: item.title.clone(),
                detail,
            });
        }
        penalty += item_penalty;
        weighted_items += 1.0;
    }

    for group in by_password.values().filter(|g| g.len() > 1) {
        for (vault_id, item) in group {
            let others: Vec<&str> = group
                .iter()
                .filter(|(_, o)| o.id != item.id)
                .map(|(_, o)| o.title.as_str())
                .collect();
            report.issues.push(Issue {
                kind: IssueKind::Reused,
                item_id: item.id.clone(),
                vault_id: vault_id.to_string(),
                title: item.title.clone(),
                detail: format!("also used by {}", others.join(", ")),
            });
            penalty += IssueKind::Reused.weight() * 0.5;
        }
    }

    report.issues.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.title.to_lowercase().cmp(&b.title.to_lowercase())));
    report.score = if weighted_items == 0.0 {
        1000
    } else {
        let ratio = (penalty / weighted_items).min(1.0);
        ((1.0 - ratio) * 1000.0).round() as u32
    };
    report
}

/// SHA-1 of a password split into the 5 character prefix sent to the Have I
/// Been Pwned range API and the suffix that stays on the device.
pub fn hibp_hash(password: &str) -> (String, String) {
    let digest = Sha1::digest(password.as_bytes());
    let hex = crate::util::hex(&digest).to_uppercase();
    (hex[..5].to_string(), hex[5..].to_string())
}

/// URL of the Have I Been Pwned range API for a prefix.
pub fn hibp_url(prefix: &str) -> String {
    format!("https://api.pwnedpasswords.com/range/{prefix}")
}

/// Find the breach count of `suffix` in a range API response body.
pub fn hibp_range_count(body: &str, suffix: &str) -> u64 {
    body.lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find(|(s, _)| s.eq_ignore_ascii_case(suffix))
        .and_then(|(_, c)| c.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Category, Item};

    #[test]
    fn detects_issues() {
        let t = 1_700_000_000;
        let mut weak = Item::login("Weak", "a", "password1", Some("https://a.com"));
        weak.password_changed_at = Some(t);
        let mut r1 = Item::login("Reuse 1", "b", "Xk9#mP2$vL8@qR5!", Some("http://b.com"));
        r1.password_changed_at = Some(t);
        let mut r2 = Item::login("Reuse 2", "c", "Xk9#mP2$vL8@qR5!", Some("https://c.com"));
        r2.password_changed_at = Some(t - 4 * 365 * 86_400);
        let mut card = Item::new(Category::CreditCard, "Card");
        card.set_value("expiry", "01/2020");
        let mut card2 = Item::new(Category::CreditCard, "Card 2");
        card2.set_value("expiry", "12/2023");
        let items = [("v", &weak), ("v", &r1), ("v", &r2), ("v", &card), ("v", &card2)];
        let mut breached = HashMap::new();
        breached.insert(weak.id.clone(), 42);
        let report = analyze(items, &breached, Some(t));
        assert_eq!(report.count(IssueKind::Weak), 1);
        assert_eq!(report.count(IssueKind::Reused), 2);
        assert_eq!(report.count(IssueKind::InsecureWebsite), 1);
        assert_eq!(report.count(IssueKind::Old), 1);
        assert_eq!(report.count(IssueKind::Expired), 1);
        assert_eq!(report.count(IssueKind::ExpiringSoon), 1);
        assert_eq!(report.count(IssueKind::Breached), 1);
        assert_eq!(report.issues[0].kind, IssueKind::Breached);
        assert!(report.score < 1000);
        let clean = analyze([("v", &card2)], &HashMap::new(), Some(0));
        assert_eq!(clean.score, 1000);
    }

    #[test]
    fn expiry_parsing() {
        assert_eq!(parse_expiry("12/2024"), Some(unix_from_civil(2025, 1, 1)));
        assert_eq!(parse_expiry("02/25"), Some(unix_from_civil(2025, 3, 1)));
        assert_eq!(parse_expiry("202501"), Some(unix_from_civil(2025, 2, 1)));
        assert_eq!(parse_expiry("2030-05-01"), Some(unix_from_civil(2030, 5, 2)));
        assert_eq!(parse_expiry("13/2024"), None);
        assert_eq!(parse_expiry(""), None);
    }

    #[test]
    fn hibp() {
        let (prefix, suffix) = hibp_hash("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n";
        assert_eq!(hibp_range_count(body, &suffix), 9_659_365);
        assert_eq!(hibp_range_count(body, "FFFF"), 0);
        assert_eq!(hibp_url(&prefix), "https://api.pwnedpasswords.com/range/5BAA6");
    }
}
