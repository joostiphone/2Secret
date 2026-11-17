//! The AutoFill cache for iOS and macOS: what the AutoFill extension may
//! fill, sealed for the extension. Also what Android's AutoFill service may
//! fill ([`AndroidAutofill`]), which the Android app seals itself.
//!
//! The extension runs outside the app and cannot unlock the vault, so the app
//! (while unlocked, with Face ID / Touch ID unlock turned on) writes the
//! logins, passkeys and one-time password secrets it may fill to a file
//! shared with the extension. The
//! file is encrypted with ChaCha20-Poly1305 under a fresh random 256-bit key
//! on every write; the key goes into the keychain, readable only after Face ID
//! or Touch ID on this device. The layout is CryptoKit's
//! `ChaChaPoly.SealedBox` (`nonce ‖ ciphertext ‖ tag`).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::SymmetricKey;
use crate::session::Session;
use crate::totp::Totp;
use crate::util::{b64url, base_domain, is_public_suffix, now, random_bytes, web_host};
use crate::{Error, Result};

/// Associated data of the sealed cache.
pub const AAD: &[u8] = b"2secret/v1/autofill";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AutofillCache {
    pub version: u32,
    pub account_id: String,
    /// When the master password was last entered on this device; the
    /// extension stops filling after `BiometricUnlock::MAX_DAYS`.
    pub password_entered_at: i64,
    pub created_at: i64,
    pub logins: Vec<AutofillLogin>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AutofillLogin {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    /// Registrable domains of the item's websites (`example.co.uk`), so the
    /// extension needs no public suffix list.
    pub domains: Vec<String>,
    /// Websites whose host is itself a public suffix (`github.io`): they
    /// match that host only, never a subdomain (someone else's site).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exact_hosts: Vec<String>,
    pub passkeys: Vec<AutofillPasskey>,
    /// The login's one-time password, for filling verification codes (iOS 18,
    /// macOS 15).
    #[serde(default)]
    pub totp: Option<AutofillTotp>,
    /// The website's icon as a checked `data:image/…` URL (at most 24 KB),
    /// for the list the extension shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AutofillPasskey {
    /// base64url, like the other binary values.
    pub credential_id: String,
    pub rp_id: String,
    pub user_handle: String,
    pub user_name: String,
    /// PKCS #8 private key.
    pub private_key: String,
}

/// What the extension needs to compute codes like [`Totp::code_at`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AutofillTotp {
    /// The shared secret, base64url.
    pub secret: String,
    /// `SHA1`, `SHA256` or `SHA512`.
    pub algorithm: String,
    pub digits: u32,
    pub period: u64,
    /// Steam Guard: five characters from Steam's alphabet instead of digits.
    pub steam: bool,
}

impl From<&Totp> for AutofillTotp {
    fn from(t: &Totp) -> Self {
        AutofillTotp {
            secret: b64url(t.secret()),
            algorithm: t.algorithm.name().into(),
            digits: t.digits,
            period: t.period,
            steam: t.steam,
        }
    }
}

impl Session {
    /// Everything the AutoFill extension may fill: logins with a password, a
    /// passkey or a one-time password, outside the trash.
    pub fn autofill_cache(&self, password_entered_at: i64) -> AutofillCache {
        let mut logins: Vec<AutofillLogin> = self
            .all_items()
            .filter(|(_, i)| !i.is_trashed())
            .map(|(_, i)| (i, i.totp_secret().and_then(|t| Totp::parse(t).ok())))
            .filter(|(i, totp)| i.password().is_some_and(|p| !p.is_empty()) || !i.passkeys.is_empty() || totp.is_some())
            .map(|(i, totp)| {
                let (domains, exact_hosts) = websites(i);
                AutofillLogin {
                    id: i.id.clone(),
                    title: i.title.clone(),
                    username: i.username().unwrap_or("").to_string(),
                    password: i.password().unwrap_or("").to_string(),
                    domains,
                    exact_hosts,
                    passkeys: i
                        .passkeys
                        .iter()
                        .map(|p| AutofillPasskey {
                            credential_id: p.credential_id.clone(),
                            rp_id: p.rp_id.clone(),
                            user_handle: p.user_handle.clone(),
                            user_name: p.user_name.clone(),
                            private_key: p.private_key.clone(),
                        })
                        .collect(),
                    totp: totp.as_ref().map(AutofillTotp::from),
                    icon: i.icon.as_ref().and_then(|icon| icon.safe_image()).map(str::to_string),
                }
            })
            .collect();
        logins.sort_by_key(|l| l.title.to_lowercase());
        AutofillCache {
            version: 1,
            account_id: self.account().id.clone(),
            password_entered_at,
            created_at: now(),
            logins,
        }
    }
}

/// The registrable domains (`example.co.uk`) and the exact hosts (a host
/// that is itself a public suffix, like `github.io`) of an item's websites
/// and passkeys. App addresses (`androidapp://`, `iosapp://`) are no
/// websites.
fn websites(item: &crate::item::Item) -> (Vec<String>, Vec<String>) {
    let hosts: Vec<String> = item.urls.iter().filter(|u| !is_app_address(u)).filter_map(|u| web_host(u)).collect();
    let (mut exact_hosts, hosts): (Vec<String>, Vec<String>) = hosts.into_iter().partition(|h| is_public_suffix(h));
    let mut domains: Vec<String> = hosts.iter().map(|h| base_domain(h)).collect();
    domains.extend(item.passkeys.iter().map(|p| base_domain(&p.rp_id)));
    domains.sort();
    domains.dedup();
    exact_hosts.sort();
    exact_hosts.dedup();
    (domains, exact_hosts)
}

fn is_app_address(url: &str) -> bool {
    let url = url.trim().to_ascii_lowercase();
    url.starts_with("androidapp://") || url.starts_with("iosapp://")
}

/// The Android package name of an `androidapp://com.example.app` address
/// (the form Bitwarden and others use), if it is one.
pub fn android_package(url: &str) -> Option<String> {
    let url = url.trim();
    let rest = url.get(..13).filter(|s| s.eq_ignore_ascii_case("androidapp://")).map(|_| &url[13..])?;
    let name = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let valid = name.contains('.')
        && name.split('.').all(|part| {
            part.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
    valid.then(|| name.to_string())
}

/// What Android's AutoFill service may fill: the logins with a password,
/// outside the trash, with their websites and apps. No passkeys, one-time
/// password secrets or icons: the service fills user names and passwords
/// only. The Android app encrypts it before it leaves Rust's memory
/// (AutofillStore in crates/app/android/MainActivity.kt).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AndroidAutofill {
    pub version: u32,
    pub account_id: String,
    /// When the master password was last entered on this device; the
    /// service stops filling after `BiometricUnlock::MAX_DAYS`.
    pub password_entered_at: i64,
    pub created_at: i64,
    pub logins: Vec<AndroidLogin>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AndroidLogin {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    /// Registrable domains of the item's websites: a page matches when its
    /// host is one of them or ends in "." and one of them.
    pub domains: Vec<String>,
    /// Websites whose host is itself a public suffix (`github.io`): that
    /// host only, never a subdomain.
    pub exact_hosts: Vec<String>,
    /// Package names of the item's `androidapp://` addresses: the apps it
    /// is for.
    pub packages: Vec<String>,
}

impl Session {
    /// Everything Android's AutoFill service may fill.
    pub fn android_autofill(&self, password_entered_at: i64) -> AndroidAutofill {
        let mut logins: Vec<AndroidLogin> = self
            .all_items()
            .map(|(_, i)| i)
            .filter(|i| !i.is_trashed() && i.password().is_some_and(|p| !p.is_empty()))
            .map(|i| {
                let (domains, exact_hosts) = websites(i);
                let mut packages: Vec<String> = i.urls.iter().filter_map(|u| android_package(u)).collect();
                packages.sort();
                packages.dedup();
                AndroidLogin {
                    id: i.id.clone(),
                    title: i.title.clone(),
                    username: i.username().unwrap_or("").to_string(),
                    password: i.password().unwrap_or("").to_string(),
                    domains,
                    exact_hosts,
                    packages,
                }
            })
            .collect();
        logins.sort_by_key(|l| l.title.to_lowercase());
        AndroidAutofill {
            version: 1,
            account_id: self.account().id.clone(),
            password_entered_at,
            created_at: now(),
            logins,
        }
    }
}

impl AutofillCache {
    /// Encrypt under a new random key. Returns the sealed bytes and the key.
    pub fn seal(&self) -> Result<(Vec<u8>, SymmetricKey)> {
        let key = SymmetricKey::generate();
        let json = Zeroizing::new(serde_json::to_vec(self)?);
        let nonce: [u8; 12] = random_bytes();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &json, aad: AAD })
            .map_err(|_| Error::invalid("could not encrypt the AutoFill cache"))?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&ciphertext);
        Ok((sealed, key))
    }

    pub fn open(sealed: &[u8], key: &SymmetricKey) -> Result<Self> {
        if sealed.len() < 12 + 16 {
            return Err(Error::Decryption);
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        let json = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(&sealed[..12]), Payload { msg: &sealed[12..], aad: AAD })
                .map_err(|_| Error::Decryption)?,
        );
        Ok(serde_json::from_slice(&json)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::favicon::WebsiteIcon;
    use crate::item::Item;
    use crate::passkey::{self, CreationOptions};
    use crate::session::tests::new_session;

    #[test]
    fn cache_holds_what_autofill_needs() {
        let (mut s, _) = new_session();
        let v = s.default_vault_id().unwrap();
        let mut bank = Item::login("Bank", "jan", "pw-1", Some("https://login.mybank.co.uk/"));
        bank.icon = Some(WebsiteIcon { host: "login.mybank.co.uk".into(), image: "data:image/png;base64,AA==".into() });
        s.add_item(&v, bank).unwrap();
        s.add_item(&v, Item::login("Empty", "nobody", "", Some("https://example.com"))).unwrap();
        let mut codes = Item::login("Codes", "me", "", Some("https://codes.example.org"));
        codes.set_value(
            "totp",
            "otpauth://totp/Codes:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&algorithm=SHA256",
        );
        s.add_item(&v, codes).unwrap();
        let trashed = s.add_item(&v, Item::login("Old", "old", "pw-2", Some("https://old.example.com"))).unwrap();
        s.trash_item(&trashed).unwrap();
        let mut tenant = Item::login("Tenants", "t", "pw-3", Some("https://www.pythonanywhere.com/login"));
        tenant.urls.push("https://github.io".into());
        s.add_item(&v, tenant).unwrap();
        let options = CreationOptions {
            rp_id: None,
            rp_name: "GitHub".into(),
            user_handle: b64url(b"u1"),
            user_name: "octo".into(),
            user_display_name: String::new(),
            challenge: b64url(&[1u8; 32]),
            algorithms: vec![],
            exclude_credentials: vec![],
        };
        let (pk, _) = passkey::create("https://github.com", &options).unwrap();
        s.save_passkey(&v, None, "https://github.com", pk).unwrap();

        let cache = s.autofill_cache(123);
        assert_eq!(cache.password_entered_at, 123);
        let titles: Vec<&str> = cache.logins.iter().map(|l| l.title.as_str()).collect();
        assert_eq!(titles, ["Bank", "Codes", "GitHub", "Tenants"]);
        assert_eq!(cache.logins[0].domains, ["mybank.co.uk"]);
        // A tenant's site is not its neighbour's: no "pythonanywhere.com".
        assert_eq!(cache.logins[3].domains, ["www.pythonanywhere.com"]);
        assert_eq!(cache.logins[3].exact_hosts, ["github.io"]);
        assert_eq!(cache.logins[0].icon.as_deref(), Some("data:image/png;base64,AA=="));
        assert!(cache.logins[3].icon.is_none(), "no icon, no field");
        assert!(cache.logins[0].totp.is_none());
        let totp = cache.logins[1].totp.as_ref().unwrap();
        assert_eq!(totp.secret, b64url(b"12345678901234567890"));
        assert_eq!((totp.algorithm.as_str(), totp.digits, totp.period, totp.steam), ("SHA256", 8, 30, false));
        assert_eq!(cache.logins[2].passkeys[0].rp_id, "github.com");

        let (sealed, key) = cache.seal().unwrap();
        assert_eq!(AutofillCache::open(&sealed, &key).unwrap(), cache);
        assert!(AutofillCache::open(&sealed, &SymmetricKey::generate()).is_err());
        let mut tampered = sealed.clone();
        tampered[20] ^= 1;
        assert!(AutofillCache::open(&tampered, &key).is_err());
        // Every write uses a new key and nonce.
        let (again, key2) = cache.seal().unwrap();
        assert_ne!(again[..12], sealed[..12]);
        assert_ne!(key, key2);
    }

    #[test]
    fn app_addresses_are_no_websites() {
        let (mut s, _) = new_session();
        let v = s.default_vault_id().unwrap();
        let mut bank = Item::login("Bank", "jan", "pw", Some("https://www.mybank.nl/login"));
        bank.urls.push("androidapp://nl.mybank.app".into());
        s.add_item(&v, bank).unwrap();
        let cache = s.autofill_cache(0);
        assert_eq!(cache.logins[0].domains, ["mybank.nl"], "not \"mybank.app\"");
    }

    #[test]
    fn android_package_names() {
        assert_eq!(android_package("androidapp://com.example.app").as_deref(), Some("com.example.app"));
        assert_eq!(android_package(" AndroidApp://com.example.app/ ").as_deref(), Some("com.example.app"));
        assert_eq!(android_package("androidapp://nl.bank_app.v2?x=1").as_deref(), Some("nl.bank_app.v2"));
        assert_eq!(android_package("https://com.example.app"), None);
        assert_eq!(android_package("androidapp://nodot"), None);
        assert_eq!(android_package("androidapp://com.1bad"), None);
        assert_eq!(android_package("androidapp://com.ex ample"), None);
        assert_eq!(android_package("androidapp://"), None);
        assert_eq!(android_package("android"), None);
    }

    #[test]
    fn android_store_holds_logins_with_a_password() {
        let (mut s, _) = new_session();
        let v = s.default_vault_id().unwrap();
        let mut bank = Item::login("Bank", "jan", "pw-1", Some("https://login.mybank.co.uk/"));
        bank.urls.push("androidapp://uk.mybank.mobile".into());
        bank.urls.push("androidapp://uk.mybank.mobile/".into());
        bank.set_value("totp", "otpauth://totp/Bank:jan?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        s.add_item(&v, bank).unwrap();
        s.add_item(&v, Item::login("Empty", "nobody", "", Some("https://example.com"))).unwrap();
        let trashed = s.add_item(&v, Item::login("Old", "old", "pw-2", Some("https://old.example.com"))).unwrap();
        s.trash_item(&trashed).unwrap();
        let mut tenant = Item::login("Tenants", "t", "pw-3", Some("https://www.pythonanywhere.com/login"));
        tenant.urls.push("https://github.io".into());
        s.add_item(&v, tenant).unwrap();
        s.add_item(&v, Item::login("app only", "a", "pw-4", Some("androidapp://com.example.app"))).unwrap();

        let store = s.android_autofill(123);
        assert_eq!(store.password_entered_at, 123);
        assert_eq!(store.account_id, s.account().id);
        let titles: Vec<&str> = store.logins.iter().map(|l| l.title.as_str()).collect();
        assert_eq!(titles, ["app only", "Bank", "Tenants"]);
        assert!(store.logins[0].domains.is_empty());
        assert_eq!(store.logins[0].packages, ["com.example.app"]);
        let bank = &store.logins[1];
        assert_eq!((bank.username.as_str(), bank.password.as_str()), ("jan", "pw-1"));
        assert_eq!(bank.domains, ["mybank.co.uk"]);
        assert_eq!(bank.packages, ["uk.mybank.mobile"]);
        assert_eq!(store.logins[2].domains, ["www.pythonanywhere.com"]);
        assert_eq!(store.logins[2].exact_hosts, ["github.io"]);
        // What the Kotlin side reads.
        let json: serde_json::Value = serde_json::to_value(&store).unwrap();
        assert_eq!(json["logins"][1]["packages"][0], "uk.mybank.mobile");
        assert!(json["logins"][1].get("totp").is_none(), "no one-time password secrets");
        assert_eq!(json["logins"][0]["exact_hosts"], serde_json::json!([]));
    }
}
