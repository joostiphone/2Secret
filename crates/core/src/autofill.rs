//! The AutoFill cache for iOS: what the AutoFill extension may fill, sealed
//! for the extension.
//!
//! The extension runs outside the app and cannot unlock the vault, so the app
//! (while unlocked, with Face ID / Touch ID unlock turned on) writes the
//! logins and passkeys it may fill to a file shared with the extension. The
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
use crate::util::{base_domain, now, random_bytes, url_host};
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
    pub passkeys: Vec<AutofillPasskey>,
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

impl Session {
    /// Everything the AutoFill extension may fill: logins with a password or
    /// a passkey, outside the trash.
    pub fn autofill_cache(&self, password_entered_at: i64) -> AutofillCache {
        let mut logins: Vec<AutofillLogin> = self
            .all_items()
            .filter(|(_, i)| !i.is_trashed())
            .filter(|(_, i)| i.password().is_some_and(|p| !p.is_empty()) || !i.passkeys.is_empty())
            .map(|(_, i)| {
                let mut domains: Vec<String> =
                    i.urls.iter().filter_map(|u| url_host(u)).map(|h| base_domain(&h)).collect();
                domains.extend(i.passkeys.iter().map(|p| base_domain(&p.rp_id)));
                domains.sort();
                domains.dedup();
                AutofillLogin {
                    id: i.id.clone(),
                    title: i.title.clone(),
                    username: i.username().unwrap_or("").to_string(),
                    password: i.password().unwrap_or("").to_string(),
                    domains,
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
    use crate::item::Item;
    use crate::passkey::{self, CreationOptions};
    use crate::session::tests::new_session;
    use crate::util::b64url;

    #[test]
    fn cache_holds_what_autofill_needs() {
        let (mut s, _) = new_session();
        let v = s.default_vault_id().unwrap();
        s.add_item(&v, Item::login("Bank", "jan", "pw-1", Some("https://login.mybank.co.uk/"))).unwrap();
        s.add_item(&v, Item::login("Empty", "nobody", "", Some("https://example.com"))).unwrap();
        let trashed = s.add_item(&v, Item::login("Old", "old", "pw-2", Some("https://old.example.com"))).unwrap();
        s.trash_item(&trashed).unwrap();
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
        assert_eq!(titles, ["Bank", "GitHub"]);
        assert_eq!(cache.logins[0].domains, ["mybank.co.uk"]);
        assert_eq!(cache.logins[1].passkeys[0].rp_id, "github.com");

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
}
