//! Share links: an item, or the fields of it the user picks, for someone
//! without 2Secret, at a link like `https://sync.example.com/s/<id>#<key>`.
//!
//! The server keeps the content encrypted with AES-256-GCM under a key made
//! from a random 256-bit link key, which only the link's fragment holds
//! (browsers never send the fragment), and gives it out a limited number of
//! times until it expires. An optional password is mixed into the key
//! (PBKDF2-HMAC-SHA256, 600 000 rounds) for links sent through a channel
//! others can read; send the password another way.
//!
//! The server releases the content only to someone who proves to know the key
//! (`proof`, a hash of the content key), so a link without its fragment, a
//! guessed id or a wrong password cannot use up its views, and too many wrong
//! proofs delete the link.
//!
//! The page that opens links (`crates/server/src/share.js`) decrypts with the
//! browser's WebCrypto, which has AES-GCM, SHA-256 and PBKDF2 (but neither
//! XChaCha20-Poly1305 nor Argon2id), hence these choices here.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::util::{b64url, unb64url};
use crate::{Error, Result};

/// PBKDF2 rounds for a link password (OWASP's advice for PBKDF2-HMAC-SHA256).
pub const PBKDF2_ROUNDS: u32 = 600_000;

/// What a link shows.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct SharedItem {
    pub title: String,
    #[serde(default)]
    pub fields: Vec<SharedField>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct SharedField {
    pub label: String,
    pub value: String,
    /// Hidden until shown (passwords and other secrets).
    #[serde(default)]
    pub concealed: bool,
}

impl SharedItem {
    /// An item's fields that `keep` keeps and have a value, with its notes
    /// and websites. Attachments and passkeys are never shared.
    pub fn from_item(
        item: &crate::item::Item,
        label: impl Fn(&crate::item::Field) -> String,
        keep: impl Fn(&crate::item::Field) -> bool,
        notes: bool,
    ) -> SharedItem {
        use crate::item::FieldKind;
        SharedItem {
            title: item.title.clone(),
            fields: item
                .fields
                .iter()
                .filter(|f| !f.value.trim().is_empty() && keep(f))
                .map(|f| SharedField {
                    label: label(f),
                    value: f.value.clone(),
                    concealed: matches!(f.kind, FieldKind::Concealed | FieldKind::Totp),
                })
                .collect(),
            notes: if notes { item.notes.clone() } else { String::new() },
            urls: item.urls.iter().filter(|u| !u.trim().is_empty()).cloned().collect(),
        }
    }
}

/// A new link, to send to the server (all but `key`).
#[derive(Debug)]
pub struct SealedShare {
    pub id: String,
    /// The link key for the fragment (base64url).
    pub key: Zeroizing<String>,
    /// Nonce and AES-GCM ciphertext (base64url).
    pub data: String,
    /// What the server checks before it gives out the data (base64url).
    pub proof: String,
}

fn content_key(link_key: &[u8], id: &str, password: Option<&str>) -> Zeroizing<[u8; 32]> {
    let mut stretched = Zeroizing::new([0u8; 32]);
    if let Some(password) = password {
        let password = crate::crypto::normalize_password(password);
        pbkdf2::pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            format!("2secret share {id}").as_bytes(),
            PBKDF2_ROUNDS,
            &mut *stretched,
        );
    }
    let mut hasher = Sha256::new();
    hasher.update(b"2secret/share/v1/key");
    hasher.update(link_key);
    if password.is_some() {
        hasher.update(*stretched);
    }
    Zeroizing::new(hasher.finalize().into())
}

fn proof(key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"2secret/share/v1/proof");
    hasher.update(key);
    b64url(&hasher.finalize())
}

fn aad(id: &str) -> Vec<u8> {
    format!("2secret/share/v1:{id}").into_bytes()
}

/// Encrypt `item` for a new link.
pub fn seal(item: &SharedItem, password: Option<&str>) -> Result<SealedShare> {
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let id = b64url(&random);
    let mut link_key = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *link_key);
    let key = content_key(&*link_key, &id, password.filter(|p| !p.is_empty()));
    let plaintext = Zeroizing::new(serde_json::to_vec(item)?);
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| Error::Encryption)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &aad(&id) })
        .map_err(|_| Error::Encryption)?;
    let mut data = nonce.to_vec();
    data.extend_from_slice(&ciphertext);
    Ok(SealedShare { proof: proof(&key), data: b64url(&data), key: Zeroizing::new(b64url(&*link_key)), id })
}

/// The proof for opening a link: from its key and password.
pub fn open_proof(id: &str, link_key: &str, password: Option<&str>) -> Result<String> {
    let link_key = Zeroizing::new(unb64url(link_key)?);
    Ok(proof(&content_key(&link_key, id, password.filter(|p| !p.is_empty()))))
}

/// Decrypt what the server gave out (what the page does in the browser).
pub fn open(id: &str, data: &str, link_key: &str, password: Option<&str>) -> Result<SharedItem> {
    let link_key = Zeroizing::new(unb64url(link_key)?);
    let key = content_key(&link_key, id, password.filter(|p| !p.is_empty()));
    let data = unb64url(data)?;
    if data.len() < 12 {
        return Err(Error::invalid("shared data is too short"));
    }
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| Error::Decryption)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&data[..12]), Payload { msg: &data[12..], aad: &aad(id) })
            .map_err(|_| Error::WrongPassword)?,
    );
    Ok(serde_json::from_slice(&plaintext)?)
}

/// The link for a share on a server (`https://sync.example.com`).
pub fn link(server: &str, sealed: &SealedShare) -> String {
    format!("{}/s/{}#{}", server.trim_end_matches('/'), sealed.id, sealed.key.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item() -> SharedItem {
        SharedItem {
            title: "Wi-Fi".into(),
            fields: vec![SharedField { label: "password".into(), value: "hunter2 ü".into(), concealed: true }],
            notes: "Second floor".into(),
            urls: vec![],
        }
    }

    #[test]
    fn opens_with_the_link_key() {
        let sealed = seal(&item(), None).unwrap();
        assert_eq!(sealed.id.len(), 22);
        assert_eq!(sealed.key.len(), 43);
        assert_eq!(open(&sealed.id, &sealed.data, &sealed.key, None).unwrap(), item());
        assert_eq!(open_proof(&sealed.id, &sealed.key, None).unwrap(), sealed.proof);
        // Another id (the ciphertext moved to another link) fails.
        let other = seal(&item(), None).unwrap();
        assert!(open(&other.id, &sealed.data, &sealed.key, None).is_err());
        let link = link("https://sync.example.com/", &sealed);
        assert_eq!(link, format!("https://sync.example.com/s/{}#{}", sealed.id, sealed.key.as_str()));
    }

    #[test]
    fn password_is_part_of_the_key() {
        let sealed = seal(&item(), Some("correct horse")).unwrap();
        assert!(open(&sealed.id, &sealed.data, &sealed.key, None).is_err());
        assert!(open(&sealed.id, &sealed.data, &sealed.key, Some("wrong")).is_err());
        assert_eq!(open(&sealed.id, &sealed.data, &sealed.key, Some("correct horse")).unwrap(), item());
        assert_ne!(open_proof(&sealed.id, &sealed.key, Some("wrong")).unwrap(), sealed.proof);
        assert_eq!(open_proof(&sealed.id, &sealed.key, Some("correct horse")).unwrap(), sealed.proof);
    }

    /// The page in the browser derives the same keys (`share.js`); these
    /// values were computed independently (Python's hashlib).
    #[test]
    fn matches_the_web_page() {
        let link_key = b64url(&[7u8; 32]);
        let id = "AAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(open_proof(id, &link_key, None).unwrap(), "DCjz0vy6WEkfMbGrTeswHABb8kJMlpACbllEMijxfEM");
        assert_eq!(
            open_proof(id, &link_key, Some("wachtwoord")).unwrap(),
            "-m4bKdfk_IZkwQSZtO7yzWjj5CA3IkETa5awyPaRa38"
        );
    }
}
