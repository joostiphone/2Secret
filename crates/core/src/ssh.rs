//! SSH key generation for SSH Key items.

use rand::rngs::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use zeroize::Zeroizing;

use crate::item::{Category, Item};
use crate::{Error, Result};

/// A freshly generated key pair in OpenSSH formats.
pub struct SshKeyPair {
    pub private_key: Zeroizing<String>,
    pub public_key: String,
    pub fingerprint: String,
    pub key_type: String,
}

/// Generate a new Ed25519 key pair.
pub fn generate_ed25519(comment: &str) -> Result<SshKeyPair> {
    let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|e| Error::invalid(e.to_string()))?;
    key.set_comment(comment);
    let private_key = key.to_openssh(LineEnding::LF).map_err(|e| Error::invalid(e.to_string()))?;
    let public_key = key.public_key().to_openssh().map_err(|e| Error::invalid(e.to_string()))?;
    Ok(SshKeyPair {
        private_key,
        public_key,
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        key_type: "ed25519".into(),
    })
}

/// Fill an SSH Key item with a new key pair.
pub fn fill_item(item: &mut Item, comment: &str) -> Result<()> {
    if item.category != Category::SshKey {
        return Err(Error::invalid("only SSH Key items can hold a generated key"));
    }
    let pair = generate_ed25519(comment)?;
    item.set_value("private_key", &pair.private_key);
    item.set_value("public_key", &pair.public_key);
    item.set_value("fingerprint", &pair.fingerprint);
    item.set_value("key_type", &pair.key_type);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_openssh_keys() {
        let pair = generate_ed25519("me@laptop").unwrap();
        assert!(pair.private_key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(pair.public_key.starts_with("ssh-ed25519 "));
        assert!(pair.public_key.ends_with(" me@laptop"));
        assert!(pair.fingerprint.starts_with("SHA256:"));
        let parsed = PrivateKey::from_openssh(pair.private_key.as_bytes()).unwrap();
        assert_eq!(parsed.public_key().to_openssh().unwrap(), pair.public_key);

        let mut item = Item::new(Category::SshKey, "Server");
        fill_item(&mut item, "x").unwrap();
        assert!(item.value("public_key").unwrap().starts_with("ssh-ed25519"));
        assert!(fill_item(&mut Item::new(Category::Login, "x"), "x").is_err());
    }
}
