//! Signed updates.
//!
//! Every release carries `update.json`, which lists the installer the apps
//! update with for each platform, with its size and SHA-256, and
//! `update.json.sig`, an Ed25519 signature over the exact bytes of
//! `update.json`. The Release workflow makes both, signing with the private
//! key in the `UPDATE_SIGNING_KEY` repository secret. An app only installs an
//! update when:
//!
//! - the signature verifies with one of the public keys built into the app
//!   ([`public_keys`]), so a changed manifest, or one from anywhere else, is
//!   rejected;
//! - its version is newer than the running one, so an old (validly signed)
//!   manifest cannot downgrade the app to a version with known problems;
//! - the installer comes from this version's GitHub release and has exactly
//!   the signed size and SHA-256.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::util::{hex, unb64};
use crate::{Error, Result};

/// The newest release's manifest (GitHub redirects to the release).
pub const MANIFEST_URL: &str = "https://github.com/joostiphone/2Secret/releases/latest/download/update.json";
/// Its signature.
pub const SIGNATURE_URL: &str = "https://github.com/joostiphone/2Secret/releases/latest/download/update.json.sig";
/// All releases, for people who update by hand.
pub const RELEASES_URL: &str = "https://github.com/joostiphone/2Secret/releases";
/// Largest manifest and installer the apps download.
pub const MAX_MANIFEST_SIZE: u64 = 64 * 1024;
pub const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// Platform names in `update.json`.
pub mod target {
    /// The NSIS installer (`2Secret_<version>_x64-setup.exe`).
    pub const WINDOWS_X64: &str = "windows-x64";
    pub const MACOS_ARM64: &str = "macos-arm64";
    pub const MACOS_X64: &str = "macos-x64";
    pub const LINUX_X64_APPIMAGE: &str = "linux-x64-appimage";
    pub const ANDROID_ARM64: &str = "android-arm64";
    /// `2secret-v<version>-x86_64-unknown-linux-gnu.tar.gz` (server and CLI).
    pub const SERVER_LINUX_X64: &str = "server-linux-x64";
    /// `2secret-web-v<version>.tar.gz`, the web vault.
    pub const WEB: &str = "web";
}

const KEYS: &str = include_str!("update_keys.txt");

/// The public keys whose signature the apps accept (more than one while the
/// signing key is being changed).
pub fn public_keys() -> Vec<[u8; 32]> {
    KEYS.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| unb64(l).ok()?.try_into().ok())
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The version, without "v" (`1.3.0`).
    pub version: String,
    /// Release date (`2026-10-13`).
    #[serde(default)]
    pub date: String,
    /// The release page, with the release notes.
    pub url: String,
    /// Installer per platform ([`target`]).
    pub files: BTreeMap<String, Asset>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub url: String,
    pub size: u64,
    /// Lower-case hex.
    pub sha256: String,
}

/// A manifest whose signature was verified, with the signed bytes (the apps
/// keep them next to a downloaded update and verify them again before
/// installing it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub manifest: Manifest,
    pub json: Vec<u8>,
    pub signature: String,
}

impl Update {
    /// Verify `json` with the built-in public keys.
    pub fn verify(json: Vec<u8>, signature: &str) -> Result<Update> {
        Self::verify_with(json, signature, &public_keys())
    }

    pub fn verify_with(json: Vec<u8>, signature: &str, keys: &[[u8; 32]]) -> Result<Update> {
        let not_signed = || Error::invalid("the update is not signed with 2Secret's key");
        let bytes: [u8; 64] = unb64(signature.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(not_signed)?;
        let sig = Signature::from_bytes(&bytes);
        let valid =
            keys.iter().any(|k| VerifyingKey::from_bytes(k).is_ok_and(|key| key.verify_strict(&json, &sig).is_ok()));
        if !valid {
            return Err(not_signed());
        }
        let manifest: Manifest = serde_json::from_slice(&json)?;
        manifest.check()?;
        Ok(Update { manifest, json, signature: signature.trim().to_string() })
    }
}

impl Manifest {
    /// The installer for a platform.
    pub fn file(&self, target: &str) -> Option<&Asset> {
        self.files.get(target)
    }

    pub fn is_newer_than(&self, version: &str) -> bool {
        is_newer(&self.version, version)
    }

    /// Signed is not enough: the files must come from this version's release.
    fn check(&self) -> Result<()> {
        let bad = |what: &str| Error::invalid(format!("update manifest: {what}"));
        if parse_version(&self.version).is_none() {
            return Err(bad("invalid version"));
        }
        if self.url != format!("{RELEASES_URL}/tag/v{}", self.version) {
            return Err(bad("unexpected release page"));
        }
        let prefix = format!("{RELEASES_URL}/download/v{}/", self.version);
        for asset in self.files.values() {
            let name = asset.url.strip_prefix(&prefix).ok_or_else(|| bad("file outside the release"))?;
            let name_ok = !name.is_empty()
                && !name.starts_with('.')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-+".contains(c));
            if !name_ok {
                return Err(bad("invalid file name"));
            }
            if asset.size == 0 || asset.size > MAX_FILE_SIZE {
                return Err(bad("invalid file size"));
            }
            if asset.sha256.len() != 64 || !asset.sha256.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
                return Err(bad("invalid SHA-256"));
            }
        }
        Ok(())
    }
}

impl Asset {
    /// The file name (the last part of the URL; checked when verifying).
    pub fn name(&self) -> &str {
        self.url.rsplit('/').next().unwrap_or_default()
    }

    /// Check a download against the signed size and SHA-256.
    pub fn verify(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 != self.size || hex(&Sha256::digest(bytes)) != self.sha256 {
            return Err(Error::invalid("the downloaded update does not match its signature"));
        }
        Ok(())
    }
}

/// `1.2.3`, `v1.2.3` or `1.2.3-rc.1` as (major, minor, patch, is a release).
pub fn parse_version(version: &str) -> Option<(u64, u64, u64, bool)> {
    let version = version.strip_prefix('v').unwrap_or(version);
    let (numbers, pre) = match version.split_once('-') {
        Some((n, p)) => (n, Some(p)),
        None => (version, None),
    };
    let mut parts = numbers.split('.').map(|p| p.parse::<u64>().ok());
    let (major, minor, patch) = (parts.next()??, parts.next()??, parts.next()??);
    if parts.next().is_some() || pre.is_some_and(str::is_empty) {
        return None;
    }
    Some((major, minor, patch, pre.is_none()))
}

/// Whether `candidate` is a newer version than `current`. Pre-releases of the
/// same version count as older than the release.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn manifest(version: &str) -> Manifest {
        let bytes = b"installer".to_vec();
        let mut files = BTreeMap::new();
        files.insert(
            target::WINDOWS_X64.to_string(),
            Asset {
                url: format!("{RELEASES_URL}/download/v{version}/2Secret_{version}_x64-setup.exe"),
                size: bytes.len() as u64,
                sha256: hex(&Sha256::digest(&bytes)),
            },
        );
        Manifest {
            version: version.into(),
            date: "2026-10-13".into(),
            url: format!("{RELEASES_URL}/tag/v{version}"),
            files,
        }
    }

    fn sign(m: &Manifest, key: &SigningKey) -> (Vec<u8>, String) {
        let json = serde_json::to_vec_pretty(m).unwrap();
        let sig = crate::util::b64(&key.sign(&json).to_bytes());
        (json, sig)
    }

    #[test]
    fn built_in_key_parses() {
        assert_eq!(public_keys().len(), 1);
        assert!(VerifyingKey::from_bytes(&public_keys()[0]).is_ok());
    }

    #[test]
    fn verifies_signed_manifests_only() {
        let k = key(1);
        let keys = [k.verifying_key().to_bytes()];
        let m = manifest("1.3.0");
        let (json, sig) = sign(&m, &k);
        let update = Update::verify_with(json.clone(), &sig, &keys).unwrap();
        assert_eq!(update.manifest, m);
        assert!(update.manifest.is_newer_than("1.2.0"));
        let asset = update.manifest.file(target::WINDOWS_X64).unwrap();
        assert_eq!(asset.name(), "2Secret_1.3.0_x64-setup.exe");
        assert!(asset.verify(b"installer").is_ok());
        assert!(asset.verify(b"installes").is_err());
        assert!(asset.verify(b"installer!").is_err());

        // Any change to the manifest breaks the signature.
        let mut tampered = json.clone();
        let at = tampered.iter().position(|&b| b == b'3').unwrap();
        tampered[at] = b'9';
        assert!(Update::verify_with(tampered, &sig, &keys).is_err());
        // Other keys, no key, garbage.
        assert!(Update::verify_with(json.clone(), &sign(&m, &key(2)).1, &keys).is_err());
        assert!(Update::verify_with(json.clone(), &sig, &[]).is_err());
        assert!(Update::verify_with(json.clone(), "not base64!", &keys).is_err());
        assert!(Update::verify_with(json.clone(), &crate::util::b64(&[0; 64]), &keys).is_err());
        // A second key (while changing keys) is accepted too.
        assert!(Update::verify_with(json, &sig, &[key(2).verifying_key().to_bytes(), keys[0]]).is_ok());
    }

    #[test]
    fn signed_files_must_come_from_the_release() {
        let k = key(1);
        let keys = [k.verifying_key().to_bytes()];
        let reject = |m: Manifest| {
            let (json, sig) = sign(&m, &k);
            assert!(Update::verify_with(json, &sig, &keys).is_err(), "{m:?}");
        };
        let edit = |f: &dyn Fn(&mut Asset)| {
            let mut m = manifest("1.3.0");
            f(m.files.get_mut(target::WINDOWS_X64).unwrap());
            m
        };
        reject(edit(&|a| a.url = "https://example.com/2Secret_1.3.0_x64-setup.exe".into()));
        reject(edit(&|a| a.url = format!("{RELEASES_URL}/download/v1.2.0/2Secret_1.2.0_x64-setup.exe")));
        reject(edit(&|a| a.url = format!("{RELEASES_URL}/download/v1.3.0/../v1.0.0/x.exe")));
        reject(edit(&|a| a.url = format!("{RELEASES_URL}/download/v1.3.0/")));
        reject(edit(&|a| a.size = 0));
        reject(edit(&|a| a.size = MAX_FILE_SIZE + 1));
        reject(edit(&|a| a.sha256 = "AB".repeat(32)));
        let mut m = manifest("1.3.0");
        m.url = "https://example.com".into();
        reject(m);
        let mut m = manifest("1.3.0");
        m.version = "latest".into();
        reject(m);
    }

    /// The Release workflow signs with `openssl pkeyutl -sign -rawin` and
    /// writes the signature in base64; this vector was made that way with
    /// the test key below.
    #[test]
    fn accepts_openssl_signatures() {
        let public = key(7).verifying_key().to_bytes();
        assert_eq!(crate::util::b64(&public), "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=");
        let sig = "1Awn4QuhItePOVmIqend4AbbCu/anQ+KWSYRHBGdR7JciqwJrORuO+SY6nt5/Tbidm15xutDczx2lZQHc0LqBQ==\n";
        let sig: [u8; 64] = unb64(sig.trim()).unwrap().try_into().unwrap();
        let key = VerifyingKey::from_bytes(&public).unwrap();
        assert!(key.verify_strict(br#"{"version":"9.9.9"}"#, &Signature::from_bytes(&sig)).is_ok());
    }

    #[test]
    fn versions() {
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3, true)));
        assert_eq!(parse_version("1.2.3-rc.1"), Some((1, 2, 3, false)));
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("1.2.3-"), None);
        assert!(is_newer("1.3.0", "1.2.9"));
        assert!(is_newer("1.10.0", "1.9.0"));
        assert!(is_newer("2.0.0", "1.99.99"));
        assert!(is_newer("1.3.0", "1.3.0-rc.1"));
        assert!(!is_newer("1.3.0-rc.1", "1.3.0"));
        assert!(!is_newer("1.2.0", "1.2.0"));
        assert!(!is_newer("1.1.9", "1.2.0"));
        assert!(!is_newer("garbage", "1.2.0"));
    }
}
