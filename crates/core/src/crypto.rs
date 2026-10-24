//! Cryptographic primitives and the 2Secret key hierarchy.
//!
//! * **Key derivation** – Two-Secret Key Derivation (2SKD): the master password
//!   is stretched with Argon2id and combined with a 130-bit random
//!   [`SecretKey`] that never leaves the user's devices. A server breach alone
//!   is therefore useless for offline password guessing.
//! * **Symmetric encryption** – XChaCha20-Poly1305 with random 192-bit nonces
//!   and associated data that binds every ciphertext to its purpose and owner.
//! * **Public-key encryption** – X25519 + HKDF-SHA256 + XChaCha20-Poly1305
//!   sealed boxes, used to share vault keys between accounts.
//!
//! See `docs/SECURITY.md` for the complete design.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::util::{b64, b64url, normalize_email, random_bytes, unb64, unb64url};
use crate::{Error, Result};

/// Length of every symmetric key in bytes.
pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const ENC_PREFIX: &str = "2s1.";

// ---------------------------------------------------------------------------
// Symmetric keys
// ---------------------------------------------------------------------------

/// A 256-bit symmetric key that is wiped from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SymmetricKey([u8; KEY_LEN]);

impl SymmetricKey {
    /// Generate a fresh random key.
    pub fn generate() -> Self {
        Self(random_bytes())
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_LEN] = bytes.try_into().map_err(|_| Error::invalid("key has the wrong length"))?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive an independent sub key for the given purpose (HKDF-SHA256).
    pub fn derive(&self, info: &str) -> SymmetricKey {
        hkdf32(&self.0, None, info.as_bytes())
    }

    /// Base64 representation, used by the CLI session cache.
    pub fn to_b64(&self) -> String {
        b64url(&self.0)
    }

    pub fn from_b64(s: &str) -> Result<Self> {
        let bytes = Zeroizing::new(unb64url(s)?);
        Self::from_slice(&bytes)
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(<redacted>)")
    }
}

/// HKDF-SHA256 with a 32 byte output.
pub fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> SymmetricKey {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm).expect("32 bytes is a valid HKDF-SHA256 output length");
    let key = SymmetricKey(okm);
    okm.zeroize();
    key
}

/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ---------------------------------------------------------------------------
// Authenticated encryption
// ---------------------------------------------------------------------------

/// An encrypted, authenticated blob: `2s1.` followed by
/// base64url(nonce ‖ ciphertext ‖ tag).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncString(String);

impl EncString {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parse and validate the textual representation.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if !s.starts_with(ENC_PREFIX) {
            return Err(Error::Unsupported("unknown ciphertext version".into()));
        }
        let raw = unb64url(&s[ENC_PREFIX.len()..])?;
        if raw.len() < NONCE_LEN + 16 {
            return Err(Error::Decryption);
        }
        Ok(Self(s.to_string()))
    }

    /// Size of the encoded ciphertext in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Encrypt `plaintext` with XChaCha20-Poly1305. `aad` is authenticated but not
/// encrypted and must be supplied again for decryption.
pub fn encrypt(key: &SymmetricKey, plaintext: &[u8], aad: &[u8]) -> EncString {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory buffers");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    EncString(format!("{ENC_PREFIX}{}", b64url(&out)))
}

/// Decrypt and authenticate a blob produced by [`encrypt`].
pub fn decrypt(key: &SymmetricKey, enc: &EncString, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let body = enc.0.strip_prefix(ENC_PREFIX).ok_or_else(|| Error::Unsupported("unknown ciphertext version".into()))?;
    let raw = unb64url(body).map_err(|_| Error::Decryption)?;
    if raw.len() < NONCE_LEN + 16 {
        return Err(Error::Decryption);
    }
    let (nonce, ct) = raw.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decryption)
}

/// Serialize `value` as JSON and encrypt it.
pub fn encrypt_json<T: Serialize>(key: &SymmetricKey, value: &T, aad: &[u8]) -> Result<EncString> {
    let mut json = Zeroizing::new(serde_json::to_vec(value)?);
    // Trailing spaces are valid JSON whitespace: padding means a ciphertext
    // only reveals a size class, not the exact length of a title or password.
    let padded = padded_len(json.len());
    json.resize(padded, b' ');
    Ok(encrypt(key, &json, aad))
}

/// Size classes for padding: 256-byte steps up to 4 KiB, 4 KiB steps up to
/// 64 KiB, then 64 KiB steps.
fn padded_len(len: usize) -> usize {
    let step = match len {
        0..=4096 => 256,
        4097..=65536 => 4096,
        _ => 65536,
    };
    len.div_ceil(step).max(1) * step
}

/// Decrypt a blob and deserialize the JSON inside.
pub fn decrypt_json<T: DeserializeOwned>(key: &SymmetricKey, enc: &EncString, aad: &[u8]) -> Result<T> {
    let plain = decrypt(key, enc, aad)?;
    Ok(serde_json::from_slice(&plain)?)
}

// ---------------------------------------------------------------------------
// Password hashing
// ---------------------------------------------------------------------------

/// Minimum Argon2id memory cost accepted anywhere (OWASP: 19 MiB with 2 passes).
pub const MIN_KDF_MEMORY_KIB: u32 = 19 * 1024;
/// Minimum Argon2id passes accepted anywhere.
pub const MIN_KDF_ITERATIONS: u32 = 2;
static WEAK_KDF_ALLOWED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Argon2id parameters. Stored with the account so they can be raised later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 4 lanes – comfortably above the OWASP recommendation
    /// while still unlocking in well under a second on phones and in browsers.
    fn default() -> Self {
        Self { algorithm: "argon2id".into(), memory_kib: 64 * 1024, iterations: 3, parallelism: 4 }
    }
}

impl KdfParams {
    /// Deliberately weak parameters for tests only. Calling this also lifts the
    /// minimum below for the rest of the process.
    pub fn insecure_for_tests() -> Self {
        Self::allow_weak_for_tests();
        Self { algorithm: "argon2id".into(), memory_kib: 64, iterations: 1, parallelism: 1 }
    }

    /// Reject parameters that are unsupported or absurd (protects clients
    /// against denial of service through hostile server responses).
    pub fn validate(&self) -> Result<()> {
        if self.algorithm != "argon2id" {
            return Err(Error::Unsupported(format!("KDF {}", self.algorithm)));
        }
        if self.parallelism == 0 || self.parallelism > 16 {
            return Err(Error::Kdf("parallelism out of range".into()));
        }
        if self.memory_kib < 8 * self.parallelism || self.memory_kib > 2 * 1024 * 1024 {
            return Err(Error::Kdf("memory cost out of range".into()));
        }
        if self.iterations == 0 || self.iterations > 64 {
            return Err(Error::Kdf("iteration count out of range".into()));
        }
        // A hostile or outdated server must not be able to make clients derive
        // keys with weak parameters (LastPass kept accounts on 1 or 500
        // PBKDF2 iterations for years). Servers refuse them too.
        if self.is_weak() && !WEAK_KDF_ALLOWED.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Kdf(format!(
                "Argon2id parameters below the minimum ({} MiB, {} passes)",
                MIN_KDF_MEMORY_KIB / 1024,
                MIN_KDF_ITERATIONS
            )));
        }
        Ok(())
    }

    /// Accept parameters below the minimum for the rest of the process (tests).
    pub fn allow_weak_for_tests() {
        WEAK_KDF_ALLOWED.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Below the minimum this crate accepts outside of tests?
    pub fn is_weak(&self) -> bool {
        self.memory_kib < MIN_KDF_MEMORY_KIB || self.iterations < MIN_KDF_ITERATIONS
    }

    /// Run Argon2id with these parameters.
    pub fn hash(&self, password: &[u8], salt: &[u8]) -> Result<SymmetricKey> {
        self.validate()?;
        let params = argon2::Params::new(self.memory_kib, self.iterations, self.parallelism, Some(KEY_LEN))
            .map_err(|e| Error::Kdf(e.to_string()))?;
        let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut out = [0u8; KEY_LEN];
        argon.hash_password_into(password, salt, &mut out).map_err(|e| Error::Kdf(e.to_string()))?;
        let key = SymmetricKey(out);
        out.zeroize();
        Ok(key)
    }
}

// ---------------------------------------------------------------------------
// Secret Key
// ---------------------------------------------------------------------------

const SK_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
/// Random characters in a new Secret Key: 26 × 5 = 130 bits of entropy.
const SK_RANDOM_CHARS: usize = 26;
/// Keys created by 2Secret 1.0 have 25 random characters (125 bits) and keep
/// working.
const SK_LEGACY_RANDOM_CHARS: usize = 25;
const SK_PREFIX: &str = "2S";

/// The account Secret Key: 130 random bits plus a check character, shown to
/// the user as `2S-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`.
///
/// It is generated on the user's device, stored only on their devices and in
/// their Emergency Kit, and mixed into key derivation so that the server never
/// holds enough information to attack the master password.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SecretKey {
    chars: String,
}

impl SecretKey {
    pub fn generate() -> Self {
        // Rejection-free: 256 is a multiple of 32.
        let bytes: [u8; SK_RANDOM_CHARS] = random_bytes();
        let mut chars: String = bytes.iter().map(|b| SK_ALPHABET[(*b as usize) % 32] as char).collect();
        chars.push(Self::check_char(&chars));
        Self { chars }
    }

    fn check_char(body: &str) -> char {
        let digest = sha256(format!("2secret-secret-key-check:{body}").as_bytes());
        SK_ALPHABET[(digest[0] as usize) % 32] as char
    }

    /// Parse a Secret Key as typed by a user. Case, spaces and dashes are
    /// ignored; the check character catches most typos.
    pub fn parse(input: &str) -> Result<Self> {
        let mut cleaned: String =
            input.chars().filter(|c| !c.is_whitespace() && *c != '-').flat_map(|c| c.to_uppercase()).collect();
        // With and without the prefix, the two key lengths never collide.
        let lengths = [SK_RANDOM_CHARS + 1, SK_LEGACY_RANDOM_CHARS + 1];
        if lengths.iter().any(|l| cleaned.len() == l + SK_PREFIX.len()) && cleaned.starts_with(SK_PREFIX) {
            cleaned.drain(..SK_PREFIX.len());
        }
        if !lengths.contains(&cleaned.len()) {
            return Err(Error::InvalidSecretKey(format!(
                "expected {} characters, got {}",
                SK_RANDOM_CHARS + 1,
                cleaned.len()
            )));
        }
        if let Some(bad) = cleaned.chars().find(|c| !c.is_ascii() || !SK_ALPHABET.contains(&(*c as u8))) {
            return Err(Error::InvalidSecretKey(format!("character '{bad}' is not allowed")));
        }
        let (body, check) = cleaned.split_at(cleaned.len() - 1);
        if !check.starts_with(Self::check_char(body)) {
            return Err(Error::InvalidSecretKey("checksum mismatch – please check for typos".into()));
        }
        Ok(Self { chars: cleaned })
    }

    /// `2S-ABCDEF-GHJKL-MNPQR-STUVW-XYZ234` (keys from 2Secret 1.0 have five
    /// characters in the last group).
    pub fn formatted(&self) -> String {
        let c = &self.chars;
        format!("{SK_PREFIX}-{}-{}-{}-{}-{}", &c[0..6], &c[6..11], &c[11..16], &c[16..21], &c[21..])
    }

    /// Only the first group is shown, e.g. `2S-ABCDEF-•••••-…`.
    pub fn masked(&self) -> String {
        format!("{SK_PREFIX}-{}-•••••-•••••-•••••-•••••", &self.chars[0..6])
    }

    fn material(&self) -> &[u8] {
        self.chars.as_bytes()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({})", self.masked())
    }
}

// ---------------------------------------------------------------------------
// Two-Secret Key Derivation
// ---------------------------------------------------------------------------

/// Keys derived from the master password and Secret Key.
#[derive(Clone)]
pub struct DerivedKeys {
    /// Master Unlock Key: decrypts the account keyset. Never leaves the client.
    pub master_key: SymmetricKey,
    /// Authentication key: proves knowledge of the secrets to the sync server.
    /// Derived independently, so it reveals nothing about the master key.
    pub auth_key: SymmetricKey,
}

impl fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DerivedKeys(<redacted>)")
    }
}

/// Normalise a master password (Unicode NFKD) so that the same password typed
/// on different platforms always produces the same key.
pub fn normalize_password(password: &str) -> Zeroizing<String> {
    Zeroizing::new(password.nfkd().collect())
}

/// Derive the Master Unlock Key and authentication key (2SKD).
///
/// ```text
/// salt'   = HKDF(salt, email, "2secret/v1/argon2-salt")
/// k_pw    = Argon2id(NFKD(password), salt')
/// k_sk    = HKDF(secret_key, email, "2secret/v1/secret-key")
/// k       = k_pw XOR k_sk
/// MUK     = HKDF(k, "2secret/v1/master-unlock-key")
/// AUTH    = HKDF(k, "2secret/v1/auth-key")
/// ```
pub fn derive_keys(
    password: &str,
    secret_key: &SecretKey,
    email: &str,
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<DerivedKeys> {
    if salt.len() < 16 {
        return Err(Error::Kdf("salt too short".into()));
    }
    let email = normalize_email(email);
    let password = normalize_password(password);
    let argon_salt = hkdf32(salt, Some(email.as_bytes()), b"2secret/v1/argon2-salt");
    let k_pw = kdf.hash(password.as_bytes(), argon_salt.as_bytes())?;
    let k_sk = hkdf32(secret_key.material(), Some(email.as_bytes()), b"2secret/v1/secret-key");
    let mut combined = [0u8; KEY_LEN];
    for (i, b) in combined.iter_mut().enumerate() {
        *b = k_pw.as_bytes()[i] ^ k_sk.as_bytes()[i];
    }
    let keys = DerivedKeys {
        master_key: hkdf32(&combined, None, b"2secret/v1/master-unlock-key"),
        auth_key: hkdf32(&combined, None, b"2secret/v1/auth-key"),
    };
    combined.zeroize();
    Ok(keys)
}

// ---------------------------------------------------------------------------
// Asymmetric keys
// ---------------------------------------------------------------------------

/// An X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn to_b64(&self) -> String {
        b64(&self.0)
    }

    pub fn from_b64(s: &str) -> Result<Self> {
        let bytes = unb64(s)?;
        let arr: [u8; 32] =
            bytes.as_slice().try_into().map_err(|_| Error::invalid("public key has the wrong length"))?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Short human-verifiable fingerprint, e.g. `3F9A-77C1-0B2E-91D4`.
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&sha256(&self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.fingerprint())
    }
}

/// An X25519 private key (wiped on drop by `x25519-dalek`).
#[derive(Clone)]
pub struct PrivateKey(x25519_dalek::StaticSecret);

impl PrivateKey {
    pub fn generate() -> Self {
        Self(x25519_dalek::StaticSecret::random_from_rng(OsRng))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(bytes))
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&self.0).to_bytes())
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

/// Anonymous public-key encryption (comparable to libsodium sealed boxes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBox {
    /// Ephemeral public key (base64).
    pub epk: String,
    pub ct: EncString,
}

fn sealed_box_key(shared: &[u8; 32], epk: &PublicKey, rpk: &PublicKey) -> SymmetricKey {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(epk.as_bytes());
    salt[32..].copy_from_slice(rpk.as_bytes());
    hkdf32(shared, Some(&salt), b"2secret/v1/sealed-box")
}

/// Encrypt `plaintext` so that only the owner of `recipient` can read it.
pub fn seal(recipient: &PublicKey, plaintext: &[u8], aad: &[u8]) -> SealedBox {
    let eph = PrivateKey::generate();
    let epk = eph.public_key();
    let shared = eph.0.diffie_hellman(&x25519_dalek::PublicKey::from(recipient.0));
    let key = sealed_box_key(shared.as_bytes(), &epk, recipient);
    SealedBox { epk: epk.to_b64(), ct: encrypt(&key, plaintext, aad) }
}

/// Open a [`SealedBox`] with the recipient's private key.
pub fn open(private_key: &PrivateKey, sealed: &SealedBox, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let epk = PublicKey::from_b64(&sealed.epk).map_err(|_| Error::Decryption)?;
    let shared = private_key.0.diffie_hellman(&x25519_dalek::PublicKey::from(epk.0));
    if !shared.was_contributory() {
        return Err(Error::Decryption);
    }
    let key = sealed_box_key(shared.as_bytes(), &epk, &private_key.public_key());
    decrypt(&key, &sealed.ct, aad)
}

// ---------------------------------------------------------------------------
// Post-quantum key encapsulation (ML-KEM-768, FIPS 203)
// ---------------------------------------------------------------------------

/// The post-quantum half of an account's public key: an ML-KEM-768
/// encapsulation key. Vault keys shared with an account that has one are
/// encrypted to both this key and the X25519 key ([`seal_hybrid`]), so an
/// attacker has to break both, including with a future quantum computer.
#[derive(Clone, PartialEq, Eq)]
pub struct PqPublicKey(Vec<u8>);

impl PqPublicKey {
    pub fn from_b64(s: &str) -> Result<Self> {
        let key = Self(unb64(s)?);
        key.encapsulation_key()?;
        Ok(key)
    }

    pub fn to_b64(&self) -> String {
        b64(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn encapsulation_key(&self) -> Result<ml_kem::ml_kem_768::EncapsulationKey> {
        let encoded = ml_kem::Key::<ml_kem::ml_kem_768::EncapsulationKey>::try_from(self.0.as_slice())
            .map_err(|_| Error::invalid("post-quantum public key has the wrong length"))?;
        ml_kem::ml_kem_768::EncapsulationKey::new(&encoded)
            .map_err(|_| Error::invalid("invalid post-quantum public key"))
    }
}

impl fmt::Debug for PqPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PqPublicKey({} bytes)", self.0.len())
    }
}

/// An ML-KEM-768 decapsulation key. It is derived from the account key, so
/// every device of an account arrives at the same key and nothing new has to
/// be stored or kept in sync.
pub struct PqPrivateKey(ml_kem::ml_kem_768::DecapsulationKey);

impl PqPrivateKey {
    pub fn derive(account_key: &SymmetricKey) -> Self {
        let mut seed = Zeroizing::new([0u8; 64]);
        seed[..32].copy_from_slice(account_key.derive("2secret/v1/ml-kem-768/d").as_bytes());
        seed[32..].copy_from_slice(account_key.derive("2secret/v1/ml-kem-768/z").as_bytes());
        let seed = ml_kem::Seed::try_from(&seed[..]).expect("seed is 64 bytes");
        Self(ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed))
    }

    pub fn public_key(&self) -> PqPublicKey {
        use ml_kem::KeyExport as _;
        PqPublicKey(self.0.encapsulation_key().to_bytes().to_vec())
    }
}

impl fmt::Debug for PqPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PqPrivateKey(<redacted>)")
    }
}

/// Everything others need to share a vault with an account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountPublicKeys {
    pub x25519: PublicKey,
    /// Absent for accounts that have not used a 2Secret version with
    /// post-quantum sharing yet.
    pub ml_kem: Option<PqPublicKey>,
}

impl AccountPublicKeys {
    pub fn from_b64(x25519: &str, ml_kem: Option<&str>) -> Result<Self> {
        Ok(Self { x25519: PublicKey::from_b64(x25519)?, ml_kem: ml_kem.map(PqPublicKey::from_b64).transpose()? })
    }

    /// Short human-verifiable fingerprint over both keys, e.g.
    /// `3F9A-77C1-0B2E-91D4`.
    pub fn fingerprint(&self) -> String {
        match &self.ml_kem {
            None => self.x25519.fingerprint(),
            Some(pq) => {
                let mut both = self.x25519.as_bytes().to_vec();
                both.extend_from_slice(pq.as_bytes());
                fingerprint_of(&sha256(&both))
            }
        }
    }
}

fn fingerprint_of(digest: &[u8; 32]) -> String {
    digest[..8].chunks(2).map(|c| format!("{:02X}{:02X}", c[0], c[1])).collect::<Vec<_>>().join("-")
}

/// [`SealedBox`] with an additional ML-KEM-768 encapsulation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSealedBox {
    /// Ephemeral X25519 public key (base64).
    pub epk: String,
    /// ML-KEM-768 ciphertext (base64).
    pub kem_ct: String,
    pub ct: EncString,
}

/// Both shared secrets and everything they were derived from go into the key.
fn hybrid_box_key(
    x_shared: &[u8; 32],
    pq_shared: &[u8],
    epk: &PublicKey,
    rpk: &PublicKey,
    rpk_pq: &PqPublicKey,
    kem_ct: &[u8],
) -> SymmetricKey {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(pq_shared);
    ikm.extend_from_slice(x_shared);
    let mut salt = Vec::with_capacity(128);
    salt.extend_from_slice(epk.as_bytes());
    salt.extend_from_slice(rpk.as_bytes());
    salt.extend_from_slice(&sha256(rpk_pq.as_bytes()));
    salt.extend_from_slice(&sha256(kem_ct));
    hkdf32(&ikm, Some(&salt), b"2secret/v1/hybrid-sealed-box")
}

/// Encrypt `plaintext` so that only the owner of both `recipient` keys can
/// read it: X25519 and ML-KEM-768 combined (a "hybrid" KEM, as in Signal's
/// PQXDH and Apple's PQ3).
pub fn seal_hybrid(
    recipient: &PublicKey,
    recipient_pq: &PqPublicKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<HybridSealedBox> {
    let ek = recipient_pq.encapsulation_key()?;
    let m: [u8; 32] = random_bytes();
    let (kem_ct, pq_shared) = ek.encapsulate_deterministic(&ml_kem::B32::from(m));
    let eph = PrivateKey::generate();
    let epk = eph.public_key();
    let x_shared = eph.0.diffie_hellman(&x25519_dalek::PublicKey::from(recipient.0));
    let key =
        hybrid_box_key(x_shared.as_bytes(), pq_shared.as_slice(), &epk, recipient, recipient_pq, kem_ct.as_slice());
    Ok(HybridSealedBox { epk: epk.to_b64(), kem_ct: b64(kem_ct.as_slice()), ct: encrypt(&key, plaintext, aad) })
}

/// Open a [`HybridSealedBox`] with both of the recipient's private keys.
pub fn open_hybrid(
    private_key: &PrivateKey,
    pq_private_key: &PqPrivateKey,
    sealed: &HybridSealedBox,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use ml_kem::Decapsulate as _;
    let epk = PublicKey::from_b64(&sealed.epk).map_err(|_| Error::Decryption)?;
    let kem_ct_bytes = unb64(&sealed.kem_ct).map_err(|_| Error::Decryption)?;
    let kem_ct = ml_kem::ml_kem_768::Ciphertext::try_from(kem_ct_bytes.as_slice()).map_err(|_| Error::Decryption)?;
    let pq_shared = pq_private_key.0.decapsulate(&kem_ct);
    let x_shared = private_key.0.diffie_hellman(&x25519_dalek::PublicKey::from(epk.0));
    if !x_shared.was_contributory() {
        return Err(Error::Decryption);
    }
    let key = hybrid_box_key(
        x_shared.as_bytes(),
        pq_shared.as_slice(),
        &epk,
        &private_key.public_key(),
        &pq_private_key.public_key(),
        &kem_ct_bytes,
    );
    decrypt(&key, &sealed.ct, aad)
}

// ---------------------------------------------------------------------------
// Account keyset
// ---------------------------------------------------------------------------

const AAD_ACCOUNT_KEY: &[u8] = b"2secret/v1/keyset/account-key";
const AAD_PRIVATE_KEY: &[u8] = b"2secret/v1/keyset/private-key";

/// The account keyset as stored on disk and on the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedKeyset {
    pub version: u32,
    /// Account key, encrypted with the Master Unlock Key.
    pub account_key: EncString,
    /// X25519 private key, encrypted with the account key.
    pub private_key: EncString,
    /// X25519 public key (base64), used by others to share vaults with us.
    pub public_key: String,
    /// ML-KEM-768 public key (base64); the private key is derived from the
    /// account key ([`PqPrivateKey::derive`]). Missing in keysets created by
    /// 2Secret 1.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_public_key: Option<String>,
}

/// The decrypted account keyset.
#[derive(Clone)]
pub struct Keyset {
    pub account_key: SymmetricKey,
    pub private_key: PrivateKey,
}

impl fmt::Debug for Keyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keyset(<redacted>)")
    }
}

impl Keyset {
    pub fn generate() -> Self {
        Self { account_key: SymmetricKey::generate(), private_key: PrivateKey::generate() }
    }

    pub fn public_key(&self) -> PublicKey {
        self.private_key.public_key()
    }

    /// The post-quantum private key (derived from the account key).
    pub fn pq_private_key(&self) -> PqPrivateKey {
        PqPrivateKey::derive(&self.account_key)
    }

    /// Both public keys of this account.
    pub fn public_keys(&self) -> AccountPublicKeys {
        AccountPublicKeys { x25519: self.public_key(), ml_kem: Some(self.pq_private_key().public_key()) }
    }

    /// Encrypt the keyset under a Master Unlock Key.
    pub fn encrypt(&self, master_key: &SymmetricKey) -> EncryptedKeyset {
        EncryptedKeyset {
            version: 1,
            account_key: encrypt(master_key, self.account_key.as_bytes(), AAD_ACCOUNT_KEY),
            private_key: encrypt(&self.account_key, &*self.private_key.to_bytes(), AAD_PRIVATE_KEY),
            public_key: self.public_key().to_b64(),
            pq_public_key: Some(self.pq_private_key().public_key().to_b64()),
        }
    }

    /// Reconstruct the keyset from an already decrypted account key (used by
    /// short-lived CLI sessions that cache the account key).
    pub fn from_account_key(enc: &EncryptedKeyset, account_key: SymmetricKey) -> Result<Self> {
        let pk = decrypt(&account_key, &enc.private_key, AAD_PRIVATE_KEY).map_err(|_| Error::WrongPassword)?;
        let arr: [u8; 32] = pk.as_slice().try_into().map_err(|_| Error::invalid("private key has the wrong length"))?;
        let private_key = PrivateKey::from_bytes(arr);
        if private_key.public_key().to_b64() != enc.public_key {
            return Err(Error::invalid("keyset public key does not match its private key"));
        }
        Ok(Self { account_key, private_key })
    }

    /// Decrypt a keyset. A wrong password or Secret Key yields
    /// [`Error::WrongPassword`].
    pub fn decrypt(enc: &EncryptedKeyset, master_key: &SymmetricKey) -> Result<Self> {
        if enc.version != 1 {
            return Err(Error::Unsupported(format!("keyset version {}", enc.version)));
        }
        let ak = decrypt(master_key, &enc.account_key, AAD_ACCOUNT_KEY).map_err(|_| Error::WrongPassword)?;
        let account_key = SymmetricKey::from_slice(&ak)?;
        let pk = decrypt(&account_key, &enc.private_key, AAD_PRIVATE_KEY)?;
        let arr: [u8; 32] = pk.as_slice().try_into().map_err(|_| Error::invalid("private key has the wrong length"))?;
        let private_key = PrivateKey::from_bytes(arr);
        if private_key.public_key().to_b64() != enc.public_key {
            return Err(Error::invalid("keyset public key does not match its private key"));
        }
        Ok(Self { account_key, private_key })
    }
}

// ---------------------------------------------------------------------------
// Wrapped (encrypted) keys
// ---------------------------------------------------------------------------

/// A vault key encrypted for one account member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WrappedKey {
    /// Encrypted with the member's own account key (personal vaults).
    Symmetric { ct: EncString },
    /// Encrypted to the member's X25519 public key (vaults shared by someone
    /// else, before the member had a post-quantum key).
    Sealed { epk: String, ct: EncString },
    /// Encrypted to the member's X25519 and ML-KEM-768 public keys.
    HybridSealed { epk: String, kem_ct: String, ct: EncString },
}

impl WrappedKey {
    pub fn wrap_symmetric(wrapping_key: &SymmetricKey, key: &SymmetricKey, aad: &[u8]) -> Self {
        WrappedKey::Symmetric { ct: encrypt(wrapping_key, key.as_bytes(), aad) }
    }

    pub fn wrap_sealed(recipient: &PublicKey, key: &SymmetricKey, aad: &[u8]) -> Self {
        let sealed = seal(recipient, key.as_bytes(), aad);
        WrappedKey::Sealed { epk: sealed.epk, ct: sealed.ct }
    }

    /// Wrap for another account: hybrid post-quantum when the recipient has
    /// an ML-KEM key, X25519 only otherwise.
    pub fn wrap_for(recipient: &AccountPublicKeys, key: &SymmetricKey, aad: &[u8]) -> Result<Self> {
        Ok(match &recipient.ml_kem {
            Some(pq) => {
                let sealed = seal_hybrid(&recipient.x25519, pq, key.as_bytes(), aad)?;
                WrappedKey::HybridSealed { epk: sealed.epk, kem_ct: sealed.kem_ct, ct: sealed.ct }
            }
            None => Self::wrap_sealed(&recipient.x25519, key, aad),
        })
    }

    pub fn unwrap(&self, keyset: &Keyset, aad: &[u8]) -> Result<SymmetricKey> {
        let raw = match self {
            WrappedKey::Symmetric { ct } => decrypt(&keyset.account_key, ct, aad)?,
            WrappedKey::Sealed { epk, ct } => {
                open(&keyset.private_key, &SealedBox { epk: epk.clone(), ct: ct.clone() }, aad)?
            }
            WrappedKey::HybridSealed { epk, kem_ct, ct } => open_hybrid(
                &keyset.private_key,
                &keyset.pq_private_key(),
                &HybridSealedBox { epk: epk.clone(), kem_ct: kem_ct.clone(), ct: ct.clone() },
                aad,
            )?,
        };
        SymmetricKey::from_slice(&raw)
    }

    /// Encrypted to the member's public key(s) rather than their own account key.
    pub fn is_sealed(&self) -> bool {
        matches!(self, WrappedKey::Sealed { .. } | WrappedKey::HybridSealed { .. })
    }
}

// ---------------------------------------------------------------------------
// Password-protected envelopes (encrypted exports / backups)
// ---------------------------------------------------------------------------

const ENVELOPE_FORMAT: &str = "2secret-encrypted";

/// Data encrypted with a password only (used for encrypted exports).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordEnvelope {
    pub format: String,
    pub version: u32,
    pub kdf: KdfParams,
    pub salt: String,
    pub data: EncString,
}

impl PasswordEnvelope {
    pub fn seal(password: &str, plaintext: &[u8], kdf: KdfParams) -> Result<Self> {
        if password.is_empty() {
            return Err(Error::invalid("a password is required"));
        }
        let salt: [u8; 16] = random_bytes();
        let key = kdf.hash(normalize_password(password).as_bytes(), &salt)?;
        Ok(Self {
            format: ENVELOPE_FORMAT.into(),
            version: 1,
            data: encrypt(&key, plaintext, ENVELOPE_FORMAT.as_bytes()),
            kdf,
            salt: b64(&salt),
        })
    }

    pub fn open(&self, password: &str) -> Result<Zeroizing<Vec<u8>>> {
        if self.format != ENVELOPE_FORMAT || self.version != 1 {
            return Err(Error::Unsupported("encrypted file format".into()));
        }
        let salt = unb64(&self.salt)?;
        let key = self.kdf.hash(normalize_password(password).as_bytes(), &salt)?;
        decrypt(&key, &self.data, ENVELOPE_FORMAT.as_bytes()).map_err(|_| Error::WrongPassword)
    }

    pub fn is_envelope(data: &str) -> bool {
        data.contains(ENVELOPE_FORMAT) && data.trim_start().starts_with('{')
    }
}

/// Constant time equality for secrets.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_sealed_box_roundtrip_and_tampering() {
        let alice = Keyset::generate();
        let bob = Keyset::generate();
        let keys = alice.public_keys();
        let pq = keys.ml_kem.clone().unwrap();
        // ML-KEM-768 sizes from FIPS 203.
        assert_eq!(pq.as_bytes().len(), 1184);
        let sealed = seal_hybrid(&keys.x25519, &pq, b"vault key", b"aad").unwrap();
        assert_eq!(unb64(&sealed.kem_ct).unwrap().len(), 1088);
        let pqk = alice.pq_private_key();
        assert_eq!(&*open_hybrid(&alice.private_key, &pqk, &sealed, b"aad").unwrap(), b"vault key");
        // Wrong recipient, wrong AAD, tampered parts.
        assert!(open_hybrid(&bob.private_key, &bob.pq_private_key(), &sealed, b"aad").is_err());
        assert!(open_hybrid(&alice.private_key, &pqk, &sealed, b"other").is_err());
        let mut bad_kem = unb64(&sealed.kem_ct).unwrap();
        bad_kem[0] ^= 1;
        let tampered = HybridSealedBox { kem_ct: b64(&bad_kem), ..sealed.clone() };
        assert!(open_hybrid(&alice.private_key, &pqk, &tampered, b"aad").is_err());
        let other_eph = HybridSealedBox { epk: PrivateKey::generate().public_key().to_b64(), ..sealed.clone() };
        assert!(open_hybrid(&alice.private_key, &pqk, &other_eph, b"aad").is_err());
        // Only the X25519 half is not enough: the ML-KEM secret is required.
        let x_only = HybridSealedBox { kem_ct: b64(&[0u8; 1088]), ..sealed };
        assert!(open_hybrid(&alice.private_key, &pqk, &x_only, b"aad").is_err());
    }

    #[test]
    fn pq_key_is_derived_from_the_account_key() {
        let ks = Keyset::generate();
        assert_eq!(ks.pq_private_key().public_key(), ks.pq_private_key().public_key());
        assert_ne!(ks.pq_private_key().public_key(), Keyset::generate().pq_private_key().public_key());
        let enc = ks.encrypt(&SymmetricKey::generate());
        assert_eq!(enc.pq_public_key, Some(ks.pq_private_key().public_key().to_b64()));
        assert!(PqPublicKey::from_b64(&b64(&[1u8; 100])).is_err());
    }

    #[test]
    fn wrap_for_uses_post_quantum_when_available() {
        let recipient = Keyset::generate();
        let vault_key = SymmetricKey::generate();
        let hybrid = WrappedKey::wrap_for(&recipient.public_keys(), &vault_key, b"v").unwrap();
        assert!(matches!(hybrid, WrappedKey::HybridSealed { .. }) && hybrid.is_sealed());
        assert_eq!(hybrid.unwrap(&recipient, b"v").unwrap().as_bytes(), vault_key.as_bytes());
        let classic_only = AccountPublicKeys { x25519: recipient.public_key(), ml_kem: None };
        let classic = WrappedKey::wrap_for(&classic_only, &vault_key, b"v").unwrap();
        assert!(matches!(classic, WrappedKey::Sealed { .. }));
        assert_eq!(classic.unwrap(&recipient, b"v").unwrap().as_bytes(), vault_key.as_bytes());
        // The fingerprint covers both keys once the account has an ML-KEM key.
        assert_ne!(recipient.public_keys().fingerprint(), classic_only.fingerprint());
        assert_eq!(classic_only.fingerprint(), recipient.public_key().fingerprint());
    }

    #[test]
    fn json_is_padded_to_size_classes() {
        let key = SymmetricKey::generate();
        let short = encrypt_json(&key, &"x", b"aad").unwrap();
        let longer = encrypt_json(&key, &"x".repeat(200), b"aad").unwrap();
        assert_eq!(short.as_str().len(), longer.as_str().len());
        let back: String = decrypt_json(&key, &longer, b"aad").unwrap();
        assert_eq!(back, "x".repeat(200));
        assert_eq!([0, 256, 257, 4096, 5000, 70_000].map(padded_len), [256, 256, 512, 4096, 8192, 131_072]);
    }

    #[test]
    fn weak_kdf_parameters_are_detected() {
        assert!(!KdfParams::default().is_weak());
        assert!(KdfParams { memory_kib: 8 * 1024, ..Default::default() }.is_weak());
        assert!(KdfParams { iterations: 1, ..Default::default() }.is_weak());
    }

    #[test]
    fn encrypt_roundtrip_and_aad_binding() {
        let key = SymmetricKey::generate();
        let enc = encrypt(&key, b"hello world", b"context-a");
        assert!(enc.as_str().starts_with("2s1."));
        assert_eq!(&*decrypt(&key, &enc, b"context-a").unwrap(), b"hello world");
        assert!(matches!(decrypt(&key, &enc, b"context-b"), Err(Error::Decryption)));
        let other = SymmetricKey::generate();
        assert!(decrypt(&other, &enc, b"context-a").is_err());
        // Nonces are random: encrypting twice gives different ciphertexts.
        assert_ne!(enc, encrypt(&key, b"hello world", b"context-a"));
    }

    #[test]
    fn tampering_is_detected() {
        let key = SymmetricKey::generate();
        let enc = encrypt(&key, b"secret", b"");
        let mut raw = unb64url(&enc.as_str()[4..]).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        let tampered = EncString(format!("2s1.{}", b64url(&raw)));
        assert!(decrypt(&key, &tampered, b"").is_err());
    }

    #[test]
    fn secret_key_format_and_parse() {
        let sk = SecretKey::generate();
        let f = sk.formatted();
        assert!(f.starts_with("2S-"));
        assert_eq!(f.len(), 34);
        assert_eq!(SecretKey::parse(&f).unwrap(), sk);
        assert_eq!(SecretKey::parse(&f.to_lowercase().replace('-', " ")).unwrap(), sk);
        assert_eq!(SecretKey::parse(&f[3..]).unwrap(), sk);
        // A single typo is caught by the check character most of the time.
        let mut chars: Vec<char> = f.chars().collect();
        let i = 5;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        let _ = SecretKey::parse(&typo); // may or may not be caught (1/32)
        assert!(SecretKey::parse("2S-0000").is_err());
        assert!(SecretKey::parse(&f.replace(&f[4..5], "0")).is_err());
        // Two bytes, and 'Ł' as a byte is 'A': refused, not a crash.
        assert!(SecretKey::parse(&format!("{}Ł", &f[..f.len() - 2])).is_err());
    }

    #[test]
    fn legacy_125_bit_secret_keys_still_work() {
        let body: String = (0..SK_LEGACY_RANDOM_CHARS).map(|i| SK_ALPHABET[(i * 7) % 32] as char).collect();
        let legacy = format!("{body}{}", SecretKey::check_char(&body));
        let sk = SecretKey::parse(&legacy).unwrap();
        assert_eq!(sk.formatted().len(), 33);
        assert_eq!(SecretKey::parse(&sk.formatted()).unwrap(), sk);
        assert_eq!(SecretKey::parse(&sk.formatted()[3..]).unwrap(), sk);
        // Same derivation input as in 2Secret 1.0.
        assert_eq!(sk.material(), legacy.as_bytes());
    }

    #[test]
    fn two_secret_key_derivation() {
        let kdf = KdfParams::insecure_for_tests();
        let sk = SecretKey::generate();
        let salt = [7u8; 16];
        let a = derive_keys("correct horse", &sk, "Me@Example.com ", &salt, &kdf).unwrap();
        let b = derive_keys("correct horse", &sk, "me@example.com", &salt, &kdf).unwrap();
        assert_eq!(a.master_key, b.master_key);
        assert_ne!(a.master_key, a.auth_key);
        let c = derive_keys("correct horsf", &sk, "me@example.com", &salt, &kdf).unwrap();
        assert_ne!(a.master_key, c.master_key);
        let d = derive_keys("correct horse", &SecretKey::generate(), "me@example.com", &salt, &kdf).unwrap();
        assert_ne!(a.master_key, d.master_key);
        // NFKD normalisation: precomposed and decomposed é are the same password.
        let e1 = derive_keys("caf\u{e9}", &sk, "x@y.z", &salt, &kdf).unwrap();
        let e2 = derive_keys("cafe\u{301}", &sk, "x@y.z", &salt, &kdf).unwrap();
        assert_eq!(e1.master_key, e2.master_key);
    }

    #[test]
    fn keyset_roundtrip() {
        let mk = SymmetricKey::generate();
        let ks = Keyset::generate();
        let enc = ks.encrypt(&mk);
        let back = Keyset::decrypt(&enc, &mk).unwrap();
        assert_eq!(back.account_key, ks.account_key);
        assert_eq!(back.public_key(), ks.public_key());
        assert!(matches!(Keyset::decrypt(&enc, &SymmetricKey::generate()), Err(Error::WrongPassword)));
    }

    #[test]
    fn sealed_boxes() {
        let alice = Keyset::generate();
        let bob = Keyset::generate();
        let vk = SymmetricKey::generate();
        let wrapped = WrappedKey::wrap_sealed(&bob.public_key(), &vk, b"vault-1");
        assert_eq!(wrapped.unwrap(&bob, b"vault-1").unwrap(), vk);
        assert!(wrapped.unwrap(&alice, b"vault-1").is_err());
        assert!(wrapped.unwrap(&bob, b"vault-2").is_err());
        let sym = WrappedKey::wrap_symmetric(&alice.account_key, &vk, b"vault-1");
        assert_eq!(sym.unwrap(&alice, b"vault-1").unwrap(), vk);
        let json = serde_json::to_string(&wrapped).unwrap();
        assert!(json.contains("\"type\":\"sealed\""));
        assert_eq!(serde_json::from_str::<WrappedKey>(&json).unwrap(), wrapped);
    }

    #[test]
    fn password_envelope() {
        let env = PasswordEnvelope::seal("hunter2", b"payload", KdfParams::insecure_for_tests()).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        assert!(PasswordEnvelope::is_envelope(&json));
        let env: PasswordEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(&*env.open("hunter2").unwrap(), b"payload");
        assert!(matches!(env.open("hunter3"), Err(Error::WrongPassword)));
    }

    #[test]
    fn kdf_validation() {
        assert!(KdfParams::default().validate().is_ok());
        let bad = KdfParams { memory_kib: u32::MAX, ..Default::default() };
        assert!(bad.validate().is_err());
        let bad = KdfParams { algorithm: "pbkdf2".into(), ..Default::default() };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn fingerprints() {
        let pk = Keyset::generate().public_key();
        let fp = pk.fingerprint();
        assert_eq!(fp.len(), 19);
        assert_eq!(PublicKey::from_b64(&pk.to_b64()).unwrap(), pk);
    }
}
