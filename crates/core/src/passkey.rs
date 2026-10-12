//! Passkeys (WebAuthn credentials) kept in the vault, and the authenticator
//! side of WebAuthn: creating a passkey and signing in with one.
//!
//! 2Secret acts as a software authenticator for *synced* passkeys, like the
//! passkey providers of other password managers: ES256 keys (ECDSA P-256 with
//! SHA-256), "none" attestation, the backup-eligible and backed-up flags set,
//! and a signature counter that stays 0. The private key is part of the
//! encrypted item, so it is end-to-end encrypted and syncs with the vault.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::util::{b64url, now, random_bytes, unb64url};
use crate::{Error, Result};

/// COSE algorithm identifier of ES256.
pub const ES256: i64 = -7;

/// Identifies 2Secret as the authenticator ("AAGUID") in new passkeys.
pub const AAGUID: [u8; 16] =
    [0x2f, 0x5e, 0xc7, 0x1a, 0x93, 0x4b, 0x4e, 0x0d, 0xa6, 0x18, 0x5c, 0x2e, 0x7b, 0x90, 0xd4, 0x31];

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_BACKED_UP: u8 = 0x10;
const FLAG_ATTESTED_DATA: u8 = 0x40;

fn es256() -> i64 {
    ES256
}

/// A passkey stored in an item. Binary values are base64url (no padding).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Passkey {
    pub credential_id: String,
    /// The website ("relying party") the passkey belongs to, e.g. `github.com`.
    pub rp_id: String,
    #[serde(default)]
    pub rp_name: String,
    pub user_handle: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub user_display_name: String,
    /// PKCS #8 private key.
    pub private_key: String,
    #[serde(default = "es256")]
    pub algorithm: i64,
    #[serde(default)]
    pub counter: u32,
    pub created_at: i64,
}

impl std::fmt::Debug for Passkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passkey")
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("credential_id", &self.credential_id)
            .finish_non_exhaustive()
    }
}

/// What a page passed to `navigator.credentials.create()`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreationOptions {
    /// `rp.id`; defaults to the page's host.
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub rp_name: String,
    pub user_handle: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub user_display_name: String,
    pub challenge: String,
    /// `pubKeyCredParams[].alg`, in order of preference.
    #[serde(default)]
    pub algorithms: Vec<i64>,
    /// `excludeCredentials[].id`: passkeys the account already has.
    #[serde(default)]
    pub exclude_credentials: Vec<String>,
}

/// What a page passed to `navigator.credentials.get()`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestOptions {
    #[serde(default)]
    pub rp_id: Option<String>,
    pub challenge: String,
    /// `allowCredentials[].id`; empty means "any passkey for this site".
    #[serde(default)]
    pub allow_credentials: Vec<String>,
}

/// A new passkey's public part, as `navigator.credentials.create()` returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub credential_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
    pub authenticator_data: String,
    /// SubjectPublicKeyInfo (`response.getPublicKey()`).
    pub public_key: String,
    pub algorithm: i64,
}

/// A signed sign-in, as `navigator.credentials.get()` returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assertion {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
}

fn decode(value: &str) -> Result<Vec<u8>> {
    unb64url(value.trim().trim_end_matches('='))
}

/// The relying party ID a page on `origin` may use: its own host, or a
/// parent domain of it that is not a public suffix (`co.uk`, `github.io`).
/// Only `https` origins qualify, and `http://localhost` for development.
pub fn rp_id_for(origin: &str, requested: Option<&str>) -> Result<String> {
    let invalid = || Error::invalid(format!("passkeys are not allowed for {origin}"));
    let url = url::Url::parse(origin).map_err(|_| invalid())?;
    let host = url.host_str().ok_or_else(invalid)?.trim_end_matches('.').to_lowercase();
    let localhost = host == "localhost" || host.ends_with(".localhost");
    match url.scheme() {
        "https" => {}
        "http" if localhost => {}
        _ => return Err(invalid()),
    }
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return Err(invalid());
    }
    let rp = match requested.map(|r| r.trim().trim_end_matches('.').to_lowercase()) {
        None => host.clone(),
        Some(r) if r.is_empty() => host.clone(),
        Some(r) => r,
    };
    let same_or_parent = rp == host || host.ends_with(&format!(".{rp}"));
    let registrable = localhost || psl::domain_str(&rp).is_some();
    if !same_or_parent || !registrable {
        return Err(Error::invalid(format!("{origin} may not use passkeys for {rp}")));
    }
    Ok(rp)
}

#[derive(Serialize)]
struct ClientData<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    challenge: String,
    origin: &'a str,
    #[serde(rename = "crossOrigin")]
    cross_origin: bool,
}

fn client_data_json(kind: &str, challenge: &str, origin: &str) -> Result<Vec<u8>> {
    let challenge = decode(challenge)?;
    if challenge.len() < 16 {
        return Err(Error::invalid("the challenge is too short"));
    }
    let origin = origin.trim_end_matches('/');
    Ok(serde_json::to_vec(&ClientData { kind, challenge: b64url(&challenge), origin, cross_origin: false })?)
}

/// Create a passkey for a page on `origin`.
pub fn create(origin: &str, options: &CreationOptions) -> Result<(Passkey, Registration)> {
    let rp_id = rp_id_for(origin, options.rp_id.as_deref())?;
    if !options.algorithms.is_empty() && !options.algorithms.contains(&ES256) {
        return Err(Error::Unsupported("this website does not accept ES256 passkeys".into()));
    }
    let user_handle = decode(&options.user_handle)?;
    if user_handle.is_empty() || user_handle.len() > 64 {
        return Err(Error::invalid("invalid user handle"));
    }
    let client_data = client_data_json("webauthn.create", &options.challenge, origin)?;

    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
    let verifying_key = *signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let (x, y) = (point.x().ok_or(Error::Decryption)?, point.y().ok_or(Error::Decryption)?);
    let credential_id: [u8; 16] = random_bytes();

    let mut cose_key = Vec::with_capacity(77);
    cbor::map(&mut cose_key, 5);
    cbor::int(&mut cose_key, 1);
    cbor::int(&mut cose_key, 2); // kty: EC2
    cbor::int(&mut cose_key, 3);
    cbor::int(&mut cose_key, ES256); // alg
    cbor::int(&mut cose_key, -1);
    cbor::int(&mut cose_key, 1); // crv: P-256
    cbor::int(&mut cose_key, -2);
    cbor::bytes(&mut cose_key, x);
    cbor::int(&mut cose_key, -3);
    cbor::bytes(&mut cose_key, y);

    let flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_BACKUP_ELIGIBLE | FLAG_BACKED_UP | FLAG_ATTESTED_DATA;
    let mut auth_data = authenticator_data(&rp_id, flags, 0);
    auth_data.extend_from_slice(&AAGUID);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(&credential_id);
    auth_data.extend_from_slice(&cose_key);

    let mut attestation = Vec::with_capacity(auth_data.len() + 32);
    cbor::map(&mut attestation, 3);
    cbor::text(&mut attestation, "fmt");
    cbor::text(&mut attestation, "none");
    cbor::text(&mut attestation, "attStmt");
    cbor::map(&mut attestation, 0);
    cbor::text(&mut attestation, "authData");
    cbor::bytes(&mut attestation, &auth_data);

    let private_key = signing_key.to_pkcs8_der().map_err(|_| Error::invalid("could not encode the passkey"))?;
    let public_key = verifying_key.to_public_key_der().map_err(|_| Error::invalid("could not encode the passkey"))?;
    let passkey = Passkey {
        credential_id: b64url(&credential_id),
        rp_id,
        rp_name: options.rp_name.trim().to_string(),
        user_handle: b64url(&user_handle),
        user_name: options.user_name.trim().to_string(),
        user_display_name: options.user_display_name.trim().to_string(),
        private_key: b64url(private_key.as_bytes()),
        algorithm: ES256,
        counter: 0,
        created_at: now(),
    };
    let registration = Registration {
        credential_id: passkey.credential_id.clone(),
        client_data_json: b64url(&client_data),
        attestation_object: b64url(&attestation),
        authenticator_data: b64url(&auth_data),
        public_key: b64url(public_key.as_bytes()),
        algorithm: ES256,
    };
    Ok((passkey, registration))
}

/// Sign in to a page on `origin` with `passkey`.
pub fn assert(passkey: &Passkey, origin: &str, options: &RequestOptions) -> Result<Assertion> {
    let rp_id = rp_id_for(origin, options.rp_id.as_deref())?;
    if rp_id != passkey.rp_id {
        return Err(Error::invalid(format!("this passkey is for {}, not {rp_id}", passkey.rp_id)));
    }
    if !options.allow_credentials.is_empty()
        && !options.allow_credentials.iter().any(|c| c.trim_end_matches('=') == passkey.credential_id)
    {
        return Err(Error::invalid("the website did not ask for this passkey"));
    }
    let client_data = client_data_json("webauthn.get", &options.challenge, origin)?;
    let flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_BACKUP_ELIGIBLE | FLAG_BACKED_UP;
    let auth_data = authenticator_data(&rp_id, flags, passkey.counter);

    let der = Zeroizing::new(decode(&passkey.private_key)?);
    let signing_key = SigningKey::from_pkcs8_der(&der).map_err(|_| Error::invalid("damaged passkey"))?;
    let mut message = auth_data.clone();
    message.extend_from_slice(&Sha256::digest(&client_data));
    let signature: Signature = signing_key.sign(&message);

    Ok(Assertion {
        credential_id: passkey.credential_id.clone(),
        client_data_json: b64url(&client_data),
        authenticator_data: b64url(&auth_data),
        signature: b64url(signature.to_der().as_bytes()),
        user_handle: passkey.user_handle.clone(),
    })
}

/// A passkey from a Bitwarden JSON export (`login.fido2Credentials[]`).
/// `None` for anything but ES256 keys.
pub fn from_bitwarden(v: &serde_json::Value) -> Option<Passkey> {
    let text = |key: &str| v.get(key).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if !text("keyAlgorithm").eq_ignore_ascii_case("ECDSA") || !text("keyCurve").eq_ignore_ascii_case("P-256") {
        return None;
    }
    // Credential ids are stored as a GUID, or as "b64." + base64url.
    let id = text("credentialId");
    let credential_id = match id.strip_prefix("b64.") {
        Some(b64) => decode(b64).ok()?,
        None => uuid::Uuid::parse_str(&id).ok()?.as_bytes().to_vec(),
    };
    let key = text("keyValue");
    let der = Zeroizing::new(decode(&key).or_else(|_| crate::util::unb64(&key)).ok()?);
    SigningKey::from_pkcs8_der(&der).ok()?;
    let user_handle = decode(&text("userHandle")).ok()?;
    let rp_id = text("rpId").to_lowercase();
    if rp_id.is_empty() || user_handle.is_empty() {
        return None;
    }
    Some(Passkey {
        credential_id: b64url(&credential_id),
        rp_id,
        rp_name: text("rpName"),
        user_handle: b64url(&user_handle),
        user_name: text("userName"),
        user_display_name: text("userDisplayName"),
        private_key: b64url(&der),
        algorithm: ES256,
        counter: text("counter").parse().unwrap_or(0),
        created_at: crate::util::parse_date(&text("creationDate")).unwrap_or_else(now),
    })
}

fn authenticator_data(rp_id: &str, flags: u8, counter: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    data.push(flags);
    data.extend_from_slice(&counter.to_be_bytes());
    data
}

/// The few CBOR (RFC 8949) encodings WebAuthn needs.
mod cbor {
    fn head(out: &mut Vec<u8>, major: u8, len: u64) {
        let m = major << 5;
        match len {
            0..=23 => out.push(m | len as u8),
            24..=0xff => out.extend_from_slice(&[m | 24, len as u8]),
            0x100..=0xffff => {
                out.push(m | 25);
                out.extend_from_slice(&(len as u16).to_be_bytes());
            }
            _ => {
                out.push(m | 26);
                out.extend_from_slice(&(len as u32).to_be_bytes());
            }
        }
    }

    pub fn int(out: &mut Vec<u8>, n: i64) {
        if n >= 0 {
            head(out, 0, n as u64);
        } else {
            head(out, 1, (-1 - n) as u64);
        }
    }

    pub fn bytes(out: &mut Vec<u8>, b: &[u8]) {
        head(out, 2, b.len() as u64);
        out.extend_from_slice(b);
    }

    pub fn text(out: &mut Vec<u8>, s: &str) {
        head(out, 3, s.len() as u64);
        out.extend_from_slice(s.as_bytes());
    }

    pub fn map(out: &mut Vec<u8>, entries: u64) {
        head(out, 5, entries);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;
    use p256::pkcs8::DecodePublicKey;

    const ORIGIN: &str = "https://login.example.com";

    fn creation() -> CreationOptions {
        CreationOptions {
            rp_id: Some("example.com".into()),
            rp_name: "Example".into(),
            user_handle: b64url(b"user-1234"),
            user_name: "alex@example.com".into(),
            user_display_name: "Alex".into(),
            challenge: b64url(&[7u8; 32]),
            algorithms: vec![-8, ES256, -257],
            exclude_credentials: vec![],
        }
    }

    #[test]
    fn registration_has_the_webauthn_layout() {
        let (passkey, reg) = create(ORIGIN, &creation()).unwrap();
        assert_eq!(passkey.rp_id, "example.com");
        assert_eq!(passkey.user_name, "alex@example.com");

        let client: serde_json::Value = serde_json::from_slice(&decode(&reg.client_data_json).unwrap()).unwrap();
        assert_eq!(client["type"], "webauthn.create");
        assert_eq!(client["origin"], ORIGIN);
        assert_eq!(client["challenge"], b64url(&[7u8; 32]));

        let auth = decode(&reg.authenticator_data).unwrap();
        assert_eq!(&auth[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(auth[32], 0x5d, "UP, UV, BE, BS and AT");
        assert_eq!(&auth[33..37], &[0, 0, 0, 0]);
        assert_eq!(&auth[37..53], &AAGUID);
        assert_eq!(u16::from_be_bytes([auth[53], auth[54]]), 16);
        assert_eq!(b64url(&auth[55..71]), passkey.credential_id);
        // COSE key: map(5) {1: 2, 3: -7, -1: 1, -2: x, -3: y}
        assert_eq!(&auth[71..79], &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]);
        assert_eq!(auth.len(), 71 + 77);

        let att = decode(&reg.attestation_object).unwrap();
        assert!(att.starts_with(&[0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']));
        assert!(att.ends_with(&auth));

        // The public key that sites store is the one that verifies sign-ins.
        let public = VerifyingKey::from_public_key_der(&decode(&reg.public_key).unwrap()).unwrap();
        let options = RequestOptions {
            rp_id: Some("example.com".into()),
            challenge: b64url(&[9u8; 32]),
            allow_credentials: vec![],
        };
        let a = assert(&passkey, "https://example.com", &options).unwrap();
        let auth = decode(&a.authenticator_data).unwrap();
        assert_eq!(auth[32], 0x1d, "UP, UV, BE and BS");
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(decode(&a.client_data_json).unwrap()));
        let signature = Signature::from_der(&decode(&a.signature).unwrap()).unwrap();
        public.verify(&message, &signature).unwrap();
        assert_eq!(a.user_handle, b64url(b"user-1234"));
    }

    #[test]
    fn sites_only_get_passkeys_for_their_own_domain() {
        assert_eq!(rp_id_for("https://login.example.com", None).unwrap(), "login.example.com");
        assert_eq!(rp_id_for("https://login.example.com", Some("example.com")).unwrap(), "example.com");
        assert!(rp_id_for("https://login.example.com", Some("other.com")).is_err());
        assert!(rp_id_for("https://evil-example.com", Some("example.com")).is_err());
        assert!(rp_id_for("https://alice.github.io", Some("github.io")).is_err(), "public suffix");
        assert!(rp_id_for("https://example.co.uk", Some("co.uk")).is_err(), "public suffix");
        assert!(rp_id_for("http://example.com", None).is_err(), "no https");
        assert!(rp_id_for("https://192.168.1.10", None).is_err(), "IP address");
        assert_eq!(rp_id_for("http://localhost:8080", None).unwrap(), "localhost");

        let (passkey, _) = create(ORIGIN, &creation()).unwrap();
        let options = RequestOptions { rp_id: None, challenge: b64url(&[1u8; 32]), allow_credentials: vec![] };
        assert!(assert(&passkey, "https://example.org", &options).is_err());
        // The page asked for a different passkey.
        let options = RequestOptions {
            rp_id: Some("example.com".into()),
            challenge: b64url(&[1u8; 32]),
            allow_credentials: vec![b64url(b"another credential")],
        };
        assert!(assert(&passkey, ORIGIN, &options).is_err());
    }

    #[test]
    fn rejects_unsupported_requests() {
        let mut options = creation();
        options.algorithms = vec![-257];
        assert!(create(ORIGIN, &options).is_err(), "RS256 only");
        let mut options = creation();
        options.challenge = b64url(b"short");
        assert!(create(ORIGIN, &options).is_err());
        let mut options = creation();
        options.user_handle = String::new();
        assert!(create(ORIGIN, &options).is_err());
    }
}
