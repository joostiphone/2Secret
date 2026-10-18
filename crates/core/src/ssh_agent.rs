//! The SSH agent protocol (draft-miller-ssh-agent) for the SSH agent of the
//! desktop apps: the keys of SSH Key items log in to servers and sign Git
//! commits, after the user allows it, and their private keys never leave
//! 2Secret.
//!
//! The agent lists keys and signs with them. Adding or removing keys, locking
//! the agent and extensions are refused: the vault holds the keys.

use std::io::{Read, Write};

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::SignatureEncoding;
use signature::Signer;
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, Signature};

use crate::item::{Category, Item};
use crate::{Error, Result};

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
/// Sign flags for RSA keys.
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;

/// Largest message accepted, as in OpenSSH.
pub const MAX_MESSAGE: usize = 256 * 1024;

/// What a client asks.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// The public keys.
    Identities,
    /// A signature with the key whose public key blob is `key`.
    Sign { key: Vec<u8>, data: Vec<u8>, flags: u32 },
    /// Anything else, which is refused.
    Unsupported,
}

/// A key as the agent offers it: an SSH Key item's public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentKey {
    pub item_id: String,
    pub title: String,
    /// The public key in the SSH wire format.
    pub blob: Vec<u8>,
    pub fingerprint: String,
}

/// Read one message (its length first). `None` at the end of the stream.
pub fn read_message(stream: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad SSH agent message length"));
    }
    let mut message = vec![0u8; length];
    stream.read_exact(&mut message)?;
    Ok(Some(message))
}

pub fn write_message(stream: &mut impl Write, message: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(message.len() as u32).to_be_bytes())?;
    stream.write_all(message)?;
    stream.flush()
}

/// A length-prefixed string of the SSH wire format.
fn take_string<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = u32::from_be_bytes(input.get(..4)?.try_into().ok()?) as usize;
    let value = input.get(4..4 + length)?;
    *input = &input[4 + length..];
    Some(value)
}

fn put_string(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

pub fn parse(message: &[u8]) -> Request {
    match message.first() {
        Some(&REQUEST_IDENTITIES) => Request::Identities,
        Some(&SIGN_REQUEST) => {
            let mut rest = &message[1..];
            let parsed = (|| {
                let key = take_string(&mut rest)?.to_vec();
                let data = take_string(&mut rest)?.to_vec();
                let flags = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?);
                Some(Request::Sign { key, data, flags })
            })();
            parsed.unwrap_or(Request::Unsupported)
        }
        _ => Request::Unsupported,
    }
}

pub fn failure() -> Vec<u8> {
    vec![FAILURE]
}

pub fn identities_answer(keys: &[AgentKey]) -> Vec<u8> {
    let mut answer = vec![IDENTITIES_ANSWER];
    answer.extend_from_slice(&(keys.len() as u32).to_be_bytes());
    for key in keys {
        put_string(&mut answer, &key.blob);
        put_string(&mut answer, key.title.as_bytes());
    }
    answer
}

/// `signature`: an encoded signature from [`sign`].
pub fn sign_response(signature: &[u8]) -> Vec<u8> {
    let mut answer = vec![SIGN_RESPONSE];
    put_string(&mut answer, signature);
    answer
}

/// Read a private key: OpenSSH format (any algorithm, also passphrase
/// protected), or an RSA key in PKCS#1 or PKCS#8 PEM.
fn parse_private_key(text: &str) -> Result<PrivateKey> {
    let text = text.trim();
    let invalid = |e: &dyn std::fmt::Display| Error::invalid(format!("SSH key: {e}"));
    if text.contains("BEGIN OPENSSH PRIVATE KEY") {
        return PrivateKey::from_openssh(text).map_err(|e| invalid(&e));
    }
    let rsa = if text.contains("BEGIN RSA PRIVATE KEY") {
        rsa::RsaPrivateKey::from_pkcs1_pem(text).map_err(|e| invalid(&e))?
    } else if text.contains("BEGIN PRIVATE KEY") {
        rsa::RsaPrivateKey::from_pkcs8_pem(text).map_err(|e| invalid(&e))?
    } else {
        return Err(Error::invalid("SSH key: unknown format"));
    };
    let keypair = RsaKeypair::try_from(rsa).map_err(|e| invalid(&e))?;
    PrivateKey::new(KeypairData::from(keypair), "").map_err(|e| invalid(&e))
}

/// The public key of an SSH Key item: from its private key (readable without
/// the passphrase), else from its public key field.
fn public_key(item: &Item) -> Option<PublicKey> {
    if let Some(key) = item.value("private_key").and_then(|k| parse_private_key(k).ok()) {
        return Some(key.public_key().clone());
    }
    item.value("public_key").and_then(|k| PublicKey::from_openssh(k.trim()).ok())
}

/// The keys the agent offers: SSH Key items (not in the trash) with a
/// private key.
pub fn keys<'a>(items: impl IntoIterator<Item = &'a Item>) -> Vec<AgentKey> {
    let mut keys: Vec<AgentKey> = items
        .into_iter()
        .filter(|i| i.category == Category::SshKey && !i.is_trashed() && i.value("private_key").is_some())
        .filter_map(|item| {
            let public = public_key(item)?;
            Some(AgentKey {
                item_id: item.id.clone(),
                title: item.title.clone(),
                blob: public.to_bytes().ok()?,
                fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
            })
        })
        .collect();
    keys.sort_by_key(|k| k.title.to_lowercase());
    keys
}

/// The RSA key for signing. `ssh-key` 0.6 builds it from the wrong primes
/// (`p` twice), so its own RSA signatures fail.
fn rsa_private_key(keypair: &RsaKeypair) -> Result<rsa::RsaPrivateKey> {
    let number = |m: &ssh_key::Mpint| rsa::BigUint::try_from(m).map_err(|e| Error::invalid(format!("SSH key: {e}")));
    rsa::RsaPrivateKey::from_components(
        number(&keypair.public.n)?,
        number(&keypair.public.e)?,
        number(&keypair.private.d)?,
        vec![number(&keypair.private.p)?, number(&keypair.private.q)?],
    )
    .map_err(|e| Error::invalid(format!("SSH key: {e}")))
}

/// Sign `data` with an SSH Key item's private key. Returns the signature in
/// the SSH wire format (algorithm and signature blob).
pub fn sign(item: &Item, data: &[u8], flags: u32) -> Result<Vec<u8>> {
    let mut key = parse_private_key(item.value("private_key").ok_or_else(|| Error::invalid("no private key"))?)?;
    if key.is_encrypted() {
        key = key
            .decrypt(item.value("passphrase").unwrap_or_default())
            .map_err(|_| Error::invalid("the passphrase of this SSH key is wrong"))?;
    }
    let failed = |e: &dyn std::fmt::Display| Error::invalid(format!("signing failed: {e}"));
    let signature = match key.key_data() {
        // SHA-2 as the client asks; SHA-1 RSA signatures are obsolete.
        KeypairData::Rsa(keypair) => {
            let private = rsa_private_key(keypair)?;
            let (hash, bytes) = if flags & RSA_SHA2_512 != 0 {
                (HashAlg::Sha512, rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private).sign(data).to_vec())
            } else if flags & RSA_SHA2_256 != 0 {
                (HashAlg::Sha256, rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private).sign(data).to_vec())
            } else {
                return Err(Error::invalid("SHA-1 RSA signatures are not supported"));
            };
            Signature::new(Algorithm::Rsa { hash: Some(hash) }, bytes).map_err(|e| failed(&e))?
        }
        _ => key.try_sign(data).map_err(|e| failed(&e))?,
    };
    Vec::<u8>::try_from(signature).map_err(|e| failed(&e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use signature::Verifier;
    use ssh_key::LineEnding;

    fn ssh_item(title: &str, private_key: &str, passphrase: &str) -> Item {
        let mut item = Item::new(Category::SshKey, title);
        item.set_value("private_key", private_key);
        item.set_value("passphrase", passphrase);
        item
    }

    /// Sign as a client asks and check the signature with the public key.
    fn signs(item: &Item, flags: u32) -> Signature {
        let key = &keys([item])[0];
        let request = {
            let mut m = vec![SIGN_REQUEST];
            put_string(&mut m, &key.blob);
            put_string(&mut m, b"session data");
            m.extend_from_slice(&flags.to_be_bytes());
            m
        };
        let Request::Sign { key: blob, data, flags } = parse(&request) else { panic!("not a sign request") };
        assert_eq!(blob, key.blob);
        let encoded = sign(item, &data, flags).unwrap();
        let signature = Signature::try_from(encoded.as_slice()).unwrap();
        let public = PublicKey::from_bytes(&key.blob).unwrap();
        public.key_data().verify(b"session data", &signature).unwrap();
        signature
    }

    #[test]
    fn ed25519_and_ecdsa_keys() {
        for algorithm in [Algorithm::Ed25519, Algorithm::Ecdsa { curve: ssh_key::EcdsaCurve::NistP256 }] {
            let key = PrivateKey::random(&mut OsRng, algorithm.clone()).unwrap();
            let item = ssh_item("Server", &key.to_openssh(LineEnding::LF).unwrap(), "");
            assert_eq!(signs(&item, 0).algorithm(), algorithm);
        }
    }

    #[test]
    fn passphrase_protected_key() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let locked = key.encrypt(&mut OsRng, "open sesame").unwrap().to_openssh(LineEnding::LF).unwrap();
        // Offered without the passphrase, signing needs it.
        let item = ssh_item("Locked", &locked, "open sesame");
        signs(&item, 0);
        let wrong = ssh_item("Locked", &locked, "wrong");
        assert_eq!(keys([&wrong]).len(), 1);
        assert!(sign(&wrong, b"x", 0).is_err());
    }

    #[test]
    fn rsa_keys_sign_with_sha2() {
        let rsa = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pem = rsa.to_pkcs1_pem(LineEnding::LF).unwrap();
        let openssh = PrivateKey::new(KeypairData::from(RsaKeypair::try_from(rsa).unwrap()), "rsa")
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap();
        for text in [pem.as_str(), openssh.as_str()] {
            let item = ssh_item("RSA", text, "");
            assert_eq!(signs(&item, RSA_SHA2_256).algorithm(), Algorithm::Rsa { hash: Some(HashAlg::Sha256) });
            assert_eq!(signs(&item, RSA_SHA2_512).algorithm(), Algorithm::Rsa { hash: Some(HashAlg::Sha512) });
            assert!(sign(&item, b"x", 0).is_err());
        }
    }

    #[test]
    fn lists_ssh_key_items_only() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ssh = ssh_item("b server", &key.to_openssh(LineEnding::LF).unwrap(), "");
        let mut trashed = ssh.clone();
        trashed.trashed_at = Some(1);
        let login = Item::login("A", "me", "pw", None);
        let broken = ssh_item("a broken", "not a key", "");
        let listed = keys([&ssh, &trashed, &login, &broken]);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].title, "b server");
        assert!(listed[0].fingerprint.starts_with("SHA256:"));

        let answer = identities_answer(&listed);
        assert_eq!(answer[0], IDENTITIES_ANSWER);
        assert_eq!(&answer[1..5], &1u32.to_be_bytes());
        assert_eq!(parse(&[REQUEST_IDENTITIES]), Request::Identities);
        assert_eq!(parse(&[17]), Request::Unsupported);
        assert_eq!(parse(&[SIGN_REQUEST, 0, 0]), Request::Unsupported);
    }

    #[test]
    fn messages_are_framed() {
        let mut wire = Vec::new();
        write_message(&mut wire, &[REQUEST_IDENTITIES]).unwrap();
        assert_eq!(wire, [0, 0, 0, 1, REQUEST_IDENTITIES]);
        let mut reader = wire.as_slice();
        assert_eq!(read_message(&mut reader).unwrap(), Some(vec![REQUEST_IDENTITIES]));
        assert_eq!(read_message(&mut reader).unwrap(), None);
        let mut huge = &(MAX_MESSAGE as u32 + 1).to_be_bytes()[..];
        assert!(read_message(&mut huge).is_err());
    }
}
