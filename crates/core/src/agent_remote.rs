//! Agents elsewhere: an AI agent on another computer (a cloud agent, a build
//! server, an agent in a browser on a second machine) cannot reach the app's
//! local socket. It talks to the owner's app through the sync server instead,
//! which relays sealed envelopes it cannot read. This module holds the
//! cryptography and the wire formats of that relay; the server, the client
//! crate, the app and `2secret mcp --remote` build on it.
//!
//! The pieces, in the order they are used:
//!
//! 1. **Pairing code** ([`PairingCode`]): the app makes it and shows it;
//!    the person pastes it where the agent runs. It names the server and
//!    holds a random seed from which two values follow: a *token* the agent
//!    shows the server, and a *secret* the server never sees. It also holds
//!    a hash of the account's public keys, so the agent can check the keys
//!    the server gives it.
//! 2. **Agent keys** ([`RemoteKeys`]): X25519 and ML-KEM-768 to receive
//!    sealed envelopes, Ed25519 to sign; all three from one 32-byte root the
//!    agent keeps. [`RemotePublicKeys`] is what the server and the app see;
//!    the agent id is the fingerprint of the Ed25519 key, like a local
//!    agent's.
//! 3. **Proof** ([`seal_proof`], [`open_proof`]): the agent seals the secret
//!    and its public keys to the account. The app that made the code opens
//!    it, compares the secret and the keys, and only then confirms the agent
//!    by storing an encrypted [`AgentRecordData`] on the server, which every
//!    device of the account can open and check against the listed keys.
//! 4. **Requests** ([`seal_request`], [`open_request`]): a method and its
//!    parameters, signed by the agent and sealed to the account, with a
//!    fresh reply key inside. The app verifies the signature against the
//!    pinned key from the record, so not even the server can forge a
//!    request.
//! 5. **Answers** ([`seal_answer`], [`open_answer`]): encrypted with the
//!    reply key from the request, which only the agent and whoever opened
//!    the request know, so the server cannot forge an answer either.
//! 6. **HTTP signature** ([`HttpSignature`]): the server lets an agent post
//!    and fetch only with a signed header over the method, the path, the
//!    body and a fresh time and nonce. It is for routing and limits; the
//!    security of the content rests on the envelopes.
//!
//! The server sees agent ids, public keys, sizes and times. Never a method,
//! an item, a field or a value.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::agent::{agent_id, AgentError};
use crate::crypto::{
    constant_time_eq, decrypt, decrypt_json, encrypt, encrypt_json, fingerprint_of, hkdf32, open_hybrid, seal_hybrid,
    sha256, AccountPublicKeys, EncString, HybridSealedBox, Keyset, PqPrivateKey, PqPublicKey, PrivateKey, PublicKey,
    SymmetricKey, SK_ALPHABET,
};
use crate::util::{b64, b64url, hex, random_bytes, unb64, unb64url};
use crate::{Error, Result};

/// Version of the relay protocol.
pub const REMOTE_PROTOCOL: u32 = 1;
/// How long a pairing code, and the pending agent it makes, is valid.
pub const PAIRING_SECONDS: i64 = 10 * 60;
/// How long a request waits for an answer before it expires.
pub const REQUEST_SECONDS: i64 = 10 * 60;
/// How far an agent's clock may be off for the server to take its signature.
pub const HTTP_SKEW_SECONDS: i64 = 5 * 60;
/// Longest a long-poll (`?wait=`) holds a connection.
pub const MAX_WAIT_SECONDS: u32 = 25;
/// The header that carries an agent's [`HttpSignature`].
pub const HTTP_HEADER: &str = "x-2secret-agent";
/// Largest sealed request or answer the server relays.
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;

const URI_SCHEME: &str = "2secret-agent:";
const URI_VERSION: &str = "v1";
const CODE_PREFIX: &str = "2A";
const CODE_SEED_LEN: usize = 16;
const CODE_HASH_LEN: usize = 16;
const CODE_BYTES: usize = CODE_SEED_LEN + CODE_HASH_LEN;
/// 32 bytes in 5-bit characters, then the check character.
const CODE_CHARS: usize = 53;
const CODE_GROUP: usize = 6;

const INFO_TOKEN: &[u8] = b"2secret/v1/agent-pair/token";
const INFO_SECRET: &[u8] = b"2secret/v1/agent-pair/secret";
const INFO_KEY_HASH: &[u8] = b"2secret/v1/agent-pair/keys";
const INFO_X25519: &[u8] = b"2secret/v1/agent/x25519";
const INFO_ML_KEM: &[u8] = b"2secret/v1/agent/ml-kem";
const INFO_ED25519: &[u8] = b"2secret/v1/agent/ed25519";
const REQUEST_CONTEXT: &[u8] = b"2secret/v1/agent-request";
const HTTP_CONTEXT: &[u8] = b"2secret/v1/agent-http";

fn invalid(message: &str) -> Error {
    Error::invalid(message)
}

// ---------------------------------------------------------------------------
// Pairing code
// ---------------------------------------------------------------------------

/// What the app shows and the agent is given: the server, a seed and a hash
/// of the account's public keys. As text it reads
/// `2A-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXX` (the
/// alphabet of the Secret Key, with a check character); as a URI, also for a
/// QR code, `2secret-agent:v1?server=…&code=…`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PairingCode {
    /// The sync server, without a trailing slash.
    #[zeroize(skip)]
    pub server: String,
    seed: [u8; CODE_SEED_LEN],
    #[zeroize(skip)]
    key_hash: [u8; CODE_HASH_LEN],
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PairingCode({}, <redacted>)", self.server)
    }
}

/// The first 16 bytes of a hash over both public keys of an account; an
/// agent checks the keys the server hands it against this.
pub fn account_key_hash(keys: &AccountPublicKeys) -> Result<[u8; CODE_HASH_LEN]> {
    let pq = keys.ml_kem.as_ref().ok_or_else(|| invalid("the account has no post-quantum key yet"))?;
    let mut data = INFO_KEY_HASH.to_vec();
    data.extend_from_slice(keys.x25519.as_bytes());
    data.extend_from_slice(pq.as_bytes());
    let digest = sha256(&data);
    let mut out = [0u8; CODE_HASH_LEN];
    out.copy_from_slice(&digest[..CODE_HASH_LEN]);
    Ok(out)
}

/// What the database keeps of a pairing token (base64url of its SHA-256).
pub fn pairing_token_hash(token: &str) -> String {
    b64url(&sha256(token.as_bytes()))
}

/// A token as the server expects it: 32 bytes, base64url.
pub fn valid_token(token: &str) -> bool {
    token.len() == 43 && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The sync server as an agent should store it: `https://host[:port]`, no
/// trailing slash. Plain `http` is taken here; the client decides whether
/// to use it (only on the same computer).
pub fn normalize_server(server: &str) -> Result<String> {
    let server = server.trim().trim_end_matches('/');
    let url = url::Url::parse(server).map_err(|_| invalid("the server address is not a URL"))?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        return Err(invalid("the server address has to start with https://"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("the server address has to be a plain address"));
    }
    Ok(server.to_string())
}

impl PairingCode {
    /// A new code for an account on `server`.
    pub fn new(server: &str, keys: &AccountPublicKeys) -> Result<Self> {
        Ok(Self { server: normalize_server(server)?, seed: random_bytes(), key_hash: account_key_hash(keys)? })
    }

    /// The value the agent shows the server (base64url, 32 bytes).
    pub fn token(&self) -> String {
        let mut data = INFO_TOKEN.to_vec();
        data.extend_from_slice(&self.seed);
        b64url(&sha256(&data))
    }

    /// What the server stores for this code (see [`pairing_token_hash`]).
    pub fn token_hash(&self) -> String {
        pairing_token_hash(&self.token())
    }

    /// The value the agent proves to the app and the server never sees.
    pub fn secret(&self) -> Zeroizing<[u8; 32]> {
        let mut data = Zeroizing::new(INFO_SECRET.to_vec());
        data.extend_from_slice(&self.seed);
        Zeroizing::new(sha256(&data))
    }

    /// Are these the account keys the code was made for?
    pub fn matches(&self, keys: &AccountPublicKeys) -> bool {
        account_key_hash(keys).is_ok_and(|h| constant_time_eq(&h, &self.key_hash))
    }

    /// The typable form, `2A-XXXXXX-…-XXXXX`.
    pub fn text(&self) -> String {
        let mut bytes = [0u8; CODE_BYTES];
        bytes[..CODE_SEED_LEN].copy_from_slice(&self.seed);
        bytes[CODE_SEED_LEN..].copy_from_slice(&self.key_hash);
        let mut body = code_encode(&bytes);
        body.push(check_char(&body));
        let groups: Vec<&str> =
            body.as_bytes().chunks(CODE_GROUP).map(|c| std::str::from_utf8(c).expect("ascii")).collect();
        format!("{CODE_PREFIX}-{}", groups.join("-"))
    }

    /// The URI form, for copying and for a QR code.
    pub fn uri(&self) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("server", &self.server).append_pair("code", &self.text());
        format!("{URI_SCHEME}{URI_VERSION}?{}", query.finish())
    }

    /// Parse a code as pasted: the URI, or the typable text with the server
    /// from `default_server`. Case, spaces and dashes in the text are
    /// ignored; the check character catches most typos.
    pub fn parse(input: &str, default_server: Option<&str>) -> Result<Self> {
        let input = input.trim();
        if input.get(..URI_SCHEME.len()).is_some_and(|s| s.eq_ignore_ascii_case(URI_SCHEME)) {
            let rest = input[URI_SCHEME.len()..].trim_start_matches('/');
            let (version, query) = rest.split_once('?').ok_or_else(|| invalid("the pairing code is incomplete"))?;
            if version != URI_VERSION {
                return Err(Error::Unsupported(format!("pairing code version '{version}'")));
            }
            let (mut server, mut code) = (None, None);
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                match &*key {
                    "server" => server = Some(value.into_owned()),
                    "code" => code = Some(value.into_owned()),
                    _ => {}
                }
            }
            let server = server.ok_or_else(|| invalid("the pairing code names no server"))?;
            let code = code.ok_or_else(|| invalid("the pairing code is incomplete"))?;
            return Self::from_parts(&server, &code);
        }
        let server = default_server.ok_or_else(|| invalid("this code names no server; pass the server address"))?;
        Self::from_parts(server, input)
    }

    fn from_parts(server: &str, code: &str) -> Result<Self> {
        let mut cleaned: String =
            code.chars().filter(|c| !c.is_whitespace() && *c != '-').flat_map(|c| c.to_uppercase()).collect();
        if cleaned.len() == CODE_CHARS + CODE_PREFIX.len() && cleaned.starts_with(CODE_PREFIX) {
            cleaned.drain(..CODE_PREFIX.len());
        }
        if cleaned.len() != CODE_CHARS {
            return Err(invalid(&format!("a pairing code has {CODE_CHARS} characters, this one {}", cleaned.len())));
        }
        if let Some(bad) = cleaned.chars().find(|c| !c.is_ascii() || !SK_ALPHABET.contains(&(*c as u8))) {
            return Err(invalid(&format!("character '{bad}' is not allowed in a pairing code")));
        }
        let (body, check) = cleaned.split_at(CODE_CHARS - 1);
        if !check.starts_with(check_char(body)) {
            return Err(invalid("the pairing code has a typo (check character mismatch)"));
        }
        let bytes = code_decode(body, CODE_BYTES).ok_or_else(|| invalid("the pairing code is malformed"))?;
        let mut seed = [0u8; CODE_SEED_LEN];
        let mut key_hash = [0u8; CODE_HASH_LEN];
        seed.copy_from_slice(&bytes[..CODE_SEED_LEN]);
        key_hash.copy_from_slice(&bytes[CODE_SEED_LEN..]);
        Ok(Self { server: normalize_server(server)?, seed, key_hash })
    }
}

fn check_char(body: &str) -> char {
    let digest = sha256(format!("2secret-agent-code-check:{body}").as_bytes());
    SK_ALPHABET[(digest[0] as usize) % 32] as char
}

/// Bytes as 5-bit characters of the Secret Key alphabet (no padding).
fn code_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(SK_ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(SK_ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The inverse of [`code_encode`]; `None` for a wrong length, a character
/// outside the alphabet or padding bits that are not zero.
fn code_decode(chars: &str, len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in chars.bytes() {
        let v = SK_ALPHABET.iter().position(|a| *a == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (out.len() == len && acc == 0).then_some(out)
}

// ---------------------------------------------------------------------------
// Agent keys
// ---------------------------------------------------------------------------

/// The agent's three public keys as they travel (base64).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotePublicKeys {
    pub x25519: String,
    pub ml_kem: String,
    pub ed25519: String,
}

/// [`RemotePublicKeys`] after parsing: valid keys of the right kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedKeys {
    pub x25519: PublicKey,
    pub ml_kem: PqPublicKey,
    pub ed25519: VerifyingKey,
}

impl RemotePublicKeys {
    /// Parse and validate all three keys.
    pub fn verify(&self) -> Result<VerifiedKeys> {
        let ed: [u8; 32] =
            unb64(&self.ed25519)?.try_into().map_err(|_| invalid("the agent's signing key is not an Ed25519 key"))?;
        let ed25519 =
            VerifyingKey::from_bytes(&ed).map_err(|_| invalid("the agent's signing key is not an Ed25519 key"))?;
        Ok(VerifiedKeys {
            x25519: PublicKey::from_b64(&self.x25519)?,
            ml_kem: PqPublicKey::from_b64(&self.ml_kem)?,
            ed25519,
        })
    }

    /// The agent id: the fingerprint of the Ed25519 key.
    pub fn agent_id(&self) -> Result<String> {
        Ok(self.verify()?.agent_id())
    }

    /// A fingerprint over all three keys, shown to the person on both sides.
    pub fn fingerprint(&self) -> Result<String> {
        Ok(self.verify()?.fingerprint())
    }
}

impl VerifiedKeys {
    pub fn agent_id(&self) -> String {
        agent_id(self.ed25519.as_bytes())
    }

    pub fn fingerprint(&self) -> String {
        let mut all = self.x25519.as_bytes().to_vec();
        all.extend_from_slice(self.ml_kem.as_bytes());
        all.extend_from_slice(self.ed25519.as_bytes());
        fingerprint_of(&sha256(&all))
    }

    pub fn to_remote(&self) -> RemotePublicKeys {
        RemotePublicKeys {
            x25519: self.x25519.to_b64(),
            ml_kem: self.ml_kem.to_b64(),
            ed25519: b64(self.ed25519.as_bytes()),
        }
    }
}

/// The agent's private keys, all derived from one root the agent stores.
pub struct RemoteKeys {
    root: Zeroizing<[u8; 32]>,
    x25519: PrivateKey,
    pq: PqPrivateKey,
    signing: SigningKey,
}

impl fmt::Debug for RemoteKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RemoteKeys({})", self.agent_id())
    }
}

impl RemoteKeys {
    pub fn generate() -> Self {
        Self::from_root(random_bytes())
    }

    /// The same root always gives the same keys.
    pub fn from_root(root: [u8; 32]) -> Self {
        let root = Zeroizing::new(root);
        let x25519 = PrivateKey::from_bytes(*hkdf32(&*root, None, INFO_X25519).as_bytes());
        let pq = PqPrivateKey::derive(&hkdf32(&*root, None, INFO_ML_KEM));
        let signing = SigningKey::from_bytes(hkdf32(&*root, None, INFO_ED25519).as_bytes());
        Self { root, x25519, pq, signing }
    }

    /// What the agent stores (and nothing else).
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    pub fn verified(&self) -> VerifiedKeys {
        VerifiedKeys {
            x25519: self.x25519.public_key(),
            ml_kem: self.pq.public_key(),
            ed25519: self.signing.verifying_key(),
        }
    }

    pub fn public(&self) -> RemotePublicKeys {
        self.verified().to_remote()
    }

    pub fn agent_id(&self) -> String {
        agent_id(self.signing.verifying_key().as_bytes())
    }

    pub fn fingerprint(&self) -> String {
        self.verified().fingerprint()
    }

    fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }
}

// ---------------------------------------------------------------------------
// Pairing proof and the agent record
// ---------------------------------------------------------------------------

/// What the agent seals to the account when it pairs: the secret from the
/// code, its keys, and how it wants to be known.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairProof {
    /// The code's secret (base64).
    pub secret: String,
    pub keys: RemotePublicKeys,
    pub name: String,
    #[serde(default)]
    pub version: String,
    /// The computer the agent runs on, as it sees it (a host name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
}

fn pair_aad(token_hash: &str) -> String {
    format!("2secret/v1/agent-pair/{token_hash}")
}

/// Seal the pairing proof to the account the code was made for.
pub fn seal_proof(
    code: &PairingCode,
    account: &AccountPublicKeys,
    keys: &RemoteKeys,
    name: &str,
    version: &str,
    device: Option<&str>,
) -> Result<HybridSealedBox> {
    if !code.matches(account) {
        return Err(Error::PermissionDenied("the server's keys for this account do not match the pairing code".into()));
    }
    let pq = account.ml_kem.as_ref().ok_or_else(|| invalid("the account has no post-quantum key yet"))?;
    let proof = PairProof {
        secret: b64(&*code.secret()),
        keys: keys.public(),
        name: name.to_string(),
        version: version.to_string(),
        device: device.map(str::to_string),
    };
    let plain = Zeroizing::new(serde_json::to_vec(&proof)?);
    seal_hybrid(&account.x25519, pq, &plain, pair_aad(&code.token_hash()).as_bytes())
}

/// Open a proof with the account's keys. [`PairProof::check`] then says
/// whether it belongs to a code this device made.
pub fn open_proof(keyset: &Keyset, token_hash: &str, sealed: &HybridSealedBox) -> Result<PairProof> {
    let plain = open_hybrid(&keyset.private_key, &keyset.pq_private_key(), sealed, pair_aad(token_hash).as_bytes())?;
    Ok(serde_json::from_slice(&plain)?)
}

impl PairProof {
    /// Does the proof hold the code's secret, and are the keys the server
    /// lists for the agent the ones in the proof?
    pub fn check(&self, code: &PairingCode, listed: &RemotePublicKeys) -> Result<()> {
        let secret = Zeroizing::new(unb64(&self.secret).map_err(|_| Error::Decryption)?);
        if !constant_time_eq(&secret, &*code.secret()) {
            return Err(Error::PermissionDenied("the agent does not know this pairing code".into()));
        }
        if &self.keys != listed {
            return Err(Error::PermissionDenied("the server lists other keys for this agent than it proved".into()));
        }
        self.keys.verify()?;
        Ok(())
    }
}

/// What the owner's devices know about a paired agent: stored on the
/// server, encrypted with the account key, so every device can answer its
/// requests and check the keys the server lists against the pinned ones.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRecordData {
    pub name: String,
    #[serde(default)]
    pub version: String,
    pub keys: RemotePublicKeys,
    /// [`VerifiedKeys::fingerprint`], as shown when the agent was confirmed.
    pub fingerprint: String,
    pub paired_at: i64,
    /// The computer the agent runs on, as it said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// The owner's device that confirmed the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_on: Option<String>,
}

impl AgentRecordData {
    pub fn aad(account_id: &str, agent_id: &str) -> String {
        format!("2secret/v1/agent-record/{account_id}/{agent_id}")
    }

    pub fn seal(&self, account_key: &SymmetricKey, account_id: &str, agent_id: &str) -> Result<EncString> {
        encrypt_json(account_key, self, Self::aad(account_id, agent_id).as_bytes())
    }

    /// Open a record and check that the keys the server lists are the ones
    /// pinned in it.
    pub fn open(
        enc: &EncString,
        account_key: &SymmetricKey,
        account_id: &str,
        agent_id: &str,
        listed: &RemotePublicKeys,
    ) -> Result<Self> {
        let record: Self = decrypt_json(account_key, enc, Self::aad(account_id, agent_id).as_bytes())?;
        if &record.keys != listed {
            return Err(Error::PermissionDenied(
                "the server lists other keys for this agent than were confirmed".into(),
            ));
        }
        if record.keys.agent_id()? != agent_id {
            return Err(Error::PermissionDenied("the agent record belongs to another agent".into()));
        }
        Ok(record)
    }
}

// ---------------------------------------------------------------------------
// Requests and answers
// ---------------------------------------------------------------------------

/// A request id: 16 random bytes, base64url (22 characters).
pub fn new_request_id() -> String {
    b64url(&random_bytes::<16>())
}

pub fn valid_request_id(id: &str) -> bool {
    id.len() == 22 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn request_aad(request_id: &str) -> String {
    format!("2secret/v1/agent-request/{request_id}")
}

fn answer_aad(request_id: &str) -> String {
    format!("2secret/v1/agent-answer/{request_id}")
}

/// What the agent signs: the context, the request id and the exact bytes of
/// the payload that follow the signature in the envelope.
fn request_message(request_id: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = REQUEST_CONTEXT.to_vec();
    out.push(b'\n');
    out.extend_from_slice(request_id.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(payload);
    out
}

/// The plaintext of a request envelope (after the 64-byte signature).
#[derive(Serialize, Deserialize)]
struct RequestPayload {
    agent_id: String,
    ts: i64,
    method: String,
    #[serde(default)]
    params: Value,
    /// The key for the answer (base64url, 32 bytes).
    reply_key: String,
}

/// A request ready to post, and what the agent keeps to read the answer.
pub struct SealedRequest {
    pub id: String,
    pub request: HybridSealedBox,
    pub reply_key: SymmetricKey,
}

/// Sign a request and seal it to the account, with a fresh reply key.
pub fn seal_request(
    keys: &RemoteKeys,
    account: &AccountPublicKeys,
    method: &str,
    params: Value,
    now: i64,
) -> Result<SealedRequest> {
    let pq = account.ml_kem.as_ref().ok_or_else(|| invalid("the account has no post-quantum key yet"))?;
    let id = new_request_id();
    let reply_key = SymmetricKey::generate();
    let payload = Zeroizing::new(serde_json::to_vec(&RequestPayload {
        agent_id: keys.agent_id(),
        ts: now,
        method: method.to_string(),
        params,
        reply_key: reply_key.to_b64(),
    })?);
    let signature = keys.sign(&request_message(&id, &payload));
    let mut plain = Zeroizing::new(Vec::with_capacity(64 + payload.len()));
    plain.extend_from_slice(&signature.to_bytes());
    plain.extend_from_slice(&payload);
    let request = seal_hybrid(&account.x25519, pq, &plain, request_aad(&id).as_bytes())?;
    Ok(SealedRequest { id, request, reply_key })
}

/// A request as the app reads it.
pub struct OpenedRequest {
    pub ts: i64,
    pub method: String,
    pub params: Value,
    pub reply_key: SymmetricKey,
}

/// Open a request with the account's keys and check its signature against
/// the agent's pinned keys. `now` bounds the request's age.
pub fn open_request(
    keyset: &Keyset,
    agent: &VerifiedKeys,
    request_id: &str,
    sealed: &HybridSealedBox,
    now: i64,
) -> Result<OpenedRequest> {
    if !valid_request_id(request_id) {
        return Err(invalid("malformed request id"));
    }
    let plain = open_hybrid(&keyset.private_key, &keyset.pq_private_key(), sealed, request_aad(request_id).as_bytes())?;
    if plain.len() < 64 {
        return Err(Error::Decryption);
    }
    let (signature, payload) = plain.split_at(64);
    let signature = Signature::from_bytes(signature.try_into().expect("64 bytes"));
    agent
        .ed25519
        .verify_strict(&request_message(request_id, payload), &signature)
        .map_err(|_| Error::PermissionDenied("the request is not signed by the paired agent".into()))?;
    let request: RequestPayload = serde_json::from_slice(payload)?;
    if request.agent_id != agent.agent_id() {
        return Err(Error::PermissionDenied("the request names another agent".into()));
    }
    if (now - request.ts).abs() > REQUEST_SECONDS + HTTP_SKEW_SECONDS {
        return Err(Error::PermissionDenied("the request is too old".into()));
    }
    let reply_key = SymmetricKey::from_b64(&request.reply_key)?;
    Ok(OpenedRequest { ts: request.ts, method: request.method, params: request.params, reply_key })
}

/// The plaintext of an answer: the result, or the error.
#[derive(Serialize, Deserialize)]
struct AnswerPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<AgentError>,
}

/// Encrypt an answer with the reply key from the request.
pub fn seal_answer(
    reply_key: &SymmetricKey,
    request_id: &str,
    outcome: &std::result::Result<Value, AgentError>,
) -> Result<EncString> {
    let payload = match outcome {
        Ok(v) => AnswerPayload { result: Some(v.clone()), error: None },
        Err(e) => AnswerPayload { result: None, error: Some(e.clone()) },
    };
    let plain = Zeroizing::new(serde_json::to_vec(&payload)?);
    Ok(encrypt(reply_key, &plain, answer_aad(request_id).as_bytes()))
}

/// Decrypt an answer. An answer the reply key does not open was not made by
/// whoever opened the request.
pub fn open_answer(
    reply_key: &SymmetricKey,
    request_id: &str,
    enc: &EncString,
) -> Result<std::result::Result<Value, AgentError>> {
    let plain = decrypt(reply_key, enc, answer_aad(request_id).as_bytes())?;
    let payload: AnswerPayload = serde_json::from_slice(&plain)?;
    Ok(match (payload.result, payload.error) {
        (_, Some(e)) => Err(e),
        (Some(v), None) => Ok(v),
        (None, None) => Ok(Value::Object(Default::default())),
    })
}

// ---------------------------------------------------------------------------
// HTTP signature
// ---------------------------------------------------------------------------

/// The signed header an agent sends with every call to the server:
/// `<agent id>.<time>.<nonce>.<signature>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpSignature {
    pub agent_id: String,
    /// Unix seconds when the request was made.
    pub ts: i64,
    /// 16 random bytes, base64url; the server refuses one it saw before.
    pub nonce: String,
    /// Ed25519 over [`http_message`], base64url.
    pub signature: String,
}

/// What the header signs: the method, the path (with query), a hash of the
/// body, the time and the nonce.
fn http_message(method: &str, path: &str, body: &[u8], ts: i64, nonce: &str) -> Vec<u8> {
    let mut out = HTTP_CONTEXT.to_vec();
    for part in [method.to_ascii_uppercase().as_str(), path, &hex(&sha256(body)), &ts.to_string(), nonce] {
        out.push(b'\n');
        out.extend_from_slice(part.as_bytes());
    }
    out
}

impl HttpSignature {
    /// Sign a call made now.
    pub fn sign(keys: &RemoteKeys, method: &str, path: &str, body: &[u8], ts: i64) -> Self {
        let nonce = b64url(&random_bytes::<16>());
        let signature = keys.sign(&http_message(method, path, body, ts, &nonce));
        Self { agent_id: keys.agent_id(), ts, nonce, signature: b64url(&signature.to_bytes()) }
    }

    /// The header value.
    pub fn header(&self) -> String {
        format!("{}.{}.{}.{}", self.agent_id, self.ts, self.nonce, self.signature)
    }

    /// Parse a header value; the shape only, not the signature.
    pub fn parse(header: &str) -> Result<Self> {
        let mut parts = header.trim().split('.');
        let (Some(agent_id), Some(ts), Some(nonce), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid("malformed agent signature"));
        };
        let ts: i64 = ts.parse().map_err(|_| invalid("malformed agent signature"))?;
        let ok = |s: &str, len: usize| {
            s.len() == len && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        if agent_id.len() != 19 || !ok(nonce, 22) || !ok(signature, 86) {
            return Err(invalid("malformed agent signature"));
        }
        Ok(Self { agent_id: agent_id.to_string(), ts, nonce: nonce.to_string(), signature: signature.to_string() })
    }

    /// Check the signature with the agent's Ed25519 key (base64) and that
    /// the time is within [`HTTP_SKEW_SECONDS`] of `now`. Whether the nonce
    /// was seen before is the server's to check.
    pub fn verify(&self, ed25519: &str, method: &str, path: &str, body: &[u8], now: i64) -> Result<()> {
        let key: [u8; 32] =
            unb64(ed25519)?.try_into().map_err(|_| invalid("the agent key is not an Ed25519 public key"))?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| invalid("the agent key is not an Ed25519 public key"))?;
        if agent_id(key.as_bytes()) != self.agent_id {
            return Err(Error::PermissionDenied("the signature names another agent".into()));
        }
        // abs_diff: the time comes from the caller, and a subtraction of
        // i64::MIN would overflow.
        if now.abs_diff(self.ts) > HTTP_SKEW_SECONDS.unsigned_abs() {
            return Err(Error::PermissionDenied("the agent's clock is off by more than five minutes".into()));
        }
        let signature: [u8; 64] =
            unb64url(&self.signature)?.try_into().map_err(|_| invalid("the signature has the wrong length"))?;
        key.verify_strict(&http_message(method, path, body, self.ts, &self.nonce), &Signature::from_bytes(&signature))
            .map_err(|_| Error::PermissionDenied("the signature does not match the agent key".into()))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn account() -> Keyset {
        Keyset::generate()
    }

    #[test]
    fn code_text_and_uri_roundtrip() {
        let keyset = account();
        let code = PairingCode::new("https://sync.example.com/", &keyset.public_keys()).unwrap();
        assert_eq!(code.server, "https://sync.example.com");
        let text = code.text();
        assert!(text.starts_with("2A-"), "{text}");
        assert_eq!(text.replace('-', "").len(), 2 + CODE_CHARS);
        let back =
            PairingCode::parse(&text.to_lowercase().replace('-', " "), Some("https://sync.example.com")).unwrap();
        assert_eq!(back, code);
        assert_eq!(back.token(), code.token());
        assert_eq!(*back.secret(), *code.secret());
        assert!(back.matches(&keyset.public_keys()));
        assert!(!back.matches(&account().public_keys()));

        let uri = code.uri();
        assert!(uri.starts_with("2secret-agent:v1?server=https%3A%2F%2Fsync.example.com&code=2A-"), "{uri}");
        let back = PairingCode::parse(&uri, None).unwrap();
        assert_eq!(back, code);
        assert!(valid_token(&code.token()));
        assert_eq!(code.token_hash(), pairing_token_hash(&code.token()));
        assert_ne!(code.token().as_bytes(), &code.secret()[..]);
    }

    #[test]
    fn code_rejects_typos_and_odd_input() {
        let mut code = PairingCode::new("https://s.example", &account().public_keys()).unwrap();
        // A fixed code: one in 32 typos happens to match the check character
        // (a 5-bit check), so a random code made this test fail now and then.
        code.seed = [7u8; CODE_SEED_LEN];
        code.key_hash = [9u8; CODE_HASH_LEN];
        let text = code.text();
        assert!(PairingCode::parse(&text, Some("https://s.example")).is_ok());
        let changed = |i: usize, to: char| {
            let mut chars: Vec<char> = text.chars().collect();
            chars[i] = to;
            chars.into_iter().collect::<String>()
        };
        // One character changed in the body.
        let i = 5;
        let to = if text.as_bytes()[i] == b'A' { 'B' } else { 'A' };
        assert!(PairingCode::parse(&changed(i, to), Some("https://s.example")).is_err());
        // The check character itself changed: always caught.
        let last = text.len() - 1;
        let to = if text.ends_with('A') { 'B' } else { 'A' };
        assert!(PairingCode::parse(&changed(last, to), Some("https://s.example")).is_err());
        // Too short, bad alphabet, no server.
        assert!(PairingCode::parse(&text[..20], Some("https://s.example")).is_err());
        assert!(PairingCode::parse(&text.replace('A', "0"), Some("https://s.example")).is_err());
        assert!(PairingCode::parse(&text, None).is_err());
        assert!(PairingCode::parse("2secret-agent:v2?server=https%3A%2F%2Fs.example&code=x", None).is_err());
        assert!(PairingCode::parse("2secret-agent:v1?code=x", None).is_err());
        assert!(PairingCode::parse(&text, Some("ftp://s.example")).is_err());
        assert!(PairingCode::parse(&text, Some("not a url")).is_err());
    }

    #[test]
    fn code_encoding_roundtrips_and_rejects_padding() {
        for len in [1usize, 2, 3, 4, 5, 16, 32] {
            let bytes: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect();
            let text = code_encode(&bytes);
            assert_eq!(text.len(), (len * 8).div_ceil(5));
            assert_eq!(code_decode(&text, len).unwrap(), bytes);
        }
        // 32 bytes end in a character with four padding bits: they must be zero.
        let text = code_encode(&[0xffu8; 32]);
        let mut wrong = text.clone();
        wrong.pop();
        wrong.push('Z');
        assert!(code_decode(&wrong, 32).is_none());
        assert!(code_decode(&text, 31).is_none());
    }

    #[test]
    fn keys_follow_from_the_root() {
        let a = RemoteKeys::from_root([9u8; 32]);
        let b = RemoteKeys::from_root([9u8; 32]);
        assert_eq!(a.public(), b.public());
        assert_eq!(a.agent_id(), b.agent_id());
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.public(), RemoteKeys::generate().public());
        let public = a.public();
        assert_eq!(public.agent_id().unwrap(), a.agent_id());
        assert_eq!(public.fingerprint().unwrap(), a.fingerprint());
        assert_eq!(public.verify().unwrap().to_remote(), public);
        assert_eq!(a.agent_id().len(), 19);
        // Each key is independent of the others.
        assert_ne!(a.x25519.to_bytes().as_slice(), a.signing.to_bytes().as_slice());
        let bad = RemotePublicKeys { ed25519: "AAAA".into(), ..public.clone() };
        assert!(bad.verify().is_err());
        let bad = RemotePublicKeys { ml_kem: public.x25519.clone(), ..public.clone() };
        assert!(bad.verify().is_err());
    }

    #[test]
    fn proof_roundtrip_and_checks() {
        let keyset = account();
        let account_keys = keyset.public_keys();
        let code = PairingCode::new("https://s.example", &account_keys).unwrap();
        let agent = RemoteKeys::generate();
        let sealed = seal_proof(&code, &account_keys, &agent, "Claude Code", "2.1", Some("build-1")).unwrap();
        let proof = open_proof(&keyset, &code.token_hash(), &sealed).unwrap();
        assert_eq!(proof.name, "Claude Code");
        assert_eq!(proof.device.as_deref(), Some("build-1"));
        proof.check(&code, &agent.public()).unwrap();
        // Another device cannot open it, nor another token's AAD.
        assert!(open_proof(&account(), &code.token_hash(), &sealed).is_err());
        assert!(open_proof(&keyset, "other", &sealed).is_err());
        // Another code's secret, or other keys listed by the server.
        let other = PairingCode::new("https://s.example", &account_keys).unwrap();
        assert!(proof.check(&other, &agent.public()).is_err());
        assert!(proof.check(&code, &RemoteKeys::generate().public()).is_err());
        // A code for another account refuses to seal to this one.
        let foreign = PairingCode::new("https://s.example", &account().public_keys()).unwrap();
        assert!(seal_proof(&foreign, &account_keys, &agent, "x", "", None).is_err());
    }

    #[test]
    fn record_roundtrip_and_pinning() {
        let keyset = account();
        let agent = RemoteKeys::generate();
        let record = AgentRecordData {
            name: "Claude Code".into(),
            version: "2.1".into(),
            keys: agent.public(),
            fingerprint: agent.fingerprint(),
            paired_at: 1_700_000_000,
            device: None,
            paired_on: Some("MacBook".into()),
        };
        let enc = record.seal(&keyset.account_key, "acc", &agent.agent_id()).unwrap();
        let back = AgentRecordData::open(&enc, &keyset.account_key, "acc", &agent.agent_id(), &agent.public()).unwrap();
        assert_eq!(back, record);
        assert!(AgentRecordData::open(&enc, &keyset.account_key, "other", &agent.agent_id(), &agent.public()).is_err());
        assert!(
            AgentRecordData::open(&enc, &SymmetricKey::generate(), "acc", &agent.agent_id(), &agent.public()).is_err()
        );
        let swapped = RemoteKeys::generate().public();
        assert!(AgentRecordData::open(&enc, &keyset.account_key, "acc", &agent.agent_id(), &swapped).is_err());
    }

    #[test]
    fn request_and_answer_roundtrip() {
        let keyset = account();
        let agent = RemoteKeys::generate();
        let now = 1_700_000_000;
        let sealed =
            seal_request(&agent, &keyset.public_keys(), "read", json!({"item": "GitHub", "field": "password"}), now)
                .unwrap();
        assert!(valid_request_id(&sealed.id));
        let opened = open_request(&keyset, &agent.verified(), &sealed.id, &sealed.request, now + 3).unwrap();
        assert_eq!(opened.method, "read");
        assert_eq!(opened.params["item"], "GitHub");
        assert_eq!(opened.ts, now);
        assert_eq!(opened.reply_key, sealed.reply_key);

        let answer = seal_answer(&opened.reply_key, &sealed.id, &Ok(json!({"value": "hunter2"}))).unwrap();
        let back = open_answer(&sealed.reply_key, &sealed.id, &answer).unwrap().unwrap();
        assert_eq!(back["value"], "hunter2");
        let denied = seal_answer(&opened.reply_key, &sealed.id, &Err(AgentError::denied())).unwrap();
        assert_eq!(open_answer(&sealed.reply_key, &sealed.id, &denied).unwrap(), Err(AgentError::denied()));
        // Another key or another request id does not open it: an answer the
        // server made up is refused.
        assert!(open_answer(&SymmetricKey::generate(), &sealed.id, &answer).is_err());
        assert!(open_answer(&sealed.reply_key, &new_request_id(), &answer).is_err());
    }

    #[test]
    fn request_refuses_forgeries() {
        let keyset = account();
        let agent = RemoteKeys::generate();
        let now = 1_700_000_000;
        let sealed = seal_request(&agent, &keyset.public_keys(), "ping", Value::Null, now).unwrap();
        // Another agent's pinned key: the signature does not verify.
        let other = RemoteKeys::generate();
        assert!(open_request(&keyset, &other.verified(), &sealed.id, &sealed.request, now).is_err());
        // Another account cannot open it.
        assert!(open_request(&account(), &agent.verified(), &sealed.id, &sealed.request, now).is_err());
        // The id is bound: the same envelope under another id fails.
        assert!(open_request(&keyset, &agent.verified(), &new_request_id(), &sealed.request, now).is_err());
        assert!(open_request(&keyset, &agent.verified(), "short", &sealed.request, now).is_err());
        // Too old.
        assert!(open_request(&keyset, &agent.verified(), &sealed.id, &sealed.request, now + 2000).is_err());
        // A request signed by another agent but claiming this agent's id.
        let forged = seal_request(&other, &keyset.public_keys(), "ping", Value::Null, now).unwrap();
        assert!(open_request(&keyset, &agent.verified(), &forged.id, &forged.request, now).is_err());
    }

    #[test]
    fn http_signature_roundtrip() {
        let agent = RemoteKeys::generate();
        let public = agent.public();
        let now = 1_700_000_000;
        let body = br#"{"id":"x"}"#;
        let sig = HttpSignature::sign(&agent, "post", "/api/v1/agent/requests", body, now);
        let header = sig.header();
        let parsed = HttpSignature::parse(&header).unwrap();
        assert_eq!(parsed, sig);
        parsed.verify(&public.ed25519, "POST", "/api/v1/agent/requests", body, now + 10).unwrap();
        // Another method, path, body, time, or key.
        assert!(parsed.verify(&public.ed25519, "GET", "/api/v1/agent/requests", body, now).is_err());
        assert!(parsed.verify(&public.ed25519, "POST", "/api/v1/agent/requests?wait=1", body, now).is_err());
        assert!(parsed.verify(&public.ed25519, "POST", "/api/v1/agent/requests", b"{}", now).is_err());
        assert!(parsed.verify(&public.ed25519, "POST", "/api/v1/agent/requests", body, now + 400).is_err());
        assert!(parsed.verify(&public.ed25519, "POST", "/api/v1/agent/requests", body, now - 400).is_err());
        assert!(parsed
            .verify(&RemoteKeys::generate().public().ed25519, "POST", "/api/v1/agent/requests", body, now)
            .is_err());
        // Malformed headers.
        for bad in ["", "a.b.c", &header[..header.len() - 1], &format!("{header}.x"), &header.replace('.', ",")] {
            assert!(HttpSignature::parse(bad).is_err(), "{bad}");
        }
        let mut other_id = parsed.clone();
        other_id.agent_id = RemoteKeys::generate().agent_id();
        assert!(other_id.verify(&public.ed25519, "POST", "/api/v1/agent/requests", body, now).is_err());
    }
}
