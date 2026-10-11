//! Authentication: hashing of client auth keys, session tokens and the
//! request extractor for authenticated routes.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};
use twosecret_core::crypto::{constant_time_eq, sha256, KdfParams};
use twosecret_core::util::{b64, b64url, hex, now, random_bytes, unb64};

use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::AppState;

/// Server-side Argon2id parameters for hashing the (already high-entropy)
/// client authentication key. This is defence in depth: even a leaked
/// database cannot be used to log in.
fn server_kdf() -> KdfParams {
    KdfParams { algorithm: "argon2id".into(), memory_kib: 19 * 1024, iterations: 2, parallelism: 1 }
}

#[derive(Serialize, Deserialize)]
struct StoredHash {
    v: u32,
    salt: String,
    hash: String,
    kdf: KdfParams,
}

/// Decode and validate a base64 auth key sent by a client.
pub fn decode_auth_key(b64_key: &str) -> ApiResult<Vec<u8>> {
    let key = unb64(b64_key).map_err(|_| ApiError::bad_request("auth_key must be base64"))?;
    if key.len() != 32 {
        return Err(ApiError::bad_request("auth_key must be 32 bytes"));
    }
    Ok(key)
}

/// Hash an auth key for storage.
pub fn hash_auth_key(key: &[u8]) -> ApiResult<String> {
    let salt: [u8; 16] = random_bytes();
    let kdf = server_kdf();
    let hash = kdf.hash(key, &salt).map_err(ApiError::internal)?;
    Ok(serde_json::to_string(&StoredHash { v: 1, salt: b64(&salt), hash: b64(hash.as_bytes()), kdf })?)
}

/// Verify an auth key against a stored hash in constant time.
pub fn verify_auth_key(key: &[u8], stored: &str) -> bool {
    let Ok(stored) = serde_json::from_str::<StoredHash>(stored) else {
        return false;
    };
    let (Ok(salt), Ok(expected)) = (unb64(&stored.salt), unb64(&stored.hash)) else {
        return false;
    };
    match stored.kdf.hash(key, &salt) {
        Ok(h) => constant_time_eq(h.as_bytes(), &expected),
        Err(_) => false,
    }
}

/// Spend the same effort as a real verification (used for unknown accounts
/// so response times do not reveal whether an e-mail address exists).
pub fn dummy_verify(key: &[u8]) {
    let _ = server_kdf().hash(key, &[0u8; 16]);
}

/// A new random session token and its storage hash.
pub fn new_token() -> (String, String) {
    let raw: [u8; 32] = random_bytes();
    let token = b64url(&raw);
    let hash = token_hash(&token);
    (token, hash)
}

pub fn token_hash(token: &str) -> String {
    hex(&sha256(token.as_bytes()))
}

/// The authenticated caller of a request.
#[derive(Clone, Debug)]
pub struct Auth {
    pub account_id: String,
    pub session_id: String,
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(ApiError::unauthorized)?;
        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or_else(ApiError::unauthorized)?
            .trim()
            .to_string();
        if token.is_empty() || token.len() > 128 {
            return Err(ApiError::unauthorized());
        }
        let hash = token_hash(&token);
        let session_days = state.config.session_days;
        state
            .db
            .run(move |conn| {
                let session = db::session_by_token(conn, &hash)?.ok_or_else(ApiError::unauthorized)?;
                let ts = now();
                if session.expires_at < ts {
                    conn.execute("DELETE FROM sessions WHERE id = ?1", [&session.id])?;
                    return Err(ApiError::unauthorized());
                }
                // Sliding expiry, updated at most once a minute.
                if ts - session.last_used_at > 60 {
                    conn.execute(
                        "UPDATE sessions SET last_used_at = ?1, expires_at = ?2 WHERE id = ?3",
                        rusqlite::params![ts, ts + session_days * 86_400, session.id],
                    )?;
                }
                Ok(Auth { account_id: session.account_id, session_id: session.id })
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let key = [9u8; 32];
        let stored = hash_auth_key(&key).unwrap();
        assert!(verify_auth_key(&key, &stored));
        assert!(!verify_auth_key(&[8u8; 32], &stored));
        assert!(!verify_auth_key(&key, "garbage"));
        let (t, h) = new_token();
        assert_eq!(token_hash(&t), h);
    }
}
