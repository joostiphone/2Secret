//! Who is calling the agent routes: the signed `X-2Secret-Agent` header
//! (`twosecret_core::agent_remote::HttpSignature`) over the method, the path,
//! the body, a time and a nonce. The server checks the signature with the
//! Ed25519 key it stored for the agent, refuses a time more than five
//! minutes off, a nonce it saw before (within that window), an agent the
//! owner revoked and one the owner has not confirmed.
//!
//! Handlers take the raw `HeaderMap` and `Bytes` so the body the signature
//! covers is the body that is parsed afterwards.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::body::Bytes;
use axum::http::{HeaderMap, Method, Uri};
use rusqlite::{params, Connection, OptionalExtension};
use twosecret_core::agent_remote::{HttpSignature, HTTP_HEADER, HTTP_SKEW_SECONDS};
use twosecret_core::util::now;

use crate::client_ip::ClientIp;
use crate::error::{ApiError, ApiResult};
use crate::AppState;

/// Nonces seen recently, per agent, with when they may be forgotten.
#[derive(Default)]
pub struct Nonces {
    seen: Mutex<HashMap<(String, String), i64>>,
}

impl Nonces {
    /// Remember a nonce; `false` when it was seen before.
    pub fn first_time(&self, agent_id: &str, nonce: &str, now: i64) -> bool {
        let mut seen = self.seen.lock().expect("nonce lock");
        if seen.len() > 100_000 {
            seen.retain(|_, until| *until > now);
        }
        let key = (agent_id.to_string(), nonce.to_string());
        if seen.get(&key).is_some_and(|until| *until > now) {
            return false;
        }
        seen.insert(key, now + 2 * HTTP_SKEW_SECONDS);
        true
    }

    /// Forget nonces outside the time window (called every minute).
    pub fn prune(&self, now: i64) {
        self.seen.lock().expect("nonce lock").retain(|_, until| *until > now);
    }
}

/// The agent behind a verified header.
#[derive(Clone, Debug)]
pub struct AgentCaller {
    pub agent_id: String,
    pub account_id: String,
}

/// The stored keys and state of an agent, as [`verify`] needs them.
struct AgentRow {
    account_id: String,
    ed25519: String,
    confirmed: bool,
    revoked: bool,
}

fn agent_row(conn: &Connection, agent_id: &str) -> rusqlite::Result<Option<AgentRow>> {
    conn.query_row(
        "SELECT account_id, ed25519, record IS NOT NULL, revoked_at > 0 FROM agents WHERE id = ?1",
        [agent_id],
        |r| Ok(AgentRow { account_id: r.get(0)?, ed25519: r.get(1)?, confirmed: r.get(2)?, revoked: r.get(3)? }),
    )
    .optional()
}

/// The header, parsed; its signature is not checked yet.
pub fn signature(headers: &HeaderMap) -> ApiResult<HttpSignature> {
    let header = headers.get(HTTP_HEADER).and_then(|v| v.to_str().ok()).ok_or_else(|| {
        ApiError::new(axum::http::StatusCode::UNAUTHORIZED, "agent_signature", "agent signature required")
    })?;
    HttpSignature::parse(header).map_err(|_| bad_signature())
}

fn bad_signature() -> ApiError {
    ApiError::new(axum::http::StatusCode::UNAUTHORIZED, "agent_signature", "the agent signature is not valid")
}

/// What the signature covers on this server: the path with its query.
pub fn signed_path(uri: &Uri) -> String {
    uri.path_and_query().map(|p| p.to_string()).unwrap_or_else(|| uri.path().to_string())
}

/// Check a header against a key that is not in the database yet (pairing):
/// the agent proves it holds the key it announces.
pub fn verify_with_key(
    state: &AppState,
    sig: &HttpSignature,
    ed25519: &str,
    method: &Method,
    uri: &Uri,
    body: &Bytes,
) -> ApiResult<()> {
    let at = now();
    sig.verify(ed25519, method.as_str(), &signed_path(uri), body, at).map_err(|_| bad_signature())?;
    if !state.agent_nonces.first_time(&sig.agent_id, &sig.nonce, at) {
        return Err(bad_signature());
    }
    Ok(())
}

/// Check a header against the agent's stored key, and that the agent may
/// call: confirmed by the owner and not revoked. Every signed call counts
/// against the agent's limit; calls with a wrong signature count against the
/// caller's address instead, so a stranger who knows an agent's id cannot use
/// up its limit.
pub async fn verify(
    state: &AppState,
    client: &ClientIp,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &Bytes,
) -> ApiResult<AgentCaller> {
    let at = now();
    let bad_key = format!("agent-bad:{}", client.0);
    if !state.agent_bad_limiter.allowed(&bad_key, at) {
        return Err(ApiError::too_many_requests());
    }
    let refuse = |e: ApiError| {
        state.agent_bad_limiter.record_failure(&bad_key, at);
        e
    };
    let sig = signature(headers).map_err(refuse)?;
    let id = sig.agent_id.clone();
    let row = state.db.run(move |c| Ok(agent_row(c, &id)?)).await?;
    // An unknown agent gets the same answer as a wrong signature: nothing to
    // learn from the difference.
    let row = row.ok_or_else(bad_signature).map_err(refuse)?;
    sig.verify(&row.ed25519, method.as_str(), &signed_path(uri), body, at).map_err(|_| refuse(bad_signature()))?;
    if !state.agent_nonces.first_time(&sig.agent_id, &sig.nonce, at) {
        return Err(refuse(bad_signature()));
    }
    let limiter_key = format!("agent:{}", sig.agent_id);
    if !state.agent_limiter.allowed(&limiter_key, at) {
        return Err(ApiError::too_many_requests());
    }
    state.agent_limiter.record_failure(&limiter_key, at);
    if row.revoked {
        return Err(ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            "agent_revoked",
            "the owner revoked this agent; pair again with a new code",
        ));
    }
    if !row.confirmed {
        return Err(ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            "agent_not_confirmed",
            "the owner has not confirmed this agent yet",
        ));
    }
    let agent_id = sig.agent_id.clone();
    let seen = agent_id.clone();
    state
        .db
        .run(move |c| {
            c.execute("UPDATE agents SET last_seen_at = ?1 WHERE id = ?2", params![at, seen])?;
            Ok(())
        })
        .await?;
    Ok(AgentCaller { agent_id, account_id: row.account_id })
}
