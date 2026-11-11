//! Agents elsewhere (`twosecret_core::agent_remote`): the relay between an
//! AI agent on another computer and the owner's unlocked apps. The server
//! keeps public keys, sealed envelopes it cannot open and times: it learns
//! which agent asked when and how large the question was, never what it
//! was, which item or what the answer is.
//!
//! Owner routes (signed in, `/agents…`): register a pairing code, list
//! agents, confirm one with its encrypted record, revoke one, fetch open
//! requests (long-poll), answer or deny a request. Agent routes (signed with
//! `X-2Secret-Agent`, `/agent…`): look up the account keys for a pairing
//! token, pair, post a request, fetch its outcome (long-poll).

use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, OriginalUri, Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use tokio::sync::broadcast;
use twosecret_core::agent_remote::{
    pairing_token_hash, valid_request_id, valid_token, MAX_ENVELOPE_BYTES, MAX_WAIT_SECONDS, PAIRING_SECONDS,
    REQUEST_SECONDS,
};
use twosecret_core::api::{
    AgentAnswerRequest, AgentDto, AgentRequestDto, AgentRequestState, AgentRequestStatus, ConfirmAgentRequest,
    CreatePairingRequest, CreatePairingResponse, PairAgentRequest, PairAgentResponse, PairingInfo, PairingInfoRequest,
    PostAgentRequest, PostAgentRequestResponse,
};
use twosecret_core::crypto::{EncString, EncryptedKeyset, HybridSealedBox};
use twosecret_core::util::now;

use crate::agent_auth::{self, AgentCaller};
use crate::auth::Auth;
use crate::client_ip::ClientIp;
use crate::error::{ApiError, ApiResult};
use crate::AppState;

/// Pairing codes an account may have open at a time.
const MAX_PAIRINGS: i64 = 5;
/// Largest encrypted agent record.
const MAX_RECORD: usize = 64 * 1024;
/// Revoked agents are remembered this long, so the agent learns it was
/// revoked instead of seeing an unknown-agent error.
const REVOKED_KEEP_SECONDS: i64 = 7 * 86_400;
/// A body with an envelope, and some room for the JSON around it.
const MAX_BODY: usize = MAX_ENVELOPE_BYTES + 8 * 1024;

/// Something happened that a long-poll may wait for.
#[derive(Clone, Debug)]
pub enum AgentEvent {
    /// An agent posted a request for this account.
    Request { account_id: String },
    /// The owner answered or denied this request.
    Answered { request_id: String },
}

/// `/api/v1/agents…` (owner) and `/api/v1/agent…` (agents).
pub fn api() -> Router<AppState> {
    let agent_body = || DefaultBodyLimit::max(MAX_BODY);
    Router::new()
        .route("/agents", get(list_agents))
        .route("/agents/pairings", post(create_pairing))
        .route("/agents/requests", get(owner_requests))
        .route("/agents/requests/{id}/answer", post(answer_request))
        .route("/agents/requests/{id}/deny", post(deny_request))
        .route("/agents/{id}", put(confirm_agent).delete(revoke_agent))
        // POST keeps the one-time code out of URLs (and proxy logs); GET is
        // for agents before 1.15.
        .route("/agent/pairing", post(pairing_info_post).layer(agent_body()))
        .route("/agent/pairing/{token}", get(pairing_info).layer(agent_body()))
        .route("/agent/pair", post(pair).layer(agent_body()))
        .route("/agent/requests", post(post_request).layer(agent_body()))
        .route("/agent/requests/{id}", get(request_status).layer(agent_body()))
}

#[derive(Deserialize)]
pub struct WaitQuery {
    /// Seconds to hold the connection when there is nothing yet (at most
    /// [`MAX_WAIT_SECONDS`]).
    #[serde(default)]
    wait: u32,
}

/// Wait up to `wait` seconds for an event `matches` accepts. The receiver
/// has to be made before the state is read, or an event in between is lost.
async fn wait_for(rx: &mut broadcast::Receiver<AgentEvent>, wait: u32, matches: impl Fn(&AgentEvent) -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait.min(MAX_WAIT_SECONDS) as u64);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(event)) if matches(&event) => return,
            Ok(Ok(_)) => continue,
            // Lagged: something happened, look again.
            Ok(Err(_)) | Err(_) => return,
        }
    }
}

fn valid_token_hash(hash: &str) -> bool {
    valid_token(hash)
}

fn envelope_json(sealed: &HybridSealedBox) -> ApiResult<String> {
    let json = serde_json::to_string(sealed)?;
    if json.len() > MAX_ENVELOPE_BYTES {
        return Err(ApiError::bad_request("the sealed envelope is too large"));
    }
    Ok(json)
}

fn envelope_col(s: String) -> rusqlite::Result<HybridSealedBox> {
    serde_json::from_str(&s)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}

fn enc_col(s: String) -> rusqlite::Result<EncString> {
    EncString::parse(&s)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &Bytes) -> ApiResult<T> {
    serde_json::from_slice(body).map_err(|e| ApiError::bad_request(format!("invalid request body: {e}")))
}

// ---------------------------------------------------------------------------
// Owner: pairing codes and the list of agents
// ---------------------------------------------------------------------------

async fn create_pairing(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<CreatePairingRequest>,
) -> ApiResult<(StatusCode, Json<CreatePairingResponse>)> {
    if !valid_token_hash(&req.token_hash) {
        return Err(ApiError::bad_request("invalid token hash"));
    }
    let at = now();
    let expires_at = at + PAIRING_SECONDS;
    state
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            let open: i64 = tx.query_row(
                "SELECT COUNT(*) FROM agent_pairings WHERE account_id = ?1 AND expires_at > ?2",
                params![auth.account_id, at],
                |r| r.get(0),
            )?;
            if open >= MAX_PAIRINGS {
                return Err(ApiError::forbidden(format!("you can have {MAX_PAIRINGS} pairing codes open at a time")));
            }
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO agent_pairings (token_hash, account_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![req.token_hash, auth.account_id, at, expires_at],
            )?;
            if inserted == 0 {
                return Err(ApiError::conflict("pairing code already in use"));
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok((StatusCode::CREATED, Json(CreatePairingResponse { expires_at })))
}

fn agent_dtos(conn: &Connection, account_id: &str, at: i64) -> rusqlite::Result<Vec<AgentDto>> {
    let mut stmt = conn.prepare(
        "SELECT id, x25519, ml_kem, ed25519, token_hash, proof, record, created_at, expires_at, last_seen_at
         FROM agents WHERE account_id = ?1 AND revoked_at = 0 AND (record IS NOT NULL OR expires_at > ?2)
         ORDER BY created_at",
    )?;
    let rows = stmt.query_map(params![account_id, at], |r| {
        let proof: Option<String> = r.get(5)?;
        let record: Option<String> = r.get(6)?;
        let pending = record.is_none();
        Ok(AgentDto {
            id: r.get(0)?,
            keys: twosecret_core::agent_remote::RemotePublicKeys {
                x25519: r.get(1)?,
                ml_kem: r.get(2)?,
                ed25519: r.get(3)?,
            },
            token_hash: if pending { r.get(4)? } else { None },
            proof: if pending { proof.map(envelope_col).transpose()? } else { None },
            record: record.map(enc_col).transpose()?,
            created_at: r.get(7)?,
            expires_at: if pending { Some(r.get(8)?) } else { None },
            last_seen_at: r.get(9)?,
        })
    })?;
    rows.collect()
}

async fn list_agents(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<AgentDto>>> {
    let at = now();
    let agents = state.db.run(move |c| Ok(agent_dtos(c, &auth.account_id, at)?)).await?;
    Ok(Json(agents))
}

async fn confirm_agent(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(req): Json<ConfirmAgentRequest>,
) -> ApiResult<StatusCode> {
    if req.record.len() > MAX_RECORD {
        return Err(ApiError::bad_request("the agent record is too large"));
    }
    let at = now();
    let max_agents = state.config.max_agents_per_account as i64;
    let quota = state.config.account_quota_bytes;
    state
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            crate::routes::check_quota(&tx, quota, &auth.account_id, req.record.len() as i64)?;
            let confirmed: i64 = tx.query_row(
                "SELECT COUNT(*) FROM agents WHERE account_id = ?1 AND record IS NOT NULL AND revoked_at = 0",
                [&auth.account_id],
                |r| r.get(0),
            )?;
            if confirmed >= max_agents {
                return Err(ApiError::forbidden(format!("you can have {max_agents} agents elsewhere")));
            }
            let updated = tx.execute(
                "UPDATE agents SET record = ?1, proof = NULL, token_hash = NULL
                 WHERE id = ?2 AND account_id = ?3 AND record IS NULL AND revoked_at = 0 AND expires_at > ?4",
                params![req.record.as_str(), id, auth.account_id, at],
            )?;
            if updated == 0 {
                return Err(ApiError::not_found("no agent is waiting for confirmation under this id"));
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_agent(State(state): State<AppState>, auth: Auth, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let at = now();
    state
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            let updated = tx.execute(
                "UPDATE agents SET revoked_at = ?1, record = NULL, proof = NULL, token_hash = NULL
                 WHERE id = ?2 AND account_id = ?3 AND revoked_at = 0",
                params![at, id, auth.account_id],
            )?;
            if updated == 0 {
                return Err(ApiError::not_found("agent not found"));
            }
            tx.execute("DELETE FROM agent_requests WHERE agent_id = ?1", [&id])?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Owner: requests
// ---------------------------------------------------------------------------

fn open_requests(conn: &Connection, account_id: &str, at: i64) -> rusqlite::Result<Vec<AgentRequestDto>> {
    let mut stmt = conn.prepare(
        "SELECT id, agent_id, request, created_at, expires_at FROM agent_requests
         WHERE account_id = ?1 AND status = 'open' AND expires_at > ?2 ORDER BY created_at",
    )?;
    let rows = stmt.query_map(params![account_id, at], |r| {
        Ok(AgentRequestDto {
            id: r.get(0)?,
            agent_id: r.get(1)?,
            request: envelope_col(r.get(2)?)?,
            created_at: r.get(3)?,
            expires_at: r.get(4)?,
        })
    })?;
    rows.collect()
}

async fn owner_requests(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<WaitQuery>,
) -> ApiResult<Json<Vec<AgentRequestDto>>> {
    let mut rx = state.agent_events.subscribe();
    let account_id = auth.account_id.clone();
    let requests = state.db.run(move |c| Ok(open_requests(c, &account_id, now())?)).await?;
    if !requests.is_empty() || q.wait == 0 {
        return Ok(Json(requests));
    }
    let mine = auth.account_id.clone();
    wait_for(&mut rx, q.wait, |e| matches!(e, AgentEvent::Request { account_id } if *account_id == mine)).await;
    let requests = state.db.run(move |c| Ok(open_requests(c, &auth.account_id, now())?)).await?;
    Ok(Json(requests))
}

/// Set a request's outcome: `answer` with the encrypted answer, or denied.
async fn settle(state: &AppState, auth: Auth, id: String, answer: Option<EncString>) -> ApiResult<StatusCode> {
    if !valid_request_id(&id) {
        return Err(ApiError::not_found("request not found"));
    }
    let at = now();
    let request_id = id.clone();
    let quota = state.config.account_quota_bytes;
    state
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            let growth = answer.as_ref().map_or(0, |a| a.len() as i64);
            crate::routes::check_quota(&tx, quota, &auth.account_id, growth)?;
            let status = if answer.is_some() { "answered" } else { "denied" };
            let updated = tx.execute(
                "UPDATE agent_requests SET answer = ?1, status = ?2
                 WHERE id = ?3 AND account_id = ?4 AND status = 'open' AND expires_at > ?5",
                params![answer.as_ref().map(EncString::as_str), status, id, auth.account_id, at],
            )?;
            if updated == 0 {
                let exists: bool = tx.query_row(
                    "SELECT COUNT(*) FROM agent_requests WHERE id = ?1 AND account_id = ?2",
                    params![id, auth.account_id],
                    |r| r.get::<_, i64>(0).map(|n| n > 0),
                )?;
                return Err(if exists {
                    ApiError::conflict("this request was already answered")
                } else {
                    ApiError::not_found("request not found")
                });
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    let _ = state.agent_events.send(AgentEvent::Answered { request_id });
    Ok(StatusCode::NO_CONTENT)
}

async fn answer_request(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(req): Json<AgentAnswerRequest>,
) -> ApiResult<StatusCode> {
    if req.answer.len() > MAX_ENVELOPE_BYTES {
        return Err(ApiError::bad_request("the answer is too large"));
    }
    settle(&state, auth, id, Some(req.answer)).await
}

async fn deny_request(State(state): State<AppState>, auth: Auth, Path(id): Path<String>) -> ApiResult<StatusCode> {
    settle(&state, auth, id, None).await
}

// ---------------------------------------------------------------------------
// Agent: pairing
// ---------------------------------------------------------------------------

fn pairing_error() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "pairing_invalid", "this pairing code is not valid (any more)")
}

/// The account behind a valid pairing token, with its public keys.
fn pairing_account(conn: &Connection, token_hash: &str, at: i64) -> ApiResult<(String, String, String, i64)> {
    let row = conn
        .query_row(
            "SELECT p.account_id, a.public_key, a.keyset, p.expires_at
             FROM agent_pairings p JOIN accounts a ON a.id = p.account_id
             WHERE p.token_hash = ?1 AND p.expires_at > ?2",
            params![token_hash, at],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?)),
        )
        .optional()?;
    let (account_id, x25519, keyset, expires_at) = row.ok_or_else(pairing_error)?;
    let ml_kem =
        serde_json::from_str::<EncryptedKeyset>(&keyset).ok().and_then(|k| k.pq_public_key).ok_or_else(|| {
            ApiError::forbidden("this account has no post-quantum key yet; sync once with a current 2Secret")
        })?;
    Ok((account_id, x25519, ml_kem, expires_at))
}

fn pair_limit(state: &AppState, client: &ClientIp) -> ApiResult<()> {
    let key = format!("pair:{}", client.0);
    let at = now();
    if !state.pair_limiter.allowed(&key, at) {
        return Err(ApiError::too_many_requests());
    }
    state.pair_limiter.record_failure(&key, at);
    Ok(())
}

async fn pairing_info_post(
    State(state): State<AppState>,
    client: ClientIp,
    Json(req): Json<PairingInfoRequest>,
) -> ApiResult<Json<PairingInfo>> {
    pairing_info(State(state), client, Path(req.token)).await
}

async fn pairing_info(
    State(state): State<AppState>,
    client: ClientIp,
    Path(token): Path<String>,
) -> ApiResult<Json<PairingInfo>> {
    if !valid_token(&token) {
        return Err(pairing_error());
    }
    pair_limit(&state, &client)?;
    let hash = pairing_token_hash(&token);
    let (_, x25519, ml_kem, expires_at) = state.db.run(move |c| pairing_account(c, &hash, now())).await?;
    Ok(Json(PairingInfo { x25519, ml_kem, expires_at }))
}

async fn pair(
    State(state): State<AppState>,
    client: ClientIp,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<PairAgentResponse>)> {
    pair_limit(&state, &client)?;
    let sig = agent_auth::signature(&headers)?;
    let req: PairAgentRequest = parse_body(&body)?;
    if !valid_token(&req.token) {
        return Err(pairing_error());
    }
    let verified = req.keys.verify().map_err(|e| ApiError::bad_request(e.to_string()))?;
    let agent_id = verified.agent_id();
    if sig.agent_id != agent_id {
        return Err(ApiError::bad_request("the signature belongs to another key than the one announced"));
    }
    // The agent proves it holds the key it announces.
    agent_auth::verify_with_key(&state, &sig, &req.keys.ed25519, &method, &uri, &body)?;
    let proof = envelope_json(&req.proof)?;
    let hash = pairing_token_hash(&req.token);
    let at = now();
    let max_agents = state.config.max_agents_per_account as i64;
    let expires_at = state
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            let (account_id, _, _, expires_at) = pairing_account(&tx, &hash, at)?;
            // One use per code.
            tx.execute("DELETE FROM agent_pairings WHERE token_hash = ?1", [&hash])?;
            let existing: Option<String> =
                tx.query_row("SELECT account_id FROM agents WHERE id = ?1", [&agent_id], |r| r.get(0)).optional()?;
            match existing {
                Some(owner) if owner != account_id => {
                    return Err(ApiError::conflict("this agent is paired with another account; use new keys"));
                }
                Some(_) => {
                    // The same agent pairs again (after being revoked, or
                    // before it was confirmed): start over.
                    tx.execute("DELETE FROM agent_requests WHERE agent_id = ?1", [&agent_id])?;
                    tx.execute("DELETE FROM agents WHERE id = ?1", [&agent_id])?;
                }
                None => {}
            }
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM agents WHERE account_id = ?1 AND revoked_at = 0",
                [&account_id],
                |r| r.get(0),
            )?;
            if count >= max_agents {
                return Err(ApiError::forbidden(format!("this account can have {max_agents} agents elsewhere")));
            }
            tx.execute(
                "INSERT INTO agents (id, account_id, x25519, ml_kem, ed25519, token_hash, proof, record, created_at, expires_at, last_seen_at, revoked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9, NULL, 0)",
                params![agent_id, account_id, req.keys.x25519, req.keys.ml_kem, req.keys.ed25519, hash, proof, at, expires_at],
            )?;
            tx.commit()?;
            Ok(expires_at)
        })
        .await?;
    Ok((StatusCode::CREATED, Json(PairAgentResponse { agent_id: sig.agent_id, expires_at })))
}

// ---------------------------------------------------------------------------
// Agent: requests
// ---------------------------------------------------------------------------

async fn post_request(
    State(state): State<AppState>,
    client: ClientIp,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<PostAgentRequestResponse>)> {
    let caller: AgentCaller = agent_auth::verify(&state, &client, &headers, &method, &uri, &body).await?;
    let req: PostAgentRequest = parse_body(&body)?;
    if !valid_request_id(&req.id) {
        return Err(ApiError::bad_request("invalid request id"));
    }
    let request = envelope_json(&req.request)?;
    let at = now();
    let expires_at = at + REQUEST_SECONDS;
    let max_open = state.config.max_open_agent_requests as i64;
    let account_id = caller.account_id.clone();
    let quota = state.config.account_quota_bytes;
    let growth = request.len() as i64 + crate::db::ROW_BYTES;
    state
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            crate::routes::check_quota(&tx, quota, &caller.account_id, growth)?;
            let open: i64 = tx.query_row(
                "SELECT COUNT(*) FROM agent_requests WHERE agent_id = ?1 AND status = 'open' AND expires_at > ?2",
                params![caller.agent_id, at],
                |r| r.get(0),
            )?;
            if open >= max_open {
                return Err(ApiError::forbidden(format!("this agent has {max_open} requests waiting; wait for an answer")));
            }
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO agent_requests (id, agent_id, account_id, request, answer, status, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, NULL, 'open', ?5, ?6)",
                params![req.id, caller.agent_id, caller.account_id, request, at, expires_at],
            )?;
            if inserted == 0 {
                return Err(ApiError::conflict("request id already in use"));
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    let _ = state.agent_events.send(AgentEvent::Request { account_id });
    Ok((StatusCode::CREATED, Json(PostAgentRequestResponse { expires_at })))
}

/// A request's row as the agent sees it; the answer is handed out once.
fn take_status(conn: &Connection, id: &str, agent_id: &str, at: i64) -> ApiResult<Option<AgentRequestStatus>> {
    let tx = conn.unchecked_transaction()?;
    let row = tx
        .query_row(
            "SELECT status, answer, expires_at FROM agent_requests WHERE id = ?1 AND agent_id = ?2",
            params![id, agent_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, i64>(2)?)),
        )
        .optional()?;
    let Some((status, answer, expires_at)) = row else {
        return Ok(None);
    };
    let status = match status.as_str() {
        "open" if expires_at > at => {
            return Ok(Some(AgentRequestStatus { status: AgentRequestState::Open, answer: None }));
        }
        "open" => AgentRequestStatus { status: AgentRequestState::Expired, answer: None },
        "denied" => AgentRequestStatus { status: AgentRequestState::Denied, answer: None },
        _ => AgentRequestStatus { status: AgentRequestState::Answered, answer: answer.map(enc_col).transpose()? },
    };
    tx.execute("DELETE FROM agent_requests WHERE id = ?1", [id])?;
    tx.commit()?;
    Ok(Some(status))
}

// Each argument is an axum extractor.
#[allow(clippy::too_many_arguments)]
async fn request_status(
    State(state): State<AppState>,
    client: ClientIp,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<WaitQuery>,
    body: Bytes,
) -> ApiResult<Json<AgentRequestStatus>> {
    let caller = agent_auth::verify(&state, &client, &headers, &method, &uri, &body).await?;
    if !valid_request_id(&id) {
        return Err(ApiError::not_found("request not found"));
    }
    let mut rx = state.agent_events.subscribe();
    let (rid, aid) = (id.clone(), caller.agent_id.clone());
    let status = state.db.run(move |c| take_status(c, &rid, &aid, now())).await?;
    let status = match status {
        None => return Err(ApiError::not_found("request not found")),
        Some(s) if s.status != AgentRequestState::Open || q.wait == 0 => s,
        Some(_) => {
            let mine = id.clone();
            wait_for(&mut rx, q.wait, |e| matches!(e, AgentEvent::Answered { request_id } if *request_id == mine))
                .await;
            let (rid, aid) = (id.clone(), caller.agent_id.clone());
            state
                .db
                .run(move |c| take_status(c, &rid, &aid, now()))
                .await?
                .ok_or_else(|| ApiError::not_found("request not found"))?
        }
    };
    Ok(Json(status))
}

// ---------------------------------------------------------------------------
// Housekeeping
// ---------------------------------------------------------------------------

/// Expired pairing codes, unconfirmed agents past their time, expired
/// requests and long-revoked agents go (called every minute).
pub fn delete_expired(conn: &Connection, at: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM agent_pairings WHERE expires_at <= ?1", [at])?;
    conn.execute("DELETE FROM agents WHERE record IS NULL AND revoked_at = 0 AND expires_at <= ?1", [at])?;
    conn.execute("DELETE FROM agent_requests WHERE expires_at <= ?1", [at])?;
    conn.execute("DELETE FROM agents WHERE revoked_at > 0 AND revoked_at <= ?1", [at - REVOKED_KEEP_SECONDS])?;
    Ok(())
}
